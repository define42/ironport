//go:build linux

package ironport

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/define42/ironport/internal/authlimit"
	"golang.org/x/crypto/ssh"
)

func TestSSHRejectedKeyOffersDoNotStartBackoff(t *testing.T) {
	for _, username := range []string{"alice", "unknown"} {
		t.Run(username, func(t *testing.T) {
			server, _, _, wrongKey := newSSHKeyOfferServer(t, AuthLimitConfig{})
			metadata := sshKeyOfferMetadata{user: username, ip: "192.0.2.1"}
			for range 4 {
				attempt := requireRejectedSSHKeyOffer(t, server, metadata, wrongKey)
				requireSSHKeyOfferAttemptBackoff(t, server, attempt, false)
			}
		})
	}
}

func TestSSHRejectedKeyOffersPreservePriorVerificationFailures(t *testing.T) {
	for _, verification := range []string{"password", "verified key"} {
		t.Run(verification, func(t *testing.T) {
			server, cfg, key, wrongKey := newSSHKeyOfferServer(t, AuthLimitConfig{})
			metadata := sshKeyOfferMetadata{user: "alice", ip: "192.0.2.1"}
			probes := newSSHKeyOfferBackoffProbes(t, server, metadata)
			for range 2 {
				requireSSHKeyOfferPasswordFailure(t, server, cfg, metadata)
			}
			for range 4 {
				requireRejectedSSHKeyOffer(t, server, metadata, wrongKey)
				requireSSHKeyOfferBackoff(t, server, probes, false)
			}
			if verification == "password" {
				requireSSHKeyOfferPasswordFailure(t, server, cfg, metadata)
			} else {
				requireSSHKeyOfferRevokedProofFailure(t, server, cfg, metadata, key)
			}
			// A query must neither add a failure nor erase either identity's
			// previous failures. Only this third verification starts backoff.
			requireSSHKeyOfferBackoff(t, server, probes, true)
		})
	}
}

func TestSSHRejectedKeyOffersConsumeAdmissionTokens(t *testing.T) {
	for _, test := range []struct {
		name     string
		limits   AuthLimitConfig
		nextUser string
		nextIP   string
	}{
		{"global", AuthLimitConfig{GlobalBurst: 1, GlobalInterval: time.Hour}, "bob", "192.0.2.2"},
		{"IP", AuthLimitConfig{IPBurst: 1, IPInterval: time.Hour}, "bob", "192.0.2.1"},
		{"username", AuthLimitConfig{UserBurst: 1, UserInterval: time.Hour}, "alice", "192.0.2.2"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, cfg, key, wrongKey := newSSHKeyOfferServer(t, test.limits)
			first := sshKeyOfferMetadata{user: "alice", ip: "192.0.2.1"}
			attempt := requireRejectedSSHKeyOffer(t, server, first, wrongKey)
			requireSSHKeyOfferAttemptBackoff(t, server, attempt, false)
			// Other buckets retain spare tokens, even if these identities hash
			// to the same slots, so only this exhausted budget can reject.
			next := sshKeyOfferMetadata{user: test.nextUser, ip: test.nextIP}
			permissions, err := cfg.PublicKeyCallback(next, key)
			if !errors.Is(err, errInvalidCredentials) || permissions != nil {
				t.Fatalf("offer bypassed consumed %s token: permissions=%v error=%v", test.name, permissions, err)
			}
			requireSSHKeyOfferAttemptBackoff(t, server, attempt, false)
		})
	}
}

type sshKeyOfferMetadata struct {
	testConnMetadata

	ip string
}

func (m sshKeyOfferMetadata) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(m.ip), Port: 12345}
}

func newSSHKeyOfferServer(t *testing.T, limits AuthLimitConfig) (*Server, *ssh.ServerConfig, ssh.PublicKey, ssh.PublicKey) {
	t.Helper()
	_, key := testClientKey(t)
	_, wrongKey := testClientKey(t)
	// Keep a regression's unintended cooldown observable throughout the test.
	limits.BackoffInitial = time.Hour
	limits.BackoffMax = time.Hour
	if limits.UserBurst == 0 {
		limits.UserBurst = 128
	}
	if limits.IPBurst == 0 {
		limits.IPBurst = 128
	}
	user := UserInfo{Password: "correct", Root: t.TempDir(), AuthorizedKeys: []ssh.PublicKey{key}, CanRead: true}
	server := NewServer(&Config{
		SftpSigner: testSigner(t), AuthLimits: limits,
		Users: map[string]UserInfo{"alice": user, "bob": user},
	})
	state := &sshAuthState{}
	t.Cleanup(state.close)
	return server, state.config(server.sshServerConfig()), key, wrongKey
}

func requireRejectedSSHKeyOffer(t *testing.T, server *Server, metadata sshKeyOfferMetadata, key ssh.PublicKey) authlimit.Attempt {
	t.Helper()
	attempt, err := server.checkSSHKeyQuery(metadata, key, server.authEventsChan())
	if !errors.Is(err, errInvalidCredentials) {
		t.Fatalf("rejected offer error = %v; want invalid credentials", err)
	}
	event := requireAuthEventReason(t, server.AuthEvents(), AuthEventLoginFailed, metadata.User(), CompletedUploadProtocolSFTP, AuthFailureCredentials)
	if event.ClientIP != metadata.ip {
		t.Fatalf("key-offer event IP = %q; want %q", event.ClientIP, metadata.ip)
	}
	return attempt
}

type sshKeyOfferBackoffProbe struct {
	control authlimit.Attempt
	source  authlimit.Attempt
	user    authlimit.Attempt
}

func newSSHKeyOfferBackoffProbes(t *testing.T, server *Server, metadata sshKeyOfferMetadata) []sshKeyOfferBackoffProbe {
	t.Helper()
	var probes []sshKeyOfferBackoffProbe
	// Capture tickets before failures can block admission. Each control shares
	// the source probe's username and the user probe's IP. An unblocked control
	// later proves both probes isolate the failed identity without hash guesses.
	for i := 2; i < 18; i++ {
		ip := fmt.Sprintf("192.0.2.%d", i)
		username := fmt.Sprintf("key-offer-control-%d", i)
		probes = append(probes, sshKeyOfferBackoffProbe{
			control: requireAuthAdmission(t, server, username, ip),
			source:  requireAuthAdmission(t, server, username, metadata.ip),
			user:    requireAuthAdmission(t, server, metadata.User(), ip),
		})
	}
	return probes
}

func requireSSHKeyOfferBackoff(t *testing.T, server *Server, probes []sshKeyOfferBackoffProbe, wantBlocked bool) {
	t.Helper()
	for _, probe := range probes {
		if server.authControl().RetryBackoff(probe.control, time.Now()) == 0 {
			requireSSHKeyOfferAttemptBackoff(t, server, probe.source, wantBlocked)
			requireSSHKeyOfferAttemptBackoff(t, server, probe.user, wantBlocked)
			return
		}
	}
	t.Fatal("could not find independent control slots for the backoff probes")
}

func requireSSHKeyOfferAttemptBackoff(t *testing.T, server *Server, attempt authlimit.Attempt, wantBlocked bool) {
	t.Helper()
	retry := server.authControl().RetryBackoff(attempt, time.Now())
	if (retry > 0) != wantBlocked {
		t.Fatalf("attempt backoff = %v; want blocked=%t", retry, wantBlocked)
	}
}

func requireSSHKeyOfferPasswordFailure(t *testing.T, server *Server, cfg *ssh.ServerConfig, metadata sshKeyOfferMetadata) {
	t.Helper()
	permissions, err := cfg.PasswordCallback(metadata, []byte("wrong"))
	if !errors.Is(err, errInvalidCredentials) || permissions != nil {
		t.Fatalf("bad password = %v, %v; want invalid credentials without permissions", permissions, err)
	}
	requireAuthEventReason(t, server.AuthEvents(), AuthEventLoginFailed, metadata.User(), CompletedUploadProtocolSFTP, AuthFailureCredentials)
}

func requireSSHKeyOfferRevokedProofFailure(t *testing.T, server *Server, cfg *ssh.ServerConfig, metadata sshKeyOfferMetadata, key ssh.PublicKey) {
	t.Helper()
	query, err := cfg.PublicKeyCallback(metadata, key)
	if err != nil {
		t.Fatalf("eligible key offer: %v", err)
	}
	server.RemoveUserKey(metadata.User(), key)
	permissions, err := cfg.VerifiedPublicKeyCallback(metadata, key, query, "")
	if !errors.Is(err, errInvalidCredentials) || permissions != nil {
		t.Fatalf("revoked key proof = %v, %v; want invalid credentials without permissions", permissions, err)
	}
	requireAuthEventReason(t, server.AuthEvents(), AuthEventLoginFailed, metadata.User(), CompletedUploadProtocolSFTP, AuthFailureCredentials)
}
