//go:build linux

package ironport

import (
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHRejectedKeyOffersDoNotStartBackoff(t *testing.T) {
	for _, username := range []string{"alice", "unknown"} {
		t.Run(username, func(t *testing.T) {
			server, cfg, _, wrongKey := newSSHKeyOfferServer(t, AuthLimitConfig{})
			metadata := sshKeyOfferMetadata{user: username, ip: "192.0.2.1"}
			for range 4 {
				requireRejectedSSHKeyOffer(t, server, cfg, metadata, wrongKey)
				requireSSHKeyOfferBackoff(t, server, metadata, false)
			}
		})
	}
}

func TestSSHRejectedKeyOffersPreservePriorVerificationFailures(t *testing.T) {
	for _, verification := range []string{"password", "verified key"} {
		t.Run(verification, func(t *testing.T) {
			server, cfg, key, wrongKey := newSSHKeyOfferServer(t, AuthLimitConfig{})
			metadata := sshKeyOfferMetadata{user: "alice", ip: "192.0.2.1"}
			for range 2 {
				requireSSHKeyOfferPasswordFailure(t, server, cfg, metadata)
			}
			for range 4 {
				requireRejectedSSHKeyOffer(t, server, cfg, metadata, wrongKey)
				requireSSHKeyOfferBackoff(t, server, metadata, false)
			}
			if verification == "password" {
				requireSSHKeyOfferPasswordFailure(t, server, cfg, metadata)
			} else {
				requireSSHKeyOfferRevokedProofFailure(t, server, cfg, metadata, key)
			}
			// A query must neither add a failure nor erase either identity's
			// previous failures. Only this third verification starts backoff.
			requireSSHKeyOfferBackoff(t, server, metadata, true)
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
			requireRejectedSSHKeyOffer(t, server, cfg, first, wrongKey)
			requireSSHKeyOfferBackoff(t, server, first, false)
			// Change identities in the other dimensions so only this bucket
			// can explain rejection of an otherwise eligible key offer.
			next := sshKeyOfferMetadata{user: test.nextUser, ip: test.nextIP}
			permissions, err := cfg.PublicKeyCallback(next, key)
			if !errors.Is(err, errInvalidCredentials) || permissions != nil {
				t.Fatalf("offer bypassed consumed %s token: permissions=%v error=%v", test.name, permissions, err)
			}
			requireSSHKeyOfferBackoff(t, server, next, false)
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
	user := UserInfo{Password: "correct", Root: t.TempDir(), AuthorizedKeys: []ssh.PublicKey{key}, CanRead: true}
	server := NewServer(&Config{
		SftpSigner: testSigner(t), AuthLimits: limits,
		Users: map[string]UserInfo{"alice": user, "bob": user},
	})
	state := &sshAuthState{}
	t.Cleanup(state.close)
	return server, state.config(server.sshServerConfig()), key, wrongKey
}

func requireRejectedSSHKeyOffer(t *testing.T, server *Server, cfg *ssh.ServerConfig, metadata sshKeyOfferMetadata, key ssh.PublicKey) {
	t.Helper()
	permissions, err := cfg.PublicKeyCallback(metadata, key)
	if !errors.Is(err, errInvalidCredentials) || permissions != nil {
		t.Fatalf("rejected offer = %v, %v; want invalid credentials without permissions", permissions, err)
	}
	event := requireAuthEventReason(t, server.AuthEvents(), AuthEventLoginFailed, metadata.User(), CompletedUploadProtocolSFTP, AuthFailureCredentials)
	if event.ClientIP != metadata.ip {
		t.Fatalf("key-offer event IP = %q; want %q", event.ClientIP, metadata.ip)
	}
}

func requireSSHKeyOfferBackoff(t *testing.T, server *Server, metadata sshKeyOfferMetadata, wantBlocked bool) {
	t.Helper()
	for _, identity := range []struct {
		name     string
		username string
		ip       string
	}{
		{"username", metadata.User(), "192.0.2.99"},
		{"IP", "independent-user", metadata.ip},
	} {
		retry := server.authControl().RetryBackoff(identity.username, identity.ip, time.Now())
		if (retry > 0) != wantBlocked {
			t.Fatalf("%s backoff = %v; want blocked=%t", identity.name, retry, wantBlocked)
		}
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
