//go:build linux

package ironport

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/define42/ironport/internal/authlimit"
	"golang.org/x/crypto/ssh"
)

func TestAuthLogSampler(t *testing.T) {
	t.Parallel()
	var sampler authLogSampler
	now := time.Now()
	if allowed, suppressed := sampler.allow(now); !allowed || suppressed != 0 {
		t.Fatalf("first sample=(%t,%d)", allowed, suppressed)
	}
	for range 1000 {
		if allowed, _ := sampler.allow(now); allowed {
			t.Fatal("log flood was not sampled")
		}
	}
	if allowed, suppressed := sampler.allow(now.Add(time.Second)); !allowed || suppressed != 1000 {
		t.Fatalf("next sample=(%t,%d)", allowed, suppressed)
	}
}

func TestAuthenticationLimitsSharedByProtocols(t *testing.T) {
	server := NewServer(&Config{SftpSigner: testSigner(t), Users: map[string]UserInfo{"alice": {Password: "correct", Root: t.TempDir(), CanWrite: true}}, AuthLimits: AuthLimitConfig{UserBurst: 1, UserInterval: time.Hour}})
	if response := doHTTPUpload(t, server, "alice", "bad", "file", "x", nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("HTTP status=%d", response.Code)
	}
	var authState sshAuthState
	defer authState.close()
	config := authState.config(server.sshServerConfig())
	if _, err := config.PasswordCallback(testConnMetadata{user: "alice"}, []byte("correct")); err == nil {
		t.Fatal("SSH bypassed the shared username limit")
	}
	var response bytes.Buffer
	session := &ftpSession{server: server, username: "alice", clientIP: "192.0.2.2", w: bufio.NewWriter(&response)}
	if !session.handleFTPCommand("PASS", "correct") {
		t.Fatal("FTP did not close throttled session")
	}
	if !strings.HasPrefix(response.String(), "421 ") {
		t.Fatalf("FTP response=%q", response.String())
	}
}

//nolint:gocognit // query admission, intervening failures, and proof form one authentication scenario
func TestSSHKeyProofUsesSharedAuthenticationLimit(t *testing.T) {
	for _, blockBeforeProof := range []bool{false, true} {
		t.Run(fmt.Sprintf("blocked=%t", blockBeforeProof), func(t *testing.T) {
			_, key := testClientKey(t)
			server := NewServer(&Config{
				SftpSigner: testSigner(t),
				Users:      map[string]UserInfo{"alice": {Root: t.TempDir(), AuthorizedKeys: []ssh.PublicKey{key}}},
				AuthLimits: AuthLimitConfig{BackoffInitial: time.Hour, BackoffMax: time.Hour},
			})
			limiter := server.authControl()
			failures, metadata := newSSHProofFailureAttempts(t, limiter)
			for _, attempt := range failures[:2] {
				limiter.Result(attempt, false, time.Now())
			}
			var authState sshAuthState
			defer authState.close()
			config := authState.config(server.sshServerConfig())
			permissions, err := config.PublicKeyCallback(metadata, key)
			if err != nil {
				t.Fatalf("public-key query: %v", err)
			}
			if blockBeforeProof {
				limiter.Result(failures[2], false, time.Now())
			}
			verified, err := config.VerifiedPublicKeyCallback(metadata, key, permissions, "")
			if (err != nil) != blockBeforeProof {
				t.Fatalf("verified-key error = %v, blocked = %t", err, blockBeforeProof)
			}
			if !blockBeforeProof {
				attempt, ok := verified.ExtraData[sshAdmissionKey{}].(authlimit.Attempt)
				if !ok {
					t.Fatal("verified key returned no admission ticket")
				}
				// The proof must have cleared the username failures. Its source
				// was chosen outside the failed source slot.
				limiter.Result(failures[2], false, time.Now())
				if retry := limiter.RetryBackoff(attempt, time.Now()); retry != 0 {
					t.Fatalf("verified key did not clear username failure state: %v", retry)
				}
			}
		})
	}
}

func TestSSHKeyProofCannotReuseQueryAdmission(t *testing.T) {
	_, key := testClientKey(t)
	user := UserInfo{Root: t.TempDir(), AuthorizedKeys: []ssh.PublicKey{key}}
	server := NewServer(&Config{
		SftpSigner: testSigner(t), Users: map[string]UserInfo{"alice": user},
		AuthLimits: AuthLimitConfig{UserBurst: 1, UserInterval: time.Hour},
	})
	var authState sshAuthState
	defer authState.close()
	config := authState.config(server.sshServerConfig())
	metadata := testConnMetadata{user: "alice"}
	permissions, err := config.PublicKeyCallback(metadata, key)
	if err != nil {
		t.Fatalf("public-key query: %v", err)
	}
	server.RemoveUser("alice")
	if _, err := config.VerifiedPublicKeyCallback(metadata, key, permissions, ""); err == nil {
		t.Fatal("proof ignored credential revocation after the query")
	}
	server.AddUser("alice", user)
	// x/crypto can reuse the same accepted query after a rejected signature
	// callback. This next proof must require a fresh authentication attempt.
	if _, err := config.VerifiedPublicKeyCallback(metadata, key, permissions, ""); err == nil {
		t.Fatal("repeated proof reused the consumed query admission")
	}
}

func newSSHProofFailureAttempts(t *testing.T, limiter *authlimit.Limiter) ([3]authlimit.Attempt, sshKeyOfferMetadata) {
	t.Helper()
	var admitted [7]authlimit.Attempt
	for i := range admitted {
		attempt, retry := limiter.Allow("alice", "192.0.2.1", time.Now())
		if retry != 0 {
			t.Fatal(retry)
		}
		admitted[i] = attempt
	}
	// Seed source backoff, then clear only the username through a separate
	// admitted success. The three remaining attempts drive the actual scenario.
	for _, attempt := range admitted[:3] {
		limiter.Result(attempt, false, time.Now())
	}
	limiter.Result(admitted[3], true, time.Now())
	failures := [3]authlimit.Attempt(admitted[4:])
	for i := 2; i < 66; i++ {
		ip := fmt.Sprintf("192.0.2.%d", i)
		username := fmt.Sprintf("source-control-%d", i)
		if _, retry := limiter.Allow(username, ip, time.Now()); retry == 0 {
			return failures, sshKeyOfferMetadata{user: "alice", ip: ip}
		}
	}
	t.Fatal("could not find an independent source slot for the key proof")
	return failures, sshKeyOfferMetadata{}
}

func requireAuthAdmission(t *testing.T, server *Server, username, ip string) authlimit.Attempt {
	t.Helper()
	attempt, retry := server.allowAuth(username, ip)
	if retry != 0 {
		t.Fatalf("authentication admission rejected for %v", retry)
	}
	return attempt
}
