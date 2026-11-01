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
			})
			limiter := server.authControl()
			// Seed failures from another IP so only the username can carry
			// backoff across the unsigned query and its later signature proof.
			if retry := limiter.Allow("alice", "192.0.2.1", time.Now()); retry != 0 {
				t.Fatal(retry)
			}
			for range 2 {
				limiter.Result("alice", "192.0.2.1", false, time.Now())
			}
			var authState sshAuthState
			defer authState.close()
			config := authState.config(server.sshServerConfig())
			metadata := testConnMetadata{user: "alice"}
			permissions, err := config.PublicKeyCallback(metadata, key)
			if err != nil {
				t.Fatalf("public-key query: %v", err)
			}
			if blockBeforeProof {
				limiter.Result("alice", "", false, time.Now())
			}
			_, err = config.VerifiedPublicKeyCallback(metadata, key, permissions, "")
			if (err != nil) != blockBeforeProof {
				t.Fatalf("verified-key error = %v, blocked = %t", err, blockBeforeProof)
			}
			if !blockBeforeProof {
				// Use a fresh IP to observe only the username's state. One more
				// failure would trigger backoff if proof had not cleared the first two.
				limiter.Result("alice", "192.0.2.99", false, time.Now())
				if retry := limiter.RetryBackoff("alice", "192.0.2.99", time.Now()); retry != 0 {
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
