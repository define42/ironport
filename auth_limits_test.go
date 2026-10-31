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
)

func TestAuthLimiterIdentityBuckets(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		users [3]string
		ips   [3]string
	}{
		{name: "IP across usernames", users: [3]string{"a", "b", "c"}, ips: [3]string{"192.0.2.1", "192.0.2.1", "192.0.2.1"}},
		{name: "username across IPs", users: [3]string{"a", "a", "a"}, ips: [3]string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}},
		{name: "IPv4 mapped address", users: [3]string{"a", "b", "c"}, ips: [3]string{"192.0.2.1", "::ffff:192.0.2.1", "192.0.2.1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l := newAuthLimiter(AuthLimitConfig{IPBurst: 2, UserBurst: 2, IPInterval: time.Hour, UserInterval: time.Hour})
			now := time.Now()
			for i := range 3 {
				retry := l.allow(tc.users[i], tc.ips[i], now)
				if (retry > 0) != (i == 2) {
					t.Fatalf("attempt %d retry=%v", i+1, retry)
				}
			}
			if retry := l.allow(tc.users[2], tc.ips[2], now.Add(time.Hour)); retry != 0 {
				t.Fatalf("refilled bucket rejected: %v", retry)
			}
		})
	}
}

func TestAuthLimiterGlobalAndMemoryBounds(t *testing.T) {
	t.Parallel()
	t.Run("global backstop", func(t *testing.T) {
		l := newAuthLimiter(AuthLimitConfig{GlobalBurst: 2, GlobalInterval: time.Hour})
		now := time.Now()
		for i := range 3 {
			retry := l.allow(fmt.Sprintf("user%d", i), fmt.Sprintf("192.0.2.%d", i+1), now)
			if (retry > 0) != (i == 2) {
				t.Fatalf("attempt %d retry=%v", i+1, retry)
			}
		}
	})
	t.Run("saturated table fails closed then expires", func(t *testing.T) {
		l := newAuthLimiter(AuthLimitConfig{MaxEntries: 2, EntryTTL: time.Minute})
		now := time.Now()
		if retry := l.allow("a", "192.0.2.1", now); retry != 0 {
			t.Fatal(retry)
		}
		for i := range 100 {
			if retry := l.allow(fmt.Sprintf("unknown%d", i), "192.0.2.2", now); retry == 0 {
				t.Fatal("table overflow permitted authentication")
			}
		}
		if len(l.entries) != 2 {
			t.Fatalf("retained %d identities, want 2", len(l.entries))
		}
		if retry := l.allow("new", "192.0.2.2", now.Add(time.Minute)); retry != 0 {
			t.Fatalf("expired table did not recover: %v", retry)
		}
	})
}

func TestAuthLimiterLocalRejectionDoesNotConsumeGlobal(t *testing.T) {
	t.Parallel()
	l := newAuthLimiter(AuthLimitConfig{
		GlobalBurst:    2,
		GlobalInterval: time.Hour,
		IPBurst:        1,
		IPInterval:     time.Hour,
	})
	now := time.Now()
	const attackerIP = "192.0.2.1"
	if retry := l.allow("attacker-first", attackerIP, now); retry != 0 {
		t.Fatalf("initial attacker attempt rejected: %v", retry)
	}
	if retry := l.allow("attacker-throttled", attackerIP, now); retry == 0 {
		t.Fatal("exhausted IP bucket permitted another attempt")
	}
	attackerKeys := authIdentities("attacker-throttled", attackerIP)
	if _, exists := l.entries[attackerKeys[1]]; exists {
		t.Fatal("locally rejected attempt allocated a username entry")
	}
	if retry := l.allow("victim", "192.0.2.2", now); retry != 0 {
		t.Fatalf("locally rejected attempt consumed global capacity: %v", retry)
	}
}

func TestAuthLimiterThrottledIPCannotExhaustIdentityTable(t *testing.T) {
	t.Parallel()
	l := newAuthLimiter(AuthLimitConfig{
		GlobalBurst:    256,
		GlobalInterval: time.Hour,
		IPBurst:        1,
		IPInterval:     time.Hour,
		UserBurst:      256,
		UserInterval:   time.Hour,
		MaxEntries:     4,
		EntryTTL:       time.Hour,
	})
	now := time.Now()
	const attackerIP = "192.0.2.1"
	if retry := l.allow("attacker-first", attackerIP, now); retry != 0 {
		t.Fatalf("initial attacker attempt rejected: %v", retry)
	}
	for i := range 100 {
		if retry := l.allow(fmt.Sprintf("attacker-%d", i), attackerIP, now); retry == 0 {
			t.Fatalf("throttled attacker username %d was admitted", i)
		}
	}
	if got := len(l.entries); got != 2 {
		t.Fatalf("throttled IP created %d identity entries, want 2", got)
	}
	if retry := l.allow("victim", "192.0.2.2", now); retry != 0 {
		t.Fatalf("throttled IP blocked an unrelated identity: %v", retry)
	}
}

func TestAuthLimiterSuccessPreservesSharedIPBackoff(t *testing.T) {
	t.Parallel()
	const backoff = time.Minute
	l := newAuthLimiter(AuthLimitConfig{
		GlobalBurst:    16,
		GlobalInterval: time.Hour,
		IPBurst:        16,
		IPInterval:     time.Hour,
		UserBurst:      16,
		UserInterval:   time.Hour,
		BackoffInitial: backoff,
		BackoffMax:     backoff,
	})
	now := time.Now()
	const clientIP = "192.0.2.1"

	// Admit the valid request first, then complete it after concurrent failures
	// against other usernames have placed the shared IP into backoff.
	if retry := l.allow("trusted", clientIP, now); retry != 0 {
		t.Fatalf("trusted request rejected: %v", retry)
	}
	for i := range 3 {
		username := fmt.Sprintf("target-%d", i)
		if retry := l.allow(username, clientIP, now); retry != 0 {
			t.Fatalf("failure request %d rejected before verification: %v", i, retry)
		}
		l.result(username, clientIP, false, now)
	}
	l.result("trusted", clientIP, true, now)
	if retry := l.allow("another-target", clientIP, now); retry != backoff {
		t.Fatalf("successful username cleared shared-IP backoff: got %v, want %v", retry, backoff)
	}
}

func TestAuthLimiterBackoff(t *testing.T) {
	t.Parallel()
	l := newAuthLimiter(AuthLimitConfig{})
	now := time.Now()
	for range 3 {
		if retry := l.allow("alice", "192.0.2.1", now); retry != 0 {
			t.Fatal(retry)
		}
		l.result("alice", "192.0.2.1", false, now)
	}
	if retry := l.allow("alice", "192.0.2.1", now); retry != 250*time.Millisecond {
		t.Fatalf("initial retry=%v", retry)
	}
	now = now.Add(250 * time.Millisecond)
	if retry := l.allow("alice", "192.0.2.1", now); retry != 0 {
		t.Fatal(retry)
	}
	l.result("alice", "192.0.2.1", false, now)
	if retry := l.allow("alice", "192.0.2.1", now); retry != 500*time.Millisecond {
		t.Fatalf("doubled retry=%v", retry)
	}
	now = now.Add(500 * time.Millisecond)
	if retry := l.allow("alice", "192.0.2.1", now); retry != 0 {
		t.Fatal(retry)
	}
	l.result("alice", "192.0.2.1", true, now)
	if retry := l.allow("alice", "192.0.2.1", now); retry != 0 {
		t.Fatalf("successful retry did not recover: %v", retry)
	}
}

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

func TestFTPAuthenticationFailureLimitSurvivesUSER(t *testing.T) {
	server := NewServer(&Config{FTPMaxAuthFailures: 2})
	var response bytes.Buffer
	session := &ftpSession{server: server, clientIP: "192.0.2.1", w: bufio.NewWriter(&response)}
	for i := range 2 {
		if session.handleFTPCommand("USER", fmt.Sprintf("missing%d", i)) {
			t.Fatal("USER closed session")
		}
		quit := session.handleFTPCommand("PASS", "bad")
		if quit != (i == 1) {
			t.Fatalf("attempt %d quit=%t", i+1, quit)
		}
	}
	if !strings.Contains(response.String(), "421 too many authentication failures") {
		t.Fatalf("response=%q", response.String())
	}
}

func TestAuthenticationLimitsSharedByProtocols(t *testing.T) {
	server := NewServer(&Config{SftpSigner: testSigner(t), Users: map[string]UserInfo{"alice": {Password: "correct", Root: t.TempDir(), CanWrite: true}}, AuthLimits: AuthLimitConfig{UserBurst: 1, UserInterval: time.Hour}})
	if response := doHTTPUpload(t, server, "alice", "bad", "file", "x", nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("HTTP status=%d", response.Code)
	}
	config := testSSHServerConfig(t, server)
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
