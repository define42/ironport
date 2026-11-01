package authlimit

import (
	"fmt"
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
			l := New(Config{IPBurst: 2, UserBurst: 2, IPInterval: time.Hour, UserInterval: time.Hour})
			now := time.Now()
			for i := range 3 {
				retry := l.Allow(tc.users[i], tc.ips[i], now)
				if (retry > 0) != (i == 2) {
					t.Fatalf("attempt %d retry=%v", i+1, retry)
				}
			}
			if retry := l.Allow(tc.users[2], tc.ips[2], now.Add(time.Hour)); retry != 0 {
				t.Fatalf("refilled bucket rejected: %v", retry)
			}
		})
	}
}

func TestAuthLimiterGlobalBound(t *testing.T) {
	t.Parallel()
	l := New(Config{GlobalBurst: 2, GlobalInterval: time.Hour})
	now := time.Now()
	for i := range 3 {
		retry := l.Allow(fmt.Sprintf("user%d", i), fmt.Sprintf("192.0.2.%d", i+1), now)
		if (retry > 0) != (i == 2) {
			t.Fatalf("attempt %d retry=%v", i+1, retry)
		}
	}
}

func TestAuthLimiterMemoryBound(t *testing.T) {
	t.Parallel()
	l := New(Config{MaxEntries: 2, EntryTTL: time.Minute})
	now := time.Now()
	if retry := l.Allow("a", "192.0.2.1", now); retry != 0 {
		t.Fatal(retry)
	}
	for i := range 100 {
		if retry := l.Allow(fmt.Sprintf("unknown%d", i), "192.0.2.2", now); retry == 0 {
			t.Fatal("table overflow permitted authentication")
		}
	}
	if len(l.entries) != 2 {
		t.Fatalf("retained %d identities, want 2", len(l.entries))
	}
	if retry := l.Allow("new", "192.0.2.2", now.Add(time.Minute)); retry != 0 {
		t.Fatalf("expired table did not recover: %v", retry)
	}
}

func TestAuthLimiterLocalRejectionDoesNotConsumeGlobal(t *testing.T) {
	t.Parallel()
	l := New(Config{
		GlobalBurst:    2,
		GlobalInterval: time.Hour,
		IPBurst:        1,
		IPInterval:     time.Hour,
	})
	now := time.Now()
	const attackerIP = "192.0.2.1"
	if retry := l.Allow("attacker-first", attackerIP, now); retry != 0 {
		t.Fatalf("initial attacker attempt rejected: %v", retry)
	}
	if retry := l.Allow("attacker-throttled", attackerIP, now); retry == 0 {
		t.Fatal("exhausted IP bucket permitted another attempt")
	}
	attackerKeys := identities("attacker-throttled", attackerIP)
	if _, exists := l.entries[attackerKeys[1]]; exists {
		t.Fatal("locally rejected attempt allocated a username entry")
	}
	if retry := l.Allow("victim", "192.0.2.2", now); retry != 0 {
		t.Fatalf("locally rejected attempt consumed global capacity: %v", retry)
	}
}

func TestAuthLimiterThrottledIPCannotExhaustIdentityTable(t *testing.T) {
	t.Parallel()
	l := New(Config{
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
	if retry := l.Allow("attacker-first", attackerIP, now); retry != 0 {
		t.Fatalf("initial attacker attempt rejected: %v", retry)
	}
	for i := range 100 {
		if retry := l.Allow(fmt.Sprintf("attacker-%d", i), attackerIP, now); retry == 0 {
			t.Fatalf("throttled attacker username %d was admitted", i)
		}
	}
	if got := len(l.entries); got != 2 {
		t.Fatalf("throttled IP created %d identity entries, want 2", got)
	}
	if retry := l.Allow("victim", "192.0.2.2", now); retry != 0 {
		t.Fatalf("throttled IP blocked an unrelated identity: %v", retry)
	}
}

func TestAuthLimiterSuccessPreservesSharedIPBackoff(t *testing.T) {
	t.Parallel()
	const backoff = time.Minute
	l := New(Config{
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
	if retry := l.Allow("trusted", clientIP, now); retry != 0 {
		t.Fatalf("trusted request rejected: %v", retry)
	}
	for i := range 3 {
		username := fmt.Sprintf("target-%d", i)
		if retry := l.Allow(username, clientIP, now); retry != 0 {
			t.Fatalf("failure request %d rejected before verification: %v", i, retry)
		}
		l.Result(username, clientIP, false, now)
	}
	l.Result("trusted", clientIP, true, now)
	if retry := l.Allow("another-target", clientIP, now); retry != backoff {
		t.Fatalf("successful username cleared shared-IP backoff: got %v, want %v", retry, backoff)
	}
}

func TestAuthLimiterBackoff(t *testing.T) {
	t.Parallel()
	l := New(Config{})
	now := time.Now()
	for range 3 {
		if retry := l.Allow("alice", "192.0.2.1", now); retry != 0 {
			t.Fatal(retry)
		}
		l.Result("alice", "192.0.2.1", false, now)
	}
	if retry := l.Allow("alice", "192.0.2.1", now); retry != 250*time.Millisecond {
		t.Fatalf("initial retry=%v", retry)
	}
	now = now.Add(250 * time.Millisecond)
	if retry := l.Allow("alice", "192.0.2.1", now); retry != 0 {
		t.Fatal(retry)
	}
	l.Result("alice", "192.0.2.1", false, now)
	if retry := l.Allow("alice", "192.0.2.1", now); retry != 500*time.Millisecond {
		t.Fatalf("doubled retry=%v", retry)
	}
	now = now.Add(500 * time.Millisecond)
	if retry := l.Allow("alice", "192.0.2.1", now); retry != 0 {
		t.Fatal(retry)
	}
	l.Result("alice", "192.0.2.1", true, now)
	if retry := l.Allow("alice", "192.0.2.1", now); retry != 0 {
		t.Fatalf("successful retry did not recover: %v", retry)
	}
}

func TestAuthLimiterProofChecksIdentityBackoff(t *testing.T) {
	for _, identity := range []string{"IP", "username"} {
		t.Run(identity, func(t *testing.T) {
			testAuthProofIdentityBackoff(t, identity)
		})
	}
}

func testAuthProofIdentityBackoff(t *testing.T, identity string) {
	t.Helper()
	limiter := New(Config{GlobalBurst: 1, GlobalInterval: time.Hour})
	now := time.Now()
	if retry := limiter.Allow("alice", "192.0.2.1", now); retry != 0 {
		t.Fatal(retry)
	}
	if retry := limiter.RetryBackoff("alice", "192.0.2.1", now); retry != 0 {
		t.Fatalf("proof was charged a second token: %v", retry)
	}
	username, ip := "alice", "192.0.2.2"
	if identity == "IP" {
		username, ip = "other", "192.0.2.1"
	}
	for range 3 {
		limiter.Result(username, ip, false, now)
	}
	if retry := limiter.RetryBackoff("alice", "192.0.2.1", now); retry != 250*time.Millisecond {
		t.Fatalf("proof ignored %s backoff: %v", identity, retry)
	}
}

func TestAuthTableCapacityNeverEnlarged(t *testing.T) {
	limiter := New(Config{MaxEntries: 1})
	if retry := limiter.Allow("u", "192.0.2.1", time.Now()); retry <= 0 {
		t.Fatal("one-entry table admitted a two-entry identity pair")
	}
	if len(limiter.entries) != 0 {
		t.Fatal("rejected admission retained identities")
	}
}
