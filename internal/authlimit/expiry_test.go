package authlimit

import (
	"fmt"
	"testing"
	"time"
)

func TestAuthLimiterExpiryPreservesRefill(t *testing.T) {
	t.Parallel()
	for _, identity := range []string{"IP", "username"} {
		for _, burst := range []int{1, 3} {
			t.Run(fmt.Sprintf("%s/burst%d", identity, burst), func(t *testing.T) {
				t.Parallel()
				testAuthLimiterExpiryRefill(t, identity, burst)
			})
		}
	}
}

func testAuthLimiterExpiryRefill(t *testing.T, identity string, burst int) {
	t.Helper()
	config := Config{}
	if identity == "IP" {
		config.IPBurst, config.IPInterval = burst, time.Hour
	} else {
		config.UserBurst, config.UserInterval = burst, time.Hour
	}
	limiter := New(config)
	now := time.Now()
	for range burst {
		admit(t, limiter, "alice", "192.0.2.1", now)
	}
	// Idle expiry cannot restore a burst that has only partly refilled.
	refilled := burst / 2
	later := now.Add(time.Duration(refilled)*time.Hour + 15*time.Minute)
	for range refilled {
		admit(t, limiter, "alice", "192.0.2.1", later)
	}
	if _, retry := limiter.Allow("alice", "192.0.2.1", later); retry != 45*time.Minute {
		t.Fatalf("idle expiry reset depleted bucket: retry = %v, want 45m", retry)
	}
}

func TestAuthLimiterExpiryPreservesDelayedBackoff(t *testing.T) {
	t.Parallel()
	limiter := New(Config{EntryTTL: time.Minute, BackoffInitial: time.Minute, BackoffMax: time.Minute})
	now := time.Now()
	var attempts [3]Attempt
	for i := range attempts {
		attempts[i] = admit(t, limiter, "alice", "192.0.2.1", now)
	}
	for _, attempt := range attempts[:2] {
		limiter.Result(attempt, false, now)
	}
	// Verification can finish long after admission. Expiry retains its penalty.
	limiter.Result(attempts[2], false, now.Add(55*time.Second))
	if _, retry := limiter.Allow("alice", "192.0.2.1", now.Add(time.Minute)); retry != 55*time.Second {
		t.Fatalf("idle expiry erased active backoff: retry = %v, want 55s", retry)
	}
	admit(t, limiter, "alice", "192.0.2.1", now.Add(115*time.Second))
}

func TestAuthLimiterExpiryResetsOnlyRecoveredSlots(t *testing.T) {
	t.Parallel()
	limiter := New(Config{MaxEntries: 2, IPBurst: 1, IPInterval: time.Hour, UserBurst: 1, UserInterval: time.Hour})
	now := time.Now()
	alice := admit(t, limiter, "alice", "192.0.2.1", now)
	limiter.Result(alice, false, now)
	if _, retry := limiter.Allow("bob", "192.0.2.2", now.Add(15*time.Minute)); retry != 45*time.Minute {
		t.Fatalf("colliding identity reset depleted slot: retry = %v", retry)
	}
	if limiter.users[alice.user].owner != alice.username {
		t.Fatal("rejected collision replaced the existing owner")
	}
	bob := admit(t, limiter, "bob", "192.0.2.2", now.Add(time.Hour))
	if user := limiter.users[bob.user]; user.owned || user.mixed {
		t.Fatal("fully recovered slot retained previous failure ownership")
	}
}

func TestAuthLimiterResultRefreshesIdleTime(t *testing.T) {
	t.Parallel()
	l := New(Config{EntryTTL: time.Minute})
	now := time.Now()
	var attempts [3]Attempt
	for i := range attempts {
		attempts[i] = admit(t, l, "alice", "192.0.2.1", now)
	}
	late := now.Add(2 * time.Minute)
	l.Result(attempts[0], false, late)
	l.Result(attempts[1], false, late)
	admit(t, l, "alice", "192.0.2.1", late)
	l.Result(attempts[2], false, late)
	if retry := l.RetryBackoff(attempts[0], late); retry != 250*time.Millisecond {
		t.Fatalf("idle expiry erased recently completed failures: %v", retry)
	}
}
