package authlimit

import (
	"testing"
	"time"
)

func TestLimiterStaleAdmissionDoesNotRefillTwice(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		config Config
	}{
		{name: "global", config: Config{GlobalBurst: 2, GlobalInterval: time.Second}},
		{name: "IP", config: Config{IPBurst: 2, IPInterval: time.Second}},
		{name: "username", config: Config{UserBurst: 2, UserInterval: time.Second}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			limiter := New(tc.config)
			earlier := time.Now()
			later := earlier.Add(time.Second)
			// Model a queued call whose timestamp was captured before another
			// caller acquired the mutex. Only one token has refilled at later.
			for _, now := range []time.Time{earlier, later, earlier} {
				if retry := limiter.Allow("alice", "192.0.2.1", now); retry != 0 {
					t.Fatalf("available token rejected: %v", retry)
				}
			}
			if retry := limiter.Allow("alice", "192.0.2.1", later); retry != time.Second {
				t.Fatalf("stale timestamp credited the refill twice: retry = %v, want 1s", retry)
			}
			if retry := limiter.Allow("alice", "192.0.2.1", later.Add(time.Second)); retry != 0 {
				t.Fatalf("next refill rejected: %v", retry)
			}
		})
	}
}

func TestLimiterStaleFailurePreservesBackoff(t *testing.T) {
	t.Parallel()
	for _, identity := range []string{"IP", "username"} {
		t.Run(identity, func(t *testing.T) {
			t.Parallel()
			testLimiterStaleFailure(t, identity)
		})
	}
}

func testLimiterStaleFailure(t *testing.T, identity string) {
	t.Helper()
	limiter := New(Config{BackoffInitial: time.Second, BackoffMax: time.Second})
	earlier := time.Now()
	later := earlier.Add(2 * time.Second)
	for range 4 {
		if retry := limiter.Allow("alice", "192.0.2.1", earlier); retry != 0 {
			t.Fatalf("initial attempt rejected: %v", retry)
		}
	}
	for range 3 {
		limiter.Result("alice", "192.0.2.1", false, later)
	}
	// A delayed failure must not replace the active cooldown with one
	// computed from an older timestamp, even once backoff is capped.
	limiter.Result("alice", "192.0.2.1", false, earlier)
	username, ip := "alice", "192.0.2.2"
	if identity == "IP" {
		username, ip = "bob", "192.0.2.1"
	}
	if retry := limiter.RetryBackoff(username, ip, later); retry != time.Second {
		t.Fatalf("stale failure shortened cooldown: retry = %v, want 1s", retry)
	}
	if retry := limiter.Allow(username, ip, later); retry != time.Second {
		t.Fatalf("active cooldown did not reject admission: retry = %v", retry)
	}
	if retry := limiter.Allow(username, ip, later.Add(time.Second)); retry != 0 {
		t.Fatalf("elapsed cooldown did not recover: %v", retry)
	}
	if retry := limiter.RetryBackoff(username, ip, earlier); retry != 0 {
		t.Fatalf("stale proof check revived an elapsed cooldown: %v", retry)
	}
}
