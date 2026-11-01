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
				admit(t, limiter, "alice", "192.0.2.1", now)
			}
			if _, retry := limiter.Allow("alice", "192.0.2.1", later); retry != time.Second {
				t.Fatalf("stale timestamp credited the refill twice: retry = %v, want 1s", retry)
			}
			admit(t, limiter, "alice", "192.0.2.1", later.Add(time.Second))
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
	var attempts [4]Attempt
	for i := range attempts {
		attempts[i] = admit(t, limiter, "alice", "192.0.2.1", earlier)
	}
	username, ip := "alice", differentSource(t, limiter, "192.0.2.1")
	if identity == "IP" {
		username, ip = differentUsername(t, limiter, "alice"), "192.0.2.1"
	}
	proof := admit(t, limiter, username, ip, earlier)
	for _, attempt := range attempts[:3] {
		limiter.Result(attempt, false, later)
	}
	// A queued failure cannot replace an active cooldown with an older one.
	limiter.Result(attempts[3], false, earlier)
	if retry := limiter.RetryBackoff(proof, later); retry != time.Second {
		t.Fatalf("stale failure shortened cooldown: retry = %v, want 1s", retry)
	}
	if _, retry := limiter.Allow(username, ip, later); retry != time.Second {
		t.Fatalf("active cooldown did not reject admission: retry = %v", retry)
	}
	admit(t, limiter, username, ip, later.Add(time.Second))
	if retry := limiter.RetryBackoff(proof, earlier); retry != 0 {
		t.Fatalf("stale proof check revived an elapsed cooldown: %v", retry)
	}
}
