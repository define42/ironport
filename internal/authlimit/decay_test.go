package authlimit

import (
	"fmt"
	"testing"
	"time"
)

// saturate fails attempts as soon as backoff permits, well past maximum backoff,
// and returns the time of the final failure.
func saturate(t *testing.T, l *Limiter, username, ip string, now time.Time) time.Time {
	t.Helper()
	last := now
	for range 20 {
		attempt := admit(t, l, username, ip, now)
		l.Result(attempt, false, now)
		last = now
		now = now.Add(l.RetryBackoff(attempt, now))
	}
	return last
}

type decayCase struct {
	quiet int
	want  time.Duration
}

// decayCases expects default backoff to saturate at ten failures, with each
// quiet BackoffMax retiring one.
func decayCases() []decayCase {
	return []decayCase{
		{1, 30 * time.Second},
		{2, 16 * time.Second},
		{4, 4 * time.Second},
		{8, 250 * time.Millisecond},
		{9, 0},
		{20, 0},
	}
}

func TestAuthLimiterActiveSourceForgetsFinishedAttack(t *testing.T) {
	t.Parallel()
	for _, tc := range decayCases() {
		t.Run(fmt.Sprintf("quiet%d", tc.quiet), func(t *testing.T) {
			t.Parallel()
			l := New(Config{})
			const ip = "192.0.2.1"
			attack := saturate(t, l, "mallory", ip, time.Now())
			alice := differentUsername(t, l, "mallory")
			typo := attack.Add(time.Duration(tc.quiet) * 30 * time.Second)
			// Successful logins keep the source active but never clear it.
			for now := attack.Add(30 * time.Second); now.Before(typo); now = now.Add(10 * time.Second) {
				l.Result(admit(t, l, alice, ip, now), true, now)
			}
			attempt := admit(t, l, alice, ip, typo)
			l.Result(attempt, false, typo)
			if retry := l.RetryBackoff(attempt, typo); retry != tc.want {
				t.Fatalf("one failure after %d quiet steps: backoff %v, want %v", tc.quiet, retry, tc.want)
			}
		})
	}
}

func TestAuthLimiterActiveUsernameForgetsFinishedCollision(t *testing.T) {
	t.Parallel()
	for _, tc := range decayCases() {
		t.Run(fmt.Sprintf("quiet%d", tc.quiet), func(t *testing.T) {
			t.Parallel()
			l := New(Config{MaxEntries: 16})
			const ip = "192.0.2.1"
			attack := saturate(t, l, collidingUsername(t, l, "alice"), differentSource(t, l, ip), time.Now())
			typo := attack.Add(time.Duration(tc.quiet) * 30 * time.Second)
			// Failures owned by a colliding name survive alice's successes.
			for now := attack.Add(30 * time.Second); now.Before(typo); now = now.Add(10 * time.Second) {
				l.Result(admit(t, l, "alice", ip, now), true, now)
			}
			attempt := admit(t, l, "alice", ip, typo)
			l.Result(attempt, false, typo)
			if retry := l.RetryBackoff(attempt, typo); retry != tc.want {
				t.Fatalf("one failure after %d quiet steps: backoff %v, want %v", tc.quiet, retry, tc.want)
			}
			// Ownership is released only after every retained failure is retired.
			if user := l.users[attempt.user]; tc.quiet >= 10 && (user.mixed || user.owner != attempt.username) {
				t.Fatal("forgotten collision retained failure ownership")
			}
		})
	}
}

// expiryTTLs include the minimum EntryTTL, which equals default BackoffMax, so
// a steady attacker's bucket is idle for exactly EntryTTL between failures.
func expiryTTLs() []time.Duration {
	return []time.Duration{0, 30 * time.Second, 2 * time.Minute}
}

func TestAuthLimiterSteadyFailuresHoldMaximumBackoff(t *testing.T) {
	t.Parallel()
	for _, ttl := range expiryTTLs() {
		t.Run(fmt.Sprintf("ttl%v", ttl), func(t *testing.T) {
			t.Parallel()
			l := New(Config{EntryTTL: ttl})
			now := saturate(t, l, "mallory", "192.0.2.1", time.Now())
			for i := range 100 {
				now = now.Add(30 * time.Second)
				attempt := admit(t, l, "mallory", "192.0.2.1", now)
				l.Result(attempt, false, now)
				if retry := l.RetryBackoff(attempt, now); retry != 30*time.Second {
					t.Fatalf("steady failure %d reduced backoff to %v", i, retry)
				}
			}
		})
	}
}

func TestAuthLimiterPausingCannotRaiseAttemptRate(t *testing.T) {
	t.Parallel()
	for _, ttl := range expiryTTLs() {
		t.Run(fmt.Sprintf("ttl%v", ttl), func(t *testing.T) {
			t.Parallel()
			testAuthLimiterPausingRate(t, ttl)
		})
	}
}

func testAuthLimiterPausingRate(t *testing.T, ttl time.Duration) {
	t.Helper()
	const horizon = 2 * time.Hour
	step := Config{}.WithDefaults().BackoffMax
	steady := 0
	for pause := range 12 {
		l := New(Config{EntryTTL: ttl})
		start := time.Now()
		failures := 0
		for now := start; now.Before(start.Add(horizon)); {
			attempt, retry := l.Allow("mallory", "192.0.2.1", now)
			if retry > 0 {
				now = now.Add(retry)
				continue
			}
			l.Result(attempt, false, now)
			failures++
			wait := l.RetryBackoff(attempt, now)
			if wait >= step {
				// Saturated: let failures decay or the bucket idle-expire.
				wait += time.Duration(pause) * step
			}
			now = now.Add(wait)
		}
		if pause == 0 {
			steady = failures
		}
		// Ten failures saturate default backoff; then one per BackoffMax.
		if limit := int(horizon/step) + 10; failures > limit || failures > steady {
			t.Fatalf("pausing %d steps allowed %d failures; steady %d, limit %d", pause, failures, steady, limit)
		}
	}
}
