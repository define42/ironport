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
		if retry := limiter.Allow("alice", "192.0.2.1", now); retry != 0 {
			t.Fatalf("initial burst rejected: %v", retry)
		}
	}
	// A single-token bucket is still empty after the idle TTL. Larger buckets
	// may contain a usable token without having recovered the entire burst.
	refilled := burst / 2
	later := now.Add(time.Duration(refilled)*time.Hour + 15*time.Minute)
	for range refilled {
		if retry := limiter.Allow("alice", "192.0.2.1", later); retry != 0 {
			t.Fatalf("refilled token rejected: %v", retry)
		}
	}
	if retry := limiter.Allow("alice", "192.0.2.1", later); retry != 45*time.Minute {
		t.Fatalf("idle expiry reset depleted bucket: retry = %v, want 45m", retry)
	}
}

func TestAuthLimiterExpiryPreservesDelayedBackoff(t *testing.T) {
	t.Parallel()
	limiter := New(Config{
		EntryTTL:       time.Minute,
		BackoffInitial: time.Minute,
		BackoffMax:     time.Minute,
	})
	now := time.Now()
	for range 3 {
		if retry := limiter.Allow("alice", "192.0.2.1", now); retry != 0 {
			t.Fatalf("initial attempt rejected: %v", retry)
		}
	}
	for range 2 {
		limiter.Result("alice", "192.0.2.1", false, now)
	}
	// Verification may finish well after admission. Its cooldown then extends
	// beyond the idle TTL even though every consumed token has refilled.
	limiter.Result("alice", "192.0.2.1", false, now.Add(55*time.Second))
	if retry := limiter.Allow("alice", "192.0.2.1", now.Add(time.Minute)); retry != 55*time.Second {
		t.Fatalf("idle expiry erased active backoff: retry = %v, want 55s", retry)
	}
	if retry := limiter.Allow("alice", "192.0.2.1", now.Add(115*time.Second)); retry != 0 {
		t.Fatalf("elapsed backoff rejected authentication: %v", retry)
	}
}

func TestAuthLimiterExpiryReclaimsEligibleCapacity(t *testing.T) {
	t.Parallel()
	limiter := New(Config{
		MaxEntries:   2,
		IPBurst:      1,
		IPInterval:   time.Hour,
		UserBurst:    1,
		UserInterval: time.Hour,
	})
	now := time.Now()
	if retry := limiter.Allow("alice", "192.0.2.1", now); retry != 0 {
		t.Fatalf("initial attempt rejected: %v", retry)
	}
	if retry := limiter.Allow("bob", "192.0.2.2", now.Add(15*time.Minute)); retry == 0 {
		t.Fatal("full table reclaimed depleted identities")
	}
	if got := len(limiter.entries); got != 2 {
		t.Fatalf("retained %d identities, want 2", got)
	}
	if retry := limiter.Allow("bob", "192.0.2.2", now.Add(time.Hour)); retry != 0 {
		t.Fatalf("fully refilled identities were not reclaimed: %v", retry)
	}
	if got := len(limiter.entries); got != 2 {
		t.Fatalf("retained %d identities after reclamation, want 2", got)
	}
	for _, key := range identities("alice", "192.0.2.1") {
		if limiter.entries[key] != nil {
			t.Fatal("reclaimed table still contains the old identity")
		}
	}
}
