package authlimit

import (
	"math"
	"testing"
	"time"
)

func TestLimiterExtremeRefillIntervals(t *testing.T) {
	t.Parallel()
	for _, interval := range []struct {
		name             string
		value, wantRetry time.Duration
	}{
		{"maximum", time.Duration(math.MaxInt64), time.Duration(math.MaxInt64)},
		{"rounds above maximum", time.Duration(math.MaxInt64 - 1), time.Duration(math.MaxInt64)},
		{"below rounding boundary", time.Duration(math.MaxInt64 - 1023), time.Duration(math.MaxInt64 - 1023)},
	} {
		for _, bucket := range []struct {
			name   string
			config Config
		}{
			{"global", Config{GlobalBurst: 1, GlobalInterval: interval.value}},
			{"IP", Config{IPBurst: 1, IPInterval: interval.value}},
			{"username", Config{UserBurst: 1, UserInterval: interval.value}},
		} {
			t.Run(interval.name+"/"+bucket.name, func(t *testing.T) {
				t.Parallel()
				testLimiterExtremeRefill(t, New(bucket.config), interval.value, interval.wantRetry)
			})
		}
	}
}

func testLimiterExtremeRefill(t *testing.T, limiter *Limiter, interval, wantRetry time.Duration) {
	t.Helper()
	now := time.Now()
	if retry := limiter.Allow("alice", "192.0.2.1", now); retry != 0 {
		t.Fatalf("initial attempt rejected: %v", retry)
	}
	for range 2 {
		if retry := limiter.Allow("alice", "192.0.2.1", now); retry != wantRetry {
			t.Fatalf("exhausted bucket retry = %v; want %v", retry, wantRetry)
		}
	}
	if retry := limiter.Allow("alice", "192.0.2.1", now.Add(interval/2)); retry <= 0 || retry >= wantRetry {
		t.Fatalf("partially refilled bucket retry = %v; want a shorter positive wait", retry)
	}
	recovered := now.Add(interval)
	if retry := limiter.Allow("alice", "192.0.2.1", recovered); retry != 0 {
		t.Fatalf("refilled bucket rejected: %v", retry)
	}
	if retry := limiter.Allow("alice", "192.0.2.1", recovered); retry != wantRetry {
		t.Fatalf("refilled token was not consumed: retry = %v; want %v", retry, wantRetry)
	}
}
