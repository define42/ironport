//go:build linux

package ironport

import (
	"strings"
	"testing"
	"time"
)

func TestConfigValidateLimits(t *testing.T) {
	for _, tt := range []struct {
		name      string
		config    *Config
		wantError string
	}{
		{name: "nil"},
		{name: "zero", config: &Config{}},
		{name: "defaults", config: DefaultConfig()},
		{name: "negative selects defaults", config: &Config{AuthLimits: AuthLimitConfig{MaxEntries: -1}}},
		{name: "identity pair", config: &Config{AuthLimits: AuthLimitConfig{MaxEntries: 2}}},
		{name: "identity too small", config: &Config{AuthLimits: AuthLimitConfig{MaxEntries: 1}}, wantError: "AuthLimits.MaxEntries"},
		{name: "small maximum", config: &Config{AuthLimits: AuthLimitConfig{BackoffMax: time.Millisecond}}},
		{name: "large initial", config: &Config{AuthLimits: AuthLimitConfig{BackoffInitial: time.Minute}}},
		{name: "contradictory backoff", config: &Config{AuthLimits: AuthLimitConfig{BackoffInitial: time.Second, BackoffMax: time.Millisecond}}, wantError: "AuthLimits.BackoffInitial"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("Validate() = %v; want error containing %q", err, tt.wantError)
			}
		})
	}
}

func TestInvalidLimitsPreventListen(t *testing.T) {
	config := DefaultConfig()
	config.AuthLimits.MaxEntries = 1
	s := NewServer(config)
	// Later mutation cannot bypass the invalid configuration captured at creation.
	config.AuthLimits.MaxEntries = 2
	if err := s.ListenAndServe(); err == nil || !strings.Contains(err.Error(), "AuthLimits.MaxEntries") {
		t.Fatalf("ListenAndServe() = %v; want invalid limit error", err)
	}
	if s.ln != nil || s.ftpLn != nil || s.serving || s.sftpSigner != nil {
		t.Fatal("invalid limits started listener preparation")
	}
}

func TestAuthExplicitBackoffBounds(t *testing.T) {
	for _, tt := range []struct {
		name   string
		config AuthLimitConfig
		want   time.Duration
	}{
		{name: "initial above default maximum", config: AuthLimitConfig{BackoffInitial: time.Minute}, want: time.Minute},
		{name: "maximum below default initial", config: AuthLimitConfig{BackoffMax: 100 * time.Millisecond}, want: 100 * time.Millisecond},
	} {
		t.Run(tt.name, func(t *testing.T) {
			limiter := newAuthLimiter(tt.config)
			now := time.Now()
			for range 3 {
				if retry := limiter.Allow("u", "192.0.2.1", now); retry != 0 {
					t.Fatalf("attempt before backoff: %v", retry)
				}
				limiter.Result("u", "192.0.2.1", false, now)
			}
			if retry := limiter.Allow("u", "192.0.2.1", now); retry != tt.want {
				t.Fatalf("backoff = %v; want configured bound %v", retry, tt.want)
			}
			if retry := limiter.Allow("u", "192.0.2.1", now.Add(tt.want)); retry != 0 {
				t.Fatalf("bound elapsed but authentication still blocked for %v", retry)
			}
		})
	}
}
