//go:build linux

package ironport

import (
	"log"
	"sync"
	"time"

	"github.com/define42/ironport/internal/authlimit"
)

// AuthLimitConfig bounds authentication work across SSH, FTP, and HTTP.
// All non-positive fields select secure defaults; limits cannot be disabled.
// Limits apply to successful and failed authentication attempts. Source budgets
// use individual IPv4 addresses and IPv6 /64 prefixes. Addresses come only from
// the transport peer; forwarded headers are never trusted. Every supplied username
// consumes the same budgets, whether or not the account currently exists.
type AuthLimitConfig struct {
	// GlobalBurst and GlobalInterval default to 200 attempts and one token per
	// 10 ms. IPBurst/IPInterval default to 30 and one per second; UserBurst/
	// UserInterval default to 20 and one per second.
	GlobalBurst    int
	GlobalInterval time.Duration
	IPBurst        int
	IPInterval     time.Duration
	UserBurst      int
	UserInterval   time.Duration
	// MaxEntries bounds source and username buckets (default 8192).
	// A positive value must be at least two. Half the slots serve sources and
	// the remainder serve usernames. Private hashing assigns stable slots;
	// collisions share budgets and backoff rather than evicting active state
	// or rejecting all new identities when storage fills. Smaller limits
	// increase collateral throttling. EntryTTL is the minimum idle time before
	// resetting a slot, defaults to 15 minutes, and is never shorter than the
	// maximum backoff. Reset also requires full tokens, elapsed cooldown, and
	// fully decayed failures, so a short EntryTTL cannot restart backoff early.
	MaxEntries int
	EntryTTL   time.Duration
	// Backoff starts after three failed verifications and doubles after each
	// further failure. Defaults are 250 ms initial and 30 seconds maximum.
	// SSH key eligibility rejections consume tokens but do not advance backoff.
	// When BackoffInitial is unset, it is capped by BackoffMax. Explicit positive
	// values with BackoffInitial greater than BackoffMax fail Config.Validate.
	// An unset maximum is raised to an explicit initial value above 30 seconds.
	// Backoff rejects attempts immediately; it never sleeps in a handler.
	// Successful authentication clears a username slot's failure history only
	// when all retained failures belong to that username. Unsigned key queries
	// do not change failure ownership. Source and mixed-username failure state
	// is not cleared by success; each slot forgets one failure per BackoffMax
	// without another failure, so a finished attack's penalties fade while the
	// slot stays active. Steady failures still hold maximum backoff for any
	// EntryTTL.
	BackoffInitial time.Duration
	BackoffMax     time.Duration
}

// Keep the public config a root-package type; explicit conversions check that
// every setting is carried across the internal package boundary.
func normalizeAuthLimits(c AuthLimitConfig) AuthLimitConfig {
	return AuthLimitConfig(authlimit.Config(c).WithDefaults())
}

func newAuthLimiter(config AuthLimitConfig) *authlimit.Limiter {
	return authlimit.New(authlimit.Config(config))
}

func (s *Server) authControl() *authlimit.Limiter {
	s.authOnce.Do(func() {
		if s.authLimiter == nil {
			s.authLimiter = newAuthLimiter(AuthLimitConfig{})
		}
	})
	return s.authLimiter
}

func (s *Server) allowAuth(username, clientIP string) (authlimit.Attempt, time.Duration) {
	// Admission depends only on the supplied identities, so account changes
	// cannot bypass an existing username budget or cooldown.
	return s.authControl().Allow(username, clientIP, time.Now())
}

func (s *Server) authSucceeded(attempt authlimit.Attempt) {
	s.authControl().Result(attempt, true, time.Now())
}

func (s *Server) authFailed(attempt authlimit.Attempt, username, clientIP, protocol string, events chan<- AuthEvent, throttled bool) {
	if !throttled {
		s.authControl().Result(attempt, false, time.Now())
	}
	s.reportAuthFailure(username, clientIP, protocol, events, throttled)
}

// reportAuthFailure preserves rejection diagnostics without advancing backoff.
// SSH key eligibility checks use it before the client proves key ownership.
func (s *Server) reportAuthFailure(username, clientIP, protocol string, events chan<- AuthEvent, throttled bool) {
	reason := AuthFailureCredentials
	if throttled {
		reason = AuthFailureThrottled
	}
	sample, suppressed := s.authLogs.allow(time.Now())
	if sample {
		//nolint:gosec // G706: %q escapes client-controlled usernames and addresses, including CR/LF
		log.Printf("login failed protocol=%q user=%q from=%q throttled=%t suppressed=%d", protocol, username, clientIP, throttled, suppressed)
	}
	// Credential failures are emitted until the limiter engages. Floods of
	// rejected attempts are sampled along with logs to protect event consumers.
	if !throttled || sample {
		announceAuthEvent(events, AuthEvent{Type: AuthEventLoginFailed, Reason: reason, Username: username, ClientIP: clientIP, Protocol: protocol})
	}
}

type authLogSampler struct {
	mu         sync.Mutex
	next       time.Time
	suppressed uint64
}

func (s *authLogSampler) allow(now time.Time) (bool, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.Before(s.next) {
		s.suppressed++
		return false, 0
	}
	n := s.suppressed
	s.suppressed = 0
	s.next = now.Add(time.Second)
	return true, n
}

// One process-wide sampler protects the legacy channel-only event helper.
//
//nolint:gochecknoglobals // synchronized global cap on dropped-event diagnostics
var authEventDropLogs authLogSampler
