//go:build linux

package ironport

import (
	"crypto/sha256"
	"log"
	"math"
	"net/netip"
	"sync"
	"time"
)

// AuthLimitConfig bounds authentication work across SSH, FTP, and HTTP.
// All non-positive fields select secure defaults; limits cannot be disabled.
// Limits apply to successful and failed authentication attempts. Client IPs
// come only from the transport peer; forwarded headers are never trusted.
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
	// MaxEntries bounds the combined IP and username table (default 8192).
	// New identities are denied when full until entries expire. EntryTTL
	// defaults to 15 minutes and is never shorter than the maximum backoff.
	MaxEntries int
	EntryTTL   time.Duration
	// Backoff starts after three failed verifications and doubles after each
	// further failure. Defaults are 250 ms initial and 30 seconds maximum.
	// Backoff rejects attempts immediately; it never sleeps in a handler.
	// Successful authentication clears only that username's backoff; shared-IP
	// failure state remains until the entry expires.
	BackoffInitial time.Duration
	BackoffMax     time.Duration
}

func normalizeAuthLimits(c AuthLimitConfig) AuthLimitConfig {
	if c.GlobalBurst <= 0 {
		c.GlobalBurst = 200
	}
	if c.GlobalInterval <= 0 {
		c.GlobalInterval = 10 * time.Millisecond
	}
	if c.IPBurst <= 0 {
		c.IPBurst = 30
	}
	if c.IPInterval <= 0 {
		c.IPInterval = time.Second
	}
	if c.UserBurst <= 0 {
		c.UserBurst = 20
	}
	if c.UserInterval <= 0 {
		c.UserInterval = time.Second
	}
	if c.MaxEntries < 2 {
		c.MaxEntries = 8192
	}
	if c.EntryTTL <= 0 {
		c.EntryTTL = 15 * time.Minute
	}
	if c.BackoffInitial <= 0 {
		c.BackoffInitial = 250 * time.Millisecond
	}
	if c.BackoffMax <= 0 {
		c.BackoffMax = 30 * time.Second
	}
	if c.BackoffMax < c.BackoffInitial {
		c.BackoffMax = c.BackoffInitial
	}
	if c.EntryTTL < c.BackoffMax {
		c.EntryTTL = c.BackoffMax
	}
	return c
}

type authBucket struct {
	tokens       float64
	updated      time.Time
	seen         time.Time
	blockedUntil time.Time
	failures     int
}

// available reports the bucket's refilled token count and any required wait
// without mutating the bucket. Callers can therefore inspect every bucket
// before committing an authentication attempt to any of them.
func (b *authBucket) available(now time.Time, burst int, interval time.Duration) (float64, time.Duration) {
	tokens := b.tokens
	if b.updated.IsZero() {
		tokens = float64(burst)
	} else if now.After(b.updated) {
		tokens = math.Min(float64(burst), tokens+float64(now.Sub(b.updated))/float64(interval))
	}
	if now.Before(b.blockedUntil) {
		return tokens, b.blockedUntil.Sub(now)
	}
	if tokens < 1 {
		return tokens, time.Duration(math.Ceil((1 - tokens) * float64(interval)))
	}
	return tokens, 0
}

func (b *authBucket) consume(now time.Time, tokens float64) {
	b.tokens = tokens - 1
	b.updated = now
	b.seen = now
}

type authIdentity struct {
	kind byte
	hash [32]byte
}

func authIdentities(username, clientIP string) [2]authIdentity {
	if ip, err := netip.ParseAddr(clientIP); err == nil {
		clientIP = ip.Unmap().String()
	} else {
		// Invalid/missing transport addresses share a single bucket, preventing
		// callers from creating unbounded distinct non-IP identities.
		clientIP = "unknown"
	}
	return [2]authIdentity{{kind: 'i', hash: sha256.Sum256([]byte(clientIP))}, {kind: 'u', hash: sha256.Sum256([]byte(username))}}
}

type authLimiter struct {
	mu        sync.Mutex
	config    AuthLimitConfig
	global    authBucket
	entries   map[authIdentity]*authBucket
	nextSweep time.Time
	logs      authLogSampler
}

func newAuthLimiter(config AuthLimitConfig) *authLimiter {
	return &authLimiter{config: normalizeAuthLimits(config), entries: make(map[authIdentity]*authBucket)}
}

func (s *Server) authControl() *authLimiter {
	s.authOnce.Do(func() {
		if s.authLimiter == nil {
			s.authLimiter = newAuthLimiter(AuthLimitConfig{})
		}
	})
	return s.authLimiter
}

func (s *Server) allowAuth(username, clientIP string) time.Duration {
	return s.authControl().allow(username, clientIP, time.Now())
}

func (l *authLimiter) allow(username, clientIP string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	globalTokens, retry := l.global.available(now, l.config.GlobalBurst, l.config.GlobalInterval)
	if retry > 0 {
		return retry
	}
	// Inspect the global bucket first so an exhausted process-wide bucket
	// rejects before identity hashing. Do not consume it until every identity
	// bucket and the bounded identity table have also admitted the request.
	keys := authIdentities(username, clientIP)
	if !now.Before(l.nextSweep) {
		for key, bucket := range l.entries {
			if now.Sub(bucket.seen) >= l.config.EntryTTL {
				delete(l.entries, key)
			}
		}
		l.nextSweep = now.Add(min(time.Minute, l.config.EntryTTL))
	}
	missing := 0
	for _, key := range keys {
		if l.entries[key] == nil {
			missing++
		}
	}
	if len(l.entries)+missing > l.config.MaxEntries {
		return time.Second
	}
	var buckets [2]*authBucket
	var tokens [2]float64
	for i, key := range keys {
		b := l.entries[key]
		buckets[i] = b
		burst, interval := l.config.IPBurst, l.config.IPInterval
		if i == 1 {
			burst, interval = l.config.UserBurst, l.config.UserInterval
		}
		if b == nil {
			tokens[i] = float64(burst)
			continue
		}
		var bucketRetry time.Duration
		tokens[i], bucketRetry = b.available(now, burst, interval)
		retry = max(retry, bucketRetry)
	}
	if retry > 0 {
		return retry
	}

	// The mutex makes the checks and commits one transaction: no bucket state
	// can change between inspection and consumption.
	l.global.consume(now, globalTokens)
	for i, key := range keys {
		b := buckets[i]
		if b == nil {
			b = &authBucket{}
			l.entries[key] = b
		}
		b.consume(now, tokens[i])
	}
	return 0
}

func (l *authLimiter) result(username, clientIP string, success bool, now time.Time) {
	keys := authIdentities(username, clientIP)
	l.mu.Lock()
	defer l.mu.Unlock()
	if success {
		// A successful username proves nothing about other authentication
		// attempts from the same IP. Preserve shared-IP backoff so one valid
		// low-privilege account cannot mask password spraying against others.
		if b := l.entries[keys[1]]; b != nil {
			b.failures = 0
			b.blockedUntil = time.Time{}
		}
		return
	}
	for _, key := range keys {
		b := l.entries[key]
		if b == nil {
			continue
		}
		// Saturating count avoids integer overflow under prolonged attacks.
		if b.failures < 64 {
			b.failures++
		}
		if b.failures < 3 {
			continue
		}
		delay := l.config.BackoffInitial
		for n := 3; n < b.failures && delay < l.config.BackoffMax; n++ {
			if delay > l.config.BackoffMax/2 {
				delay = l.config.BackoffMax
				break
			}
			delay *= 2
		}
		b.blockedUntil = now.Add(min(delay, l.config.BackoffMax))
	}
}

func (s *Server) authSucceeded(username, clientIP string) {
	s.authControl().result(username, clientIP, true, time.Now())
}

func (s *Server) authFailed(username, clientIP, protocol string, events chan<- AuthEvent, throttled bool) {
	l := s.authControl()
	if !throttled {
		l.result(username, clientIP, false, time.Now())
	}
	sample, suppressed := l.logs.allow(time.Now())
	if sample {
		log.Printf("login failed protocol=%q user=%q from=%q throttled=%t suppressed=%d", protocol, username, clientIP, throttled, suppressed)
	}
	// Credential failures are emitted until the limiter engages. Floods of
	// rejected attempts are sampled along with logs to protect event consumers.
	if !throttled || sample {
		announceAuthEvent(events, AuthEvent{Type: AuthEventLoginFailed, Username: username, ClientIP: clientIP, Protocol: protocol})
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
