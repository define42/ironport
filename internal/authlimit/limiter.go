// Package authlimit bounds authentication work with shared token buckets and backoff.
package authlimit

import (
	"crypto/sha256"
	"math"
	"net/netip"
	"sync"
	"time"
)

type bucket struct {
	tokens       float64
	updated      time.Time
	seen         time.Time
	blockedUntil time.Time
	failures     int
}

// available reports the bucket's refilled token count and any required wait
// without mutating the bucket. Callers can therefore inspect every bucket
// before committing an authentication attempt to any of them.
func (b *bucket) available(now time.Time, burst int, interval time.Duration) (float64, time.Duration) {
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
		retry := math.Ceil((1 - tokens) * float64(interval))
		// float64 rounds MaxInt64 up to 2^63. Saturate before converting so
		// a long refill interval cannot wrap negative and admit extra work.
		if retry >= float64(math.MaxInt64) {
			return tokens, time.Duration(math.MaxInt64)
		}
		return tokens, time.Duration(retry)
	}
	return tokens, 0
}

func (b *bucket) consume(now time.Time, tokens float64) {
	b.tokens = tokens - 1
	b.updated = now
	b.seen = now
}

type identity struct {
	kind byte
	hash [32]byte
}

func identities(username, clientIP string) [2]identity {
	if ip, err := netip.ParseAddr(clientIP); err == nil {
		clientIP = ip.Unmap().String()
	} else {
		// Invalid/missing transport addresses share a single bucket, preventing
		// callers from creating unbounded distinct non-IP identities.
		clientIP = "unknown"
	}
	return [2]identity{{kind: 'i', hash: sha256.Sum256([]byte(clientIP))}, {kind: 'u', hash: sha256.Sum256([]byte(username))}}
}

// Limiter shares authentication budgets and backoff across concurrent callers.
// Construct it with New; its zero value is not ready for use.
type Limiter struct {
	mu        sync.Mutex
	config    Config
	global    bucket
	entries   map[identity]*bucket
	nextSweep time.Time
	lastTime  time.Time
}

// New creates an authentication limiter with bounded identity storage.
func New(config Config) *Limiter {
	return &Limiter{config: config.WithDefaults(), entries: make(map[identity]*bucket)}
}

// advanceTime serializes caller timestamps while l.mu is held. Callers may
// capture time before waiting for the mutex, so arrival order can differ from
// timestamp order. Never move refill, idle-expiry, or backoff accounting back.
func (l *Limiter) advanceTime(now time.Time) time.Time {
	if now.After(l.lastTime) {
		l.lastTime = now
	}
	return l.lastTime
}

// Allow consumes one attempt when every bucket and the identity table admit it.
// It returns zero on admission or the required retry delay on rejection.
func (l *Limiter) Allow(username, clientIP string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now = l.advanceTime(now)
	globalTokens, retry := l.global.available(now, l.config.GlobalBurst, l.config.GlobalInterval)
	if retry > 0 {
		return retry
	}
	// Inspect the global bucket first so an exhausted server-wide bucket
	// rejects before identity hashing. Do not consume it until every identity
	// bucket and the bounded identity table have also admitted the request.
	keys := identities(username, clientIP)
	l.expireEntries(now)
	missing := 0
	for _, key := range keys {
		if l.entries[key] == nil {
			missing++
		}
	}
	if len(l.entries)+missing > l.config.MaxEntries {
		return time.Second
	}
	var buckets [2]*bucket
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
			b = &bucket{}
			l.entries[key] = b
		}
		b.consume(now, tokens[i])
	}
	return 0
}

// RetryBackoff checks an already-admitted attempt without consuming another
// token. SSH uses it when a public-key query is followed by signature proof.
func (l *Limiter) RetryBackoff(username, clientIP string, now time.Time) time.Duration {
	keys := identities(username, clientIP)
	l.mu.Lock()
	defer l.mu.Unlock()
	now = l.advanceTime(now)
	var retry time.Duration
	for _, key := range keys {
		if bucket := l.entries[key]; bucket != nil && now.Before(bucket.blockedUntil) {
			retry = max(retry, bucket.blockedUntil.Sub(now))
		}
	}
	return retry
}

// expireEntries reclaims inactive identities while l.mu is held.
func (l *Limiter) expireEntries(now time.Time) {
	if now.Before(l.nextSweep) {
		return
	}
	for key, bucket := range l.entries {
		if now.Sub(bucket.seen) < l.config.EntryTTL {
			continue
		}
		// Recreating an identity grants a full burst, so retain any token
		// deficit and any cooldown established after its last admission.
		burst, interval := l.config.IPBurst, l.config.IPInterval
		if key.kind == 'u' {
			burst, interval = l.config.UserBurst, l.config.UserInterval
		}
		tokens, retry := bucket.available(now, burst, interval)
		if tokens >= float64(burst) && retry == 0 {
			delete(l.entries, key)
		}
	}
	l.nextSweep = now.Add(min(time.Minute, l.config.EntryTTL))
}

// Result records a completed credential verification for an admitted attempt.
func (l *Limiter) Result(username, clientIP string, success bool, now time.Time) {
	keys := identities(username, clientIP)
	l.mu.Lock()
	defer l.mu.Unlock()
	now = l.advanceTime(now)
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
		b.recordFailure(now, l.config)
	}
}

// recordFailure advances the bucket's backoff while its limiter mutex is held.
func (b *bucket) recordFailure(now time.Time, config Config) {
	// Saturating count avoids integer overflow under prolonged attacks.
	if b.failures < 64 {
		b.failures++
	}
	if b.failures < 3 {
		return
	}
	delay := config.BackoffInitial
	for n := 3; n < b.failures && delay < config.BackoffMax; n++ {
		if delay > config.BackoffMax/2 {
			delay = config.BackoffMax
			break
		}
		delay *= 2
	}
	b.blockedUntil = now.Add(min(delay, config.BackoffMax))
}
