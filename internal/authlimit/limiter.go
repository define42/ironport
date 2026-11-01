// Package authlimit bounds authentication work with shared token buckets and backoff.
package authlimit

import (
	"crypto/sha256"
	"hash/maphash"
	"net/netip"
	"sync"
	"time"
)

// Attempt identifies the buckets charged by a successful admission. Its zero
// value is invalid. Retain it through verification so results and SSH proofs
// use exactly the source and username slots charged at admission.
type Attempt struct {
	owner    *Limiter
	ip       int
	user     int
	username [32]byte
}

// Limiter shares authentication budgets and backoff across concurrent callers.
// Fixed, privately hashed partitions bound memory without a table-full lockout.
// Collisions share limits conservatively; they never replace active state.
// Construct it with New; its zero value is not ready for use.
type Limiter struct {
	mu        sync.Mutex
	config    Config
	seed      maphash.Seed
	global    bucket
	ips       map[int]*bucket
	users     map[int]*userBucket
	ipCount   int
	userCount int
	lastTime  time.Time
}

// New creates a limiter with MaxEntries lazily allocated slots, split between
// source addresses and supplied usernames. Account existence never changes
// admission or result accounting.
func New(config Config) *Limiter {
	config = config.WithDefaults()
	ipCount := config.MaxEntries / 2
	return &Limiter{
		config:    config,
		seed:      maphash.MakeSeed(),
		ips:       make(map[int]*bucket),
		users:     make(map[int]*userBucket),
		ipCount:   ipCount,
		userCount: config.MaxEntries - ipCount,
	}
}

// sourceIdentity groups IPv6 hosts by /64, ignoring interface zones. IPv4 and
// IPv4-mapped IPv6 addresses share their exact IPv4 identity.
func sourceIdentity(clientIP string) string {
	ip, err := netip.ParseAddr(clientIP)
	if err != nil {
		return "unknown"
	}
	ip = ip.Unmap().WithZone("")
	if ip.Is6() {
		return netip.PrefixFrom(ip, 64).Masked().String()
	}
	return ip.String()
}

func (l *Limiter) locate(username, clientIP string) Attempt {
	attempt := Attempt{owner: l, username: sha256.Sum256([]byte(username))}
	attempt.ip = slotIndex(maphash.String(l.seed, sourceIdentity(clientIP)), l.ipCount)
	attempt.user = slotIndex(maphash.Bytes(l.seed, attempt.username[:]), l.userCount)
	return attempt
}

func slotIndex(hash uint64, count int) int {
	if count <= 0 {
		return -1
	}
	//nolint:gosec // G115: modulo a positive int bounds the result below count and therefore MaxInt.
	return int(hash % uint64(count))
}

func (l *Limiter) valid(attempt Attempt) bool {
	return attempt.owner == l && attempt.owner != nil &&
		attempt.ip >= 0 && attempt.ip < l.ipCount &&
		attempt.user >= 0 && attempt.user < l.userCount
}

// advanceTime serializes caller timestamps while l.mu is held. Never move
// refill, idle-expiry, or backoff accounting back for a queued caller.
func (l *Limiter) advanceTime(now time.Time) time.Time {
	if now.After(l.lastTime) {
		l.lastTime = now
	}
	return l.lastTime
}

// Allow consumes one attempt when every applicable bucket admits it. A positive
// retry returns an invalid Attempt and consumes no tokens. Every supplied
// username receives the same controls, including nonexistent accounts.
func (l *Limiter) Allow(username, clientIP string, now time.Time) (Attempt, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ipCount == 0 || l.userCount == 0 {
		return Attempt{}, time.Second
	}
	now = l.advanceTime(now)
	globalTokens, retry := l.global.available(now, l.config.GlobalBurst, l.config.GlobalInterval)
	if retry > 0 {
		return Attempt{}, retry
	}
	// Check the global budget before hashing attacker-controlled identities.
	attempt := l.locate(username, clientIP)
	tokens, retry := l.available(attempt, now)
	if retry > 0 {
		return Attempt{}, retry
	}
	l.global.consume(now, globalTokens)
	if l.ips[attempt.ip] == nil {
		l.ips[attempt.ip] = &bucket{}
	}
	l.ips[attempt.ip].consume(now, tokens[0])
	if l.users[attempt.user] == nil {
		l.users[attempt.user] = &userBucket{}
	}
	l.users[attempt.user].consume(now, tokens[1])
	return attempt, 0
}

func (l *Limiter) available(attempt Attempt, now time.Time) ([2]float64, time.Duration) {
	var tokens [2]float64
	var retry time.Duration
	tokens[0], retry = l.ipAvailable(attempt.ip, now)
	var userRetry time.Duration
	tokens[1], userRetry = l.userAvailable(attempt.user, now)
	return tokens, max(retry, userRetry)
}

func (l *Limiter) ipAvailable(slot int, now time.Time) (float64, time.Duration) {
	ip := l.ips[slot]
	if ip == nil {
		return float64(l.config.IPBurst), 0
	}
	ip.expire(now, l.config.IPBurst, l.config.IPInterval, l.config)
	return ip.available(now, l.config.IPBurst, l.config.IPInterval)
}

func (l *Limiter) userAvailable(slot int, now time.Time) (float64, time.Duration) {
	user := l.users[slot]
	if user == nil {
		return float64(l.config.UserBurst), 0
	}
	user.prepare(now, l.config)
	return user.available(now, l.config.UserBurst, l.config.UserInterval)
}

// RetryBackoff checks an admitted attempt without charging another token. SSH
// uses it between a public-key query and proof. Invalid/foreign attempts fail
// closed; callers must obtain a fresh admission instead of manufacturing one.
func (l *Limiter) RetryBackoff(attempt Attempt, now time.Time) time.Duration {
	if !l.valid(attempt) {
		return time.Second
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ips[attempt.ip] == nil || l.users[attempt.user] == nil {
		return time.Second
	}
	now = l.advanceTime(now)
	retry := max(time.Duration(0), l.ips[attempt.ip].blockedUntil.Sub(now))
	return max(retry, l.users[attempt.user].blockedUntil.Sub(now))
}

// Result records completed verification against the original admission slots.
// Invalid/foreign attempts are ignored. Success never clears source penalties
// or a username slot containing failures from distinct usernames; those decay
// by one failure per BackoffMax without another failure.
func (l *Limiter) Result(attempt Attempt, success bool, now time.Time) {
	if !l.valid(attempt) {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ips[attempt.ip] == nil || l.users[attempt.user] == nil {
		return
	}
	now = l.advanceTime(now)
	ip := l.ips[attempt.ip]
	ip.seen = now
	ip.forget(now, l.config.BackoffMax)
	if !success {
		ip.recordFailure(now, l.config)
	}
	user := l.users[attempt.user]
	user.seen = now
	user.forget(now, l.config.BackoffMax)
	if !success {
		// A delayed failure may arrive after idle expiry and a new owner.
		user.observe(attempt.username)
		user.recordFailure(now, l.config)
	} else if user.owned && !user.mixed && user.owner == attempt.username {
		user.clearFailures()
	}
}
