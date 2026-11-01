package authlimit

import (
	"math"
	"time"
)

type bucket struct {
	tokens       float64
	updated      time.Time
	seen         time.Time
	blockedUntil time.Time
	// decayed starts the current failure-decay step; each failure restarts it.
	decayed  time.Time
	failures int
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

// expire only restores an idle bucket after its complete burst and cooldown
// have recovered and forget has retired every failure. Colliding identities
// cannot discard an active penalty, and an EntryTTL near BackoffMax cannot let
// an attacker who pauses until expiry restart backoff sooner than decay would.
func (b *bucket) expire(now time.Time, burst int, interval time.Duration, config Config) bool {
	if b.seen.IsZero() || now.Sub(b.seen) < config.EntryTTL {
		return false
	}
	tokens, retry := b.available(now, burst, interval)
	if tokens < float64(burst) || retry != 0 {
		return false
	}
	b.forget(now, config.BackoffMax)
	if b.failures != 0 {
		return false
	}
	*b = bucket{}
	return true
}

// forget retires one failure per complete step without another failure. Active
// buckets would otherwise retain a finished attack's penalty indefinitely,
// because successful use keeps refreshing idle expiry. With step BackoffMax, a
// steady attacker's failure replaces each retired one, so maximum backoff holds
// and waiting for decay cannot raise the long-run attempt rate.
func (b *bucket) forget(now time.Time, step time.Duration) {
	if b.failures == 0 || !now.After(b.decayed) {
		return
	}
	// steps*step cannot overflow: it never exceeds the elapsed Duration.
	steps := now.Sub(b.decayed) / step
	if steps >= time.Duration(b.failures) {
		b.failures = 0
		return
	}
	b.failures -= int(steps)
	b.decayed = b.decayed.Add(steps * step)
}

// recordFailure advances the bucket's backoff while its limiter mutex is held.
func (b *bucket) recordFailure(now time.Time, config Config) {
	b.failures++
	b.decayed = now
	if b.failures < 3 {
		return
	}
	delay, n := config.BackoffInitial, 3
	for ; n < b.failures && delay < config.BackoffMax; n++ {
		if delay > config.BackoffMax/2 {
			delay = config.BackoffMax
		} else {
			delay *= 2
		}
	}
	// Further failures cannot lengthen a saturated backoff. Capping the count
	// at saturation also bounds how long forget takes to retire an attack.
	b.failures = n
	b.blockedUntil = now.Add(min(delay, config.BackoffMax))
}

type userBucket struct {
	bucket

	owner [32]byte
	owned bool
	mixed bool
}

// observe tracks only failed verification, never an unsigned key offer or
// successful verification. Unproved identities must not prevent backoff recovery.
func (b *userBucket) observe(owner [32]byte) {
	if !b.owned {
		b.owner, b.owned = owner, true
	} else if b.owner != owner {
		b.mixed = true
	}
}

// forget also releases ownership once every retained failure has been retired,
// so failures from a finished collision cannot block a later owner's recovery.
func (b *userBucket) forget(now time.Time, step time.Duration) {
	b.bucket.forget(now, step)
	if b.failures == 0 {
		b.owner, b.owned, b.mixed = [32]byte{}, false, false
	}
}

func (b *userBucket) prepare(now time.Time, config Config) {
	if b.expire(now, config.UserBurst, config.UserInterval, config) {
		*b = userBucket{}
	}
}

// clearFailures preserves token and idle accounting while forgetting the
// successfully resolved failure history and its exclusive owner.
func (b *userBucket) clearFailures() {
	b.failures = 0
	b.blockedUntil = time.Time{}
	b.owner, b.owned, b.mixed = [32]byte{}, false, false
}
