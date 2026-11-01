package authlimit

import "time"

// Config sets token-bucket, fixed-slot, and backoff limits.
// Non-positive fields select defaults. Callers validate contradictory settings.
type Config struct {
	GlobalBurst    int
	GlobalInterval time.Duration
	IPBurst        int
	IPInterval     time.Duration
	UserBurst      int
	UserInterval   time.Duration
	MaxEntries     int
	EntryTTL       time.Duration
	BackoffInitial time.Duration
	BackoffMax     time.Duration
}

// WithDefaults returns a copy with defaults and dependent bounds applied.
func (c Config) WithDefaults() Config {
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
	if c.MaxEntries <= 0 {
		c.MaxEntries = 8192
	}
	if c.EntryTTL <= 0 {
		c.EntryTTL = 15 * time.Minute
	}
	if c.BackoffInitial <= 0 {
		c.BackoffInitial = 250 * time.Millisecond
	}
	if c.BackoffMax <= 0 {
		c.BackoffMax = max(30*time.Second, c.BackoffInitial)
	}
	if c.BackoffInitial > c.BackoffMax {
		c.BackoffInitial = c.BackoffMax
	}
	if c.EntryTTL < c.BackoffMax {
		c.EntryTTL = c.BackoffMax
	}
	return c
}
