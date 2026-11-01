//go:build linux

package netconn

import (
	"net"
	"sync"
	"time"
)

// ExpiringListener closes its listener after a fixed lifetime and invokes
// its on-close callback exactly once. Each timer owns only its own listener.
type ExpiringListener struct {
	net.Listener

	deadline time.Time
	mu       sync.Mutex
	timer    *time.Timer
	once     sync.Once
	err      error
	onClose  func()
}

// NewExpiringListener starts the lifetime immediately. onClose must be non-nil
// and is called after the underlying listener closes, even if Close fails.
func NewExpiringListener(ln net.Listener, lifetime time.Duration, onClose func()) *ExpiringListener {
	l := &ExpiringListener{Listener: ln, deadline: time.Now().Add(lifetime), onClose: onClose}
	l.mu.Lock()
	l.timer = time.AfterFunc(lifetime, func() { _ = l.Close() })
	l.mu.Unlock()
	return l
}

// Close stops expiration, closes the listener, and calls onClose once.
func (l *ExpiringListener) Close() error {
	l.once.Do(func() {
		l.mu.Lock()
		l.timer.Stop()
		l.mu.Unlock()
		l.err = l.Listener.Close()
		l.onClose()
	})
	return l.err
}

// Deadline returns the fixed expiration time established at construction.
func (l *ExpiringListener) Deadline() time.Time {
	return l.deadline
}

// SetDeadline forwards an accept deadline when the underlying listener supports
// it. It does not change the fixed expiration time returned by Deadline.
func (l *ExpiringListener) SetDeadline(deadline time.Time) error {
	if tcp, ok := l.Listener.(interface{ SetDeadline(time.Time) error }); ok {
		return tcp.SetDeadline(deadline)
	}
	return nil
}
