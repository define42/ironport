//go:build linux

package netconn

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestExpiringListenerExpiration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		raw := &expiringTestListener{closed: make(chan struct{})}
		var closed atomic.Int32
		deadline := time.Now().Add(time.Second)
		ln := NewExpiringListener(raw, time.Second, func() { closed.Add(1) })
		if !ln.Deadline().Equal(deadline) {
			t.Fatalf("Deadline() = %v, want %v", ln.Deadline(), deadline)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		select {
		case <-raw.closed:
		default:
			t.Fatal("listener did not expire")
		}
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() { _ = ln.Close() })
		}
		wg.Wait()
		if got := closed.Load(); got != 1 {
			t.Fatalf("onClose called %d times, want 1", got)
		}
	})
}

func TestExpiringListenerReplacementTimer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old := NewExpiringListener(&expiringTestListener{closed: make(chan struct{})}, time.Second, func() {})
		time.Sleep(500 * time.Millisecond)
		_ = old.Close()
		raw := &expiringTestListener{closed: make(chan struct{})}
		next := NewExpiringListener(raw, time.Second, func() {})
		defer func() { _ = next.Close() }()
		time.Sleep(500 * time.Millisecond)
		synctest.Wait()
		select {
		case <-raw.closed:
			t.Fatal("old reservation timer closed replacement")
		default:
		}
	})
}

func TestExpiringListenerAcceptDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		raw := &expiringDeadlineListener{expiringTestListener: &expiringTestListener{closed: make(chan struct{})}}
		ln := NewExpiringListener(raw, time.Second, func() {})
		defer func() { _ = ln.Close() }()
		expires := ln.Deadline()
		acceptDeadline := time.Now().Add(time.Minute)
		if err := ln.SetDeadline(acceptDeadline); err != nil {
			t.Fatal(err)
		}
		if !raw.deadline.Equal(acceptDeadline) {
			t.Fatalf("underlying deadline = %v, want %v", raw.deadline, acceptDeadline)
		}
		if !ln.Deadline().Equal(expires) {
			t.Fatal("accept deadline changed the listener lifetime")
		}
	})
}

type expiringTestListener struct {
	closed chan struct{}
	once   sync.Once
}

func (l *expiringTestListener) Accept() (net.Conn, error) { <-l.closed; return nil, net.ErrClosed }
func (l *expiringTestListener) Close() error              { l.once.Do(func() { close(l.closed) }); return nil }
func (*expiringTestListener) Addr() net.Addr              { return &net.TCPAddr{} }

type expiringDeadlineListener struct {
	*expiringTestListener

	deadline time.Time
}

func (l *expiringDeadlineListener) SetDeadline(deadline time.Time) error {
	l.deadline = deadline
	return nil
}
