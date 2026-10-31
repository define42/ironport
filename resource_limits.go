//go:build linux

package ironport

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/pkg/sftp"
)

const (
	defaultMaxConnections           = 128
	defaultMaxConnectionsPerIP      = 32
	defaultFTPAuthTimeout           = 30 * time.Second
	defaultSFTPMaxHandles           = 256
	defaultSFTPMaxHandlesPerUser    = 64
	defaultSFTPMaxHandlesPerSession = 32
)

func positiveLimit(value, fallback int) int {
	if value <= 0 {
		return fallback
	}
	return value
}

func positiveDuration(value, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}

func canonicalClientIP(value string) string {
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return value
}

// handleBudget owns all counters, including session counters. Empty user
// entries are removed on release, so its memory is bounded by open handles.
type handleBudget struct {
	mu                       sync.Mutex
	max, maxUser, maxSession int
	used                     int
	users                    map[string]int
}

type sessionHandleBudget struct {
	owner    *handleBudget
	username string
	used     int // guarded by owner.mu
}

func (b *sessionHandleBudget) acquire() (func(), error) {
	// Standalone filesystem handlers used by internal tests have no server.
	// Every production SSH connection supplies a shared budget.
	if b == nil || b.owner == nil {
		return func() {}, nil
	}
	g := b.owner
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.used >= positiveLimit(g.max, defaultSFTPMaxHandles) ||
		g.users[b.username] >= positiveLimit(g.maxUser, defaultSFTPMaxHandlesPerUser) ||
		b.used >= positiveLimit(g.maxSession, defaultSFTPMaxHandlesPerSession) {
		return nil, sftp.ErrSSHFxFailure
	}
	if g.users == nil {
		g.users = make(map[string]int)
	}
	g.used++
	g.users[b.username]++
	b.used++
	return sync.OnceFunc(func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.used--
		b.used--
		g.users[b.username]--
		if g.users[b.username] == 0 {
			delete(g.users, b.username)
		}
	}), nil
}

type budgetReader struct {
	*managedFile
	once     sync.Once
	release  func()
	closeErr error
}

func (f *budgetReader) Close() error {
	f.once.Do(func() {
		defer f.release()
		f.closeErr = f.managedFile.Close()
	})
	return f.closeErr
}

type budgetWriter struct {
	*writeLogger
	once     sync.Once
	release  func()
	closeErr error
}

func (f *budgetWriter) Close() error {
	f.once.Do(func() {
		defer f.release()
		f.closeErr = f.writeLogger.Close()
	})
	return f.closeErr
}

type budgetLister struct {
	sftp.ListerAt
	closer   io.Closer
	once     sync.Once
	release  func()
	closeErr error
}

func (f *budgetLister) Close() error {
	f.once.Do(func() {
		defer f.release()
		f.closeErr = f.closer.Close()
	})
	return f.closeErr
}
