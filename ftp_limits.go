//go:build linux

package ironport

import (
	"errors"
	"net"
	"sync"

	"github.com/define42/ironport/internal/netconn"
)

const (
	defaultFTPMaxPassiveListeners        = 64
	defaultFTPMaxPassiveListenersPerUser = 2
	defaultFTPMaxPassiveListenersPerIP   = 8
)

var errFTPPassiveLimit = errors.New("passive listener limit reached")

// ftpPassiveLimits accounts for reserved ports, including listeners currently
// accepting and authenticating a data connection. Entries disappear on release
// so a stream of distinct users or source addresses cannot grow the maps.
type ftpPassiveLimits struct {
	mu         sync.Mutex
	maxTotal   int
	maxPerUser int
	maxPerIP   int
	total      int
	users      map[string]int
	ips        map[string]int
}

func newFTPPassiveLimits(config *Config) ftpPassiveLimits {
	return ftpPassiveLimits{
		maxTotal:   positiveFTPLimit(config.ResourceLimits.FTPMaxPassiveListeners, defaultFTPMaxPassiveListeners),
		maxPerUser: positiveFTPLimit(config.ResourceLimits.FTPMaxPassiveListenersPerUser, defaultFTPMaxPassiveListenersPerUser),
		maxPerIP:   positiveFTPLimit(config.ResourceLimits.FTPMaxPassiveListenersPerIP, defaultFTPMaxPassiveListenersPerIP),
	}
}

func positiveFTPLimit(value, fallback int) int {
	if value <= 0 {
		return fallback
	}
	return value
}

func (l *ftpPassiveLimits) reserve(username, ip string) (func(), error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Retain secure defaults for zero-value Servers used by embedders/tests.
	if l.total >= positiveFTPLimit(l.maxTotal, defaultFTPMaxPassiveListeners) ||
		l.users[username] >= positiveFTPLimit(l.maxPerUser, defaultFTPMaxPassiveListenersPerUser) ||
		l.ips[ip] >= positiveFTPLimit(l.maxPerIP, defaultFTPMaxPassiveListenersPerIP) {
		return nil, errFTPPassiveLimit
	}
	if l.users == nil {
		l.users = make(map[string]int)
		l.ips = make(map[string]int)
	}
	l.total++
	l.users[username]++
	l.ips[ip]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.total--
			l.users[username]--
			if l.users[username] == 0 {
				delete(l.users, username)
			}
			l.ips[ip]--
			if l.ips[ip] == 0 {
				delete(l.ips, ip)
			}
		})
	}, nil
}

func (s *Server) listenReservedFTPData(host, username, ip string) (net.Listener, error) {
	release, err := s.ftpPassiveLimits.reserve(username, ip)
	if err != nil {
		return nil, err
	}
	ln, err := s.listenFTPData(host)
	if err != nil {
		release()
		return nil, err
	}
	timeout := s.effectiveFTPDataAcceptTimeout()
	if timeout <= 0 {
		timeout = defaultFTPDataAcceptTimeout
	}
	return netconn.NewExpiringListener(ln, timeout, release), nil
}
