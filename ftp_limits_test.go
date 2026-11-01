//go:build linux

package ironport

import (
	"errors"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/define42/ironport/internal/netconn"
)

//nolint:gocognit // each independent cap verifies concurrent release and subsequent reuse
func TestFTPPassiveLimits(t *testing.T) {
	for _, tt := range []struct {
		name         string
		config       Config
		username, ip string
	}{
		{name: "global", config: Config{ResourceLimits: ResourceLimitConfig{FTPMaxPassiveListeners: 1}}, username: "other", ip: "192.0.2.2"},
		{name: "user", config: Config{ResourceLimits: ResourceLimitConfig{FTPMaxPassiveListenersPerUser: 1}}, username: "u", ip: "192.0.2.2"},
		{name: "IP", config: Config{ResourceLimits: ResourceLimitConfig{FTPMaxPassiveListenersPerIP: 1}}, username: "other", ip: "192.0.2.1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			limits := newFTPPassiveLimits(&tt.config)
			release, err := limits.reserve("u", "192.0.2.1")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := limits.reserve(tt.username, tt.ip); !errors.Is(err, errFTPPassiveLimit) {
				t.Fatalf("reserve over %s cap: %v", tt.name, err)
			}
			var wg sync.WaitGroup
			for range 8 {
				wg.Go(release)
			}
			wg.Wait()
			if limits.total != 0 || len(limits.users) != 0 || len(limits.ips) != 0 {
				t.Fatal("release did not clear accounting exactly once")
			}
			release, err = limits.reserve(tt.username, tt.ip)
			if err != nil {
				t.Fatalf("reserve after release: %v", err)
			}
			release()
		})
	}
}

func TestFTPPassiveListenerExpiration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		limits := newFTPPassiveLimits(&Config{ResourceLimits: ResourceLimitConfig{FTPMaxPassiveListeners: 1}})
		release, err := limits.reserve("u", "192.0.2.1")
		if err != nil {
			t.Fatal(err)
		}
		raw := &ftpLimitsListener{closed: make(chan struct{})}
		ln := netconn.NewExpiringListener(raw, time.Second, release)
		time.Sleep(time.Second)
		synctest.Wait()
		select {
		case <-raw.closed:
		default:
			t.Fatal("passive listener did not expire without a transfer")
		}
		if err := ln.Close(); err != nil {
			t.Fatal(err)
		}
		release, err = limits.reserve("next", "192.0.2.2")
		if err != nil {
			t.Fatalf("expired reservation retained permit: %v", err)
		}
		release()
	})
}

func TestFTPPassiveListenFailureReleasesPermit(t *testing.T) {
	s := NewServer(&Config{FtpPassivePortRange: "invalid", ResourceLimits: ResourceLimitConfig{FTPMaxPassiveListeners: 1}})
	for range 2 {
		if ln, err := s.listenReservedFTPData("127.0.0.1", "u", "192.0.2.1"); err == nil {
			_ = ln.Close()
			t.Fatal("invalid passive port range succeeded")
		} else if errors.Is(err, errFTPPassiveLimit) {
			t.Fatal("failed listener creation leaked its reservation")
		}
	}
}

type ftpLimitsListener struct {
	closed chan struct{}
	once   sync.Once
}

func (l *ftpLimitsListener) Accept() (net.Conn, error) { <-l.closed; return nil, net.ErrClosed }
func (l *ftpLimitsListener) Close() error              { l.once.Do(func() { close(l.closed) }); return nil }
func (*ftpLimitsListener) Addr() net.Addr              { return &net.TCPAddr{} }
