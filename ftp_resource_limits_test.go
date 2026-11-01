//go:build linux

package ironport

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/define42/ironport/internal/netconn"
)

//nolint:gocognit // exercise each authentication reset between the same two failed attempts
func TestFTPAuthenticationFailureLimitSurvivesReset(t *testing.T) {
	for _, reset := range []string{"USER", "REIN", "successful login"} {
		t.Run(reset, func(t *testing.T) {
			s := NewServer(&Config{ResourceLimits: ResourceLimitConfig{FTPMaxAuthFailures: 2}, Users: map[string]UserInfo{
				"alice": {Password: "pw", Root: t.TempDir()},
			}})
			var response bytes.Buffer
			f := &ftpSession{server: s, clientIP: "192.0.2.1", w: bufio.NewWriter(&response), conn: &stubConn{}}
			f.handleFTPCommand("USER", "alice")
			if f.handleFTPCommand("PASS", "bad") {
				t.Fatal("first failed attempt closed session")
			}
			switch reset {
			case "USER":
				f.handleFTPCommand("USER", "missing")
			case "REIN":
				f.handleFTPCommand("REIN", "")
				f.handleFTPCommand("USER", "alice")
			case "successful login":
				f.handleFTPCommand("PASS", "pw")
				if !f.authenticated {
					t.Fatal("valid credentials did not authenticate")
				}
				f.handleFTPCommand("USER", "alice")
			}
			if !f.handleFTPCommand("PASS", "bad") {
				t.Fatal("second failed attempt did not close session")
			}
			if !strings.Contains(response.String(), "421 too many authentication failures") {
				t.Fatalf("response=%q", response.String())
			}
		})
	}
}

func waitFTPPassiveRelease(t *testing.T, s *Server) {
	t.Helper()
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		s.ftpPassiveLimits.mu.Lock()
		used := s.ftpPassiveLimits.total
		s.ftpPassiveLimits.mu.Unlock()
		if used == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("passive reservation was not released promptly")
}

func TestFTPPassivePermitHeldThroughTLSAuthentication(t *testing.T) {
	s := NewServer(&Config{ResourceLimits: ResourceLimitConfig{FTPMaxPassiveListeners: 1}})
	release, err := s.ftpPassiveLimits.reserve("u", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })
	reading := make(chan struct{})
	raw := &ftpSetupListener{conn: &ftpSetupReadSignal{Conn: serverConn, reading: reading}}
	ln := netconn.NewExpiringListener(raw, time.Minute, release)
	f := &ftpSession{server: s, dataLn: ln, dataProt: 'P', dataTLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	done := make(chan error, 1)
	go func() {
		dc, err := f.acceptDataConn()
		if dc != nil {
			_ = dc.Close()
		}
		done <- err
	}()
	select {
	case <-reading:
	case <-time.After(time.Second):
		t.Fatal("data connection did not enter TLS authentication")
	}
	if release, err := s.ftpPassiveLimits.reserve("other", "192.0.2.2"); err == nil {
		release()
		t.Fatal("accepted but unauthenticated data connection released its permit")
	}
	f.cancelDataOperations()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled TLS setup succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled TLS setup did not return")
	}
	waitFTPPassiveRelease(t, s)
}

type ftpSetupListener struct{ conn net.Conn }

func (l *ftpSetupListener) Accept() (net.Conn, error) { return l.conn, nil }
func (*ftpSetupListener) Close() error                { return nil }
func (*ftpSetupListener) Addr() net.Addr              { return &net.TCPAddr{} }

type ftpSetupReadSignal struct {
	net.Conn

	once    sync.Once
	reading chan struct{}
}

func (c *ftpSetupReadSignal) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.reading) })
	return c.Conn.Read(p)
}
