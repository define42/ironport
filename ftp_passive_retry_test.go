//go:build linux

package ironport

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/define42/ironport/internal/netconn"
)

func TestFTPPassiveRetryAcceptsMatchingPeer(t *testing.T) {
	foreign := newFTPRetryPeer("192.0.2.2")
	legitimate := newFTPRetryPeer("192.0.2.1")
	raw := newFTPRetryListener(foreign, legitimate)
	var released atomic.Int32
	ln := netconn.NewExpiringListener(raw, time.Minute, func() { released.Add(1) })
	t.Cleanup(func() { _ = ln.Close() })
	f := &ftpSession{server: NewServer(&Config{}), clientIP: "192.0.2.1", dataLn: ln}
	dc, err := f.acceptDataConn()
	if err != nil || dc != legitimate {
		t.Fatalf("accepted connection = %v, %v; want legitimate peer", dc, err)
	}
	defer func() { _ = dc.Close() }()
	if raw.accepts != 2 || foreign.closed.Load() != 1 || legitimate.closed.Load() != 0 {
		t.Fatalf("accepts=%d, foreign closes=%d, legitimate closes=%d", raw.accepts, foreign.closed.Load(), legitimate.closed.Load())
	}
	if released.Load() != 1 || raw.closeCount.Load() != 1 {
		t.Fatal("successful setup did not release the passive reservation exactly once")
	}
	if !raw.deadline.Equal(ln.Deadline()) {
		t.Fatal("passive accept did not use the reservation deadline")
	}
}

func TestFTPPassiveRetryCapsRejectedPeers(t *testing.T) {
	for _, rejection := range []string{"foreign address", "failed TLS"} {
		t.Run(rejection, func(t *testing.T) {
			ip := "192.0.2.1"
			if rejection == "foreign address" {
				ip = "192.0.2.2"
			}
			peers := makeFTPRetryPeers(ip, 33)
			raw := newFTPRetryListener(peers...)
			raw.terminalErr = io.EOF
			f := &ftpSession{server: &Server{ftpDataAcceptTimeout: -1}, clientIP: "192.0.2.1", dataLn: raw}
			if rejection == "failed TLS" {
				f.dataProt = 'P'
				f.dataTLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			}
			if dc, err := f.acceptDataConn(); err == nil || dc != nil {
				t.Fatalf("exhausted setup returned %v, %v", dc, err)
			}
			assertFTPRetryLimit(t, f, raw, peers)
		})
	}
}

func assertFTPRetryLimit(t *testing.T, f *ftpSession, raw *ftpRetryListener, peers []net.Conn) {
	t.Helper()
	if raw.accepts != 32 {
		t.Fatalf("accepted %d rejected peers; want exactly 32", raw.accepts)
	}
	for i, conn := range peers {
		want := int32(1)
		if i == 32 {
			want = 0
		}
		if got := conn.(*ftpRetryPeer).closed.Load(); got != want {
			t.Fatalf("peer %d closed %d times; want %d", i, got, want)
		}
	}
	if raw.closeCount.Load() != 1 || f.dataLn != nil || f.dataCancel != nil || f.dataConn != nil {
		t.Fatal("exhausted setup retained listener or rejected connection state")
	}
}

func TestFTPPassiveRetryKeepsOriginalTLSDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := newFTPRetryPeer("192.0.2.1")
		serverConn, clientConn := net.Pipe()
		t.Cleanup(func() { _ = clientConn.Close() })
		second := &ftpRetryPeer{Conn: serverConn, ip: "192.0.2.1"}
		raw := newFTPRetryListener(first, second)
		raw.acceptDelay = 200 * time.Millisecond
		var released atomic.Int32
		ln := netconn.NewExpiringListener(raw, time.Second, func() { released.Add(1) })
		t.Cleanup(func() { _ = ln.Close() })
		f := &ftpSession{
			server: &Server{ftpDataAcceptTimeout: time.Minute}, clientIP: "192.0.2.1", dataLn: ln,
			dataProt: 'P', dataTLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		}
		// Time spent after PASV and on the rejected first peer must count toward
		// the same deadline that bounds the second peer's stalled handshake.
		time.Sleep(400 * time.Millisecond)
		if dc, err := f.acceptDataConn(); err == nil || dc != nil {
			t.Fatalf("expired TLS setup returned %v, %v", dc, err)
		}
		synctest.Wait()
		if !time.Now().Equal(ln.Deadline()) {
			t.Fatalf("setup ended at %v, want original deadline %v", time.Now(), ln.Deadline())
		}
		if !first.deadline.Equal(ln.Deadline()) || !second.deadline.Equal(ln.Deadline()) || !raw.deadline.Equal(ln.Deadline()) {
			t.Fatal("a retry extended the accept or TLS deadline")
		}
		if raw.accepts != 2 || released.Load() != 1 || second.closed.Load() == 0 || f.dataConn != nil {
			t.Fatal("expiry retained the listener or stalled TLS peer")
		}
	})
}

func TestFTPPassiveRetryCancellationStopsWaitingAccept(t *testing.T) {
	for _, cause := range []string{"revocation", "control EOF"} {
		t.Run(cause, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				checkFTPPassiveRetryCancellation(t, cause)
			})
		})
	}
}

func checkFTPPassiveRetryCancellation(t *testing.T, cause string) {
	t.Helper()
	raw := newFTPRetryListener(newFTPRetryPeer("192.0.2.1"))
	ln := netconn.NewExpiringListener(raw, time.Minute, func() {})
	t.Cleanup(func() { _ = ln.Close() })
	f := &ftpSession{
		server: NewServer(&Config{}), clientIP: "192.0.2.1", dataLn: ln,
		dataProt: 'P', dataTLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	done := make(chan error, 1)
	go func() {
		_, err := f.acceptDataConn()
		done <- err
	}()
	<-raw.accepting
	<-raw.accepting
	synctest.Wait()
	f.dataMu.Lock()
	retainedPeer := f.dataConn
	f.dataMu.Unlock()
	if retainedPeer != nil {
		t.Fatal("retry retained its rejected TLS connection")
	}
	if cause == "revocation" {
		f.cancelDataOperations()
	} else {
		f.controlReaderClosed()
	}
	if err := <-done; err == nil {
		t.Fatal("cancelled passive retry succeeded")
	}
	if raw.accepts != 2 || raw.closeCount.Load() != 1 {
		t.Fatal("cancellation did not promptly end the pending retry")
	}
}

func TestFTPPassiveRetryHonorsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	raw := newFTPRetryListener(newFTPRetryPeer("192.0.2.1"))
	f := &ftpSession{clientIP: "192.0.2.1"}
	if dc, err := f.acceptPassiveDataConn(ctx, raw, time.Time{}); !errors.Is(err, context.Canceled) || dc != nil {
		t.Fatalf("cancelled accept returned %v, %v", dc, err)
	}
	if raw.accepts != 0 {
		t.Fatal("cancelled setup accepted another peer")
	}
}

type ftpRetryPeer struct {
	net.Conn

	ip       string
	closed   atomic.Int32
	deadline time.Time
}

func newFTPRetryPeer(ip string) *ftpRetryPeer {
	return &ftpRetryPeer{Conn: &stubConn{readErr: io.EOF}, ip: ip}
}

func makeFTPRetryPeers(ip string, count int) []net.Conn {
	peers := make([]net.Conn, count)
	for i := range peers {
		peers[i] = newFTPRetryPeer(ip)
	}
	return peers
}

func (c *ftpRetryPeer) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.ParseIP(c.ip)} }

func (c *ftpRetryPeer) Close() error {
	c.closed.Add(1)
	return c.Conn.Close()
}

func (c *ftpRetryPeer) SetDeadline(deadline time.Time) error {
	c.deadline = deadline
	return c.Conn.SetDeadline(deadline)
}

type ftpRetryListener struct {
	peers       []net.Conn
	accepts     int
	accepting   chan int
	acceptDelay time.Duration
	terminalErr error
	deadline    time.Time
	closed      chan struct{}
	closeOnce   sync.Once
	closeCount  atomic.Int32
}

func newFTPRetryListener(peers ...net.Conn) *ftpRetryListener {
	return &ftpRetryListener{peers: peers, accepting: make(chan int, 40), closed: make(chan struct{})}
}

func (l *ftpRetryListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	default:
	}
	l.accepts++
	l.accepting <- l.accepts
	if l.acceptDelay > 0 {
		time.Sleep(l.acceptDelay)
	}
	if len(l.peers) > 0 {
		peer := l.peers[0]
		l.peers = l.peers[1:]
		return peer, nil
	}
	if l.terminalErr != nil {
		return nil, l.terminalErr
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *ftpRetryListener) Close() error {
	l.closeOnce.Do(func() {
		l.closeCount.Add(1)
		close(l.closed)
	})
	return nil
}

func (*ftpRetryListener) Addr() net.Addr { return &net.TCPAddr{} }

func (l *ftpRetryListener) SetDeadline(deadline time.Time) error {
	l.deadline = deadline
	return nil
}
