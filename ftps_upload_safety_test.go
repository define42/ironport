//go:build linux && integration

package ironport

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestFTPSUploadSafetyRejectedData(t *testing.T) {
	for _, version := range []struct {
		name  string
		value uint16
	}{
		{name: "TLS 1.2", value: tls.VersionTLS12},
		{name: "TLS 1.3", value: tls.VersionTLS13},
	} {
		t.Run(version.name, func(t *testing.T) {
			fixture := newFTPSUploadSafetyServer(t, version.value)
			for _, failure := range []string{"malformed handshake", "fresh session", "foreign session"} {
				fixture.checkRejectedUploadCases(t, failure)
			}
			// Rejected candidates must not poison the control session or its
			// own ticket. Both overwrite and append still work afterward.
			for _, command := range []string{"STOR", "APPE"} {
				t.Run("bound session/"+command, func(t *testing.T) {
					fixture.checkBoundUpload(t, command)
				})
			}
		})
	}
}

type ftpsUploadSafetyServer struct {
	server  *Server
	client  *ftpsTestClient
	root    *os.Root
	addr    string
	pool    *x509.CertPool
	version uint16
}

func newFTPSUploadSafetyServer(t *testing.T, version uint16) *ftpsUploadSafetyServer {
	t.Helper()
	rootPath := t.TempDir()
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	cfg, pool := newTestFTPSConfig(t, map[string]UserInfo{
		"alice": {Password: "pw", Root: rootPath, CanWrite: true},
	}, true)
	cfg.FtpTLSConfig.MinVersion = version
	cfg.FtpTLSConfig.MaxVersion = version
	cfg.FtpDataAcceptTimeout = 5 * time.Second
	server, addr, stop := startTestFTPServerWithConfig(t, cfg)
	t.Cleanup(stop)
	client := dialFTPS(t, addr, pool)
	client.tlsCfg.MinVersion = version
	client.tlsCfg.MaxVersion = version
	client.authTLS()
	client.login("alice", "pw")
	client.command(200, "PBSZ 0")
	client.command(200, "PROT P")
	return &ftpsUploadSafetyServer{server: server, client: client, root: root, addr: addr, pool: pool, version: version}
}

func (f *ftpsUploadSafetyServer) checkRejectedUploadCases(t *testing.T, failure string) {
	t.Helper()
	for _, command := range []string{"STOR", "APPE"} {
		for _, target := range []string{"existing", "new"} {
			t.Run(failure+"/"+command+"/"+target, func(t *testing.T) {
				f.checkRejectedUpload(t, failure, command, target == "existing")
			})
		}
	}
}

func (f *ftpsUploadSafetyServer) checkRejectedUpload(t *testing.T, failure, command string, existing bool) {
	t.Helper()
	// Share the established session, but attribute helper failures to this
	// subtest rather than the parent that created the connection.
	client := *f.client
	client.t = t
	_ = client.conn.SetDeadline(time.Now().Add(5 * time.Second))
	filename := "rejected.bin"
	original := []byte("preserve this existing content")
	prepareFTPSUploadSafetyTarget(t, f.root, filename, original, existing)
	raw := client.passiveDial()
	defer func() { _ = raw.Close() }()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	client.command(150, "%s rejected.bin", command)
	if failure == "malformed handshake" {
		if _, err := io.WriteString(raw, "not a TLS record\r\n"); err != nil {
			t.Fatal(err)
		}
		_ = raw.Close()
	} else {
		config, cache := f.rejectedDataConfig(t, failure)
		checkFTPSUploadTLSRejected(t, raw, config, cache)
	}
	client.read(425)
	assertFTPSUploadSafetyTarget(t, f.root, filename, original, existing)
	select {
	case event := <-f.server.CompletedUploads():
		t.Fatalf("rejected data setup announced a completed upload: %+v", event)
	default:
	}
}

func (f *ftpsUploadSafetyServer) rejectedDataConfig(t *testing.T, failure string) (*tls.Config, *trackingTLSSessionCache) {
	t.Helper()
	if failure == "fresh session" {
		config := f.client.tlsCfg.Clone()
		config.ClientSessionCache = tls.NewLRUClientSessionCache(1)
		return config, nil
	}
	foreign := dialFTPS(t, f.addr, f.pool)
	foreign.tlsCfg.MinVersion = f.version
	foreign.tlsCfg.MaxVersion = f.version
	cache := newTrackingTLSSessionCache()
	foreign.tlsCfg.ClientSessionCache = cache
	foreign.authTLS()
	// Consume TLS 1.3's post-handshake ticket without authenticating this
	// control connection. It shares the victim's source IP, as behind NAT.
	foreign.command(200, "NOOP")
	foreign.command(530, "PWD")
	if cached, puts, _ := cache.stats(); cached == 0 || puts == 0 {
		t.Fatal("foreign control session did not receive a resumable ticket")
	}
	return foreign.tlsCfg, cache
}

func checkFTPSUploadTLSRejected(t *testing.T, raw net.Conn, config *tls.Config, cache *trackingTLSSessionCache) {
	t.Helper()
	hitsBefore := 0
	if cache != nil {
		_, _, hitsBefore = cache.stats()
	}
	tc := tls.Client(raw, config)
	err := tc.HandshakeContext(t.Context())
	if cache != nil {
		if _, _, hitsAfter := cache.stats(); hitsAfter <= hitsBefore {
			t.Fatal("foreign control ticket was not offered to the data connection")
		}
	}
	if err == nil {
		// TLS 1.3 may finish the client handshake before consuming the
		// server's rejection alert. The subsequent read must terminate.
		if tc.ConnectionState().DidResume {
			t.Fatal("unbound data connection resumed an accepted session")
		}
		_, err = tc.Read(make([]byte, 1))
	}
	var netErr net.Error
	if err == nil || (errors.As(err, &netErr) && netErr.Timeout()) {
		t.Fatalf("unbound data handshake was not rejected promptly: %v", err)
	}
}

func prepareFTPSUploadSafetyTarget(t *testing.T, root *os.Root, filename string, original []byte, existing bool) {
	t.Helper()
	if existing {
		if err := root.WriteFile(filename, original, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := root.Remove(filename); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func assertFTPSUploadSafetyTarget(t *testing.T, root *os.Root, filename string, original []byte, existing bool) {
	t.Helper()
	got, err := root.ReadFile(filename)
	if !existing {
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rejected data setup created a file: contents=%q, err=%v", got, err)
		}
		return
	}
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("rejected data setup changed existing file: contents=%q, err=%v", got, err)
	}
}

func (f *ftpsUploadSafetyServer) checkBoundUpload(t *testing.T, command string) {
	t.Helper()
	client := *f.client
	client.t = t
	_ = client.conn.SetDeadline(time.Now().Add(5 * time.Second))
	filename := "accepted.bin"
	original, payload := []byte("old content"), []byte("new payload")
	prepareFTPSUploadSafetyTarget(t, f.root, filename, original, true)
	raw := client.passiveDial()
	defer func() { _ = raw.Close() }()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	client.command(150, "%s accepted.bin", command)
	tc := client.upgradeDataConn(raw)
	if !tc.ConnectionState().DidResume {
		t.Fatal("legitimate data upload did not resume its control session")
	}
	if _, err := tc.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := tc.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = tc.Close()
	client.read(226)
	want := payload
	if command == "APPE" {
		want = bytes.Clone(original)
		want = append(want, payload...)
	}
	got, err := f.root.ReadFile(filename)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("bound data upload stored %q, err=%v; want %q", got, err, want)
	}
	select {
	case event := <-f.server.CompletedUploads():
		if event.Username != "alice" || event.Protocol != CompletedUploadProtocolFTP {
			t.Fatalf("unexpected completed upload: %+v", event)
		}
	default:
		t.Fatal("bound data upload did not announce completion")
	}
}
