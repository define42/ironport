//go:build linux && integration

package ironport

import (
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestFTPPassiveRetryForeignPeerThenUpload(t *testing.T) {
	root := t.TempDir()
	resetFTPUploadSafetyDestinations(t, root)
	cfg := newTestFTPConfig(t, map[string]UserInfo{
		"alice": {Password: "pw", Root: root, CanWrite: true},
	}, "", false)
	cfg.FtpDataAcceptTimeout = 5 * time.Second
	srv, addr, stop := startTestFTPServerWithConfig(t, cfg)
	t.Cleanup(stop)
	client := dialFTP(t, addr)
	_ = client.conn.SetDeadline(time.Now().Add(5 * time.Second))
	client.login("alice", "pw")
	dataAddr := ftpRetryPassiveAddress(t, client)
	foreign := dialForeignFTPData(t, dataAddr)
	client.command(150, "STOR existing.txt")
	if _, err := foreign.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("foreign data peer was not rejected: %v", err)
	}
	assertFTPUploadDestinationsUntouched(t, root)
	assertNoFTPUploadCompletion(t, srv.CompletedUploads())

	// Continue the already-pending STOR on the same port, with no new PASV.
	legitimate := dialFTPDataRetry(t, dataAddr)
	if _, err := io.WriteString(legitimate, "legitimate retry"); err != nil {
		t.Fatal(err)
	}
	_ = legitimate.Close()
	client.read(226)
	assertFTPUploadContents(t, root, "existing.txt", "legitimate retry")
	select {
	case event := <-srv.CompletedUploads():
		if event.FilePath != "/existing.txt" || event.Username != "alice" || event.Protocol != CompletedUploadProtocolFTP {
			t.Fatalf("unexpected retry upload event: %+v", event)
		}
	default:
		t.Fatal("legitimate retry did not announce completion")
	}
	assertNoFTPUploadCompletion(t, srv.CompletedUploads())
	waitFTPPassiveRelease(t, srv)
}

func ftpRetryPassiveAddress(t *testing.T, client *ftpTestClient) string {
	t.Helper()
	host, port, err := parseFTPPASVResponse(client.command(227, "PASV"))
	if err != nil {
		t.Fatal(err)
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func dialForeignFTPData(t *testing.T, addr string) net.Conn {
	t.Helper()
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}, Timeout: time.Second}
	conn, err := dialer.DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn
}
