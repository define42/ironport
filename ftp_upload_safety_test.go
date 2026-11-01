//go:build linux

package ironport

import (
	"bufio"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/define42/ironport/internal/jailfs"
	"golang.org/x/sys/unix"
)

const ftpUploadSafetyOriginal = "retain the existing file contents"

func TestFTPUploadFailedDataSetupPreservesFiles(t *testing.T) {
	for _, setup := range []string{"no endpoint", "passive timeout", "foreign peer", "active dial failure"} {
		t.Run(setup, func(t *testing.T) {
			srv, client, root := newFTPUploadSafetySession(t)
			for _, command := range []string{"STOR", "APPE"} {
				for _, name := range []string{"existing.txt", "new.txt"} {
					t.Run(command+"/"+name, func(t *testing.T) {
						resetFTPUploadSafetyDestinations(t, root)
						current := *client
						current.t = t
						cleanup := prepareFailedFTPUpload(t, &current, setup)
						defer cleanup()
						current.command(150, "%s %s", command, name)
						current.read(425)
						assertFTPUploadDestinationsUntouched(t, root)
						assertNoFTPUploadCompletion(t, srv.CompletedUploads())
						current.command(200, "NOOP")
					})
				}
			}
			completeFTPUploadSafetyRecovery(t, client, srv, root, "recovered.txt", "recovered")
		})
	}
}

func newFTPUploadSafetySession(t *testing.T) (*Server, *ftpTestClient, string) {
	t.Helper()
	root := t.TempDir()
	resetFTPUploadSafetyDestinations(t, root)
	cfg := newTestFTPConfig(t, map[string]UserInfo{
		"alice": {Password: "pw", Root: root, CanWrite: true},
	}, "", true)
	cfg.FtpDataAcceptTimeout = 250 * time.Millisecond
	srv, addr, stop := startTestFTPServerWithConfig(t, cfg)
	t.Cleanup(stop)
	client := dialFTP(t, addr)
	_ = client.conn.SetDeadline(time.Now().Add(5 * time.Second))
	client.login("alice", "pw")
	return srv, client, root
}

func resetFTPUploadSafetyDestinations(t *testing.T, root string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "existing.txt"), []byte(ftpUploadSafetyOriginal), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "new.txt")); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func prepareFailedFTPUpload(t *testing.T, client *ftpTestClient, setup string) func() {
	t.Helper()
	switch setup {
	case "no endpoint":
		return func() {}
	case "passive timeout":
		client.command(227, "PASV")
		return func() {}
	case "foreign peer":
		host, port, err := parseFTPPASVResponse(client.command(227, "PASV"))
		if err != nil {
			t.Fatal(err)
		}
		dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}, Timeout: time.Second}
		conn, err := dialer.DialContext(t.Context(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			t.Fatal(err)
		}
		return func() { _ = conn.Close() }
	case "active dial failure":
		return prepareRefusedFTPActiveEndpoint(t, client)
	default:
		t.Fatalf("unknown data setup %q", setup)
		return func() {}
	}
}

func prepareRefusedFTPActiveEndpoint(t *testing.T, client *ftpTestClient) func() {
	t.Helper()
	// Reserve a TCP port without listening, so the server's connect is refused
	// and another test/process cannot claim the port between setup and dialing.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	addr, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	port := addr.(*unix.SockaddrInet4).Port
	client.command(200, "EPRT |1|127.0.0.1|%d|", port)
	return func() {}
}

func assertFTPUploadDestinationsUntouched(t *testing.T, root string) {
	t.Helper()
	assertFTPUploadContents(t, root, "existing.txt", ftpUploadSafetyOriginal)
	if _, err := os.Stat(filepath.Join(root, "new.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed upload created new.txt: %v", err)
	}
}

func assertFTPUploadContents(t *testing.T, root, name, want string) {
	t.Helper()
	dir, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	data, err := dir.ReadFile(name)
	if err != nil || string(data) != want {
		t.Fatalf("%s contents = %q, %v; want %q", name, data, err, want)
	}
}

func assertNoFTPUploadCompletion(t *testing.T, events <-chan CompletedUpload) {
	t.Helper()
	select {
	case event := <-events:
		t.Fatalf("failed upload announced completion: %+v", event)
	default:
	}
}

func completeFTPUploadSafetyRecovery(t *testing.T, client *ftpTestClient, srv *Server, root, name, content string) {
	t.Helper()
	conn, _ := client.passiveConn()
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	client.command(150, "STOR %s", name)
	if _, err := io.WriteString(conn, content); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	client.read(226)
	assertFTPUploadContents(t, root, name, content)
	select {
	case event := <-srv.CompletedUploads():
		if event.FilePath != "/"+name || event.Protocol != CompletedUploadProtocolFTP {
			t.Fatalf("recovery upload event = %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("recovery upload did not announce completion")
	}
	assertNoFTPUploadCompletion(t, srv.CompletedUploads())
}

func TestFTPUploadFailedSetupConsumesTransferHints(t *testing.T) {
	for _, command := range []string{"STOR", "APPE"} {
		t.Run(command, func(t *testing.T) {
			srv, client, root := newFTPUploadSafetySession(t)
			client.command(350, "REST 2")
			client.command(200, "ALLO 999")
			client.command(150, "%s existing.txt", command)
			client.read(425)
			assertFTPUploadDestinationsUntouched(t, root)
			assertNoFTPUploadCompletion(t, srv.CompletedUploads())
			// A fresh STOR must truncate normally and accept its actual length;
			// retained REST or ALLO would change the bytes or reject completion.
			completeFTPUploadSafetyRecovery(t, client, srv, root, "existing.txt", "fresh")
		})
	}
}

func TestFTPUploadFailedPreliminaryReplyPreservesFiles(t *testing.T) {
	for _, command := range []string{"STOR", "APPE"} {
		t.Run(command, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "existing.txt"), []byte(ftpUploadSafetyOriginal), 0o600); err != nil {
				t.Fatal(err)
			}
			fs, err := jailfs.Open(root)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = fs.Close() })
			events := make(chan CompletedUpload, 1)
			for _, name := range []string{"existing.txt", "new.txt"} {
				f := &ftpSession{
					server: NewServer(&Config{}), fs: fs, user: UserInfo{CanWrite: true},
					w: bufio.NewWriter(ftpUploadFailedReplyWriter{}), uploads: events,
				}
				f.cmdStor(name, command == "APPE")
				assertFTPUploadDestinationsUntouched(t, root)
				assertNoFTPUploadCompletion(t, events)
			}
		})
	}
}

type ftpUploadFailedReplyWriter struct{}

func (ftpUploadFailedReplyWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
