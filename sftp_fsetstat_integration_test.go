//go:build linux && integration

package ironport

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSFTPFsetstatRejectsCombinedAttributes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		canWrite bool
		status   uint32
	}{
		{"writer", true, 8},  // SSH_FX_OP_UNSUPPORTED.
		{"reader", false, 4}, // Existing read-only policy returns SSH_FX_FAILURE.
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFsetstatTestFile(t, root, "original", "opened contents")
			config := newTestConfig("", "", "", map[string]UserInfo{
				"alice": {Password: "pw", Root: root, CanRead: true, CanWrite: tc.canWrite},
			}, testSigner(t), defaultCompletedUploadsSize)
			config.SftpAllowChown = true
			srv, addr, stop := startTestServerWithConfig(t, config)
			t.Cleanup(stop)
			conn := resourceSSH(t, addr)
			t.Cleanup(func() { _ = conn.Close(); srv.connWG.Wait() })
			client := newDirectorySFTPClient(t, conn)
			handle := openFsetstatReadHandle(t, client)
			if err := os.Rename(filepath.Join(root, "original"), filepath.Join(root, "renamed")); err != nil {
				t.Fatal(err)
			}
			writeFsetstatTestFile(t, root, "original", "replacement contents")
			before, err := os.Stat(filepath.Join(root, "original"))
			if err != nil {
				t.Fatal(err)
			}

			requestFsetstatAllAttrs(t, client, handle, tc.status)
			assertFsetstatTestFile(t, root, "original", "replacement contents")
			assertFsetstatTestFile(t, root, "renamed", "opened contents")
			after, err := os.Stat(filepath.Join(root, "original"))
			if err != nil {
				t.Fatal(err)
			}
			if !after.ModTime().Equal(before.ModTime()) {
				t.Fatal("rejected FSETSTAT changed replacement modification time")
			}
			assertFsetstatReadHandleClosed(t, srv, client, handle)
		})
	}
}

func openFsetstatReadHandle(t *testing.T, client *directorySFTPClient) string {
	t.Helper()
	client.id++
	client.write(ssh.Marshal(struct {
		Kind  byte
		ID    uint32
		Path  string
		Flags uint32
		Attrs uint32
	}{3, client.id, "/original", 1, 0})) // OPEN: READ.
	kind, body := client.response(client.id)
	if kind != 102 {
		t.Fatalf("OPEN response type = %d; want HANDLE", kind)
	}
	return readDirectoryString(t, body)
}

func requestFsetstatAllAttrs(t *testing.T, client *directorySFTPClient, handle string, want uint32) {
	t.Helper()
	client.id++
	client.write(ssh.Marshal(struct {
		Kind   byte
		ID     uint32
		Handle string
		Flags  uint32
		Size   uint64
		UID    uint32
		GID    uint32
		Mode   uint32
		Atime  uint32
		Mtime  uint32
	}{10, client.id, handle, 1 | 2 | 4 | 8, 2, 0, 0, 0o100400, 123, 456}))
	kind, body := client.response(client.id)
	if kind != 101 {
		t.Fatalf("FSETSTAT response type = %d; want STATUS", kind)
	}
	if got := readDirectoryUint32(t, body); got != want {
		t.Fatalf("FSETSTAT status = %d; want %d", got, want)
	}
}

func assertFsetstatReadHandleClosed(t *testing.T, srv *Server, client *directorySFTPClient, handle string) {
	t.Helper()
	client.expectStatus(4, handle, 0) // CLOSE still releases the read handle.
	srv.sftpHandles.mu.Lock()
	used := srv.sftpHandles.used
	srv.sftpHandles.mu.Unlock()
	if used != 0 {
		t.Fatalf("open handles after CLOSE = %d; want 0", used)
	}
	assertNoSFTPUploadNotification(t, srv.CompletedUploads())
}
