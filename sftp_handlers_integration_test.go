//go:build linux && integration

package ironport

import (
	"math"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSFTPFailedWriteSuppressesUploadNotification(t *testing.T) {
	for _, tc := range []struct {
		name       string
		writeAfter bool
	}{
		{name: "failed-write-then-close"},
		{name: "failed-write-then-successful-write", writeAfter: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			srv, addr, stop := startTestServer(t, map[string]UserInfo{
				"alice": {Password: "pw", Root: root, CanWrite: true},
			})
			t.Cleanup(stop)
			conn := resourceSSH(t, addr)
			t.Cleanup(func() { _ = conn.Close(); srv.connWG.Wait() })
			client := newDirectorySFTPClient(t, conn)
			handle := openSFTPUpload(t, client, "/failed.bin")
			writeSFTPUpload(t, client, handle, math.MaxUint64, "rejected", 4) // SSH_FX_FAILURE.
			want := ""
			if tc.writeAfter {
				want = "later valid write"
				writeSFTPUpload(t, client, handle, 0, want, 0)
			}
			client.expectStatus(4, handle, 0) // SSH_FXP_CLOSE must still succeed.
			assertNoSFTPUploadNotification(t, srv.CompletedUploads())
			assertSFTPUploadContents(t, root, "failed.bin", want)

			// Failure is local to its handle, not the connection or event queue.
			handle = openSFTPUpload(t, client, "/healthy.bin")
			writeSFTPUpload(t, client, handle, 0, "complete", 0)
			client.expectStatus(4, handle, 0)
			assertSFTPHealthyUploadNotification(t, srv.CompletedUploads(), root)
			assertSFTPUploadContents(t, root, "healthy.bin", "complete")
		})
	}
}

func openSFTPUpload(t *testing.T, client *directorySFTPClient, name string) string {
	t.Helper()
	client.id++
	client.write(ssh.Marshal(struct {
		Kind  byte
		ID    uint32
		Path  string
		Flags uint32
		Attrs uint32
	}{3, client.id, name, 2 | 8 | 16, 0})) // OPEN: WRITE | CREAT | TRUNC.
	kind, body := client.response(client.id)
	if kind != 102 {
		t.Fatalf("OPEN response type = %d; want HANDLE", kind)
	}
	return readDirectoryString(t, body)
}

func writeSFTPUpload(t *testing.T, client *directorySFTPClient, handle string, offset uint64, data string, want uint32) {
	t.Helper()
	client.id++
	client.write(ssh.Marshal(struct {
		Kind   byte
		ID     uint32
		Handle string
		Offset uint64
		Data   string
	}{6, client.id, handle, offset, data})) // SSH_FXP_WRITE.
	kind, body := client.response(client.id)
	if kind != 101 {
		t.Fatalf("WRITE response type = %d; want STATUS", kind)
	}
	if got := readDirectoryUint32(t, body); got != want {
		t.Fatalf("WRITE status = %d; want %d", got, want)
	}
}

func assertNoSFTPUploadNotification(t *testing.T, uploads <-chan CompletedUpload) {
	t.Helper()
	// CLOSE's response follows the synchronous upload notification decision,
	// so the acknowledged request is a barrier and no waiting is necessary.
	select {
	case event := <-uploads:
		t.Fatalf("failed upload announced as complete: %+v", event)
	default:
	}
}

func assertSFTPHealthyUploadNotification(t *testing.T, uploads <-chan CompletedUpload, root string) {
	t.Helper()
	select {
	case event := <-uploads:
		if event.FilePath != "/healthy.bin" || event.FullFilePath != filepath.Join(root, "healthy.bin") ||
			event.Username != "alice" || event.Protocol != CompletedUploadProtocolSFTP {
			t.Fatalf("unexpected healthy upload notification: %+v", event)
		}
	default:
		t.Fatal("successful CLOSE did not announce the healthy upload")
	}
	assertNoSFTPUploadNotification(t, uploads)
}

func assertSFTPUploadContents(t *testing.T, root, name, want string) {
	t.Helper()
	base, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = base.Close() }()
	got, err := base.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("%s contents = %q; want %q", name, got, want)
	}
}
