//go:build linux && integration

package ironport

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// directorySFTPClient exposes the three directory operations absent from the
// public client API, so tests can pipeline READDIR and abandon an unread handle.
type directorySFTPClient struct {
	t  *testing.T
	ch ssh.Channel
	id uint32
}

func newDirectorySFTPClient(t *testing.T, conn *ssh.Client) *directorySFTPClient {
	t.Helper()
	ch, requests, err := conn.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	go ssh.DiscardRequests(requests)
	timer := time.AfterFunc(10*time.Second, func() { _ = ch.Close() })
	t.Cleanup(func() { timer.Stop(); _ = ch.Close() })
	ok, err := ch.SendRequest("subsystem", true, ssh.Marshal(struct{ Name string }{"sftp"}))
	if err != nil || !ok {
		t.Fatalf("request sftp subsystem: accepted=%t err=%v", ok, err)
	}
	client := &directorySFTPClient{t: t, ch: ch}
	client.write([]byte{1, 0, 0, 0, 3}) // SSH_FXP_INIT, version 3.
	packet := client.read()
	if len(packet) < 5 || packet[0] != 2 || binary.BigEndian.Uint32(packet[1:5]) != 3 {
		t.Fatalf("unexpected SFTP version packet: %x", packet)
	}
	return client
}

func (c *directorySFTPClient) write(payload []byte) {
	c.t.Helper()
	size := len(payload)
	if size < 0 || size > 1<<20 {
		c.t.Fatal("test packet exceeds maximum size")
		return
	}
	packet := binary.BigEndian.AppendUint32(nil, uint32(size))
	if _, err := c.ch.Write(append(packet, payload...)); err != nil {
		c.t.Fatal(err)
	}
}

func (c *directorySFTPClient) read() []byte {
	c.t.Helper()
	var size uint32
	if err := binary.Read(c.ch, binary.BigEndian, &size); err != nil {
		c.t.Fatal(err)
	}
	if size == 0 || size > 1<<20 {
		c.t.Fatalf("invalid SFTP packet size: %d", size)
	}
	packet := make([]byte, size)
	if _, err := io.ReadFull(c.ch, packet); err != nil {
		c.t.Fatal(err)
	}
	return packet
}

func (c *directorySFTPClient) send(kind byte, value string) uint32 {
	c.id++
	c.write(ssh.Marshal(struct {
		Kind  byte
		ID    uint32
		Value string
	}{kind, c.id, value}))
	return c.id
}

func (c *directorySFTPClient) response(id uint32) (byte, *bytes.Reader) {
	c.t.Helper()
	packet := c.read()
	if len(packet) < 5 || binary.BigEndian.Uint32(packet[1:5]) != id {
		c.t.Fatalf("unexpected SFTP response to request %d: %x", id, packet)
	}
	return packet[0], bytes.NewReader(packet[5:])
}

func (c *directorySFTPClient) open(path string) string {
	c.t.Helper()
	kind, body := c.response(c.send(11, path)) // SSH_FXP_OPENDIR.
	if kind != 102 {
		c.t.Fatalf("OPENDIR response type = %d; want HANDLE", kind)
	}
	return readDirectoryString(c.t, body)
}

func (c *directorySFTPClient) expectStatus(kind byte, value string, want uint32) {
	c.t.Helper()
	reply, body := c.response(c.send(kind, value))
	if reply != 101 {
		c.t.Fatalf("response type = %d; want STATUS", reply)
	}
	if got := readDirectoryUint32(c.t, body); got != want {
		c.t.Fatalf("SFTP status = %d; want %d", got, want)
	}
}

func readDirectoryUint32(t *testing.T, reader io.Reader) uint32 {
	t.Helper()
	var value uint32
	if err := binary.Read(reader, binary.BigEndian, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func readDirectoryString(t *testing.T, reader *bytes.Reader) string {
	t.Helper()
	length := readDirectoryUint32(t, reader)
	if int64(length) > int64(reader.Len()) {
		t.Fatal("truncated SFTP string")
	}
	value := make([]byte, length)
	if _, err := io.ReadFull(reader, value); err != nil {
		t.Fatal(err)
	}
	return string(value)
}

func readDirectoryNames(t *testing.T, body *bytes.Reader) []string {
	t.Helper()
	count := readDirectoryUint32(t, body)
	var names []string
	for range count {
		names = append(names, readDirectoryString(t, body))
		_ = readDirectoryString(t, body) // Long name.
		flags := readDirectoryUint32(t, body)
		if flags&^uint32(15) != 0 {
			t.Fatalf("unexpected directory attribute flags: %x", flags)
		}
		for _, attr := range []struct{ flag, size uint32 }{{1, 8}, {2, 8}, {4, 4}, {8, 8}} {
			if flags&attr.flag != 0 {
				if _, err := io.CopyN(io.Discard, body, int64(attr.size)); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if body.Len() != 0 {
		t.Fatalf("directory reply has %d trailing bytes", body.Len())
	}
	return names
}

func startDirectorySFTPServer(t *testing.T) (*Server, string, string) {
	t.Helper()
	root := t.TempDir()
	directory := filepath.Join(root, "listing")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := newTestConfig("", "", "", map[string]UserInfo{
		"alice": {Password: "pw", Root: root, CanRead: true},
	}, testSigner(t), 1)
	cfg.ResourceLimits.SFTPMaxHandles = 1
	cfg.ResourceLimits.SFTPMaxHandlesPerUser = 1
	cfg.ResourceLimits.SFTPMaxHandlesPerConnection = 1
	srv, addr, stop := startTestServerWithConfig(t, cfg)
	t.Cleanup(stop)
	return srv, addr, directory
}

func TestSFTPDirectoryPipelinedReadsAreIncremental(t *testing.T) {
	srv, addr, directory := startDirectorySFTPServer(t)
	client := newDirectorySFTPClient(t, resourceSSH(t, addr))
	handle := client.open("/listing")
	// Opening the empty directory must not snapshot it. Populate more than
	// two filesystem batches before the first READDIR reaches the server.
	const entries = 1037
	for i := range entries {
		name := filepath.Join(directory, fmt.Sprintf("entry-%04d", i))
		if err := os.WriteFile(name, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	assertPipelinedDirectoryNames(t, client, handle, entries)
	// EOF does not close the SFTP handle or release its admission permit.
	client.expectStatus(11, "/listing", 4)
	client.expectStatus(4, handle, 0) // SSH_FXP_CLOSE.
	waitDirectoryResources(t, srv, directory, 0)
}

func assertPipelinedDirectoryNames(t *testing.T, client *directorySFTPClient, handle string, entries int) {
	t.Helper()
	batchCount := (entries+int(sftp.MaxFilelist)-1)/int(sftp.MaxFilelist) + 2
	ids := make([]uint32, batchCount)
	for i := range ids {
		ids[i] = client.send(12, handle) // Queue every READDIR before receiving.
	}
	seen := make(map[string]bool, entries)
	eof := false
	for _, id := range ids {
		names, done := readPipelinedDirectoryReply(t, client, id)
		if eof && !done {
			t.Fatal("READDIR returned NAME after EOF")
		}
		eof = done
		for _, name := range names {
			if seen[name] {
				t.Fatalf("pipelined READDIR repeated %q", name)
			}
			seen[name] = true
		}
	}
	if !eof || len(seen) != entries {
		t.Fatalf("READDIR entries=%d EOF=%t; want %d and EOF", len(seen), eof, entries)
	}
	for i := range entries {
		if !seen[fmt.Sprintf("entry-%04d", i)] {
			t.Fatalf("READDIR omitted entry-%04d", i)
		}
	}
}

func readPipelinedDirectoryReply(t *testing.T, client *directorySFTPClient, id uint32) ([]string, bool) {
	t.Helper()
	kind, body := client.response(id)
	if kind == 101 {
		if code := readDirectoryUint32(t, body); code != 1 {
			t.Fatalf("READDIR status = %d; want EOF", code)
		}
		return nil, true
	}
	if kind != 104 {
		t.Fatalf("READDIR response type=%d; want NAME or EOF", kind)
	}
	return readDirectoryNames(t, body), false
}

func TestSFTPUnreadDirectoryCleanup(t *testing.T) {
	for _, mode := range []string{"close", "channel", "transport", "revocation"} {
		t.Run(mode, func(t *testing.T) {
			srv, addr, directory := startDirectorySFTPServer(t)
			conn := resourceSSH(t, addr)
			client := newDirectorySFTPClient(t, conn)
			handle := client.open("/listing")
			waitDirectoryResources(t, srv, directory, 1)
			client.expectStatus(11, "/listing", 4)
			switch mode {
			case "close":
				client.expectStatus(4, handle, 0)
			case "channel":
				_ = client.ch.Close()
			case "transport":
				_ = conn.Close()
			case "revocation":
				srv.RemoveUser("alice")
			}
			waitDirectoryResources(t, srv, directory, 0)
		})
	}
}

func waitDirectoryResources(t *testing.T, srv *Server, directory string, want int) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		srv.sftpHandles.mu.Lock()
		used := srv.sftpHandles.used
		srv.sftpHandles.mu.Unlock()
		if used == want && countDirectoryDescriptors(t, directory) == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("directory descriptors and handle permits did not reach %d", want)
}

func countDirectoryDescriptors(t *testing.T, directory string) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err == nil && target == directory {
			count++
		}
	}
	return count
}
