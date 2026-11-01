//go:build linux && integration

package ironport

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/define42/ironport/internal/jailfs"
)

func TestFTPStatLargeDirectoryAndPathValidation(t *testing.T) {
	const entryCount = 1543 // Several ListStream directory batches.
	root, rootPath := newFTPStatDirectory(t, entryCount)
	if err := root.Mkdir("empty", 0o700); err != nil {
		t.Fatal(err)
	}
	_, addr, stop := startTestFTPServer(t, map[string]UserInfo{
		"reader": {Password: "pw", Root: rootPath, CanRead: true},
		"denied": {Password: "pw", Root: rootPath},
	}, "")
	t.Cleanup(stop)
	client := dialFTP(t, addr)
	client.command(530, "STAT /")
	client.login("reader", "pw")
	client.command(550, "STAT /missing")
	client.command(213, "STAT /empty")
	listing := client.command(213, "STAT /")
	assertFTPStatLargeListing(t, listing, entryCount)
	fileListing := client.command(213, "STAT /entry-00000")
	if !strings.Contains(fileListing, "entry-00000") {
		t.Fatalf("file listing omitted the file: %q", fileListing)
	}
	client.command(200, "NOOP")
	client.login("denied", "pw")
	client.command(550, "STAT /")
	client.command(200, "NOOP")
}

func assertFTPStatLargeListing(t *testing.T, listing string, entryCount int) {
	t.Helper()
	if got := strings.Count(listing, "entry-"); got != entryCount {
		t.Fatalf("STAT returned %d file entries; want %d", got, entryCount)
	}
	for i := range entryCount {
		name := fmt.Sprintf("entry-%05d", i)
		if !strings.Contains(listing, name) {
			t.Fatalf("STAT omitted %q", name)
		}
	}
	if !strings.Contains(listing, "End of status") {
		t.Fatal("STAT omitted its completion marker")
	}
}

// This exercises cmdStat itself: once its first output reaches the connection,
// remove the last entry observed by an independent directory walk. A streaming
// command has not stat'd that late entry yet; an eager snapshot still emits it.
func TestFTPStatCommandStreamsDirectory(t *testing.T) {
	const entryCount = 1543
	root, rootPath := newFTPStatDirectory(t, entryCount)
	lastName := lastFTPStatDirectoryEntry(t, root)
	fs, err := jailfs.Open(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fs.Close() })
	f, conn := newFTPStatStreamSession()
	f.fs = fs
	f.cwd = "/"
	f.authenticated = true
	f.user.CanRead = true
	wrote := false
	var removeErr error
	conn.onWrite = func() {
		if !wrote {
			wrote = true
			removeErr = root.Remove(lastName)
		}
	}
	f.cmdStat("/")
	if !wrote || removeErr != nil {
		t.Fatalf("late-entry removal on first output: wrote=%t err=%v", wrote, removeErr)
	}
	output := conn.output.String()
	if strings.Contains(output, " "+lastName+"\r\n") {
		t.Fatalf("STAT emitted %q removed on first output; command buffered the directory before writing", lastName)
	}
	if got := strings.Count(output, "entry-"); got != entryCount-1 {
		t.Fatalf("STAT returned %d entries after removal; want %d", got, entryCount-1)
	}
	if !strings.HasPrefix(output, "213-Status of \"/\":\r\n") || !strings.HasSuffix(output, "213 End of status\r\n") {
		t.Fatal("streamed STAT reply did not complete its multiline framing")
	}
	assertFTPStatReplyFinished(t, f, conn)
}

func newFTPStatDirectory(t *testing.T, entryCount int) (*os.Root, string) {
	t.Helper()
	rootPath := t.TempDir()
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	for i := range entryCount {
		if err := root.WriteFile(fmt.Sprintf("entry-%05d", i), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root, rootPath
}

func lastFTPStatDirectoryEntry(t *testing.T, root *os.Root) string {
	t.Helper()
	dir, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) == 0 {
		t.Fatal("fixture directory is empty")
	}
	return names[len(names)-1]
}
