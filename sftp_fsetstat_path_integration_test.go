//go:build linux && integration

package ironport

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pkg/sftp"
)

// The pinned pkg/sftp request server loses the retained file handle when it
// dispatches FSETSTAT. Verify the protocol operation fails closed instead of
// mutating a replacement at the handle's original pathname.
func TestSFTPFsetstatRejectsReplacedPath(t *testing.T) {
	for _, mode := range []struct {
		name  string
		flags int
	}{
		{"read", os.O_RDONLY},
		{"write", os.O_WRONLY},
		{"read-write", os.O_RDWR},
	} {
		for _, op := range []struct {
			name string
			call func(*sftp.File) error
		}{
			{"truncate", func(f *sftp.File) error { return f.Truncate(2) }},
			{"chmod", func(f *sftp.File) error { return f.Chmod(0o400) }},
			{"chown", func(f *sftp.File) error { return f.Chown(os.Getuid(), os.Getgid()) }},
		} {
			t.Run(mode.name+"/"+op.name, func(t *testing.T) {
				testSFTPFsetstatReplacedPath(t, mode.flags, op.call)
			})
		}
	}
}

func testSFTPFsetstatReplacedPath(t *testing.T, flags int, mutate func(*sftp.File) error) {
	t.Helper()
	root := t.TempDir()
	writeFsetstatTestFile(t, root, "original", "opened contents")
	config := newTestConfig("", "", "", map[string]UserInfo{
		"alice": {Password: "pw", Root: root, CanRead: true, CanWrite: true},
	}, testSigner(t), defaultCompletedUploadsSize)
	// Even opt-in ownership changes cannot safely use a stale pathname.
	config.SftpAllowChown = true
	_, addr, stop := startTestServerWithConfig(t, config)
	t.Cleanup(stop)
	client := dialSFTP(t, addr, "alice", "pw")
	f, err := client.OpenFile("/original", flags)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := client.Rename("/original", "/renamed"); err != nil {
		t.Fatal(err)
	}
	writeFsetstatTestFile(t, root, "original", "replacement contents")

	var status *sftp.StatusError
	if err := mutate(f); !errors.As(err, &status) || status.FxCode() != sftp.ErrSSHFxOpUnsupported {
		t.Fatalf("FSETSTAT error = %v; want operation unsupported", err)
	}
	assertFsetstatTestFile(t, root, "renamed", "opened contents")
	assertFsetstatTestFile(t, root, "original", "replacement contents")

	// Pathname SETSTAT still names its intended target and must keep working.
	if err := client.Truncate("/original", 2); err != nil {
		t.Fatalf("pathname SETSTAT: %v", err)
	}
	assertFsetstatTestFile(t, root, "original", "re")
	assertFsetstatTestFile(t, root, "renamed", "opened contents")
}

func writeFsetstatTestFile(t *testing.T, root, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertFsetstatTestFile(t *testing.T, root, name, want string) {
	t.Helper()
	base, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = base.Close() }()
	data, err := base.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != want {
		t.Fatalf("%s contents = %q; want %q", name, data, want)
	}
	info, err := base.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("%s permissions = %o; want 600", name, info.Mode().Perm())
	}
}
