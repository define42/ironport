//go:build linux

package jailfs

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

//nolint:gocognit // exhaustively walks symlink/non-dir/relative-path error paths
func TestCanonicalJailRoot(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("os.Symlink: %v", err)
	}

	filePath := filepath.Join(t.TempDir(), "root-file")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	missingPath := filepath.Join(t.TempDir(), "missing")

	tests := []struct {
		name    string
		root    string
		want    string
		wantErr error
	}{
		{name: "empty", root: "", wantErr: os.ErrInvalid},
		{name: "whitespace", root: " \t ", wantErr: os.ErrInvalid},
		{name: "missing", root: missingPath, wantErr: os.ErrNotExist},
		{name: "file", root: filePath, wantErr: syscall.ENOTDIR},
		{name: "symlink", root: link, want: target},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalRoot(tc.root)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("CanonicalRoot(%q) error = %v; want %v", tc.root, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("CanonicalRoot(%q): %v", tc.root, err)
			}
			if got != tc.want {
				t.Fatalf("CanonicalRoot(%q) = %q; want %q", tc.root, got, tc.want)
			}
		})
	}
}
