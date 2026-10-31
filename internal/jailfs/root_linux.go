//go:build linux

package jailfs

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// CanonicalRoot resolves an operator-configured jail root to an absolute
// directory path, following symlinks in the configured root.
func CanonicalRoot(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", os.ErrInvalid
	}

	abs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", err
	}

	// Resolve the configured root before validating it. Broken symlinks in the
	// jail root path intentionally reject the login/server start; a jail root
	// must name a real directory at authentication time.
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}

	st, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", syscall.ENOTDIR
	}

	return resolved, nil
}
