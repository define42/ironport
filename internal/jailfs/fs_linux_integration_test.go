//go:build linux && integration

package jailfs

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCheckSupportRetriesAfterDescriptorExhaustion(t *testing.T) {
	const helperRootEnv = "IRONPORT_SUPPORT_RETRY_ROOT"
	if root := os.Getenv(helperRootEnv); root != "" {
		checkSupportAfterDescriptorExhaustion(t, root)
		return
	}

	// A fresh process gives the first probe an uncached result and keeps the
	// temporary process-wide descriptor limit away from other tests.
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	//nolint:gosec // G204: only this test binary is executed, with a fixed test filter
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCheckSupportRetriesAfterDescriptorExhaustion$", "-test.count=1")
	cmd.Env = append(os.Environ(), helperRootEnv+"="+t.TempDir())
	cmd.WaitDelay = time.Second
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("descriptor exhaustion subprocess: %v (context: %v)\n%s", err, ctx.Err(), output)
	}
}

func checkSupportAfterDescriptorExhaustion(t *testing.T, root string) {
	t.Helper()
	var original unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &original); err != nil {
		t.Fatal(err)
	}
	limited := original
	limited.Cur = 0
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limited); err != nil {
		t.Fatal(err)
	}
	firstErr := CheckSupport()
	// Restore before assertions or any further filesystem activity. The hard
	// limit is unchanged, so restoring the original soft limit needs no privilege.
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &original); err != nil {
		t.Fatalf("restore descriptor limit: %v", err)
	}
	if !errors.Is(firstErr, unix.EMFILE) {
		t.Fatalf("first CheckSupport error = %v; want EMFILE", firstErr)
	}
	if err := CheckSupport(); err != nil {
		t.Fatalf("CheckSupport after restoring descriptor limit: %v", err)
	}
	fs, err := Open(root)
	if err != nil {
		t.Fatalf("Open after restoring descriptor limit: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("close recovered jail: %v", err)
	}
}
