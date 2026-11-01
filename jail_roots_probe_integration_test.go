//go:build linux && integration

package ironport

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestJailRootProbeFailureHTTPRecovery(t *testing.T) {
	const childRootEnv = "IRONPORT_JAIL_ROOT_PROBE_RETRY_ROOT"
	if root := os.Getenv(childRootEnv); root != "" {
		checkJailRootProbeFailureHTTPRecovery(t, root)
		return
	}

	// A fresh process keeps the support probe uncached and isolates the
	// temporary process-wide descriptor limit from all other tests.
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	//nolint:gosec // G204: execute only this test binary with a fixed test filter
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestJailRootProbeFailureHTTPRecovery$", "-test.count=1")
	cmd.Env = append(os.Environ(), childRootEnv+"="+t.TempDir())
	cmd.WaitDelay = time.Second
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("jail probe subprocess: %v (context: %v)\n%s", err, ctx.Err(), output)
	}
}

func checkJailRootProbeFailureHTTPRecovery(t *testing.T, root string) {
	t.Helper()
	requireUncachedOpenat2Support(t)
	cfg := DefaultConfig()
	cfg.Users = map[string]UserInfo{"user": {Password: "pass", Root: root, CanWrite: true}}
	cfg.ResourceLimits.HTTPMaxConcurrentRequests = 1
	srv := NewServer(cfg)
	request := httptest.NewRequest(http.MethodGet, "/upload", nil)
	unavailable := httptest.NewRecorder()

	var original unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &original); err != nil {
		t.Fatal(err)
	}
	limited := original
	limited.Cur = 0
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limited); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Setrlimit(unix.RLIMIT_NOFILE, &original) }()

	validationErr := srv.ValidateJailRoots()
	handler := srv.HttpIngest()
	handler(unavailable, request)
	// Restore before assertions or further filesystem activity. The unchanged
	// hard limit lets the unprivileged child restore its original soft limit.
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &original); err != nil {
		t.Fatalf("restore descriptor limit: %v", err)
	}
	if !errors.Is(validationErr, unix.EMFILE) {
		t.Fatalf("ValidateJailRoots error = %v; want wrapped EMFILE", validationErr)
	}
	if unavailable.Code != http.StatusServiceUnavailable {
		t.Fatalf("HTTP during probe failure = %d; want 503", unavailable.Code)
	}
	assertHTTPProbeRecovered(t, srv, handler)
}

func assertHTTPProbeRecovered(t *testing.T, srv *Server, handler http.HandlerFunc) {
	t.Helper()
	// Reuse the handler created during failure without pre-warming the probe.
	// A second request also verifies rejection released the sole request slot.
	for range 2 {
		response := httptest.NewRecorder()
		handler(response, httptest.NewRequest(http.MethodGet, "/upload", nil))
		if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodPost {
			t.Fatalf("HTTP after probe recovery = %d, Allow=%q; want 405, POST", response.Code, response.Header().Get("Allow"))
		}
	}
	if err := srv.ValidateJailRoots(); err != nil {
		t.Fatalf("ValidateJailRoots after recovery: %v", err)
	}
}

func requireUncachedOpenat2Support(t *testing.T) {
	t.Helper()
	// Calling the syscall directly leaves jailfs's process-wide probe cold.
	fd, err := unix.Openat2(unix.AT_FDCWD, "/", &unix.OpenHow{
		Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
	})
	if errors.Is(err, unix.ENOSYS) {
		t.Skip("kernel does not support openat2")
	}
	if err != nil {
		t.Fatalf("openat2 preflight: %v", err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatalf("close openat2 preflight: %v", err)
	}
}
