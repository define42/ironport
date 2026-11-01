//go:build linux && integration

package jailfs

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	regularLeaseHelperEnv = "IRONPORT_REGULAR_LEASE_HELPER"
	regularLeaseTimeout   = 5 * time.Second
	regularLeaseContents  = "preserve contents until lease release"
)

type regularLeaseResult struct {
	file *os.File
	err  error
}

func TestRegularOperationsWaitForLease(t *testing.T) {
	cases := []struct {
		name string
		kind int
	}{
		{"read", unix.F_WRLCK},
		{"write-truncate", unix.F_RDLCK},
		{"create-truncate", unix.F_RDLCK},
		{"truncate", unix.F_RDLCK},
		{"chmod", unix.F_WRLCK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "leased")
			if err := os.WriteFile(path, []byte(regularLeaseContents), 0o600); err != nil {
				t.Fatal(err)
			}
			fs := openRootTestFS(t, root)
			holder := startRegularLeaseHolder(t, path, tc.kind)
			result := startRegularLeaseOperation(t, holder, fs, tc.name)
			// The holder reads its existing descriptor after SIGIO, avoiding
			// another open that could itself wait on the conflicting lease.
			holder.expect(t, "break "+strconv.Quote(regularLeaseContents))
			assertRegularLeaseMode(t, path, 0o600)
			select {
			case got := <-result:
				closeRegularLeaseResult(got)
				t.Fatalf("operation returned before lease release: %v", got.err)
			case <-time.After(100 * time.Millisecond):
			}
			if _, err := io.WriteString(holder.control, "release\n"); err != nil {
				t.Fatal(err)
			}
			holder.expect(t, "released")
			got := receiveRegularLeaseResult(t, result)
			defer closeRegularLeaseResult(got)
			if got.err != nil {
				t.Fatal(got.err)
			}
			assertRegularLeaseResult(t, tc.name, path, got.file)
			holder.wait(t)
		})
	}
}

func performRegularLeaseOperation(fs *FS, name string) regularLeaseResult {
	var result regularLeaseResult
	switch name {
	case "read":
		result.file, result.err = fs.OpenRead("leased")
	case "write-truncate":
		result.file, result.err = fs.OpenWrite("leased", os.O_WRONLY|os.O_TRUNC, 0)
	case "create-truncate":
		result.file, result.err = fs.OpenWrite("leased", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	case "truncate":
		result.err = fs.Truncate("leased", 4)
	case "chmod":
		result.err = fs.Chmod("leased", 0o640)
	}
	return result
}

func startRegularLeaseOperation(t *testing.T, holder *regularLeaseHolder, fs *FS, name string) <-chan regularLeaseResult {
	t.Helper()
	result := make(chan regularLeaseResult, 1)
	go func() {
		result <- performRegularLeaseOperation(fs, name)
		close(result)
	}()
	t.Cleanup(func() {
		// Release the lease before joining a potentially blocked filesystem
		// operation; fs.Close is registered earlier and therefore runs last.
		holder.stop()
		closeRegularLeaseResult(receiveRegularLeaseResult(t, result))
	})
	return result
}

func receiveRegularLeaseResult(t *testing.T, result <-chan regularLeaseResult) regularLeaseResult {
	t.Helper()
	select {
	case got := <-result:
		return got
	case <-time.After(regularLeaseTimeout):
		t.Fatal("filesystem operation did not finish after lease release")
		return regularLeaseResult{}
	}
}

func closeRegularLeaseResult(result regularLeaseResult) {
	if result.file != nil {
		_ = result.file.Close()
	}
}

func assertRegularLeaseResult(t *testing.T, operation, path string, file *os.File) {
	t.Helper()
	want := regularLeaseContents
	var data []byte
	var err error
	if operation == "read" {
		data, err = io.ReadAll(file)
	} else {
		data, err = os.ReadFile(path) //nolint:gosec // generated fixture path under t.TempDir
	}
	switch operation {
	case "write-truncate", "create-truncate":
		want = ""
	case "truncate":
		want = regularLeaseContents[:4]
	case "chmod":
		assertRegularLeaseMode(t, path, 0o640)
	}
	if err != nil || string(data) != want {
		t.Fatalf("contents after operation = %q, %v; want %q", data, err, want)
	}
}

func assertRegularLeaseMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != want {
		t.Fatalf("mode = %#o; want %#o", info.Mode().Perm(), want)
	}
}

type regularLeaseHolder struct {
	control io.WriteCloser
	events  *os.File
	reader  *bufio.Reader
	done    chan struct{}
	waitErr error
	stop    func()
}

func startRegularLeaseHolder(t *testing.T, path string, kind int) *regularLeaseHolder {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	defer func() { _ = writer.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*regularLeaseTimeout)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRegularLeaseHelper$") //nolint:gosec // executes this test binary with fixed arguments
	cmd.Env = append(os.Environ(), regularLeaseHelperEnv+"="+strconv.Itoa(kind), "IRONPORT_REGULAR_LEASE_PATH="+path)
	cmd.Stdout, cmd.Stderr = writer, io.Discard
	control, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	holder := &regularLeaseHolder{control: control, events: reader, reader: bufio.NewReader(reader), done: make(chan struct{})}
	go func() { holder.waitErr = cmd.Wait(); close(holder.done) }()
	holder.stop = sync.OnceFunc(func() {
		_ = control.Close()
		cancel()
		select {
		case <-holder.done:
		case <-time.After(regularLeaseTimeout):
			t.Error("lease holder did not exit during cleanup")
		}
	})
	t.Cleanup(holder.stop)
	if ready := holder.event(t); ready != "ready" {
		if strings.HasPrefix(ready, "unsupported: ") {
			t.Skip(ready)
		}
		t.Fatalf("lease setup: %s", ready)
	}
	return holder
}

func (h *regularLeaseHolder) event(t *testing.T) string {
	t.Helper()
	if err := h.events.SetReadDeadline(time.Now().Add(regularLeaseTimeout)); err != nil {
		t.Fatal(err)
	}
	line, err := h.reader.ReadString('\n')
	if err != nil {
		t.Fatalf("lease helper event: %v", err)
	}
	return strings.TrimSuffix(line, "\n")
}

func (h *regularLeaseHolder) expect(t *testing.T, want string) {
	t.Helper()
	if got := h.event(t); got != want {
		t.Fatalf("lease event = %q; want %q", got, want)
	}
}

func (h *regularLeaseHolder) wait(t *testing.T) {
	t.Helper()
	select {
	case <-h.done:
		if h.waitErr != nil {
			t.Fatalf("lease holder: %v", h.waitErr)
		}
	case <-time.After(regularLeaseTimeout):
		t.Fatal("lease holder did not exit")
	}
}

func TestRegularLeaseHelper(t *testing.T) {
	value := os.Getenv(regularLeaseHelperEnv)
	if value == "" {
		return
	}
	kind, err := strconv.Atoi(value)
	if err != nil || (kind != unix.F_RDLCK && kind != unix.F_WRLCK) {
		t.Fatal("invalid lease type")
	}
	if err := runRegularLeaseHelper(kind); err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fatal(err)
	}
}

func runRegularLeaseHelper(kind int) error {
	flags := os.O_RDONLY
	if kind == unix.F_WRLCK {
		flags = os.O_RDWR
	}
	file, err := os.OpenFile(os.Getenv("IRONPORT_REGULAR_LEASE_PATH"), flags, 0) //nolint:gosec // parent test supplies its temporary fixture path
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	notifications := make(chan os.Signal, 1)
	signal.Notify(notifications, unix.SIGIO)
	defer signal.Stop(notifications)
	if _, err := unix.FcntlInt(file.Fd(), unix.F_SETOWN, os.Getpid()); err != nil {
		return err
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_SETLEASE, kind); err != nil {
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOSYS) {
			fmt.Printf("unsupported: %v\n", err)
			return nil
		}
		return err
	}
	defer func() { _, _ = unix.FcntlInt(file.Fd(), unix.F_SETLEASE, unix.F_UNLCK) }()
	fmt.Println("ready")
	select {
	case <-notifications:
	case <-time.After(regularLeaseTimeout):
		return errors.New("no lease break notification")
	}
	data := make([]byte, len(regularLeaseContents))
	n, err := file.ReadAt(data, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	fmt.Printf("break %q\n", data[:n])
	command, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return fmt.Errorf("read lease release command: %w", err)
	}
	if command != "release\n" {
		return fmt.Errorf("lease release command = %q; want release", command)
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_SETLEASE, unix.F_UNLCK); err != nil {
		return err
	}
	fmt.Println("released")
	return nil
}
