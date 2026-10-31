//go:build linux && integration

package ironport

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	leaseHelperEnv     = "IRONPORT_TEST_LEASE_HELPER"
	leaseHelperPathEnv = "IRONPORT_TEST_LEASE_PATH"
	leaseHelperTypeEnv = "IRONPORT_TEST_LEASE_TYPE"
	leaseTestTimeout   = 5 * time.Second
)

type leaseOperationResult struct {
	file *managedFile
	err  error
}

func TestJailFS_OpenRegularWaitsForConflictingLease(t *testing.T) {
	const original = "content that must remain until the lease is released"
	tests := []struct {
		name        string
		leaseType   int
		operation   func(*jailFS) (*managedFile, error)
		verifyHeld  func(*testing.T, string)
		verifyAfter func(*testing.T, string, *managedFile)
	}{
		{
			name:      "read waits for write lease",
			leaseType: unix.F_WRLCK,
			operation: func(jfs *jailFS) (*managedFile, error) {
				return jfs.OpenRead("leased")
			},
			verifyAfter: func(t *testing.T, _ string, file *managedFile) {
				t.Helper()
				got, err := io.ReadAll(file)
				if err != nil {
					t.Fatalf("read opened file: %v", err)
				}
				if string(got) != original {
					t.Fatalf("read opened file = %q, want %q", got, original)
				}
			},
		},
		{
			name:      "truncate write waits for read lease",
			leaseType: unix.F_RDLCK,
			operation: func(jfs *jailFS) (*managedFile, error) {
				return jfs.OpenWrite("leased", os.O_WRONLY|os.O_TRUNC, 0)
			},
			verifyHeld: func(t *testing.T, path string) {
				t.Helper()
				got, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read file while write open is blocked: %v", err)
				}
				if string(got) != original {
					t.Fatalf("file changed before lease release: got %q, want %q", got, original)
				}
			},
			verifyAfter: func(t *testing.T, path string, _ *managedFile) {
				t.Helper()
				got, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read truncated file: %v", err)
				}
				if len(got) != 0 {
					t.Fatalf("file after truncate open = %q, want empty", got)
				}
			},
		},
		{
			name:      "chmod waits for write lease",
			leaseType: unix.F_WRLCK,
			operation: func(jfs *jailFS) (*managedFile, error) {
				return nil, jfs.Chmod("leased", 0o640)
			},
			verifyHeld: func(t *testing.T, path string) {
				t.Helper()
				assertLeaseTestMode(t, path, 0o600, "before lease release")
			},
			verifyAfter: func(t *testing.T, path string, _ *managedFile) {
				t.Helper()
				assertLeaseTestMode(t, path, 0o640, "after chmod")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			filePath := filepath.Join(root, "leased")
			if err := os.WriteFile(filePath, []byte(original), 0o600); err != nil {
				t.Fatalf("create leased file: %v", err)
			}
			jfs, err := openJailFS(root)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = jfs.Close() })

			lease := startLeaseHelper(t, filePath, tt.leaseType)
			result := make(chan leaseOperationResult, 1)
			go func() {
				file, err := tt.operation(jfs)
				result <- leaseOperationResult{file: file, err: err}
			}()
			resultConsumed := false
			t.Cleanup(func() {
				// An assertion can end the subtest while the operation is still
				// waiting on the lease. Stop the holder first, then join the
				// operation and close any descriptor it managed to open.
				lease.stop()
				if resultConsumed {
					return
				}
				select {
				case pending := <-result:
					if pending.file != nil {
						_ = pending.file.Close()
					}
				case <-time.After(leaseTestTimeout):
					t.Error("lease operation did not stop during cleanup")
				}
			})

			lease.waitEvent(t, "break")
			if tt.verifyHeld != nil {
				tt.verifyHeld(t, filePath)
			}
			select {
			case got := <-result:
				resultConsumed = true
				if got.file != nil {
					_ = got.file.Close()
				}
				t.Fatalf("operation completed before lease release: %v", got.err)
			case <-time.After(100 * time.Millisecond):
			}

			lease.release(t)
			lease.waitEvent(t, "released")
			var got leaseOperationResult
			select {
			case got = <-result:
				resultConsumed = true
			case <-time.After(leaseTestTimeout):
				t.Fatal("operation remained blocked after lease release")
			}
			if got.err != nil {
				t.Fatalf("operation after lease release: %v", got.err)
			}
			if got.file != nil {
				t.Cleanup(func() { _ = got.file.Close() })
			}
			tt.verifyAfter(t, filePath, got.file)
			lease.wait(t)
		})
	}
}

func assertLeaseTestMode(t *testing.T, path string, want os.FileMode, when string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", when, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode %s = %#o, want %#o", when, got, want)
	}
}

type leaseHelperProcess struct {
	cmd         *exec.Cmd
	events      <-chan string
	eventReader *os.File
	control     *os.File
	done        chan struct{}
	waitErr     error
	released    bool
}

func startLeaseHelper(t *testing.T, path string, leaseType int) *leaseHelperProcess {
	t.Helper()
	eventReader, eventWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create lease event pipe: %v", err)
	}
	controlReader, controlWriter, err := os.Pipe()
	if err != nil {
		_ = eventReader.Close()
		_ = eventWriter.Close()
		t.Fatalf("create lease control pipe: %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestJailFS_LeaseHelperProcess$") //nolint:gosec // re-executes this test binary
	cmd.Env = append(os.Environ(),
		leaseHelperEnv+"=1",
		leaseHelperPathEnv+"="+path,
		leaseHelperTypeEnv+"="+strconv.Itoa(leaseType),
	)
	cmd.ExtraFiles = []*os.File{eventWriter, controlReader}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		_ = eventReader.Close()
		_ = eventWriter.Close()
		_ = controlReader.Close()
		_ = controlWriter.Close()
		t.Fatalf("start lease helper: %v", err)
	}
	_ = eventWriter.Close()
	_ = controlReader.Close()

	events := make(chan string, 4)
	go func() {
		defer close(events)
		scanner := bufio.NewScanner(eventReader)
		for scanner.Scan() {
			events <- scanner.Text()
		}
		if err := scanner.Err(); err != nil {
			events <- "protocol error: " + err.Error()
		}
	}()
	lease := &leaseHelperProcess{
		cmd:         cmd,
		events:      events,
		eventReader: eventReader,
		control:     controlWriter,
		done:        make(chan struct{}),
	}
	go func() {
		lease.waitErr = cmd.Wait()
		close(lease.done)
	}()
	t.Cleanup(lease.stop)

	select {
	case event, ok := <-lease.events:
		if !ok {
			t.Fatal("lease helper exited before reporting readiness")
		}
		switch {
		case event == "ready":
			return lease
		case strings.HasPrefix(event, "unsupported: "):
			t.Skipf("file leases unsupported: %s", strings.TrimPrefix(event, "unsupported: "))
		default:
			t.Fatalf("lease helper setup: %s", event)
		}
	case <-time.After(leaseTestTimeout):
		t.Fatal("lease helper did not report readiness")
	}
	return nil
}

func (p *leaseHelperProcess) waitEvent(t *testing.T, want string) {
	t.Helper()
	select {
	case got, ok := <-p.events:
		if !ok {
			t.Fatalf("lease helper exited before %q", want)
		}
		if got != want {
			t.Fatalf("lease helper event = %q, want %q", got, want)
		}
	case <-time.After(leaseTestTimeout):
		t.Fatalf("timed out waiting for lease helper event %q", want)
	}
}

func (p *leaseHelperProcess) release(t *testing.T) {
	t.Helper()
	if p.released {
		t.Fatal("lease helper release sent twice")
	}
	p.released = true
	if _, err := fmt.Fprintln(p.control, "release"); err != nil {
		t.Fatalf("release lease helper: %v", err)
	}
}

func (p *leaseHelperProcess) wait(t *testing.T) {
	t.Helper()
	select {
	case <-p.done:
		if p.waitErr != nil {
			t.Fatalf("lease helper exit: %v", p.waitErr)
		}
	case <-time.After(leaseTestTimeout):
		t.Fatal("lease helper did not exit")
	}
}

func (p *leaseHelperProcess) stop() {
	_ = p.control.Close()
	select {
	case <-p.done:
	default:
		_ = p.cmd.Process.Kill()
		select {
		case <-p.done:
		case <-time.After(leaseTestTimeout):
		}
	}
	_ = p.eventReader.Close()
}

func TestJailFS_LeaseHelperProcess(t *testing.T) {
	if os.Getenv(leaseHelperEnv) != "1" {
		return
	}
	events := os.NewFile(3, "lease-events")
	control := os.NewFile(4, "lease-control")
	if events == nil || control == nil {
		return
	}
	defer func() { _ = events.Close() }()
	defer func() { _ = control.Close() }()

	leaseType, err := strconv.Atoi(os.Getenv(leaseHelperTypeEnv))
	if err != nil || (leaseType != unix.F_RDLCK && leaseType != unix.F_WRLCK) {
		_, _ = fmt.Fprintf(events, "error: invalid lease type %q\n", os.Getenv(leaseHelperTypeEnv))
		return
	}
	flags := os.O_RDONLY
	if leaseType == unix.F_WRLCK {
		flags = os.O_RDWR
	}
	file, err := os.OpenFile(os.Getenv(leaseHelperPathEnv), flags, 0)
	if err != nil {
		_, _ = fmt.Fprintf(events, "error: open lease file: %v\n", err)
		return
	}
	defer func() { _ = file.Close() }()

	fd := file.Fd()
	if _, err := unix.FcntlInt(fd, unix.F_SETOWN, os.Getpid()); err != nil {
		_, _ = fmt.Fprintf(events, "error: set lease signal owner: %v\n", err)
		return
	}
	leaseSignals := make(chan os.Signal, 1)
	signal.Notify(leaseSignals, unix.SIGIO)
	defer signal.Stop(leaseSignals)
	if _, err := unix.FcntlInt(fd, unix.F_SETLEASE, leaseType); err != nil {
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP) {
			_, _ = fmt.Fprintf(events, "unsupported: %v\n", err)
			return
		}
		_, _ = fmt.Fprintf(events, "error: set lease: %v\n", err)
		return
	}
	leased := true
	defer func() {
		if leased {
			_, _ = unix.FcntlInt(fd, unix.F_SETLEASE, unix.F_UNLCK)
		}
	}()
	_, _ = fmt.Fprintln(events, "ready")

	select {
	case <-leaseSignals:
		_, _ = fmt.Fprintln(events, "break")
	case <-time.After(leaseTestTimeout):
		_, _ = fmt.Fprintln(events, "error: timed out waiting for lease break")
		return
	}

	commands := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(control)
		if scanner.Scan() {
			commands <- scanner.Text()
			return
		}
		commands <- ""
	}()
	select {
	case command := <-commands:
		if command != "release" {
			_, _ = fmt.Fprintf(events, "error: lease command = %q, want release\n", command)
			return
		}
	case <-time.After(leaseTestTimeout):
		_, _ = fmt.Fprintln(events, "error: timed out waiting for lease release")
		return
	}
	if _, err := unix.FcntlInt(fd, unix.F_SETLEASE, unix.F_UNLCK); err != nil {
		_, _ = fmt.Fprintf(events, "error: release lease: %v\n", err)
		return
	}
	leased = false
	_, _ = fmt.Fprintln(events, "released")
}
