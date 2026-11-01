//go:build linux

package ironport

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateJailRootsValidRootsReleaseDescriptors(t *testing.T) {
	root := t.TempDir()
	server := NewServer(&Config{Users: map[string]UserInfo{"alice": {Root: root}}})
	output := captureRootDiagnosticLog(t)
	before := countRetainedJailDescriptors(t, root)
	for range 3 {
		if err := checkJailRoot(root); err != nil {
			t.Fatal(err)
		}
		if err := server.ValidateJailRoots(); err != nil {
			t.Fatal(err)
		}
	}
	if after := countRetainedJailDescriptors(t, root); after != before {
		t.Fatalf("root descriptors after validation = %d; before = %d", after, before)
	}
	if output.Len() != 0 {
		t.Fatalf("valid root produced diagnostics: %q", output.String())
	}
}

func TestValidateJailRootsInvalidRootsAreAdvisory(t *testing.T) {
	base := t.TempDir()
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(base, link); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, root string }{
		{"missing", filepath.Join(base, "missing\r\n\x1b\"root")},
		{"blank", " \t\n"},
		{"regular_file", file},
		{"symlink", link},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const username = "alice\r\n\x1b\"user"
			server := NewServer(&Config{Users: map[string]UserInfo{username: {Root: tc.root}}})
			rootErr := checkJailRoot(tc.root)
			if rootErr == nil {
				t.Fatal("invalid fixture root passed validation")
			}
			output := captureRootDiagnosticLog(t)
			if err := server.ValidateJailRoots(); err != nil {
				t.Fatalf("invalid user root must be advisory: %v", err)
			}
			assertEscapedRootDiagnostic(t, output.String(), username, tc.root, rootErr.Error())
		})
	}
}

func TestRootDiagnosticsSuppressStaleRevisions(t *testing.T) {
	for _, removed := range []bool{false, true} {
		t.Run(fmt.Sprintf("removed=%t", removed), func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "missing")
			server := NewServer(&Config{Users: map[string]UserInfo{"alice": {Root: root}}})
			_, oldRevision, _ := server.userSnapshot("alice")
			valid := UserInfo{Root: t.TempDir()}
			if removed {
				server.RemoveUser("alice")
			} else {
				server.AddUser("alice", valid)
			}
			output := captureRootDiagnosticLog(t)
			rootErr := errors.New("stale root failure")
			server.warnUnusableJailRoot("alice", root, oldRevision)
			server.logUnusableJailRootIfCurrent("alice", root, oldRevision, rootErr)
			server.logRootAuthFailure("alice", root, oldRevision, rootErr)
			if output.Len() != 0 {
				t.Fatalf("stale revision produced diagnostics: %q", output.String())
			}
			server.AddUser("alice", valid)
			_, revision, _ := server.userSnapshot("alice")
			server.logRootAuthFailure("alice", valid.Root, revision, rootErr)
			assertEscapedRootDiagnostic(t, output.String(), "alice", valid.Root, rootErr.Error())
			if !strings.Contains(output.String(), "suppressed=0") {
				t.Fatalf("stale diagnostics consumed the current root sample: %q", output.String())
			}
		})
	}
}

func TestAuthenticationRootDiagnosticsRequireCorrectCredentials(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing")
	server := NewServer(&Config{Users: map[string]UserInfo{"alice": {Password: "correct", Root: root}}})
	output := captureRootDiagnosticLog(t)
	for _, tc := range []struct{ name, username, password string }{
		{"wrong_password", "alice", "wrong"},
		{"unknown_user", "unknown", "correct"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertRootAuthenticationRejected(t, server, tc.username, tc.password)
		})
	}
	if output.Len() != 0 {
		t.Fatalf("invalid credentials exposed root diagnostics: %q", output.String())
	}
	assertRootAuthenticationRejected(t, server, "alice", "correct")
	rootErr := checkJailRoot(root)
	if rootErr == nil {
		t.Fatal("invalid fixture root passed validation")
	}
	assertEscapedRootDiagnostic(t, output.String(), "alice", root, rootErr.Error())
}

func TestRootAuthenticationDiagnosticsSampleIndependently(t *testing.T) {
	const username = "alice\r\n\x1b\"user"
	root := filepath.Join(t.TempDir(), "missing\r\n\x1b\"root")
	server := NewServer(&Config{Users: map[string]UserInfo{username: {Root: root}}})
	_, revision, _ := server.userSnapshot(username)
	rootErr := errors.New("failed\r\n\x1b\"operation")
	output := captureRootDiagnosticLog(t)

	server.authFailed(username, "192.0.2.1", "http", nil, false)
	if !strings.Contains(output.String(), "login failed") {
		t.Fatalf("missing ordinary authentication diagnostic: %q", output.String())
	}
	server.authLogs.mu.Lock()
	server.authLogs.next = time.Now().Add(time.Hour)
	server.authLogs.mu.Unlock()
	output.Reset()
	server.logRootAuthFailure(username, root, revision, rootErr)
	assertEscapedRootDiagnostic(t, output.String(), username, root, rootErr.Error())
	if !strings.Contains(output.String(), "suppressed=0") {
		t.Fatalf("ordinary authentication consumed the root sample: %q", output.String())
	}

	setRootDiagnosticSampleTime(server, time.Now().Add(time.Hour))
	output.Reset()
	for range 4 {
		server.logRootAuthFailure(username, root, revision, rootErr)
	}
	if output.Len() != 0 {
		t.Fatalf("root failures bypassed sampling: %q", output.String())
	}
	setRootDiagnosticSampleTime(server, time.Time{})
	server.logRootAuthFailure(username, root, revision, rootErr)
	assertEscapedRootDiagnostic(t, output.String(), username, root, rootErr.Error())
	if !strings.Contains(output.String(), "suppressed=4") {
		t.Fatalf("root diagnostic lost its suppressed count: %q", output.String())
	}
}

// These tests use the process logger and deliberately do not run in parallel.
func captureRootDiagnosticLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(previous) })
	return &output
}

func assertEscapedRootDiagnostic(t *testing.T, output string, fields ...string) {
	t.Helper()
	if strings.Count(output, "\n") != 1 || strings.ContainsAny(output, "\r\x00\x1b") {
		t.Fatalf("root diagnostic contains unescaped controls or extra lines: %q", output)
	}
	for _, field := range fields {
		if !strings.Contains(output, fmt.Sprintf("%q", field)) {
			t.Errorf("root diagnostic %q lacks quoted field %q", output, field)
		}
	}
}

func assertRootAuthenticationRejected(t *testing.T, server *Server, username, password string) {
	t.Helper()
	_, jfs, revision, ok := server.authenticateUser(username, func(user UserInfo) bool {
		return checkPassword(user.Password, password)
	})
	if jfs != nil {
		_ = jfs.Close()
		t.Fatal("rejected authentication returned a jail")
	}
	if ok || revision != 0 {
		t.Fatalf("authentication = ok:%t revision:%d; want rejection", ok, revision)
	}
}

func setRootDiagnosticSampleTime(server *Server, next time.Time) {
	server.rootAuthLogs.mu.Lock()
	defer server.rootAuthLogs.mu.Unlock()
	server.rootAuthLogs.next = next
}
