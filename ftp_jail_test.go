//go:build linux

package ironport

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestFTPAuthenticationCommitRetainsOpenedJail(t *testing.T) {
	base, configuredRoot := newRetainedJailFixture(t)
	u := UserInfo{Password: "pw", Root: configuredRoot, CanRead: true, CanWrite: true}
	s, f := newFTPRevisionSession(t, u)
	snapshot, fs, revision, ok := s.authenticateUser("alice", func(stored UserInfo) bool {
		return checkPassword(stored.Password, "pw")
	})
	if !ok {
		t.Fatal("authentication failed")
	}
	t.Cleanup(func() { _ = fs.Close() })
	if err := replaceRetainedJailPath(base); err != nil {
		t.Fatal(err)
	}
	if !f.commitAuthentication(snapshot, revision, fs) {
		t.Fatal("authentication commit failed after root pathname replacement")
	}
	var output bytes.Buffer
	f.w = bufio.NewWriter(&output)
	f.handleFTPCommand("SIZE", "/marker")
	if got := output.String(); !strings.Contains(got, "213 13\r\n") {
		t.Fatalf("SIZE from retained jail = %q; want original marker size13", got)
	}
	f.logoutIfAuthenticated()
	if f.fs != nil {
		t.Fatal("logout retained the session jail")
	}
	if _, err := fs.Stat("/"); err == nil {
		t.Fatal("logout did not close the authenticated jail descriptor")
	}
}
