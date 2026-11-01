//go:build linux && integration

package ironport

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newFTPPathnameClient(t *testing.T) (string, *ftpTestClient) {
	t.Helper()
	root := t.TempDir()
	_, addr, stop := startTestFTPServer(t, map[string]UserInfo{
		"alice": {Password: "pw", Root: root, CanRead: true, CanWrite: true},
	}, "")
	t.Cleanup(stop)
	client := dialFTP(t, addr)
	client.login("alice", "pw")
	return root, client
}

func TestFTPDeletePreservesPathnameWhitespace(t *testing.T) {
	root, client := newFTPPathnameClient(t)
	for _, name := range []string{"report ", " report", "re port", " ", "\treport", "report\t"} {
		t.Run(name, func(t *testing.T) {
			client := &ftpTestClient{t: t, conn: client.conn, tp: client.tp}
			if err := os.WriteFile(filepath.Join(root, "report"), []byte("decoy"), 0o600); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(root, name)
			if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
				t.Fatal(err)
			}
			client.command(250, "DELE %s", name)
			if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("requested file %q was not deleted: %v", name, err)
			}
			if data, err := os.ReadFile(filepath.Join(root, "report")); err != nil || string(data) != "decoy" { //nolint:gosec // path is a fixed fixture in a test-owned temporary directory
				t.Fatalf("DELE %q changed the decoy: data=%q err=%v", name, data, err)
			}
		})
	}
}

func TestFTPListingsPreservePathnameWhitespace(t *testing.T) {
	root, client := newFTPPathnameClient(t)
	for _, name := range []string{"report", "report detail ", " report", " ", "-report detail "} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, verb := range []string{"LIST", "NLST", "STAT"} {
		for _, arg := range []struct{ path, name string }{
			{"report detail ", "report detail "},
			{" report", " report"},
			{" ", " "},
			{"-la report detail ", "report detail "},
			{"-la  report", " report"},
			{"-- -report detail ", "-report detail "},
		} {
			t.Run(verb+"/"+arg.path, func(t *testing.T) {
				client := &ftpTestClient{t: t, conn: client.conn, tp: client.tp}
				listing := readFTPPathListing(t, client, verb, arg.path)
				assertFTPPathListing(t, verb, arg.name, listing)
			})
		}
	}
}

func assertFTPPathListing(t *testing.T, verb, name, listing string) {
	t.Helper()
	if verb == "NLST" {
		if listing != name+"\r\n" {
			t.Fatalf("NLST = %q; want %q", listing, name+"\r\n")
		}
		return
	}
	if verb == "LIST" && strings.Count(listing, "\n") != 1 {
		t.Fatalf("LIST returned multiple entries for file %q: %q", name, listing)
	}
	if !strings.Contains(listing, " "+name+"\n") {
		t.Fatalf("%s omitted exact filename %q: %q", verb, name, listing)
	}
}

func readFTPPathListing(t *testing.T, client *ftpTestClient, verb, arg string) string {
	t.Helper()
	if verb == "STAT" {
		return client.command(213, "%s %s", verb, arg)
	}
	dc, _ := client.passiveConn()
	defer func() { _ = dc.Close() }()
	client.send("%s %s", verb, arg)
	client.read(150)
	listing, err := io.ReadAll(dc)
	if err != nil {
		t.Fatal(err)
	}
	client.read(226)
	if verb == "LIST" {
		return strings.ReplaceAll(string(listing), "\r\n", "\n")
	}
	return string(listing)
}

func TestFTPMutationsPreservePathnameWhitespace(t *testing.T) {
	root, client := newFTPPathnameClient(t)
	const uploaded = " uploaded file "
	dc, _ := client.passiveConn()
	client.send("STOR %s", uploaded)
	client.read(150)
	if _, err := io.WriteString(dc, "payload"); err != nil {
		_ = dc.Close()
		t.Fatal(err)
	}
	_ = dc.Close()
	client.read(226)
	if data, err := os.ReadFile(filepath.Join(root, uploaded)); err != nil || string(data) != "payload" { //nolint:gosec // path is a fixed fixture in a test-owned temporary directory
		t.Fatalf("STOR changed the pathname: data=%q err=%v", data, err)
	}
	const renamed = " renamed file "
	client.command(350, "RNFR %s", uploaded)
	client.command(250, "RNTO %s", renamed)
	client.command(213, "MFMT 20240102030405 %s", renamed)
	info, err := os.Stat(filepath.Join(root, renamed))
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC); !info.ModTime().Equal(want) {
		t.Fatalf("MFMT mtime=%v; want %v", info.ModTime(), want)
	}
	client.command(257, "MKD  directory ")
	client.command(250, "CWD  directory ")
	if got := client.command(257, "PWD"); !strings.Contains(got, `"/ directory "`) {
		t.Fatalf("CWD/PWD changed pathname: %q", got)
	}
}
