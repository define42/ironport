//go:build linux

package ironport

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/define42/ironport/internal/jailfs"
	"golang.org/x/crypto/ssh"
)

func TestFTPAuthenticationCommitRejectsStaleOrClosedConnections(t *testing.T) {
	changes := map[string]func(*Server, *ftpSession, UserInfo){
		"changed password": func(s *Server, _ *ftpSession, u UserInfo) {
			u.Password = "new-password"
			s.AddUser("alice", u)
		},
		"removed user": func(s *Server, _ *ftpSession, _ UserInfo) { s.RemoveUser("alice") },
		"removed and recreated user": func(s *Server, _ *ftpSession, u UserInfo) {
			s.RemoveUser("alice")
			s.AddUser("alice", u)
		},
		"cancelled connection": func(s *Server, _ *ftpSession, _ UserInfo) { s.forceCloseActiveConns() },
		"untracked connection": func(s *Server, f *ftpSession, _ UserInfo) { s.untrackConn(f.rawConn) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			u := UserInfo{Password: "pw", Root: t.TempDir(), CanRead: true}
			s, f := newFTPRevisionSession(t, u)
			snapshot, root, revision, ok := s.authenticateUser("alice", func(stored UserInfo) bool {
				return checkPassword(stored.Password, "pw")
			})
			if !ok {
				t.Fatal("initial credential check failed")
			}
			jfs, err := jailfs.Open(root)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = jfs.Close() })
			change(s, f, u)
			if f.commitAuthentication(snapshot, revision, jfs) {
				t.Fatal("stale or closed connection authenticated")
			}
			assertFTPAuthenticationNotInstalled(t, f, jfs)
		})
	}
}

func assertFTPAuthenticationNotInstalled(t *testing.T, f *ftpSession, jfs *jailfs.FS) {
	t.Helper()
	if f.authenticated || f.fs != nil || f.user.Root != "" {
		t.Fatal("failed commit installed authenticated session state")
	}
	if _, err := jfs.Stat("/"); err == nil {
		t.Fatal("failed commit retained its opened jail")
	}
}

func newFTPRevisionSession(t *testing.T, u UserInfo) (*Server, *ftpSession) {
	t.Helper()
	s := NewServer(&Config{Users: map[string]UserInfo{"alice": u}})
	conn := &stubConn{}
	if !s.trackConn(conn) {
		t.Fatal("control connection was not admitted")
	}
	t.Cleanup(func() {
		s.untrackConn(conn)
		s.connWG.Done()
	})
	f := &ftpSession{server: s, username: "alice", rawConn: conn, conn: conn}
	t.Cleanup(f.closeJail)
	return s, f
}

func TestFTPUserChangesCancelDataOperations(t *testing.T) {
	_, key := testClientKey(t)
	for _, action := range []string{"replace user", "remove key"} {
		for _, stage := range []string{"passive accept", "established upload"} {
			t.Run(action+"/"+stage, func(t *testing.T) {
				u := UserInfo{Password: "pw", Root: t.TempDir(), CanWrite: true, AuthorizedKeys: []ssh.PublicKey{key}}
				cfg := newTestFTPConfig(t, map[string]UserInfo{"alice": u}, "", false)
				cfg.FtpDataAcceptTimeout = time.Minute
				s, addr, stop := startTestFTPServerWithConfig(t, cfg)
				t.Cleanup(stop)
				client := dialFTP(t, addr)
				client.login("alice", "pw")
				data := startFTPRevisionUpload(t, client, u.Root, stage)
				if action == "replace user" {
					u.Password = "changed"
					s.AddUser("alice", u)
				} else {
					s.RemoveUserKey("alice", key)
				}
				assertFTPRevisionConnectionClosed(t, client.conn)
				assertFTPRevisionUploadCancelled(t, s, data)
			})
		}
	}
}

func assertFTPRevisionUploadCancelled(t *testing.T, s *Server, data net.Conn) {
	t.Helper()
	if data != nil {
		assertFTPRevisionConnectionClosed(t, data)
	}
	waitFTPRevisionHandler(t, s)
	waitFTPPassiveRelease(t, s)
	select {
	case event := <-s.CompletedUploads():
		t.Fatalf("revoked upload announced success: %+v", event)
	default:
	}
}

func startFTPRevisionUpload(t *testing.T, client *ftpTestClient, root, stage string) net.Conn {
	t.Helper()
	if stage == "passive accept" {
		client.command(227, "PASV")
		client.command(150, "STOR pending")
		return nil
	}
	data, _ := client.passiveConn()
	t.Cleanup(func() { _ = data.Close() })
	client.command(150, "STOR pending")
	if _, err := data.Write([]byte("partial upload")); err != nil {
		t.Fatal(err)
	}
	// A nonzero file size proves the server has passed data setup and entered
	// the upload copy, rather than merely buffering bytes in the socket.
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		info, err := os.Stat(filepath.Join(root, "pending"))
		if err == nil && info.Size() > 0 {
			return data
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("upload copy did not start")
	return nil
}

func assertFTPRevisionConnectionClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := conn.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("revoked connection remained usable: n=%d, err=%v", n, err)
	} else if netErr, ok := errors.AsType[net.Error](err); ok && netErr.Timeout() {
		t.Fatal("revocation did not close the connection before its read deadline")
	}
}

func waitFTPRevisionHandler(t *testing.T, s *Server) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		s.connWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("revoked FTP handler did not finish")
	}
}

func TestFTPBenignUserChangesPreserveSession(t *testing.T) {
	u := UserInfo{Password: "pw", Root: t.TempDir()}
	s, addr, stop := startTestFTPServer(t, map[string]UserInfo{"alice": u}, "")
	t.Cleanup(stop)
	client := dialFTP(t, addr)
	client.login("alice", "pw")
	s.AddUser("alice", u)
	client.command(200, "NOOP")
	_, key := testClientKey(t)
	s.AddUserKey("alice", key)
	client.command(200, "NOOP")
	s.AddUserKey("alice", key)
	client.command(200, "NOOP")
	_, missingKey := testClientKey(t)
	s.RemoveUserKey("alice", missingKey)
	client.command(200, "NOOP")
}
