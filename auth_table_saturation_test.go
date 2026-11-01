//go:build linux

package ironport

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/define42/ironport/internal/authlimit"
	"golang.org/x/crypto/ssh"
)

func TestAuthUsernameBudgetIndependentOfUserExistence(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(fmt.Sprintf("configured=%t", present), func(t *testing.T) {
			server, _, _, _ := newAuthTableServer(t, AuthLimitConfig{
				GlobalBurst: 128, IPBurst: 128, UserBurst: 2, UserInterval: time.Hour,
			})
			if !present {
				server.RemoveUser("alice")
			}
			for i := range 3 {
				_, retry := server.allowAuth("alice", "192.0.2.1")
				if (retry > 0) != (i == 2) {
					t.Fatalf("attempt %d retry=%v; configured=%t want limited=%t", i+1, retry, present, i == 2)
				}
			}
		})
	}
}

func TestAuthUnknownSSHNamesUseBoundedUsernameBudget(t *testing.T) {
	server, cfg, key, _ := newAuthTableServer(t, AuthLimitConfig{
		MaxEntries: 2, GlobalBurst: 128, IPBurst: 128, UserBurst: 2, UserInterval: time.Hour,
	})
	// One username slot makes collisions deterministic. Absent names consume
	// the same bounded budget as configured users, without recording failures.
	for i := range 2 {
		metadata := authTableMetadata(fmt.Sprintf("unknown-%d", i), fmt.Sprintf("2001:db8:1::%x", i+1))
		if _, err := cfg.PublicKeyCallback(metadata, key); !errors.Is(err, errInvalidCredentials) {
			t.Fatalf("unknown key offer %d: %v", i, err)
		}
	}
	if _, retry := server.allowAuth("alice", "198.51.100.1"); retry <= 0 {
		t.Fatal("unknown SSH names bypassed the shared username budget")
	}
}

func TestAuthIPv6HostRotationSharesPrefixLimit(t *testing.T) {
	server, _, _, _ := newAuthTableServer(t, AuthLimitConfig{IPBurst: 3, IPInterval: time.Hour})
	for i := range 4 {
		_, retry := server.allowAuth(fmt.Sprintf("unknown-%d", i), fmt.Sprintf("2001:db8:1::%x", i+1))
		if (retry > 0) != (i == 3) {
			t.Fatalf("offer %d from the same IPv6 /64 retry=%v; want limited=%t", i+1, retry, i == 3)
		}
	}
}

func TestAuthIdentityFloodDoesNotLockOutFreshProtocolLogins(t *testing.T) {
	server, cfg, key, _ := newAuthTableServer(t, AuthLimitConfig{
		MaxEntries: 8, GlobalBurst: 128, IPBurst: 128, UserBurst: 128,
		GlobalInterval: time.Millisecond, IPInterval: time.Millisecond, UserInterval: time.Millisecond,
	})
	for i := range 100 {
		metadata := authTableMetadata(fmt.Sprintf("unknown-%d", i), fmt.Sprintf("2001:db8:%x::1", i+1))
		if _, err := cfg.PublicKeyCallback(metadata, key); !errors.Is(err, errInvalidCredentials) {
			t.Fatalf("unknown key offer %d: %v", i, err)
		}
	}
	// Refill even a worst-case collision of every probe into one slot.
	// This is well before identity expiry, so recovery cannot rely on eviction.
	_, _ = server.authControl().Allow("clock-only", "2001:db8:ffff::1", time.Now().Add(time.Second))
	t.Run("SSH", func(t *testing.T) {
		var state sshAuthState
		defer state.close()
		config := state.config(server.sshServerConfig())
		permissions, err := config.PasswordCallback(authTableMetadata("alice", "198.51.100.1"), []byte("pw"))
		if err != nil || permissions == nil || state.fs == nil {
			t.Fatalf("SSH login after identity flood: permissions=%v err=%v jail=%v", permissions, err, state.fs)
		}
	})
	t.Run("FTP", func(t *testing.T) { requireAuthTableFTPLogin(t, server) })
	t.Run("HTTP", func(t *testing.T) {
		response := doHTTPUpload(t, server, "alice", "pw", "file", "after-flood.txt", []byte("accepted"))
		if response.Code != http.StatusCreated {
			t.Fatalf("HTTP login after identity flood: status=%d body=%q", response.Code, response.Body.String())
		}
	})
}

func TestAuthPendingFailuresSurviveUserCreation(t *testing.T) {
	server, _, _, user := newAuthTableServer(t, authTableBackoffLimits())
	server.RemoveUser("alice")
	attempts := captureAuthTableAttempts(t, server, "alice", "192.0.2.1", 3)
	server.AddUser("alice", user)
	for _, attempt := range attempts {
		server.authFailed(attempt, "alice", "192.0.2.1", CompletedUploadProtocolSFTP, nil, false)
	}
	if _, retry := server.allowAuth("another-user", "192.0.2.1"); retry <= 0 {
		t.Fatal("pending failures did not retain source backoff")
	}
	ip := findAuthTableUnblockedSource(t, server)
	if _, retry := server.allowAuth("alice", ip); retry <= 0 {
		t.Fatal("creating the account discarded pending username failures")
	}
}

func TestAuthPendingSuccessUsesSameUsernameAcrossCreation(t *testing.T) {
	server, _, _, user := newAuthTableServer(t, authTableBackoffLimits())
	server.RemoveUser("alice")
	pending := captureAuthTableAttempts(t, server, "alice", "192.0.2.1", 1)[0]
	server.AddUser("alice", user)
	for range 2 {
		recordAuthTableFailure(t, server, "alice", "192.0.2.2")
	}
	// Verification can succeed after creation. The original admission still
	// identifies this username, so its success clears exclusive failures.
	server.authSucceeded(pending)
	recordAuthTableFailure(t, server, "alice", "192.0.2.2")
	ip := findAuthTableUnblockedSource(t, server)
	if _, retry := server.allowAuth("alice", ip); retry != 0 {
		t.Fatalf("creation changed the pending attempt's username accounting: %v", retry)
	}
}

func TestAuthUsernameCooldownSurvivesRemovalAndRecreation(t *testing.T) {
	server, _, _, user := newAuthTableServer(t, authTableBackoffLimits())
	for range 3 {
		recordAuthTableFailure(t, server, "alice", "192.0.2.1")
	}
	server.RemoveUser("alice")
	ip := findAuthTableUnblockedSource(t, server)
	if _, retry := server.allowAuth("alice", ip); retry <= 0 {
		t.Fatal("removing the user admitted an attempt during username cooldown")
	}
	server.AddUser("alice", user)
	if _, retry := server.allowAuth("alice", ip); retry <= 0 {
		t.Fatal("recreating the user discarded its username cooldown")
	}
}

func TestAuthSSHQueryAdmissionRetainsRemovedUsername(t *testing.T) {
	server, cfg, key, user := newAuthTableServer(t, authTableBackoffLimits())
	metadata := authTableMetadata("alice", "192.0.2.1")
	queries := make([]*ssh.Permissions, 3)
	for i := range queries {
		permissions, err := cfg.PublicKeyCallback(metadata, key)
		if err != nil {
			t.Fatalf("eligible query %d: %v", i, err)
		}
		queries[i] = permissions
	}
	server.RemoveUser("alice")
	for _, query := range queries {
		if _, err := cfg.VerifiedPublicKeyCallback(metadata, key, query, ""); !errors.Is(err, errInvalidCredentials) {
			t.Fatalf("removed-user proof: %v", err)
		}
	}
	server.AddUser("alice", user)
	ip := findAuthTableUnblockedSource(t, server)
	if _, retry := server.allowAuth("alice", ip); retry <= 0 {
		t.Fatal("removal between query and proof discarded the original username's failure backoff")
	}
}

type authTableConnMetadata struct {
	testConnMetadata

	ip string
}

func (m authTableConnMetadata) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(m.ip), Port: 12345}
}

func authTableMetadata(username, ip string) authTableConnMetadata {
	return authTableConnMetadata{user: username, ip: ip}
}

func newAuthTableServer(t *testing.T, limits AuthLimitConfig) (*Server, *ssh.ServerConfig, ssh.PublicKey, UserInfo) {
	t.Helper()
	_, key := testClientKey(t)
	user := UserInfo{Password: "pw", Root: t.TempDir(), AuthorizedKeys: []ssh.PublicKey{key}, CanRead: true, CanWrite: true}
	server := NewServer(&Config{
		SftpSigner: testSigner(t), Users: map[string]UserInfo{"alice": user}, AuthLimits: limits, AuthEventSize: 256,
	})
	return server, server.sshServerConfig(), key, user
}

func authTableBackoffLimits() AuthLimitConfig {
	return AuthLimitConfig{GlobalBurst: 1024, BackoffInitial: time.Hour, BackoffMax: time.Hour}
}

func captureAuthTableAttempts(t *testing.T, server *Server, username, ip string, count int) []authlimit.Attempt {
	t.Helper()
	attempts := make([]authlimit.Attempt, count)
	for i := range attempts {
		attempt, retry := server.allowAuth(username, ip)
		if retry != 0 {
			t.Fatalf("initial admission for %q: %v", username, retry)
		}
		attempts[i] = attempt
	}
	return attempts
}

func recordAuthTableFailure(t *testing.T, server *Server, username, ip string) {
	t.Helper()
	attempt := captureAuthTableAttempts(t, server, username, ip, 1)[0]
	server.authFailed(attempt, username, ip, CompletedUploadProtocolSFTP, nil, false)
}

func findAuthTableUnblockedSource(t *testing.T, server *Server) string {
	t.Helper()
	// Find an admitted control identity instead of assuming a chosen name or
	// address cannot collide with an active penalty in either partition.
	for i := range 128 {
		ip := fmt.Sprintf("2001:db8:%x::1", i+1)
		if _, retry := server.allowAuth(fmt.Sprintf("control-%d", i), ip); retry == 0 {
			return ip
		}
	}
	t.Fatal("no unblocked control source found")
	return ""
}

func requireAuthTableFTPLogin(t *testing.T, server *Server) {
	t.Helper()
	conn := &stubConn{}
	if !server.trackConn(conn) {
		t.Fatal("FTP control connection was not admitted")
	}
	t.Cleanup(func() {
		server.untrackConn(conn)
		server.connWG.Done()
	})
	var reply bytes.Buffer
	session := &ftpSession{
		server: server, username: "alice", clientIP: "198.51.100.2", conn: conn, rawConn: conn, w: bufio.NewWriter(&reply),
	}
	defer session.closeJail()
	session.cmdPass("pw")
	if !session.authenticated || !strings.HasPrefix(reply.String(), "230 ") {
		t.Fatalf("FTP login after identity flood: authenticated=%t reply=%q", session.authenticated, reply.String())
	}
}
