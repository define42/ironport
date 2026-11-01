//go:build linux

package ironport

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSSHKeyQueryDefersJailUntilProof(t *testing.T) {
	_, key := testClientKey(t)
	for _, exists := range []bool{false, true} {
		t.Run(fmt.Sprintf("root_exists=%t", exists), func(t *testing.T) {
			checkSSHKeyQueryDeferredRoot(t, key, exists)
		})
	}
}

func checkSSHKeyQueryDeferredRoot(t *testing.T, key ssh.PublicKey, exists bool) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "root")
	if exists {
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	_, state, cfg := newSSHKeyQueryTestServer(t, UserInfo{Root: root, AuthorizedKeys: []ssh.PublicKey{key}})
	output := captureRootDiagnosticLog(t)
	metadata := testConnMetadata{user: "alice"}
	query, err := cfg.PublicKeyCallback(metadata, key)
	if err != nil {
		t.Fatalf("unsigned key query: %v", err)
	}
	assertSSHKeyQueryHasNoJail(t, query, state)
	assertSSHJailDescriptors(t, root, 0)
	if output.Len() != 0 {
		t.Fatalf("unsigned query emitted a diagnostic: %q", output.String())
	}
	if !exists {
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	permissions, err := cfg.VerifiedPublicKeyCallback(metadata, key, query, "")
	if err != nil {
		t.Fatalf("verified proof: %v", err)
	}
	if state.fs == nil || permissions.Extensions["jailRoot"] != root {
		t.Fatalf("proof did not retain the current root: permissions=%+v", permissions)
	}
	assertSSHJailDescriptors(t, root, 1)
	state.close()
	assertSSHJailDescriptors(t, root, 0)
}

func TestSSHKeyProofRejectsRevokedUserOrKey(t *testing.T) {
	_, key := testClientKey(t)
	_, replacementKey := testClientKey(t)
	for _, tc := range []struct {
		name   string
		update func(*Server, UserInfo)
	}{
		{"removed user", func(s *Server, _ UserInfo) { s.RemoveUser("alice") }},
		{"removed key", func(s *Server, _ UserInfo) { s.RemoveUserKey("alice", key) }},
		{"replaced key", func(s *Server, user UserInfo) {
			user.AuthorizedKeys = []ssh.PublicKey{replacementKey}
			s.AddUser("alice", user)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user := UserInfo{Root: t.TempDir(), AuthorizedKeys: []ssh.PublicKey{key}}
			server, state, cfg := newSSHKeyQueryTestServer(t, user)
			metadata := testConnMetadata{user: "alice"}
			query, err := cfg.PublicKeyCallback(metadata, key)
			if err != nil {
				t.Fatal(err)
			}
			assertSSHKeyQueryHasNoJail(t, query, state)
			tc.update(server, user)
			permissions, err := cfg.VerifiedPublicKeyCallback(metadata, key, query, "")
			if !errors.Is(err, errInvalidCredentials) || permissions != nil || state.fs != nil {
				t.Fatalf("revoked proof = %v, %v; retained jail=%v", permissions, err, state.fs)
			}
			assertSSHJailDescriptors(t, user.Root, 0)
		})
	}
}

func TestSSHKeyProofUsesUpdatedRootAndPermissions(t *testing.T) {
	_, key := testClientKey(t)
	original := UserInfo{Root: t.TempDir(), CanRead: true, AuthorizedKeys: []ssh.PublicKey{key}}
	server, state, cfg := newSSHKeyQueryTestServer(t, original)
	metadata := testConnMetadata{user: "alice"}
	query, err := cfg.PublicKeyCallback(metadata, key)
	if err != nil {
		t.Fatal(err)
	}
	assertSSHKeyQueryHasNoJail(t, query, state)
	replacement := original
	replacement.Root = t.TempDir()
	replacement.CanRead, replacement.CanWrite = false, true
	server.AddUser("alice", replacement)
	_, currentRevision, _ := server.userSnapshot("alice")
	permissions, err := cfg.VerifiedPublicKeyCallback(metadata, key, query, "")
	if err != nil {
		t.Fatal(err)
	}
	if permissions.Extensions["jailRoot"] != replacement.Root || permissions.Extensions["user"] != "alice" ||
		permissions.Extensions["canRead"] != "false" || permissions.Extensions["canWrite"] != "true" {
		t.Fatalf("proof retained query-time user configuration: %+v", permissions.Extensions)
	}
	if state.fs == nil || state.fs.FullPath(".") != replacement.Root || state.revision != currentRevision {
		t.Fatalf("proof state does not own current root/revision: %+v", state)
	}
	assertSSHJailDescriptors(t, original.Root, 0)
	assertSSHJailDescriptors(t, replacement.Root, 1)
}

func TestSSHKeyQueryRejectsRevisionChangedDuringKeyMatch(t *testing.T) {
	_, key := testClientKey(t)
	root := t.TempDir()
	server, state, cfg := newSSHKeyQueryTestServer(t, UserInfo{Root: root, AuthorizedKeys: []ssh.PublicKey{key}})
	output := captureRootDiagnosticLog(t)
	presented := revisionObservedKey{PublicKey: key, onMarshal: func() { server.RemoveUser("alice") }}
	permissions, err := cfg.PublicKeyCallback(testConnMetadata{user: "alice"}, presented)
	if !errors.Is(err, errInvalidCredentials) || permissions != nil || state.fs != nil {
		t.Fatalf("query accepted a stale key match: permissions=%v err=%v state=%+v", permissions, err, state)
	}
	assertSSHJailDescriptors(t, root, 0)
	if strings.Contains(output.String(), "jail-root check failed") {
		t.Fatalf("stale query emitted a root diagnostic: %q", output.String())
	}
}

func newSSHKeyQueryTestServer(t *testing.T, user UserInfo) (*Server, *sshAuthState, *ssh.ServerConfig) {
	t.Helper()
	server := NewServer(&Config{SftpSigner: testSigner(t), Users: map[string]UserInfo{"alice": user}})
	state := &sshAuthState{}
	t.Cleanup(state.close)
	return server, state, state.config(server.sshServerConfig())
}

func assertSSHKeyQueryHasNoJail(t *testing.T, permissions *ssh.Permissions, state *sshAuthState) {
	t.Helper()
	if permissions == nil {
		t.Fatal("accepted key query returned no admission permissions")
	}
	if len(permissions.Extensions) != 0 || len(permissions.CriticalOptions) != 0 || len(permissions.ExtraData) != 1 {
		t.Fatalf("unsigned query returned more than admission metadata: %+v", permissions)
	}
	if permissions.ExtraData[sshJailFSKey{}] != nil || permissions.ExtraData[sshRevisionKey{}] != nil ||
		state.fs != nil || state.revision != 0 {
		t.Fatalf("unsigned query retained a jail or user revision: permissions=%+v state=%+v", permissions, state)
	}
}
