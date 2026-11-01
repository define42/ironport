//go:build linux

package ironport

import (
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSSHAuthStateClosesSupersededJails(t *testing.T) {
	_, key := testClientKey(t)
	for _, next := range []string{"query", "password", "bad password", "proof", "revoked proof"} {
		t.Run(next, func(t *testing.T) {
			root := t.TempDir()
			server := NewServer(&Config{SftpSigner: testSigner(t), Users: map[string]UserInfo{
				"alice": {Password: "pw", Root: root, AuthorizedKeys: []ssh.PublicKey{key}},
			}})
			var state sshAuthState
			defer state.close()
			cfg := state.config(server.sshServerConfig())
			metadata := testConnMetadata{user: "alice"}
			query, err := cfg.PublicKeyCallback(metadata, key)
			if err != nil {
				t.Fatal(err)
			}
			assertSSHJailDescriptors(t, root, 1)
			err = nextSSHJailAuthentication(next, server, cfg, metadata, key, query)
			failed := next == "bad password" || next == "revoked proof"
			if (err != nil) != failed {
				t.Fatalf("authentication error = %v; want failure=%t", err, failed)
			}
			want := 1
			if failed {
				want = 0
			}
			assertSSHJailDescriptors(t, root, want)
			state.close()
			state.close()
			assertSSHJailDescriptors(t, root, 0)
		})
	}
}

func nextSSHJailAuthentication(next string, server *Server, cfg *ssh.ServerConfig, metadata testConnMetadata, key ssh.PublicKey, query *ssh.Permissions) error {
	var err error
	switch next {
	case "query":
		_, err = cfg.PublicKeyCallback(metadata, key)
	case "password":
		_, err = cfg.PasswordCallback(metadata, []byte("pw"))
	case "bad password":
		_, err = cfg.PasswordCallback(metadata, []byte("wrong"))
	default:
		if next == "revoked proof" {
			server.RemoveUser("alice")
		}
		_, err = cfg.VerifiedPublicKeyCallback(metadata, key, query, "")
	}
	return err
}

func assertSSHJailDescriptors(t *testing.T, root string, want int) {
	t.Helper()
	if got := countRetainedJailDescriptors(t, root); got != want {
		t.Fatalf("open jail descriptors = %d; want %d", got, want)
	}
}
