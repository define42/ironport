//go:build linux && integration

package ironport

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestSFTPRetainsAuthenticatedJailAcrossChannels(t *testing.T) {
	signer, key := testClientKey(t)
	cases := []struct {
		name   string
		auth   ssh.AuthMethod
		revoke bool
	}{
		{name: "password-disconnect", auth: ssh.Password("pw")},
		{name: "public-key-revoke", auth: ssh.PublicKeys(signer), revoke: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base, root := newRetainedJailFixture(t)
			srv, addr, stop := startTestServer(t, map[string]UserInfo{
				"alice": {Password: "pw", Root: root, AuthorizedKeys: []ssh.PublicKey{key}, CanRead: true, CanWrite: true},
			})
			t.Cleanup(stop)
			client := retainedJailSSHClient(t, addr, tc.auth)
			// No SFTP channel exists yet. Authentication itself must retain the jail.
			assertSSHJailDescriptors(t, root, 1)
			if err := replaceRetainedJailPath(base); err != nil {
				t.Fatal(err)
			}
			opened := filepath.Join(filepath.Dir(root), "opened")
			first := resourceSFTP(t, client)
			assertSFTPRetainedJail(t, first, base, "first")
			_ = first.Close()
			second := resourceSFTP(t, client)
			assertSFTPRetainedJail(t, second, base, "second")
			assertSSHJailDescriptors(t, opened, 1)
			assertSSHJailDescriptors(t, root, 0)
			if tc.revoke {
				srv.RemoveUser("alice")
			} else {
				_ = client.Close()
			}
			waitResourceConnections(t, srv)
			assertSSHJailDescriptors(t, opened, 0)
		})
	}
}

func retainedJailSSHClient(t *testing.T, addr string, auth ssh.AuthMethod) *ssh.Client {
	t.Helper()
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: "alice", Auth: []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // loopback test server
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func assertSFTPRetainedJail(t *testing.T, client *sftp.Client, base *os.Root, name string) {
	t.Helper()
	marker, err := client.Open("/marker")
	if err != nil {
		t.Fatal(err)
	}
	data, readErr := io.ReadAll(marker)
	_ = marker.Close()
	if readErr != nil || string(data) != "original jail" {
		t.Fatalf("marker = %q, %v; want original jail", data, readErr)
	}
	file, err := client.Create("/" + name)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.Write([]byte("retained upload"))
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatalf("upload write=%v close=%v", writeErr, closeErr)
	}
	if data, err := base.ReadFile("opened/" + name); err != nil || string(data) != "retained upload" {
		t.Fatalf("retained upload = %q, %v", data, err)
	}
	if _, err := base.Stat("root/" + name); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement jail received upload: %v", err)
	}
}

type abortedJailProofSigner struct {
	ssh.Signer

	beforeSign func()
}

func (s abortedJailProofSigner) Sign(_ io.Reader, _ []byte) (*ssh.Signature, error) {
	s.beforeSign()
	return nil, errors.New("abort after accepted public-key query")
}

func TestSSHAbortedPublicKeyHandshakeNeverOpensJail(t *testing.T) {
	signer, key := testClientKey(t)
	root := t.TempDir()
	srv, addr, stop := startTestServer(t, map[string]UserInfo{
		"alice": {Root: root, AuthorizedKeys: []ssh.PublicKey{key}},
	})
	t.Cleanup(stop)
	queryDescriptors := -1
	aborted := abortedJailProofSigner{Signer: signer, beforeSign: func() {
		queryDescriptors = countRetainedJailDescriptors(t, root)
	}}
	client, err := dialSSHKeyProof(t, addr, aborted)
	if client != nil {
		_ = client.Close()
	}
	if err == nil || queryDescriptors != 0 {
		t.Fatalf("aborted handshake error=%v; query jail descriptors=%d, want 0", err, queryDescriptors)
	}
	waitResourceConnections(t, srv)
	assertSSHJailDescriptors(t, root, 0)
}

func TestSSHRejectedCommitClosesAuthenticatedJail(t *testing.T) {
	root := t.TempDir()
	h := newSSHRevisionRejectionHarness(t, root)
	// Password authentication opened the jail, but revocation invalidated
	// its revision before the server could commit the successful handshake.
	assertSSHJailDescriptors(t, root, 1)
	h.finish()
	assertSSHJailDescriptors(t, root, 0)
}
