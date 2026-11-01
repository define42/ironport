//go:build linux && integration

package ironport

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Sign runs only after the server accepts the unsigned key query. The hook
// changes server-side state before the signed authentication request is sent.
type jailQueryProofSigner struct {
	ssh.Signer

	beforeSign func() error
}

func (s jailQueryProofSigner) Sign(random io.Reader, data []byte) (*ssh.Signature, error) {
	if err := s.beforeSign(); err != nil {
		return nil, err
	}
	return s.Signer.Sign(random, data)
}

func TestSSHKeyQueryAllowsRootProvisioningBeforeProof(t *testing.T) {
	signer, key := testClientKey(t)
	root := filepath.Join(t.TempDir(), "provision-before-proof")
	srv, addr := startSSHKeyQueryServer(t, root, key)
	queryDescriptors := -1
	proof := jailQueryProofSigner{Signer: signer, beforeSign: func() error {
		queryDescriptors = countRetainedJailDescriptors(t, root)
		return os.Mkdir(root, 0o700)
	}}
	client, err := dialSSHKeyProof(t, addr, proof)
	if err != nil || queryDescriptors != 0 {
		t.Fatalf("login error=%v; unsigned query descriptors=%d, want 0", err, queryDescriptors)
	}
	// The same handshake must now own the newly provisioned root, and an SFTP
	// channel must be usable without reconnecting or updating the user.
	sftpClient := resourceSFTP(t, client)
	info, err := sftpClient.Stat(".")
	if err != nil || !info.IsDir() {
		t.Fatalf("SFTP root after proof: info=%v err=%v", info, err)
	}
	assertSSHJailDescriptors(t, root, 1)
	_ = client.Close()
	waitResourceConnections(t, srv)
	assertSSHJailDescriptors(t, root, 0)
}

func TestSSHKeyProofHonorsRevocationAfterQuery(t *testing.T) {
	signer, key := testClientKey(t)
	for _, tc := range []struct {
		name   string
		revoke func(*Server)
	}{
		{name: "key", revoke: func(s *Server) { s.RemoveUserKey("alice", key) }},
		{name: "user", revoke: func(s *Server) { s.RemoveUser("alice") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			srv, addr := startSSHKeyQueryServer(t, root, key)
			queryDescriptors := -1
			proof := jailQueryProofSigner{Signer: signer, beforeSign: func() error {
				queryDescriptors = countRetainedJailDescriptors(t, root)
				tc.revoke(srv)
				return nil
			}}
			client, err := dialSSHKeyProof(t, addr, proof)
			if client != nil {
				_ = client.Close()
			}
			if err == nil || queryDescriptors != 0 {
				t.Fatalf("revoked proof error=%v; unsigned query descriptors=%d, want 0", err, queryDescriptors)
			}
			waitResourceConnections(t, srv)
			assertSSHJailDescriptors(t, root, 0)
		})
	}
}

func startSSHKeyQueryServer(t *testing.T, root string, key ssh.PublicKey) (*Server, string) {
	t.Helper()
	srv, addr, stop := startTestServer(t, map[string]UserInfo{
		"alice": {Root: root, AuthorizedKeys: []ssh.PublicKey{key}, CanRead: true},
	})
	t.Cleanup(func() {
		stop()
		waitResourceConnections(t, srv)
	})
	return srv, addr
}

func dialSSHKeyProof(t *testing.T, addr string, signer ssh.Signer) (*ssh.Client, error) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = raw.Close() })
	if err := raw.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	conn, channels, requests, err := ssh.NewClientConn(raw, addr, &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // loopback test server with an ephemeral key
	})
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	client := ssh.NewClient(conn, channels, requests)
	t.Cleanup(func() { _ = client.Close() })
	return client, nil
}
