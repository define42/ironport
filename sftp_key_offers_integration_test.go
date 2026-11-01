//go:build linux && integration

package ironport

import (
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHKeyOffersAllowAuthorizedKeyAfterUnrelatedKeys(t *testing.T) {
	for _, wrong := range []int{3, 5} {
		t.Run(fmt.Sprintf("wrong_keys_%d", wrong), func(t *testing.T) {
			offers, key, signed := newSSHKeyOffers(t, wrong)
			server, addr := startSSHKeyQueryServer(t, t.TempDir(), key)
			requireSSHKeyOffersLogin(t, server, addr, "alice", offers)
			if got := signed.Load(); got != 1 {
				t.Fatalf("authorized-key signatures = %d; want 1", got)
			}
		})
	}
}

func TestSSHWrongKeyOffersDoNotBlockOtherAccount(t *testing.T) {
	offers, key, signed := newSSHKeyOffers(t, 5)
	server, addr, stop := startTestServer(t, map[string]UserInfo{
		"alice": {Root: t.TempDir(), AuthorizedKeys: []ssh.PublicKey{key}, CanRead: true},
		"bob":   {Root: t.TempDir(), AuthorizedKeys: []ssh.PublicKey{key}, CanRead: true},
	})
	t.Cleanup(func() {
		stop()
		waitResourceConnections(t, server)
	})
	// Every offered key is unrelated. Removing failure backoff from unsigned
	// probes must not make any of these keys eligible for authentication.
	client, err := dialSSHKeyOffers(t, addr, "alice", offers[:len(offers)-1])
	if client != nil {
		_ = client.Close()
	}
	if err == nil {
		t.Fatal("login succeeded with only unauthorized keys")
	}
	// Both connections originate from loopback. The unrelated offers must not
	// establish shared-IP failure backoff that rejects Bob's first valid key.
	requireSSHKeyOffersLogin(t, server, addr, "bob", offers[len(offers)-1:])
	if got := signed.Load(); got != 1 {
		t.Fatalf("authorized-key signatures = %d; want Bob's one proof", got)
	}
}

func TestSSHSuccessfulKeyOffersDoNotAccumulateIPBackoff(t *testing.T) {
	offers, key, signed := newSSHKeyOffers(t, 1)
	server, addr := startSSHKeyQueryServer(t, t.TempDir(), key)
	// A successful login clears username failure state, but deliberately does
	// not clear shared-IP failures. Charging even one unrelated key per login
	// therefore blocks the third proof unless unsigned probes are excluded.
	for range 4 {
		requireSSHKeyOffersLogin(t, server, addr, "alice", offers)
	}
	if got := signed.Load(); got != 4 {
		t.Fatalf("authorized-key signatures = %d; want 4", got)
	}
}

func newSSHKeyOffers(t *testing.T, wrong int) ([]ssh.Signer, ssh.PublicKey, *atomic.Int32) {
	t.Helper()
	offers := make([]ssh.Signer, 0, wrong+1)
	for range wrong {
		signer, _ := testClientKey(t)
		offers = append(offers, signer)
	}
	signer, key := testClientKey(t)
	signed := new(atomic.Int32)
	offers = append(offers, jailQueryProofSigner{Signer: signer, beforeSign: func() error {
		signed.Add(1)
		return nil
	}})
	return offers, key, signed
}

func requireSSHKeyOffersLogin(t *testing.T, server *Server, addr, username string, offers []ssh.Signer) {
	t.Helper()
	client, err := dialSSHKeyOffers(t, addr, username, offers)
	if err != nil {
		t.Fatalf("login for %q after %d offered keys: %v", username, len(offers), err)
	}
	sftpClient := resourceSFTP(t, client)
	info, err := sftpClient.Stat(".")
	if err != nil || !info.IsDir() {
		t.Fatalf("SFTP root after multi-key login: info=%v err=%v", info, err)
	}
	_ = sftpClient.Close()
	_ = client.Close()
	waitResourceConnections(t, server)
}

func dialSSHKeyOffers(t *testing.T, addr, username string, offers []ssh.Signer) (*ssh.Client, error) {
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
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(offers...)},
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
