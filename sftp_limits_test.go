//go:build linux

package ironport

import (
	"bufio"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

func TestSSHHandshakeDeadlineIsAbsolute(t *testing.T) {
	srv := NewServer(&Config{SftpSigner: testSigner(t)})
	cfg := srv.sshServerConfig()
	synctest.Test(t, func(t *testing.T) {
		server, client := net.Pipe()
		defer func() { _ = client.Close() }()
		done := make(chan struct{})
		go func() {
			defer close(done)
			srv.handleConn(server, cfg, nil, nil, nil, time.Minute, false)
		}()
		if _, err := bufio.NewReader(client).ReadString('\n'); err != nil {
			t.Fatalf("SSH server banner: %v", err)
		}
		time.Sleep(sshHandshakeTimeout / 2)
		// Refresh the read deadline without finishing the client banner.
		if _, err := io.WriteString(client, "SSH-2.0-trickle"); err != nil {
			t.Fatalf("partial client banner: %v", err)
		}
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("handshake closed before its deadline")
		default:
		}
		time.Sleep(sshHandshakeTimeout/2 + time.Second)
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("partial banner extended the absolute handshake deadline")
		}
	})
}
