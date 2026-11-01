//go:build linux && integration

package ironport

import (
	"os"
	"testing"
	"time"
)

func TestFTPSCommandRejectionsPreserveProtectedUpload(t *testing.T) {
	rootPath := t.TempDir()
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	cfg, pool := newTestFTPSConfig(t, map[string]UserInfo{
		"alice": {Password: "pw", Root: rootPath, CanWrite: true},
	}, true)
	cfg.FtpDataAcceptTimeout = 5 * time.Second
	server, addr, stop := startTestFTPServerWithConfig(t, cfg)
	t.Cleanup(stop)
	client := dialFTPS(t, addr, pool)
	if err := client.conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}

	// Rejected plaintext commands must leave the connection ready to upgrade.
	client.command(503, "PBSZ 0")
	client.command(503, "PROT P")
	client.command(501, "AUTH")
	client.command(504, "AUTH GSSAPI")
	client.authTLS()
	client.command(503, "AUTH TLS")
	// The rejected pre-TLS PBSZ must not authorize PROT after the upgrade.
	client.command(503, "PROT P")
	client.login("alice", "pw")
	client.command(200, "PBSZ 0")
	client.command(200, "PROT P")

	// Neither a forbidden downgrade nor an invalid level may replace PROT P.
	client.command(534, "PROT C")
	client.command(536, "PROT S")
	client.command(504, "PROT invalid")
	const payload = "protected data after rejected FTPS commands"
	storeFTPSCommandTestUpload(t, client, payload)
	got, err := root.ReadFile("protected.bin")
	if err != nil || string(got) != payload {
		t.Fatalf("uploaded contents = %q, error = %v; want %q", got, err, payload)
	}
	if event := receiveUpload(t, server); event.FilePath != "/protected.bin" {
		t.Fatalf("completed upload = %+v; want /protected.bin", event)
	}
	client.command(200, "NOOP")
}

func storeFTPSCommandTestUpload(t *testing.T, client *ftpsTestClient, payload string) {
	t.Helper()
	raw := client.passiveDial()
	defer func() { _ = raw.Close() }()
	if err := raw.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	client.command(150, "STOR protected.bin")
	data := client.upgradeDataConn(raw)
	if !data.ConnectionState().DidResume {
		t.Fatal("data connection did not resume the control session")
	}
	if _, err := data.Write([]byte(payload)); err != nil {
		t.Fatalf("write protected data: %v", err)
	}
	if err := data.CloseWrite(); err != nil {
		t.Fatalf("close protected data: %v", err)
	}
	_ = data.Close()
	client.read(226)
}
