//go:build linux && integration

package ironport

import (
	"testing"
	"time"
)

func TestSFTPStartsWithUnusedInvalidFTPTLS(t *testing.T) {
	signer := testSigner(t)
	root := t.TempDir()
	for _, addr := range []struct{ name, value string }{
		{name: "empty"},
		{name: "whitespace", value: " \t\n"},
	} {
		t.Run(addr.name, func(t *testing.T) {
			for _, tc := range ftpTLSStartupCases() {
				if tc.wantErr == "" {
					continue
				}
				t.Run(tc.name, func(t *testing.T) {
					cfg := newTestConfig("127.0.0.1:0", addr.value, "", map[string]UserInfo{
						"user": {Password: "pass", Root: root, CanRead: true},
					}, signer, defaultCompletedUploadsSize)
					cfg.FtpRequireTLS = tc.requireTLS
					cfg.FtpTLSConfig = tc.tlsConfig
					assertSFTPOnlyStartup(t, cfg)
				})
			}
		})
	}
}

func assertSFTPOnlyStartup(t *testing.T, cfg *Config) {
	t.Helper()
	srv := NewServer(cfg)
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	t.Cleanup(func() { _ = srv.Close() })
	listenAddr := waitForSFTPListener(t, srv, errCh)
	if srv.FTPListeningAddr() != nil {
		t.Fatal("disabled FTP published a listener")
	}
	assertSFTPStartupUsable(t, listenAddr)
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ListenAndServe: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not return after Close")
	}
}

func assertSFTPStartupUsable(t *testing.T, addr string) {
	t.Helper()
	client := dialSFTP(t, addr, "user", "pass")
	defer func() { _ = client.Close() }()
	info, err := client.Stat(".")
	if err != nil {
		t.Fatalf("SFTP Stat after startup: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("SFTP root is not a directory")
	}
}
