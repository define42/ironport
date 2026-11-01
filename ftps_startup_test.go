//go:build linux

package ironport

import (
	"crypto/tls"
	"strings"
	"testing"
)

type ftpTLSStartupCase struct {
	name       string
	requireTLS bool
	tlsConfig  *tls.Config
	wantErr    string
}

func ftpTLSStartupCases() []ftpTLSStartupCase {
	return []ftpTLSStartupCase{
		{name: "plain FTP"},
		{name: "required TLS missing", requireTLS: true, wantErr: "FtpRequireTLS requires FtpTLSConfig"},
		{name: "optional TLS configured", tlsConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
		{name: "required TLS configured", requireTLS: true, tlsConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
		{
			name: "custom WrapSession",
			tlsConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				WrapSession: func(tls.ConnectionState, *tls.SessionState) ([]byte, error) {
					return nil, nil
				},
			},
			wantErr: "custom TLS session wrapping",
		},
		{
			name:       "custom UnwrapSession",
			requireTLS: true,
			tlsConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				UnwrapSession: func([]byte, tls.ConnectionState) (*tls.SessionState, error) {
					return nil, nil
				},
			},
			wantErr: "custom TLS session wrapping",
		},
	}
}

func TestFTPTLSStartupValidation(t *testing.T) {
	signer := testSigner(t)
	for _, addr := range []struct {
		name    string
		value   string
		enabled bool
	}{
		{name: "enabled", value: "127.0.0.1:0", enabled: true},
		{name: "disabled empty"},
		{name: "disabled whitespace", value: " \t\n"},
	} {
		t.Run(addr.name, func(t *testing.T) {
			for _, tc := range ftpTLSStartupCases() {
				t.Run(tc.name, func(t *testing.T) {
					cfg := DefaultConfig()
					cfg.FtpAddr = addr.value
					cfg.FtpRequireTLS = tc.requireTLS
					cfg.FtpTLSConfig = tc.tlsConfig
					cfg.SftpSigner = signer
					want := tc.wantErr
					if !addr.enabled {
						want = ""
					}
					assertFTPTLSStartupError(t, NewServer(cfg).prepareForListen(), want)
				})
			}
		})
	}
}

func TestFTPTLSStartupRejectsBeforeOpeningListeners(t *testing.T) {
	signer := testSigner(t)
	for _, tc := range ftpTLSStartupCases() {
		if tc.wantErr == "" {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			// Invalid addresses make this test fail promptly if startup reaches
			// listener creation before rejecting the FTP TLS configuration.
			cfg.SftpAddr = "invalid SFTP listen address"
			cfg.FtpAddr = "invalid FTP listen address"
			cfg.SftpSigner = signer
			cfg.FtpRequireTLS = tc.requireTLS
			cfg.FtpTLSConfig = tc.tlsConfig
			srv := NewServer(cfg)
			assertFTPTLSStartupError(t, srv.ListenAndServe(), tc.wantErr)
			if srv.ListeningAddr() != nil || srv.FTPListeningAddr() != nil {
				t.Fatal("failed startup published a listener")
			}
		})
	}
}

func assertFTPTLSStartupError(t *testing.T, err error, want string) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Fatalf("startup check: %v", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("startup error = %v; want %q", err, want)
	}
}
