//go:build linux && integration

package ironport

import "testing"

func TestFTPSAuthTLSDiscardsPlaintextEPSVAll(t *testing.T) {
	users := map[string]UserInfo{
		"user": {Password: "password", Root: t.TempDir(), CanRead: true, CanWrite: true},
	}
	cfg, pool := newTestFTPSConfig(t, users, false)
	cfg.FtpAllowActiveMode = true
	_, addr, stop := startTestFTPServerWithConfig(t, cfg)
	t.Cleanup(stop)
	client := dialFTPS(t, addr, pool)
	client.login("user", "password")
	client.command(200, "EPSV ALL")
	client.command(502, "PORT 127,0,0,1,12,34")

	client.authTLS()
	client.command(530, "PORT 127,0,0,1,12,34")
	client.command(503, "PROT P")
	client.login("user", "password")
	client.command(200, "PORT 127,0,0,1,12,34")
	client.command(200, "PBSZ 0")
	client.command(200, "PROT P")
}
