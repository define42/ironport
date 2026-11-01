//go:build linux && integration

package ironport

import (
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHKeyAuthConsumesOneAttempt(t *testing.T) {
	for _, test := range []struct {
		name   string
		limits AuthLimitConfig
	}{
		{name: "global", limits: AuthLimitConfig{GlobalBurst: 1, GlobalInterval: time.Hour}},
		{name: "IP", limits: AuthLimitConfig{IPBurst: 1, IPInterval: time.Hour}},
		{name: "username", limits: AuthLimitConfig{UserBurst: 1, UserInterval: time.Hour}},
	} {
		t.Run(test.name, func(t *testing.T) {
			signer, key := testClientKey(t)
			config := newTestConfig("", "", "", map[string]UserInfo{
				"alice": {Root: t.TempDir(), AuthorizedKeys: []ssh.PublicKey{key}},
			}, testSigner(t), defaultCompletedUploadsSize)
			config.AuthLimits = test.limits
			server, addr, stop := startTestServerWithConfig(t, config)
			t.Cleanup(stop)
			clientConfig := &ssh.ClientConfig{
				User: "alice", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // loopback test server with an ephemeral host key
				Timeout:         time.Second,
			}
			client, err := ssh.Dial("tcp", addr, clientConfig)
			if err != nil {
				t.Fatalf("one-token public-key authentication failed: %v", err)
			}
			t.Cleanup(func() {
				_ = client.Close()
				server.connWG.Wait()
			})
			if second, err := ssh.Dial("tcp", addr, clientConfig); err == nil {
				_ = second.Close()
				t.Fatal("a second key login bypassed the exhausted authentication bucket")
			}
		})
	}
}
