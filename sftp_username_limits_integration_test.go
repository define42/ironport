//go:build linux && integration

package ironport

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHKeyOffersApplyUsernameLimitsUniformly(t *testing.T) {
	for _, username := range []string{"alice", "absent"} {
		t.Run(username, func(t *testing.T) {
			checkSSHUsernameLimit(t, username)
		})
	}
}

func checkSSHUsernameLimit(t *testing.T, username string) {
	t.Helper()
	wrong := newSSHUsernameLimitSigner(t)
	authorized := newSSHUsernameLimitSigner(t)
	var signatures atomic.Int32
	offered := jailQueryProofSigner{Signer: wrong, beforeSign: func() error {
		signatures.Add(1)
		return nil
	}}
	config := newTestConfig("", "", "", map[string]UserInfo{
		"alice": {Root: t.TempDir(), Password: "correct", AuthorizedKeys: []ssh.PublicKey{authorized.PublicKey()}, CanWrite: true},
	}, testSigner(t), defaultCompletedUploadsSize)
	// Keep the default 20 username and 30 source tokens, but prevent refill
	// during a slow CI run. No elapsed-time or scheduling assumption is needed.
	config.AuthLimits.UserInterval = time.Hour
	config.AuthLimits.IPInterval = time.Hour
	server, addr, stop := startTestServerWithConfig(t, config)
	t.Cleanup(func() {
		stop()
		waitResourceConnections(t, server)
	})
	httpServer := httptest.NewServer(server.HttpIngest())
	defer httpServer.Close()
	// Separate handshakes prevent the SSH query cache from merging offers.
	// Unsigned ineligible offers consume tokens without starting failure backoff.
	for range 24 {
		client, err := dialSSHKeyOffers(t, addr, username, []ssh.Signer{offered})
		if client != nil {
			_ = client.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "unable to authenticate") {
			t.Fatalf("unauthorized key offer error = %v; want authentication rejection", err)
		}
	}
	requireSSHUsernameHTTPThrottle(t, httpServer, username)
	if got := signatures.Load(); got != 0 {
		t.Fatalf("ineligible key signatures = %d; want zero", got)
	}
}

func requireSSHUsernameHTTPThrottle(t *testing.T, server *httptest.Server, username string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.SetBasicAuth(username, "wrong")
	client := server.Client()
	client.Timeout = 5 * time.Second
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("HTTP status after unsigned offers for %q = %d; want 429 for configured and unknown usernames", username, response.StatusCode)
	}
	if response.Header.Get("Retry-After") == "" {
		t.Fatal("throttled HTTP response omitted Retry-After")
	}
}

func newSSHUsernameLimitSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}
