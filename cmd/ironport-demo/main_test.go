package main

import (
	"slices"
	"testing"

	"github.com/define42/ironport"
)

func TestSplitCSV(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "empty", in: "", want: nil},
		{name: "whitespace", in: "  \t ", want: nil},
		{name: "single", in: "curve25519-sha256", want: []string{"curve25519-sha256"}},
		{name: "trims and skips empty", in: " aes128-ctr, ,aes256-ctr ,, ", want: []string{"aes128-ctr", "aes256-ctr"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := splitCSV(tc.in); !slices.Equal(got, tc.want) {
				t.Fatalf("splitCSV(%q) = %v; want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestNewHTTPIngestServer_HardenedTimeoutsAndHeaderLimit(t *testing.T) {
	server := newHTTPIngestServer(ironport.NewServer(nil), "127.0.0.1:8080")

	if server.Addr != "127.0.0.1:8080" {
		t.Fatalf("Addr = %q; want 127.0.0.1:8080", server.Addr)
	}
	if server.Handler == nil {
		t.Fatal("Handler is nil")
	}
	if server.ReadHeaderTimeout != demoHTTPReadHeaderTimeout {
		t.Fatalf("ReadHeaderTimeout = %v; want %v", server.ReadHeaderTimeout, demoHTTPReadHeaderTimeout)
	}
	if server.ReadTimeout != demoHTTPReadTimeout {
		t.Fatalf("ReadTimeout = %v; want %v", server.ReadTimeout, demoHTTPReadTimeout)
	}
	if server.WriteTimeout != demoHTTPWriteTimeout {
		t.Fatalf("WriteTimeout = %v; want %v", server.WriteTimeout, demoHTTPWriteTimeout)
	}
	if server.IdleTimeout != demoHTTPIdleTimeout {
		t.Fatalf("IdleTimeout = %v; want %v", server.IdleTimeout, demoHTTPIdleTimeout)
	}
	if server.MaxHeaderBytes != demoHTTPMaxHeaderBytes {
		t.Fatalf("MaxHeaderBytes = %d; want %d", server.MaxHeaderBytes, demoHTTPMaxHeaderBytes)
	}
}
