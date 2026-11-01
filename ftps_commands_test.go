//go:build linux

package ironport

import (
	"bytes"
	"crypto/tls"
	"testing"
)

func TestFTPSPBSZCommandState(t *testing.T) {
	tests := []struct {
		name     string
		tls      bool
		pbsz     bool
		wantPBSZ bool
		want     string
	}{
		{name: "before TLS", want: "503 PBSZ only valid after AUTH TLS\r\n"},
		{name: "after TLS", tls: true, wantPBSZ: true, want: "200 PBSZ=0\r\n"},
		{name: "repeated", tls: true, pbsz: true, wantPBSZ: true, want: "200 PBSZ=0\r\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reply bytes.Buffer
			f := newFTPSCommandSession(&reply, tt.tls)
			f.pbszSet = tt.pbsz
			beforeTLS, beforeProt := f.tlsConn, f.dataProt
			f.cmdPbsz()
			if got := reply.String(); got != tt.want {
				t.Fatalf("PBSZ reply = %q; want %q", got, tt.want)
			}
			if f.pbszSet != tt.wantPBSZ {
				t.Errorf("PBSZ negotiated = %t; want %t", f.pbszSet, tt.wantPBSZ)
			}
			if f.tlsConn != beforeTLS || f.dataProt != beforeProt {
				t.Fatal("PBSZ changed control or data protection")
			}
		})
	}
}

//nolint:funlen // keep the protection transition and rejection matrix with its shared state assertions
func TestFTPSPROTCommandState(t *testing.T) {
	tests := []struct {
		name       string
		arg        string
		tls        bool
		pbsz       bool
		requireTLS bool
		before     byte
		after      byte
		want       string
	}{
		{
			name: "before TLS", arg: "P", before: 'C', after: 'C',
			want: "503 PROT only valid after AUTH TLS\r\n",
		},
		{
			name: "before PBSZ", arg: "P", tls: true, before: 'C', after: 'C',
			want: "503 send PBSZ first\r\n",
		},
		{
			name: "clear before PBSZ", arg: "C", tls: true, before: 'C', after: 'C',
			want: "503 send PBSZ first\r\n",
		},
		{
			name: "forbidden clear", arg: "C", tls: true, pbsz: true, requireTLS: true, before: 'P', after: 'P',
			want: "534 PROT C refused; data protection is required\r\n",
		},
		{
			name: "safe unsupported", arg: "S", tls: true, pbsz: true, before: 'P', after: 'P',
			want: "536 protection level not supported\r\n",
		},
		{
			name: "confidential unsupported", arg: "E", tls: true, pbsz: true, before: 'P', after: 'P',
			want: "536 protection level not supported\r\n",
		},
		{
			name: "unknown", arg: "unknown", tls: true, pbsz: true, before: 'P', after: 'P',
			want: "504 unknown protection level\r\n",
		},
		{
			name: "empty", tls: true, pbsz: true, before: 'P', after: 'P',
			want: "504 unknown protection level\r\n",
		},
		{
			name: "clear allowed", arg: "C", tls: true, pbsz: true, before: 'P', after: 'C',
			want: "200 protection level set to Clear\r\n",
		},
		{
			name: "private required", arg: "P", tls: true, pbsz: true, requireTLS: true, before: 'C', after: 'P',
			want: "200 protection level set to Private\r\n",
		},
		{
			name: "normalized clear", arg: "  c  ", tls: true, pbsz: true, before: 'P', after: 'C',
			want: "200 protection level set to Clear\r\n",
		},
		{
			name: "normalized private", arg: "  p  ", tls: true, pbsz: true, before: 'C', after: 'P',
			want: "200 protection level set to Private\r\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reply bytes.Buffer
			f := newFTPSCommandSession(&reply, tt.tls)
			f.server.ftpRequireTLS = tt.requireTLS
			f.pbszSet, f.dataProt = tt.pbsz, tt.before
			beforeTLS := f.tlsConn
			f.cmdProt(tt.arg)
			if got := reply.String(); got != tt.want {
				t.Fatalf("PROT %q reply = %q; want %q", tt.arg, got, tt.want)
			}
			if f.dataProt != tt.after {
				t.Errorf("data protection = %q; want %q", f.dataProt, tt.after)
			}
			if f.tlsConn != beforeTLS || f.pbszSet != tt.pbsz {
				t.Fatal("PROT changed control TLS or PBSZ negotiation")
			}
		})
	}
}

func TestFTPSAUTHRejectionPreservesState(t *testing.T) {
	tests := []struct {
		name       string
		arg        string
		configured bool
		tls        bool
		want       string
	}{
		{name: "TLS unavailable", arg: "TLS", want: "502 AUTH not supported\r\n"},
		{name: "already TLS", arg: "TLS", configured: true, tls: true, want: "503 already TLS\r\n"},
		{name: "missing mechanism", configured: true, want: "501 AUTH requires a mechanism\r\n"},
		{name: "blank mechanism", arg: "  ", configured: true, want: "501 AUTH requires a mechanism\r\n"},
		{name: "unsupported mechanism", arg: "GSSAPI", configured: true, want: "504 unsupported AUTH mechanism\r\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reply bytes.Buffer
			f := newFTPSCommandSession(&reply, tt.tls)
			if tt.configured {
				f.server.ftpTLSConfig = &tls.Config{}
			}
			f.username, f.epsvAll = "pending-user", true
			beforeTLS, beforeProt, beforePBSZ := f.tlsConn, f.dataProt, f.pbszSet
			// Exercise the command itself so a rejected upgrade must return
			// before resetting state or starting a TLS handshake.
			f.cmdAuth(tt.arg)
			if got := reply.String(); got != tt.want {
				t.Fatalf("AUTH %q reply = %q; want %q", tt.arg, got, tt.want)
			}
			if f.tlsConn != beforeTLS || f.dataProt != beforeProt || f.pbszSet != beforePBSZ {
				t.Fatal("rejected AUTH changed control or data protection")
			}
			if f.username != "pending-user" || !f.epsvAll || f.controlTLSConfig != nil || f.dataTLSConfig != nil {
				t.Fatal("rejected AUTH reset the session or prepared a TLS upgrade")
			}
		})
	}
}

func TestFTPSAUTHSupportedMechanisms(t *testing.T) {
	for _, mechanism := range []string{"TLS", "TLS-C", "SSL", "  tls  ", "tls-c", "ssl"} {
		t.Run(mechanism, func(t *testing.T) {
			var reply bytes.Buffer
			f := newFTPSCommandSession(&reply, false)
			f.server.ftpTLSConfig = &tls.Config{}
			if !f.validateAuthRequest(mechanism) {
				t.Fatalf("supported AUTH mechanism %q rejected: %q", mechanism, reply.String())
			}
			if reply.Len() != 0 {
				t.Fatalf("AUTH validation sent a reply before upgrade setup: %q", reply.String())
			}
		})
	}
}

func newFTPSCommandSession(reply *bytes.Buffer, secure bool) *ftpSession {
	f := newReplyCaptureSession(reply)
	f.server = &Server{}
	f.dataProt = 'C'
	if secure {
		// Only the negotiated-state marker is needed by these commands;
		// real TLS negotiation is exercised by the integration tests.
		f.tlsConn = tls.Server(&stubConn{}, &tls.Config{})
		f.pbszSet, f.dataProt = true, 'P'
	}
	return f
}
