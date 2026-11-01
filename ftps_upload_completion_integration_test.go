//go:build linux && integration

package ironport

import (
	"bytes"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestFTPSUploadRequiresCloseNotify(t *testing.T) {
	for _, version := range []struct {
		name  string
		value uint16
	}{
		{name: "TLS 1.2", value: tls.VersionTLS12},
		{name: "TLS 1.3", value: tls.VersionTLS13},
	} {
		t.Run(version.name, func(t *testing.T) {
			fixture := newFTPSUploadSafetyServer(t, version.value)
			for _, command := range []string{"STOR", "APPE"} {
				for _, closure := range []string{"TCP Close", "TCP CloseWrite", "TLS Close", "TLS CloseWrite"} {
					t.Run(command+"/"+closure, func(t *testing.T) {
						fixture.checkUploadClosure(t, command, closure)
					})
				}
			}
		})
	}
}

func (f *ftpsUploadSafetyServer) checkUploadClosure(t *testing.T, command, closure string) {
	t.Helper()
	client := *f.client
	client.t = t
	_ = client.conn.SetDeadline(time.Now().Add(5 * time.Second))
	const filename = "closure.bin"
	original, payload := []byte("existing content"), []byte("uploaded prefix")
	if err := f.root.WriteFile(filename, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if closure == "TCP Close" {
		// Even a matching size hint cannot authenticate TLS stream closure.
		client.command(200, "ALLO %d", len(payload))
	}
	raw := client.passiveDial()
	defer func() { _ = raw.Close() }()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	client.command(150, "%s %s", command, filename)
	tc := client.upgradeDataConn(raw)
	if _, err := tc.Write(payload); err != nil {
		t.Fatal(err)
	}
	closeFTPSUpload(t, raw, tc, closure)
	clean := closure == "TLS Close" || closure == "TLS CloseWrite"
	if clean {
		client.read(226)
	} else {
		client.read(426)
	}
	want := payload
	if command == "APPE" {
		want = append(bytes.Clone(original), payload...)
	}
	if got, err := f.root.ReadFile(filename); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("upload contents = %q, err = %v; want %q", got, err, want)
	}
	select {
	case event := <-f.server.CompletedUploads():
		if !clean || event.FilePath != "/"+filename {
			t.Fatalf("unexpected completed upload after %s: %+v", closure, event)
		}
	default:
		if clean {
			t.Fatal("clean upload did not announce completion")
		}
	}
	client.command(200, "NOOP")
}

func closeFTPSUpload(t *testing.T, raw net.Conn, tc *tls.Conn, closure string) {
	t.Helper()
	var err error
	switch closure {
	case "TCP Close":
		err = raw.Close()
	case "TCP CloseWrite":
		tcp, ok := raw.(*net.TCPConn)
		if !ok {
			t.Fatalf("data transport type = %T; want *net.TCPConn", raw)
		}
		err = tcp.CloseWrite()
	case "TLS Close":
		err = tc.Close()
	case "TLS CloseWrite":
		err = tc.CloseWrite()
	default:
		t.Fatalf("unknown closure %q", closure)
	}
	if err != nil {
		t.Fatalf("%s: %v", closure, err)
	}
}
