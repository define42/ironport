package ironport

import (
	"testing"
	"time"
)

//nolint:gocognit,cyclop,funlen // verifies every default field; splitting would just rename the function
func TestDefaultConfig(t *testing.T) {
	const wantCompletedUploadSize = 65_536

	config := DefaultConfig()
	if config.SftpAddr != ":2022" {
		t.Errorf("SftpAddr = %q; want :2022", config.SftpAddr)
	}
	if config.FtpAddr != "" {
		t.Errorf("FtpAddr = %q; want empty", config.FtpAddr)
	}
	if config.FtpPassivePortRange != "5000-5010" {
		t.Errorf("FtpPassivePortRange = %q; want 5000-5010", config.FtpPassivePortRange)
	}
	if config.FtpDataAcceptTimeout != 0 {
		t.Errorf("FtpDataAcceptTimeout = %v; want 0", config.FtpDataAcceptTimeout)
	}
	if config.FtpAllowActiveMode {
		t.Error("FtpAllowActiveMode = true; want false")
	}
	if config.CompletedUploadSize != wantCompletedUploadSize {
		t.Errorf("CompletedUploadSize = %d; want %d", config.CompletedUploadSize, wantCompletedUploadSize)
	}
	if config.AuthEventSize != defaultAuthEventsSize {
		t.Errorf("AuthEventSize = %d; want %d", config.AuthEventSize, defaultAuthEventsSize)
	}
	if config.Users != nil {
		t.Error("Users is non-nil; want nil")
	}
	if config.SftpSigner != nil {
		t.Error("SftpSigner is non-nil; want nil")
	}
	if config.SSHKeyExchanges != nil {
		t.Error("SSHKeyExchanges is non-nil; want nil")
	}
	if config.SSHCiphers != nil {
		t.Error("SSHCiphers is non-nil; want nil")
	}
	if config.SSHMACs != nil {
		t.Error("SSHMACs is non-nil; want nil")
	}
	if config.SSHPublicKeyAuthAlgorithms != nil {
		t.Error("SSHPublicKeyAuthAlgorithms is non-nil; want nil")
	}
	if config.TempExtensions != nil {
		t.Error("TempExtensions is non-nil; want nil")
	}
	if config.IdleTimeout != 0 {
		t.Errorf("IdleTimeout = %v; want 0", config.IdleTimeout)
	}
	if config.TCPKeepAlivePeriod != 0 {
		t.Errorf("TCPKeepAlivePeriod = %v; want 0", config.TCPKeepAlivePeriod)
	}
	if config.SftpAllowChown {
		t.Error("SftpAllowChown is true; want false")
	}

	other := DefaultConfig()
	if config == other {
		t.Fatal("DefaultConfig returned the same pointer twice")
	}
	config.SftpAddr = ":9999"
	if other.SftpAddr != ":2022" {
		t.Errorf("second config SftpAddr = %q after mutating first; want :2022", other.SftpAddr)
	}
}

// TestServer_TempExtensionsNormalisation verifies that TempExtensions are
// normalised (lower-cased, dot-prefixed, empty entries stripped) at
// construction.
func TestServer_TempExtensionsNormalisation(t *testing.T) {
	config := DefaultConfig()
	config.TempExtensions = []string{"TMP", ".Writing", "  ", ".part"}
	srv := NewServer(config)
	got := srv.configuredTempExtensions()
	want := []string{".tmp", ".writing", ".part"}
	if len(got) != len(want) {
		t.Fatalf("configuredTempExtensions() = %v; want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("configuredTempExtensions()[%d] = %q; want %q", i, got[i], w)
		}
	}
}

// TestServer_EffectiveIdleTimeout verifies the resolution rules of Server.effectiveIdleTimeout.
func TestServer_EffectiveIdleTimeout(t *testing.T) {
	s := &Server{}
	if got := s.effectiveIdleTimeout(); got != defaultSFTPIdleTimeout {
		t.Errorf("default idleTimeout = %v; want %v", got, defaultSFTPIdleTimeout)
	}
	s.idleTimeout = 7 * time.Second
	if got := s.effectiveIdleTimeout(); got != 7*time.Second {
		t.Errorf("custom idleTimeout = %v; want 7s", got)
	}
	s.idleTimeout = -1
	if got := s.effectiveIdleTimeout(); got != 0 {
		t.Errorf("negative idleTimeout = %v; want 0", got)
	}
}

func TestServer_EffectiveFTPDataAcceptTimeout(t *testing.T) {
	s := &Server{}
	if got := s.effectiveFTPDataAcceptTimeout(); got != defaultFTPDataAcceptTimeout {
		t.Errorf("default ftpDataAcceptTimeout = %v; want %v", got, defaultFTPDataAcceptTimeout)
	}
	s.ftpDataAcceptTimeout = 7 * time.Second
	if got := s.effectiveFTPDataAcceptTimeout(); got != 7*time.Second {
		t.Errorf("custom ftpDataAcceptTimeout = %v; want 7s", got)
	}
	s.ftpDataAcceptTimeout = -1
	if got := s.effectiveFTPDataAcceptTimeout(); got != 0 {
		t.Errorf("negative ftpDataAcceptTimeout = %v; want 0", got)
	}
}

// TestServer_EffectiveTCPKeepAlivePeriod verifies the resolution rules of
// Server.effectiveTCPKeepAlivePeriod.
func TestServer_EffectiveTCPKeepAlivePeriod(t *testing.T) {
	s := &Server{}
	if got := s.effectiveTCPKeepAlivePeriod(); got != defaultTCPKeepAlivePeriod {
		t.Errorf("default tcpKeepAlivePeriod = %v; want %v", got, defaultTCPKeepAlivePeriod)
	}
	s.tcpKeepAlivePeriod = 90 * time.Second
	if got := s.effectiveTCPKeepAlivePeriod(); got != 90*time.Second {
		t.Errorf("custom tcpKeepAlivePeriod = %v; want 90s", got)
	}
	s.tcpKeepAlivePeriod = -1
	if got := s.effectiveTCPKeepAlivePeriod(); got != 0 {
		t.Errorf("negative tcpKeepAlivePeriod = %v; want 0", got)
	}
}
