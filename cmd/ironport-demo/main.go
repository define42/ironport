// Command ironport-demo is a runnable library demo for the ironport package.
// It is not an operator-ready server; production deployments should provide
// their own user source, logging, and host-key management.
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/define42/ironport"
	"golang.org/x/crypto/ssh"
)

type flags struct {
	hostKeyPath                *string
	sftpAddr                   *string
	ftpAddr                    *string
	httpAddr                   *string
	ftpPassive                 *string
	ftpActive                  *bool
	ftpsCert                   *string
	ftpsKey                    *string
	ftpsRequireTLS             *bool
	sshKex                     *string
	sshCiphers                 *string
	sshMACs                    *string
	sshPublicKeyAuthAlgorithms *string
}

func parseFlags() flags {
	f := flags{
		hostKeyPath:                flag.String("host-key", "", "path to a PEM-encoded private key file to use as the server host key (generated if not provided)"),
		sftpAddr:                   flag.String("sftp-addr", ":2022", "TCP address to listen on for SFTP"),
		ftpAddr:                    flag.String("ftp-addr", "", "TCP address to listen on for FTP/FTPS (empty to disable; credentials are sent in the clear unless -ftps-cert is set, see README)"),
		httpAddr:                   flag.String("http-addr", "", "TCP address to listen on for HTTP uploads at POST /upload (empty to disable; Basic-auth credentials are sent in the clear, put this behind TLS, see README)"),
		ftpPassive:                 flag.String("ftp-passive", "5000-5010", "FTP passive-mode data port range (used only when -ftp-addr is set)"),
		ftpActive:                  flag.Bool("ftp-active", false, "enable FTP active mode PORT/EPRT (dials back only to the control connection IP)"),
		ftpsCert:                   flag.String("ftps-cert", "", "path to a PEM-encoded certificate to advertise AUTH TLS (RFC 4217) on the FTP listener; requires -ftps-key"),
		ftpsKey:                    flag.String("ftps-key", "", "path to the PEM-encoded private key matching -ftps-cert"),
		ftpsRequireTLS:             flag.Bool("ftps-require-tls", false, "refuse USER/PASS over the FTP control connection until AUTH TLS has succeeded (requires -ftps-cert)"),
		sshKex:                     flag.String("ssh-key-exchanges", "", "comma-separated SSH key-exchange algorithms to allow (empty uses defaults)"),
		sshCiphers:                 flag.String("ssh-ciphers", "", "comma-separated SSH cipher algorithms to allow (empty uses defaults)"),
		sshMACs:                    flag.String("ssh-macs", "", "comma-separated SSH MAC algorithms to allow (empty uses defaults)"),
		sshPublicKeyAuthAlgorithms: flag.String("ssh-public-key-auth-algorithms", "", "comma-separated public-key auth signature algorithms to allow (empty uses defaults)"),
	}
	flag.Parse()
	return f
}

func buildConfig(f flags, signer ssh.Signer, users map[string]ironport.UserInfo) *ironport.Config {
	config := ironport.DefaultConfig()
	config.SftpAddr = *f.sftpAddr
	config.FtpAddr = *f.ftpAddr
	config.FtpPassivePortRange = *f.ftpPassive
	config.FtpAllowActiveMode = *f.ftpActive
	config.FtpTLSConfig = loadFTPSTLSConfig(*f.ftpsCert, *f.ftpsKey)
	if *f.ftpsRequireTLS {
		if config.FtpTLSConfig == nil {
			log.Fatal("-ftps-require-tls requires -ftps-cert and -ftps-key")
		}
		config.FtpRequireTLS = true
	}
	config.Users = users
	config.SftpSigner = signer
	config.CompletedUploadSize = 64
	config.AuthEventSize = 64
	config.SSHKeyExchanges = splitCSV(*f.sshKex)
	config.SSHCiphers = splitCSV(*f.sshCiphers)
	config.SSHMACs = splitCSV(*f.sshMACs)
	config.SSHPublicKeyAuthAlgorithms = splitCSV(*f.sshPublicKeyAuthAlgorithms)
	// Files written with one of these extensions are considered "still being
	// written" and won't be announced on CompletedUploads until the client
	// renames them to a final (non-temp) name.
	config.TempExtensions = []string{".tmp", ".writing"}
	return config
}

func loadSigner(path string) ssh.Signer {
	if path == "" {
		return nil
	}
	signer, err := ironport.NewSignerFromFile(path)
	if err != nil {
		log.Fatal(err)
	}
	return signer
}

func startEventLoggers(srv *ironport.Server) {
	go func() {
		for ev := range srv.CompletedUploads() {
			log.Printf("completed upload: protocol=%q user=%q ip=%q path=%q full=%q",
				ev.Protocol, ev.Username, ev.ClientIP, ev.FilePath, ev.FullFilePath)
		}
	}()
	go func() {
		for ev := range srv.AuthEvents() {
			log.Printf("auth event: type=%q protocol=%q user=%q ip=%q",
				ev.Type, ev.Protocol, ev.Username, ev.ClientIP)
		}
	}()
}

func main() {
	// This command is a runnable library demo, not an operator-ready server.
	// Production deployments should provide their own user source, logging,
	// metrics, health checks, process supervision, and stable host-key handling.
	f := parseFlags()

	// Example user DB (replace with your auth source).
	// WARNING: never hardcode credentials in production; use env vars or a secret store.
	users := map[string]ironport.UserInfo{
		"alice": {Password: "alicepw", Root: "/srv/sftp/alice", CanRead: true, CanWrite: true},
		"bob":   {Password: "bobpw", Root: "/srv/sftp/bob", CanRead: true, CanWrite: false},
	}

	signer := loadSigner(*f.hostKeyPath)
	config := buildConfig(f, signer, users)
	srv := ironport.NewServer(config)
	startEventLoggers(srv)
	startHTTPIngest(srv, *f.httpAddr)
	log.Fatal(srv.ListenAndServe())
}

// startHTTPIngest exposes the HTTP upload endpoint on addr in a background
// goroutine when addr is non-empty. The demo serves it in the clear; a real
// deployment should terminate TLS here (http.ListenAndServeTLS) or in front of
// it so the Basic-auth credential is not sent unencrypted.
func startHTTPIngest(srv *ironport.Server, addr string) {
	if addr == "" {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/upload", srv.HttpIngest())
	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Printf("HTTP upload endpoint listening on %s (POST multipart key=file to /upload)", addr)
		log.Fatal(server.ListenAndServe())
	}()
}

// loadFTPSTLSConfig builds a *tls.Config from the operator-supplied cert/key
// pair. Returns nil when neither flag is set; calls log.Fatal when only one
// of the pair is set or when the key pair cannot be loaded.
func loadFTPSTLSConfig(certPath, keyPath string) *tls.Config {
	if certPath == "" && keyPath == "" {
		return nil
	}
	if certPath == "" || keyPath == "" {
		log.Fatal("-ftps-cert and -ftps-key must be supplied together")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatalf("load FTPS certificate: %v", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			values = append(values, part)
		}
	}
	if len(values) == 0 {
		return nil
	}
	return values
}
