package main

import (
	"flag"
	"log"
	"strings"

	"github.com/define42/ironport"
	"golang.org/x/crypto/ssh"
)

func main() {
	// This command is a runnable library demo, not an operator-ready server.
	// Production deployments should provide their own user source, logging,
	// metrics, health checks, process supervision, and stable host-key handling.
	hostKeyPath := flag.String("host-key", "", "path to a PEM-encoded private key file to use as the server host key (generated if not provided)")
	sftpAddr := flag.String("sftp-addr", ":2022", "TCP address to listen on for SFTP")
	ftpAddr := flag.String("ftp-addr", "", "TCP address to listen on for plaintext FTP (empty to disable; credentials are sent in the clear, see README)")
	ftpPassive := flag.String("ftp-passive", "5000-5010", "FTP passive-mode data port range (used only when -ftp-addr is set)")
	sshKex := flag.String("ssh-key-exchanges", "", "comma-separated SSH key-exchange algorithms to allow (empty uses defaults)")
	sshCiphers := flag.String("ssh-ciphers", "", "comma-separated SSH cipher algorithms to allow (empty uses defaults)")
	sshMACs := flag.String("ssh-macs", "", "comma-separated SSH MAC algorithms to allow (empty uses defaults)")
	sshPublicKeyAuthAlgorithms := flag.String("ssh-public-key-auth-algorithms", "", "comma-separated public-key auth signature algorithms to allow (empty uses defaults)")
	flag.Parse()

	// Example user DB (replace with your auth source).
	// WARNING: never hardcode credentials in production; use env vars or a secret store.
	users := map[string]ironport.UserInfo{
		"alice": {Password: "alicepw", Root: "/srv/sftp/alice", CanRead: true, CanWrite: true},
		"bob":   {Password: "bobpw", Root: "/srv/sftp/bob", CanRead: true, CanWrite: false},
	}

	var signer ssh.Signer
	if *hostKeyPath != "" {
		var err error
		signer, err = ironport.NewSignerFromFile(*hostKeyPath)
		if err != nil {
			log.Fatal(err)
		}
	}

	config := ironport.DefaultIronportConfig()
	config.Addr = *sftpAddr
	config.FtpAddr = *ftpAddr
	config.FtpPassivePortRange = *ftpPassive
	config.Users = users
	config.Signer = signer
	config.CompletedUploadSize = 64
	config.AuthEventSize = 64
	config.SSHKeyExchanges = splitCSV(*sshKex)
	config.SSHCiphers = splitCSV(*sshCiphers)
	config.SSHMACs = splitCSV(*sshMACs)
	config.SSHPublicKeyAuthAlgorithms = splitCSV(*sshPublicKeyAuthAlgorithms)
	// Files written with one of these extensions are considered "still being
	// written" and won't be announced on CompletedUploads until the client
	// renames them to a final (non-temp) name.
	config.TempExtensions = []string{".tmp", ".writing"}
	srv := ironport.NewServer(config)

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

	log.Fatal(srv.ListenAndServe())
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
