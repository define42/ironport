package main

import (
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"log"

	"github.com/define42/ironport"
	"golang.org/x/crypto/ssh"
)

func main() {
	hostKeyPath := flag.String("host-key", "", "path to a PEM-encoded private key file to use as the server host key (generated if not provided)")
	sftpAddr := flag.String("sftp-addr", ":2022", "TCP address to listen on for SFTP")
	ftpAddr := flag.String("ftp-addr", "", "TCP address to listen on for plaintext FTP (empty to disable; credentials are sent in the clear, see README)")
	ftpPassive := flag.String("ftp-passive", "5000-5010", "FTP passive-mode data port range (used only when -ftp-addr is set)")
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
	} else {
		signer = mustHostKey()
	}

	srv := ironport.NewServer(*sftpAddr, *ftpAddr, *ftpPassive, users, signer, 64)
	// Files written with one of these extensions are considered "still being
	// written" and won't be announced on CompletedUploads until the client
	// renames them to a final (non-temp) name.
	srv.TempExtensions = []string{".tmp", ".writing"}

	go func() {
		for ev := range srv.CompletedUploads() {
			log.Printf("completed upload: user=%q ip=%q path=%q full=%q",
				ev.Username, ev.ClientIP, ev.FilePath, ev.FullFilePath)
		}
	}()

	log.Fatal(srv.ListenAndServe())
}

func mustHostKey() ssh.Signer {
	// For demo: generate a new key on each start.
	// In production: load from disk and keep stable.
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		log.Fatal(err)
	}
	return signer
}
