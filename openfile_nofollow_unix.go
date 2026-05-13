//go:build unix

package sftpserver

import (
	"os"

	"golang.org/x/sys/unix"
)

func openFileNoFollow(name string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(name, flag|unix.O_NOFOLLOW, perm)
}
