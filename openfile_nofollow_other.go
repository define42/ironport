//go:build !unix

package sftpserver

import "os"

func openFileNoFollow(name string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(name, flag, perm)
}
