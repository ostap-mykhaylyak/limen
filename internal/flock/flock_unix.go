//go:build unix

package flock

import (
	"os"
	"path/filepath"
	"syscall"
)

// Lock takes an exclusive flock on path, waiting for any other
// holder. The lock belongs to the open file description, so it is
// released when the process dies, however it dies: a crashed writer
// never leaves the model locked.
func Lock(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
