//go:build windows

package proc

import "errors"

// Reopen is a Unix signal; limen runs on Linux.
func Reopen(pidfile string) error { return errors.New("reopen: not supported on Windows") }
