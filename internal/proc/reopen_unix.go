//go:build !windows

package proc

import "syscall"

// Reopen asks the process of a pidfile to reopen its log files
// (SIGUSR1), which is what nginx does on that signal: logrotate's
// renamed files are let go, and new ones created.
func Reopen(pidfile string) error { return signal(pidfile, syscall.SIGUSR1) }
