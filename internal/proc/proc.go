// Package proc handles the pidfile and the signals that drive a
// running daemon: it is how `limen stop` and `limen reload` reach the
// process started by `limen start` (or by systemd).
package proc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ErrNotRunning is returned when no live daemon owns the pidfile.
var ErrNotRunning = errors.New("service not running")

// WritePidfile records the current pid, creating the parent directory
// if needed. The caller removes the file on shutdown.
func WritePidfile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("pidfile dir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
		return fmt.Errorf("write pidfile: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("install pidfile: %w", err)
	}
	return nil
}

// ReadPidfile returns the pid recorded in path.
func ReadPidfile(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, ErrNotRunning
		}
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("pidfile %s: malformed content", path)
	}
	return pid, nil
}

// Alive reports whether pid is a live process. Signal 0 performs the
// permission and existence check without delivering anything.
func Alive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}

// Running returns the pid of the live daemon, or ErrNotRunning when
// the pidfile is absent or stale.
func Running(pidfile string) (int, error) {
	pid, err := ReadPidfile(pidfile)
	if err != nil {
		return 0, err
	}
	if !Alive(pid) {
		return 0, ErrNotRunning
	}
	return pid, nil
}

func signal(pidfile string, sig syscall.Signal) error {
	pid, err := Running(pidfile)
	if err != nil {
		return err
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Signal(sig)
}

// Stop asks the daemon to shut down gracefully (SIGTERM).
func Stop(pidfile string) error { return signal(pidfile, syscall.SIGTERM) }

// Reload asks the daemon to re-read its configuration and reopen its
// log files (SIGHUP). It never terminates the process.
func Reload(pidfile string) error { return signal(pidfile, syscall.SIGHUP) }

// StopAndWait sends SIGTERM and waits for the process to disappear, so
// that a restart does not race the old daemon for the listening
// sockets.
func StopAndWait(pidfile string, timeout time.Duration) error {
	if err := Stop(pidfile); err != nil {
		if errors.Is(err, ErrNotRunning) {
			return nil
		}
		return err
	}
	pid, err := ReadPidfile(pidfile)
	if err != nil {
		return nil
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !Alive(pid) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("pid %d still running after %s", pid, timeout)
}
