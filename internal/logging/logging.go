// Package logging provides the independent JSON log streams of limen.
//
// Observability is reading log files: no rotation logic lives in the
// binary. Rotation is delegated to logrotate, which sends SIGHUP; the
// daemon then calls Reopen on every stream.
//
// There are three streams, one per concern:
//
//	limen.log   daemon lifecycle, config reloads, certificate renewals
//	api.log     every panel request: who, what, from where, outcome
//	apply.log   every nginx render/test/reload, the audit trail of the
//	            configuration actually served
package logging

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/ostap-mykhaylyak/limen/internal/paths"
)

// stream is a log file that can be reopened in place (logrotate hook).
// Writes are serialized with a mutex so a reopen never races a line.
type stream struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

func openStream(path string) (*stream, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, err
	}
	return &stream{path: path, f: f}, nil
}

func (s *stream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Write(p)
}

// Reopen closes the current file and opens the path again, which is
// what makes logrotate's copy/rename dance work.
func (s *stream) Reopen() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	old := s.f
	s.f = f
	return old.Close()
}

func (s *stream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

// Logs holds every stream the daemon writes to.
type Logs struct {
	Service *slog.Logger
	API     *slog.Logger
	Apply   *slog.Logger

	streams []*stream
}

// Level maps a configured level name to its slog value. Unknown names
// fall back to info: the level is validated in config, and a logger is
// never a reason to refuse to start.
func Level(name string) slog.Level {
	switch name {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Open creates the three streams under dir. Every file is JSON, one
// object per line, at the given level.
func Open(dir string, level slog.Level) (*Logs, error) {
	l := &Logs{}
	mk := func(name string) (*slog.Logger, error) {
		s, err := openStream(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		l.streams = append(l.streams, s)
		return slog.New(slog.NewJSONHandler(s, &slog.HandlerOptions{Level: level})), nil
	}

	var err error
	if l.Service, err = mk(paths.ServiceLog); err != nil {
		l.Close()
		return nil, err
	}
	if l.API, err = mk(paths.APILog); err != nil {
		l.Close()
		return nil, err
	}
	if l.Apply, err = mk(paths.ApplyLog); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Stderr returns a Logs whose three streams all go to stderr. It is
// what the daemon uses before the log directory is known, and what
// tests use.
func Stderr(level slog.Level) *Logs {
	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	lg := slog.New(h)
	return &Logs{Service: lg, API: lg, Apply: lg}
}

// Discard returns a Logs that writes nowhere.
func Discard() *Logs {
	lg := slog.New(slog.NewJSONHandler(io.Discard, nil))
	return &Logs{Service: lg, API: lg, Apply: lg}
}

// Reopen reopens every stream. Call it on SIGHUP, after logrotate has
// moved the files aside.
func (l *Logs) Reopen() error {
	var errs []error
	for _, s := range l.streams {
		if err := s.Reopen(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Close closes every stream.
func (l *Logs) Close() error {
	var errs []error
	for _, s := range l.streams {
		if err := s.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	l.streams = nil
	return errors.Join(errs...)
}
