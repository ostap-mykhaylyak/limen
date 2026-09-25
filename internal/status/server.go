package status

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Server publishes the report on a local unix socket.
//
// Running the binary a second time starts a separate process, which
// cannot see the memory of the daemon; the socket is how the live
// numbers cross that boundary. It is local only: no network bind, no
// remote access, nothing to authenticate. Anything reachable from the
// network is the panel's job, not this one's.
type Server struct {
	path string
	ln   net.Listener
	fn   func() Report
}

// Serve starts the status server on path, replacing a stale socket
// left behind by a previous crash.
func Serve(path string, fn func() Report) (*Server, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("status socket dir: %w", err)
	}
	// A socket file that nothing is listening on would make every
	// connection fail with ECONNREFUSED; remove it before binding.
	if err := removeStale(path); err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("status socket: %w", err)
	}
	// 0660: the operator reaches it through the group, not the world.
	// Windows has no POSIX mode on an AF_UNIX path, and rejects the
	// call; limen is a Linux service, this only keeps the tests honest
	// on a development machine.
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o660); err != nil {
			ln.Close()
			return nil, fmt.Errorf("status socket permissions: %w", err)
		}
	}

	s := &Server{path: path, ln: ln, fn: fn}
	go s.accept()
	return s, nil
}

func removeStale(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	c, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err == nil {
		c.Close()
		return fmt.Errorf("status socket %s is already served by another process", path)
	}
	return os.Remove(path)
}

func (s *Server) accept() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			// Closed listener: the daemon is shutting down.
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	rep := s.fn()
	_ = rep.WriteJSON(conn)
}

// Addr returns the socket path.
func (s *Server) Addr() string { return s.path }

// Close stops serving and removes the socket file.
func (s *Server) Close() error {
	err := s.ln.Close()
	if rmErr := os.Remove(s.path); rmErr != nil && !os.IsNotExist(rmErr) && err == nil {
		err = rmErr
	}
	return err
}
