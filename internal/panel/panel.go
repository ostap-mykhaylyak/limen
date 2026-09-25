// Package panel serves the web interface and its REST API.
//
// The panel is the control plane of the whole machine, so it never
// faces the network itself: it listens on loopback (or on a unix
// socket) and is published by a virtual host that limen generates for
// the nginx it manages — TLS, access lists and rate limits are applied
// in front of it, by the same nginx as every other backend.
//
// At this milestone the server carries the plumbing only: listener,
// request log, client address behind a proxy, health probe and
// graceful shutdown. Authentication, the REST resources and the UI
// arrive with their own milestones.
package panel

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/audit"
	"github.com/ostap-mykhaylyak/limen/internal/config"
	"github.com/ostap-mykhaylyak/limen/internal/logging"
	"github.com/ostap-mykhaylyak/limen/internal/metrics"
	"github.com/ostap-mykhaylyak/limen/internal/status"
)

// Server is the panel HTTP server.
type Server struct {
	cfgs    *config.Manager
	logs    *logging.Logs
	metrics *metrics.Registry
	report  func() status.Report

	srv  *http.Server
	mux  *http.ServeMux
	ln   net.Listener
	addr string
	net  string
}

// New wires a panel server. report is the same function the status
// socket serves, so /healthz and `limen status` can never disagree.
// api, when not nil, serves everything under /api/; ui, when not nil,
// everything else.
func New(cfgs *config.Manager, logs *logging.Logs, reg *metrics.Registry, report func() status.Report, api, ui http.Handler) *Server {
	s := &Server{cfgs: cfgs, logs: logs, metrics: reg, report: report}

	mux := http.NewServeMux()
	s.mux = mux
	mux.HandleFunc("GET /healthz", s.handleHealth)
	if api != nil {
		mux.Handle("/api/", api)
	}
	if ui != nil {
		mux.Handle("/", ui)
	} else {
		mux.HandleFunc("/", s.handleNotFound)
	}

	cfg := cfgs.Get()
	s.srv = &http.Server{
		Handler:           s.instrument(mux),
		ReadHeaderTimeout: cfg.Panel.ReadHeaderTimeout.Std(),
		IdleTimeout:       cfg.Panel.IdleTimeout.Std(),
		// Whole requests and whole answers are bounded too: a client
		// that trickles its body a byte at a time must not hold a
		// connection for ever, whatever nginx in front does. No answer
		// of the API comes near these.
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}
	return s
}

// Handle adds a route. It is meant for wiring, before Serve: the ACME
// challenges, which nginx sends to the panel from every host.
func (s *Server) Handle(pattern string, h http.Handler) { s.mux.Handle(pattern, h) }

// Listen binds the configured address without serving yet, so that a
// bind failure is reported before the daemon claims to be up.
func (s *Server) Listen() error {
	cfg := s.cfgs.Get()
	network, addr := cfg.Panel.Network(), cfg.Panel.Listen

	if network == "unix" {
		// A socket left behind by a crash would make the bind fail;
		// nothing else may own this path.
		if _, err := os.Stat(addr); err == nil {
			if c, derr := net.DialTimeout("unix", addr, 200*time.Millisecond); derr == nil {
				c.Close()
				return fmt.Errorf("panel socket %s is already served by another process", addr)
			}
			if err := os.Remove(addr); err != nil {
				return fmt.Errorf("stale panel socket: %w", err)
			}
		}
	}

	ln, err := net.Listen(network, addr)
	if err != nil {
		return fmt.Errorf("panel listen %s: %w", addr, err)
	}
	// Only nginx and the operator's group reach the panel socket.
	// (Windows has no POSIX mode on an AF_UNIX path and rejects the
	// call; limen is a Linux service.)
	if network == "unix" && runtime.GOOS != "windows" {
		if err := os.Chmod(addr, 0o660); err != nil {
			ln.Close()
			return fmt.Errorf("panel socket permissions: %w", err)
		}
	}
	s.ln, s.net, s.addr = ln, network, addr
	return nil
}

// Serve runs the accept loop until Shutdown is called. It returns nil
// on a clean shutdown.
func (s *Server) Serve() error {
	if s.ln == nil {
		if err := s.Listen(); err != nil {
			return err
		}
	}
	err := s.srv.Serve(s.ln)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Addr returns the address the panel is bound to.
func (s *Server) Addr() string {
	if s.ln == nil {
		return s.cfgs.Get().Panel.Listen
	}
	return s.ln.Addr().String()
}

// Shutdown drains in-flight requests, then closes the listener.
func (s *Server) Shutdown(ctx context.Context) error {
	err := s.srv.Shutdown(ctx)
	if s.net == "unix" && s.addr != "" {
		if rmErr := os.Remove(s.addr); rmErr != nil && !os.IsNotExist(rmErr) && err == nil {
			err = rmErr
		}
	}
	return err
}

// statusWriter records the status code for the access log.
type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// instrument counts every request and writes one line per request to
// the api stream: the panel is a privileged surface and its log is an
// audit trail.
func (s *Server) instrument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		ctx, info := audit.With(r.Context())
		r = r.WithContext(ctx)

		s.metrics.Begin()
		defer func() {
			code := sw.code
			if code == 0 {
				code = http.StatusOK
			}
			s.metrics.End(code >= 400)
			attrs := []any{
				"method", r.Method,
				"path", r.URL.Path,
				"status", code,
				"client", s.ClientIP(r),
				"duration_ms", time.Since(start).Milliseconds(),
			}
			if info.User != "" {
				attrs = append(attrs, "user", info.User)
			}
			if info.Action != "" {
				attrs = append(attrs, "action", info.Action)
			}
			s.logs.API.Info("request", attrs...)
		}()

		next.ServeHTTP(sw, r)
	})
}

// ClientIP returns the address of the caller, honouring
// X-Forwarded-For only when the immediate peer is a trusted proxy —
// the nginx in front. An untrusted peer could otherwise forge any
// address it wanted in the audit log and in the access lists.
func (s *Server) ClientIP(r *http.Request) string {
	peer := peerIP(r.RemoteAddr)
	if !s.trusted(peer) {
		return peer
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// The rightmost entry is the one our own proxy appended; the
		// ones before it come from further out and are not trustworthy.
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
		return xr
	}
	return peer
}

func peerIP(remoteAddr string) string {
	if remoteAddr == "" {
		// A unix socket has no peer address: the caller is nginx,
		// running on this very machine.
		return "@local"
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func (s *Server) trusted(ip string) bool {
	if ip == "@local" {
		return true
	}
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	for _, entry := range s.cfgs.Get().Panel.TrustedProxies {
		if _, network, err := net.ParseCIDR(entry); err == nil {
			if network.Contains(addr) {
				return true
			}
			continue
		}
		if single := net.ParseIP(entry); single != nil && single.Equal(addr) {
			return true
		}
	}
	return false
}

// handleHealth is the probe for nginx and for any load balancer: it
// reuses the very same report the status socket serves, and maps its
// aggregate onto 200 or 503.
//
// It is the only route without authentication, and once the panel is
// published it answers the whole internet: so it says how limen is and
// nothing else. The full report — paths, versions, warnings, what an
// apply left out — is /api/v1/status, behind a login.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	rep := s.report()
	code := http.StatusOK
	if rep.Status == status.StatusCritical {
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]string{"status": rep.Status})
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
