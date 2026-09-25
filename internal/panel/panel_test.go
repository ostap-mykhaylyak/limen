package panel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/config"
	"github.com/ostap-mykhaylyak/limen/internal/logging"
	"github.com/ostap-mykhaylyak/limen/internal/metrics"
	"github.com/ostap-mykhaylyak/limen/internal/status"
)

// newServer wires a panel on an ephemeral loopback port and returns it
// with its base URL.
func newServer(t *testing.T, body string, report func() status.Report) (*Server, string) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgs, err := config.NewManager(path)
	if err != nil {
		t.Fatal(err)
	}

	s := New(cfgs, logging.Discard(), metrics.New(), report, nil, nil)
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	go s.Serve()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.Shutdown(ctx)
	})
	return s, "http://" + s.Addr()
}

func okReport() status.Report {
	rep := status.Report{Service: status.Service{Active: true, PID: 1}}
	rep.Add("nginx", status.StatusOK, "running")
	rep.Finish()
	return rep
}

// The probe must answer whatever the daemon is feeling, and say so
// with the status code a load balancer understands.
func TestHealthMapsTheReportOntoTheStatusCode(t *testing.T) {
	var critical atomic.Bool
	_, base := newServer(t, "panel:\n  listen: \"127.0.0.1:0\"\n", func() status.Report {
		if critical.Load() {
			rep := status.Report{}
			rep.Add("logdir", status.StatusCritical, "not writable")
			rep.Finish()
			return rep
		}
		return okReport()
	})

	resp, err := http.Get(base + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthy probe = %d, want 200", resp.StatusCode)
	}
	var rep status.Report
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		t.Fatal(err)
	}
	if rep.Status != status.StatusOK {
		t.Errorf("probe body says %q, want ok", rep.Status)
	}
	if rep.Service.PID != 0 || len(rep.Checks) != 0 {
		t.Errorf("the public probe tells more than the status: %+v", rep)
	}

	critical.Store(true)
	resp2, err := http.Get(base + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("critical probe = %d, want 503", resp2.StatusCode)
	}
}

func TestUnknownRouteIsJSON(t *testing.T) {
	_, base := newServer(t, "panel:\n  listen: \"127.0.0.1:0\"\n", okReport)

	resp, err := http.Get(base + "/nothing-here")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("content type = %q, want application/json", ct)
	}
	b, _ := io.ReadAll(resp.Body)
	var payload map[string]string
	if err := json.Unmarshal(b, &payload); err != nil {
		t.Fatalf("body is not JSON: %s", b)
	}
	if payload["error"] == "" {
		t.Errorf("body = %s, want an error field", b)
	}
}

// X-Forwarded-For decides what ends up in the audit log and, later,
// what the access lists match on. Believing it from an untrusted peer
// would let any caller write whatever address it liked.
func TestForwardedAddressIsBelievedOnlyFromATrustedProxy(t *testing.T) {
	s, _ := newServer(t, "panel:\n  listen: \"127.0.0.1:0\"\n  trusted_proxies: [\"127.0.0.1/32\", \"10.0.0.5\"]\n", okReport)

	cases := []struct {
		name   string
		peer   string
		header string
		value  string
		want   string
	}{
		{"trusted proxy, forwarded client", "127.0.0.1:5000", "X-Forwarded-For", "203.0.113.9", "203.0.113.9"},
		{"trusted single address", "10.0.0.5:5000", "X-Forwarded-For", "203.0.113.9", "203.0.113.9"},
		{"untrusted peer forging a header", "198.51.100.7:5000", "X-Forwarded-For", "203.0.113.9", "198.51.100.7"},
		{"trusted proxy, chain of hops", "127.0.0.1:5000", "X-Forwarded-For", "1.2.3.4, 203.0.113.9", "203.0.113.9"},
		{"trusted proxy, X-Real-IP", "127.0.0.1:5000", "X-Real-IP", "203.0.113.9", "203.0.113.9"},
		{"no header at all", "127.0.0.1:5000", "", "", "127.0.0.1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = c.peer
			if c.header != "" {
				r.Header.Set(c.header, c.value)
			}
			if got := s.ClientIP(r); got != c.want {
				t.Errorf("client = %q, want %q", got, c.want)
			}
		})
	}
}

// A unix socket has no peer address: the caller is the nginx on this
// very machine, so its forwarded header is the only client address
// there is.
func TestUnixPeerIsTrusted(t *testing.T) {
	s, _ := newServer(t, "panel:\n  listen: \"127.0.0.1:0\"\n", okReport)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = ""
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := s.ClientIP(r); got != "203.0.113.9" {
		t.Errorf("client = %q, want the forwarded address", got)
	}
}

// A client that trickles its request must not hold a connection for
// ever: every phase of a request has a bound.
func TestEveryPhaseOfARequestIsBounded(t *testing.T) {
	s, _ := newServer(t, "panel:\n  listen: \"127.0.0.1:0\"\n", okReport)
	for name, d := range map[string]time.Duration{
		"header": s.srv.ReadHeaderTimeout, "read": s.srv.ReadTimeout,
		"write": s.srv.WriteTimeout, "idle": s.srv.IdleTimeout,
	} {
		if d <= 0 || d > 5*time.Minute {
			t.Errorf("%s timeout %v", name, d)
		}
	}
}
