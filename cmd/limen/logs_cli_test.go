package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/config"
)

func accessLine(t time.Time, status int, uri string) string {
	return fmt.Sprintf(`{"time":"%s","msec":%.3f,"remote":"203.0.113.7","host":"app.example.com","method":"GET","uri":"%s","proto":"HTTP/1.1","status":%d,"bytes":1234,"duration":0.012,"upstream":"127.0.0.1:3000","upstream_status":"%d","upstream_time":"0.010","tls":"","referer":"","agent":"curl"}`+"\n",
		t.Format(time.RFC3339), float64(t.UnixMilli())/1000, uri, status, status)
}

func TestHostLogsAndLogs(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Nginx.HostLogs = dir
	cfg.Nginx.ErrorLog = filepath.Join(dir, "error.log")
	h.config = func() (*config.Config, error) { return cfg, nil }
	h.must(t, "host add app --domain app.example.com --forward 10.0.0.5:8080")

	now := time.Now()
	var b strings.Builder
	for i := range 30 {
		b.WriteString(accessLine(now, 200, fmt.Sprintf("/ok/%d", i)))
	}
	b.WriteString(accessLine(now, 502, "/broken"))
	b.WriteString(accessLine(now, 404, "/missing"))
	os.WriteFile(filepath.Join(dir, "app.access.log"), []byte(b.String()), 0o644)
	os.WriteFile(filepath.Join(dir, "app.error.log"),
		[]byte("2026/09/25 10:11:12 [error] 7#7: *3 connect() failed (111: Connection refused) while connecting to upstream, client: 203.0.113.7, server: app.example.com, request: \"GET /broken HTTP/1.1\"\n"), 0o644)

	out := h.must(t, "host logs app -n 3")
	if n := strings.Count(out, "\n"); n != 3 || !strings.Contains(out, "/missing") || !strings.Contains(out, "  502  GET") {
		t.Errorf("the last 3 requests:\n%s", out)
	}
	out = h.must(t, "host logs app --status 5xx")
	if strings.Count(out, "\n") != 1 || !strings.Contains(out, "/broken") {
		t.Errorf("5xx:\n%s", out)
	}
	out = h.must(t, "host logs app --grep OK/2 -n 100")
	if strings.Count(out, "\n") != 11 { // /ok/2 and /ok/20../ok/29
		t.Errorf("grep:\n%s", out)
	}
	out = h.must(t, "host logs app --errors")
	if !strings.Contains(out, "error") || !strings.Contains(out, "connect() failed") {
		t.Errorf("errors:\n%s", out)
	}
	out = h.must(t, "host logs app -n 1 --json")
	if !strings.HasPrefix(out, `{"time":`) || !strings.Contains(out, `"status":404`) {
		t.Errorf("json:\n%s", out)
	}
	if err := h.do(t, "host logs app --errors --status 5xx"); err == nil {
		t.Error("--status on an error log accepted")
	}
	if err := h.do(t, "host logs nope"); err == nil {
		t.Error("the logs of a host that does not exist")
	}

	h.must(t, "logs nginx-error")
	if !strings.Contains(h.errOut.String(), "nothing logged yet") {
		t.Errorf("a missing log: %q", h.errOut.String())
	}
	if err := h.do(t, "logs everything"); err == nil {
		t.Error("an unknown stream accepted")
	}
}
