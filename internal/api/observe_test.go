package api

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/traffic"
)

func accessLine(t time.Time, status int, uri string) string {
	return fmt.Sprintf(`{"time":"%s","msec":%.3f,"remote":"203.0.113.7","host":"app.example.com","method":"GET","uri":"%s","proto":"HTTP/1.1","status":%d,"bytes":10,"duration":0.012,"upstream":"","upstream_status":"","upstream_time":"","tls":"","referer":"","agent":"curl"}`+"\n",
		t.Format(time.RFC3339), float64(t.UnixMilli())/1000, uri, status)
}

// withObserve gives the API a collector and log files in a temporary
// directory.
func withObserve(e *env) string {
	dir := e.t.TempDir()
	c := traffic.NewCollector(func(h string) string { return filepath.Join(dir, h+".access.log") }, nil)
	e.t.Cleanup(c.Close)
	e.api = e.build()
	e.api.d.Traffic = c
	e.api.d.Nginx = &traffic.NginxProbe{}
	e.api.d.Logs = LogSource{
		Host: func(n string) (string, string) {
			return filepath.Join(dir, n+".access.log"), filepath.Join(dir, n+".error.log")
		},
		System: func(s string) (string, bool) { return filepath.Join(dir, s+".log"), true },
	}
	return dir
}

func TestLogsAreForOperatorsAndTheAuditForAdmins(t *testing.T) {
	e := newEnv(t)
	dir := withObserve(e)
	viewer, operator, admin := e.login("vic"), e.login("olga"), e.login("alice")
	operator.do("POST", "/hosts", host("app.example.com", 8080))
	now := time.Now()
	os.WriteFile(filepath.Join(dir, "app.example.com.access.log"),
		[]byte(accessLine(now, 200, "/a")+accessLine(now, 502, "/b")+"garbage\n"+accessLine(now, 404, "/c")), 0o644)
	os.WriteFile(filepath.Join(dir, "api.log"), []byte(`{"time":"x","level":"INFO","msg":"request"}`+"\n"), 0o644)

	checks := []struct {
		who  *client
		path string
		want int
	}{
		{viewer, "/hosts/app.example.com/logs/access", 403},
		{viewer, "/hosts/app.example.com/traffic", 200},
		{viewer, "/traffic", 200},
		{operator, "/hosts/app.example.com/logs/access", 200},
		{operator, "/hosts/app.example.com/logs/nope", 404},
		{operator, "/hosts/ghost/logs/access", 404},
		{operator, "/logs/limen", 200},
		{operator, "/logs/api", 403},
		{admin, "/logs/api", 200},
		{operator, "/logs/etc-passwd", 404},
		{operator, "/traffic?window=7d", 400},
	}
	for _, c := range checks {
		if r := c.who.do("GET", c.path, nil); r.code != c.want {
			t.Errorf("GET %s: %d %s, want %d", c.path, r.code, r.raw, c.want)
		}
	}

	r := operator.do("GET", "/hosts/app.example.com/logs/access", nil)
	lines := r.body["lines"].([]any)
	if len(lines) != 4 || r.body["format"] != "access" {
		t.Fatalf("lines = %s", r.raw)
	}
	if lines[1].(map[string]any)["status"].(float64) != 502 {
		t.Errorf("parsed line = %v", lines[1])
	}
	if lines[2].(map[string]any)["raw"] != "garbage" {
		t.Errorf("an unreadable line = %v", lines[2])
	}

	r = operator.do("GET", "/hosts/app.example.com/logs/access?status=5xx", nil)
	if n := len(r.body["lines"].([]any)); n != 1 {
		t.Errorf("status=5xx: %d lines", n)
	}
	r = operator.do("GET", "/hosts/app.example.com/logs/access?q=%2Fc&lines=1", nil)
	if n := len(r.body["lines"].([]any)); n != 1 {
		t.Errorf("q=/c: %s", r.raw)
	}

	// Follow: what comes after the offset of the last answer.
	offset := int64(r.body["offset"].(float64))
	f, _ := os.OpenFile(filepath.Join(dir, "app.example.com.access.log"), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(accessLine(now, 201, "/new"))
	f.Close()
	r = operator.do("GET", fmt.Sprintf("/hosts/app.example.com/logs/access?after=%d", offset), nil)
	if ls := r.body["lines"].([]any); len(ls) != 1 || ls[0].(map[string]any)["uri"] != "/new" {
		t.Errorf("after=%d: %s", offset, r.raw)
	}

	r = operator.do("GET", "/hosts/app.example.com/logs/error", nil)
	if r.code != 200 || r.body["missing"] != true {
		t.Errorf("a log not written yet: %d %s", r.code, r.raw)
	}
	if r := operator.do("GET", "/hosts/app.example.com/logs/error?status=5xx", nil); r.code != 400 {
		t.Errorf("status on an error log: %d", r.code)
	}
	r = admin.do("GET", "/logs/api", nil)
	if ls := r.body["lines"].([]any); len(ls) != 1 || !strings.Contains(r.raw, `"msg": "request"`) {
		t.Errorf("the audit log: %s", r.raw)
	}
}

func TestTrafficOfAHost(t *testing.T) {
	e := newEnv(t)
	dir := withObserve(e)
	c := e.login("vic")
	e.login("olga").do("POST", "/hosts", host("app.example.com", 8080))
	now := time.Now()
	os.WriteFile(filepath.Join(dir, "app.example.com.access.log"),
		[]byte(accessLine(now, 200, "/a")+accessLine(now, 503, "/b")), 0o644)
	e.api.d.Traffic.Watch([]string{"app.example.com"})
	e.api.d.Traffic.Poll()

	r := c.do("GET", "/hosts/app.example.com/traffic?window=5m", nil)
	sum := r.body["summary"].(map[string]any)
	if sum["requests"].(float64) != 2 || sum["error_rate"].(float64) != 0.5 || r.body["logged"] != true {
		t.Errorf("summary = %s", r.raw)
	}
	if pts := r.body["series"].([]any); len(pts) != 5 {
		t.Errorf("%d points for 5 minutes", len(pts))
	}
	r = c.do("GET", "/traffic?window=24h", nil)
	if pts := r.body["series"].([]any); len(pts) != 288 {
		t.Errorf("%d points for a day, want 288", len(pts))
	}
	hosts := r.body["hosts"].([]any)
	if len(hosts) != 1 || hosts[0].(map[string]any)["name"] != "app.example.com" {
		t.Errorf("hosts = %v", hosts)
	}
}

// Following from offset 0 a log of megabytes does not load it whole in
// one answer: the next call carries on from where this one stopped.
func TestFollowingReadsABoundedPiece(t *testing.T) {
	e := newEnv(t)
	dir := withObserve(e)
	c := e.login("olga")
	c.do("POST", "/hosts", host("app.example.com", 8080))
	// 2000 lines of these weigh more than the bound: the bytes stop the
	// read, not the count.
	line := accessLine(time.Now(), 200, "/"+strings.Repeat("x", 4000))
	big := strings.Repeat(line, (10<<20)/len(line))
	os.WriteFile(filepath.Join(dir, "app.example.com.access.log"), []byte(big), 0o644)

	r := c.do("GET", "/hosts/app.example.com/logs/access?after=0&lines=2000", nil)
	off := int64(r.body["offset"].(float64))
	if off == 0 || off > maxFollow {
		t.Errorf("one read went to offset %d of a %d-byte log, want at most %d", off, len(big), maxFollow)
	}
}
