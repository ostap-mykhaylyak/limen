package nginx

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/proc"
	"github.com/ostap-mykhaylyak/limen/internal/traffic"
)

// rawGet sends a request byte for byte, headers a Go client would
// refuse to send included.
func rawGet(t *testing.T, request string) {
	c, err := net.DialTimeout("tcp", "127.0.0.1:80", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte(request))
	bufio.NewReader(c).ReadString('\n')
}

// readLines waits for a log to hold want lines: nginx writes a line
// when it finalizes the request, which may come after the client has
// its answer.
func readLines(t *testing.T, path string, want int) []string {
	t.Helper()
	var lines []string
	for range 30 {
		b, _ := os.ReadFile(path)
		lines = strings.Split(strings.TrimSpace(string(b)), "\n")
		if len(b) > 0 && len(lines) >= want {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return lines
}

// lineWith is the line holding needle; with several workers the order
// of the lines is the order nginx finished the requests in.
func lineWith(lines []string, needle string) string {
	for _, l := range lines {
		if strings.Contains(l, needle) {
			return l
		}
	}
	return ""
}

// What real nginx writes in limen's format, with what a hostile client
// sends, must read back as the request it was.
func TestRealNginxHostLogsAndCounters(t *testing.T) {
	r := newRig(t)
	_, port := backend(t)
	app := host("app", port, "app.example.com")
	r.put(app)
	dead := host("dead", 1, "dead.example.com") // nothing listens on port 1
	r.put(dead)
	quiet := host("quiet", port, "quiet.example.com")
	quiet.LogRequests = false
	r.put(quiet)
	r.apply()
	r.startNginx()

	get("app.example.com", "/plain?a=1&b=%22x%22", nil)
	rawGet(t, "GET /evil?q=\"}\\x HTTP/1.1\r\nHost: app.example.com\r\nUser-Agent: Mozilla \"quoted\" \\ back ünï\r\nReferer: http://r.example/\"';\r\n\r\n")
	get("dead.example.com", "/", nil)
	get("quiet.example.com", "/nothing-logged", nil)

	access, errorLog := HostLogPaths(r.cfg.Nginx.HostLogs, "app")
	lines := readLines(t, access, 2)
	if len(lines) != 2 {
		t.Fatalf("app access log has %d lines:\n%s", len(lines), strings.Join(lines, "\n"))
	}
	evil := lineWith(lines, "/evil")
	e, err := traffic.ParseAccess([]byte(evil))
	if err != nil {
		t.Fatalf("a line real nginx wrote does not parse: %v\n%s", err, evil)
	}
	if e.Host != "app.example.com" || e.Method != "GET" || e.Status != 200 || e.URI != `/evil?q="}\x` {
		t.Errorf("parsed %+v\nfrom %s", e, evil)
	}
	if e.Agent != `Mozilla "quoted" \ back ünï` || e.Referer != `http://r.example/"';` {
		t.Errorf("agent %q, referer %q: escape=json must give back what the client sent", e.Agent, e.Referer)
	}
	if e.Upstream == "" || e.UpstreamStatus != "200" || time.Since(e.Time) > time.Minute || e.Time.After(time.Now().Add(time.Second)) {
		t.Errorf("upstream %q (%q), time %v", e.Upstream, e.UpstreamStatus, e.Time)
	}

	deadAccess, deadErrors := HostLogPaths(r.cfg.Nginx.HostLogs, "dead")
	if d, err := traffic.ParseAccess([]byte(readLines(t, deadAccess, 1)[0])); err != nil || d.Status != 502 {
		t.Errorf("dead: %+v %v", d, err)
	}
	el := traffic.ParseError([]byte(readLines(t, deadErrors, 1)[0]))
	if el.Level != "error" || !strings.Contains(el.Message, "connect() failed") || el.Client != "127.0.0.1" ||
		!strings.HasPrefix(el.Request, "GET / HTTP/1.1") || time.Since(el.Time) > time.Minute {
		t.Errorf("error line %+v", el)
	}
	if b, _ := os.ReadFile(errorLog); len(b) != 0 {
		t.Errorf("app's error log holds another host's errors:\n%s", b)
	}
	quietAccess, _ := HostLogPaths(r.cfg.Nginx.HostLogs, "quiet")
	if _, err := os.Stat(quietAccess); err == nil {
		t.Error("a host that does not log its requests has an access log")
	}

	// The counters, from the default server, for loopback only.
	f, err := Probe(context.Background(), r.cfg.Nginx.Bin)
	if err != nil {
		t.Fatal(err)
	}
	if !f.StubStatus {
		t.Fatalf("this nginx has no stub_status module: %+v", f)
	}
	p := &traffic.NginxProbe{URL: "http://127.0.0.1" + StatusPath}
	st := p.Poll(context.Background())
	if !st.OK || st.Requests < 4 || st.Active < 1 {
		t.Errorf("nginx counters %+v", st)
	}
	// Named like a host, the path is the host's: its backend answers,
	// not nginx's counters.
	if _, body, _ := get("app.example.com", StatusPath, nil); strings.Contains(body, "Active connections") {
		t.Error("the counters answer through a host")
	}

	// logrotate, as it runs: rename, create the new file at once, and
	// only in postrotate tell nginx to reopen. In between nginx writes
	// to the renamed file, while the new one already sits at the path.
	c := traffic.NewCollector(func(h string) string { a, _ := HostLogPaths(r.cfg.Nginx.HostLogs, h); return a }, nil)
	defer c.Close()
	c.Watch([]string{"app"})
	c.Poll()
	get("app.example.com", "/before-rotation", nil)
	if err := os.Rename(access, access+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(access, nil, 0o640); err != nil { // create 0640 root adm
		t.Fatal(err)
	}
	get("app.example.com", "/after-rename", nil)
	c.Poll() // the collector sees the new file
	get("app.example.com", "/before-reopen", nil)
	if err := proc.Reopen(r.cfg.Nginx.PIDFile); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	get("app.example.com", "/after-reopen", nil)
	time.Sleep(200 * time.Millisecond)
	c.Poll()

	// Every worker reopened: the workers run as the worker user and
	// reopen the files themselves, which the directory must let them.
	newer, _ := os.ReadFile(access)
	older, _ := os.ReadFile(access + ".1")
	if !strings.Contains(string(newer), "/after-reopen") || strings.Contains(string(older), "/after-reopen") {
		errs, _ := os.ReadFile(r.cfg.Nginx.ErrorLog)
		t.Errorf("after the reopen nginx still writes to the rotated file:\nnew: %s\nold: %s\nerror log: %s", newer, older, errs)
	}
	if tot := c.Totals()["app"]; tot.Requests != 4 {
		t.Errorf("across the rotation the collector counted %d new requests, want 4", tot.Requests)
	}
	// Read back from history: /plain, /evil and the status path asked of
	// app; then the four new ones.
	if s, _ := c.HostSummary("app", time.Hour); s.Requests != 7 {
		t.Errorf("history and new: %d requests in the last hour, want 7", s.Requests)
	}
}

func TestRealNginxRateLimitsThePanel(t *testing.T) {
	r := newRig(t)
	_, port := backend(t)
	panel := host(PanelHost, port, "limen.example.com")
	panel.Protected = true
	r.put(panel)
	r.apply()
	r.startNginx()

	send := func(method, path string, n int) (ok, limited int) {
		for range n {
			req, _ := http.NewRequest(method, "http://127.0.0.1"+path, strings.NewReader("{}"))
			req.Host = "limen.example.com"
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			switch resp.StatusCode {
			case 200:
				ok++
			case 429:
				limited++
			default:
				t.Fatalf("%s %s: %d", method, path, resp.StatusCode)
			}
		}
		return
	}
	// A person using the panel: a page is a handful of calls.
	if ok, limited := send("GET", "/api/v1/status", 20); ok != 20 || limited != 0 {
		t.Errorf("normal use: %d ok, %d limited", ok, limited)
	}
	// A login flood: the burst goes through, the rest waits outside.
	ok, limited := send("POST", LoginPath, 30)
	if ok < 10 || ok > 13 || limited == 0 {
		t.Errorf("30 logins at once: %d reached the panel, %d were refused; want about 11 and the rest refused", ok, limited)
	}
	// The flood of logins did not lock the rest of the panel.
	if ok, _ := send("GET", "/api/v1/status", 5); ok != 5 {
		t.Errorf("after a login flood the panel answers %d of 5 requests", ok)
	}
	// A flood of anything is shed too.
	if _, limited := send("GET", "/api/v1/hosts", 120); limited == 0 {
		t.Error("120 requests at once, none refused")
	}
}
