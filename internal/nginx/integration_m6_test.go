package nginx

import (
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/model"
	"github.com/ostap-mykhaylyak/limen/internal/secret"
)

// tagged is a backend that says who it is and what it received.
func tagged(t *testing.T, tag string) int {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s path=%s host=%s env=%s auth=%q", tag, r.URL.Path, r.Host, r.Header.Get("X-Env"), r.Header.Get("Authorization"))
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().(*net.TCPAddr).Port
}

// denied connects and returns what came back; nginx answers a denied
// client by closing (or resetting) the connection, so "" is expected.
func denied(t *testing.T, addr string) string {
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return ""
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte("ping\n"))
	b, _ := io.ReadAll(c)
	return string(b)
}

func getHeader(host, path string, header http.Header) (int, string, http.Header, error) {
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil)
	req.Host = host
	maps.Copy(req.Header, header)
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return resp.StatusCode, b.String(), resp.Header, nil
}

func TestRealNginxLocationsGuardsAndSnippets(t *testing.T) {
	r := newRig(t)
	a, b := tagged(t, "A"), tagged(t, "B")

	hash, err := secret.HashBasic("gate-password")
	if err != nil {
		t.Fatal(err)
	}
	staff := model.NewAccessList("staff")
	staff.Users = []model.BasicUser{{Username: "ops", Password: hash}}
	lan := model.NewAccessList("lan")
	lan.Rules = []model.Rule{{Action: "allow", Address: "127.0.0.1"}, {Action: "deny", Address: "all"}}
	elsewhere := model.NewAccessList("elsewhere")
	elsewhere.Rules = []model.Rule{{Action: "deny", Address: "127.0.0.1"}, {Action: "allow", Address: "all"}}
	r.put(staff)
	r.put(lan)
	r.put(elsewhere)

	h := host("app", a, "app.example.com")
	h.AccessList = "staff"
	h.CacheAssets = true
	h.Snippet = "add_header X-Snippet yes always;\nproxy_read_timeout 30s;"
	h.Proxy = model.ProxyOptions{
		HostHeader:     model.HostHeaderUpstream,
		RequestHeaders: []model.Header{{Name: "X-Env", Value: "test-$request_method"}},
	}
	h.Locations = []model.Location{
		{Path: "/api/", Forward: &model.Upstream{Scheme: "http", Host: "127.0.0.1", Port: b}},
		{Path: "/hooks/", Public: true},
		{Path: "/lan/", AccessList: "lan"},
		{Path: "/closed/", AccessList: "elsewhere"},
		{Path: "/health", Exact: true, Public: true, Snippet: `return 200 "ok;} server { listen 8081; \"";`},
	}
	r.put(h)
	r.apply()
	r.startNginx()

	auth := http.Header{"Authorization": {basic("ops", "gate-password")}}
	checks := []struct {
		name   string
		path   string
		header http.Header
		code   int
		body   string // a prefix
	}{
		{"the host is guarded", "/", nil, 401, ""},
		{"with the password", "/x", auth, 200, "A path=/x"},
		{"a location inherits the guard", "/api/v1", nil, 401, ""},
		{"and goes to its own backend", "/api/v1", auth, 200, "B path=/api/v1"},
		{"a stylesheet under /api/ too", "/api/app.css", auth, 200, "B path=/api/app.css"},
		{"a public location", "/hooks/push", nil, 200, "A path=/hooks/push"},
		{"a list of rules asks no password", "/lan/x", nil, 200, "A path=/lan/x"},
		{"a list of rules refuses", "/closed/x", auth, 403, ""},
		{"a snippet answers, whole", "/health", nil, 200, `ok;} server { listen 8081; "`},
	}
	for _, c := range checks {
		code, body, _, err := getHeader("app.example.com", c.path, c.header)
		if err != nil || code != c.code || !strings.HasPrefix(body, c.body) {
			t.Errorf("%s: GET %s = %d %q %v, want %d %q", c.name, c.path, code, body, err, c.code, c.body)
		}
	}

	_, body, hdr, _ := getHeader("app.example.com", "/x", auth)
	if hdr.Get("X-Snippet") != "yes" {
		t.Errorf("the host snippet's header is missing: %v", hdr)
	}
	if !strings.Contains(body, "env=test-GET") {
		t.Errorf("the request header did not reach the backend, variables expanded: %s", body)
	}
	if !strings.Contains(body, fmt.Sprintf("host=127.0.0.1:%d", a)) {
		t.Errorf("host_header upstream: the backend saw %s", body)
	}
	if !strings.Contains(body, `auth=""`) {
		t.Errorf("the gate's credentials reached the backend: %s", body)
	}
	// Had the snippet escaped its block, nginx would listen on 8081.
	if c, err := net.Dial("tcp", "127.0.0.1:8081"); err == nil {
		c.Close()
		t.Error("something listens on 8081: the snippet opened a server")
	}

	if r.engineHasStream(t) {
		echo := echoServer(t)
		open := model.NewStream("open")
		open.Listen, open.Forward, open.AccessList = 15441, model.Endpoint{Host: "127.0.0.1", Port: echo}, "lan"
		shut := model.NewStream("shut")
		shut.Listen, shut.Forward, shut.AccessList = 15442, model.Endpoint{Host: "127.0.0.1", Port: echo}, "elsewhere"
		r.put(open)
		r.put(shut)
		if res := r.apply(); !res.Reloaded || len(res.Skipped) > 0 {
			t.Fatalf("apply with guarded streams = %+v", res)
		}
		if got := roundTrip(t, "127.0.0.1:15441", "ping\n"); got != "ping" {
			t.Errorf("an allowed client got %q", got)
		}
		if got := denied(t, "127.0.0.1:15442"); got != "" {
			t.Errorf("a denied client got %q", got)
		}
	}
}
