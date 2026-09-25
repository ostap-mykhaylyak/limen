package nginx

import (
	"strings"
	"testing"

	"github.com/ostap-mykhaylyak/limen/internal/importer"
	"github.com/ostap-mykhaylyak/limen/internal/model"
)

func TestEveryHostHasItsOwnLogs(t *testing.T) {
	in := baseInput(t)
	in.Nginx.HostLogs = "/var/log/nginx/limen"
	app := proxyHost("app", "app.example.com")
	app.TLS.Certificate = "app"
	giveCert(t, in, "app")
	quiet := proxyHost("quiet", "quiet.example.com")
	quiet.LogRequests = false
	in.Hosts = append(in.Hosts, app, quiet)
	out := render(t, in)

	for _, srv := range importer.Find(parsed(t, file(t, out, "hosts/app.conf")), "server") {
		if got := values(srv.Block, "access_log"); len(got) != 1 || got[0] != "/var/log/nginx/limen/app.access.log limen" {
			t.Errorf("app access_log = %v, in every server block of the host", got)
		}
		if got := values(srv.Block, "error_log"); len(got) != 1 || got[0] != "/var/log/nginx/limen/app.error.log warn" {
			t.Errorf("app error_log = %v", got)
		}
	}
	srv := importer.First(parsed(t, file(t, out, "hosts/quiet.conf")), "server")
	if got := values(srv.Block, "access_log"); len(got) != 1 || got[0] != "off" {
		t.Errorf("a host that does not log its requests: access_log = %v", got)
	}
	if got := values(srv.Block, "error_log"); len(got) != 1 {
		t.Errorf("it still has its error log: %v", got)
	}

	http := file(t, out, "http.conf")
	if !strings.Contains(http, "log_format limen escape=json '{") {
		t.Errorf("the log format is not declared:\n%s", http)
	}
	// Every value a client controls goes through escape=json, inside
	// quotes; the numbers are variables nginx always fills.
	for _, v := range []string{`"uri":"$request_uri"`, `"agent":"$http_user_agent"`, `"referer":"$http_referer"`, `"host":"$host"`, `"status":$status`, `"msec":$msec`} {
		if !strings.Contains(http, v) {
			t.Errorf("log format lacks %s", v)
		}
	}
}

func TestNginxCountersAreForLoopbackOnly(t *testing.T) {
	in := baseInput(t)
	in.Features.StubStatus = true
	def := file(t, render(t, in), "default.conf")
	srv := importer.First(parsed(t, def), "server")
	var loc *importer.Directive
	for _, l := range importer.Find(srv.Block, "location") {
		if strings.Join(l.Args, " ") == "= "+StatusPath {
			loc = l
		}
	}
	if loc == nil {
		t.Fatalf("no status location in the default server:\n%s", def)
	}
	for name, want := range map[string]string{"allow": "127.0.0.1", "deny": "all", "access_log": "off", "error_page": "403 = @limen_closed"} {
		if got := values(loc.Block, name); len(got) == 0 || got[0] != want {
			t.Errorf("status location: %s = %v, want %s", name, got, want)
		}
	}
	if importer.First(loc.Block, "stub_status") == nil {
		t.Error("no stub_status")
	}
	// Everyone else gets what any unknown request gets: nothing.
	if !strings.Contains(def, "location @limen_closed {\n        return 444;") {
		t.Errorf("a denied client is not closed like an unknown one:\n%s", def)
	}

	in.Features.StubStatus = false
	if strings.Contains(file(t, render(t, in), "default.conf"), "stub_status") {
		t.Error("stub_status written for an nginx built without it")
	}
}

func TestThePanelIsRateLimited(t *testing.T) {
	in := baseInput(t)
	in.Features.LimitReq = true
	panel := proxyHost(PanelHost, "limen.example.com")
	panel.Protected = true
	other := proxyHost("app", "app.example.com")
	in.Hosts = []*model.ProxyHost{panel, other}
	out := render(t, in)

	http := file(t, out, "http.conf")
	for _, want := range []string{"limit_req_zone $binary_remote_addr zone=limen_panel:10m rate=10r/s;", "limit_req_zone $binary_remote_addr zone=limen_login:10m rate=30r/m;"} {
		if !strings.Contains(http, want) {
			t.Errorf("http.conf lacks %q", want)
		}
	}
	srv := importer.First(parsed(t, file(t, out, "hosts/"+PanelHost+".conf")), "server")
	if got := values(srv.Block, "limit_req"); len(got) != 1 || got[0] != "zone=limen_panel burst=50 nodelay" {
		t.Errorf("panel limit_req = %v", got)
	}
	var login *importer.Directive
	for _, l := range importer.Find(srv.Block, "location") {
		if strings.Join(l.Args, " ") == "= "+LoginPath {
			login = l
		}
	}
	if login == nil || !has(values(login.Block, "limit_req"), "zone=limen_login burst=10 nodelay") || len(values(login.Block, "proxy_pass")) != 1 {
		t.Errorf("the login has no limit of its own, or does not reach the panel")
	}
	if strings.Contains(file(t, out, "hosts/app.conf"), "limit_req") {
		t.Error("a host of the model got the panel's limits")
	}
	// A host that merely calls itself limen-panel is not the panel.
	fake := proxyHost(PanelHost, "fake.example.com")
	in.Hosts = []*model.ProxyHost{fake}
	if strings.Contains(file(t, render(t, in), "hosts/"+PanelHost+".conf"), "limit_req ") {
		t.Error("an unprotected host named like the panel got its limits")
	}
}
