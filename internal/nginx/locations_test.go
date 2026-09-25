package nginx

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ostap-mykhaylyak/limen/internal/importer"
	"github.com/ostap-mykhaylyak/limen/internal/model"
)

// parsed reads a rendered file back the way nginx would, to check its
// structure rather than its text.
func parsed(t *testing.T, conf string) []*importer.Directive {
	t.Helper()
	path := filepath.Join(t.TempDir(), "x.conf")
	if err := os.WriteFile(path, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	var p importer.Parser
	ds, err := p.ParseFile(path)
	if err != nil {
		t.Fatalf("the rendered file does not parse: %v\n%s", err, conf)
	}
	return ds
}

// location finds a location block of the first server by its arguments.
func location(t *testing.T, ds []*importer.Directive, args ...string) *importer.Directive {
	t.Helper()
	server := importer.First(ds, "server")
	for _, l := range importer.Find(server.Block, "location") {
		if strings.Join(l.Args, " ") == strings.Join(args, " ") {
			return l
		}
	}
	t.Fatalf("no location %q", args)
	return nil
}

// values returns the arguments of every directive with that name, one
// string each.
func values(ds []*importer.Directive, name string) []string {
	var out []string
	for _, d := range importer.Find(ds, name) {
		out = append(out, strings.Join(d.Args, " "))
	}
	return out
}

// section returns a block of the text, from its first line to the
// brace that closes it at the same indentation.
func section(conf, first string) string {
	i := strings.Index(conf, first)
	if i < 0 {
		return ""
	}
	lineStart := strings.LastIndex(conf[:i], "\n") + 1
	indent := conf[lineStart:i]
	end := strings.Index(conf[i:], "\n"+indent+"}\n")
	if end < 0 {
		return conf[i:]
	}
	return conf[i : i+end]
}

func has(list []string, want string) bool {
	return slices.Contains(list, want)
}

func TestCustomLocations(t *testing.T) {
	in := baseInput(t)
	h := proxyHost("app", "app.example.com")
	h.CacheAssets = true
	h.Websockets = true
	h.Locations = []model.Location{
		{Path: "/api/", Forward: &model.Upstream{Scheme: "http", Host: "10.0.0.7", Port: 9000}},
		{Path: "/health", Exact: true},
	}
	in.Hosts = []*model.ProxyHost{h}
	ds := parsed(t, file(t, render(t, in), "hosts/app.conf"))

	api := location(t, ds, "/api/")
	if got := values(api.Block, "proxy_pass"); !has(got, "http://10.0.0.7:9000") {
		t.Errorf("/api/ proxies to %v", got)
	}
	// A stylesheet under /api/ belongs to /api/'s backend.
	nested := importer.First(api.Block, "location")
	if nested == nil || !has(values(nested.Block, "proxy_pass"), "http://10.0.0.7:9000") {
		t.Errorf("/api/ has no asset location of its own going to its backend")
	}
	if has(values(api.Block, "proxy_set_header"), "Upgrade $http_upgrade") {
		t.Error("the location took the host's websockets without asking")
	}

	health := location(t, ds, "=", "/health")
	if !has(values(health.Block, "proxy_pass"), "http://10.0.0.5:8080") {
		t.Error("a location without a forward does not go to the host's backend")
	}
	if importer.First(health.Block, "location") != nil {
		t.Error("an exact location has a nested one")
	}
	root := location(t, ds, "/")
	if !has(values(root.Block, "proxy_set_header"), "Upgrade $http_upgrade") {
		t.Error("the host's websockets are gone from location /")
	}
}

func TestLocationGuards(t *testing.T) {
	in := baseInput(t)
	staff := model.NewAccessList("staff")
	staff.Users = []model.BasicUser{{Username: "ops", Password: apr1Hash}}
	office := model.NewAccessList("office")
	office.Rules = []model.Rule{{Action: "allow", Address: "10.0.0.0/8"}, {Action: "deny", Address: "all"}}
	in.Access = []*model.AccessList{staff, office}

	h := proxyHost("app", "app.example.com")
	h.AccessList = "staff"
	h.Locations = []model.Location{
		{Path: "/hooks/", Public: true},
		{Path: "/admin/", AccessList: "office"},
		{Path: "/docs/"},
	}
	in.Hosts = []*model.ProxyHost{h}
	out := render(t, in)
	ds := parsed(t, file(t, out, "hosts/app.conf"))

	hooks := location(t, ds, "/hooks/")
	for _, want := range []string{"satisfy all", "allow all", "auth_basic off"} {
		name, arg, _ := strings.Cut(want, " ")
		if !has(values(hooks.Block, name), arg) {
			t.Errorf("the public location does not say %q", want)
		}
	}
	// The parser inlines includes: look at the text for those.
	conf := file(t, out, "hosts/app.conf")
	admin := location(t, ds, "/admin/")
	if !strings.Contains(section(conf, `location "/admin/" {`), "include limen/access/office.conf;") {
		t.Error("the location does not include its own list")
	}
	// office has no users: the backend may see the client's own
	// Authorization, and the file switches the server's passwords off.
	if has(values(admin.Block, "proxy_set_header"), "Authorization ") {
		t.Error("Authorization stripped where no password is asked")
	}
	docs := location(t, ds, "/docs/")
	if strings.Contains(section(conf, `location "/docs/" {`), "include") {
		t.Error("an inheriting location includes a list of its own")
	}
	if !has(values(docs.Block, "proxy_set_header"), "Authorization ") {
		t.Error("the host's credentials reach the backend of an inheriting location")
	}

	// Each file is complete: included in a location, it overrides all
	// that the location would inherit from its server.
	rulesOnly := parsed(t, file(t, out, "access/office.conf"))
	if !has(values(rulesOnly, "auth_basic"), "off") || !has(values(rulesOnly, "satisfy"), "all") {
		t.Errorf("a list of rules does not switch the server's passwords off")
	}
	usersOnly := parsed(t, file(t, out, "access/staff.conf"))
	if !has(values(usersOnly, "allow"), "all") || !has(values(usersOnly, "satisfy"), "all") {
		t.Errorf("a list of users does not reset the server's rules")
	}
}

func TestSatisfyAnyOnlyWithBothHalves(t *testing.T) {
	in := baseInput(t)
	a := model.NewAccessList("staff")
	a.Users = []model.BasicUser{{Username: "ops", Password: apr1Hash}}
	a.SatisfyAny = true // meaningless without rules; must not become "any"
	in.Access = []*model.AccessList{a}
	conf := file(t, render(t, in), "access/staff.conf")
	if strings.Contains(conf, "satisfy any") {
		t.Errorf("satisfy any with allow all lets everybody in:\n%s", conf)
	}
}

func TestALocationWithoutItsListFailsClosed(t *testing.T) {
	in := baseInput(t)
	h := proxyHost("app", "app.example.com")
	h.Locations = []model.Location{{Path: "/admin/", AccessList: "office"}}
	in.Hosts = []*model.ProxyHost{h}
	out := render(t, in)
	if _, ok := out.Tree.Files["hosts/app.conf"]; ok {
		t.Error("the host is served while one of its locations has lost its guard")
	}
	if !strings.Contains(skipped(out, model.KindProxyHost, "app"), "office") {
		t.Errorf("skip reason: %q", skipped(out, model.KindProxyHost, "app"))
	}
}

func TestSnippetsOverrideTheDefaultsAndStayInTheirBlock(t *testing.T) {
	in := baseInput(t)
	h := proxyHost("app", "app.example.com")
	h.Snippet = "proxy_read_timeout 1h;\nadd_header X-Host host;\nproxy_set_header Host $proxy_host;"
	h.Locations = []model.Location{{
		Path:    "/escape/",
		Snippet: `proxy_read_timeout 5s; add_header x-host location; return 200 "a;} server { listen 8080; \"";`,
	}}
	in.Hosts = []*model.ProxyHost{h}
	ds := parsed(t, file(t, render(t, in), "hosts/app.conf"))

	if n := len(importer.Find(ds, "server")); n != 1 {
		t.Fatalf("%d server blocks: the snippet broke out of its block", n)
	}
	root := location(t, ds, "/")
	if got := values(root.Block, "proxy_read_timeout"); len(got) != 1 || got[0] != "1h" {
		t.Errorf("location / read timeouts = %v, want only the host snippet's", got)
	}
	if got := values(root.Block, "proxy_set_header"); has(got, "Host $host") || !has(got, "Host $proxy_host") {
		t.Errorf("the snippet's Host did not replace limen's: %v", got)
	}

	esc := location(t, ds, "/escape/")
	if got := values(esc.Block, "proxy_read_timeout"); len(got) != 1 || got[0] != "5s" {
		t.Errorf("/escape/ read timeouts = %v, want only the location snippet's", got)
	}
	if got := values(esc.Block, "add_header"); len(got) != 1 || got[0] != "x-host location" {
		t.Errorf("/escape/ headers = %v: the location's must replace the host's, case aside", got)
	}
	if got := values(esc.Block, "return"); len(got) != 1 || got[0] != `200 a;} server { listen 8080; "` {
		t.Errorf("return = %q: the argument was not kept whole", got)
	}
}

func TestProxyOptionsReachEveryLocation(t *testing.T) {
	in := baseInput(t)
	h := proxyHost("app", "app.example.com")
	h.TLS = model.TLS{Certificate: "app", HSTS: true}
	giveCert(t, in, "app")
	h.Proxy = model.ProxyOptions{
		ConnectTimeout: "5s", ReadTimeout: "1h",
		StreamResponses: true, StreamRequests: true,
		HostHeader:      model.HostHeaderUpstream,
		RequestHeaders:  []model.Header{{Name: "X-Request-Id", Value: "$request_id"}},
		ResponseHeaders: []model.Header{{Name: "X-Frame-Options", Value: `DENY"; evil on; #`}},
	}
	h.Locations = []model.Location{{Path: "/api/"}}
	in.Hosts = []*model.ProxyHost{h}
	ds := parsed(t, file(t, render(t, in), "hosts/app.conf"))
	tls := importer.Find(ds, "server")[1]

	for _, path := range []string{"/api/", "/"} {
		var loc *importer.Directive
		for _, l := range importer.Find(tls.Block, "location") {
			if l.Arg(0) == path {
				loc = l
			}
		}
		for name, want := range map[string]string{
			"proxy_connect_timeout":   "5s",
			"proxy_read_timeout":      "1h",
			"proxy_send_timeout":      "300s",
			"proxy_buffering":         "off",
			"proxy_request_buffering": "off",
		} {
			if got := values(loc.Block, name); len(got) != 1 || got[0] != want {
				t.Errorf("%s: %s = %v, want %s", path, name, got, want)
			}
		}
		headers := values(loc.Block, "proxy_set_header")
		if !has(headers, "Host $proxy_host") || !has(headers, "X-Request-Id $request_id") {
			t.Errorf("%s: request headers %v", path, headers)
		}
		added := values(loc.Block, "add_header")
		if !has(added, `X-Frame-Options DENY"; evil on; # always`) {
			t.Errorf("%s: response headers %v: the value was not kept whole", path, added)
		}
		if !has(added, "Strict-Transport-Security max-age=63072000 always") {
			t.Errorf("%s: HSTS lost where add_header resets it: %v", path, added)
		}
	}
}

func TestStreamGuards(t *testing.T) {
	in := baseInput(t)
	office := model.NewAccessList("office")
	office.Rules = []model.Rule{{Action: "allow", Address: "10.0.0.0/8"}, {Action: "deny", Address: "all"}}
	// Rules and users: its rules alone would render, and drop the
	// password half of the guard.
	gate := model.NewAccessList("gate")
	gate.Users = []model.BasicUser{{Username: "ops", Password: apr1Hash}}
	gate.Rules = office.Rules
	in.Access = []*model.AccessList{office, gate}

	pg := model.NewStream("pg")
	pg.Listen, pg.Forward, pg.AccessList = 5432, model.Endpoint{Host: "10.0.0.9", Port: 5432}, "office"
	redis := model.NewStream("redis")
	redis.Listen, redis.Forward, redis.AccessList = 6379, model.Endpoint{Host: "10.0.0.9", Port: 6379}, "gate"
	lost := model.NewStream("lost")
	lost.Listen, lost.Forward, lost.AccessList = 6380, model.Endpoint{Host: "10.0.0.9", Port: 6380}, "missing"
	in.Streams = []*model.Stream{pg, redis, lost}
	out := render(t, in)

	conf := file(t, out, "streams/pg.conf")
	iAllow, iDeny, iPass := strings.Index(conf, "allow 10.0.0.0/8;"), strings.Index(conf, "deny all;"), strings.Index(conf, "proxy_pass")
	if iAllow < 0 || iDeny < iAllow || iPass < iDeny {
		t.Errorf("stream rules missing or out of order:\n%s", conf)
	}
	for _, name := range []string{"redis", "lost"} {
		if _, ok := out.Tree.Files["streams/"+name+".conf"]; ok {
			t.Errorf("stream %s is served without its guard", name)
		}
		if skipped(out, model.KindStream, name) == "" {
			t.Errorf("stream %s: no reason given", name)
		}
	}
}
