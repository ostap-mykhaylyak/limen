package model

import (
	"reflect"
	"strings"
	"testing"
)

func TestSnippetIsReadTheWayNginxReadsIt(t *testing.T) {
	src := `
# a comment, and a # inside a word is not one
add_header X-Frame-Options "SAMEORIGIN" always;
proxy_set_header X-Id ${request_id}-a#b;
rewrite ^/old/(.*)$ /new/$1 permanent;
return 200 'it\'s "fine"';
sub_filter "a;b{c}" "x";
proxy_read_timeout
    120s;
`
	got, err := ParseSnippet(src)
	if err != nil {
		t.Fatal(err)
	}
	want := []Directive{
		{"add_header", []string{"X-Frame-Options", "SAMEORIGIN", "always"}},
		{"proxy_set_header", []string{"X-Id", "${request_id}-a#b"}},
		{"rewrite", []string{"^/old/(.*)$", "/new/$1", "permanent"}},
		{"return", []string{"200", `it's "fine"`}},
		{"sub_filter", []string{"a;b{c}", "x"}},
		{"proxy_read_timeout", []string{"120s"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestSnippetArgumentsKeepWhatNginxKeeps(t *testing.T) {
	got, err := ParseSnippet(`rewrite "^/a\.b$" /c last; sub_filter "a;b{c}" "x\\y";`)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Args[0] != `^/a\.b$` {
		t.Errorf(`\. must reach PCRE untouched: %q`, got[0].Args[0])
	}
	if got[1].Args[0] != "a;b{c}" || got[1].Args[1] != `x\y` {
		t.Errorf("quoted ; { } are data: %q", got[1].Args)
	}
}

func TestSnippetRefuses(t *testing.T) {
	cases := map[string]string{
		"a block":                        "location /x { return 404; }",
		"closing the enclosing block":    "} server { listen 8080; ",
		"a closing brace alone":          "return 404; }",
		"a closing brace as an argument": "return 200 };",
		"a file read":                    "include /etc/shadow;",
		"a log file written as root":     "access_log /etc/cron.d/x;",
		"an error log":                   "error_log /tmp/x;",
		"another backend":                "proxy_pass http://unix:/var/run/docker.sock:;",
		"serving files":                  "root /;",
		"opening access":                 "allow all;",
		"closing basic auth":             "auth_basic off;",
		"an unknown directive":           "frobnicate on;",
		"a missing semicolon":            "gzip on",
		"a lone semicolon":               ";",
		"too few arguments":              "add_header X-A;",
		"a bad header name":              "add_header X:A b;",
		"a third add_header argument":    "add_header X-A b never;",
		"a tab inside a value":           `return 200 "a\tb";`,
		"an unclosed quote":              `return 200 "abc;`,
		"text glued to a quote":          `return 200 "abc"def;`,
		"a module":                       "load_module x.so;",
		"a quoted name":                  `"gzip" on;`,
		"a directive that writes files":  "proxy_store on;",
		"on/off with something else":     "gzip yes;",
		"a brace after a word":           "gzip on{",
	}
	for name, src := range cases {
		if _, err := ParseSnippet(src); err == nil {
			t.Errorf("%s: %q accepted", name, src)
		}
	}
}

func TestSnippetRefusalsSayWhy(t *testing.T) {
	_, err := ParseSnippet("gzip on;\nallow 10.0.0.0/8;")
	if err == nil || !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), "access list") {
		t.Errorf("err = %v", err)
	}
}

func TestSnippetDirectivesAreKeyedByWhatTheySet(t *testing.T) {
	ds, err := ParseSnippet("proxy_set_header X-A 1; add_header x-a 2; rewrite ^ / last; proxy_read_timeout 5s;")
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{ds[0].Key(), ds[1].Key(), ds[2].Key(), ds[3].Key()}
	want := []string{"proxy_set_header x-a", "add_header x-a", "", "proxy_read_timeout"}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("keys %q, want %q", keys, want)
	}
}

func TestSnippetsHaveLimits(t *testing.T) {
	if _, err := ParseSnippet(strings.Repeat("gzip on;\n", 65)); err == nil {
		t.Error("65 directives accepted")
	}
	if _, err := ParseSnippet(strings.Repeat("#", 9000)); err == nil {
		t.Error("9000 bytes accepted")
	}
}

func TestLocations(t *testing.T) {
	base := func() *ProxyHost {
		h := NewProxyHost("app")
		h.Domains = []string{"app.example.com"}
		h.Forward = Upstream{Scheme: "http", Host: "10.0.0.5", Port: 8080}
		return h
	}
	ok := base()
	ok.Locations = []Location{
		{Path: "/api/", Forward: &Upstream{Scheme: "http", Host: "10.0.0.7", Port: 9000}, Websockets: true},
		{Path: "/admin/", AccessList: "office", Snippet: "client_max_body_size 1g;"},
		{Path: "/healthz", Exact: true, Public: true},
		{Path: "/", Exact: true, Snippet: "return 302 /app/;"},
	}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid host: %v", err)
	}
	if got := ok.AccessLists(); !reflect.DeepEqual(got, []string{"office"}) {
		t.Errorf("AccessLists = %v", got)
	}

	bad := map[string]Location{
		"a relative path":                {Path: "api/"},
		"a space in the path":            {Path: "/a b/"},
		"a brace in the path":            {Path: "/a{b}/"},
		"a quote in the path":            {Path: `/a"b/`},
		"the whole host":                 {Path: "/"},
		"the ACME challenges":            {Path: "/.well-known/acme-challenge/"},
		"public and guarded":             {Path: "/x/", Public: true, AccessList: "office"},
		"a socket":                       {Path: "/x/", Forward: &Upstream{Scheme: "http", Socket: "/var/run/docker.sock"}},
		"a bad backend":                  {Path: "/x/", Forward: &Upstream{Scheme: "ftp", Host: "a", Port: 1}},
		"a snippet that opens":           {Path: "/x/", Snippet: "allow all;"},
		"an access list name that walks": {Path: "/x/", AccessList: "../x"},
	}
	for name, l := range bad {
		h := base()
		h.Locations = []Location{l}
		if err := h.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	twice := base()
	twice.Locations = []Location{{Path: "/a/"}, {Path: "/a/"}}
	if err := twice.Validate(); err == nil {
		t.Error("the same location twice accepted")
	}
	both := base()
	both.Locations = []Location{{Path: "/a"}, {Path: "/a", Exact: true}}
	if err := both.Validate(); err != nil {
		t.Errorf("a prefix and an exact location on the same path: %v", err)
	}
}

func TestProxyOptions(t *testing.T) {
	h := NewProxyHost("app")
	h.Domains = []string{"app.example.com"}
	h.Forward = Upstream{Scheme: "http", Host: "10.0.0.5", Port: 8080}
	h.Proxy = ProxyOptions{
		ConnectTimeout: "5s", ReadTimeout: "1h", SendTimeout: "500ms",
		HostHeader:      "internal.local",
		RequestHeaders:  []Header{{"X-Request-Id", "$request_id"}},
		ResponseHeaders: []Header{{"X-Frame-Options", "DENY"}},
	}
	if err := h.Validate(); err != nil {
		t.Fatalf("valid options: %v", err)
	}
	bad := map[string]func(*ProxyOptions){
		"a timeout without a number": func(p *ProxyOptions) { p.ReadTimeout = "s" },
		"a timeout in weeks":         func(p *ProxyOptions) { p.ReadTimeout = "1w" },
		"a host header with a slash": func(p *ProxyOptions) { p.HostHeader = "a/b" },
		"Host as a request header":   func(p *ProxyOptions) { p.RequestHeaders = []Header{{"host", "x"}} },
		"a header twice":             func(p *ProxyOptions) { p.ResponseHeaders = []Header{{"X-A", "1"}, {"x-a", "2"}} },
		"a newline in a value":       func(p *ProxyOptions) { p.RequestHeaders = []Header{{"X-A", "1\r\nX-B: 2"}} },
		"a colon in a name":          func(p *ProxyOptions) { p.RequestHeaders = []Header{{"X-A:", "1"}} },
	}
	for name, mutate := range bad {
		c := Clone(h).(*ProxyHost)
		mutate(&c.Proxy)
		if err := c.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestStreamAccessListName(t *testing.T) {
	s := NewStream("pg")
	s.Listen, s.Forward = 5432, Endpoint{Host: "10.0.0.9", Port: 5432}
	s.AccessList = "../etc"
	if err := s.Validate(); err == nil {
		t.Error("a walking access list name accepted")
	}
}

func TestCloneCopiesLocations(t *testing.T) {
	h := NewProxyHost("app")
	h.Locations = []Location{{Path: "/a/", Forward: &Upstream{Scheme: "http", Host: "a", Port: 1}}}
	c := Clone(h).(*ProxyHost)
	c.Locations[0].Forward.Port = 2
	c.Locations[0].Path = "/b/"
	if h.Locations[0].Forward.Port != 1 || h.Locations[0].Path != "/a/" {
		t.Error("the clone shares its locations with the original")
	}
}
