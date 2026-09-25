package model

import (
	"strings"
	"testing"
)

const (
	apr1Hash  = "$apr1$Zq3.x9Ab$5rGuPlizGh.BXpJzPdKHt1"
	panelHash = "pbkdf2-sha256$600000$c2FsdHNhbHRzYWx0$a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2U"
)

func validHost() *ProxyHost {
	h := NewProxyHost("app")
	h.Domains = []string{"app.example.com"}
	h.Forward = Upstream{Scheme: "http", Host: "10.0.0.5", Port: 8080}
	return h
}

// A hand-written file that says nothing about `enabled` must publish
// the host, not silently switch it off — the zero value of a bool
// would do exactly that without the defaults underneath.
func TestOmittedFieldsTakeTheirDefaults(t *testing.T) {
	doc, err := Decode(KindProxyHost, "app", []byte(`
kind: proxy_host
name: app
domains: [app.example.com]
forward: {host: 10.0.0.5, port: 8080}
`))
	if err != nil {
		t.Fatal(err)
	}
	h := doc.(*ProxyHost)
	if !h.Enabled {
		t.Error("a host without `enabled` was loaded disabled")
	}
	if h.Forward.Scheme != "http" {
		t.Errorf("forward.scheme = %q, want the default http", h.Forward.Scheme)
	}
	if !h.TLS.HTTP2 || !h.BlockExploits {
		t.Error("http2 and block_exploits are on by default")
	}
	if err := h.Validate(); err != nil {
		t.Errorf("a minimal hand-written host does not validate: %v", err)
	}
}

// "acess_list: staff" is a typo that would publish the host unguarded
// if it were quietly ignored.
func TestMisspelledFieldIsAnError(t *testing.T) {
	_, err := Decode(KindProxyHost, "app", []byte(`
kind: proxy_host
name: app
domains: [app.example.com]
forward: {host: 10.0.0.5, port: 8080}
acess_list: staff
`))
	if err == nil {
		t.Fatal("a misspelled field was accepted")
	}
	if !strings.Contains(err.Error(), "unknown field acess_list") {
		t.Errorf("error %q does not name the unknown field", err)
	}
	// The operator edits YAML, not Go: the message must not talk
	// about Go types.
	if strings.Contains(err.Error(), "model.") || strings.Contains(err.Error(), "\n") {
		t.Errorf("error %q is written for a programmer", err)
	}
}

func TestEmptyDocumentIsAllDefaults(t *testing.T) {
	doc, err := Decode(KindStream, "db", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !doc.(*Stream).Enabled {
		t.Error("an empty stream document is disabled")
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	h := validHost()
	h.TLS = TLS{Certificate: "app", ForceHTTPS: true, HTTP2: true, HSTS: true}
	h.Websockets = true
	b, err := Encode(h)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(b), "# limen proxy host") {
		t.Errorf("the file does not start with its header:\n%s", b)
	}
	back, err := Decode(KindProxyHost, "app", b)
	if err != nil {
		t.Fatalf("limen cannot read what it writes: %v\n%s", err, b)
	}
	got := back.(*ProxyHost)
	if got.Forward != h.Forward || got.TLS != h.TLS || !got.Websockets {
		t.Errorf("round trip lost data:\nwrote %+v\nread  %+v", h, got)
	}
}

// The name is also a file name: nothing may walk out of the directory
// or hide from a listing.
func TestNamesCannotEscapeTheirDirectory(t *testing.T) {
	for _, bad := range []string{"", "../etc", "a/b", `a\b`, ".hidden", "a..b", "UPPER", "trailing-", "-leading", "white space", strings.Repeat("a", 65)} {
		if err := ValidateName(bad); err == nil {
			t.Errorf("name %q was accepted", bad)
		}
	}
	for _, good := range []string{"a", "app", "app.example.com", "my_host-2", strings.Repeat("a", 64)} {
		if err := ValidateName(good); err != nil {
			t.Errorf("name %q was refused: %v", good, err)
		}
	}
}

func TestDomainRules(t *testing.T) {
	for _, bad := range []string{"localhost", "App.example.com", "*.*.example.com", "a.*.example.com", "-a.example.com", "a..example.com", "exa mple.com", "*"} {
		if err := ValidateDomain(bad); err == nil {
			t.Errorf("domain %q was accepted", bad)
		}
	}
	for _, good := range []string{"example.com", "*.example.com", "a-b.c.example.co.uk", "xn--bcher-kva.example"} {
		if err := ValidateDomain(good); err != nil {
			t.Errorf("domain %q was refused: %v", good, err)
		}
	}
}

// Forcing HTTPS without a certificate renders a host that redirects to
// a port nothing answers on.
func TestHTTPSOptionsNeedACertificate(t *testing.T) {
	h := validHost()
	h.TLS.ForceHTTPS = true
	if err := h.Validate(); err == nil {
		t.Error("force_https without a certificate was accepted")
	}
	h = validHost()
	h.TLS.HSTS = true
	if err := h.Validate(); err == nil {
		t.Error("hsts without a certificate was accepted")
	}
	h = validHost()
	h.TLS = TLS{Certificate: "app", HSTSSubdomains: true}
	if err := h.Validate(); err == nil {
		t.Error("hsts_subdomains without hsts was accepted")
	}
}

func TestProtectedHostCannotBeDisabled(t *testing.T) {
	h := validHost()
	h.Protected = true
	h.Enabled = false
	if err := h.Validate(); err == nil {
		t.Error("a protected host was disabled")
	}
}

func TestRedirectToItselfIsRefused(t *testing.T) {
	r := NewRedirect("old")
	r.Domains = []string{"old.example.com"}
	r.Target.Domain = "old.example.com"
	if err := r.Validate(); err == nil {
		t.Error("a redirect to its own domain was accepted: an infinite loop")
	}
	r.Target.Domain = "new.example.com:8443"
	if err := r.Validate(); err != nil {
		t.Errorf("a redirect with a port was refused: %v", err)
	}
	r.Code = 303
	if err := r.Validate(); err == nil {
		t.Error("an unsupported redirect code was accepted")
	}
}

func TestStreamRules(t *testing.T) {
	s := NewStream("db")
	s.Listen = 5432
	s.Forward = Endpoint{Host: "10.0.0.9", Port: 5432}
	if err := s.Validate(); err != nil {
		t.Fatalf("a valid stream was refused: %v", err)
	}
	for _, port := range []int{0, 80, 443, 70000} {
		s.Listen = port
		if err := s.Validate(); err == nil {
			t.Errorf("listen_port %d was accepted", port)
		}
	}
	s.Listen = 5432
	s.Protocols = []string{"tcp", "tcp"}
	if err := s.Validate(); err == nil {
		t.Error("a protocol listed twice was accepted")
	}
	s.Protocols = []string{"sctp"}
	if err := s.Validate(); err == nil {
		t.Error("an unknown protocol was accepted")
	}
}

func TestAccessListRules(t *testing.T) {
	a := NewAccessList("staff")
	if err := a.Validate(); err == nil {
		t.Error("an empty access list was accepted: it would guard nothing")
	}
	a.Rules = []Rule{{Action: "allow", Address: "10.0.0.0/8"}, {Action: "deny", Address: "all"}}
	if err := a.Validate(); err != nil {
		t.Errorf("a valid rule set was refused: %v", err)
	}
	a.Users = []BasicUser{{Username: "ops", Password: "plaintext"}}
	if err := a.Validate(); err == nil {
		t.Error("a plaintext password was accepted in an access list")
	}
	// A colon or a newline in a username would corrupt the htpasswd
	// file nginx reads.
	a.Users = []BasicUser{{Username: "ops:root", Password: apr1Hash}}
	if err := a.Validate(); err == nil {
		t.Error("a username with a colon was accepted")
	}
	a.Users = []BasicUser{{Username: "ops", Password: apr1Hash}}
	a.Rules = []Rule{{Action: "permit", Address: "10.0.0.0/8"}}
	if err := a.Validate(); err == nil {
		t.Error("an unknown rule action was accepted")
	}
}

func TestUserRules(t *testing.T) {
	u := NewUser("ostap")
	u.Role = RoleAdmin
	u.Password = panelHash
	if err := u.Validate(); err != nil {
		t.Fatalf("a valid user was refused: %v", err)
	}
	u.Password = "hunter2"
	if err := u.Validate(); err == nil {
		t.Error("a plaintext panel password was accepted")
	}
	u.Password = panelHash
	u.Role = "root"
	if err := u.Validate(); err == nil {
		t.Error("an unknown role was accepted")
	}
}

func TestParseUpstream(t *testing.T) {
	cases := []struct {
		in   string
		want Upstream
	}{
		{"http://10.0.0.5:8080", Upstream{Scheme: "http", Host: "10.0.0.5", Port: 8080}},
		{"https://backend", Upstream{Scheme: "https", Host: "backend", Port: 443}},
		{"app:3000", Upstream{Scheme: "http", Host: "app", Port: 3000}},
		{"http://[fd00::5]:8080", Upstream{Scheme: "http", Host: "fd00::5", Port: 8080}},
	}
	for _, c := range cases {
		got, err := ParseUpstream(c.in)
		if err != nil {
			t.Errorf("ParseUpstream(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseUpstream(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
	for _, bad := range []string{"ftp://x:21", "http://x:0", "http://x/path", "http://user:pw@x"} {
		if _, err := ParseUpstream(bad); err == nil {
			t.Errorf("ParseUpstream(%q) was accepted", bad)
		}
	}
}

// Clone must not share slices: a caller appending a domain to its copy
// would otherwise change what the store serves.
func TestCloneIsDeep(t *testing.T) {
	h := validHost()
	c := Clone(h).(*ProxyHost)
	c.Domains[0] = "changed.example.com"
	if h.Domains[0] != "app.example.com" {
		t.Error("the clone shares its domains with the original")
	}
}
