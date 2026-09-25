package nginx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/config"
	"github.com/ostap-mykhaylyak/limen/internal/model"
)

const apr1Hash = "$apr1$Zq3.x9Ab$5rGuPlizGh.BXpJzPdKHt1"

var modern = Features{Version: [3]int{1, 30, 5}, Stream: true, HTTP2: true}

func baseInput(t *testing.T) Input {
	t.Helper()
	cfg := config.Default()
	cfg.Nginx.User = "nginx"
	return Input{
		Nginx:        cfg.Nginx,
		Panel:        cfg.Panel,
		CertsDir:     t.TempDir(),
		Features:     modern,
		Exclude:      map[Ref]string{},
		StreamModule: true,
	}
}

func proxyHost(name string, domains ...string) *model.ProxyHost {
	h := model.NewProxyHost(name)
	h.Domains = domains
	h.Forward = model.Upstream{Scheme: "http", Host: "10.0.0.5", Port: 8080}
	return h
}

func render(t *testing.T, in Input) *Output {
	t.Helper()
	out, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func file(t *testing.T, out *Output, path string) string {
	t.Helper()
	f, ok := out.Tree.Files[path]
	if !ok {
		t.Fatalf("%s was not rendered; files: %v", path, out.Tree.Paths())
	}
	return string(f.Data)
}

func skipped(out *Output, kind model.Kind, name string) string {
	for _, s := range out.Skipped {
		if s.Ref == (Ref{kind, name}) {
			return s.Reason
		}
	}
	return ""
}

// giveCert creates the files of a certificate for names, as the ACME
// manager does.
func giveCert(t *testing.T, in Input, name string, names ...string) {
	t.Helper()
	if len(names) == 0 {
		names = []string{"app.example.com"}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	dir := filepath.Join(in.CertsDir, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "fullchain.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(filepath.Join(dir, "privkey.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600)
}

// A renewed certificate lives at the same path: only its fingerprint in
// the tree tells the apply that nginx must reload, or nginx would serve
// the old one from memory until it expired.
func TestARenewedCertificateChangesTheTree(t *testing.T) {
	in := baseInput(t)
	h := proxyHost("app", "app.example.com")
	h.TLS = model.TLS{Certificate: "app", HTTP2: true}
	in.Hosts = []*model.ProxyHost{h}
	giveCert(t, in, "app")
	before := treeHash(render(t, in).Tree)
	giveCert(t, in, "app") // renewed: same names, same paths, new certificate
	if treeHash(render(t, in).Tree) == before {
		t.Fatal("a renewal did not change the rendered tree: nginx would never reload it")
	}
}

func TestACertificateThatDoesNotCoverTheHostIsReported(t *testing.T) {
	in := baseInput(t)
	h := proxyHost("app", "app.example.com", "www.app.example.com")
	h.TLS = model.TLS{Certificate: "app", HTTP2: true}
	in.Hosts = []*model.ProxyHost{h}
	giveCert(t, in, "app", "app.example.com")
	out := render(t, in)
	if !strings.Contains(strings.Join(out.Warnings, "\n"), "does not cover www.app.example.com") {
		t.Errorf("no warning about the uncovered name: %v", out.Warnings)
	}
}

// The same model must give the same bytes: that is how an apply knows
// nothing changed and leaves nginx alone.
func TestRenderingIsDeterministic(t *testing.T) {
	in := baseInput(t)
	in.Hosts = []*model.ProxyHost{proxyHost("b", "b.example.com"), proxyHost("a", "a.example.com")}
	first := treeHash(render(t, in).Tree)
	for range 5 {
		if got := treeHash(render(t, in).Tree); got != first {
			t.Fatal("two renderings of the same model differ")
		}
	}
}

func TestEveryIncludeIsRelative(t *testing.T) {
	in := baseInput(t)
	in.Hosts = []*model.ProxyHost{proxyHost("a", "a.example.com")}
	out := render(t, in)
	for _, p := range out.Tree.Paths() {
		for line := range strings.SplitSeq(string(out.Tree.Files[p].Data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "include /etc/nginx/limen") {
				t.Errorf("%s: %q points at the live tree: the candidate would be tested against it", p, line)
			}
		}
	}
	if !strings.Contains(file(t, out, "http.conf"), "include limen/hosts/a.conf;") {
		t.Errorf("http.conf does not include the host:\n%s", file(t, out, "http.conf"))
	}
}

func TestDisabledHostsAreNotRendered(t *testing.T) {
	in := baseInput(t)
	h := proxyHost("off", "off.example.com")
	h.Enabled = false
	in.Hosts = []*model.ProxyHost{h}
	out := render(t, in)
	if _, ok := out.Tree.Files["hosts/off.conf"]; ok {
		t.Error("a disabled host was rendered")
	}
	if strings.Contains(file(t, out, "http.conf"), "off.conf") {
		t.Error("a disabled host is included")
	}
}

// Without its guard, a guarded host is not served at all.
func TestHostWithoutItsAccessListFailsClosed(t *testing.T) {
	in := baseInput(t)
	h := proxyHost("admin", "admin.example.com")
	h.AccessList = "staff"
	in.Hosts = []*model.ProxyHost{h}
	out := render(t, in)
	if _, ok := out.Tree.Files["hosts/admin.conf"]; ok {
		t.Fatal("a host whose access list is missing was rendered")
	}
	if !strings.Contains(skipped(out, model.KindProxyHost, "admin"), "staff") {
		t.Errorf("skip reason = %q", skipped(out, model.KindProxyHost, "admin"))
	}

	// And an access list left out by nginx -t takes its hosts with it.
	a := model.NewAccessList("staff")
	a.Rules = []model.Rule{{Action: "allow", Address: "10.0.0.0/8"}}
	in.Access = []*model.AccessList{a}
	in.Exclude[Ref{model.KindAccessList, "staff"}] = "nginx -t: something"
	out = render(t, in)
	if _, ok := out.Tree.Files["hosts/admin.conf"]; ok {
		t.Error("a host whose access list was excluded was rendered")
	}
}

func TestAccessListKeepsOrderAndWritesHtpasswd(t *testing.T) {
	in := baseInput(t)
	a := model.NewAccessList("office")
	a.Rules = []model.Rule{{Action: "allow", Address: "192.168.1.0/24"}, {Action: "deny", Address: "192.168.1.66"}, {Action: "deny", Address: "all"}}
	a.Users = []model.BasicUser{{Username: "ops", Password: apr1Hash}}
	a.SatisfyAny = true
	h := proxyHost("admin", "admin.example.com")
	h.AccessList = "office"
	in.Access = []*model.AccessList{a}
	in.Hosts = []*model.ProxyHost{h}
	out := render(t, in)

	conf := file(t, out, "access/office.conf")
	iAllow := strings.Index(conf, "allow 192.168.1.0/24;")
	iDeny := strings.Index(conf, "deny 192.168.1.66;")
	iAll := strings.Index(conf, "deny all;")
	if iAllow < 0 || iDeny < iAllow || iAll < iDeny {
		t.Errorf("rules out of order — the first match wins in nginx:\n%s", conf)
	}
	if !strings.Contains(conf, "satisfy any;") || !strings.Contains(conf, "auth_basic_user_file limen/access/office.htpasswd;") {
		t.Errorf("access conf:\n%s", conf)
	}

	pw := out.Tree.Files["access/office.htpasswd"]
	if string(pw.Data) != "ops:"+apr1Hash+"\n" {
		t.Errorf("htpasswd = %q", pw.Data)
	}
	if pw.Mode != 0o640 || pw.Group != "nginx" {
		t.Errorf("htpasswd mode %o group %q: workers read it, nobody else should", pw.Mode, pw.Group)
	}

	host := file(t, out, "hosts/admin.conf")
	if !strings.Contains(host, "include limen/access/office.conf;") {
		t.Errorf("the host does not include its access list:\n%s", host)
	}
	if !strings.Contains(host, `proxy_set_header Authorization "";`) {
		t.Error("the gate's credentials are passed to the backend")
	}
}

// The CA must reach the challenge even on a guarded host, or its
// certificate could never be issued.
func TestAcmeChallengesBypassAccessLists(t *testing.T) {
	out := render(t, baseInput(t))
	acme := file(t, out, "snippets/acme.conf")
	for _, want := range []string{"location ^~ /.well-known/acme-challenge/", "allow all;", "auth_basic off;", "proxy_pass http://127.0.0.1:9187;"} {
		if !strings.Contains(acme, want) {
			t.Errorf("acme snippet is missing %q:\n%s", want, acme)
		}
	}
}

func TestTheClientCannotForgeForwardedFor(t *testing.T) {
	in := baseInput(t)
	in.Hosts = []*model.ProxyHost{proxyHost("app", "app.example.com")}
	proxy := file(t, render(t, in), "hosts/app.conf")
	if !strings.Contains(proxy, "proxy_set_header X-Forwarded-For $remote_addr;") {
		t.Error("X-Forwarded-For is not the client address")
	}
	if strings.Contains(proxy, "$proxy_add_x_forwarded_for") {
		t.Error("X-Forwarded-For appends to what the client sent")
	}
}

func TestMissingCertificateServesPlainHTTPAndSaysSo(t *testing.T) {
	in := baseInput(t)
	h := proxyHost("app", "app.example.com")
	h.TLS = model.TLS{Certificate: "app", ForceHTTPS: true, HTTP2: true}
	in.Hosts = []*model.ProxyHost{h}

	out := render(t, in)
	conf := file(t, out, "hosts/app.conf")
	if strings.Contains(conf, "443") || strings.Contains(conf, "return 301 https") {
		t.Errorf("without certificate files the host listens on 443 or redirects to it:\n%s", conf)
	}
	if !strings.Contains(strings.Join(out.Warnings, "\n"), `certificate "app"`) {
		t.Errorf("no warning about the missing certificate: %v", out.Warnings)
	}

	giveCert(t, in, "app")
	conf = file(t, render(t, in), "hosts/app.conf")
	for _, want := range []string{"listen 443 ssl;", "http2 on;", "ssl_certificate " + filepath.ToSlash(filepath.Join(in.CertsDir, "app", "fullchain.pem")), "return 301 https://$host$request_uri;"} {
		if !strings.Contains(conf, want) {
			t.Errorf("with the certificate, the host is missing %q:\n%s", want, conf)
		}
	}
}

// HTTP/2 moved from a listen parameter to a directive in 1.25.1; the
// wrong one is an [emerg] on the other side of that version.
func TestHTTP2FollowsTheNginxVersion(t *testing.T) {
	in := baseInput(t)
	h := proxyHost("app", "app.example.com")
	h.TLS = model.TLS{Certificate: "app", HTTP2: true}
	in.Hosts = []*model.ProxyHost{h}
	giveCert(t, in, "app")

	in.Features = Features{Version: [3]int{1, 22, 1}, HTTP2: true, Stream: true}
	old := file(t, render(t, in), "hosts/app.conf")
	if !strings.Contains(old, "listen 443 ssl http2;") || strings.Contains(old, "http2 on;") {
		t.Errorf("nginx 1.22 needs the listen parameter:\n%s", old)
	}

	in.Features = modern
	now := file(t, render(t, in), "hosts/app.conf")
	if strings.Contains(now, "ssl http2;") || !strings.Contains(now, "http2 on;") {
		t.Errorf("nginx 1.30 needs the directive:\n%s", now)
	}
}

func TestHSTSIsRepeatedWhereAddHeaderResetsIt(t *testing.T) {
	in := baseInput(t)
	h := proxyHost("app", "app.example.com")
	h.TLS = model.TLS{Certificate: "app", HSTS: true, HSTSSubdomains: true}
	h.CacheAssets = true
	in.Hosts = []*model.ProxyHost{h}
	giveCert(t, in, "app")
	conf := file(t, render(t, in), "hosts/app.conf")
	// The server, location / and the asset location nested in it.
	if n := strings.Count(conf, `Strict-Transport-Security "max-age=63072000; includeSubDomains" always`); n != 3 {
		t.Errorf("HSTS appears %d times, want 3 (server, location, asset location):\n%s", n, conf)
	}
}

// A value that would end a directive must never reach nginx: it would
// let one document write configuration for the whole machine.
func TestUnsafeValueSkipsOnlyItsDocument(t *testing.T) {
	in := baseInput(t)
	evil := proxyHost("evil", "evil.example.com")
	evil.Domains = []string{"evil.example.com; include /etc/shadow"}
	in.Hosts = []*model.ProxyHost{evil, proxyHost("good", "good.example.com")}
	out := render(t, in)
	if _, ok := out.Tree.Files["hosts/evil.conf"]; ok {
		t.Fatal("a value with ';' was written into the configuration")
	}
	if skipped(out, model.KindProxyHost, "evil") == "" {
		t.Error("the unsafe document is not reported")
	}
	if _, ok := out.Tree.Files["hosts/good.conf"]; !ok {
		t.Error("an unsafe document took a good one down with it")
	}
}

func TestStreamsNeedTheStreamModule(t *testing.T) {
	in := baseInput(t)
	s := model.NewStream("pg")
	s.Listen = 5432
	s.Forward = model.Endpoint{Host: "10.0.0.9", Port: 5432}
	s.Protocols = []string{"tcp", "udp"}
	in.Streams = []*model.Stream{s}

	out := render(t, in)
	st := file(t, out, "streams/pg.conf")
	if !strings.Contains(st, "listen 5432;") || !strings.Contains(st, "listen 5432 udp;") || !strings.Contains(st, "proxy_pass 10.0.0.9:5432;") {
		t.Errorf("stream:\n%s", st)
	}
	if !strings.Contains(file(t, out, "nginx.conf"), "include limen/streams/pg.conf;") {
		t.Error("nginx.conf has no stream block")
	}

	in.Features = Features{Version: [3]int{1, 30, 0}}
	out = render(t, in)
	if skipped(out, model.KindStream, "pg") == "" || strings.Contains(file(t, out, "nginx.conf"), "stream {") {
		t.Error("streams were rendered for an nginx without the stream module")
	}

	in.Features = Features{Version: [3]int{1, 22, 1}, Stream: true, StreamDynamic: true}
	in.StreamModule = false
	out = render(t, in)
	if !strings.Contains(skipped(out, model.KindStream, "pg"), "libnginx-mod-stream") {
		t.Errorf("a dynamic stream module that is not loaded was relied on: %v", out.Skipped)
	}
	if strings.Contains(file(t, out, "nginx.conf"), "stream {") {
		t.Error("nginx.conf has a stream block the module is not there for")
	}
}

// Debian builds stream as a dynamic module, loaded only when the
// libnginx-mod-stream package drops its loader in modules-enabled.
func TestStreamLoadableLooksForTheLoader(t *testing.T) {
	dir := t.TempDir()
	dyn := Features{Stream: true, StreamDynamic: true}
	pattern := filepath.Join(dir, "*.conf")
	if StreamLoadable(dyn, pattern) {
		t.Error("no loader, yet the module counts as loadable")
	}
	os.WriteFile(filepath.Join(dir, "50-mod-http-geoip.conf"), []byte("load_module modules/ngx_http_geoip_module.so;\n"), 0o644)
	if StreamLoadable(dyn, pattern) {
		t.Error("another module's loader counted as the stream one")
	}
	os.WriteFile(filepath.Join(dir, "50-mod-stream.conf"), []byte("load_module modules/ngx_stream_module.so;\n"), 0o644)
	if !StreamLoadable(dyn, pattern) {
		t.Error("the stream loader is there and was not seen")
	}
	if !StreamLoadable(Features{Stream: true}, "") {
		t.Error("a built-in stream module needs no loader")
	}
	if StreamLoadable(Features{}, pattern) {
		t.Error("an nginx without stream counted as having it")
	}
}

func TestIPv6ListensOnlyWhenAvailable(t *testing.T) {
	in := baseInput(t)
	in.Hosts = []*model.ProxyHost{proxyHost("a", "a.example.com")}
	if strings.Contains(file(t, render(t, in), "hosts/a.conf"), "[::]") {
		t.Error("IPv6 listen without IPv6")
	}
	in.IPv6 = true
	if !strings.Contains(file(t, render(t, in), "hosts/a.conf"), "listen [::]:80;") {
		t.Error("no IPv6 listen with IPv6")
	}
}

func TestMainConfLoadsTheDistributionModules(t *testing.T) {
	main := file(t, render(t, baseInput(t)), "nginx.conf")
	if !strings.HasPrefix(strings.SplitN(main, "include", 2)[1], " /etc/nginx/modules-enabled/*.conf;") {
		t.Errorf("the module loaders are not the first include:\n%s", main)
	}
	for _, want := range []string{"user nginx;", "pid /run/nginx.pid;", "include limen/http.conf;", "sites-enabled/ and conf.d/ are ignored"} {
		if !strings.Contains(main, want) {
			t.Errorf("nginx.conf is missing %q", want)
		}
	}
}

func TestRedirectTargets(t *testing.T) {
	in := baseInput(t)
	a := model.NewRedirect("a")
	a.Domains = []string{"old.example.com"}
	a.Target = model.Target{Scheme: "https", Domain: "new.example.com", PreservePath: true}
	b := model.NewRedirect("b")
	b.Domains = []string{"legacy.example.com"}
	b.Target = model.Target{Scheme: "auto", Domain: "new.example.com:8443"}
	b.Code = 302
	in.Redirects = []*model.Redirect{a, b}
	out := render(t, in)
	if !strings.Contains(file(t, out, "redirects/a.conf"), "return 301 https://new.example.com$request_uri;") {
		t.Errorf("a:\n%s", file(t, out, "redirects/a.conf"))
	}
	if !strings.Contains(file(t, out, "redirects/b.conf"), "return 302 $scheme://new.example.com:8443;") {
		t.Errorf("b:\n%s", file(t, out, "redirects/b.conf"))
	}
}

func TestParseFeatures(t *testing.T) {
	official := `nginx version: nginx/1.30.5
built by gcc 12.2.0
configure arguments: --prefix=/etc/nginx --user=nginx --with-http_v2_module --with-stream --with-stream_ssl_module`
	f, err := ParseFeatures(official)
	if err != nil {
		t.Fatal(err)
	}
	if f.Version != [3]int{1, 30, 5} || !f.Stream || f.StreamDynamic || !f.HTTP2 || f.BuildUser != "nginx" || !f.LimitReq {
		t.Errorf("official: %+v", f)
	}
	debian := `nginx version: nginx/1.22.1
configure arguments: --with-http_v2_module --with-stream=dynamic --with-stream_geoip_module=dynamic`
	if f, _ := ParseFeatures(official + " --without-http_limit_req_module"); f.LimitReq {
		t.Error("an nginx built without limit_req")
	}
	f, _ = ParseFeatures(debian)
	if !f.Stream || !f.StreamDynamic || f.HTTP2Directive() || !f.RejectHandshake() {
		t.Errorf("debian: %+v", f)
	}
}

func TestBlamePinsTheErrorOnItsDocument(t *testing.T) {
	gen := "/etc/nginx/limen.d/20260924T101500-0123456789ab"
	tree := Tree{
		Files: map[string]File{
			"hosts/app.conf": {Data: []byte("proxy_pass http://backend:8080;")},
			"hosts/web.conf": {Data: []byte("ssl_certificate /var/lib/limen/certs/web/fullchain.pem;")},
			"http.conf":      {Data: []byte("include limen/hosts/app.conf;")},
		},
		Owners: map[string]Ref{
			"hosts/app.conf": {model.KindProxyHost, "app"},
			"hosts/web.conf": {model.KindProxyHost, "web"},
		},
	}

	out := `nginx: [emerg] 3417#3417: host not found in upstream "backend:8080" in ` + gen + `/limen/hosts/app.conf:12
nginx: configuration file ` + gen + `/nginx.conf test failed`
	got := blame(out, gen, tree, "")
	if len(got) != 1 || got[Ref{model.KindProxyHost, "app"}] == "" {
		t.Errorf("by file and line: %v", got)
	}
	if reason := got[Ref{model.KindProxyHost, "app"}]; reason != `host not found in upstream "backend:8080"` {
		t.Errorf("reason = %q: nginx's pid and the file position are noise for a person", reason)
	}

	// A quoted word that only a comment carries pins nothing.
	tree.Files["streams/pg.conf"] = File{Data: []byte("# limen stream pg -> 10.0.0.9:5432\nserver {\n    listen 5432;\n}\n")}
	tree.Owners["streams/pg.conf"] = Ref{model.KindStream, "pg"}
	if got := blame(`nginx: [emerg] unknown directive "stream" in `+gen+`/nginx.conf:21`, gen, tree, ""); len(got) != 0 {
		t.Errorf("a comment took the blame: %v", got)
	}

	// Certificate errors come without a file: the quoted path finds the host.
	out = `nginx: [emerg] cannot load certificate "/var/lib/limen/certs/web/fullchain.pem": PEM_read_bio_X509_AUX() failed`
	got = blame(out, gen, tree, "")
	if len(got) != 1 || got[Ref{model.KindProxyHost, "web"}] == "" {
		t.Errorf("by quoted value: %v", got)
	}

	// An error in a shared file is nobody's: the apply must stop.
	out = `nginx: [emerg] unknown directive "bogus" in ` + gen + `/limen/http.conf:3`
	if got = blame(out, gen, tree, ""); len(got) != 0 {
		t.Errorf("a shared file was pinned on %v", got)
	}
}

func TestBlameBindFindsTheStream(t *testing.T) {
	s := model.NewStream("pg")
	s.Listen = 5432
	emerg := `2026/09/24 10:15:00 [emerg] 1#1: bind() to 0.0.0.0:5432 failed (98: Address already in use)`
	got := blameBind(emerg, []*model.Stream{s})
	if len(got) != 1 {
		t.Errorf("blameBind = %v", got)
	}
	if got := blameBind(`[emerg] 1#1: bind() to 0.0.0.0:80 failed (98: Address already in use)`, []*model.Stream{s}); len(got) != 0 {
		t.Errorf("port 80 was pinned on a stream: %v", got)
	}
}
