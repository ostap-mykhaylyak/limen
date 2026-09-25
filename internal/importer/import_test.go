package importer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ostap-mykhaylyak/limen/internal/model"
)

const apr1Hash = "$apr1$Zq3.x9Ab$5rGuPlizGh.BXpJzPdKHt1"

// backup lays out a copy of /etc/nginx the way `limen --init` saves it,
// and returns the rebasing an import of it uses.
func backup(t *testing.T, files map[string]string) (string, func(string) string) {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rebase := func(p string) string {
		if rest, ok := strings.CutPrefix(p, "/etc/nginx/"); ok {
			return filepath.Join(root, filepath.FromSlash(rest))
		}
		return p
	}
	return root, rebase
}

func plan(t *testing.T, files map[string]string) *Plan {
	t.Helper()
	root, rebase := backup(t, files)
	p := &Parser{Rebase: rebase}
	top, err := p.ParseFile(filepath.Join(root, "nginx.conf"))
	if err != nil {
		t.Fatal(err)
	}
	return Build(top, Options{
		Exists:   func(model.Kind, string) bool { return false },
		ReadFile: func(path string) ([]byte, error) { return os.ReadFile(rebase(path)) },
	})
}

const debianMain = `user www-data;
worker_processes auto;
include /etc/nginx/modules-enabled/*.conf;
events { worker_connections 768; }
http {
    include /etc/nginx/mime.types;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
`

func find[T model.Document](p *Plan, name string) (T, bool) {
	var zero T
	for _, d := range p.Docs {
		if v, ok := d.(T); ok && d.Header().Name == name {
			return v, true
		}
	}
	return zero, false
}

func skippedAbout(p *Plan, needle string) string {
	for _, s := range p.Skipped {
		if strings.Contains(s, needle) {
			return s
		}
	}
	return ""
}

// The configuration certbot leaves behind: a TLS server that proxies,
// and a plain one made of `if ($host = ...)` redirects.
func TestCertbotSiteBecomesOneHostWithForcedHTTPS(t *testing.T) {
	p := plan(t, map[string]string{
		"nginx.conf": debianMain,
		"sites-enabled/app": `
server {
    server_name app.example.com www.app.example.com;
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    listen 443 ssl http2; # managed by Certbot
    ssl_certificate /etc/letsencrypt/live/app.example.com/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/app.example.com/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot
}
server {
    if ($host = www.app.example.com) {
        return 301 https://$host$request_uri;
    } # managed by Certbot
    if ($host = app.example.com) {
        return 301 https://$host$request_uri;
    } # managed by Certbot
    listen 80;
    server_name app.example.com www.app.example.com;
    return 404; # managed by Certbot
}
`,
	})
	h, ok := find[*model.ProxyHost](p, "app.example.com")
	if !ok {
		t.Fatalf("the host was not imported; skipped: %v", p.Skipped)
	}
	if h.Forward != (model.Upstream{Scheme: "http", Host: "127.0.0.1", Port: 3000}) || !h.Websockets {
		t.Errorf("host = %+v", h)
	}
	if h.TLS.Certificate != "app.example.com" || !h.TLS.ForceHTTPS || !h.TLS.HTTP2 {
		t.Errorf("tls = %+v", h.TLS)
	}
	if len(p.Certs) != 1 || p.Certs[0].Chain != "/etc/letsencrypt/live/app.example.com/fullchain.pem" {
		t.Errorf("certificates to copy = %+v", p.Certs)
	}
	// The host refers to a certificate of the model, which comes before
	// it in the plan: it is uploaded, so limen watches its expiry and
	// takes renewals over only when told to.
	c, ok := find[*model.Certificate](p, "app.example.com")
	if !ok || c.Provider != model.ProviderCustom {
		t.Fatalf("no custom certificate document in the plan: %v", p.Docs)
	}
	for i, d := range p.Docs {
		if d == model.Document(h) {
			for _, e := range p.Docs[i:] {
				if e == model.Document(c) {
					t.Error("the certificate comes after the host that refers to it")
				}
			}
		}
	}
	// The options file is not in the backup: said, not fatal.
	if len(p.Skipped) != 0 {
		t.Errorf("nothing should be skipped: %v", p.Skipped)
	}
}

func TestPlainProxyAndRedirect(t *testing.T) {
	p := plan(t, map[string]string{
		"nginx.conf": debianMain,
		"sites-enabled/api": `
upstream api_backend { server 10.0.0.6:9000; }
server {
    listen 80;
    server_name api.example.com;
    client_max_body_size 50m;
    gzip on;
    location / { proxy_pass http://api_backend; proxy_read_timeout 90; }
}
server {
    listen 80;
    server_name old.example.com;
    return 308 https://new.example.com$request_uri;
}
`,
	})
	h, ok := find[*model.ProxyHost](p, "api.example.com")
	if !ok {
		t.Fatalf("api not imported: %v", p.Skipped)
	}
	if h.Forward.Host != "10.0.0.6" || h.Forward.Port != 9000 || h.ClientMaxBodySize != "50m" {
		t.Errorf("api = %+v (the single-server upstream should resolve)", h)
	}
	if !strings.Contains(strings.Join(p.Notes, "\n"), "gzip") {
		t.Errorf("dropped directives are not reported: %v", p.Notes)
	}

	r, ok := find[*model.Redirect](p, "old.example.com")
	if !ok {
		t.Fatalf("redirect not imported: %v", p.Skipped)
	}
	if r.Code != 308 || r.Target != (model.Target{Scheme: "https", Domain: "new.example.com", PreservePath: true}) {
		t.Errorf("redirect = %+v", r)
	}
}

func TestBasicAuthIsImportedWithItsUsers(t *testing.T) {
	p := plan(t, map[string]string{
		"nginx.conf": debianMain,
		"htpasswd":   "ops:" + apr1Hash + "\n# a comment\ndev:" + apr1Hash + ":Dev Team\n",
		"sites-enabled/admin": `
server {
    listen 80;
    server_name admin.example.com;
    satisfy any;
    allow 10.0.0.0/8;
    deny all;
    auth_basic "Admin";
    auth_basic_user_file /etc/nginx/htpasswd;
    location / { proxy_pass http://127.0.0.1:8081; }
}
`,
	})
	h, ok := find[*model.ProxyHost](p, "admin.example.com")
	if !ok {
		t.Fatalf("not imported: %v", p.Skipped)
	}
	a, ok := find[*model.AccessList](p, h.AccessList)
	if !ok {
		t.Fatalf("the host refers to %q, which is not in the plan", h.AccessList)
	}
	if len(a.Users) != 2 || a.Users[1].Username != "dev" || !a.SatisfyAny || !a.PassAuth {
		t.Errorf("access list = %+v", a)
	}
	if len(a.Rules) != 2 || a.Rules[0] != (model.Rule{Action: "allow", Address: "10.0.0.0/8"}) {
		t.Errorf("rules = %+v", a.Rules)
	}
}

// A guard limen cannot keep must keep the host out, not let it in open.
func TestUnkeepableGuardsFailClosed(t *testing.T) {
	p := plan(t, map[string]string{
		"nginx.conf": debianMain,
		"htpasswd":   "ops:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\n",
		"sites-enabled/guarded": `
server {
    listen 80;
    server_name sha.example.com;
    auth_basic "x";
    auth_basic_user_file /etc/nginx/htpasswd;
    location / { proxy_pass http://127.0.0.1:1; }
}
server {
    listen 80;
    server_name sso.example.com;
    location / { auth_request /auth; proxy_pass http://127.0.0.1:2; }
}
server {
    listen 80;
    server_name missing.example.com;
    auth_basic "x";
    auth_basic_user_file /etc/nginx/nowhere;
    location / { proxy_pass http://127.0.0.1:3; }
}
server {
    listen 80;
    server_name iffy.example.com;
    if ($http_x_token != "secret") { return 403; }
    location / { proxy_pass http://127.0.0.1:4; }
}
`,
	})
	for _, name := range []string{"sha.example.com", "sso.example.com", "missing.example.com", "iffy.example.com"} {
		if _, ok := find[*model.ProxyHost](p, name); ok {
			t.Errorf("%s was imported without its guard", name)
		}
		if skippedAbout(p, name) == "" {
			t.Errorf("%s is not reported as skipped: %v", name, p.Skipped)
		}
	}
	// The model would refuse the {SHA} hash too, but only the importer
	// can tell the operator what to do about it.
	if reason := skippedAbout(p, "sha.example.com"); !strings.Contains(reason, "limen access passwd") {
		t.Errorf("the {SHA} user's reason does not say how to fix it: %s", reason)
	}
}

func TestWhatLimenCannotSayIsSkippedWithTheLine(t *testing.T) {
	p := plan(t, map[string]string{
		"nginx.conf": debianMain,
		"sites-enabled/other": `
server {
    listen 80;
    server_name php.example.com;
    root /var/www/php;
    location ~ \.php$ { fastcgi_pass unix:/run/php/php-fpm.sock; }
}
server {
    listen 80;
    server_name split.example.com;
    location / { proxy_pass http://127.0.0.1:1; }
    location /static/ { root /var/www; }
}
server {
    listen 80;
    server_name guard.example.com;
    location / { proxy_pass http://127.0.0.1:1; }
    location /admin/ { allow 10.0.0.0/8; deny all; proxy_pass http://127.0.0.1:2; }
}
server {
    listen 80;
    server_name path.example.com;
    location / { proxy_pass http://127.0.0.1:1/app/; }
}
server {
    listen 80;
    server_name lb.example.com;
    location / { proxy_pass http://pool; }
}
upstream pool { server 10.0.0.1:80; server 10.0.0.2:80; }
server {
    listen 8080;
    server_name alt.example.com;
    location / { proxy_pass http://127.0.0.1:1; }
}
server {
    listen 80;
    server_name ~^(?<sub>.+)\.example\.com$;
    location / { proxy_pass http://127.0.0.1:1; }
}
server {
    listen 80 default_server;
    server_name _;
    return 444;
}
`,
	})
	if len(p.Docs) != 0 {
		t.Errorf("something was imported: %v", p.Docs)
	}
	for _, needle := range []string{"php.example.com", "split.example.com", "guard.example.com", "path.example.com", "lb.example.com", "alt.example.com", "regular expression"} {
		s := skippedAbout(p, needle)
		if s == "" {
			t.Errorf("no skip reason mentions %q: %v", needle, p.Skipped)
			continue
		}
		if !strings.Contains(s, "sites-enabled") || !strings.Contains(s, ":") {
			t.Errorf("the reason does not say where: %s", s)
		}
	}
	if !strings.Contains(strings.Join(p.Notes, "\n"), "default server") {
		t.Errorf("the default server is not mentioned: %v", p.Notes)
	}
}

func TestStreams(t *testing.T) {
	p := plan(t, map[string]string{
		"nginx.conf": `events {}
stream {
    upstream pg { server 10.0.0.9:5432; }
    server { listen 5432; proxy_pass pg; }
    server { listen 53 udp; listen 53; proxy_pass 10.0.0.53:53; }
    server { listen 6379; allow 10.0.0.0/8; deny all; proxy_pass 10.0.0.7:6379; }
}
`,
	})
	pg, ok := find[*model.Stream](p, "port-5432")
	if !ok || pg.Forward != (model.Endpoint{Host: "10.0.0.9", Port: 5432}) {
		t.Errorf("pg = %+v, %v; skipped %v", pg, ok, p.Skipped)
	}
	dns, ok := find[*model.Stream](p, "port-53")
	if !ok || !dns.Has("tcp") || !dns.Has("udp") {
		t.Errorf("dns = %+v, %v", dns, ok)
	}
	if _, ok := find[*model.Stream](p, "port-6379"); ok {
		t.Error("a stream restricted by address was imported open")
	}
}

func TestNothingIsOverwritten(t *testing.T) {
	root, rebase := backup(t, map[string]string{
		"nginx.conf":        debianMain,
		"sites-enabled/app": `server { listen 80; server_name app.example.com; location / { proxy_pass http://127.0.0.1:1; } }`,
	})
	pr := &Parser{Rebase: rebase}
	top, err := pr.ParseFile(filepath.Join(root, "nginx.conf"))
	if err != nil {
		t.Fatal(err)
	}
	p := Build(top, Options{Exists: func(k model.Kind, n string) bool { return n == "app.example.com" }})
	if len(p.Docs) != 0 || skippedAbout(p, "already exists") == "" {
		t.Errorf("an existing name was not respected: docs %v, skipped %v", p.Docs, p.Skipped)
	}
}

func TestParserReportsSyntaxErrorsWithTheLine(t *testing.T) {
	root, rebase := backup(t, map[string]string{"nginx.conf": "events {}\nhttp {\n    server {\n"})
	_, err := (&Parser{Rebase: rebase}).ParseFile(filepath.Join(root, "nginx.conf"))
	if err == nil {
		t.Fatal("an unclosed block was accepted")
	}
}

func TestParserTokens(t *testing.T) {
	toks := tokenize("add_header X \"a b;c\" always; # comment ; {\nlisten 80;")
	var words []string
	for _, tk := range toks {
		words = append(words, tk.text)
	}
	got := strings.Join(words, "|")
	if got != "add_header|X|a b;c|always|;|listen|80|;" {
		t.Errorf("tokens = %s", got)
	}
	if toks[len(toks)-2].line != 2 {
		t.Errorf("line of listen = %d, want 2", toks[len(toks)-2].line)
	}
}
