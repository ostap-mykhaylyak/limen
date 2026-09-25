// Package nginx turns the model into an nginx configuration and puts
// it in front of nginx safely.
//
// Rendering is a pure function of the model and of what the installed
// nginx can do: the same input always gives the same tree, byte for
// byte, which is what lets an apply notice that nothing changed and
// leave nginx alone.
//
// Every include in the tree is relative, and nginx resolves relative
// includes against the directory of the file it was started with (-c).
// The same tree therefore tests in its own directory and runs, once
// installed, from /etc/nginx — there is only one rendering, never a
// second one "for real" that could differ from what was tested.
package nginx

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ostap-mykhaylyak/limen/internal/acme"
	"github.com/ostap-mykhaylyak/limen/internal/config"
	"github.com/ostap-mykhaylyak/limen/internal/model"
)

// Ref names one document of the model.
type Ref struct {
	Kind model.Kind
	Name string
}

func (r Ref) String() string { return fmt.Sprintf("%s %q", r.Kind, r.Name) }

// Input is everything a rendering depends on.
type Input struct {
	Hosts     []*model.ProxyHost
	Redirects []*model.Redirect
	Streams   []*model.Stream
	Access    []*model.AccessList

	Nginx    config.Nginx // with User already resolved
	Panel    config.Panel
	CertsDir string
	Features Features
	IPv6     bool

	// Exclude leaves documents out, with the reason: the ones a
	// previous `nginx -t` pinned an error on.
	Exclude map[Ref]string

	// StreamModule is true when the stream module is there to be used:
	// built in, or dynamic with a loader the modules include reaches.
	// Rendering a stream block without it is an "unknown directive" in
	// nginx.conf, a file no document owns, and the whole apply fails.
	StreamModule bool
}

// File is one file of the rendered tree.
type File struct {
	Data []byte
	Mode fs.FileMode
	// Group, when set, owns the file: the htpasswd files are read by
	// the workers at every request, not by the master at startup.
	Group string
}

// Tree is a rendered configuration: paths relative to its root, with
// forward slashes.
type Tree struct {
	Files map[string]File
	// Owners maps a file to the document it was rendered from, so that
	// an error nginx reports in that file can be pinned on the document.
	Owners map[string]Ref
}

// Paths lists the files in a stable order.
func (t Tree) Paths() []string {
	out := make([]string, 0, len(t.Files))
	for p := range t.Files {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Skip is a document that was not rendered, and why.
type Skip struct {
	Ref    Ref
	Reason string
}

// Output is the result of a rendering.
type Output struct {
	Tree     Tree
	Skipped  []Skip
	Warnings []string
}

type renderer struct {
	in       Input
	out      *Output
	access   map[string]*model.AccessList // the ones actually rendered
	upstream string                       // the panel, for ACME challenges
}

// Render builds the whole tree. A document that cannot be rendered is
// skipped and reported; only a failure in a shared file is an error.
func Render(in Input) (*Output, error) {
	r := &renderer{
		in:     in,
		out:    &Output{Tree: Tree{Files: map[string]File{}, Owners: map[string]Ref{}}},
		access: map[string]*model.AccessList{},
	}
	if in.Panel.IsUnixSocket() {
		r.upstream = "http://unix:" + in.Panel.Listen + ":"
	} else {
		r.upstream = "http://" + in.Panel.Listen
	}

	r.static()
	for _, a := range in.Access {
		r.accessList(a)
	}
	var hosts, redirects, streams []string
	for _, h := range in.Hosts {
		if p := r.proxyHost(h); p != "" {
			hosts = append(hosts, p)
		}
	}
	for _, rd := range in.Redirects {
		if p := r.redirect(rd); p != "" {
			redirects = append(redirects, p)
		}
	}
	for _, s := range in.Streams {
		if p := r.stream(s); p != "" {
			streams = append(streams, p)
		}
	}

	if err := r.defaultServers(); err != nil {
		return nil, err
	}
	if err := r.httpConf(append(hosts, redirects...)); err != nil {
		return nil, err
	}
	if err := r.mainConf(streams); err != nil {
		return nil, err
	}
	return r.out, nil
}

func (r *renderer) skip(ref Ref, format string, args ...any) {
	r.out.Skipped = append(r.out.Skipped, Skip{Ref: ref, Reason: fmt.Sprintf(format, args...)})
}

func (r *renderer) warn(format string, args ...any) {
	r.out.Warnings = append(r.out.Warnings, fmt.Sprintf(format, args...))
}

func (r *renderer) put(path string, data []byte, owner *Ref) {
	r.out.Tree.Files[path] = File{Data: data, Mode: 0o644}
	if owner != nil {
		r.out.Tree.Owners[path] = *owner
	}
}

// excluded reports, and records, a document an earlier test ruled out.
func (r *renderer) excluded(ref Ref) bool {
	if reason, ok := r.in.Exclude[ref]; ok {
		r.skip(ref, "%s", reason)
		return true
	}
	return false
}

// certificate returns the paths of a certificate, or ok=false when its
// files are not there (yet).
func (r *renderer) certificate(name string) (chain, key string, ok bool) {
	chain = filepath.ToSlash(filepath.Join(r.in.CertsDir, name, "fullchain.pem"))
	key = filepath.ToSlash(filepath.Join(r.in.CertsDir, name, "privkey.pem"))
	for _, p := range []string{chain, key} {
		if _, err := os.Stat(filepath.FromSlash(p)); err != nil {
			return chain, key, false
		}
	}
	return chain, key, true
}

// certificateNote writes which certificate a file serves, by the
// fingerprint of its leaf, and warns about the domains it does not
// cover.
//
// The fingerprint is what makes a renewal reach nginx. A renewed
// certificate lives at the same path, so without it the rendered tree
// would be byte for byte the one already live, the apply would find
// nothing to do, and nginx would keep serving the old certificate from
// memory until the day it expired.
func (r *renderer) certificateNote(c *conf, ref Ref, name string, domains []string) {
	info := acme.ReadInfo(r.in.CertsDir, name)
	if !info.Present || info.Error != "" {
		c.comment("certificate %s: unreadable", name)
		return
	}
	c.comment("certificate %s, serial %s, sha256 %s", name, info.Serial, info.Fingerprint)
	if missing := acme.Uncovered(info.Names, domains); len(missing) > 0 {
		r.warn("%s: certificate %q does not cover %s: browsers will refuse it there", ref, name, strings.Join(missing, ", "))
	}
}

// ---------------------------------------------------------------------
// Listening
// ---------------------------------------------------------------------

func (r *renderer) listen(c *conf, port int, extra ...any) {
	c.d("listen", append([]any{port}, extra...)...)
	if r.in.IPv6 {
		c.d("listen", append([]any{raw(fmt.Sprintf("[::]:%d", port))}, extra...)...)
	}
}

// listenTLS opens 443. Before nginx 1.25.1 HTTP/2 was a parameter of
// listen; since then it is a directive of its own.
func (r *renderer) listenTLS(c *conf, http2 bool, extra ...any) {
	params := []any{raw("ssl")}
	useParam := http2 && r.in.Features.HTTP2 && !r.in.Features.HTTP2Directive()
	if useParam {
		params = append(params, raw("http2"))
	}
	r.listen(c, 443, append(params, extra...)...)
	if http2 && r.in.Features.HTTP2 && r.in.Features.HTTP2Directive() {
		c.d("http2", raw("on"))
	}
}

func (r *renderer) tls(c *conf, t model.TLS, chain, key string) {
	c.d("ssl_certificate", chain)
	c.d("ssl_certificate_key", key)
	if t.HSTS {
		r.hsts(c, t)
	}
}

func (r *renderer) hsts(c *conf, t model.TLS) {
	c.d("add_header", raw("Strict-Transport-Security"), raw(hstsValue(t)), raw("always"))
}

func hstsValue(t model.TLS) string {
	value := "max-age=63072000"
	if t.HSTSSubdomains {
		value += "; includeSubDomains"
	}
	return `"` + value + `"`
}

// ---------------------------------------------------------------------
// Access lists
// ---------------------------------------------------------------------

func (r *renderer) accessList(a *model.AccessList) {
	ref := Ref{model.KindAccessList, a.Name}
	if r.excluded(ref) {
		return
	}
	var c conf
	c.comment("limen access list %s", a.Name)
	// Every directive of both mechanisms is written, even the ones the
	// list does not use: the file is also included in locations, and a
	// location inherits from its server whatever it does not set. A list
	// of rules alone, in a location of a host guarded by passwords, must
	// not keep asking for them — and "satisfy any" inherited next to an
	// "allow all" would let everybody in.
	if a.SatisfyAny && len(a.Rules) > 0 && len(a.Users) > 0 {
		c.d("satisfy", raw("any"))
	} else {
		c.d("satisfy", raw("all"))
	}
	// nginx evaluates allow and deny in order and stops at the first
	// match: the order of the model is the order written here.
	for _, rule := range a.Rules {
		c.d(rule.Action, rule.Address)
	}
	if len(a.Rules) == 0 {
		c.d("allow", raw("all"))
	}
	if len(a.Users) > 0 {
		c.d("auth_basic", raw(`"Restricted"`))
		c.d("auth_basic_user_file", "limen/access/"+a.Name+".htpasswd")
	} else {
		c.d("auth_basic", raw("off"))
	}
	data, err := c.bytes()
	if err != nil {
		r.skip(ref, "%v", err)
		return
	}

	var pw strings.Builder
	for _, u := range a.Users {
		// Usernames and hashes are validated to hold no ':' or newline:
		// one line per user, nothing else.
		if strings.ContainsAny(u.Username, ":\r\n") || strings.ContainsAny(u.Password, ":\r\n") {
			r.skip(ref, "user %q cannot be written to an htpasswd file", u.Username)
			return
		}
		pw.WriteString(u.Username + ":" + u.Password + "\n")
	}

	r.put("access/"+a.Name+".conf", data, &ref)
	if len(a.Users) > 0 {
		r.out.Tree.Files["access/"+a.Name+".htpasswd"] = File{
			Data: []byte(pw.String()), Mode: 0o640, Group: r.in.Nginx.User,
		}
		r.out.Tree.Owners["access/"+a.Name+".htpasswd"] = ref
	}
	r.access[a.Name] = a
}

// ---------------------------------------------------------------------
// Proxy hosts
// ---------------------------------------------------------------------

func (r *renderer) proxyHost(h *model.ProxyHost) string {
	ref := Ref{model.KindProxyHost, h.Name}
	if !h.Enabled || r.excluded(ref) {
		return ""
	}
	for _, name := range h.AccessLists() {
		if _, ok := r.access[name]; !ok {
			// Fail closed: without its guard the host is not served.
			r.skip(ref, "access list %q could not be rendered, and the host is not served without it", name)
			return ""
		}
	}
	acl := r.access[h.AccessList] // nil when the host has none
	var snippets hostSnippets
	var err error
	if snippets.host, err = model.ParseSnippet(h.Snippet); err != nil {
		r.skip(ref, "%v", err)
		return ""
	}
	snippets.locations = make([][]model.Directive, len(h.Locations))
	for i, l := range h.Locations {
		if snippets.locations[i], err = model.ParseSnippet(l.Snippet); err != nil {
			r.skip(ref, "location %s: %v", l.Match(), err)
			return ""
		}
	}

	chain, key, haveCert := "", "", false
	if h.TLS.Certificate != "" {
		chain, key, haveCert = r.certificate(h.TLS.Certificate)
		if !haveCert {
			r.warn("%s: certificate %q has no files yet, serving plain HTTP until it has", ref, h.TLS.Certificate)
		}
	}

	var c conf
	c.comment("limen proxy host %s -> %s", h.Name, h.Forward)
	if haveCert {
		r.certificateNote(&c, ref, h.TLS.Certificate, h.Domains)
	}
	c.block("server", nil, func() {
		r.listen(&c, 80)
		c.d("server_name", toAny(h.Domains)...)
		r.hostLogs(&c, h)
		c.d("include", raw("limen/snippets/acme.conf"))
		if haveCert && h.TLS.ForceHTTPS {
			c.block("location", args(raw("/")), func() {
				c.d("return", 301, raw("https://$host$request_uri"))
			})
			return
		}
		r.hostBody(&c, h, acl, snippets, false)
	})
	if haveCert {
		c.blank()
		c.block("server", nil, func() {
			r.listenTLS(&c, h.TLS.HTTP2)
			c.d("server_name", toAny(h.Domains)...)
			r.hostLogs(&c, h)
			r.tls(&c, h.TLS, chain, key)
			c.d("include", raw("limen/snippets/acme.conf"))
			r.hostBody(&c, h, acl, snippets, true)
		})
	}

	data, err := c.bytes()
	if err != nil {
		r.skip(ref, "%v", err)
		return ""
	}
	path := "hosts/" + h.Name + ".conf"
	r.put(path, data, &ref)
	return path
}

// The rate limits in front of the panel: every request, and the login.
const (
	panelRate  = "10r/s"
	panelBurst = "50"
	loginRate  = "30r/m"
	loginBurst = "10"
	// LoginPath is the panel's login, limited on its own.
	LoginPath = "/api/v1/session"
)

// StatusPath is where the default server answers nginx's counters to
// loopback clients.
const StatusPath = "/limen-nginx-status"

// LogFormat is the name of limen's access log format.
const LogFormat = "limen"

// logFormat writes one JSON object per request. escape=json makes every
// value a valid JSON string whatever the client sent; the numbers are
// variables nginx always fills with a number.
const logFormat = `log_format limen escape=json '{"time":"$time_iso8601","msec":$msec,'
    '"remote":"$remote_addr","host":"$host","method":"$request_method",'
    '"uri":"$request_uri","proto":"$server_protocol","status":$status,'
    '"bytes":$body_bytes_sent,"duration":$request_time,'
    '"upstream":"$upstream_addr","upstream_status":"$upstream_status",'
    '"upstream_time":"$upstream_response_time","tls":"$ssl_protocol",'
    '"referer":"$http_referer","agent":"$http_user_agent"}';
`

// HostLogPaths returns where a host's access and error logs are.
func HostLogPaths(dir, host string) (access, errorLog string) {
	dir = strings.TrimSuffix(filepath.ToSlash(dir), "/")
	return dir + "/" + host + ".access.log", dir + "/" + host + ".error.log"
}

// hostLogs writes a host's own logs: its requests, unless it said not
// to, and its errors, so that a host's problems are read without the
// others'.
func (r *renderer) hostLogs(c *conf, h *model.ProxyHost) {
	access, errorLog := HostLogPaths(r.in.Nginx.HostLogs, h.Name)
	if h.LogRequests {
		c.d("access_log", access, raw(LogFormat))
	} else {
		c.d("access_log", raw("off"))
	}
	c.d("error_log", errorLog, raw("warn"))
}

const assetPattern = `\.(?:css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|woff2?|ttf|otf|eot)$`

// hostSnippets are a host's snippets, read once.
type hostSnippets struct {
	host      []model.Directive
	locations [][]model.Directive
}

// hostBody writes what a host's server block holds besides listening:
// its guard, its custom locations, and the location for everything
// else.
func (r *renderer) hostBody(c *conf, h *model.ProxyHost, acl *model.AccessList, sn hostSnippets, https bool) {
	if h.BlockExploits {
		c.d("include", raw("limen/snippets/exploits.conf"))
	}
	panel := h.Protected && h.Name == PanelHost && r.in.Features.LimitReq
	if panel {
		// The panel is the control plane: a flood is shed here, before
		// it reaches limen, and a login — 600 000 rounds of PBKDF2 — has
		// a tighter limit of its own. limen throttles failed logins too;
		// this is the part that costs it nothing.
		c.d("limit_req", raw("zone=limen_panel"), raw("burst="+panelBurst), raw("nodelay"))
		c.d("limit_req_status", 429)
		c.block("location", args(raw("="), raw(LoginPath)), func() {
			c.d("limit_req", raw("zone=limen_login"), raw("burst="+loginBurst), raw("nodelay"))
			r.proxy(c, h, proxyTarget{up: h.Forward, websockets: h.Websockets, guard: acl, https: https,
				snippets: [][]model.Directive{sn.host}})
		})
	}
	if h.ClientMaxBodySize != "" {
		c.d("client_max_body_size", h.ClientMaxBodySize)
	}
	if acl != nil {
		c.d("include", "limen/access/"+acl.Name+".conf")
	}
	for i, l := range h.Locations {
		up, guard := h.Forward, acl
		if l.Forward != nil {
			up = *l.Forward
		}
		modifier := []any{}
		if l.Exact {
			modifier = append(modifier, raw("="))
		}
		c.block("location", append(modifier, quoted(l.Path)), func() {
			switch {
			case l.Public:
				// Open on purpose, whatever the server block says.
				c.d("satisfy", raw("all"))
				c.d("allow", raw("all"))
				c.d("auth_basic", raw("off"))
				guard = nil
			case l.AccessList != "":
				guard = r.access[l.AccessList]
				c.d("include", "limen/access/"+guard.Name+".conf")
			}
			p := proxyTarget{up: up, websockets: l.Websockets, guard: guard, https: https,
				snippets: [][]model.Directive{sn.host, sn.locations[i]}}
			if h.CacheAssets && !l.Exact {
				r.assets(c, h, p)
			}
			r.proxy(c, h, p)
		})
	}
	c.block("location", args(raw("/")), func() {
		p := proxyTarget{up: h.Forward, websockets: h.Websockets, guard: acl, https: https,
			snippets: [][]model.Directive{sn.host}}
		if h.CacheAssets {
			r.assets(c, h, p)
		}
		r.proxy(c, h, p)
	})
}

// assets nests, in a location, the one that lets browsers keep static
// files for a week. Nested rather than beside it, so that a stylesheet
// under /api/ still goes to /api/'s backend.
func (r *renderer) assets(c *conf, h *model.ProxyHost, p proxyTarget) {
	c.block("location", args(raw("~*"), raw(`"`+assetPattern+`"`)), func() {
		p.extra = []model.Directive{
			{Name: "expires", Args: []string{"7d"}},
			{Name: "add_header", Args: []string{"Cache-Control", "public"}},
		}
		r.proxy(c, h, p)
	})
}

// proxyTarget is what one location proxies to, and how.
type proxyTarget struct {
	up         model.Upstream
	websockets bool
	guard      *model.AccessList // the list in force in the location
	https      bool
	extra      []model.Directive // limen's own, after the defaults
	snippets   [][]model.Directive
}

// proxy writes the directives of a proxying location. They are built
// as a list first, keyed by what each one sets, so that the host's
// options and then the snippets replace limen's defaults instead of
// repeating them — nginx refuses a duplicate proxy_read_timeout, and
// sends a header set twice twice.
func (r *renderer) proxy(c *conf, h *model.ProxyHost, p proxyTarget) {
	var ds directives
	ds.set("proxy_pass", raw(p.up.String()))
	ds.set("proxy_http_version", raw("1.1"))
	switch h.Proxy.HostHeader {
	case "":
		ds.header("proxy_set_header", "Host", raw("$host"))
	case model.HostHeaderUpstream:
		ds.header("proxy_set_header", "Host", raw("$proxy_host"))
	default:
		ds.header("proxy_set_header", "Host", quoted(h.Proxy.HostHeader))
	}
	ds.header("proxy_set_header", "X-Real-IP", raw("$remote_addr"))
	// The client's own X-Forwarded-For is dropped, not appended to:
	// nginx is the edge, and a backend that reads the first entry would
	// otherwise believe whatever address the client wrote there.
	ds.header("proxy_set_header", "X-Forwarded-For", raw("$remote_addr"))
	ds.header("proxy_set_header", "X-Forwarded-Proto", raw("$scheme"))
	ds.header("proxy_set_header", "X-Forwarded-Host", raw("$host"))
	ds.header("proxy_set_header", "X-Forwarded-Port", raw("$server_port"))
	if p.websockets {
		ds.header("proxy_set_header", "Upgrade", raw("$http_upgrade"))
		ds.header("proxy_set_header", "Connection", raw("$connection_upgrade"))
	} else {
		ds.header("proxy_set_header", "Connection", raw(`""`))
	}
	if p.guard != nil && len(p.guard.Users) > 0 && !p.guard.PassAuth {
		// The credentials open the gate; the backend does not need them.
		ds.header("proxy_set_header", "Authorization", raw(`""`))
	}
	if h.Proxy.ConnectTimeout != "" {
		ds.set("proxy_connect_timeout", h.Proxy.ConnectTimeout)
	}
	ds.set("proxy_read_timeout", orDefault(h.Proxy.ReadTimeout, "300s"))
	ds.set("proxy_send_timeout", orDefault(h.Proxy.SendTimeout, "300s"))
	if h.Proxy.StreamResponses {
		ds.set("proxy_buffering", raw("off"))
	}
	if h.Proxy.StreamRequests {
		ds.set("proxy_request_buffering", raw("off"))
	}
	if p.up.Scheme == "https" {
		ds.set("proxy_ssl_server_name", raw("on"))
		if p.up.VerifyTLS {
			ds.set("proxy_ssl_verify", raw("on"))
			ds.set("proxy_ssl_trusted_certificate", r.in.Nginx.TrustedCA)
			ds.set("proxy_ssl_name", p.up.Host)
		}
	}
	for _, hd := range h.Proxy.RequestHeaders {
		ds.header("proxy_set_header", hd.Name, quoted(hd.Value))
	}
	// add_header in a location drops every add_header of the server:
	// HSTS is said again here, in every location, whether or not
	// anything else below adds a header.
	if p.https && h.TLS.HSTS {
		ds.header("add_header", "Strict-Transport-Security", raw(hstsValue(h.TLS)), raw("always"))
	}
	for _, hd := range h.Proxy.ResponseHeaders {
		ds.header("add_header", hd.Name, quoted(hd.Value), raw("always"))
	}
	for _, d := range p.extra {
		ds.directive(d)
	}
	for _, sn := range p.snippets {
		for _, d := range sn {
			ds.directive(d)
		}
	}
	ds.write(c)
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// directives is a location's body before it is written.
type directives struct {
	list []entry
}

type entry struct {
	key  string // what it sets; "" for the ones that are only added
	name string
	args []any
}

// put adds a directive, replacing the one with the same key.
func (ds *directives) put(key, name string, args ...any) {
	if key != "" {
		for i := range ds.list {
			if ds.list[i].key == key {
				ds.list[i] = entry{key, name, args}
				return
			}
		}
	}
	ds.list = append(ds.list, entry{key, name, args})
}

func (ds *directives) set(name string, args ...any) { ds.put(name, name, args...) }

func (ds *directives) header(name, header string, args ...any) {
	ds.put(name+" "+strings.ToLower(header), name, append([]any{raw(header)}, args...)...)
}

// directive adds one directive of a snippet, every argument quoted.
func (ds *directives) directive(d model.Directive) {
	args := make([]any, len(d.Args))
	for i, a := range d.Args {
		args[i] = quoted(a)
	}
	ds.put(d.Key(), d.Name, args...)
}

func (ds *directives) write(c *conf) {
	for _, e := range ds.list {
		c.d(e.name, e.args...)
	}
}

// ---------------------------------------------------------------------
// Redirects
// ---------------------------------------------------------------------

func (r *renderer) redirect(rd *model.Redirect) string {
	ref := Ref{model.KindRedirect, rd.Name}
	if !rd.Enabled || r.excluded(ref) {
		return ""
	}
	chain, key, haveCert := "", "", false
	if rd.TLS.Certificate != "" {
		chain, key, haveCert = r.certificate(rd.TLS.Certificate)
		if !haveCert {
			r.warn("%s: certificate %q has no files yet, serving plain HTTP until it has", ref, rd.TLS.Certificate)
		}
	}

	var c conf
	scheme := raw("$scheme://")
	if rd.Target.Scheme != "auto" {
		scheme = raw(c.arg(rd.Target.Scheme) + "://")
	}
	target := string(scheme) + c.arg(rd.Target.Domain)
	if rd.Target.PreservePath {
		target += "$request_uri"
	}

	c.comment("limen redirect %s -> %s", rd.Name, rd.Target)
	if haveCert {
		r.certificateNote(&c, ref, rd.TLS.Certificate, rd.Domains)
	}
	body := func() {
		if rd.BlockExploits {
			c.d("include", raw("limen/snippets/exploits.conf"))
		}
		c.block("location", args(raw("/")), func() {
			c.d("return", rd.Code, raw(target))
		})
	}
	c.block("server", nil, func() {
		r.listen(&c, 80)
		c.d("server_name", toAny(rd.Domains)...)
		c.d("include", raw("limen/snippets/acme.conf"))
		if haveCert && rd.TLS.ForceHTTPS {
			c.block("location", args(raw("/")), func() {
				c.d("return", 301, raw("https://$host$request_uri"))
			})
			return
		}
		body()
	})
	if haveCert {
		c.blank()
		c.block("server", nil, func() {
			r.listenTLS(&c, rd.TLS.HTTP2)
			c.d("server_name", toAny(rd.Domains)...)
			r.tls(&c, rd.TLS, chain, key)
			c.d("include", raw("limen/snippets/acme.conf"))
			body()
		})
	}

	data, err := c.bytes()
	if err != nil {
		r.skip(ref, "%v", err)
		return ""
	}
	path := "redirects/" + rd.Name + ".conf"
	r.put(path, data, &ref)
	return path
}

// ---------------------------------------------------------------------
// Streams
// ---------------------------------------------------------------------

func (r *renderer) stream(s *model.Stream) string {
	ref := Ref{model.KindStream, s.Name}
	if !s.Enabled || r.excluded(ref) {
		return ""
	}
	switch {
	case !r.in.Features.Stream:
		r.skip(ref, "this nginx was built without the stream module")
		return ""
	case !r.in.StreamModule:
		r.skip(ref, "the stream module is not installed or not loaded (on Debian and Ubuntu: apt install libnginx-mod-stream)")
		return ""
	}

	var guard *model.AccessList
	if s.AccessList != "" {
		var ok bool
		if guard, ok = r.access[s.AccessList]; !ok {
			r.skip(ref, "access list %q could not be rendered, and the stream is not served without it", s.AccessList)
			return ""
		}
		if len(guard.Users) > 0 || len(guard.Rules) == 0 {
			// A stream cannot ask for a password: serving it would
			// drop the half of the guard that is not an address.
			r.skip(ref, "access list %q is not made of address rules only, and the stream is not served without it", s.AccessList)
			return ""
		}
	}

	var c conf
	c.comment("limen stream %s -> %s", s.Name, s.Forward)
	c.block("server", nil, func() {
		for _, p := range s.Protocols {
			if p == "udp" {
				r.listen(&c, s.Listen, raw("udp"))
			} else {
				r.listen(&c, s.Listen)
			}
		}
		if guard != nil {
			c.comment("access list %s", guard.Name)
			for _, rule := range guard.Rules {
				c.d(rule.Action, rule.Address)
			}
		}
		c.d("proxy_pass", s.Forward.String())
	})
	data, err := c.bytes()
	if err != nil {
		r.skip(ref, "%v", err)
		return ""
	}
	path := "streams/" + s.Name + ".conf"
	r.put(path, data, &ref)
	return path
}

// ---------------------------------------------------------------------
// Shared files
// ---------------------------------------------------------------------

func (r *renderer) defaultServers() error {
	var c conf
	c.comment("Requests for a name no host answers on.")
	c.block("server", nil, func() {
		r.listen(&c, 80, raw("default_server"))
		c.d("server_name", raw("_"))
		c.d("include", raw("limen/snippets/acme.conf"))
		c.block("location", args(raw("/")), func() {
			// 444: close the connection without an answer. A scanner
			// probing addresses learns nothing about what runs here.
			c.d("return", 444)
		})
		if r.in.Features.StubStatus {
			// nginx's connection counters, for limen on this machine
			// only. Anyone else gets what any unknown request gets: the
			// connection closed, not a 403 saying something is there.
			c.block("location", args(raw("="), raw(StatusPath)), func() {
				c.d("stub_status")
				c.d("access_log", raw("off"))
				c.d("allow", raw("127.0.0.1"))
				c.d("allow", raw("::1"))
				c.d("deny", raw("all"))
				c.d("error_page", 403, raw("="), raw("@limen_closed"))
			})
			c.block("location", args(raw("@limen_closed")), func() {
				c.d("return", 444)
			})
		}
	})
	if r.in.Features.RejectHandshake() {
		c.blank()
		c.comment("Refuse TLS for unknown names instead of showing a host's certificate.")
		c.block("server", nil, func() {
			r.listen(&c, 443, raw("ssl"), raw("default_server"))
			c.d("server_name", raw("_"))
			c.d("ssl_reject_handshake", raw("on"))
		})
	}
	data, err := c.bytes()
	if err != nil {
		return fmt.Errorf("default.conf: %w", err)
	}
	r.put("default.conf", data, nil)
	return nil
}

func (r *renderer) httpConf(includes []string) error {
	n := r.in.Nginx
	var c conf
	c.comment("HTTP settings shared by every host. Generated by limen.")
	c.d("sendfile", raw("on"))
	c.d("tcp_nopush", raw("on"))
	c.d("keepalive_timeout", 65)
	c.d("server_tokens", raw("off"))
	c.d("server_names_hash_bucket_size", n.ServerNamesHash)
	c.d("client_max_body_size", n.ClientMaxBodySize)
	c.d("access_log", n.AccessLog)
	c.blank()
	if r.in.Features.LimitReq {
		c.comment("Rate limits in front of limen's panel, per client address.")
		c.d("limit_req_zone", raw("$binary_remote_addr"), raw("zone=limen_panel:10m"), raw("rate="+panelRate))
		c.d("limit_req_zone", raw("$binary_remote_addr"), raw("zone=limen_login:10m"), raw("rate="+loginRate))
		c.blank()
	}
	c.comment("One request per line, as JSON: the per-host logs limen reads.")
	c.text(logFormat)
	c.blank()
	c.text("map $http_upgrade $connection_upgrade {\n    default upgrade;\n    '' close;\n}\n")
	c.blank()
	c.d("ssl_protocols", raw("TLSv1.2"), raw("TLSv1.3"))
	c.d("ssl_prefer_server_ciphers", raw("off"))
	c.d("ssl_session_cache", raw("shared:limen_tls:10m"))
	c.d("ssl_session_timeout", raw("1d"))
	c.d("ssl_session_tickets", raw("off"))
	c.blank()
	c.d("include", raw("limen/default.conf"))
	sort.Strings(includes)
	for _, p := range includes {
		c.d("include", "limen/"+p)
	}
	data, err := c.bytes()
	if err != nil {
		return fmt.Errorf("http.conf: %w", err)
	}
	r.put("http.conf", data, nil)
	return nil
}

func (r *renderer) mainConf(streams []string) error {
	n := r.in.Nginx
	var c conf
	c.comment("Generated by limen. Do not edit: it is rewritten at every change.")
	c.comment("Manage the configuration with `limen` or its panel. Nothing else under")
	c.comment("/etc/nginx is read: sites-enabled/ and conf.d/ are ignored on purpose.")
	c.blank()
	if n.Modules != "" {
		c.d("include", n.Modules)
	}
	c.d("user", n.User)
	c.d("worker_processes", n.WorkerProcesses)
	c.d("pid", n.PIDFile)
	c.d("error_log", n.ErrorLog, raw("warn"))
	c.blank()
	c.block("events", nil, func() {
		c.d("worker_connections", n.WorkerConnections)
	})
	c.blank()
	c.block("http", nil, func() {
		c.d("include", raw("limen/mime.types"))
		c.d("default_type", raw("application/octet-stream"))
		c.d("include", raw("limen/http.conf"))
	})
	if len(streams) > 0 {
		c.blank()
		c.block("stream", nil, func() {
			sort.Strings(streams)
			for _, p := range streams {
				c.d("include", "limen/"+p)
			}
		})
	}
	data, err := c.bytes()
	if err != nil {
		return fmt.Errorf("nginx.conf: %w", err)
	}
	r.put("nginx.conf", data, nil)
	return nil
}

func (r *renderer) static() {
	r.put("mime.types", []byte(mimeTypes), nil)
	r.put("snippets/exploits.conf", []byte(exploitsSnippet), nil)

	var c conf
	c.comment("ACME HTTP-01 challenges are answered by limen itself.")
	c.block("location", args(raw("^~"), raw("/.well-known/acme-challenge/")), func() {
		// An access list on the host must not stop the CA, or the
		// certificate of a guarded host could never be issued.
		c.d("allow", raw("all"))
		c.d("auth_basic", raw("off"))
		c.d("proxy_pass", r.upstream)
		c.d("proxy_set_header", raw("Host"), raw("$host"))
	})
	data, err := c.bytes()
	if err != nil {
		// The panel address is validated by the configuration; if it
		// still cannot be written, the snippet is left empty and the
		// challenges fail visibly rather than the whole tree.
		r.warn("ACME challenges cannot be routed to the panel: %v", err)
		data = []byte("# ACME challenges disabled: the panel address cannot be written here.\n")
	}
	r.put("snippets/acme.conf", data, nil)
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

const exploitsSnippet = `# Requests only a scanner or an exploit sends. Kept short on purpose: a
# false positive breaks a real application. Generated by limen.
if ($request_uri ~* "(\.\./|\.\.%2f|%2e%2e%2f|%2e%2e/|/\.git/|/\.env$|/\.htaccess|/etc/passwd|wp-config\.php)") {
    return 403;
}
if ($query_string ~* "(<script|%3cscript|union(\+|%20)+select|base64_decode\(|/proc/self/environ)") {
    return 403;
}
`
