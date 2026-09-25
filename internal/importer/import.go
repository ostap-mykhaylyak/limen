package importer

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/ostap-mykhaylyak/limen/internal/model"
)

// Plan is what an import would do.
type Plan struct {
	Docs    []model.Document
	Certs   []CertCopy
	Skipped []string // what was not imported, and why
	Notes   []string // what was imported with something left behind
}

// CertCopy is a certificate to copy into limen's store, so that an
// imported host keeps serving HTTPS.
type CertCopy struct {
	Name  string
	Chain string
	Key   string
}

// Options are the outside world the import needs.
type Options struct {
	// Exists reports a name already taken in the model: an import never
	// overwrites anything.
	Exists func(kind model.Kind, name string) bool
	// ReadFile reads a file the configuration refers to (htpasswd),
	// with the same rebasing as the includes.
	ReadFile func(path string) ([]byte, error)
}

// listen is one listen directive of a server.
type listen struct {
	port        int
	ssl, http2  bool
	defaultSrv  bool
	unsupported string
}

// server is what the importer understood of a server block.
type server struct {
	d       *Directive
	names   []string
	listens []listen

	cert, key     string
	http2         bool
	hsts, hstsSub bool

	proxy      *model.Upstream
	redirect   *redirectSpec
	websockets bool
	maxBody    string
	locations  []model.Location

	authFile   string
	authOff    bool
	rules      []model.Rule
	satisfyAny bool
	stripAuth  bool

	// httpsNames are the names this server sends to HTTPS on the same
	// host (return 301 https://$host$request_uri, or certbot's
	// "if ($host = x)" blocks).
	httpsNames []string

	problems []string // any of these and the server is not imported
	ignored  []string // directives dropped on the way
}

type redirectSpec struct {
	code int
	url  string
	at   string
}

func (s *server) problem(d *Directive, format string, args ...any) {
	s.problems = append(s.problems, fmt.Sprintf("%s: %s", d.At(), fmt.Sprintf(format, args...)))
}

func (s *server) ignore(name string) {
	if slices.Contains(s.ignored, name) {
		return
	}
	s.ignored = append(s.ignored, name)
}

func (s *server) hasSSL() bool {
	for _, l := range s.listens {
		if l.ssl {
			return true
		}
	}
	return false
}

func (s *server) isDefault() bool {
	if len(s.names) > 0 {
		return false
	}
	for _, l := range s.listens {
		if l.defaultSrv {
			return true
		}
	}
	return true
}

func (s *server) label() string {
	if len(s.names) == 0 {
		return "server at " + s.d.At()
	}
	return "server " + strings.Join(s.names, " ") + " (" + s.d.At() + ")"
}

// Directives that grant or refuse access in ways limen cannot express.
// A server that has one is not imported at all: imported without it,
// it would be open.
var guarding = map[string]string{
	"auth_request":           "delegates authentication to another service",
	"auth_jwt":               "checks JWT tokens",
	"ssl_verify_client":      "requires client certificates",
	"ssl_client_certificate": "requires client certificates",
	"limit_except":           "restricts HTTP methods",
	"geo":                    "decides access by address map",
}

// Build turns parsed configuration into a plan.
func Build(top []*Directive, opt Options) *Plan {
	p := &Plan{}
	upstreams := map[string][]string{}
	for _, http := range Find(top, "http") {
		for _, up := range Find(http.Block, "upstream") {
			for _, srv := range Find(up.Block, "server") {
				upstreams[up.Arg(0)] = append(upstreams[up.Arg(0)], srv.Arg(0))
			}
		}
	}

	var servers []*server
	for _, http := range Find(top, "http") {
		for _, d := range Find(http.Block, "server") {
			servers = append(servers, analyse(d, upstreams))
		}
	}
	p.hosts(servers, opt)

	for _, st := range Find(top, "stream") {
		streamUps := map[string][]string{}
		for _, up := range Find(st.Block, "upstream") {
			for _, srv := range Find(up.Block, "server") {
				streamUps[up.Arg(0)] = append(streamUps[up.Arg(0)], srv.Arg(0))
			}
		}
		for _, d := range Find(st.Block, "server") {
			p.stream(d, streamUps, opt)
		}
	}
	return p
}

// analyse reads one http server block.
func analyse(d *Directive, upstreams map[string][]string) *server {
	s := &server{d: d}
	for _, c := range d.Block {
		switch c.Name {
		case "listen":
			l := parseListen(c)
			if l.unsupported != "" {
				s.problem(c, "%s", l.unsupported)
			}
			s.listens = append(s.listens, l)
		case "server_name":
			for _, n := range c.Args {
				switch {
				case n == "_" || n == "":
				case strings.HasPrefix(n, "~"):
					s.problem(c, "server_name %s is a regular expression: limen keeps exact and wildcard names only", n)
				default:
					n = strings.ToLower(strings.TrimSuffix(n, "."))
					if err := model.ValidateDomain(n); err != nil {
						s.problem(c, "%v", err)
						continue
					}
					s.names = append(s.names, n)
				}
			}
		case "ssl_certificate":
			s.cert = c.Arg(0)
		case "ssl_certificate_key":
			s.key = c.Arg(0)
		case "http2":
			s.http2 = c.Arg(0) == "on"
		case "add_header":
			if strings.EqualFold(c.Arg(0), "Strict-Transport-Security") {
				s.hsts = true
				s.hstsSub = strings.Contains(strings.ToLower(c.Arg(1)), "includesubdomains")
			} else {
				s.ignore("add_header " + c.Arg(0))
			}
		case "return":
			s.redirect = parseReturn(c, s)
		case "rewrite":
			s.rewrite(c)
		case "if":
			s.ifBlock(c)
		case "location":
			s.location(c, upstreams)
		case "proxy_pass":
			s.proxyPass(c, upstreams)
		case "client_max_body_size":
			s.maxBody = c.Arg(0)
		case "auth_basic", "auth_basic_user_file", "allow", "deny", "satisfy":
			s.access(c)
		case "proxy_set_header":
			s.header(c)
		case "try_files", "fastcgi_pass", "uwsgi_pass", "scgi_pass", "grpc_pass", "alias", "autoindex", "memcached_pass":
			s.problem(c, "%s: the server serves files or runs an application itself, limen only proxies", c.Name)
		default:
			if why, ok := guarding[c.Name]; ok {
				s.problem(c, "%s %s: limen cannot reproduce that guard, and will not import the host without it", c.Name, why)
				continue
			}
			s.ignore(c.Name)
		}
	}
	return s
}

// location handles the locations of a server: location / is the host
// itself, the ACME webroot certbot adds is limen's own business, and a
// prefix or exact location that proxies or answers becomes a custom
// location. A regular expression or a named location has no place in
// the model, and neither has a location that serves files.
func (s *server) location(c *Directive, upstreams map[string][]string) {
	path := strings.Join(c.Args, " ")
	if strings.Contains(path, "/.well-known/acme-challenge") || strings.Contains(path, "/.well-known") && strings.Contains(path, "acme") {
		return // limen answers ACME challenges itself
	}
	switch {
	case path == "/":
		s.rootLocation(c, upstreams)
	case len(c.Args) == 1 && strings.HasPrefix(c.Args[0], "/"):
		s.customLocation(c, model.Location{Path: c.Args[0]}, upstreams)
	case len(c.Args) == 2 && c.Args[0] == "=" && strings.HasPrefix(c.Args[1], "/"):
		s.customLocation(c, model.Location{Path: c.Args[1], Exact: true}, upstreams)
	default:
		s.problem(c, "location %s: limen keeps prefix and exact locations, not regular expressions or named ones", path)
	}
}

func (s *server) rootLocation(c *Directive, upstreams map[string][]string) {
	for _, d := range c.Block {
		switch d.Name {
		case "proxy_pass":
			if up := s.upstream(d, upstreams); up != nil {
				s.proxy = up
			}
		case "return":
			s.redirect = parseReturn(d, s)
		case "rewrite":
			s.rewrite(d)
		case "proxy_set_header":
			s.header(d)
		case "client_max_body_size":
			s.maxBody = d.Arg(0)
		case "auth_basic", "auth_basic_user_file", "allow", "deny", "satisfy":
			s.access(d)
		case "try_files", "fastcgi_pass", "uwsgi_pass", "scgi_pass", "grpc_pass", "alias", "root", "autoindex", "memcached_pass":
			if d.Name == "root" {
				s.problem(d, "location / serves files from %s, limen only proxies", d.Arg(0))
			} else {
				s.problem(d, "%s: the server serves files or runs an application itself, limen only proxies", d.Name)
			}
		case "location", "if":
			s.problem(d, "a nested %s in location /: limen does not keep those", d.Name)
		default:
			if why, ok := guarding[d.Name]; ok {
				s.problem(d, "%s %s: limen cannot reproduce that guard, and will not import the host without it", d.Name, why)
				continue
			}
			s.ignore(d.Name)
		}
	}
}

// limenHeaders are the request headers limen sets on every location
// itself: an imported location does not need to say them again.
var limenHeaders = map[string]bool{
	"x-real-ip": true, "x-forwarded-for": true, "x-forwarded-proto": true,
	"x-forwarded-host": true, "x-forwarded-port": true, "connection": true,
}

// customLocation imports a location other than /. What the model says
// on its own (the backend, websockets) goes to its fields; whatever
// else a snippet may hold goes to its snippet, written back as nginx
// read it; anything else leaves the whole server out.
func (s *server) customLocation(c *Directive, l model.Location, upstreams map[string][]string) {
	var snippet []string
	answers := false
	for _, d := range c.Block {
		switch d.Name {
		case "proxy_pass":
			up := s.upstream(d, upstreams)
			if up == nil {
				return
			}
			l.Forward = up
			answers = true
			continue
		case "proxy_set_header":
			name := strings.ToLower(d.Arg(0))
			switch {
			case name == "upgrade" && strings.Contains(d.Arg(1), "$http_upgrade"):
				l.Websockets = true
				continue
			case limenHeaders[name], name == "host" && d.Arg(1) == "$host":
				continue
			}
		case "return":
			answers = true
		case "auth_basic", "auth_basic_user_file", "allow", "deny", "satisfy":
			s.problem(d, "location %s: %s: a guard of its own in a location is not imported; give the location an access list after the import", l.Match(), d.Name)
			return
		case "location", "if":
			s.problem(d, "location %s: a nested %s is not kept", l.Match(), d.Name)
			return
		}
		if why, ok := guarding[d.Name]; ok {
			s.problem(d, "%s %s: limen cannot reproduce that guard, and will not import the host without it", d.Name, why)
			return
		}
		line := snippetLine(d)
		if _, err := model.ParseSnippet(line); err != nil {
			s.problem(d, "location %s: %s is not something limen keeps", l.Match(), d.Name)
			return
		}
		snippet = append(snippet, line)
	}
	if !answers {
		s.problem(c, "location %s neither proxies nor answers: it serves files, and limen only proxies", l.Match())
		return
	}
	l.Snippet = strings.Join(snippet, "\n")
	s.locations = append(s.locations, l)
}

// snippetLine writes a directive back, every argument quoted, so that
// the snippet means what the original configuration meant.
func snippetLine(d *Directive) string {
	var b strings.Builder
	b.WriteString(d.Name)
	for _, a := range d.Args {
		b.WriteString(` "`)
		b.WriteString(strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(a))
		b.WriteString(`"`)
	}
	b.WriteString(";")
	return b.String()
}

func (s *server) proxyPass(d *Directive, upstreams map[string][]string) {
	if up := s.upstream(d, upstreams); up != nil {
		s.proxy = up
	}
}

// upstream reads the target of a proxy_pass, or records why it cannot
// and returns nil.
func (s *server) upstream(d *Directive, upstreams map[string][]string) *model.Upstream {
	target := d.Arg(0)
	if strings.Contains(target, "$") {
		s.problem(d, "proxy_pass %s uses variables", target)
		return nil
	}
	for _, scheme := range []string{"http", "https"} {
		if sock, ok := strings.CutPrefix(target, scheme+"://unix:"); ok {
			// proxy_pass http://unix:/run/app.sock:/ — the socket path
			// ends at the colon.
			sock, rest, _ := strings.Cut(sock, ":")
			if rest != "" && rest != "/" {
				s.problem(d, "proxy_pass %s rewrites the path, which limen does not", target)
				return nil
			}
			return &model.Upstream{Scheme: scheme, Socket: sock}
		}
	}
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		s.problem(d, "proxy_pass %s is not an http or https address", target)
		return nil
	}
	if u.Path != "" && u.Path != "/" {
		s.problem(d, "proxy_pass %s rewrites the path, which limen does not", target)
		return nil
	}
	up := model.Upstream{Scheme: u.Scheme}
	host, port := u.Hostname(), u.Port()
	if servers, ok := upstreams[host]; ok {
		if len(servers) != 1 {
			s.problem(d, "proxy_pass %s balances across %d servers: limen sends a host to one backend", target, len(servers))
			return nil
		}
		h, p, err := net.SplitHostPort(servers[0])
		if err != nil {
			h, p = servers[0], ""
		}
		host, port = h, p
	}
	up.Host = host
	switch {
	case port != "":
		up.Port, _ = strconv.Atoi(port)
	case u.Scheme == "https":
		up.Port = 443
	default:
		up.Port = 80
	}
	return &up
}

func (s *server) header(d *Directive) {
	name := strings.ToLower(d.Arg(0))
	switch {
	case name == "upgrade" && strings.Contains(d.Arg(1), "$http_upgrade"):
		s.websockets = true
	case name == "authorization" && d.Arg(1) == "":
		s.stripAuth = true
	}
	// The other headers limen sets itself (Host, X-Forwarded-*).
}

func (s *server) access(d *Directive) {
	switch d.Name {
	case "auth_basic":
		s.authOff = d.Arg(0) == "off"
	case "auth_basic_user_file":
		s.authFile = d.Arg(0)
	case "allow", "deny":
		s.rules = append(s.rules, model.Rule{Action: d.Name, Address: d.Arg(0)})
	case "satisfy":
		s.satisfyAny = d.Arg(0) == "any"
	}
}

var httpsSameHost = regexp.MustCompile(`^https://\$(host|server_name|http_host)(\$request_uri|\$1)?\??$`)

// parseReturn reads `return CODE URL`. A redirect to HTTPS on the same
// host is not a redirect document: it is the host's force_https.
func parseReturn(d *Directive, s *server) *redirectSpec {
	code, err := strconv.Atoi(d.Arg(0))
	if err != nil || d.Arg(1) == "" {
		// `return 404;` and the like: certbot ends its HTTP server
		// with one. Nothing to import from it.
		return nil
	}
	if httpsSameHost.MatchString(d.Arg(1)) && (code == 301 || code == 302 || code == 307 || code == 308) {
		s.httpsNames = append(s.httpsNames, "*")
		return nil
	}
	return &redirectSpec{code: code, url: d.Arg(1), at: d.At()}
}

// rewrite understands the old way of sending everything to HTTPS.
func (s *server) rewrite(d *Directive) {
	flag := d.Arg(2)
	if (flag == "permanent" || flag == "redirect") && httpsSameHost.MatchString(d.Arg(1)) {
		s.httpsNames = append(s.httpsNames, "*")
		return
	}
	s.problem(d, "rewrite %s %s: not imported", d.Arg(0), d.Arg(1))
}

var certbotIf = regexp.MustCompile(`^\(?\$host$`)

// ifBlock accepts the one kind of `if` certbot writes:
//
//	if ($host = example.com) { return 301 https://$host$request_uri; }
//
// Any other `if` may be guarding something, so the server is not
// imported.
func (s *server) ifBlock(d *Directive) {
	if len(d.Args) == 3 && certbotIf.MatchString(d.Args[0]) && d.Args[1] == "=" && len(d.Block) == 1 {
		r := d.Block[0]
		name := strings.ToLower(strings.TrimSuffix(d.Args[2], ")"))
		if r.Name == "return" && httpsSameHost.MatchString(r.Arg(1)) {
			s.httpsNames = append(s.httpsNames, name)
			return
		}
	}
	s.problem(d, "if (%s): limen cannot tell what it guards, so the server is not imported", strings.Join(d.Args, " "))
}

func parseListen(d *Directive) listen {
	var l listen
	addr := d.Arg(0)
	if strings.HasPrefix(addr, "unix:") {
		l.unsupported = "listens on a unix socket"
		return l
	}
	port := addr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		port = addr[i+1:]
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		l.unsupported = fmt.Sprintf("listen %s: cannot read the port", addr)
		return l
	}
	l.port = p
	for _, a := range d.Args[1:] {
		switch a {
		case "ssl":
			l.ssl = true
		case "http2":
			l.http2 = true
		case "default_server", "default":
			l.defaultSrv = true
		}
	}
	if p != 80 && p != 443 {
		l.unsupported = fmt.Sprintf("listens on port %d: limen serves hosts on 80 and 443", p)
	}
	return l
}

// ---------------------------------------------------------------------
// From servers to documents
// ---------------------------------------------------------------------

func (p *Plan) hosts(servers []*server, opt Options) {
	// The names some server sends to HTTPS on the same host.
	toHTTPS := map[string]bool{}
	for _, s := range servers {
		for _, n := range s.httpsNames {
			if n == "*" {
				for _, name := range s.names {
					toHTTPS[name] = true
				}
				continue
			}
			toHTTPS[n] = true
		}
	}

	// Pair the plain and the TLS server of the same names.
	type pair struct{ plain, tls *server }
	groups := map[string]*pair{}
	var keys []string
	for _, s := range servers {
		// Problems first: a server whose only name is a regular
		// expression has no name left, and is not a default server.
		if len(s.problems) > 0 {
			p.Skipped = append(p.Skipped, fmt.Sprintf("%s: %s", s.label(), strings.Join(s.problems, "; ")))
			continue
		}
		if s.isDefault() {
			p.Notes = append(p.Notes, fmt.Sprintf("%s: the default server is not imported, limen writes its own", s.d.At()))
			continue
		}
		names := append([]string(nil), s.names...)
		sort.Strings(names)
		key := strings.Join(names, " ")
		g, ok := groups[key]
		if !ok {
			g = &pair{}
			groups[key] = g
			keys = append(keys, key)
		}
		if s.hasSSL() {
			if g.tls != nil {
				p.Skipped = append(p.Skipped, fmt.Sprintf("%s: a second TLS server for the same names", s.label()))
				continue
			}
			g.tls = s
		} else {
			if g.plain != nil {
				p.Skipped = append(p.Skipped, fmt.Sprintf("%s: a second plain server for the same names", s.label()))
				continue
			}
			g.plain = s
		}
	}
	sort.Strings(keys)

	for _, key := range keys {
		g := groups[key]
		main := g.tls
		if main == nil {
			main = g.plain
		}
		// A plain server whose whole job is sending its names to HTTPS
		// becomes the host's force_https; there is nothing else in it.
		if main == g.plain && main.proxy == nil && main.redirect == nil && allIn(main.names, toHTTPS) {
			p.Skipped = append(p.Skipped, fmt.Sprintf("%s: it only sends its names to HTTPS, and no TLS server here answers on them", main.label()))
			continue
		}
		if g.tls != nil && g.plain != nil && (g.plain.proxy != nil || g.plain.redirect != nil) &&
			!(g.plain.proxy != nil && g.tls.proxy != nil && *g.plain.proxy == *g.tls.proxy) {
			p.Notes = append(p.Notes, fmt.Sprintf("%s: the plain HTTP server does something else than the TLS one; the TLS one is imported", g.plain.label()))
		}

		switch {
		case main.proxy != nil:
			p.proxyHost(main, allIn(main.names, toHTTPS) && main.hasSSL(), opt)
		case main.redirect != nil && main.redirect.url != "":
			p.redirectDoc(main, allIn(main.names, toHTTPS) && main.hasSSL(), opt)
		default:
			p.Skipped = append(p.Skipped, fmt.Sprintf("%s: it neither proxies nor redirects", main.label()))
		}
	}
}

func allIn(names []string, set map[string]bool) bool {
	if len(names) == 0 {
		return false
	}
	for _, n := range names {
		if !set[n] {
			return false
		}
	}
	return true
}

// docName names an imported document after its first domain.
func docName(domain string) string {
	n := strings.Replace(domain, "*.", "wildcard.", 1)
	if len(n) > 64 {
		n = strings.TrimRight(n[:64], ".-_")
	}
	return n
}

func (p *Plan) proxyHost(s *server, forceHTTPS bool, opt Options) {
	name := docName(s.names[0])
	if opt.Exists != nil && opt.Exists(model.KindProxyHost, name) {
		p.Skipped = append(p.Skipped, fmt.Sprintf("%s: a proxy host named %q already exists, it is not overwritten", s.label(), name))
		return
	}
	h := model.NewProxyHost(name)
	h.Description = "imported from " + s.d.At()
	h.Domains = s.names
	h.Forward = *s.proxy
	h.Websockets = s.websockets
	h.ClientMaxBodySize = s.maxBody
	for _, l := range s.locations {
		if l.Forward != nil && *l.Forward == h.Forward {
			l.Forward = nil // the host's own backend: say so
		}
		h.Locations = append(h.Locations, l)
	}
	// Imported hosts keep what they did: no exploit blocking they did
	// not have before.
	h.BlockExploits = false

	if acl, ok := p.accessList(s, name, opt); !ok {
		return
	} else if acl != nil {
		h.AccessList = acl.Name
		p.Docs = append(p.Docs, acl)
	}

	if s.hasSSL() {
		if s.cert == "" || s.key == "" {
			p.Notes = append(p.Notes, fmt.Sprintf("%s: TLS without ssl_certificate here, imported as plain HTTP", s.label()))
		} else {
			if !p.certificate(s, name, opt) {
				return
			}
			h.TLS = model.TLS{
				Certificate: name, ForceHTTPS: forceHTTPS, HTTP2: s.http2 || anyHTTP2(s),
				HSTS: s.hsts, HSTSSubdomains: s.hsts && s.hstsSub,
			}
		}
	}
	if err := h.Validate(); err != nil {
		p.Skipped = append(p.Skipped, fmt.Sprintf("%s: %v", s.label(), err))
		return
	}
	p.note(s)
	p.Docs = append(p.Docs, h)
}

// certificate plans the copy of a server's certificate and the custom
// certificate document hosts refer to it by. It reports false, with the
// reason, when the name is taken.
func (p *Plan) certificate(s *server, name string, opt Options) bool {
	if opt.Exists != nil && opt.Exists(model.KindCertificate, name) {
		p.Skipped = append(p.Skipped, fmt.Sprintf("%s: a certificate named %q already exists, it is not overwritten", s.label(), name))
		return false
	}
	c := model.NewCertificate(name)
	c.Provider, c.Challenge = model.ProviderCustom, ""
	c.Description = "imported from " + s.d.At()
	c.Domains = s.names
	p.Certs = append(p.Certs, CertCopy{Name: name, Chain: s.cert, Key: s.key})
	p.Docs = append(p.Docs, c)
	return true
}

func anyHTTP2(s *server) bool {
	for _, l := range s.listens {
		if l.http2 {
			return true
		}
	}
	return false
}

// accessList imports the guard of a server. ok=false means the server
// must not be imported at all: its guard cannot be kept.
func (p *Plan) accessList(s *server, host string, opt Options) (*model.AccessList, bool) {
	if (s.authFile == "" || s.authOff) && len(s.rules) == 0 {
		return nil, true
	}
	name := docName(host + "-access")
	if opt.Exists != nil && opt.Exists(model.KindAccessList, name) {
		p.Skipped = append(p.Skipped, fmt.Sprintf("%s: an access list named %q already exists; the host is not imported without its own", s.label(), name))
		return nil, false
	}
	a := model.NewAccessList(name)
	a.Description = "imported from " + s.d.At()
	a.Rules = s.rules
	a.SatisfyAny = s.satisfyAny
	// nginx passes the Authorization header on unless told not to.
	a.PassAuth = !s.stripAuth

	if s.authFile != "" && !s.authOff {
		if opt.ReadFile == nil {
			p.Skipped = append(p.Skipped, fmt.Sprintf("%s: its htpasswd file cannot be read here", s.label()))
			return nil, false
		}
		b, err := opt.ReadFile(s.authFile)
		if err != nil {
			p.Skipped = append(p.Skipped, fmt.Sprintf("%s: htpasswd %s: %v; not imported without its users", s.label(), s.authFile, err))
			return nil, false
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, ":", 3)
			if len(parts) < 2 {
				continue
			}
			if !strings.HasPrefix(parts[1], "$apr1$") {
				p.Skipped = append(p.Skipped, fmt.Sprintf("%s: user %q in %s has a hash limen does not keep (only apr1, as htpasswd -m writes); "+
					"not imported without it — recreate it with `limen access passwd`", s.label(), parts[0], s.authFile))
				return nil, false
			}
			a.Users = append(a.Users, model.BasicUser{Username: parts[0], Password: parts[1]})
		}
	}
	if err := a.Validate(); err != nil {
		p.Skipped = append(p.Skipped, fmt.Sprintf("%s: access list: %v; not imported without it", s.label(), err))
		return nil, false
	}
	return a, true
}

func (p *Plan) redirectDoc(s *server, forceHTTPS bool, opt Options) {
	name := docName(s.names[0])
	if opt.Exists != nil && opt.Exists(model.KindRedirect, name) {
		p.Skipped = append(p.Skipped, fmt.Sprintf("%s: a redirect named %q already exists, it is not overwritten", s.label(), name))
		return
	}
	target, err := parseTarget(s.redirect.url)
	if err != nil {
		p.Skipped = append(p.Skipped, fmt.Sprintf("%s: %s: %v", s.label(), s.redirect.at, err))
		return
	}
	r := model.NewRedirect(name)
	r.Description = "imported from " + s.d.At()
	r.Domains = s.names
	r.Target = target
	r.Code = s.redirect.code
	r.BlockExploits = false
	if s.hasSSL() && s.cert != "" && s.key != "" {
		if !p.certificate(s, name, opt) {
			return
		}
		r.TLS = model.TLS{Certificate: name, ForceHTTPS: forceHTTPS, HTTP2: s.http2 || anyHTTP2(s), HSTS: s.hsts, HSTSSubdomains: s.hsts && s.hstsSub}
	}
	if err := r.Validate(); err != nil {
		p.Skipped = append(p.Skipped, fmt.Sprintf("%s: %v", s.label(), err))
		return
	}
	p.note(s)
	p.Docs = append(p.Docs, r)
}

// parseTarget reads the URL of a return into a redirect target: scheme,
// host and port, with $request_uri as "keep the path".
func parseTarget(raw string) (model.Target, error) {
	t := model.Target{}
	rest := raw
	switch {
	case strings.HasPrefix(rest, "$scheme://"):
		t.Scheme, rest = "auto", strings.TrimPrefix(rest, "$scheme://")
	case strings.HasPrefix(rest, "https://"):
		t.Scheme, rest = "https", strings.TrimPrefix(rest, "https://")
	case strings.HasPrefix(rest, "http://"):
		t.Scheme, rest = "http", strings.TrimPrefix(rest, "http://")
	default:
		return t, fmt.Errorf("redirect to %q: not an absolute URL", raw)
	}
	if strings.HasSuffix(rest, "$request_uri") {
		t.PreservePath = true
		rest = strings.TrimSuffix(rest, "$request_uri")
	}
	rest = strings.TrimSuffix(rest, "/")
	if strings.ContainsAny(rest, "/$?#") {
		return t, fmt.Errorf("redirect to %q: limen keeps a scheme, a host and a port, not a path or variables", raw)
	}
	t.Domain = strings.ToLower(rest)
	return t, nil
}

func (p *Plan) note(s *server) {
	if len(s.ignored) > 0 {
		sort.Strings(s.ignored)
		p.Notes = append(p.Notes, fmt.Sprintf("%s: imported without %s", s.label(), strings.Join(s.ignored, ", ")))
	}
}

// ---------------------------------------------------------------------
// Streams
// ---------------------------------------------------------------------

func (p *Plan) stream(d *Directive, upstreams map[string][]string, opt Options) {
	label := "stream server (" + d.At() + ")"
	var ports []int
	protos := map[string]bool{}
	target := ""
	for _, c := range d.Block {
		switch c.Name {
		case "listen":
			addr := c.Arg(0)
			if i := strings.LastIndex(addr, ":"); i >= 0 {
				addr = addr[i+1:]
			}
			port, err := strconv.Atoi(addr)
			if err != nil {
				p.Skipped = append(p.Skipped, fmt.Sprintf("%s: listen %s: cannot read the port", label, c.Arg(0)))
				return
			}
			ports = append(ports, port)
			proto := "tcp"
			for _, a := range c.Args[1:] {
				if a == "udp" {
					proto = "udp"
				}
				if a == "ssl" {
					p.Skipped = append(p.Skipped, fmt.Sprintf("%s: it terminates TLS, which limen streams do not", label))
					return
				}
			}
			protos[proto] = true
		case "proxy_pass":
			target = c.Arg(0)
		default:
			if why, ok := guarding[c.Name]; ok || c.Name == "allow" || c.Name == "deny" {
				if !ok {
					why = "restricts addresses"
				}
				p.Skipped = append(p.Skipped, fmt.Sprintf("%s: %s %s, which limen streams cannot keep; not imported open", label, c.Name, why))
				return
			}
		}
	}
	if len(ports) == 0 || target == "" {
		p.Skipped = append(p.Skipped, fmt.Sprintf("%s: no listen or no proxy_pass", label))
		return
	}
	for _, port := range ports[1:] {
		if port != ports[0] {
			p.Skipped = append(p.Skipped, fmt.Sprintf("%s: listens on several ports", label))
			return
		}
	}
	if servers, ok := upstreams[target]; ok {
		if len(servers) != 1 {
			p.Skipped = append(p.Skipped, fmt.Sprintf("%s: balances across %d servers", label, len(servers)))
			return
		}
		target = servers[0]
	}
	ep, err := model.ParseEndpoint(target)
	if err != nil {
		p.Skipped = append(p.Skipped, fmt.Sprintf("%s: proxy_pass %v", label, err))
		return
	}
	name := fmt.Sprintf("port-%d", ports[0])
	if opt.Exists != nil && opt.Exists(model.KindStream, name) {
		p.Skipped = append(p.Skipped, fmt.Sprintf("%s: a stream named %q already exists", label, name))
		return
	}
	s := model.NewStream(name)
	s.Description = "imported from " + d.At()
	s.Listen = ports[0]
	s.Forward = ep
	s.Protocols = nil
	for _, proto := range []string{"tcp", "udp"} {
		if protos[proto] {
			s.Protocols = append(s.Protocols, proto)
		}
	}
	if err := s.Validate(); err != nil {
		p.Skipped = append(p.Skipped, fmt.Sprintf("%s: %v", label, err))
		return
	}
	p.Docs = append(p.Docs, s)
}
