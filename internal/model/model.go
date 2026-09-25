// Package model defines the objects limen manages: proxy hosts,
// redirects, streams, access lists and panel users.
//
// Each object is one YAML document in a file of its own, named after
// the object. The package knows the shape of a document and the rules
// a single document must obey on its own; the rules that span several
// documents (a domain served twice, an access list that does not
// exist) belong to the store, which sees all of them at once.
//
// Loading follows the same idiom as the daemon configuration: the
// document is decoded on top of its defaults, so a hand-written file
// may omit anything it does not care about — and a host that says
// nothing about `enabled` is enabled, not silently switched off.
package model

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Kind names the type of a document. It is written in every file, so
// that a document read out of context (in the history, in a bug
// report) still says what it is.
type Kind string

// The kinds of document limen manages.
const (
	KindProxyHost   Kind = "proxy_host"
	KindRedirect    Kind = "redirect"
	KindStream      Kind = "stream"
	KindAccessList  Kind = "access_list"
	KindUser        Kind = "user"
	KindCertificate Kind = "certificate"
)

// String is the name a person reads: "proxy host", not "proxy_host".
// Messages and logs go through it; the files, the JSON and the history
// paths use the value itself (string(k)), which never changes.
func (k Kind) String() string {
	switch k {
	case KindProxyHost:
		return "proxy host"
	case KindAccessList:
		return "access list"
	}
	return string(k)
}

// Kinds lists every kind, in the order they are loaded: access lists
// and certificates before the hosts that refer to them.
var Kinds = []Kind{KindAccessList, KindCertificate, KindUser, KindProxyHost, KindRedirect, KindStream}

// ParseKind accepts the canonical name and the short names the command
// line uses.
func ParseKind(s string) (Kind, error) {
	switch strings.ToLower(s) {
	case "proxy_host", "host", "hosts":
		return KindProxyHost, nil
	case "redirect", "redirects":
		return KindRedirect, nil
	case "stream", "streams":
		return KindStream, nil
	case "access_list", "access", "acl":
		return KindAccessList, nil
	case "user", "users":
		return KindUser, nil
	case "certificate", "certificates", "cert", "certs":
		return KindCertificate, nil
	}
	return "", fmt.Errorf("unknown kind %q: want host, redirect, stream, access, cert or user", s)
}

// Meta is the part every document shares.
type Meta struct {
	Kind Kind   `yaml:"kind" json:"kind"`
	Name string `yaml:"name" json:"name"`

	// Description is free text for the operator ("staging of customer
	// X"). The reason for a single change is not kept here but in the
	// history, next to the revision it replaced.
	Description string `yaml:"description,omitempty" json:"description,omitempty"`

	// Protected objects cannot be deleted, renamed or disabled: the
	// virtual host that publishes the panel is one, because removing it
	// locks the operator out of the tool that would put it back.
	Protected bool `yaml:"protected,omitempty" json:"protected,omitempty"`

	Created time.Time `yaml:"created" json:"created"`
	Updated time.Time `yaml:"updated" json:"updated"`
}

// Document is what the store keeps: any of the objects below.
type Document interface {
	Header() *Meta
	Validate() error
}

// Header returns the shared metadata.
func (m *Meta) Header() *Meta { return m }

// ---------------------------------------------------------------------
// Proxy host
// ---------------------------------------------------------------------

// ProxyHost publishes a backend under one or more domain names.
type ProxyHost struct {
	Meta `yaml:",inline"`

	Enabled bool     `yaml:"enabled" json:"enabled"`
	Domains []string `yaml:"domains" json:"domains"`
	Forward Upstream `yaml:"forward" json:"forward"`
	TLS     TLS      `yaml:"tls" json:"tls"`

	// AccessList names an access list that guards the whole host.
	AccessList string `yaml:"access_list,omitempty" json:"access_list,omitempty"`

	Websockets        bool   `yaml:"websockets" json:"websockets"`
	BlockExploits     bool   `yaml:"block_exploits" json:"block_exploits"`
	CacheAssets       bool   `yaml:"cache_assets" json:"cache_assets"`
	ClientMaxBodySize string `yaml:"client_max_body_size,omitempty" json:"client_max_body_size,omitempty"`

	// LogRequests writes every request to the host's access log, which
	// the log viewer shows and the traffic metrics are counted from.
	// Off, the host keeps only its error log.
	LogRequests bool `yaml:"log_requests" json:"log_requests"`

	// Proxy is how nginx talks to the backend, for every location.
	Proxy ProxyOptions `yaml:"proxy,omitempty" json:"proxy"`

	// Locations send parts of the host elsewhere, or guard them
	// differently. Everything else goes to Forward.
	Locations []Location `yaml:"locations,omitempty" json:"locations,omitempty"`

	// Snippet holds directives written by hand (see ParseSnippet),
	// applied to every location of the host.
	Snippet string `yaml:"snippet,omitempty" json:"snippet,omitempty"`
}

// ProxyOptions tune the conversation with the backend. The zero value
// is limen's default.
type ProxyOptions struct {
	// Timeouts, in nginx's notation ("30s", "5m"). Empty: 60s to
	// connect, 300s between two reads or two writes.
	ConnectTimeout string `yaml:"connect_timeout,omitempty" json:"connect_timeout,omitempty"`
	ReadTimeout    string `yaml:"read_timeout,omitempty" json:"read_timeout,omitempty"`
	SendTimeout    string `yaml:"send_timeout,omitempty" json:"send_timeout,omitempty"`

	// StreamResponses passes the response on as it arrives instead of
	// buffering it (proxy_buffering off): server-sent events, long
	// polling, large downloads.
	StreamResponses bool `yaml:"stream_responses,omitempty" json:"stream_responses"`
	// StreamRequests passes the request body on as it arrives instead
	// of reading it whole first (proxy_request_buffering off): uploads
	// the backend wants to see progressing.
	StreamRequests bool `yaml:"stream_requests,omitempty" json:"stream_requests"`

	// HostHeader is the Host the backend sees: empty for the one the
	// client asked for, "upstream" for the backend's own address, or a
	// host name.
	HostHeader string `yaml:"host_header,omitempty" json:"host_header,omitempty"`

	// RequestHeaders are set on the request to the backend; values may
	// use nginx variables ($request_id). ResponseHeaders are added to
	// the response, on every status.
	RequestHeaders  []Header `yaml:"request_headers,omitempty" json:"request_headers,omitempty"`
	ResponseHeaders []Header `yaml:"response_headers,omitempty" json:"response_headers,omitempty"`
}

// Header is one HTTP header.
type Header struct {
	Name  string `yaml:"name" json:"name"`
	Value string `yaml:"value" json:"value"`
}

// HostHeaderUpstream sends the backend's own address as Host.
const HostHeaderUpstream = "upstream"

// Location is a part of a proxy host handled on its own.
type Location struct {
	// Path is where it starts ("/api/"), or, with Exact, the one path
	// it answers.
	Path  string `yaml:"path" json:"path"`
	Exact bool   `yaml:"exact,omitempty" json:"exact"`

	// Forward is the backend of this location; nil sends it to the
	// host's.
	Forward *Upstream `yaml:"forward,omitempty" json:"forward"`

	// AccessList guards this location instead of the host's. Public
	// lets it through without any, even when the host has one.
	AccessList string `yaml:"access_list,omitempty" json:"access_list,omitempty"`
	Public     bool   `yaml:"public,omitempty" json:"public"`

	Websockets bool   `yaml:"websockets,omitempty" json:"websockets"`
	Snippet    string `yaml:"snippet,omitempty" json:"snippet,omitempty"`
}

// Match renders how nginx matches the location: "= /x" or "/x/".
func (l Location) Match() string {
	if l.Exact {
		return "= " + l.Path
	}
	return l.Path
}

// Upstream is where a proxy host sends its traffic.
type Upstream struct {
	Scheme string `yaml:"scheme" json:"scheme"` // http or https
	Host   string `yaml:"host" json:"host"`
	Port   int    `yaml:"port" json:"port"`

	// Socket is a unix socket path to send the traffic to instead of
	// host and port. limen uses it for its own panel, when the panel
	// listens on a socket.
	Socket string `yaml:"socket,omitempty" json:"socket,omitempty"`

	// VerifyTLS checks the upstream certificate when Scheme is https.
	// Off by default: a backend on the private network usually has a
	// self-signed one, and refusing it would be the first surprise.
	VerifyTLS bool `yaml:"verify_tls" json:"verify_tls"`
}

// String renders the upstream as a URL, in the form proxy_pass takes.
func (u Upstream) String() string {
	if u.Socket != "" {
		return u.Scheme + "://unix:" + u.Socket + ":"
	}
	return u.Scheme + "://" + net.JoinHostPort(u.Host, strconv.Itoa(u.Port))
}

// TLS is how a host or a redirect is served over HTTPS.
type TLS struct {
	// Certificate names the certificate to serve. Empty means plain
	// HTTP only.
	Certificate    string `yaml:"certificate,omitempty" json:"certificate,omitempty"`
	ForceHTTPS     bool   `yaml:"force_https" json:"force_https"`
	HTTP2          bool   `yaml:"http2" json:"http2"`
	HSTS           bool   `yaml:"hsts" json:"hsts"`
	HSTSSubdomains bool   `yaml:"hsts_subdomains" json:"hsts_subdomains"`
}

// NewProxyHost returns a proxy host carrying every default.
func NewProxyHost(name string) *ProxyHost {
	return &ProxyHost{
		Kind: KindProxyHost, Name: name,
		Enabled:       true,
		Forward:       Upstream{Scheme: "http", Port: 80},
		TLS:           TLS{HTTP2: true},
		BlockExploits: true,
		LogRequests:   true,
	}
}

// Validate checks the host on its own.
func (h *ProxyHost) Validate() error {
	if err := h.Meta.validate(KindProxyHost); err != nil {
		return err
	}
	if err := validateDomains(h.Domains); err != nil {
		return err
	}
	if err := h.Forward.validate(); err != nil {
		return err
	}
	if err := h.TLS.validate(); err != nil {
		return err
	}
	if h.AccessList != "" {
		if err := ValidateName(h.AccessList); err != nil {
			return fmt.Errorf("access_list: %w", err)
		}
	}
	if h.ClientMaxBodySize != "" && !sizeRe.MatchString(h.ClientMaxBodySize) {
		return fmt.Errorf("client_max_body_size %q: want a number with an optional k, m or g suffix", h.ClientMaxBodySize)
	}
	if err := h.Proxy.validate(); err != nil {
		return err
	}
	if h.Snippet != "" {
		if _, err := ParseSnippet(h.Snippet); err != nil {
			return err
		}
	}
	if len(h.Locations) > 64 {
		return fmt.Errorf("locations: %d, at most 64", len(h.Locations))
	}
	seen := map[string]bool{}
	for _, l := range h.Locations {
		if err := l.validate(); err != nil {
			return fmt.Errorf("location %s: %w", l.Match(), err)
		}
		if seen[l.Match()] {
			return fmt.Errorf("location %s listed twice", l.Match())
		}
		seen[l.Match()] = true
	}
	if h.Protected && !h.Enabled {
		return fmt.Errorf("a protected host cannot be disabled")
	}
	return nil
}

var (
	// locationPathRe is what a path may hold: the unreserved and
	// sub-delimiter characters of a URL path, and percent escapes.
	locationPathRe = regexp.MustCompile(`^/[A-Za-z0-9._~%!$&'()*+,;=:@/-]{0,254}$`)
	timeRe         = regexp.MustCompile(`^[0-9]{1,6}(ms|s|m|h|d)?$`)
)

func (l Location) validate() error {
	if !locationPathRe.MatchString(l.Path) {
		return fmt.Errorf("path %q: starts with / and holds only URL path characters", l.Path)
	}
	if l.Path == "/" && !l.Exact {
		return fmt.Errorf("the whole host is the host's own forward: a location is a part of it")
	}
	if strings.HasPrefix(l.Path, "/.well-known/acme-challenge") {
		// limen answers the challenges there; a location of its own
		// would take them over and no certificate could be issued.
		return fmt.Errorf("path %q is where limen answers ACME challenges", l.Path)
	}
	if l.Forward != nil {
		if l.Forward.Socket != "" {
			return fmt.Errorf("forward.socket is reserved for limen's own panel")
		}
		if err := l.Forward.validate(); err != nil {
			return err
		}
	}
	if l.Public && l.AccessList != "" {
		return fmt.Errorf("public and access_list %q: one or the other", l.AccessList)
	}
	if l.AccessList != "" {
		if err := ValidateName(l.AccessList); err != nil {
			return fmt.Errorf("access_list: %w", err)
		}
	}
	if l.Snippet != "" {
		if _, err := ParseSnippet(l.Snippet); err != nil {
			return err
		}
	}
	return nil
}

func (p ProxyOptions) validate() error {
	for _, t := range []struct{ name, v string }{
		{"proxy.connect_timeout", p.ConnectTimeout},
		{"proxy.read_timeout", p.ReadTimeout},
		{"proxy.send_timeout", p.SendTimeout},
	} {
		if t.v != "" && !timeRe.MatchString(t.v) {
			return fmt.Errorf("%s %q: want a number with ms, s, m, h or d", t.name, t.v)
		}
	}
	if p.HostHeader != "" && p.HostHeader != HostHeaderUpstream {
		if err := validateTarget(p.HostHeader); err != nil {
			return fmt.Errorf("proxy.host_header: %w; or \"upstream\" for the backend's address", err)
		}
	}
	if err := validateHeaders("proxy.request_headers", p.RequestHeaders); err != nil {
		return err
	}
	return validateHeaders("proxy.response_headers", p.ResponseHeaders)
}

func validateHeaders(field string, hs []Header) error {
	if len(hs) > 32 {
		return fmt.Errorf("%s: %d headers, at most 32", field, len(hs))
	}
	seen := map[string]bool{}
	for _, h := range hs {
		if !headerRe.MatchString(h.Name) {
			return fmt.Errorf("%s: header name %q: letters, digits and - only", field, h.Name)
		}
		key := strings.ToLower(h.Name)
		if seen[key] {
			return fmt.Errorf("%s: %s listed twice", field, h.Name)
		}
		seen[key] = true
		if key == "host" {
			return fmt.Errorf("%s: Host is proxy.host_header", field)
		}
		if len(h.Value) > 1024 || strings.ContainsFunc(h.Value, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return fmt.Errorf("%s: %s: up to 1024 characters, no control characters", field, h.Name)
		}
	}
	return nil
}

var socketRe = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)

func (u Upstream) validate() error {
	switch u.Scheme {
	case "http", "https":
	default:
		return fmt.Errorf("forward.scheme %q: want http or https", u.Scheme)
	}
	if u.Socket != "" {
		if !socketRe.MatchString(u.Socket) || strings.Contains(u.Socket, "..") {
			return fmt.Errorf("forward.socket %q: an absolute path of letters, digits and . _ - /", u.Socket)
		}
		return nil
	}
	if err := validateTarget(u.Host); err != nil {
		return fmt.Errorf("forward.host: %w", err)
	}
	if u.Port < 1 || u.Port > 65535 {
		return fmt.Errorf("forward.port %d: want 1-65535", u.Port)
	}
	return nil
}

func (t TLS) validate() error {
	if t.Certificate == "" {
		// Without a certificate there is no HTTPS to force or to pin:
		// asking for it would render a host that redirects to a port
		// nothing answers on.
		if t.ForceHTTPS {
			return fmt.Errorf("tls.force_https needs a certificate")
		}
		if t.HSTS {
			return fmt.Errorf("tls.hsts needs a certificate")
		}
		return nil
	}
	if err := ValidateName(t.Certificate); err != nil {
		return fmt.Errorf("tls.certificate: %w", err)
	}
	if t.HSTSSubdomains && !t.HSTS {
		return fmt.Errorf("tls.hsts_subdomains needs tls.hsts")
	}
	return nil
}

// ---------------------------------------------------------------------
// Redirect
// ---------------------------------------------------------------------

// Redirect sends every request for its domains somewhere else.
type Redirect struct {
	Meta `yaml:",inline"`

	Enabled bool     `yaml:"enabled" json:"enabled"`
	Domains []string `yaml:"domains" json:"domains"`
	Target  Target   `yaml:"target" json:"target"`
	Code    int      `yaml:"code" json:"code"`
	TLS     TLS      `yaml:"tls" json:"tls"`

	BlockExploits bool `yaml:"block_exploits" json:"block_exploits"`
}

// Target is the destination of a redirect.
type Target struct {
	Scheme string `yaml:"scheme" json:"scheme"` // http, https, or "auto" to keep the request's
	Domain string `yaml:"domain" json:"domain"`

	// PreservePath appends the original path and query to the target.
	PreservePath bool `yaml:"preserve_path" json:"preserve_path"`
}

// String renders the target as a URL prefix.
func (t Target) String() string {
	if t.Scheme == "auto" {
		return "$scheme://" + t.Domain
	}
	return t.Scheme + "://" + t.Domain
}

// NewRedirect returns a redirect carrying every default.
func NewRedirect(name string) *Redirect {
	return &Redirect{
		Kind: KindRedirect, Name: name,
		Enabled:       true,
		Target:        Target{Scheme: "auto", PreservePath: true},
		Code:          301,
		TLS:           TLS{HTTP2: true},
		BlockExploits: true,
	}
}

// Validate checks the redirect on its own.
func (r *Redirect) Validate() error {
	if err := r.Meta.validate(KindRedirect); err != nil {
		return err
	}
	if err := validateDomains(r.Domains); err != nil {
		return err
	}
	switch r.Target.Scheme {
	case "http", "https", "auto":
	default:
		return fmt.Errorf("target.scheme %q: want http, https or auto", r.Target.Scheme)
	}
	host := r.Target.Domain
	if h, port, err := net.SplitHostPort(host); err == nil {
		if p, perr := strconv.Atoi(port); perr != nil || p < 1 || p > 65535 {
			return fmt.Errorf("target.domain %q: invalid port", r.Target.Domain)
		}
		host = h
	}
	if err := validateTarget(host); err != nil {
		return fmt.Errorf("target.domain: %w", err)
	}
	for _, d := range r.Domains {
		if d == strings.ToLower(host) {
			// A redirect to itself is an infinite loop for every
			// browser that follows it.
			return fmt.Errorf("target.domain %q is one of the redirect's own domains", r.Target.Domain)
		}
	}
	switch r.Code {
	case 301, 302, 307, 308:
	default:
		return fmt.Errorf("code %d: want 301, 302, 307 or 308", r.Code)
	}
	if err := r.TLS.validate(); err != nil {
		return err
	}
	if r.Protected && !r.Enabled {
		return fmt.Errorf("a protected redirect cannot be disabled")
	}
	return nil
}

// ---------------------------------------------------------------------
// Stream
// ---------------------------------------------------------------------

// Stream forwards a raw TCP and/or UDP port.
type Stream struct {
	Meta `yaml:",inline"`

	Enabled   bool     `yaml:"enabled" json:"enabled"`
	Listen    int      `yaml:"listen_port" json:"listen_port"`
	Protocols []string `yaml:"protocols" json:"protocols"`
	Forward   Endpoint `yaml:"forward" json:"forward"`

	// AccessList restricts who may connect, by address: a stream has no
	// way to ask for a password, so the list must have rules only.
	AccessList string `yaml:"access_list,omitempty" json:"access_list,omitempty"`
}

// Endpoint is a host and a port.
type Endpoint struct {
	Host string `yaml:"host" json:"host"`
	Port int    `yaml:"port" json:"port"`
}

// String renders the endpoint as host:port.
func (e Endpoint) String() string { return net.JoinHostPort(e.Host, strconv.Itoa(e.Port)) }

// NewStream returns a stream carrying every default.
func NewStream(name string) *Stream {
	return &Stream{
		Kind: KindStream, Name: name,
		Enabled:   true,
		Protocols: []string{"tcp"},
	}
}

// Has reports whether the stream carries the given protocol.
func (s *Stream) Has(proto string) bool {
	return slices.Contains(s.Protocols, proto)
}

// Validate checks the stream on its own.
func (s *Stream) Validate() error {
	if err := s.Meta.validate(KindStream); err != nil {
		return err
	}
	if s.Listen < 1 || s.Listen > 65535 {
		return fmt.Errorf("listen_port %d: want 1-65535", s.Listen)
	}
	if s.Listen == 80 || s.Listen == 443 {
		// nginx already listens there for every HTTP host; a stream on
		// the same port would make the whole configuration fail to bind.
		return fmt.Errorf("listen_port %d is reserved for the HTTP hosts", s.Listen)
	}
	if len(s.Protocols) == 0 {
		return fmt.Errorf("protocols: want tcp, udp or both")
	}
	seen := map[string]bool{}
	for _, p := range s.Protocols {
		if p != "tcp" && p != "udp" {
			return fmt.Errorf("protocols: %q is neither tcp nor udp", p)
		}
		if seen[p] {
			return fmt.Errorf("protocols: %q listed twice", p)
		}
		seen[p] = true
	}
	if err := validateTarget(s.Forward.Host); err != nil {
		return fmt.Errorf("forward.host: %w", err)
	}
	if s.Forward.Port < 1 || s.Forward.Port > 65535 {
		return fmt.Errorf("forward.port %d: want 1-65535", s.Forward.Port)
	}
	if s.AccessList != "" {
		if err := ValidateName(s.AccessList); err != nil {
			return fmt.Errorf("access_list: %w", err)
		}
	}
	if s.Protected && !s.Enabled {
		return fmt.Errorf("a protected stream cannot be disabled")
	}
	return nil
}

// ---------------------------------------------------------------------
// Access list
// ---------------------------------------------------------------------

// AccessList guards a host with basic authentication, address rules,
// or both.
type AccessList struct {
	Meta `yaml:",inline"`

	// SatisfyAny lets a request in when it passes EITHER the address
	// rules OR the authentication; by default it must pass both.
	SatisfyAny bool `yaml:"satisfy_any" json:"satisfy_any"`

	// PassAuth forwards the Authorization header to the backend. Off by
	// default: the credentials are the gate's, not the application's.
	PassAuth bool `yaml:"pass_auth" json:"pass_auth"`

	Users []BasicUser `yaml:"users,omitempty" json:"users,omitempty"`
	Rules []Rule      `yaml:"rules,omitempty" json:"rules,omitempty"`
}

// BasicUser is one basic-auth credential. Password holds a hash nginx
// can verify on its own (see package secret), never the password.
type BasicUser struct {
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"-"`
}

// Rule allows or denies an address or a network. Rules are evaluated
// in order and the first match wins, exactly as nginx does.
type Rule struct {
	Action  string `yaml:"action" json:"action"` // allow or deny
	Address string `yaml:"address" json:"address"`
}

// AccessLists lists the access lists a host refers to, its own and its
// locations', each once.
func (h *ProxyHost) AccessLists() []string {
	var out []string
	seen := map[string]bool{}
	names := []string{h.AccessList}
	for _, l := range h.Locations {
		names = append(names, l.AccessList)
	}
	for _, name := range names {
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

// NewAccessList returns an empty access list.
func NewAccessList(name string) *AccessList {
	return &AccessList{Kind: KindAccessList, Name: name}
}

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

// Validate checks the access list on its own.
func (a *AccessList) Validate() error {
	if err := a.Meta.validate(KindAccessList); err != nil {
		return err
	}
	if len(a.Users) == 0 && len(a.Rules) == 0 {
		return fmt.Errorf("an access list needs at least one user or one rule")
	}
	seen := map[string]bool{}
	for _, u := range a.Users {
		// The username ends up in an htpasswd file, where a colon or a
		// newline would split or add a line.
		if !usernameRe.MatchString(u.Username) {
			return fmt.Errorf("user %q: letters, digits and . _ @ - only, up to 64", u.Username)
		}
		if seen[u.Username] {
			return fmt.Errorf("user %q listed twice", u.Username)
		}
		seen[u.Username] = true
		if !strings.HasPrefix(u.Password, "$apr1$") {
			return fmt.Errorf("user %q: password is not an apr1 hash; set it with `limen access set`", u.Username)
		}
	}
	for i, r := range a.Rules {
		if r.Action != "allow" && r.Action != "deny" {
			return fmt.Errorf("rule %d: action %q, want allow or deny", i+1, r.Action)
		}
		if r.Address == "all" {
			continue
		}
		if _, _, err := net.ParseCIDR(r.Address); err != nil && net.ParseIP(r.Address) == nil {
			return fmt.Errorf("rule %d: %q is not an address, a network or \"all\"", i+1, r.Address)
		}
	}
	return nil
}

// ---------------------------------------------------------------------
// Certificate
// ---------------------------------------------------------------------

// Certificate providers.
const (
	ProviderACME   = "acme"   // issued and renewed by limen
	ProviderCustom = "custom" // uploaded; limen only watches its expiry
)

// Challenge types for ACME.
const (
	ChallengeHTTP = "http" // HTTP-01, answered by limen through nginx
	ChallengeDNS  = "dns"  // DNS-01, through acme.dns_hook: the only way to a wildcard
)

// Certificate is a TLS certificate hosts and redirects refer to by name.
// Its files live in /var/lib/limen/certs/<name>: they are state, not
// configuration, and this document says only what the certificate is
// for and where it comes from.
type Certificate struct {
	Meta `yaml:",inline"`

	Domains   []string `yaml:"domains" json:"domains"`
	Provider  string   `yaml:"provider" json:"provider"`
	Challenge string   `yaml:"challenge,omitempty" json:"challenge,omitempty"`
	// KeyType overrides acme.key_type for this certificate.
	KeyType string `yaml:"key_type,omitempty" json:"key_type,omitempty"`
}

// NewCertificate returns an ACME certificate over HTTP-01.
func NewCertificate(name string) *Certificate {
	return &Certificate{
		Kind: KindCertificate, Name: name,
		Provider:  ProviderACME,
		Challenge: ChallengeHTTP,
	}
}

// Wildcard reports whether the certificate names a wildcard.
func (c *Certificate) Wildcard() bool {
	for _, d := range c.Domains {
		if strings.HasPrefix(d, "*.") {
			return true
		}
	}
	return false
}

// Validate checks the certificate on its own.
func (c *Certificate) Validate() error {
	if err := c.Meta.validate(KindCertificate); err != nil {
		return err
	}
	if err := validateDomains(c.Domains); err != nil {
		return err
	}
	// Let's Encrypt's limit, and a sane one anywhere.
	if len(c.Domains) > 100 {
		return fmt.Errorf("domains: %d names, at most 100 in one certificate", len(c.Domains))
	}
	switch c.Provider {
	case ProviderACME:
		switch c.Challenge {
		case ChallengeHTTP:
			if c.Wildcard() {
				return fmt.Errorf("a wildcard can only be proven through DNS: set challenge to dns")
			}
		case ChallengeDNS:
		default:
			return fmt.Errorf("challenge %q: want http or dns", c.Challenge)
		}
	case ProviderCustom:
	default:
		return fmt.Errorf("provider %q: want acme or custom", c.Provider)
	}
	switch c.KeyType {
	case "", "ec256", "ec384", "rsa2048", "rsa4096":
	default:
		return fmt.Errorf("key_type %q: want ec256, ec384, rsa2048 or rsa4096", c.KeyType)
	}
	return nil
}

// Covers reports whether a certificate for these names serves domain:
// an exact name, or a wildcard one label deep ("*.example.com" covers
// "a.example.com", not "example.com" nor "a.b.example.com").
func Covers(names []string, domain string) bool {
	for _, n := range names {
		n = strings.ToLower(n)
		if n == domain {
			return true
		}
		if rest, ok := strings.CutPrefix(n, "*."); ok {
			if i := strings.IndexByte(domain, '.'); i > 0 && domain[i+1:] == rest && !strings.HasPrefix(domain, "*.") {
				return true
			}
			// A wildcard host is served by the same wildcard.
			if domain == n {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------
// User
// ---------------------------------------------------------------------

// Panel roles, from the most to the least powerful.
const (
	RoleAdmin    = "admin"    // everything, users included
	RoleOperator = "operator" // hosts, redirects, streams, access lists, certificates
	RoleViewer   = "viewer"   // read-only
)

// User is an account on the panel.
type User struct {
	Meta `yaml:",inline"`

	Email    string `yaml:"email,omitempty" json:"email,omitempty"`
	FullName string `yaml:"full_name,omitempty" json:"full_name,omitempty"`
	Role     string `yaml:"role" json:"role"`
	Disabled bool   `yaml:"disabled" json:"disabled"`

	// Password holds the encoded hash (see package secret).
	Password string `yaml:"password" json:"-"`
}

// NewUser returns a user carrying every default.
func NewUser(name string) *User {
	return &User{Kind: KindUser, Name: name, Role: RoleViewer}
}

// IsActiveAdmin reports whether the user can administer the panel now.
func (u *User) IsActiveAdmin() bool { return u.Role == RoleAdmin && !u.Disabled }

var emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// Validate checks the user on its own.
func (u *User) Validate() error {
	if err := u.Meta.validate(KindUser); err != nil {
		return err
	}
	switch u.Role {
	case RoleAdmin, RoleOperator, RoleViewer:
	default:
		return fmt.Errorf("role %q: want admin, operator or viewer", u.Role)
	}
	if u.Email != "" && !emailRe.MatchString(u.Email) {
		return fmt.Errorf("email %q is not an address", u.Email)
	}
	if !strings.HasPrefix(u.Password, "pbkdf2-sha256$") {
		return fmt.Errorf("password is not a pbkdf2-sha256 hash; set it with `limen user set --password-stdin`")
	}
	return nil
}

// ---------------------------------------------------------------------
// Shared rules
// ---------------------------------------------------------------------

var (
	nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$`)
	sizeRe = regexp.MustCompile(`^[0-9]{1,9}[kKmMgG]?$`)
)

// ValidateName checks an object name. The name is also the file name
// of the document, so it must never be able to leave its directory:
// no separators, no dot-dot, nothing a shell would mangle.
func ValidateName(name string) error {
	if !nameRe.MatchString(name) || strings.Contains(name, "..") {
		return fmt.Errorf("name %q: lowercase letters, digits, and . _ - inside, up to 64 characters", name)
	}
	return nil
}

func (m *Meta) validate(want Kind) error {
	if m.Kind != want {
		// This one talks about the file's own field: show the value.
		return fmt.Errorf("kind %q, want %q", string(m.Kind), string(want))
	}
	return ValidateName(m.Name)
}

// validateDomains checks the server names of a host or a redirect.
func validateDomains(domains []string) error {
	if len(domains) == 0 {
		return fmt.Errorf("domains: at least one is required")
	}
	seen := map[string]bool{}
	for _, d := range domains {
		if err := ValidateDomain(d); err != nil {
			return err
		}
		if seen[d] {
			return fmt.Errorf("domain %q listed twice", d)
		}
		seen[d] = true
	}
	return nil
}

// ValidateDomain checks a server name: a lowercase host name, possibly
// with a leading wildcard label ("*.example.com").
func ValidateDomain(d string) error {
	if d != strings.ToLower(d) {
		return fmt.Errorf("domain %q: write it in lowercase", d)
	}
	name := strings.TrimPrefix(d, "*.")
	if strings.Contains(name, "*") {
		return fmt.Errorf("domain %q: a wildcard is only allowed as the whole first label", d)
	}
	if !isHostname(name) || !strings.Contains(name, ".") {
		return fmt.Errorf("domain %q is not a fully qualified host name", d)
	}
	return nil
}

// validateTarget checks where traffic is sent: an IP address or a host
// name (single-label names are fine here: "backend" on a private
// network, or a container name).
func validateTarget(host string) error {
	if host == "" {
		return fmt.Errorf("required")
	}
	if net.ParseIP(strings.Trim(host, "[]")) != nil {
		return nil
	}
	if !isHostname(strings.ToLower(host)) {
		return fmt.Errorf("%q is neither an address nor a host name", host)
	}
	return nil
}

func isHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for label := range strings.SplitSeq(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// ParseUpstream reads "http://10.0.0.5:8080" into an Upstream. The
// port defaults to the scheme's.
func ParseUpstream(raw string) (Upstream, error) {
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Upstream{}, fmt.Errorf("forward %q: %w", raw, err)
	}
	if u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.User != nil {
		return Upstream{}, fmt.Errorf("forward %q: only scheme, host and port are allowed", raw)
	}
	up := Upstream{Scheme: u.Scheme, Host: u.Hostname()}
	switch {
	case u.Port() != "":
		p, err := strconv.Atoi(u.Port())
		if err != nil {
			return Upstream{}, fmt.Errorf("forward %q: invalid port", raw)
		}
		up.Port = p
	case u.Scheme == "https":
		up.Port = 443
	default:
		up.Port = 80
	}
	return up, up.validate()
}

// ParseEndpoint reads "10.0.0.9:5432" into an Endpoint.
func ParseEndpoint(raw string) (Endpoint, error) {
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return Endpoint{}, fmt.Errorf("%q: want host:port", raw)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return Endpoint{}, fmt.Errorf("%q: invalid port", raw)
	}
	if err := validateTarget(host); err != nil {
		return Endpoint{}, fmt.Errorf("%q: %w", raw, err)
	}
	return Endpoint{Host: host, Port: p}, nil
}
