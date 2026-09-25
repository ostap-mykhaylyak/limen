package model

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// A snippet is a few nginx directives an operator writes by hand, for a
// proxy host or one of its locations: the escape hatch for what the
// model does not say.
//
// It is not pasted into the configuration. It is read here the way
// nginx reads a configuration, each directive is checked against a
// closed list, and the renderer writes it back itself, every argument
// quoted. So a snippet cannot close its block and write into the rest
// of the machine's configuration, and it can only use directives that
// change how a request is proxied or answered — never ones that read or
// write files, load code, open or close access, or send the traffic
// somewhere else. What it may do is listed in SnippetDirectives.

// Directive is one directive of a snippet, with its arguments as nginx
// reads them (quotes removed, escapes resolved).
type Directive struct {
	Name string
	Args []string
}

// Key identifies what a directive sets, so that a directive written by
// hand replaces the one limen would have written instead of colliding
// with it. Directives that may appear several times with different
// meanings (rewrite, error_page) have no key and are only added.
func (d Directive) Key() string {
	spec := snippetDirectives[d.Name]
	switch spec.key {
	case keyName:
		return d.Name
	case keyHeader:
		return d.Name + " " + strings.ToLower(d.Args[0])
	}
	return ""
}

var (
	headerRe        = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	directiveNameRe = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,63}$`)
)

const (
	maxSnippet     = 8 << 10
	maxDirectives  = 64
	maxSnippetArgs = 16
)

type keyKind int

const (
	keyNone   keyKind = iota // repeatable: added
	keyName                  // one per block: replaces
	keyHeader                // one per block and header name: replaces
)

type directiveSpec struct {
	min, max int // arguments; max -1: no limit
	key      keyKind
	check    func(args []string) error
}

func onOff(args []string) error {
	if args[0] != "on" && args[0] != "off" {
		return fmt.Errorf("want on or off")
	}
	return nil
}

func headerName(args []string) error {
	if !headerRe.MatchString(args[0]) {
		return fmt.Errorf("header name %q", args[0])
	}
	return nil
}

func addHeader(args []string) error {
	if err := headerName(args); err != nil {
		return err
	}
	if len(args) == 3 && args[2] != "always" {
		return fmt.Errorf("the third argument can only be always")
	}
	return nil
}

func onlyOff(args []string) error {
	if args[0] != "off" {
		return fmt.Errorf("only off: a log file is not a snippet's to choose")
	}
	return nil
}

// snippetDirectives is the closed list. Every one of them is valid in a
// location, which is where the renderer writes snippets.
var snippetDirectives = map[string]directiveSpec{
	// Headers, to the backend and to the client.
	"add_header":           {2, 3, keyHeader, addHeader},
	"add_trailer":          {2, 3, keyHeader, addHeader},
	"proxy_set_header":     {2, 2, keyHeader, headerName},
	"proxy_hide_header":    {1, 1, keyHeader, headerName},
	"proxy_pass_header":    {1, 1, keyHeader, headerName},
	"proxy_ignore_headers": {1, -1, keyName, nil},

	// How the backend is talked to.
	"proxy_connect_timeout":       {1, 1, keyName, nil},
	"proxy_read_timeout":          {1, 1, keyName, nil},
	"proxy_send_timeout":          {1, 1, keyName, nil},
	"proxy_buffering":             {1, 1, keyName, onOff},
	"proxy_request_buffering":     {1, 1, keyName, onOff},
	"proxy_buffer_size":           {1, 1, keyName, nil},
	"proxy_buffers":               {2, 2, keyName, nil},
	"proxy_busy_buffers_size":     {1, 1, keyName, nil},
	"proxy_max_temp_file_size":    {1, 1, keyName, nil},
	"proxy_http_version":          {1, 1, keyName, nil},
	"proxy_redirect":              {1, 2, keyNone, nil},
	"proxy_cookie_domain":         {1, 2, keyNone, nil},
	"proxy_cookie_path":           {1, 2, keyNone, nil},
	"proxy_cookie_flags":          {1, -1, keyNone, nil},
	"proxy_intercept_errors":      {1, 1, keyName, onOff},
	"proxy_next_upstream":         {1, -1, keyName, nil},
	"proxy_next_upstream_tries":   {1, 1, keyName, nil},
	"proxy_next_upstream_timeout": {1, 1, keyName, nil},
	"proxy_ssl_server_name":       {1, 1, keyName, onOff},
	"proxy_ssl_name":              {1, 1, keyName, nil},
	"proxy_ssl_protocols":         {1, -1, keyName, nil},
	"proxy_socket_keepalive":      {1, 1, keyName, onOff},

	// The client's side of the connection.
	"client_max_body_size":    {1, 1, keyName, nil},
	"client_body_buffer_size": {1, 1, keyName, nil},
	"client_body_timeout":     {1, 1, keyName, nil},
	"keepalive_timeout":       {1, 2, keyName, nil},
	"send_timeout":            {1, 1, keyName, nil},
	"limit_rate":              {1, 1, keyName, nil},
	"limit_rate_after":        {1, 1, keyName, nil},

	// The response.
	"expires":                   {1, 2, keyName, nil},
	"etag":                      {1, 1, keyName, onOff},
	"if_modified_since":         {1, 1, keyName, nil},
	"charset":                   {1, 1, keyName, nil},
	"default_type":              {1, 1, keyName, nil},
	"chunked_transfer_encoding": {1, 1, keyName, onOff},
	"server_tokens":             {1, 1, keyName, nil},
	"gzip":                      {1, 1, keyName, onOff},
	"gzip_types":                {1, -1, keyName, nil},
	"gzip_min_length":           {1, 1, keyName, nil},
	"gzip_comp_level":           {1, 1, keyName, nil},
	"gzip_proxied":              {1, -1, keyName, nil},
	"gzip_vary":                 {1, 1, keyName, onOff},
	"sub_filter":                {2, 2, keyNone, nil},
	"sub_filter_once":           {1, 1, keyName, onOff},
	"sub_filter_types":          {1, -1, keyName, nil},
	"sub_filter_last_modified":  {1, 1, keyName, onOff},

	// Answering or rewriting instead of proxying.
	"return":                  {1, 2, keyName, nil},
	"rewrite":                 {2, 3, keyNone, nil},
	"error_page":              {2, -1, keyNone, nil},
	"set":                     {2, 2, keyNone, nil},
	"absolute_redirect":       {1, 1, keyName, onOff},
	"port_in_redirect":        {1, 1, keyName, onOff},
	"server_name_in_redirect": {1, 1, keyName, onOff},
	"recursive_error_pages":   {1, 1, keyName, onOff},

	// Logging, only to switch it off: a path would be a file nginx's
	// master process, which runs as root, opens for writing.
	"access_log":    {1, 1, keyName, onlyOff},
	"log_not_found": {1, 1, keyName, onOff},
}

// refused explains the directives people reach for that a snippet will
// not take, instead of a bare "not allowed".
var refused = map[string]string{
	"proxy_pass":            "the backend is the host's or the location's forward",
	"include":               "it would read a file limen does not control",
	"root":                  "limen proxies, it does not serve files",
	"alias":                 "limen proxies, it does not serve files",
	"try_files":             "limen proxies, it does not serve files",
	"error_log":             "a log path is a file nginx opens as root",
	"allow":                 "access is an access list's business: give the location one",
	"deny":                  "access is an access list's business: give the location one",
	"satisfy":               "access is an access list's business: give the location one",
	"auth_basic":            "access is an access list's business: give the location one",
	"auth_basic_user_file":  "access is an access list's business: give the location one",
	"auth_request":          "access is an access list's business: give the location one",
	"location":              "blocks are not allowed: add a custom location instead",
	"if":                    "blocks are not allowed",
	"proxy_store":           "it writes files",
	"proxy_temp_path":       "it writes files",
	"client_body_temp_path": "it writes files",
	"mirror":                "it sends the traffic somewhere else",
	"ssl_certificate":       "certificates are the certificate's document",
	"ssl_certificate_key":   "certificates are the certificate's document",
	"load_module":           "it loads code",
}

// SnippetDirectives lists the directives a snippet may use.
func SnippetDirectives() []string {
	out := make([]string, 0, len(snippetDirectives))
	for n := range snippetDirectives {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ParseSnippet reads a snippet and checks every directive.
func ParseSnippet(src string) ([]Directive, error) {
	if len(src) > maxSnippet {
		return nil, fmt.Errorf("snippet: %d bytes, at most %d", len(src), maxSnippet)
	}
	words, err := snippetTokens(src)
	if err != nil {
		return nil, err
	}
	var out []Directive
	var cur *Directive
	for _, w := range words {
		switch {
		case w.semi:
			if cur == nil {
				return nil, fmt.Errorf("snippet line %d: a lone ;", w.line)
			}
			if err := checkDirective(*cur, w.line); err != nil {
				return nil, err
			}
			out = append(out, *cur)
			cur = nil
		case cur == nil:
			if !w.bare || !directiveNameRe.MatchString(w.text) {
				return nil, fmt.Errorf("snippet line %d: %q is not a directive name", w.line, w.text)
			}
			cur = &Directive{Name: w.text}
		default:
			if len(cur.Args) == maxSnippetArgs {
				return nil, fmt.Errorf("snippet line %d: %s has too many arguments", w.line, cur.Name)
			}
			cur.Args = append(cur.Args, w.text)
		}
	}
	if cur != nil {
		return nil, fmt.Errorf("snippet: %s is not terminated with ;", cur.Name)
	}
	if len(out) > maxDirectives {
		return nil, fmt.Errorf("snippet: %d directives, at most %d", len(out), maxDirectives)
	}
	return out, nil
}

func checkDirective(d Directive, line int) error {
	spec, ok := snippetDirectives[d.Name]
	if !ok {
		if why, known := refused[d.Name]; known {
			return fmt.Errorf("snippet line %d: %s is not allowed: %s", line, d.Name, why)
		}
		return fmt.Errorf("snippet line %d: %s is not a directive a snippet may use", line, d.Name)
	}
	if len(d.Args) < spec.min || spec.max >= 0 && len(d.Args) > spec.max {
		return fmt.Errorf("snippet line %d: %s takes %s", line, d.Name, argCount(spec))
	}
	for _, a := range d.Args {
		if strings.ContainsFunc(a, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return fmt.Errorf("snippet line %d: %s: control characters are not allowed in an argument", line, d.Name)
		}
	}
	if spec.check != nil {
		if err := spec.check(d.Args); err != nil {
			return fmt.Errorf("snippet line %d: %s: %w", line, d.Name, err)
		}
	}
	return nil
}

func argCount(s directiveSpec) string {
	switch {
	case s.max < 0:
		return fmt.Sprintf("at least %d argument(s)", s.min)
	case s.min == s.max:
		return fmt.Sprintf("%d argument(s)", s.min)
	}
	return fmt.Sprintf("%d to %d arguments", s.min, s.max)
}

type snippetWord struct {
	text string
	line int
	semi bool
	bare bool // not quoted
}

// snippetTokens splits a snippet the way nginx splits a configuration
// (ngx_conf_read_token): a snippet must mean here exactly what it would
// mean to nginx, or the check would judge something else than what gets
// written. A block is refused where nginx would open one.
func snippetTokens(src string) ([]snippetWord, error) {
	var out []snippetWord
	line := 1
	i := 0
	for i < len(src) {
		ch := src[i]
		switch ch {
		case '\n':
			line++
			i++
			continue
		case ' ', '\t', '\r':
			i++
			continue
		case '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
			continue
		case ';':
			out = append(out, snippetWord{text: ";", line: line, semi: true})
			i++
			continue
		case '{', '}':
			return nil, fmt.Errorf("snippet line %d: blocks are not allowed in a snippet", line)
		}

		start := line
		var raw strings.Builder
		bare := true
		if ch == '"' || ch == '\'' {
			bare = false
			quote := ch
			i++
			closed := false
			for i < len(src) {
				c := src[i]
				if c == '\\' && i+1 < len(src) {
					raw.WriteByte(c)
					raw.WriteByte(src[i+1])
					if src[i+1] == '\n' {
						line++
					}
					i += 2
					continue
				}
				if c == quote {
					closed = true
					i++
					break
				}
				if c == '\n' {
					line++
				}
				raw.WriteByte(c)
				i++
			}
			if !closed {
				return nil, fmt.Errorf("snippet line %d: a quote is not closed", start)
			}
			// nginx wants a space, ; or { right after a closing quote.
			if i < len(src) && !strings.ContainsRune(" \t\r\n;{", rune(src[i])) {
				return nil, fmt.Errorf("snippet line %d: unexpected %q after a quoted argument", line, src[i])
			}
		} else {
			variable := false
			for i < len(src) {
				c := src[i]
				if c == '{' && variable {
					raw.WriteByte(c)
					i++
					continue
				}
				variable = false
				if c == '\\' && i+1 < len(src) {
					raw.WriteByte(c)
					raw.WriteByte(src[i+1])
					if src[i+1] == '\n' {
						line++
					}
					i += 2
					continue
				}
				if c == '$' {
					variable = true
				}
				if strings.ContainsRune(" \t\r\n;{", rune(c)) {
					break
				}
				raw.WriteByte(c)
				i++
			}
			if i < len(src) && src[i] == '{' {
				return nil, fmt.Errorf("snippet line %d: blocks are not allowed in a snippet", line)
			}
		}
		out = append(out, snippetWord{text: Unescape(raw.String()), line: start, bare: bare})
	}
	return out, nil
}

// Unescape resolves the escapes nginx resolves, and only those: \" \'
// \\ \t \r \n. Any other backslash stays, as it does for nginx — a
// regular expression's \. reaches PCRE untouched.
func Unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '"', '\'', '\\':
				b.WriteByte(s[i+1])
				i++
				continue
			case 't':
				b.WriteByte('\t')
				i++
				continue
			case 'r':
				b.WriteByte('\r')
				i++
				continue
			case 'n':
				b.WriteByte('\n')
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
