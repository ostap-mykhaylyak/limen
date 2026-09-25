package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/ostap-mykhaylyak/limen/internal/model"
)

// proxyFlags are the host flags of M6: how nginx talks to the backend,
// and the host's snippet.
func proxyFlags(fs *flag.FlagSet) func(h *model.ProxyHost, set map[string]bool) error {
	connect := fs.String("connect-timeout", "", "time to connect to the backend, e.g. 5s (empty: 60s)")
	read := fs.String("read-timeout", "", "longest wait between two reads from the backend (empty: 300s)")
	send := fs.String("send-timeout", "", "longest wait between two writes to the backend (empty: 300s)")
	streamResp := fs.Bool("stream-responses", false, "pass responses on as they arrive, unbuffered (SSE, long polling)")
	streamReq := fs.Bool("stream-requests", false, "pass request bodies on as they arrive, unbuffered")
	hostHeader := fs.String("host-header", "", `Host sent to the backend: empty for the client's, "upstream" for the backend's address, or a name`)
	var reqHeaders, respHeaders stringList
	fs.Var(&reqHeaders, "request-header", `"Name: value" set on requests to the backend; repeat (replaces all; "" clears)`)
	fs.Var(&respHeaders, "response-header", `"Name: value" added to every response; repeat (replaces all; "" clears)`)
	snippet := fs.String("snippet-file", "", "nginx directives for every location of the host, from a file (- for stdin)")
	noSnippet := fs.Bool("no-snippet", false, "remove the host's snippet")

	return func(h *model.ProxyHost, set map[string]bool) error {
		p := &h.Proxy
		if set["connect-timeout"] {
			p.ConnectTimeout = *connect
		}
		if set["read-timeout"] {
			p.ReadTimeout = *read
		}
		if set["send-timeout"] {
			p.SendTimeout = *send
		}
		if set["stream-responses"] {
			p.StreamResponses = *streamResp
		}
		if set["stream-requests"] {
			p.StreamRequests = *streamReq
		}
		if set["host-header"] {
			p.HostHeader = *hostHeader
		}
		var err error
		if set["request-header"] {
			if p.RequestHeaders, err = parseHeaders(reqHeaders); err != nil {
				return err
			}
		}
		if set["response-header"] {
			if p.ResponseHeaders, err = parseHeaders(respHeaders); err != nil {
				return err
			}
		}
		return snippetFlag(&h.Snippet, *snippet, *noSnippet, set)
	}
}

func parseHeaders(raw []string) ([]model.Header, error) {
	var out []model.Header
	for _, r := range raw {
		if strings.TrimSpace(r) == "" {
			continue
		}
		name, value, ok := strings.Cut(r, ":")
		if !ok {
			return nil, fmt.Errorf("header %q: want \"Name: value\"", r)
		}
		out = append(out, model.Header{Name: strings.TrimSpace(name), Value: strings.TrimSpace(value)})
	}
	return out, nil
}

func snippetFlag(dst *string, file string, clear bool, set map[string]bool) error {
	switch {
	case set["snippet-file"] && set["no-snippet"]:
		return fmt.Errorf("--snippet-file and --no-snippet: one or the other")
	case set["no-snippet"] && clear:
		*dst = ""
	case set["snippet-file"]:
		var b []byte
		var err error
		if file == "-" {
			b, err = io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
		} else {
			b, err = os.ReadFile(file)
		}
		if err != nil {
			return err
		}
		// Checked here for the line numbers of the file; the model
		// checks it again on save.
		if _, err := model.ParseSnippet(string(b)); err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		*dst = string(b)
	}
	return nil
}

// ---------------------------------------------------------------------
// limen host location
// ---------------------------------------------------------------------

func (c *cli) locationUsage() {
	w := c.errOut
	fmt.Fprintln(w, "usage: limen host location COMMAND HOST [PATH] [flags]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  list HOST                  the host's custom locations")
	fmt.Fprintln(w, "  add HOST PATH [flags]      send PATH elsewhere, or guard it differently")
	fmt.Fprintln(w, "  set HOST PATH [flags]      change only the flags you pass")
	fmt.Fprintln(w, "  rm HOST PATH               remove it")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "PATH is a prefix (/api/), or an exact path when it starts with = (=/health).")
	fmt.Fprintln(w, "Every write takes --note \"why\", kept in the host's history.")
}

func (c *cli) location(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		c.locationUsage()
		if len(args) == 0 {
			return errUsage
		}
		return nil
	}
	verb, rest := args[0], args[1:]
	switch verb {
	case "list", "ls":
		return c.locationList(rest)
	case "add", "set":
		return c.locationWrite(rest, verb == "add")
	case "rm", "delete":
		return c.locationRemove(rest)
	}
	c.locationUsage()
	return fmt.Errorf("host location: unknown command %q", verb)
}

// takeLocation reads HOST and PATH.
func takeLocation(args []string) (host string, loc model.Location, rest []string, err error) {
	if len(args) < 2 || strings.HasPrefix(args[0], "-") || strings.HasPrefix(args[1], "-") {
		return "", loc, nil, fmt.Errorf("want a host and a path: limen host location add HOST PATH")
	}
	loc.Path = args[1]
	if p, ok := strings.CutPrefix(loc.Path, "="); ok {
		loc.Exact, loc.Path = true, strings.TrimSpace(p)
	}
	return args[0], loc, args[2:], nil
}

func (c *cli) locationList(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("want a host: limen host location list HOST")
	}
	doc, err := c.store.Get(model.KindProxyHost, args[0])
	if err != nil {
		return err
	}
	h := doc.(*model.ProxyHost)
	tw := tabwriter.NewWriter(c.out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "PATH\tFORWARD\tACCESS\tWEBSOCKETS\tSNIPPET")
	for _, l := range h.Locations {
		fwd := "the host's (" + h.Forward.String() + ")"
		if l.Forward != nil {
			fwd = l.Forward.String()
		}
		access := "the host's"
		switch {
		case l.Public:
			access = "public"
		case l.AccessList != "":
			access = l.AccessList
		case h.AccessList == "":
			access = "-"
		}
		lines := "-"
		if ds, _ := model.ParseSnippet(l.Snippet); len(ds) > 0 {
			lines = fmt.Sprintf("%d directive(s)", len(ds))
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%v\t%s\n", l.Match(), fwd, access, l.Websockets, lines)
	}
	return tw.Flush()
}

func (c *cli) locationWrite(args []string, create bool) error {
	hostName, want, rest, err := takeLocation(args)
	if err != nil {
		return err
	}
	verb := "set"
	if create {
		verb = "add"
	}
	fs := c.flags("host location " + verb)
	forward := fs.String("forward", "", "backend of this location, e.g. http://10.0.0.7:9000 (empty: the host's)")
	verify := fs.Bool("verify-tls", false, "verify the backend certificate (https backends)")
	acl := fs.String("access-list", "", "access list guarding this location instead of the host's (empty: the host's)")
	public := fs.Bool("public", false, "no access list at all here, even if the host has one")
	ws := fs.Bool("websockets", false, "allow websocket upgrades")
	snippet := fs.String("snippet-file", "", "nginx directives for this location, from a file (- for stdin)")
	noSnippet := fs.Bool("no-snippet", false, "remove the location's snippet")
	note := fs.String("note", "", "why this change is made (kept in the history)")
	if err := c.parse(fs, rest); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	set := visited(fs)

	err = c.store.Locked(func() error {
		doc, err := c.store.Get(model.KindProxyHost, hostName)
		if err != nil {
			return err
		}
		h := doc.(*model.ProxyHost)
		i := findLocation(h.Locations, want)
		switch {
		case create && i >= 0:
			return fmt.Errorf("location %s already exists on %q: use `limen host location set`", want.Match(), hostName)
		case !create && i < 0:
			return fmt.Errorf("location %s: not found on %q", want.Match(), hostName)
		case create:
			want.Websockets = h.Websockets // the host's, unless said otherwise
			h.Locations = append(h.Locations, want)
			i = len(h.Locations) - 1
		}
		l := &h.Locations[i]
		if set["forward"] {
			if *forward == "" {
				l.Forward = nil
			} else {
				up, err := model.ParseUpstream(*forward)
				if err != nil {
					return err
				}
				l.Forward = &up
			}
		}
		if set["verify-tls"] {
			if l.Forward == nil {
				return fmt.Errorf("--verify-tls is about the location's own backend: pass --forward")
			}
			l.Forward.VerifyTLS = *verify
		}
		if set["access-list"] {
			l.AccessList = *acl
			if *acl != "" {
				l.Public = false
			}
		}
		if set["public"] {
			l.Public = *public
			if *public {
				l.AccessList = ""
			}
		}
		if set["websockets"] {
			l.Websockets = *ws
		}
		if err := snippetFlag(&l.Snippet, *snippet, *noSnippet, set); err != nil {
			return err
		}
		_, err = c.store.Put(h, c.change(*note))
		return err
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "location %s of proxy host %q saved\n", want.Match(), hostName)
	return c.afterWrite(model.KindProxyHost)
}

func (c *cli) locationRemove(args []string) error {
	hostName, want, rest, err := takeLocation(args)
	if err != nil {
		return err
	}
	fs := c.flags("host location rm")
	note := fs.String("note", "", "why this change is made (kept in the history)")
	if err := c.parse(fs, rest); err != nil {
		return err
	}
	err = c.store.Locked(func() error {
		doc, err := c.store.Get(model.KindProxyHost, hostName)
		if err != nil {
			return err
		}
		h := doc.(*model.ProxyHost)
		i := findLocation(h.Locations, want)
		if i < 0 {
			return fmt.Errorf("location %s: not found on %q", want.Match(), hostName)
		}
		h.Locations = append(h.Locations[:i], h.Locations[i+1:]...)
		_, err = c.store.Put(h, c.change(*note))
		return err
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "location %s removed from proxy host %q\n", want.Match(), hostName)
	return c.afterWrite(model.KindProxyHost)
}

func findLocation(ls []model.Location, want model.Location) int {
	for i, l := range ls {
		if l.Match() == want.Match() {
			return i
		}
	}
	return -1
}
