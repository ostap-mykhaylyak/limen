package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/config"
	"github.com/ostap-mykhaylyak/limen/internal/model"
	"github.com/ostap-mykhaylyak/limen/internal/nginx"
	"github.com/ostap-mykhaylyak/limen/internal/paths"
	"github.com/ostap-mykhaylyak/limen/internal/traffic"
)

// logStreams are the system logs `limen logs` reads, and their format.
var logStreams = map[string]string{
	"nginx-error":  "error",
	"nginx-access": "text",
	"limen":        "json",
	"apply":        "json",
	"api":          "json",
}

func (c *cli) loadConfig() (*config.Config, error) {
	if c.config != nil {
		return c.config()
	}
	return config.Load(paths.ConfigFile)
}

// hostLogs is `limen host logs NAME`.
func (c *cli) hostLogs(args []string) error {
	name, rest, err := takeName(args)
	if err != nil {
		return err
	}
	fs := c.flags("host logs")
	errorsOnly := fs.Bool("errors", false, "the host's error log instead of its requests")
	o := logFlags(fs)
	if err := c.parse(fs, rest); err != nil {
		return err
	}
	doc, err := c.store.Get(model.KindProxyHost, name)
	if err != nil {
		return err
	}
	cfg, err := c.loadConfig()
	if err != nil {
		return err
	}
	access, errorLog := nginx.HostLogPaths(cfg.Nginx.HostLogs, name)
	if *errorsOnly {
		return c.showLog(errorLog, "error", o)
	}
	if !doc.(*model.ProxyHost).LogRequests {
		fmt.Fprintf(c.errOut, "note: %s does not log its requests (log_requests: false); showing what was logged before\n", name)
	}
	return c.showLog(access, "access", o)
}

// logsCmd is `limen logs STREAM`.
func (c *cli) logsCmd(args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(c.errOut, "usage: limen logs STREAM [-n N] [--follow] [--grep TEXT]")
		fmt.Fprintln(c.errOut, "")
		fmt.Fprintln(c.errOut, "  nginx-error    nginx's own error log")
		fmt.Fprintln(c.errOut, "  nginx-access   requests to no host (the default servers)")
		fmt.Fprintln(c.errOut, "  limen          the daemon: starts, reloads, renewals")
		fmt.Fprintln(c.errOut, "  apply          every render, test and reload of nginx")
		fmt.Fprintln(c.errOut, "  api            every panel request: the audit trail")
		fmt.Fprintln(c.errOut, "")
		fmt.Fprintln(c.errOut, "A host's own logs: limen host logs NAME [--errors].")
		return errUsage
	}
	stream, rest := args[0], args[1:]
	format, ok := logStreams[stream]
	if !ok {
		return fmt.Errorf("unknown stream %q: nginx-error, nginx-access, limen, apply or api", stream)
	}
	fs := c.flags("logs " + stream)
	o := logFlags(fs)
	if err := c.parse(fs, rest); err != nil {
		return err
	}
	cfg, err := c.loadConfig()
	if err != nil {
		return err
	}
	path := map[string]string{
		"nginx-error":  cfg.Nginx.ErrorLog,
		"nginx-access": cfg.Nginx.AccessLog,
		"limen":        filepath.Join(paths.LogDir, paths.ServiceLog),
		"apply":        filepath.Join(paths.LogDir, paths.ApplyLog),
		"api":          filepath.Join(paths.LogDir, paths.APILog),
	}[stream]
	return c.showLog(path, format, o)
}

type logOptions struct {
	lines  *int
	follow *bool
	grep   *string
	status *string
	asJSON *bool
}

func logFlags(fs *flag.FlagSet) logOptions {
	return logOptions{
		lines:  fs.Int("n", 50, "how many of the last lines"),
		follow: fs.Bool("follow", false, "keep printing lines as they are written (Ctrl-C to stop)"),
		grep:   fs.String("grep", "", "only the lines holding this text (case does not matter)"),
		status: fs.String("status", "", "access logs: only this status (404) or class (5xx)"),
		asJSON: fs.Bool("json", false, "one JSON object per line"),
	}
}

func (c *cli) showLog(path, format string, o logOptions) error {
	match, err := cliFilter(*o.grep, *o.status, format)
	if err != nil {
		return err
	}
	lines, offset, err := traffic.Tail(path, max(*o.lines, 1), match, 64<<20)
	if errors.Is(err, fs.ErrNotExist) {
		if !*o.follow {
			fmt.Fprintf(c.errOut, "%s: nothing logged yet\n", path)
			return nil
		}
	} else if err != nil {
		return err
	}
	for _, l := range lines {
		c.printLine(l, format, *o.asJSON)
	}
	if !*o.follow {
		return nil
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	defer signal.Stop(stop)
	for {
		select {
		case <-stop:
			return nil
		case <-time.After(500 * time.Millisecond):
		}
		lines, next, err := traffic.From(path, offset, 1000, match, 8<<20)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		offset = next
		for _, l := range lines {
			c.printLine(l, format, *o.asJSON)
		}
	}
}

func cliFilter(text, status, format string) (func([]byte) bool, error) {
	needle := strings.ToLower(text)
	var class, code int
	if status != "" {
		if format != "access" {
			return nil, errors.New("--status is for a host's access log")
		}
		v := traffic.StatusClass(status)
		switch {
		case v == 0:
			return nil, fmt.Errorf("--status %q: a code (404) or a class (5xx)", status)
		case strings.HasSuffix(status, "xx"):
			class = v / 100
		default:
			code = v
		}
	}
	if needle == "" && status == "" {
		return nil, nil
	}
	return func(l []byte) bool {
		if needle != "" && !strings.Contains(strings.ToLower(string(l)), needle) {
			return false
		}
		if status == "" {
			return true
		}
		e, err := traffic.ParseAccess(l)
		return err == nil && (code != 0 && e.Status == code || class != 0 && e.Status/100 == class)
	}, nil
}

// printLine writes one line of a log the way a person reads it, or as
// JSON.
func (c *cli) printLine(l []byte, format string, asJSON bool) {
	switch format {
	case "access":
		e, err := traffic.ParseAccess(l)
		if err != nil {
			fmt.Fprintln(c.out, string(l))
			return
		}
		if asJSON {
			writeJSONLine(c, e)
			return
		}
		up := ""
		if e.Upstream != "" {
			up = "  -> " + e.Upstream
			if e.UpstreamStatus != "" && e.UpstreamStatus != fmt.Sprint(e.Status) {
				up += " (" + e.UpstreamStatus + ")"
			}
		}
		fmt.Fprintf(c.out, "%s  %d  %-6s %s%s  %s  %s  %s%s\n",
			e.Time.Local().Format("2006-01-02 15:04:05"), e.Status, e.Method, e.Host, e.URI,
			duration(e.Duration), size(e.Bytes), e.Remote, up)
	case "error":
		e := traffic.ParseError(l)
		if asJSON {
			writeJSONLine(c, e)
			return
		}
		if e.Time.IsZero() {
			fmt.Fprintln(c.out, e.Message)
			return
		}
		fmt.Fprintf(c.out, "%s  %-6s %s\n", e.Time.Format("2006-01-02 15:04:05"), e.Level, e.Message)
	case "json":
		if asJSON {
			fmt.Fprintln(c.out, string(l))
			return
		}
		var m map[string]any
		if json.Unmarshal(l, &m) != nil {
			fmt.Fprintln(c.out, string(l))
			return
		}
		fmt.Fprintln(c.out, humanJSON(m))
	default:
		fmt.Fprintln(c.out, string(l))
	}
}

func writeJSONLine(c *cli, v any) {
	b, _ := json.Marshal(v)
	fmt.Fprintln(c.out, string(b))
}

// humanJSON prints a log record of limen's: time, level, message, then
// the rest as key=value, sorted.
func humanJSON(m map[string]any) string {
	var b strings.Builder
	if t, ok := m["time"].(string); ok {
		if tt, err := time.Parse(time.RFC3339Nano, t); err == nil {
			t = tt.Local().Format("2006-01-02 15:04:05")
		}
		b.WriteString(t)
	}
	fmt.Fprintf(&b, "  %-5v %v", m["level"], m["msg"])
	var keys []string
	for k := range m {
		if k != "time" && k != "level" && k != "msg" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := fmt.Sprint(m[k])
		if strings.ContainsAny(v, " \"") {
			v = fmt.Sprintf("%q", v)
		}
		fmt.Fprintf(&b, "  %s=%s", k, v)
	}
	return b.String()
}

func duration(s float64) string {
	if s < 1 {
		return fmt.Sprintf("%dms", int(s*1000+0.5))
	}
	return fmt.Sprintf("%.2fs", s)
}

func size(n int64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%dB", n)
	case n < 1<<20:
		return fmt.Sprintf("%.1fkB", float64(n)/1024)
	default:
		return fmt.Sprintf("%.1fMB", float64(n)/(1<<20))
	}
}
