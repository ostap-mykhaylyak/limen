package nginx

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Features is what the installed nginx can do. The configuration limen
// writes depends on it: the directive for HTTP/2 changed in 1.25.1, the
// stream module may be missing or loaded dynamically, and a directive
// the binary does not know fails the whole configuration.
type Features struct {
	Version       [3]int
	Stream        bool // the stream module exists, built in or dynamic
	StreamDynamic bool
	HTTP2         bool
	// StubStatus is the module behind the connection counters limen
	// reads from nginx.
	StubStatus bool
	// LimitReq is the module behind the rate limits in front of the
	// panel: built in, unless nginx was configured without it.
	LimitReq bool
	// BuildUser is the --user nginx was compiled with, if any.
	BuildUser string
}

// AtLeast reports whether the version is major.minor.patch or newer.
func (f Features) AtLeast(major, minor, patch int) bool {
	want := [3]int{major, minor, patch}
	for i := range want {
		if f.Version[i] != want[i] {
			return f.Version[i] > want[i]
		}
	}
	return true
}

// HTTP2Directive reports whether HTTP/2 is switched on with `http2 on;`
// (1.25.1 and later) rather than with a parameter of listen.
func (f Features) HTTP2Directive() bool { return f.AtLeast(1, 25, 1) }

// RejectHandshake reports whether ssl_reject_handshake exists
// (1.19.4), which lets the default HTTPS server refuse unknown names
// without a certificate of its own.
func (f Features) RejectHandshake() bool { return f.AtLeast(1, 19, 4) }

// VersionString renders the version.
func (f Features) VersionString() string {
	return fmt.Sprintf("%d.%d.%d", f.Version[0], f.Version[1], f.Version[2])
}

var versionRe = regexp.MustCompile(`nginx/(\d+)\.(\d+)\.(\d+)`)

// ParseFeatures reads the output of `nginx -V`.
func ParseFeatures(out string) (Features, error) {
	f := Features{LimitReq: true}
	m := versionRe.FindStringSubmatch(out)
	if m == nil {
		return f, fmt.Errorf("no version in the output of nginx -V")
	}
	for i := range 3 {
		f.Version[i], _ = strconv.Atoi(m[i+1])
	}
	for field := range strings.FieldsSeq(out) {
		switch {
		case field == "--with-stream":
			f.Stream = true
		case field == "--with-stream=dynamic":
			f.Stream, f.StreamDynamic = true, true
		case field == "--with-http_v2_module":
			f.HTTP2 = true
		case field == "--with-http_stub_status_module":
			f.StubStatus = true
		case field == "--without-http_limit_req_module":
			f.LimitReq = false
		case strings.HasPrefix(field, "--user="):
			f.BuildUser = strings.TrimPrefix(field, "--user=")
		}
	}
	return f, nil
}

// Probe runs `nginx -V`.
func Probe(ctx context.Context, bin string) (Features, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, "-V")
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return Features{}, fmt.Errorf("%s -V: %w", bin, err)
	}
	return ParseFeatures(out.String())
}

// WorkerUser picks the account nginx workers run as when the
// configuration does not say: the conventional one that exists on this
// machine, then the one nginx was built with.
func WorkerUser(configured string, f Features) string {
	if configured != "" {
		return configured
	}
	for _, name := range []string{"www-data", "nginx"} {
		if _, err := user.Lookup(name); err == nil {
			return name
		}
	}
	if f.BuildUser != "" {
		return f.BuildUser
	}
	return "nobody"
}

// StreamLoadable reports whether nginx can use the stream module: always
// when it is built in; when it is dynamic, only if one of the files the
// modules include reaches loads it.
func StreamLoadable(f Features, modulesInclude string) bool {
	if !f.Stream {
		return false
	}
	if !f.StreamDynamic {
		return true
	}
	if modulesInclude == "" {
		return false
	}
	matches, _ := filepath.Glob(modulesInclude)
	for _, m := range matches {
		if b, err := os.ReadFile(m); err == nil && strings.Contains(string(b), "ngx_stream_module") {
			return true
		}
	}
	return false
}

// HasIPv6 reports whether the machine can open an IPv6 socket. Where it
// cannot, `listen [::]:80` would pass `nginx -t` (which binds nothing)
// and fail at the reload.
func HasIPv6() bool {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		return false
	}
	ln.Close()
	return true
}
