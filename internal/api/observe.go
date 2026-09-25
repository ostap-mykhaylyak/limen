package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/model"
	"github.com/ostap-mykhaylyak/limen/internal/traffic"
)

// LogSource says where the logs are.
type LogSource struct {
	// Host returns a proxy host's access and error logs.
	Host func(name string) (access, errorLog string)
	// System returns the file of a system stream.
	System func(stream string) (string, bool)
}

// The system log streams.
const (
	StreamNginxError  = "nginx-error"
	StreamNginxAccess = "nginx-access"
	StreamLimen       = "limen"
	StreamApply       = "apply"
	StreamAudit       = "api"
)

// systemStreams are the streams, what their lines are, and who may read
// them. The audit trail says who did what from the panel: it is the
// admins'.
var systemStreams = map[string]struct {
	format string
	role   string
}{
	StreamNginxError:  {formatError, model.RoleOperator},
	StreamNginxAccess: {formatText, model.RoleOperator},
	StreamLimen:       {formatJSON, model.RoleOperator},
	StreamApply:       {formatJSON, model.RoleOperator},
	StreamAudit:       {formatJSON, model.RoleAdmin},
}

const (
	formatAccess = "access" // limen's JSON access log: parsed into requests
	formatError  = "error"  // nginx's error log: parsed into time, level, message
	formatJSON   = "json"   // limen's own logs: one JSON object per line
	formatText   = "text"   // anything else: the line as it is
)

// Bounds of a log request: a page of lines, read from at most so much
// of the file.
const (
	defaultLines = 200
	maxLines     = 2000
	maxScan      = 16 << 20
	// maxFollow bounds one read of what follows an offset: after=0 on a
	// large log must not load it whole; the next call carries on.
	maxFollow = 4 << 20
)

func (a *API) observeRoutes() {
	a.route("GET /traffic", model.RoleViewer, a.trafficOverview)
	a.route("GET /hosts/{name}/traffic", model.RoleViewer, a.hostTraffic)
	// Logs hold client addresses, URLs and user agents: personal data,
	// and sometimes a token in a query string. Viewers see the numbers,
	// operators the lines.
	a.route("GET /hosts/{name}/logs/{kind}", model.RoleOperator, a.hostLogs)
	a.route("GET /logs/{stream}", model.RoleOperator, a.systemLogs)
}

func window(r *http.Request, def string) (time.Duration, string, bool) {
	w := r.URL.Query().Get("window")
	if w == "" {
		w = def
	}
	d, ok := traffic.ParseWindow(w)
	return d, w, ok
}

func (a *API) trafficOverview(w http.ResponseWriter, r *http.Request, p *principal) {
	if a.d.Traffic == nil {
		writeError(w, http.StatusServiceUnavailable, "no traffic collector")
		return
	}
	d, label, ok := window(r, "1h")
	if !ok {
		writeError(w, http.StatusBadRequest, "window: 5m, 1h or 24h")
		return
	}
	series, _ := a.d.Traffic.Series("", d)
	out := map[string]any{
		"window": label,
		"hosts":  a.d.Traffic.Overview(d),
		"series": series,
	}
	if a.d.Nginx != nil {
		out["nginx"] = a.d.Nginx.Last()
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) hostTraffic(w http.ResponseWriter, r *http.Request, p *principal) {
	name := r.PathValue("name")
	doc, err := a.d.Store.Get(model.KindProxyHost, name)
	if err != nil {
		a.fail(w, err)
		return
	}
	d, label, ok := window(r, "1h")
	if !ok {
		writeError(w, http.StatusBadRequest, "window: 5m, 1h or 24h")
		return
	}
	h := doc.(*model.ProxyHost)
	out := map[string]any{"window": label, "logged": h.LogRequests && h.Enabled}
	if a.d.Traffic != nil {
		if s, ok := a.d.Traffic.HostSummary(name, d); ok {
			series, _ := a.d.Traffic.Series(name, d)
			out["summary"], out["series"] = s, series
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) hostLogs(w http.ResponseWriter, r *http.Request, p *principal) {
	name := r.PathValue("name")
	if _, err := a.d.Store.Get(model.KindProxyHost, name); err != nil {
		a.fail(w, err)
		return
	}
	if a.d.Logs.Host == nil {
		writeError(w, http.StatusServiceUnavailable, "no log source")
		return
	}
	access, errorLog := a.d.Logs.Host(name)
	switch r.PathValue("kind") {
	case "access":
		a.readLog(w, r, access, formatAccess)
	case "error":
		a.readLog(w, r, errorLog, formatError)
	default:
		writeError(w, http.StatusNotFound, "a host has an access and an error log")
	}
}

func (a *API) systemLogs(w http.ResponseWriter, r *http.Request, p *principal) {
	stream := r.PathValue("stream")
	s, ok := systemStreams[stream]
	var path string
	if ok && a.d.Logs.System != nil {
		path, ok = a.d.Logs.System(stream)
	}
	if !ok {
		writeError(w, http.StatusNotFound, "streams: nginx-error, nginx-access, limen, apply, api")
		return
	}
	if levels[p.user.Role] < levels[s.role] {
		writeError(w, http.StatusForbidden, "this needs the "+s.role+" role")
		return
	}
	a.readLog(w, r, path, s.format)
}

// logPage is what a log request answers: the lines, oldest first, and
// the offset to ask for what comes after them.
type logPage struct {
	Format string `json:"format"`
	Offset int64  `json:"offset"`
	Lines  []any  `json:"lines"`
	// Missing says the file is not there (yet): a host that has not
	// served a request since its logs were set up.
	Missing bool `json:"missing,omitempty"`
}

// readLog answers a page of a log: its last lines, or with after= the
// lines written since that offset (the panel's "follow"), filtered by
// q= (a piece of text) and, for access logs, status= (404, or 5xx).
func (a *API) readLog(w http.ResponseWriter, r *http.Request, path, format string) {
	q := r.URL.Query()
	n := defaultLines
	if v := q.Get("lines"); v != "" {
		var err error
		if n, err = strconv.Atoi(v); err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "lines: a positive number")
			return
		}
		n = min(n, maxLines)
	}
	match, err := lineFilter(q.Get("q"), q.Get("status"), format)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var lines [][]byte
	var offset int64
	if v := q.Get("after"); v != "" {
		after, err := strconv.ParseInt(v, 10, 64)
		if err != nil || after < 0 {
			writeError(w, http.StatusBadRequest, "after: an offset from a previous answer")
			return
		}
		lines, offset, err = traffic.From(path, after, n, match, maxFollow)
	} else {
		lines, offset, err = traffic.Tail(path, n, match, maxScan)
	}
	page := logPage{Format: format, Offset: offset, Lines: []any{}}
	if errors.Is(err, fs.ErrNotExist) {
		page.Missing = true
		writeJSON(w, http.StatusOK, page)
		return
	}
	if err != nil {
		a.fail(w, err)
		return
	}
	for _, l := range lines {
		page.Lines = append(page.Lines, decodeLine(l, format))
	}
	writeJSON(w, http.StatusOK, page)
}

// rawLine is a line that could not be read in its log's format.
type rawLine struct {
	Raw string `json:"raw"`
}

func decodeLine(l []byte, format string) any {
	switch format {
	case formatAccess:
		if e, err := traffic.ParseAccess(l); err == nil {
			return e
		}
	case formatError:
		return traffic.ParseError(l)
	case formatJSON:
		if json.Valid(l) {
			return json.RawMessage(append([]byte(nil), l...))
		}
	}
	return rawLine{Raw: strings.ToValidUTF8(string(l), "�")}
}

func lineFilter(text, status, format string) (func([]byte) bool, error) {
	needle := []byte(strings.ToLower(text))
	var class, code int
	if status != "" {
		if format != formatAccess {
			return nil, errors.New("status: only for access logs")
		}
		switch v := traffic.StatusClass(status); {
		case v == 0:
			return nil, errors.New("status: a code (404) or a class (5xx)")
		case strings.HasSuffix(status, "xx"):
			class = v / 100
		default:
			code = v
		}
	}
	if len(needle) == 0 && class == 0 && code == 0 {
		return nil, nil
	}
	return func(l []byte) bool {
		if len(needle) > 0 && !bytes.Contains(bytes.ToLower(l), needle) {
			return false
		}
		if class == 0 && code == 0 {
			return true
		}
		e, err := traffic.ParseAccess(l)
		if err != nil {
			return false
		}
		return code != 0 && e.Status == code || class != 0 && e.Status/100 == class
	}, nil
}
