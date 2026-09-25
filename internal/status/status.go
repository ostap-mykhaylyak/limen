// Package status is the health and live-statistics report of limen.
//
// The daemon is the only source of truth about itself: it knows which
// objects it has in memory, what it last applied to nginx, how many
// requests are in flight. `limen status` is therefore a CLIENT: it
// connects to the local socket the daemon serves and prints what it
// receives. It never rebuilds the state by scanning the disk, and it
// never starts anything.
package status

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/metrics"
	"github.com/ostap-mykhaylyak/limen/internal/traffic"
)

// Exit codes, Nagios convention, so the command is a drop-in check for
// any monitoring system.
const (
	ExitOK       = 0
	ExitWarning  = 1
	ExitCritical = 2
	ExitUnknown  = 3
)

// Check statuses.
const (
	StatusOK       = "ok"
	StatusWarn     = "warn"
	StatusCritical = "crit"
	StatusUnknown  = "unknown"
)

// Check is one named verdict. The monitor can alert on a single check
// as well as on the aggregate.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Service describes the limen process itself.
type Service struct {
	Active        bool  `json:"active"`
	PID           int   `json:"pid,omitempty"`
	UptimeSeconds int64 `json:"uptime_seconds"`
}

// ConfigState describes the configuration currently in force.
type ConfigState struct {
	Path     string   `json:"path"`
	Valid    bool     `json:"valid"`
	Error    string   `json:"error,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// NginxState describes the nginx instance limen drives.
type NginxState struct {
	Running       bool   `json:"running"`
	PID           int    `json:"pid,omitempty"`
	ConfDir       string `json:"conf_dir"`
	Generation    string `json:"generation,omitempty"`
	LastApplyUnix int64  `json:"last_apply_unix"`
	LastApplyOK   bool   `json:"last_apply_ok"`
	LastApplyErr  string `json:"last_apply_error,omitempty"`
	Pending       bool   `json:"pending_changes"`
}

// ModelState counts the managed objects.
type ModelState struct {
	Hosts       int `json:"hosts"`
	Redirects   int `json:"redirects"`
	Streams     int `json:"streams"`
	AccessLists int `json:"access_lists"`
	Users       int `json:"users"`
	Certs       int `json:"certificates"`
	CertsExpiry int `json:"certificates_expiring"`
}

// TrafficState is what nginx serves, as its logs and counters tell it:
// nginx's connections, and the busiest hosts over the last 5 minutes.
type TrafficState struct {
	Nginx traffic.NginxStatus `json:"nginx"`
	Hosts []traffic.HostRow   `json:"hosts"`
}

// Report is the whole snapshot. The JSON field names are a stable
// contract: dashboards are built on them.
type Report struct {
	Status    string            `json:"status"`
	Version   string            `json:"version"`
	Service   Service           `json:"service"`
	Config    ConfigState       `json:"config"`
	Nginx     NginxState        `json:"nginx"`
	Model     ModelState        `json:"model"`
	Live      *metrics.Snapshot `json:"live,omitempty"`
	Traffic   *TrafficState     `json:"traffic,omitempty"`
	Checks    []Check           `json:"checks"`
	Timestamp string            `json:"timestamp"`
}

// Add appends a check.
func (r *Report) Add(name, status, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, Status: status, Detail: detail})
}

// Finish stamps the report and derives the aggregate status from the
// checks: the worst one wins.
func (r *Report) Finish() {
	r.Timestamp = time.Now().UTC().Format(time.RFC3339)
	r.Status = StatusOK
	for _, c := range r.Checks {
		if severity(c.Status) > severity(r.Status) {
			r.Status = c.Status
		}
	}
}

// label is the monitoring word for a status: the check plugins of the
// world print OK, WARNING, CRITICAL and UNKNOWN, not the short forms
// the JSON uses.
func label(s string) string {
	switch s {
	case StatusOK:
		return "OK"
	case StatusWarn:
		return "WARNING"
	case StatusCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func severity(s string) int {
	switch s {
	case StatusOK:
		return 0
	case StatusWarn:
		return 1
	case StatusUnknown:
		return 2
	case StatusCritical:
		return 3
	}
	return 2
}

// ExitCode maps the aggregate status to the process exit code.
func (r *Report) ExitCode() int {
	switch r.Status {
	case StatusOK:
		return ExitOK
	case StatusWarn:
		return ExitWarning
	case StatusCritical:
		return ExitCritical
	default:
		return ExitUnknown
	}
}

// Summary is the single check-style line: the primary signal for a
// textual monitor.
func (r *Report) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "limen %s -", label(r.Status))
	if !r.Service.Active {
		b.WriteString(" service not running")
		if r.Config.Path != "" {
			if r.Config.Valid {
				b.WriteString(", config valid")
			} else if r.Config.Error != "" {
				b.WriteString(", config invalid")
			} else {
				b.WriteString(", not installed")
			}
		}
		return b.String()
	}
	fmt.Fprintf(&b, " active, pid %d, up %s", r.Service.PID, humanDuration(r.Service.UptimeSeconds))
	if r.Config.Valid {
		b.WriteString(", config valid")
	} else {
		b.WriteString(", config INVALID")
	}
	fmt.Fprintf(&b, ", %d host(s) / %d cert(s)", r.Model.Hosts, r.Model.Certs)
	if r.Nginx.Running {
		b.WriteString(", nginx up")
	} else {
		b.WriteString(", nginx DOWN")
	}
	if r.Nginx.Pending {
		b.WriteString(", changes pending")
	}
	return b.String()
}

// WriteJSON writes the machine-readable form, one object per line so
// that --watch --json can be piped into a collector.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	return enc.Encode(r)
}

// WriteText writes the human form: the summary line plus the blocks an
// operator reads while something is going wrong.
func (r *Report) WriteText(w io.Writer, rates *Rates) {
	fmt.Fprintln(w, r.Summary())

	if r.Service.Active {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "SERVICE")
		fmt.Fprintf(w, "  version        %s\n", r.Version)
		fmt.Fprintf(w, "  uptime         %s\n", humanDuration(r.Service.UptimeSeconds))
		fmt.Fprintf(w, "  config         %s\n", r.Config.Path)
		fmt.Fprintf(w, "  nginx          %s (%s)\n", upDown(r.Nginx.Running), r.Nginx.ConfDir)
		if r.Nginx.Generation != "" {
			fmt.Fprintf(w, "  generation     %s\n", r.Nginx.Generation)
		}
		if r.Nginx.LastApplyUnix > 0 {
			age := time.Since(time.Unix(r.Nginx.LastApplyUnix, 0)).Truncate(time.Second)
			fmt.Fprintf(w, "  last apply     %s ago (%s)\n", age, okFailed(r.Nginx.LastApplyOK))
		}
		if r.Nginx.Pending {
			fmt.Fprintln(w, "  pending        the model has changes nginx does not serve yet")
		}
		if r.Nginx.LastApplyErr != "" {
			fmt.Fprintf(w, "  apply error    %s\n", r.Nginx.LastApplyErr)
		}

		fmt.Fprintln(w)
		fmt.Fprintln(w, "MODEL")
		fmt.Fprintf(w, "  hosts %d  redirects %d  streams %d  access lists %d  users %d  certs %d\n",
			r.Model.Hosts, r.Model.Redirects, r.Model.Streams,
			r.Model.AccessLists, r.Model.Users, r.Model.Certs)
		if r.Model.CertsExpiry > 0 {
			fmt.Fprintf(w, "  %d certificate(s) within the renewal window\n", r.Model.CertsExpiry)
		}
	}

	if r.Live != nil {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "LIVE")
		fmt.Fprintf(w, "  requests       %d total, %d failed, %d in flight",
			r.Live.RequestsTotal, r.Live.RequestsFailed, r.Live.RequestsInFlight)
		if rates != nil {
			fmt.Fprintf(w, "  (%.1f req/s)", rates.Requests)
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  logins         %d ok, %d failed\n", r.Live.LoginsTotal, r.Live.LoginsFailed)
		fmt.Fprintf(w, "  applies        %d ok, %d failed, %d rollback(s)\n",
			r.Live.AppliesTotal-r.Live.AppliesFailed, r.Live.AppliesFailed, r.Live.Rollbacks)
		fmt.Fprintf(w, "  certificates   %d issued, %d renewed, %d failed\n",
			r.Live.CertsIssued, r.Live.CertsRenewed, r.Live.CertsFailed)
	}

	if t := r.Traffic; t != nil {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "TRAFFIC (last 5 minutes)")
		if t.Nginx.OK {
			fmt.Fprintf(w, "  nginx          %d connection(s): %d reading, %d writing, %d waiting; %.1f req/s\n",
				t.Nginx.Active, t.Nginx.Reading, t.Nginx.Writing, t.Nginx.Waiting, t.Nginx.PerSecond)
		}
		shown := 0
		for _, h := range t.Hosts {
			if h.Summary.Requests == 0 || shown == 10 {
				continue
			}
			shown++
			fmt.Fprintf(w, "  %-28s %7.2f req/s  %5.1f%% 5xx  p95 %s\n",
				h.Name, h.Summary.PerSecond, 100*h.Summary.ErrorRate, seconds(h.Summary.P95))
		}
		if shown == 0 {
			fmt.Fprintln(w, "  no request logged by any host")
		}
	}

	if len(r.Config.Warnings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "CONFIG WARNINGS")
		for _, s := range r.Config.Warnings {
			fmt.Fprintf(w, "  - %s\n", s)
		}
	}

	if len(r.Checks) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "CHECKS")
		checks := append([]Check(nil), r.Checks...)
		sort.SliceStable(checks, func(i, j int) bool {
			return severity(checks[i].Status) > severity(checks[j].Status)
		})
		for _, c := range checks {
			line := fmt.Sprintf("  [%-4s] %s", c.Status, c.Name)
			if c.Detail != "" {
				line += ": " + c.Detail
			}
			fmt.Fprintln(w, line)
		}
	}
}

// Rates holds the per-second values derived between two --watch ticks.
type Rates struct {
	Requests float64
}

// NewRates computes the rates between two snapshots taken dt apart.
func NewRates(prev, cur *metrics.Snapshot, dt time.Duration) *Rates {
	if prev == nil || cur == nil {
		return nil
	}
	return &Rates{Requests: metrics.Rate(prev.RequestsTotal, cur.RequestsTotal, dt)}
}

func seconds(s float64) string {
	if s < 1 {
		return fmt.Sprintf("%.0fms", s*1000)
	}
	return fmt.Sprintf("%.2fs", s)
}

func upDown(b bool) string {
	if b {
		return "running"
	}
	return "down"
}

func okFailed(b bool) string {
	if b {
		return "ok"
	}
	return "failed"
}

func humanDuration(seconds int64) string {
	d := time.Duration(seconds) * time.Second
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", seconds)
	case d < time.Hour:
		return fmt.Sprintf("%dm %ds", seconds/60, seconds%60)
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh %dm", seconds/3600, (seconds%3600)/60)
	default:
		return fmt.Sprintf("%dd %dh", seconds/86400, (seconds%86400)/3600)
	}
}
