package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/acme"
	"github.com/ostap-mykhaylyak/limen/internal/api"
	"github.com/ostap-mykhaylyak/limen/internal/config"
	"github.com/ostap-mykhaylyak/limen/internal/logging"
	"github.com/ostap-mykhaylyak/limen/internal/metrics"
	"github.com/ostap-mykhaylyak/limen/internal/model"
	"github.com/ostap-mykhaylyak/limen/internal/nginx"
	"github.com/ostap-mykhaylyak/limen/internal/paths"
	"github.com/ostap-mykhaylyak/limen/internal/status"
	"github.com/ostap-mykhaylyak/limen/internal/store"
	"github.com/ostap-mykhaylyak/limen/internal/traffic"
)

// loggedHosts are the hosts whose access log is counted: the enabled
// ones that log their requests.
func loggedHosts(m *store.Store) []string {
	var out []string
	for _, h := range store.All[*model.ProxyHost](m, model.KindProxyHost) {
		if h.Enabled && h.LogRequests {
			out = append(out, h.Name)
		}
	}
	return out
}

// Error rates below this many requests are noise, not an alert.
const (
	alertMinRequests = 20
	alertErrorRate   = 0.05
)

// addTraffic puts the traffic of the last 5 minutes in the report, and
// a check that warns about the hosts answering too many 5xx.
func addTraffic(rep *status.Report, c *traffic.Collector, p *traffic.NginxProbe) {
	t := &status.TrafficState{Nginx: p.Last(), Hosts: c.Overview(5 * time.Minute)}
	rep.Traffic = t
	var failing []string
	for _, h := range t.Hosts {
		if h.Summary.Requests >= alertMinRequests && h.Summary.ErrorRate >= alertErrorRate {
			failing = append(failing, fmt.Sprintf("%s answers %.0f%% 5xx", h.Name, 100*h.Summary.ErrorRate))
		}
	}
	if len(failing) > 0 {
		detail := failing[0]
		if len(failing) > 1 {
			detail += fmt.Sprintf(" (and %d more)", len(failing)-1)
		}
		rep.Add("errors", status.StatusWarn, detail+" over the last 5 minutes")
	}
	rep.Finish()
}

// logFiles tells the API where the logs are.
func logFiles(cfgs *config.Manager) api.LogSource {
	return api.LogSource{
		Host: func(name string) (string, string) {
			return nginx.HostLogPaths(cfgs.Get().Nginx.HostLogs, name)
		},
		System: func(stream string) (string, bool) {
			n := cfgs.Get().Nginx
			switch stream {
			case api.StreamNginxError:
				return n.ErrorLog, true
			case api.StreamNginxAccess:
				return n.AccessLog, true
			case api.StreamLimen:
				return filepath.Join(paths.LogDir, paths.ServiceLog), true
			case api.StreamApply:
				return filepath.Join(paths.LogDir, paths.ApplyLog), true
			case api.StreamAudit:
				return filepath.Join(paths.LogDir, paths.APILog), true
			}
			return "", false
		},
	}
}

// metricsServer is the Prometheus listener, when there is one.
type metricsServer struct {
	srv  *http.Server
	addr net.Addr
}

func (m *metricsServer) close() {
	if m == nil || m.srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m.srv.Shutdown(ctx)
}

// serveMetrics serves /metrics on metrics.listen: loopback or a unix
// socket, checked by the configuration. A listener that cannot be
// opened is logged; the daemon goes on without it.
func serveMetrics(cfgs *config.Manager, logs *logging.Logs, reg *metrics.Registry, c *traffic.Collector,
	p *traffic.NginxProbe, certs *acme.Manager, m *store.Store) *metricsServer {
	addr := cfgs.Get().Metrics.Listen
	if addr == "" {
		return nil
	}
	network := "tcp"
	if filepath.IsAbs(addr) || addr[0] == '/' {
		network = "unix"
		os.Remove(addr) // a socket left by a previous run
	}
	ln, err := net.Listen(network, addr)
	if err != nil {
		logs.Service.Error("metrics listener", "listen", addr, "error", err.Error())
		return nil
	}
	if network == "unix" {
		os.Chmod(addr, 0o660)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		out := traffic.NewProm(w)
		writeDaemonMetrics(out, reg, certs, m)
		c.WritePrometheus(out, p.Last())
		out.Flush()
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logs.Service.Error("metrics listener", "error", err.Error())
		}
	}()
	logs.Service.Info("metrics served", "listen", addr)
	return &metricsServer{srv: srv, addr: ln.Addr()}
}

// writeDaemonMetrics writes limen's own counters, and when each
// certificate expires.
func writeDaemonMetrics(p *traffic.Prom, reg *metrics.Registry, certs *acme.Manager, m *store.Store) {
	s := reg.Snapshot()
	counter := func(name, help string, v int64) {
		p.Family(name, "counter", help)
		p.Sample(name, float64(v))
	}
	p.Family("limen_up", "gauge", "Whether limen is running: 1.")
	p.Sample("limen_up", 1)
	p.Family("limen_uptime_seconds", "gauge", "Seconds since limen started.")
	p.Sample("limen_uptime_seconds", float64(s.UptimeSeconds))
	counter("limen_applies_total", "Applies of the model that changed something, or failed.", s.AppliesTotal)
	counter("limen_applies_failed_total", "Applies that failed: nginx kept its previous configuration.", s.AppliesFailed)
	counter("limen_nginx_reloads_total", "Times limen reloaded nginx.", s.NginxReloads)
	counter("limen_rollbacks_total", "Candidate configurations put back because nginx refused them.", s.Rollbacks)
	counter("limen_certificates_issued_total", "Certificates issued.", s.CertsIssued)
	counter("limen_certificates_renewed_total", "Certificates renewed.", s.CertsRenewed)
	counter("limen_certificates_failed_total", "Certificate orders that failed.", s.CertsFailed)
	counter("limen_panel_requests_total", "Requests to the panel and its API.", s.RequestsTotal)
	counter("limen_panel_logins_failed_total", "Failed logins to the panel.", s.LoginsFailed)

	p.Family("limen_certificate_expiry_timestamp_seconds", "gauge", "When a certificate stops being valid, as a Unix time; absent while it has no files.")
	for _, c := range store.All[*model.Certificate](m, model.KindCertificate) {
		if info := certs.Describe(c).Info; info.Present && !info.NotAfter.IsZero() {
			p.Sample("limen_certificate_expiry_timestamp_seconds", float64(info.NotAfter.Unix()), "certificate", c.Name)
		}
	}
}
