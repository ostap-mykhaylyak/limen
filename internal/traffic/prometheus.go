package traffic

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// Prom writes metrics in the Prometheus text exposition format
// (version 0.0.4): a HELP and a TYPE line per family, then its samples.
type Prom struct {
	w   *bufio.Writer
	err error
}

// NewProm writes to w; Flush when done.
func NewProm(w io.Writer) *Prom { return &Prom{w: bufio.NewWriter(w)} }

// Family starts a family of samples.
func (p *Prom) Family(name, kind, help string) {
	p.printf("# HELP %s %s\n# TYPE %s %s\n", name, escapeHelp(help), name, kind)
}

// Sample writes one sample; labels are name, value pairs.
func (p *Prom) Sample(name string, value float64, labels ...string) {
	var b strings.Builder
	b.WriteString(name)
	if len(labels) > 0 {
		b.WriteByte('{')
		for i := 0; i+1 < len(labels); i += 2 {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(labels[i])
			b.WriteString(`="`)
			b.WriteString(escapeLabel(labels[i+1]))
			b.WriteByte('"')
		}
		b.WriteByte('}')
	}
	p.printf("%s %s\n", b.String(), formatValue(value))
}

// Flush writes what is buffered and returns the first error met.
func (p *Prom) Flush() error {
	if err := p.w.Flush(); p.err == nil {
		p.err = err
	}
	return p.err
}

func (p *Prom) printf(format string, args ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, args...)
	}
}

func escapeLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

func formatValue(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}

var classes = [5]string{"1xx", "2xx", "3xx", "4xx", "5xx"}

// WritePrometheus writes the traffic of every host since the daemon
// started, and nginx's own counters.
func (c *Collector) WritePrometheus(p *Prom, nginx NginxStatus) {
	totals := c.Totals()
	names := make([]string, 0, len(totals))
	for n := range totals {
		names = append(names, n)
	}
	sort.Strings(names)

	p.Family("limen_http_requests_total", "counter", "Requests served by a proxy host, by status class, counted from its access log since limen started.")
	for _, n := range names {
		for i, cl := range classes {
			p.Sample("limen_http_requests_total", float64(totals[n].Status[i]), "host", n, "code", cl)
		}
	}
	p.Family("limen_http_response_bytes_total", "counter", "Body bytes sent by a proxy host since limen started.")
	for _, n := range names {
		p.Sample("limen_http_response_bytes_total", float64(totals[n].Bytes), "host", n)
	}
	p.Family("limen_http_request_duration_seconds", "histogram", "Time nginx took to answer a request of a proxy host, from its first byte read to its last byte sent.")
	for _, n := range names {
		t := totals[n]
		var cum int64
		for i, le := range LatencyBuckets {
			cum += t.Latency[i]
			p.Sample("limen_http_request_duration_seconds_bucket", float64(cum), "host", n, "le", formatValue(le))
		}
		cum += t.Latency[len(LatencyBuckets)]
		p.Sample("limen_http_request_duration_seconds_bucket", float64(cum), "host", n, "le", "+Inf")
		p.Sample("limen_http_request_duration_seconds_sum", t.Duration, "host", n)
		p.Sample("limen_http_request_duration_seconds_count", float64(t.Requests), "host", n)
	}
	p.Family("limen_access_log_malformed_lines_total", "counter", "Access log lines that were not in limen's format.")
	p.Sample("limen_access_log_malformed_lines_total", float64(c.Malformed()))

	p.Family("limen_nginx_up", "gauge", "Whether nginx answered limen's last reading of its counters.")
	up := 0.0
	if nginx.OK {
		up = 1
	}
	p.Sample("limen_nginx_up", up)
	if !nginx.OK {
		return
	}
	p.Family("limen_nginx_connections", "gauge", "nginx's client connections, by state.")
	for _, s := range []struct {
		state string
		v     int64
	}{{"active", nginx.Active}, {"reading", nginx.Reading}, {"writing", nginx.Writing}, {"waiting", nginx.Waiting}} {
		p.Sample("limen_nginx_connections", float64(s.v), "state", s.state)
	}
	p.Family("limen_nginx_connections_accepted_total", "counter", "Connections nginx accepted since it started.")
	p.Sample("limen_nginx_connections_accepted_total", float64(nginx.Accepts))
	p.Family("limen_nginx_connections_handled_total", "counter", "Connections nginx handled since it started.")
	p.Sample("limen_nginx_connections_handled_total", float64(nginx.Handled))
	p.Family("limen_nginx_requests_total", "counter", "Requests nginx served since it started, every server included.")
	p.Sample("limen_nginx_requests_total", float64(nginx.Requests))
}
