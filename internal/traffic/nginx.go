package traffic

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// NginxStatus is what nginx's stub_status says: its connections now,
// and its counters since it started.
type NginxStatus struct {
	OK      bool      `json:"ok"`
	Error   string    `json:"error,omitempty"`
	Time    time.Time `json:"time"`
	Active  int64     `json:"active"`
	Reading int64     `json:"reading"`
	Writing int64     `json:"writing"`
	Waiting int64     `json:"waiting"`
	// Accepts, Handled and Requests are nginx's own counters; they
	// start again from zero when nginx restarts.
	Accepts  int64 `json:"accepts"`
	Handled  int64 `json:"handled"`
	Requests int64 `json:"requests"`
	// PerSecond is the request rate between the last two readings.
	PerSecond float64 `json:"per_second"`
}

var (
	activeRe   = regexp.MustCompile(`Active connections:\s*(\d+)`)
	countersRe = regexp.MustCompile(`server accepts handled requests\s+(\d+)\s+(\d+)\s+(\d+)`)
	rwwRe      = regexp.MustCompile(`Reading:\s*(\d+)\s+Writing:\s*(\d+)\s+Waiting:\s*(\d+)`)
)

// ParseStubStatus reads the page ngx_http_stub_status_module writes:
//
//	Active connections: 291
//	server accepts handled requests
//	 16630948 16630948 31070465
//	Reading: 6 Writing: 179 Waiting: 106
func ParseStubStatus(b []byte) (NginxStatus, error) {
	a := activeRe.FindSubmatch(b)
	c := countersRe.FindSubmatch(b)
	r := rwwRe.FindSubmatch(b)
	if a == nil || c == nil || r == nil {
		return NginxStatus{}, fmt.Errorf("not an nginx stub_status page")
	}
	n := func(x []byte) int64 { v, _ := strconv.ParseInt(string(x), 10, 64); return v }
	return NginxStatus{
		OK: true, Active: n(a[1]),
		Accepts: n(c[1]), Handled: n(c[2]), Requests: n(c[3]),
		Reading: n(r[1]), Writing: n(r[2]), Waiting: n(r[3]),
	}, nil
}

// NginxProbe reads nginx's counters from the default server, the way
// the configuration limen renders lets loopback clients do.
type NginxProbe struct {
	// URL is where to ask: http://127.0.0.1<nginx.StatusPath>.
	URL    string
	Client *http.Client

	mu   sync.Mutex
	last NginxStatus
}

// Poll asks nginx once and keeps the answer.
func (p *NginxProbe) Poll(ctx context.Context) NginxStatus {
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second}
	}
	now := time.Now()
	st := NginxStatus{Time: now}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL, nil)
	if err == nil {
		// A name no host answers on: the default server's.
		req.Host = "limen-status.invalid"
		var resp *http.Response
		if resp, err = client.Do(req); err == nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				err = fmt.Errorf("nginx answered %s", resp.Status)
			} else if st, err = ParseStubStatus(b); err == nil {
				st.Time = now
			}
		}
	}
	if err != nil {
		st = NginxStatus{Time: now, Error: err.Error()}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if st.OK && p.last.OK && st.Requests >= p.last.Requests {
		if dt := st.Time.Sub(p.last.Time).Seconds(); dt > 0 {
			st.PerSecond = float64(st.Requests-p.last.Requests) / dt
		}
	}
	p.last = st
	return st
}

// Last returns the latest reading.
func (p *NginxProbe) Last() NginxStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.last
}

// Run polls every interval until stop is closed.
func (p *NginxProbe) Run(stop <-chan struct{}, interval time.Duration) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { <-stop; cancel() }()
	t := time.NewTicker(interval)
	defer t.Stop()
	p.Poll(ctx)
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			p.Poll(ctx)
		}
	}
}
