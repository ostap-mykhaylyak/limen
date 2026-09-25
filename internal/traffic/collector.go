package traffic

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"os"
	"sort"
	"sync"
	"time"
)

// LatencyBuckets are the upper bounds, in seconds, of the latency
// histogram: Prometheus's default buckets, which also give quantiles
// fine enough for a panel.
var LatencyBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// Counts is what is counted of a set of requests.
type Counts struct {
	Requests int64 `json:"requests"`
	// Status classes: [0] 1xx, [1] 2xx ... [4] 5xx.
	Status   [5]int64 `json:"-"`
	Bytes    int64    `json:"bytes"`
	Duration float64  `json:"-"` // sum, seconds
	// Latency is the histogram, one counter per bucket of
	// LatencyBuckets and a last one for anything slower.
	Latency [12]int64 `json:"-"`
}

func (c *Counts) add(e Entry) {
	c.Requests++
	if cl := e.Status/100 - 1; cl >= 0 && cl < 5 {
		c.Status[cl]++
	}
	c.Bytes += e.Bytes
	c.Duration += e.Duration
	i := sort.SearchFloat64s(LatencyBuckets, e.Duration)
	c.Latency[i]++
}

func (c *Counts) merge(o Counts) {
	c.Requests += o.Requests
	for i := range c.Status {
		c.Status[i] += o.Status[i]
	}
	c.Bytes += o.Bytes
	c.Duration += o.Duration
	for i := range c.Latency {
		c.Latency[i] += o.Latency[i]
	}
}

// Quantile estimates a latency quantile from the histogram, the way
// Prometheus's histogram_quantile does: linearly inside the bucket it
// falls in. It returns 0 without requests.
func (c *Counts) Quantile(q float64) float64 {
	if c.Requests == 0 {
		return 0
	}
	rank := q * float64(c.Requests)
	var seen float64
	lower := 0.0
	for i, n := range c.Latency {
		upper := math.Inf(1)
		if i < len(LatencyBuckets) {
			upper = LatencyBuckets[i]
		}
		if seen+float64(n) >= rank && n > 0 {
			if math.IsInf(upper, 1) {
				return lower // slower than the last bound: say the bound
			}
			return lower + (upper-lower)*(rank-seen)/float64(n)
		}
		seen += float64(n)
		lower = upper
	}
	return lower
}

// ring holds the counts of the last len(buckets) periods of step.
type ring struct {
	step    time.Duration
	buckets []Counts
	starts  []int64 // unix start of each bucket, to tell stale ones
}

func newRing(step time.Duration, n int) *ring {
	return &ring{step: step, buckets: make([]Counts, n), starts: make([]int64, n)}
}

// slot returns the bucket of a moment, or -1 when the ring already
// holds a later period there: a request older than the ring's span —
// read back from history, or written late — must not wipe newer counts.
func (r *ring) slot(t time.Time) int {
	start := t.Truncate(r.step).Unix()
	i := int((start / int64(r.step/time.Second)) % int64(len(r.buckets)))
	switch {
	case r.starts[i] == start:
	case r.starts[i] > start:
		return -1
	default:
		r.buckets[i] = Counts{}
		r.starts[i] = start
	}
	return i
}

func (r *ring) add(e Entry) {
	if i := r.slot(e.Time); i >= 0 {
		r.buckets[i].add(e)
	}
}

// window sums the buckets that started within d of now.
func (r *ring) window(now time.Time, d time.Duration) Counts {
	var c Counts
	from := now.Add(-d).Unix()
	step := int64(r.step / time.Second)
	for i, st := range r.starts {
		// A bucket counts when the period it covers overlaps the
		// window; buckets of another day have starts far behind.
		if st+step > from && st <= now.Unix() {
			c.merge(r.buckets[i])
		}
	}
	return c
}

// points returns one point per step over the last d, oldest first,
// with the empty periods as zeros.
func (r *ring) points(now time.Time, d time.Duration) []Point {
	stepSec := int64(r.step / time.Second)
	last := now.Truncate(r.step).Unix()
	n := int(d / r.step)
	byStart := map[int64]Counts{}
	for i, st := range r.starts {
		byStart[st] = r.buckets[i]
	}
	out := make([]Point, 0, n)
	for k := n - 1; k >= 0; k-- {
		st := last - int64(k)*stepSec
		c := byStart[st]
		out = append(out, point(time.Unix(st, 0).UTC(), c))
	}
	return out
}

// Point is the traffic of one period.
type Point struct {
	Start    time.Time `json:"start"`
	Requests int64     `json:"requests"`
	Status   [5]int64  `json:"status"` // 1xx .. 5xx
	Bytes    int64     `json:"bytes"`
	P50      float64   `json:"p50"`
	P95      float64   `json:"p95"`
}

func point(start time.Time, c Counts) Point {
	return Point{Start: start, Requests: c.Requests, Status: c.Status, Bytes: c.Bytes, P50: c.Quantile(0.5), P95: c.Quantile(0.95)}
}

// Summary is the traffic of a host over a window.
type Summary struct {
	Window    string   `json:"window"`
	Requests  int64    `json:"requests"`
	PerSecond float64  `json:"per_second"`
	Status    [5]int64 `json:"status"`
	// ErrorRate is the share of 5xx answers.
	ErrorRate float64 `json:"error_rate"`
	Bytes     int64   `json:"bytes"`
	P50       float64 `json:"p50"`
	P95       float64 `json:"p95"`
	P99       float64 `json:"p99"`
	Mean      float64 `json:"mean"`
}

func summary(window time.Duration, label string, c Counts) Summary {
	s := Summary{Window: label, Requests: c.Requests, Status: c.Status, Bytes: c.Bytes,
		PerSecond: float64(c.Requests) / window.Seconds(),
		P50:       c.Quantile(0.5), P95: c.Quantile(0.95), P99: c.Quantile(0.99)}
	if c.Requests > 0 {
		s.ErrorRate = float64(c.Status[4]) / float64(c.Requests)
		s.Mean = c.Duration / float64(c.Requests)
	}
	return s
}

// host is what is known of one host.
type host struct {
	minutes *ring // 60 × 1 minute
	fives   *ring // 288 × 5 minutes: a day
	// total counts every request read since the daemon started — not
	// the ones read back from history — for monotonic counters.
	total Counts
	last  time.Time // the latest request seen
}

func newHost() *host {
	return &host{minutes: newRing(time.Minute, 60), fives: newRing(5*time.Minute, 288)}
}

// ---------------------------------------------------------------------
// Following the files
// ---------------------------------------------------------------------

// follower reads an access log as it grows.
//
// A rotation is two steps apart for nginx: logrotate renames the file
// (and with `create` makes a new empty one at once, as does the
// `nginx -t` of a reload), and only later does nginx reopen, when it is
// signalled — until then it goes on writing to the renamed file. So a
// new file at the path does not mean the old one is finished: the
// follower keeps the old one open and reads both, and lets it go only
// once it has been quiet for rotationGrace polls.
type follower struct {
	path  string
	cur   cursor
	prev  *cursor // the file before the last rotation
	quiet int     // polls prev has gone without a line
}

// cursor is an open file and where its reading stands.
type cursor struct {
	f       *os.File
	offset  int64
	partial []byte
}

func (c *cursor) close() {
	if c != nil && c.f != nil {
		c.f.Close()
		c.f = nil
	}
}

// rotationGrace is how many quiet polls a rotated file is still read
// for: a minute at the daemon's two seconds.
const rotationGrace = 30

// History bounds what is read back when a log is first opened: the
// last Day of requests, from at most HistoryBytes at its end.
const (
	Day          = 24 * time.Hour
	HistoryBytes = 32 << 20
)

// Collector counts the traffic of the hosts from their access logs.
type Collector struct {
	// Path returns the access log of a host.
	Path func(host string) string
	Log  *slog.Logger

	mu        sync.Mutex
	hosts     map[string]*host
	followers map[string]*follower
	now       func() time.Time
	malformed int64
}

// NewCollector returns a collector reading the logs Path names.
func NewCollector(path func(host string) string, log *slog.Logger) *Collector {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Collector{Path: path, Log: log, hosts: map[string]*host{}, followers: map[string]*follower{}, now: time.Now}
}

// Watch sets the hosts whose logs are followed: new ones are opened
// (and their recent history read), gone ones closed and forgotten.
func (c *Collector) Watch(names []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
		if _, ok := c.hosts[n]; !ok {
			c.hosts[n] = newHost()
		}
	}
	for n, fl := range c.followers {
		if !want[n] {
			fl.cur.close()
			fl.prev.close()
			delete(c.followers, n)
		}
	}
	for n := range c.hosts {
		if !want[n] {
			delete(c.hosts, n)
		}
	}
	for n := range want {
		if _, ok := c.followers[n]; !ok {
			c.followers[n] = &follower{path: c.Path(n)}
		}
	}
}

// Close closes every followed file.
func (c *Collector) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for n, fl := range c.followers {
		fl.cur.close()
		fl.prev.close()
		delete(c.followers, n)
	}
}

// Poll reads what the followed logs gained since the last call.
func (c *Collector) Poll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for name, fl := range c.followers {
		c.poll(name, fl)
	}
}

// Run polls every interval until stop is closed.
func (c *Collector) Run(stop <-chan struct{}, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	c.Poll()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			c.Poll()
		}
	}
}

func (c *Collector) poll(name string, fl *follower) {
	h := c.hosts[name]
	if fl.cur.f == nil {
		f, err := os.Open(fl.path)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				c.Log.Warn("access log", "host", name, "error", err.Error())
			}
			return
		}
		fl.cur = cursor{f: f, offset: c.history(name, f, h)}
	}
	c.drain(name, &fl.cur, h)

	if fl.prev != nil {
		if c.drain(name, fl.prev, h) > 0 {
			fl.quiet = 0
		} else if fl.quiet++; fl.quiet >= rotationGrace {
			fl.prev.close()
			fl.prev = nil
		}
	}

	// Rotated: the path is another file now. The old one is kept, and
	// read until nginx has let go of it.
	path, err1 := os.Stat(fl.path)
	open, err2 := fl.cur.f.Stat()
	if err1 == nil && err2 == nil && !os.SameFile(path, open) {
		f, err := os.Open(fl.path)
		if err != nil {
			return
		}
		if fl.prev != nil {
			// Rotated twice within the grace: the oldest is done.
			c.drain(name, fl.prev, h)
			fl.prev.close()
		}
		old := fl.cur
		fl.prev, fl.quiet = &old, 0
		fl.cur = cursor{f: f}
		c.drain(name, &fl.cur, h)
		return
	}
	// Truncated in place (copytruncate): start again from the top.
	if err2 == nil && open.Size() < fl.cur.offset {
		fl.cur.offset, fl.cur.partial = 0, nil
		c.drain(name, &fl.cur, h)
	}
}

// drain reads from a cursor to the end of its file, counting what it
// reads as live requests, and returns how many bytes it read.
func (c *Collector) drain(name string, cur *cursor, h *host) int {
	read := 0
	for {
		buf := make([]byte, 256<<10)
		n, err := cur.f.ReadAt(buf, cur.offset)
		if n > 0 {
			read += n
			cur.offset += int64(n)
			data := append(cur.partial, buf[:n]...)
			last := bytes.LastIndexByte(data, '\n')
			if last < 0 {
				cur.partial = data
			} else {
				c.lines(h, data[:last], true)
				cur.partial = append([]byte(nil), data[last+1:]...)
			}
		}
		if err != nil || n < len(buf) {
			if err != nil && !errors.Is(err, io.EOF) {
				c.Log.Warn("access log", "host", name, "error", err.Error())
			}
			return read
		}
	}
}

// history reads back the last day of requests when a log is first
// opened, and returns the offset to follow it from. After a daily
// rotation most of that day is in the previous file, which the shipped
// logrotate policy keeps uncompressed (delaycompress): it is read too,
// first, from whatever the current file leaves of HistoryBytes.
func (c *Collector) history(name string, f *os.File, h *host) int64 {
	info, err := f.Stat()
	if err != nil {
		return 0
	}
	size := info.Size()
	budget := int64(HistoryBytes) - size
	if budget > 0 {
		if prev, err := os.Open(c.Path(name) + ".1"); err == nil {
			if pi, err := prev.Stat(); err == nil {
				if data, _ := tailBytes(prev, pi.Size(), budget); len(data) > 0 {
					c.lines(h, data, false)
				}
			}
			prev.Close()
		}
	}
	data, rest := tailBytes(f, size, HistoryBytes)
	if len(data) > 0 {
		c.lines(h, data, false)
	}
	c.Log.Debug("access log history read", "host", name, "bytes", len(data))
	// Follow from the start of a line still being written, if any.
	return size - int64(rest)
}

// tailBytes returns the whole lines of the last max bytes of a file of
// the given size, and how many bytes follow the last newline.
func tailBytes(f *os.File, size, max int64) ([]byte, int) {
	from := size - max
	if from < 0 {
		from = 0
	}
	buf := make([]byte, size-from)
	n, _ := f.ReadAt(buf, from)
	buf = buf[:n]
	if from > 0 {
		// Skip the line cut by the window.
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			buf = buf[i+1:]
		} else {
			return nil, len(buf)
		}
	}
	last := bytes.LastIndexByte(buf, '\n')
	if last < 0 {
		return nil, len(buf)
	}
	return buf[:last], len(buf) - last - 1
}

func (c *Collector) lines(h *host, data []byte, live bool) {
	cutoff := c.now().Add(-Day)
	for l := range bytes.SplitSeq(data, []byte("\n")) {
		if len(l) == 0 {
			continue
		}
		e, err := ParseAccess(l)
		if err != nil {
			c.malformed++
			continue
		}
		if e.Time.Before(cutoff) {
			continue
		}
		h.minutes.add(e)
		h.fives.add(e)
		if live {
			h.total.add(e)
		}
		if e.Time.After(h.last) {
			h.last = e.Time
		}
	}
}

// ---------------------------------------------------------------------
// Reading the counts
// ---------------------------------------------------------------------

// Windows the panel and the status ask for.
var windows = map[string]time.Duration{"5m": 5 * time.Minute, "1h": time.Hour, "24h": Day}

// ParseWindow reads "5m", "1h" or "24h".
func ParseWindow(s string) (time.Duration, bool) {
	d, ok := windows[s]
	return d, ok
}

func windowLabel(d time.Duration) string {
	for k, v := range windows {
		if v == d {
			return k
		}
	}
	return d.String()
}

// HostSummary is a host's traffic over a window.
func (c *Collector) HostSummary(name string, d time.Duration) (Summary, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	h, ok := c.hosts[name]
	if !ok {
		return Summary{}, false
	}
	return summary(d, windowLabel(d), c.counts(h, d)), true
}

func (c *Collector) counts(h *host, d time.Duration) Counts {
	if d <= time.Hour {
		return h.minutes.window(c.now(), d)
	}
	return h.fives.window(c.now(), d)
}

// Series is a host's traffic over a window, one point per minute for
// an hour or less, per five minutes beyond. An empty name sums every
// host.
func (c *Collector) Series(name string, d time.Duration) ([]Point, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	pick := func(h *host) *ring {
		if d <= time.Hour {
			return h.minutes
		}
		return h.fives
	}
	if name != "" {
		h, ok := c.hosts[name]
		if !ok {
			return nil, false
		}
		return pick(h).points(c.now(), d), true
	}
	var sum []Point
	for _, h := range c.hosts {
		ps := pick(h).points(c.now(), d)
		if sum == nil {
			sum = ps
			continue
		}
		for i := range sum {
			sum[i].Requests += ps[i].Requests
			sum[i].Bytes += ps[i].Bytes
			for k := range sum[i].Status {
				sum[i].Status[k] += ps[i].Status[k]
			}
			// Quantiles do not add up: the sum keeps the worst.
			sum[i].P50 = math.Max(sum[i].P50, ps[i].P50)
			sum[i].P95 = math.Max(sum[i].P95, ps[i].P95)
		}
	}
	if sum == nil {
		sum = newRing(stepFor(d), 1).points(c.now(), d)
	}
	return sum, true
}

func stepFor(d time.Duration) time.Duration {
	if d <= time.Hour {
		return time.Minute
	}
	return 5 * time.Minute
}

// HostRow is one host in the traffic overview.
type HostRow struct {
	Name    string    `json:"name"`
	Summary Summary   `json:"summary"`
	Last    time.Time `json:"last_request,omitzero"`
}

// Overview summarizes every host over a window, the busiest first.
func (c *Collector) Overview(d time.Duration) []HostRow {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]HostRow, 0, len(c.hosts))
	for name, h := range c.hosts {
		out = append(out, HostRow{Name: name, Summary: summary(d, windowLabel(d), c.counts(h, d)), Last: h.last})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Summary.Requests != out[j].Summary.Requests {
			return out[i].Summary.Requests > out[j].Summary.Requests
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Totals are the monotonic counters of a host since the daemon started.
func (c *Collector) Totals() map[string]Counts {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]Counts, len(c.hosts))
	for name, h := range c.hosts {
		out[name] = h.total
	}
	return out
}

// Malformed is how many lines could not be read as limen's format.
func (c *Collector) Malformed() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.malformed
}
