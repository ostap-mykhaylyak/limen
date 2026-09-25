package traffic

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// line writes a request in limen's log format. The format itself is
// checked against lines real nginx writes (see the integration test in
// internal/nginx/integration_m7_test.go); here it
// only feeds the counting.
func line(t time.Time, status int, bytes int64, dur float64) string {
	ms := float64(t.UnixMilli()) / 1000
	return fmt.Sprintf(`{"time":"%s","msec":%.3f,"remote":"10.0.0.1","host":"app.example.com","method":"GET","uri":"/x","proto":"HTTP/1.1","status":%d,"bytes":%d,"duration":%.3f,"upstream":"","upstream_status":"","upstream_time":"","tls":"","referer":"","agent":"test"}`+"\n",
		t.Format(time.RFC3339), ms, status, bytes, dur)
}

func appendTo(t *testing.T, path string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, l := range lines {
		f.WriteString(l)
	}
}

func TestTailReadsBackwardsAcrossChunks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.log")
	var b strings.Builder
	for i := range 5000 {
		fmt.Fprintf(&b, "line %05d %s\n", i, strings.Repeat("x", 80))
	}
	os.WriteFile(path, []byte(b.String()), 0o644)

	got, end, err := Tail(path, 3, nil, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || !strings.HasPrefix(string(got[0]), "line 04997") || !strings.HasPrefix(string(got[2]), "line 04999") {
		t.Errorf("tail = %q", got)
	}
	if end != int64(b.Len()) {
		t.Errorf("end = %d, want the size %d", end, b.Len())
	}
	// A filter far back: lines cut by the chunk borders must come out
	// whole.
	odd := func(l []byte) bool { return strings.HasPrefix(string(l), "line 0012") }
	got, _, _ = Tail(path, 100, odd, 1<<30)
	if len(got) != 10 || string(got[0][:10]) != "line 00120" {
		t.Errorf("filtered tail = %d lines, first %q", len(got), got[0][:10])
	}
	for _, l := range got {
		if len(l) != len("line 00000 ")+80 {
			t.Errorf("a line came out cut: %q", l)
		}
	}
	// The whole file back: every line whole, across every chunk border.
	all, _, _ := Tail(path, 10000, nil, 1<<30)
	if len(all) != 5000 {
		t.Errorf("read back %d lines, want 5000", len(all))
	}
	for i, l := range all {
		if want := fmt.Sprintf("line %05d ", i); !strings.HasPrefix(string(l), want) || len(l) != len(want)+80 {
			t.Fatalf("line %d came out as %q", i, l)
		}
	}
	// A filter that matches nothing stops at maxScan.
	got, _, _ = Tail(path, 10, func([]byte) bool { return false }, 100<<10)
	if len(got) != 0 {
		t.Errorf("got %d lines", len(got))
	}
}

func TestFromReadsWholeLinesAndStartsAgainAfterATruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.log")
	os.WriteFile(path, []byte("a\nb\nhalf"), 0o644)
	got, off, _ := From(path, 0, 100, nil, 1<<20)
	if len(got) != 2 || off != 4 {
		t.Fatalf("got %q, offset %d: the half line is not read yet", got, off)
	}
	appendTo(t, path, " line\n")
	got, off, _ = From(path, off, 100, nil, 1<<20)
	if len(got) != 1 || string(got[0]) != "half line" {
		t.Errorf("then %q", got)
	}
	os.WriteFile(path, []byte("new\n"), 0o644) // rotated with copytruncate
	got, _, _ = From(path, off, 100, nil, 1<<20)
	if len(got) != 1 || string(got[0]) != "new" {
		t.Errorf("after the truncation %q", got)
	}
}

func collectorAt(t *testing.T, now time.Time) (*Collector, string) {
	dir := t.TempDir()
	c := NewCollector(func(h string) string { return filepath.Join(dir, h+".access.log") }, nil)
	c.now = func() time.Time { return now }
	t.Cleanup(c.Close)
	return c, dir
}

func TestCollectorCountsWindowsAndQuantiles(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 30, 30, 0, time.UTC)
	c, dir := collectorAt(t, now)
	path := filepath.Join(dir, "app.access.log")
	os.WriteFile(path, nil, 0o644)
	c.Watch([]string{"app"})
	c.Poll()

	var lines []string
	// 90 fast 200s and 10 slow 502s in the last two minutes.
	for range 90 {
		lines = append(lines, line(now.Add(-time.Minute), 200, 1000, 0.02))
	}
	for range 10 {
		lines = append(lines, line(now.Add(-30*time.Second), 502, 100, 3))
	}
	// And 50 requests three hours ago: in 24h, not in 1h.
	for range 50 {
		lines = append(lines, line(now.Add(-3*time.Hour), 404, 10, 0.001))
	}
	appendTo(t, path, lines...)
	c.Poll()

	s5, ok := c.HostSummary("app", 5*time.Minute)
	if !ok || s5.Requests != 100 || s5.Status[1] != 90 || s5.Status[4] != 10 || s5.Bytes != 91000 {
		t.Fatalf("5m = %+v", s5)
	}
	if s5.ErrorRate != 0.1 {
		t.Errorf("error rate %v, want 0.1", s5.ErrorRate)
	}
	// 50th of 100 requests, the 90 fast ones all in the 10-25ms bucket:
	// interpolated like Prometheus, 10ms + 15ms × 50/90.
	if want := 0.01 + 0.015*50/90; s5.P50 < want-1e-9 || s5.P50 > want+1e-9 {
		t.Errorf("p50 %v, want %v", s5.P50, want)
	}
	if s5.P95 < 2.5 || s5.P95 > 5 {
		t.Errorf("p95 %v, want within the 2.5-5s bucket", s5.P95)
	}
	if s24, _ := c.HostSummary("app", Day); s24.Requests != 150 || s24.Status[3] != 50 {
		t.Errorf("24h = %+v", s24)
	}

	pts, _ := c.Series("app", time.Hour)
	if len(pts) != 60 {
		t.Fatalf("%d points in an hour, want 60", len(pts))
	}
	if last := pts[59]; last.Requests != 10 || pts[58].Requests != 90 {
		t.Errorf("the last two minutes: %d and %d", pts[58].Requests, last.Requests)
	}
	if total, _ := c.Series("", time.Hour); total[58].Requests != 90 {
		t.Error("the sum of every host differs from the only host")
	}
}

func TestCollectorReadsHistoryButCountsOnlyWhatItSees(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	c, dir := collectorAt(t, now)
	path := filepath.Join(dir, "app.access.log")
	appendTo(t, path,
		line(now.Add(-2*Day), 200, 1, 0.1), // too old
		line(now.Add(-time.Hour), 200, 1, 0.1),
		line(now.Add(-time.Minute), 500, 1, 0.1),
		"not json at all\n",
		`{"half":`) // being written
	c.Watch([]string{"app"})
	c.Poll()

	if s, _ := c.HostSummary("app", Day); s.Requests != 2 {
		t.Errorf("history: %d requests, want 2 (one is older than a day)", s.Requests)
	}
	if tot := c.Totals()["app"]; tot.Requests != 0 {
		t.Errorf("history counted in the totals: %d — a restart would jump every counter", tot.Requests)
	}
	appendTo(t, path, "\n", line(now, 200, 1, 0.1))
	c.Poll()
	if tot := c.Totals()["app"]; tot.Requests != 1 {
		t.Errorf("totals = %d, want the one new request", tot.Requests)
	}
	if c.Malformed() != 2 {
		t.Errorf("malformed = %d, want 2", c.Malformed())
	}
}

func TestHistoryReadsTheRotatedFileToo(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	c, dir := collectorAt(t, now)
	path := filepath.Join(dir, "app.access.log")
	// Yesterday's rotation: the night in .1, the morning in the file.
	appendTo(t, path+".1", line(now.Add(-10*time.Hour), 200, 1, 0.1), line(now.Add(-9*time.Hour), 500, 1, 0.1))
	appendTo(t, path, line(now.Add(-time.Hour), 200, 1, 0.1))
	c.Watch([]string{"app"})
	c.Poll()
	if s, _ := c.HostSummary("app", Day); s.Requests != 3 || s.Status[4] != 1 {
		t.Errorf("history = %+v, want the 3 requests of both files", s)
	}
	if c.Totals()["app"].Requests != 0 {
		t.Error("history in the totals")
	}
}

func TestCollectorFollowsARotation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not rename a file another handle holds open; logrotate runs on Linux, and so does CI")
	}
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	c, dir := collectorAt(t, now)
	path := filepath.Join(dir, "app.access.log")
	os.WriteFile(path, nil, 0o644)
	c.Watch([]string{"app"})
	c.Poll()
	nginx := f(t, path, 1) // nginx's handle on its log
	nginx.WriteString(line(now, 200, 1, 0.1))

	// logrotate renames the file and, with `create`, makes a new empty
	// one at once; nginx has not been told yet.
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, nil, 0o644)
	nginx.WriteString(line(now, 201, 1, 0.1))
	c.Poll()                                  // the collector sees the new file here
	nginx.WriteString(line(now, 202, 1, 0.1)) // still to the old one
	c.Poll()

	// postrotate: nginx reopens, and writes to the new file.
	nginx.Close()
	appendTo(t, path, line(now, 203, 1, 0.1))
	c.Poll()
	if tot := c.Totals()["app"]; tot.Requests != 4 {
		t.Errorf("%d requests counted, want 4: the old file must be read until nginx lets go of it", tot.Requests)
	}
}

func TestCollectorLetsGoOfARotatedFileOnceQuiet(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("rename of an open file: Linux behaviour")
	}
	now := time.Now()
	c, dir := collectorAt(t, now)
	path := filepath.Join(dir, "app.access.log")
	os.WriteFile(path, nil, 0o644)
	c.Watch([]string{"app"})
	c.Poll()
	os.Rename(path, path+".1")
	os.WriteFile(path, nil, 0o644)
	c.Poll()
	fl := c.followers["app"]
	if fl.prev == nil {
		t.Fatal("the rotated file was dropped at once")
	}
	for range rotationGrace {
		c.Poll()
	}
	if fl.prev != nil {
		t.Errorf("the rotated file is still open after %d quiet polls", rotationGrace)
	}
}

// f opens a file for appending, as nginx holds its log.
func f(t *testing.T, path string, _ int) *os.File {
	fh, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	return fh
}

func TestCollectorForgetsHostsItNoLongerWatches(t *testing.T) {
	now := time.Now()
	c, dir := collectorAt(t, now)
	appendTo(t, filepath.Join(dir, "a.access.log"), line(now, 200, 1, 0.1))
	c.Watch([]string{"a", "b"})
	c.Poll()
	c.Watch([]string{"b"})
	if _, ok := c.HostSummary("a", time.Hour); ok {
		t.Error("a is still counted")
	}
	if rows := c.Overview(time.Hour); len(rows) != 1 || rows[0].Name != "b" {
		t.Errorf("overview = %+v", rows)
	}
}

// The page as the nginx documentation shows it.
func TestParseStubStatus(t *testing.T) {
	page := "Active connections: 291 \nserver accepts handled requests\n 16630948 16630948 31070465 \nReading: 6 Writing: 179 Waiting: 106 \n"
	st, err := ParseStubStatus([]byte(page))
	if err != nil {
		t.Fatal(err)
	}
	want := NginxStatus{OK: true, Active: 291, Accepts: 16630948, Handled: 16630948, Requests: 31070465, Reading: 6, Writing: 179, Waiting: 106}
	if st != want {
		t.Errorf("got %+v", st)
	}
	if _, err := ParseStubStatus([]byte("<html>404</html>")); err == nil {
		t.Error("a 404 page parsed")
	}
}

var sampleRe = regexp.MustCompile(`^([a-z_]+)(\{[^}]*\})? (\S+)$`)

func TestPrometheusOutputIsWellFormed(t *testing.T) {
	now := time.Now()
	c, dir := collectorAt(t, now)
	os.WriteFile(filepath.Join(dir, "app.access.log"), nil, 0o644)
	c.Watch([]string{"app"})
	c.Poll()
	appendTo(t, filepath.Join(dir, "app.access.log"), line(now, 200, 10, 0.003), line(now, 200, 10, 0.2), line(now, 503, 5, 30))
	c.Poll()

	var buf bytes.Buffer
	p := NewProm(&buf)
	c.WritePrometheus(p, NginxStatus{OK: true, Active: 3, Requests: 9})
	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	var lastBucket, count float64
	for l := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		if strings.HasPrefix(l, "# ") {
			continue
		}
		m := sampleRe.FindStringSubmatch(l)
		if m == nil {
			t.Errorf("not a sample: %q", l)
			continue
		}
		v, err := strconv.ParseFloat(m[3], 64)
		if err != nil {
			t.Errorf("value %q", l)
		}
		if strings.Contains(l, `le="+Inf"`) {
			lastBucket = v
		}
		if strings.HasPrefix(l, "limen_http_request_duration_seconds_count") {
			count = v
		}
	}
	if lastBucket != 3 || count != 3 {
		t.Errorf("+Inf bucket %v and count %v, want 3 and 3", lastBucket, count)
	}
	for _, want := range []string{
		`limen_http_requests_total{host="app",code="5xx"} 1`,
		`limen_http_request_duration_seconds_bucket{host="app",le="0.005"} 1`,
		`limen_nginx_connections{state="active"} 3`,
		"# TYPE limen_http_request_duration_seconds histogram",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
