// Package traffic reads what nginx writes about the requests it
// serves — the per-host access and error logs — for the log viewer, and
// counts the metrics limen publishes from them.
//
// The logs are the source of truth. The metrics are derived from them,
// in memory, and rebuilt from them when the daemon starts: nothing is
// counted twice, and nothing depends on limen having been running when
// the request arrived.
package traffic

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Entry is one request of an access log, as nginx wrote it in limen's
// format (nginx.LogFormat).
type Entry struct {
	Time           time.Time `json:"time"`
	Remote         string    `json:"remote"`
	Host           string    `json:"host"`
	Method         string    `json:"method"`
	URI            string    `json:"uri"`
	Proto          string    `json:"proto"`
	Status         int       `json:"status"`
	Bytes          int64     `json:"bytes"`
	Duration       float64   `json:"duration"` // seconds
	Upstream       string    `json:"upstream,omitempty"`
	UpstreamStatus string    `json:"upstream_status,omitempty"`
	UpstreamTime   string    `json:"upstream_time,omitempty"`
	TLS            string    `json:"tls,omitempty"`
	Referer        string    `json:"referer,omitempty"`
	Agent          string    `json:"agent,omitempty"`
}

type rawEntry struct {
	Msec           float64 `json:"msec"`
	Remote         string  `json:"remote"`
	Host           string  `json:"host"`
	Method         string  `json:"method"`
	URI            string  `json:"uri"`
	Proto          string  `json:"proto"`
	Status         int     `json:"status"`
	Bytes          int64   `json:"bytes"`
	Duration       float64 `json:"duration"`
	Upstream       string  `json:"upstream"`
	UpstreamStatus string  `json:"upstream_status"`
	UpstreamTime   string  `json:"upstream_time"`
	TLS            string  `json:"tls"`
	Referer        string  `json:"referer"`
	Agent          string  `json:"agent"`
}

// ErrNotJSON is a line that is not one of limen's: a log written before
// limen took over the file, or by hand.
var ErrNotJSON = errors.New("not a line of limen's access log format")

// ParseAccess reads one line of an access log.
func ParseAccess(line []byte) (Entry, error) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 || line[0] != '{' {
		return Entry{}, ErrNotJSON
	}
	var r rawEntry
	if err := json.Unmarshal(line, &r); err != nil {
		return Entry{}, fmt.Errorf("%w: %v", ErrNotJSON, err)
	}
	if r.Msec <= 0 || r.Status == 0 {
		return Entry{}, ErrNotJSON
	}
	sec, frac := math.Modf(r.Msec)
	e := Entry{
		Time:   time.Unix(int64(sec), int64(math.Round(frac*1000))*int64(time.Millisecond)).UTC(),
		Remote: r.Remote, Host: r.Host, Method: r.Method, URI: r.URI, Proto: r.Proto,
		Status: r.Status, Bytes: r.Bytes, Duration: r.Duration,
		Upstream: r.Upstream, UpstreamStatus: r.UpstreamStatus, UpstreamTime: r.UpstreamTime,
		TLS: r.TLS, Referer: r.Referer, Agent: r.Agent,
	}
	return e, nil
}

// ErrorLine is one line of an nginx error log.
type ErrorLine struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
	Client  string    `json:"client,omitempty"`
	Request string    `json:"request,omitempty"`
}

var (
	errorLineRe = regexp.MustCompile(`^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) \[(\w+)\] \d+#\d+: (?:\*\d+ )?(.*)$`)
	clientRe    = regexp.MustCompile(`, client: ([^,]+)`)
	requestRe   = regexp.MustCompile(`, request: "([^"]*)"`)
)

// ParseError reads one line of an nginx error log. nginx writes its
// times in the machine's local zone, which is the zone they are read
// in. A line that does not look like one (a continuation, a note
// written by something else) comes back whole, as the message.
func ParseError(line []byte) ErrorLine {
	s := strings.TrimRight(string(line), "\r\n")
	m := errorLineRe.FindStringSubmatch(s)
	if m == nil {
		return ErrorLine{Message: s}
	}
	t, _ := time.ParseInLocation("2006/01/02 15:04:05", m[1], time.Local)
	e := ErrorLine{Time: t, Level: m[2], Message: m[3]}
	if c := clientRe.FindStringSubmatch(m[3]); c != nil {
		e.Client = c[1]
	}
	if r := requestRe.FindStringSubmatch(m[3]); r != nil {
		e.Request = r[1]
	}
	return e
}

// ---------------------------------------------------------------------
// Reading a log
// ---------------------------------------------------------------------

const chunk = 64 << 10

// Tail returns up to n lines from the end of a file, oldest first,
// keeping only those match accepts (nil keeps all), and the size of the
// file when it was read — the offset to follow it from. It reads
// backwards, and gives up after maxScan bytes: a filter that matches
// nothing must not read a log of gigabytes.
func Tail(path string, n int, match func([]byte) bool, maxScan int64) ([][]byte, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	size := info.Size()

	var out [][]byte
	var carry []byte // the start of a line whose beginning is further back
	pos := size
	scanned := int64(0)
	for pos > 0 && len(out) < n && scanned < maxScan {
		step := min(pos, int64(chunk))
		pos -= step
		scanned += step
		buf := make([]byte, step, step+int64(len(carry)))
		if _, err := f.ReadAt(buf, pos); err != nil && !errors.Is(err, io.EOF) {
			return nil, 0, err
		}
		buf = append(buf, carry...)
		lines := bytes.Split(buf, []byte("\n"))
		// The first piece may be cut: it goes back to the next round,
		// unless the start of the file is reached.
		if pos > 0 {
			carry = append([]byte(nil), lines[0]...)
			lines = lines[1:]
		} else {
			carry = nil
		}
		for i := len(lines) - 1; i >= 0 && len(out) < n; i-- {
			l := lines[i]
			if len(l) == 0 {
				continue
			}
			if match == nil || match(l) {
				out = append(out, append([]byte(nil), l...))
			}
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, size, nil
}

// From returns the whole lines written after offset, up to max of them
// and up to maxBytes read, and the offset to continue from. A file
// smaller than the offset has been rotated or truncated: it is read
// from its start. A line still being written is left for the next call.
func From(path string, offset int64, max int, match func([]byte) bool, maxBytes int64) ([][]byte, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, offset, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, offset, err
	}
	if info.Size() < offset {
		offset = 0
	}
	want := min(info.Size()-offset, maxBytes)
	if want <= 0 {
		return nil, offset, nil
	}
	buf := make([]byte, want)
	n, err := f.ReadAt(buf, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, offset, err
	}
	buf = buf[:n]
	end := bytes.LastIndexByte(buf, '\n')
	if end < 0 {
		return nil, offset, nil
	}
	var out [][]byte
	consumed := 0
	for l := range bytes.SplitSeq(buf[:end], []byte("\n")) {
		consumed += len(l) + 1
		if len(l) > 0 && (match == nil || match(l)) {
			out = append(out, l)
			if len(out) == max {
				break
			}
		}
	}
	return out, offset + int64(consumed), nil
}

// StatusClass reads "5xx", "4xx", ... into the hundreds it stands for,
// or 0 for anything else.
func StatusClass(s string) int {
	if len(s) == 3 && s[1:] == "xx" && s[0] >= '1' && s[0] <= '5' {
		return int(s[0]-'0') * 100
	}
	if v, err := strconv.Atoi(s); err == nil && v >= 100 && v <= 599 {
		return v
	}
	return 0
}
