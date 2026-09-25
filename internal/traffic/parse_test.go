package traffic

import (
	"errors"
	"testing"
	"time"
)

func TestParseAccessRefusesWhatIsNotLimensFormat(t *testing.T) {
	for _, l := range []string{
		`203.0.113.7 - - [25/Sep/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 12 "-" "curl"`, // combined
		`{"msg":"a JSON line of something else"}`,
		`{"msec":1.5,"status":`,
		``,
	} {
		if _, err := ParseAccess([]byte(l)); !errors.Is(err, ErrNotJSON) {
			t.Errorf("%q: err = %v", l, err)
		}
	}
	e, err := ParseAccess([]byte(`{"msec":1790000000.123,"status":204,"duration":0.004}`))
	if err != nil || e.Status != 204 || !e.Time.Equal(time.Unix(1790000000, 123e6)) {
		t.Errorf("%+v %v", e, err)
	}
}

// The line format of the nginx documentation and of every nginx error
// log: time, [level], pid#tid, *connection, message.
func TestParseError(t *testing.T) {
	e := ParseError([]byte(`2026/09/25 10:11:12 [crit] 12#12: *3 SSL_do_handshake() failed, client: 198.51.100.4, server: 0.0.0.0:443`))
	if e.Level != "crit" || e.Client != "198.51.100.4" || e.Message != "SSL_do_handshake() failed, client: 198.51.100.4, server: 0.0.0.0:443" {
		t.Errorf("%+v", e)
	}
	if e.Time.Hour() != 10 || e.Time.Location() != time.Local {
		t.Errorf("time %v: nginx writes local time", e.Time)
	}
	// Without a connection (a reload), and a line that is not one.
	if e := ParseError([]byte(`2026/09/25 10:11:12 [notice] 1#1: signal process started`)); e.Level != "notice" || e.Message != "signal process started" {
		t.Errorf("%+v", e)
	}
	if e := ParseError([]byte("  continuation")); !e.Time.IsZero() || e.Message != "  continuation" {
		t.Errorf("%+v", e)
	}
}

func TestStatusClass(t *testing.T) {
	for in, want := range map[string]int{"5xx": 500, "2xx": 200, "404": 404, "6xx": 0, "abc": 0, "99": 0, "": 0} {
		if got := StatusClass(in); got != want {
			t.Errorf("%q = %d, want %d", in, got, want)
		}
	}
}
