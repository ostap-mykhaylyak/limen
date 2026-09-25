package traffic

import "testing"

// Log lines are written by nginx from what clients send: whatever they
// hold, reading them must not panic.
func FuzzParseAccess(f *testing.F) {
	f.Add(`{"time":"2026-09-25T10:00:00+00:00","msec":1790000000.123,"remote":"1.2.3.4","host":"a","method":"GET","uri":"/\u0000","proto":"HTTP/1.1","status":200,"bytes":1,"duration":0.001}`)
	f.Add(`{"msec":1e308,"status":-5,"duration":-1}`)
	f.Add(`{"msec":-1e308,"status":999999999999}`)
	f.Fuzz(func(t *testing.T, s string) {
		if e, err := ParseAccess([]byte(s)); err == nil && e.Time.IsZero() {
			t.Fatalf("accepted a line without a time: %q", s)
		}
	})
}

func FuzzParseError(f *testing.F) {
	f.Add(`2026/09/25 10:11:12 [crit] 12#12: *3 SSL_do_handshake() failed, client: 198.51.100.4, request: "GET / HTTP/1.1"`)
	f.Add(`9999/99/99 99:99:99 [x] 1#1: , client: , request: "`)
	f.Fuzz(func(t *testing.T, s string) { ParseError([]byte(s)) })
}
