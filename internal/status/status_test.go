package status

import (
	"bytes"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ostap-mykhaylyak/limen/internal/metrics"
)

func TestWorstCheckDecidesTheAggregate(t *testing.T) {
	cases := []struct {
		name   string
		checks []string
		want   string
		exit   int
	}{
		{"all good", []string{StatusOK, StatusOK}, StatusOK, ExitOK},
		{"one warning", []string{StatusOK, StatusWarn}, StatusWarn, ExitWarning},
		{"critical wins over warning", []string{StatusWarn, StatusCritical, StatusOK}, StatusCritical, ExitCritical},
		{"unknown is worse than a warning", []string{StatusWarn, StatusUnknown}, StatusUnknown, ExitUnknown},
		{"critical wins over unknown", []string{StatusUnknown, StatusCritical}, StatusCritical, ExitCritical},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var rep Report
			for i, s := range c.checks {
				rep.Add("check", s, "")
				_ = i
			}
			rep.Finish()
			if rep.Status != c.want {
				t.Errorf("status = %q, want %q", rep.Status, c.want)
			}
			if got := rep.ExitCode(); got != c.exit {
				t.Errorf("exit code = %d, want %d", got, c.exit)
			}
		})
	}
}

func TestFinishStampsTheReport(t *testing.T) {
	var rep Report
	rep.Finish()
	if rep.Timestamp == "" {
		t.Error("Finish left the timestamp empty")
	}
	if rep.Status != StatusOK {
		t.Errorf("a report without checks is %q, want ok", rep.Status)
	}
}

func TestSummaryOfAStoppedService(t *testing.T) {
	var rep Report
	rep.Config.Path = "/etc/limen/config.yaml"
	rep.Config.Valid = true
	rep.Add("socket", StatusCritical, "service not running")
	rep.Finish()

	got := rep.Summary()
	if !strings.HasPrefix(got, "limen CRITICAL") {
		t.Errorf("summary = %q, want it to start with the aggregate status", got)
	}
	if !strings.Contains(got, "service not running") {
		t.Errorf("summary = %q, want it to say the service is down", got)
	}
	// "installed but stopped" must be distinguishable from "never
	// installed": that is the whole point of the offline fallback.
	if !strings.Contains(got, "config valid") {
		t.Errorf("summary = %q, want it to report the config on disk", got)
	}
}

func TestSummaryOfARunningService(t *testing.T) {
	rep := Report{
		Service: Service{Active: true, PID: 42, UptimeSeconds: 3725},
		Config:  ConfigState{Path: "/etc/limen/config.yaml", Valid: true},
		Nginx:   NginxState{Running: true},
		Model:   ModelState{Hosts: 7, Certs: 3},
	}
	rep.Finish()

	got := rep.Summary()
	for _, want := range []string{"limen OK", "pid 42", "1h 2m", "7 host(s) / 3 cert(s)", "nginx up"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary = %q, want it to contain %q", got, want)
		}
	}
}

func TestTextReportShowsLiveCountersAndChecks(t *testing.T) {
	snap := metrics.Snapshot{RequestsTotal: 10, RequestsFailed: 1, RequestsInFlight: 2}
	rep := Report{
		Service: Service{Active: true, PID: 1, UptimeSeconds: 10},
		Config:  ConfigState{Path: "/etc/limen/config.yaml", Valid: true, Warnings: []string{"no contact email"}},
		Nginx:   NginxState{Running: false, ConfDir: "/etc/nginx"},
		Live:    &snap,
	}
	rep.Add("nginx", StatusWarn, "nginx is not running")
	rep.Finish()

	var buf bytes.Buffer
	rep.WriteText(&buf, nil)
	out := buf.String()
	for _, want := range []string{"SERVICE", "MODEL", "LIVE", "2 in flight", "CONFIG WARNINGS", "no contact email", "CHECKS", "nginx is not running"} {
		if !strings.Contains(out, want) {
			t.Errorf("text report is missing %q:\n%s", want, out)
		}
	}
}

func TestJSONFieldNamesAreTheDocumentedOnes(t *testing.T) {
	snap := metrics.Snapshot{RequestsInFlight: 3}
	rep := Report{Live: &snap}
	rep.Finish()

	var buf bytes.Buffer
	if err := rep.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// Dashboards are built on these names: they are a contract.
	for _, want := range []string{`"status"`, `"live"`, `"requests_in_flight":3`, `"timestamp"`} {
		if !strings.Contains(out, want) {
			t.Errorf("JSON is missing %q:\n%s", want, out)
		}
	}
}

func TestRatesAreDerivedBetweenSnapshots(t *testing.T) {
	prev := metrics.Snapshot{RequestsTotal: 100}
	cur := metrics.Snapshot{RequestsTotal: 160}
	r := NewRates(&prev, &cur, 2e9) // 2 seconds
	if r == nil {
		t.Fatal("no rates computed")
	}
	if r.Requests != 30 {
		t.Errorf("req/s = %v, want 30", r.Requests)
	}
}

// The socket is the only way a second process can see the live
// numbers, so the round trip is worth a test of its own.
func TestServerHandsTheReportToAClient(t *testing.T) {
	sock := socketPath(t)

	srv, err := Serve(sock, func() Report {
		snap := metrics.Snapshot{RequestsTotal: 5, RequestsInFlight: 1}
		rep := Report{
			Version: "test",
			Service: Service{Active: true, PID: 4242, UptimeSeconds: 7},
			Model:   ModelState{Hosts: 2},
			Live:    &snap,
		}
		rep.Add("nginx", StatusOK, "running")
		rep.Finish()
		return rep
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	rep, err := Fetch(sock)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Service.PID != 4242 {
		t.Errorf("pid = %d, want 4242", rep.Service.PID)
	}
	if rep.Model.Hosts != 2 {
		t.Errorf("hosts = %d, want 2", rep.Model.Hosts)
	}
	if rep.Live == nil || rep.Live.RequestsTotal != 5 {
		t.Errorf("live counters did not cross the socket: %+v", rep.Live)
	}
	if rep.ExitCode() != ExitOK {
		t.Errorf("exit code = %d, want 0", rep.ExitCode())
	}
}

func TestServerRemovesItsSocketOnClose(t *testing.T) {
	sock := socketPath(t)
	srv, err := Serve(sock, func() Report { return Report{} })
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := net.DialTimeout("unix", sock, dialTimeout); err == nil {
		t.Error("the socket still answers after Close")
	}
}

// A daemon that is not running must be reported as such, not
// reconstructed from disk.
func TestStatusOfAMissingDaemonIsCritical(t *testing.T) {
	var buf bytes.Buffer
	code := Run("test", socketPath(t), filepath.Join(t.TempDir(), "absent.yaml"), false, 0, &buf)
	if code != ExitCritical {
		t.Errorf("exit code = %d, want %d", code, ExitCritical)
	}
	out := buf.String()
	if !strings.Contains(out, "not running") {
		t.Errorf("output = %q, want it to say the service is not running", out)
	}
	if !strings.Contains(out, "not installed") {
		t.Errorf("output = %q, want it to distinguish a missing installation", out)
	}
}

// socketPath returns a path short enough for the sockaddr_un limit
// (104-108 bytes), which a deep temporary directory would exceed.
//
// Windows has AF_UNIX but Go cannot dial a socket file created under a
// temporary directory there, nor unlink it afterwards. limen is a
// Linux service: rather than pretend otherwise, the socket tests are
// skipped on a Windows development machine and run in CI.
func socketPath(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("AF_UNIX round trips are not testable on Windows")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "s")
}
