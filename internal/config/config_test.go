package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// write drops a config file in a temporary directory and returns its
// path.
func write(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestEmptyFileYieldsDefaults(t *testing.T) {
	cfg, err := Load(write(t, ""))
	if err != nil {
		t.Fatalf("an empty config must load: %v", err)
	}
	def := Default()
	if cfg.Panel.Listen != def.Panel.Listen {
		t.Errorf("panel.listen = %q, want the default %q", cfg.Panel.Listen, def.Panel.Listen)
	}
	if cfg.Nginx.WorkerConnections != def.Nginx.WorkerConnections {
		t.Errorf("nginx.worker_connections = %d, want %d",
			cfg.Nginx.WorkerConnections, def.Nginx.WorkerConnections)
	}
}

func TestSparseFileKeepsUntouchedDefaults(t *testing.T) {
	cfg, err := Load(write(t, "log:\n  level: \"debug\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("log.level = %q, want debug", cfg.Log.Level)
	}
	if cfg.ACME.Directory != LetsEncryptDirectory {
		t.Errorf("acme.directory = %q, want the default", cfg.ACME.Directory)
	}
}

// The panel is the control plane of the machine and is published by
// the nginx it manages. A bind that the network can reach defeats the
// TLS, the access lists and the rate limits applied in front, so it
// must be refused outright rather than warned about.
func TestPanelRefusesToBindBeyondLoopback(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:9187", "192.168.1.10:9187", "[::]:9187"} {
		_, err := Load(write(t, "panel:\n  listen: \""+listen+"\"\n"))
		if err == nil {
			t.Fatalf("panel.listen %q was accepted, it must be refused", listen)
		}
		if !strings.Contains(err.Error(), "loopback") {
			t.Errorf("panel.listen %q: error %q does not explain the loopback rule", listen, err)
		}
	}
}

func TestPanelAcceptsLoopbackAndUnixSocket(t *testing.T) {
	cases := []struct {
		listen  string
		network string
	}{
		{"127.0.0.1:9187", "tcp"},
		{"[::1]:9187", "tcp"},
		{"127.0.0.2:8080", "tcp"},
		{"/run/limen/panel.sock", "unix"},
	}
	for _, c := range cases {
		cfg, err := Load(write(t, "panel:\n  listen: \""+c.listen+"\"\n"))
		if err != nil {
			t.Fatalf("panel.listen %q must be accepted: %v", c.listen, err)
		}
		if got := cfg.Panel.Network(); got != c.network {
			t.Errorf("panel.listen %q: network = %q, want %q", c.listen, got, c.network)
		}
	}
}

func TestNginxConfFileMustLiveInsideConfDir(t *testing.T) {
	_, err := Load(write(t, "nginx:\n  conf_dir: \"/etc/nginx\"\n  conf_file: \"/etc/other/nginx.conf\"\n"))
	if err == nil {
		t.Fatal("a conf_file outside conf_dir was accepted")
	}
	if !strings.Contains(err.Error(), "conf_dir") {
		t.Errorf("error %q does not name the offending field", err)
	}
}

func TestQuestionableValuesWarnButLoad(t *testing.T) {
	cfg, err := Load(write(t, "panel:\n  trusted_proxies: [\"127.0.0.1/32\", \"not-an-ip\"]\n"))
	if err != nil {
		t.Fatalf("an invalid list entry must not be fatal: %v", err)
	}
	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "not-an-ip") {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings = %v, want one naming the skipped entry", cfg.Warnings)
	}
}

func TestDurationsAcceptHumanValues(t *testing.T) {
	cfg, err := Load(write(t, "panel:\n  session_ttl: \"90m\"\nacme:\n  check_every: \"6h\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Panel.SessionTTL.Std(); got != 90*time.Minute {
		t.Errorf("session_ttl = %s, want 90m", got)
	}
	if got := cfg.ACME.CheckEvery.Std(); got != 6*time.Hour {
		t.Errorf("check_every = %s, want 6h", got)
	}
}

func TestInvalidKeyTypeIsFatal(t *testing.T) {
	if _, err := Load(write(t, "acme:\n  key_type: \"ed25519\"\n")); err == nil {
		t.Fatal("an unsupported ACME key type was accepted")
	}
}

func TestMissingFileIsReported(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err == nil {
		t.Fatal("a missing config file must be an error")
	}
	if !os.IsNotExist(err) && !strings.Contains(err.Error(), "read config") {
		t.Errorf("error %q does not say the file could not be read", err)
	}
}

// A configuration that no longer validates must leave the previous one
// in force: the daemon keeps serving what it already has.
func TestReloadRejectsBadConfigAndKeepsTheOldOne(t *testing.T) {
	path := write(t, "log:\n  level: \"warn\"\n")
	m, err := NewManager(path)
	if err != nil {
		t.Fatal(err)
	}
	if m.Get().Log.Level != "warn" {
		t.Fatalf("level = %q, want warn", m.Get().Log.Level)
	}

	if err := os.WriteFile(path, []byte("panel:\n  listen: \"0.0.0.0:80\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Reload(); err == nil {
		t.Fatal("reload accepted a config that does not validate")
	}
	if m.Get().Log.Level != "warn" {
		t.Errorf("the rejected config was swapped in: level = %q", m.Get().Log.Level)
	}

	if err := os.WriteFile(path, []byte("log:\n  level: \"error\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Reload(); err != nil {
		t.Fatalf("reload of a valid config failed: %v", err)
	}
	if m.Get().Log.Level != "error" {
		t.Errorf("level = %q, want error after reload", m.Get().Log.Level)
	}
}

// The metrics name every host and its traffic: the panel's rule.
func TestMetricsListenOnlyLocally(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:9188", "10.0.0.1:9188", "[::]:9188", "127.0.0.1:9187"} {
		if _, err := Load(write(t, "metrics:\n  listen: \""+listen+"\"\n")); err == nil {
			t.Errorf("metrics.listen %q accepted", listen)
		}
	}
	for _, listen := range []string{"", "127.0.0.1:9188", "[::1]:9188", "/run/limen/metrics.sock"} {
		if _, err := Load(write(t, "metrics:\n  listen: \""+listen+"\"\n")); err != nil {
			t.Errorf("metrics.listen %q refused: %v", listen, err)
		}
	}
	if _, err := Load(write(t, "nginx:\n  host_logs: \"relative/dir\"\n")); err == nil {
		t.Error("a relative nginx.host_logs accepted")
	}
}
