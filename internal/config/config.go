// Package config loads and validates the limen configuration
// (/etc/limen/config.yaml) and provides hot-reload via fsnotify.
//
// This file describes the daemon itself: where the panel listens, how
// to drive nginx, how to talk to the ACME directory. The managed
// objects (proxy hosts, redirects, streams, access lists, users) are
// NOT here: they live one YAML document per file under /etc/limen, so
// that they stay editable by hand when the panel is down.
//
// Every field has a production default (see Default), so the
// operator's config.yaml may be sparse or even empty.
package config

import (
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"

	"github.com/ostap-mykhaylyak/limen/internal/paths"
)

// Duration wraps time.Duration to accept human-friendly YAML values
// such as "30m", "24h", "5s".
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler via time.ParseDuration.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML renders the duration back in its string form.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// Std returns the value as a standard time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// Config is the whole configuration document.
type Config struct {
	Panel   Panel   `yaml:"panel"`
	Nginx   Nginx   `yaml:"nginx"`
	ACME    ACME    `yaml:"acme"`
	Metrics Metrics `yaml:"metrics"`
	Log     Log     `yaml:"log"`

	// Warnings collects non-fatal issues found by validate()
	// (e.g. a missing ACME contact). Never fatal: a questionable
	// value must not keep the daemon from starting.
	Warnings []string `yaml:"-"`
}

// Panel is the web interface and its REST API.
//
// limen never faces the internet itself: it is published by a virtual
// host that limen generates for nginx, exactly like any other backend
// it proxies. Listen is therefore restricted to loopback addresses or
// to a unix socket; validate() refuses anything else.
type Panel struct {
	Listen            string   `yaml:"listen"`
	Hostname          string   `yaml:"hostname"`
	Certificate       string   `yaml:"certificate"`
	TrustedProxies    []string `yaml:"trusted_proxies"`
	SessionTTL        Duration `yaml:"session_ttl"`
	SecureCookies     bool     `yaml:"secure_cookies"`
	ReadHeaderTimeout Duration `yaml:"read_header_timeout"`
	IdleTimeout       Duration `yaml:"idle_timeout"`
}

// Nginx describes the nginx installation limen owns and drives.
type Nginx struct {
	Bin      string `yaml:"bin"`
	ConfDir  string `yaml:"conf_dir"`
	ConfFile string `yaml:"conf_file"`
	PIDFile  string `yaml:"pid_file"`

	// User is the unprivileged account of the workers. Empty means
	// detect it: www-data on Debian and Ubuntu, nginx on the official
	// packages and images.
	User string `yaml:"user"`

	ErrorLog  string `yaml:"error_log"`
	AccessLog string `yaml:"access_log"`

	// HostLogs is the directory of the per-host logs: one access log
	// (JSON, one request per line) and one error log per proxy host,
	// named after it. limen reads them for the log viewer and derives
	// its traffic metrics from them.
	HostLogs string `yaml:"host_logs"`

	// Modules is included at the top of nginx.conf so that the modules
	// the distribution loads dynamically (stream on Debian) keep being
	// loaded now that limen writes nginx.conf. A pattern that matches
	// nothing is harmless.
	Modules string `yaml:"modules"`

	// IPv6 is "auto" (listen on [::] when the machine has IPv6), "on"
	// or "off".
	IPv6 string `yaml:"ipv6"`

	// TrustedCA verifies https backends that ask for verify_tls.
	TrustedCA string `yaml:"trusted_ca"`

	// KeepGenerations is how many rendered trees are kept to roll back
	// to.
	KeepGenerations int `yaml:"keep_generations"`

	WorkerProcesses   string `yaml:"worker_processes"`
	WorkerConnections int    `yaml:"worker_connections"`
	ClientMaxBodySize string `yaml:"client_max_body_size"`
	ServerNamesHash   int    `yaml:"server_names_hash_bucket_size"`

	// TestCommand and ReloadCommand override how limen validates and
	// applies a rendered tree. Empty means the built-in defaults
	// (nginx -t -c <candidate>, then nginx -s reload).
	TestCommand   []string `yaml:"test_command"`
	ReloadCommand []string `yaml:"reload_command"`
}

// ACME is the Let's Encrypt (or compatible) certificate authority.
type ACME struct {
	Enabled      bool     `yaml:"enabled"`
	Directory    string   `yaml:"directory"`
	ContactEmail string   `yaml:"contact_email"`
	RenewBefore  Duration `yaml:"renew_before"`
	KeyType      string   `yaml:"key_type"`
	CheckEvery   Duration `yaml:"check_every"`

	// DirectoryCA is an extra CA bundle to trust when talking to the
	// directory: a private ACME server, or Pebble in a test.
	DirectoryCA string `yaml:"directory_ca"`

	// DNSHook proves DNS-01 challenges, the only way to a wildcard. It
	// is run as `hook present <record> <value>` and `hook cleanup
	// <record> <value>`, with the record a fully qualified name.
	DNSHook string `yaml:"dns_hook"`

	// DNSWait is how long limen waits for the record to be visible
	// before asking the CA to look.
	DNSWait Duration `yaml:"dns_wait"`
}

// Metrics is what limen publishes about the traffic it sees.
type Metrics struct {
	// Listen serves the metrics in the Prometheus text format, on a
	// loopback address or a unix socket like the panel; empty serves
	// them nowhere. They stay in the panel and in `limen status`.
	Listen string `yaml:"listen"`
}

// PanelCertificateACME is the value of panel.certificate that asks
// limen to issue the panel's certificate itself.
const PanelCertificateACME = "acme"

// Log configures the JSON log streams.
type Log struct {
	Level string `yaml:"level"`
}

// LetsEncryptDirectory is the production ACME endpoint.
const LetsEncryptDirectory = "https://acme-v02.api.letsencrypt.org/directory"

// Default returns the configuration limen runs with when config.yaml
// says nothing.
func Default() *Config {
	return &Config{
		Panel: Panel{
			Listen:            "127.0.0.1:9187",
			Hostname:          "",
			TrustedProxies:    []string{"127.0.0.1/32", "::1/128"},
			SessionTTL:        Duration(12 * time.Hour),
			SecureCookies:     true,
			ReadHeaderTimeout: Duration(10 * time.Second),
			IdleTimeout:       Duration(120 * time.Second),
		},
		Nginx: Nginx{
			Bin:               paths.NginxBin,
			ConfDir:           paths.NginxConfDir,
			ConfFile:          paths.NginxConfFile,
			PIDFile:           "/run/nginx.pid",
			User:              "",
			ErrorLog:          "/var/log/nginx/error.log",
			AccessLog:         "/var/log/nginx/access.log",
			HostLogs:          "/var/log/nginx/limen",
			Modules:           "/etc/nginx/modules-enabled/*.conf",
			IPv6:              "auto",
			TrustedCA:         "/etc/ssl/certs/ca-certificates.crt",
			KeepGenerations:   5,
			WorkerProcesses:   "auto",
			WorkerConnections: 1024,
			ClientMaxBodySize: "1024m",
			ServerNamesHash:   128,
		},
		ACME: ACME{
			Enabled:     true,
			Directory:   LetsEncryptDirectory,
			RenewBefore: Duration(30 * 24 * time.Hour),
			KeyType:     "ec256",
			CheckEvery:  Duration(12 * time.Hour),
			DNSWait:     Duration(2 * time.Minute),
		},
		Log: Log{Level: "info"},
	}
}

// Load reads file on top of Default() and validates the result.
func Load(file string) (*Config, error) {
	cfg := Default()
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// localOnly accepts a unix socket path or a loopback host:port.
func localOnly(field, addr, why string) error {
	if strings.HasPrefix(addr, "/") {
		return nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s %q: not a host:port address", field, addr)
	}
	if port == "" {
		return fmt.Errorf("%s %q: missing port", field, addr)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%s %q: %s", field, addr, why)
	}
	return nil
}

// IsUnixSocket reports whether the panel listens on a unix socket
// rather than on a TCP address.
func (p Panel) IsUnixSocket() bool { return strings.HasPrefix(p.Listen, "/") }

// Network returns the net.Listen network for the panel listener.
func (p Panel) Network() string {
	if p.IsUnixSocket() {
		return "unix"
	}
	return "tcp"
}

// validate checks the invariants that must hold for limen to run at
// all. Anything merely questionable becomes a warning instead.
func (c *Config) validate() error {
	c.Warnings = nil

	if c.Panel.Listen == "" {
		return fmt.Errorf("panel.listen is required")
	}
	// The panel is published by the nginx it manages; binding it
	// anywhere reachable would put the control plane of the whole
	// machine on the network, bypassing the TLS, access lists and rate
	// limits that nginx applies in front of it.
	if err := localOnly("panel.listen", c.Panel.Listen, "the panel must stay on a loopback address "+
		"or a unix socket, it is published through nginx"); err != nil {
		return err
	}
	// The metrics name every host and its traffic: the same rule.
	if c.Metrics.Listen != "" {
		if err := localOnly("metrics.listen", c.Metrics.Listen, "metrics are served on a loopback address "+
			"or a unix socket only; a scraper elsewhere goes through an SSH tunnel or a proxy of its own"); err != nil {
			return err
		}
		if c.Metrics.Listen == c.Panel.Listen {
			return fmt.Errorf("metrics.listen %q is panel.listen", c.Metrics.Listen)
		}
	}
	if c.Panel.SessionTTL <= 0 {
		return fmt.Errorf("panel.session_ttl must be positive")
	}
	if c.Panel.Hostname == "" {
		c.Warnings = append(c.Warnings, "panel.hostname is empty: no virtual host is generated "+
			"for the panel itself, reach it over an SSH tunnel to panel.listen")
	}
	for _, p := range c.Panel.TrustedProxies {
		if _, _, err := net.ParseCIDR(p); err != nil && net.ParseIP(p) == nil {
			c.Warnings = append(c.Warnings,
				fmt.Sprintf("panel.trusted_proxies: skipping invalid entry %q", p))
		}
	}

	if c.Nginx.Bin == "" {
		return fmt.Errorf("nginx.bin is required")
	}
	// The paths are always POSIX ones, whatever the machine the
	// configuration is being checked on: limen runs on Linux.
	if !path.IsAbs(filepath.ToSlash(c.Nginx.ConfDir)) {
		return fmt.Errorf("nginx.conf_dir %q must be an absolute path", c.Nginx.ConfDir)
	}
	if !path.IsAbs(filepath.ToSlash(c.Nginx.ConfFile)) {
		return fmt.Errorf("nginx.conf_file %q must be an absolute path", c.Nginx.ConfFile)
	}
	if !strings.HasPrefix(filepath.ToSlash(c.Nginx.ConfFile), strings.TrimSuffix(filepath.ToSlash(c.Nginx.ConfDir), "/")+"/") {
		return fmt.Errorf("nginx.conf_file %q must live inside nginx.conf_dir %q",
			c.Nginx.ConfFile, c.Nginx.ConfDir)
	}
	if c.Nginx.WorkerConnections <= 0 {
		return fmt.Errorf("nginx.worker_connections must be positive")
	}
	switch c.Nginx.IPv6 {
	case "auto", "on", "off":
	default:
		return fmt.Errorf("nginx.ipv6 %q: want auto, on or off", c.Nginx.IPv6)
	}
	if c.Nginx.KeepGenerations < 2 {
		// One to serve and one to roll back to, at least.
		return fmt.Errorf("nginx.keep_generations must be at least 2")
	}
	for field, v := range map[string]string{
		"nginx.error_log": c.Nginx.ErrorLog, "nginx.access_log": c.Nginx.AccessLog,
		"nginx.pid_file": c.Nginx.PIDFile, "nginx.trusted_ca": c.Nginx.TrustedCA,
		"nginx.host_logs": c.Nginx.HostLogs,
	} {
		if !path.IsAbs(filepath.ToSlash(v)) {
			return fmt.Errorf("%s %q must be an absolute path", field, v)
		}
	}
	for field, v := range map[string]string{
		"nginx.user": c.Nginx.User, "nginx.worker_processes": c.Nginx.WorkerProcesses,
		"nginx.client_max_body_size": c.Nginx.ClientMaxBodySize, "nginx.modules": c.Nginx.Modules,
		"nginx.error_log": c.Nginx.ErrorLog, "nginx.access_log": c.Nginx.AccessLog,
		"nginx.pid_file": c.Nginx.PIDFile, "nginx.trusted_ca": c.Nginx.TrustedCA,
		"nginx.host_logs": c.Nginx.HostLogs,
	} {
		// These end up in nginx.conf as they are: nothing that could
		// end a directive or open a block.
		if strings.ContainsAny(v, " \t\r\n;{}\"'#$\\") {
			return fmt.Errorf("%s %q: spaces, quotes, ; { } # $ are not allowed", field, v)
		}
	}
	if c.Panel.Certificate != "" && c.Panel.Hostname == "" {
		return fmt.Errorf("panel.certificate needs panel.hostname")
	}
	if c.Panel.Hostname != "" && c.Panel.Certificate == "" {
		c.Warnings = append(c.Warnings, "panel.hostname is published over plain HTTP: "+
			"set panel.certificate, the login travels in clear otherwise")
	}

	if c.ACME.Enabled {
		if c.ACME.Directory == "" {
			return fmt.Errorf("acme.directory is required when acme.enabled is true")
		}
		if c.ACME.RenewBefore <= 0 {
			return fmt.Errorf("acme.renew_before must be positive")
		}
		if c.ACME.CheckEvery <= 0 {
			return fmt.Errorf("acme.check_every must be positive")
		}
		switch c.ACME.KeyType {
		case "ec256", "ec384", "rsa2048", "rsa4096":
		default:
			return fmt.Errorf("acme.key_type %q: want ec256, ec384, rsa2048 or rsa4096", c.ACME.KeyType)
		}
		if c.ACME.ContactEmail == "" {
			c.Warnings = append(c.Warnings, "acme.contact_email is empty: "+
				"the CA cannot warn you about expiring certificates")
		}
		for field, v := range map[string]string{"acme.directory_ca": c.ACME.DirectoryCA, "acme.dns_hook": c.ACME.DNSHook} {
			if v != "" && !path.IsAbs(filepath.ToSlash(v)) {
				return fmt.Errorf("%s %q must be an absolute path", field, v)
			}
		}
		if c.ACME.DNSWait < 0 {
			return fmt.Errorf("acme.dns_wait must not be negative")
		}
	}
	if c.Panel.Certificate == PanelCertificateACME && !c.ACME.Enabled {
		return fmt.Errorf("panel.certificate is acme, but acme.enabled is false")
	}

	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log.level %q: want debug, info, warn or error", c.Log.Level)
	}

	return nil
}

// Manager holds the current configuration and swaps it atomically when
// the file changes.
type Manager struct {
	path    string
	current atomic.Pointer[Config]

	mu       sync.Mutex
	watching bool
}

// NewManager loads path once and returns a manager holding it.
func NewManager(path string) (*Manager, error) {
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}
	m := &Manager{path: path}
	m.current.Store(cfg)
	return m, nil
}

// Get returns the configuration in force. It is cheap enough to call
// per request.
func (m *Manager) Get() *Config { return m.current.Load() }

// Path returns the file the manager watches.
func (m *Manager) Path() string { return m.path }

// Reload re-reads the file and swaps it in. A configuration that does
// not parse or does not validate is rejected and the previous one
// stays in force.
func (m *Manager) Reload() (*Config, error) {
	cfg, err := Load(m.path)
	if err != nil {
		return nil, err
	}
	m.current.Store(cfg)
	return cfg, nil
}

// Watch reloads the configuration whenever the file changes, until
// stop is closed. onErr and onReload run synchronously in the watch
// goroutine, so they must be quick.
//
// The file is watched through its directory: editors and atomic
// rewrites replace the inode, which a watch on the file itself would
// stop following.
func (m *Manager) Watch(stop <-chan struct{}, onErr func(error), onReload func(*Config)) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	if err := w.Add(filepath.Dir(m.path)); err != nil {
		w.Close()
		return err
	}

	m.mu.Lock()
	m.watching = true
	m.mu.Unlock()

	go func() {
		defer w.Close()
		defer func() {
			m.mu.Lock()
			m.watching = false
			m.mu.Unlock()
		}()

		// Coalesce the burst of events a single save produces.
		var timer *time.Timer
		var timerC <-chan time.Time
		for {
			select {
			case <-stop:
				return
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				if filepath.Clean(ev.Name) != filepath.Clean(m.path) {
					continue
				}
				if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
					continue
				}
				if timer == nil {
					timer = time.NewTimer(200 * time.Millisecond)
				} else {
					timer.Reset(200 * time.Millisecond)
				}
				timerC = timer.C
			case <-timerC:
				timerC = nil
				cfg, err := m.Reload()
				if err != nil {
					if onErr != nil {
						onErr(err)
					}
					continue
				}
				if onReload != nil {
					onReload(cfg)
				}
			case err, ok := <-w.Errors:
				if !ok {
					return
				}
				if onErr != nil {
					onErr(err)
				}
			}
		}
	}()
	return nil
}

// Watching reports whether a Watch goroutine is running.
func (m *Manager) Watching() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.watching
}
