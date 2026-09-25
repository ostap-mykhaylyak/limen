// limen - an nginx manager with a web panel and a command line.
//
// limen owns the nginx configuration of the machine: it renders the
// whole tree from its own model, validates every candidate with
// `nginx -t` before letting it through, and reloads nginx only once
// the candidate has passed. The panel that drives all this is itself
// published by that nginx, on loopback, never directly.
//
// Command convention: the service verbs (start, stop, reload, restart,
// status) and the object commands (host, redirect, stream, access,
// user, history, rollback) are bare words; the one-shot operations on
// the machine or the binary take a leading double dash (--init,
// --purge, --check-config, --version).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/acme"
	"github.com/ostap-mykhaylyak/limen/internal/api"
	"github.com/ostap-mykhaylyak/limen/internal/auth"
	"github.com/ostap-mykhaylyak/limen/internal/bootstrap"
	"github.com/ostap-mykhaylyak/limen/internal/config"
	"github.com/ostap-mykhaylyak/limen/internal/logging"
	"github.com/ostap-mykhaylyak/limen/internal/metrics"
	"github.com/ostap-mykhaylyak/limen/internal/model"
	"github.com/ostap-mykhaylyak/limen/internal/nginx"
	"github.com/ostap-mykhaylyak/limen/internal/panel"
	"github.com/ostap-mykhaylyak/limen/internal/paths"
	"github.com/ostap-mykhaylyak/limen/internal/proc"
	"github.com/ostap-mykhaylyak/limen/internal/status"
	"github.com/ostap-mykhaylyak/limen/internal/store"
	"github.com/ostap-mykhaylyak/limen/internal/traffic"
	ui "github.com/ostap-mykhaylyak/limen/internal/web"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

// serviceVerbs act on a daemon: bare words, like nginx or systemctl.
var serviceVerbs = map[string]bool{
	"start":   true,
	"stop":    true,
	"reload":  true,
	"restart": true,
	"status":  true,
}

// flagCommands act on the machine or on the binary itself, and are
// spelled with the dashes so that they cannot be confused with the
// verbs above.
var flagCommands = map[string]bool{
	"init":         true,
	"purge":        true,
	"check-config": true,
	"import":       true,
	"version":      true,
	"help":         true,
}

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}

	args := os.Args[2:]
	cmd, err := normalizeCommand(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "limen:", err)
		fmt.Fprintln(os.Stderr)
		usage(os.Stderr)
		os.Exit(2)
	}

	switch cmd {
	case "start":
		fs := flag.NewFlagSet("start", flag.ExitOnError)
		cfgPath := fs.String("config", paths.ConfigFile, "config file")
		pidfile := fs.String("pidfile", paths.Pidfile, "pidfile path")
		sock := fs.String("socket", paths.Socket, "status socket path")
		fs.Parse(args)
		fatalIf(runDaemon(*cfgPath, *pidfile, *sock))

	case "stop":
		fs := flag.NewFlagSet("stop", flag.ExitOnError)
		pidfile := fs.String("pidfile", paths.Pidfile, "pidfile path")
		fs.Parse(args)
		fatalIf(proc.Stop(*pidfile))

	case "reload":
		// SIGHUP: re-read the configuration and reopen the log files.
		// It does not reload nginx; that is `limen apply`, and it
		// happens on its own whenever the model changes.
		fs := flag.NewFlagSet("reload", flag.ExitOnError)
		pidfile := fs.String("pidfile", paths.Pidfile, "pidfile path")
		fs.Parse(args)
		fatalIf(proc.Reload(*pidfile))

	case "restart":
		// Stop the running daemon, wait for it to release the socket,
		// then become the new foreground daemon. Under systemd use
		// `systemctl restart limen`; this is for running it by hand.
		fs := flag.NewFlagSet("restart", flag.ExitOnError)
		cfgPath := fs.String("config", paths.ConfigFile, "config file")
		pidfile := fs.String("pidfile", paths.Pidfile, "pidfile path")
		sock := fs.String("socket", paths.Socket, "status socket path")
		fs.Parse(args)
		fatalIf(proc.StopAndWait(*pidfile, 30*time.Second))
		fatalIf(runDaemon(*cfgPath, *pidfile, *sock))

	case "status":
		fs := flag.NewFlagSet("status", flag.ExitOnError)
		cfgPath := fs.String("config", paths.ConfigFile, "config file")
		sock := fs.String("socket", paths.Socket, "status socket path")
		jsonOut := fs.Bool("json", false, "machine-readable output")
		watch := fs.Duration("watch", 0, "refresh every interval (e.g. 2s), like top")
		fs.Parse(args)
		os.Exit(status.Run(version, *sock, *cfgPath, *jsonOut, *watch, os.Stdout))

	case "init":
		fatalIf(bootstrap.Init(version, os.Stdout))

	case "purge":
		fs := flag.NewFlagSet("purge", flag.ExitOnError)
		assumeYes := fs.Bool("yes", false, "skip the confirmation prompt")
		fs.Parse(args)
		fatalIf(bootstrap.Purge(*assumeYes, os.Stdin, os.Stdout))

	case "check-config":
		fs := flag.NewFlagSet("check-config", flag.ExitOnError)
		cfgPath := fs.String("config", paths.ConfigFile, "config file")
		fs.Parse(args)
		fatalIf(checkConfig(*cfgPath, os.Stdout))

	case "import":
		fatalIf(runImport(args, os.Stdout))

	case "version":
		fmt.Println("limen", version)

	case "help":
		usage(os.Stdout)

	case "host", "redirect", "stream", "access", "user", "cert", "history", "rollback", "apply":
		switch err := runObject(cmd, args); {
		case err == nil, errors.Is(err, errHelpShown):
		case errors.Is(err, errUsage):
			os.Exit(2)
		default:
			fatalIf(err)
		}

	default:
		// Unreachable: normalizeCommand rejects anything not handled
		// above. Kept as a guard against a command being added to one
		// table but not to this switch.
		fmt.Fprintf(os.Stderr, "limen: unhandled command %q\n", cmd)
		os.Exit(2)
	}
}

func normalizeCommand(cmd string) (string, error) {
	if bare, ok := strings.CutPrefix(cmd, "--"); ok {
		switch {
		case flagCommands[bare]:
			return bare, nil
		case serviceVerbs[bare]:
			return "", fmt.Errorf("service commands take no leading --: use %q, not %q", bare, cmd)
		case objectCommands[bare]:
			return "", fmt.Errorf("object commands take no leading --: use %q, not %q", bare, cmd)
		default:
			return "", fmt.Errorf("unknown command %q", cmd)
		}
	}
	switch {
	case serviceVerbs[cmd], objectCommands[cmd]:
		return cmd, nil
	case flagCommands[cmd]:
		return "", fmt.Errorf("this command takes a leading --: use %q, not %q", "--"+cmd, cmd)
	default:
		return "", fmt.Errorf("unknown command %q", cmd)
	}
}

// runDaemon is the foreground service: what systemd starts.
func runDaemon(cfgPath, pidfile, sockPath string) error {
	// First run: provision the layout from the embedded skeleton, but
	// only for the real installation. A -config pointing somewhere
	// else is a test or a hand-run instance and must not create
	// anything under /etc.
	if cfgPath == paths.ConfigFile {
		if created, err := bootstrap.DefaultLayout().Ensure(); err != nil {
			return err
		} else if created {
			fmt.Fprintf(os.Stderr, "limen: provisioned the default layout, review %s\n", cfgPath)
		}
	}

	cfgs, err := config.NewManager(cfgPath)
	if err != nil {
		return err
	}
	cfg := cfgs.Get()

	logs, err := logging.Open(paths.LogDir, logging.Level(cfg.Log.Level))
	if err != nil {
		// Losing the log files is not a reason to refuse to serve:
		// fall back to stderr, which systemd captures anyway.
		fmt.Fprintf(os.Stderr, "limen: %v (logging to stderr)\n", err)
		logs = logging.Stderr(logging.Level(cfg.Log.Level))
	}
	defer logs.Close()

	model, err := store.Open(store.DefaultDirs())
	if err != nil {
		return err
	}

	reg := metrics.New()
	challenges := acme.NewChallenges()
	// The traffic is counted from the per-host access logs nginx
	// writes; nginx's connections come from its stub_status.
	hostTraffic := traffic.NewCollector(func(host string) string {
		access, _ := nginx.HostLogPaths(cfgs.Get().Nginx.HostLogs, host)
		return access
	}, logs.Service)
	defer hostTraffic.Close()
	nginxProbe := &traffic.NginxProbe{URL: "http://127.0.0.1" + nginx.StatusPath}
	var certs *acme.Manager
	engine := &nginx.Engine{
		Store:    model,
		Config:   cfgs.Get,
		CertsDir: paths.CertsDir,
		LockPath: paths.ApplyLock,
		Log:      logs.Apply,
	}
	// applyModel brings nginx in line with the model and the
	// configuration. Every path that can change either ends here:
	// startup, SIGHUP (the command line sends it after a write), an edit
	// of config.yaml. An apply with nothing to do leaves nginx alone, so
	// the daily SIGHUP of logrotate costs one rendering and nothing more.
	applyModel := func(reason string) (nginx.Result, error) {
		if changed, err := nginx.EnsurePanelHost(model, cfgs.Get()); err != nil {
			logs.Service.Error("panel host", "error", err.Error())
		} else if changed {
			logs.Service.Info("panel host updated from config.yaml", "hostname", cfgs.Get().Panel.Hostname)
		}
		res, err := engine.Apply(context.Background(), false)
		if res.Changed || err != nil {
			reg.Apply(err == nil, res.Reloaded)
		}
		// A change of the model may bring a new certificate, or new names
		// on an old one: let the manager look.
		if certs != nil && reason != "certificates" {
			certs.Poke()
		}
		for i := 0; i < res.RolledBack; i++ {
			reg.Rollback()
		}
		hostTraffic.Watch(loggedHosts(model))
		switch {
		case err != nil:
			logs.Service.Error("apply failed, nginx keeps its previous configuration", "reason", reason, "error", err.Error())
		case res.Changed:
			logs.Service.Info("applied", "reason", reason, "generation", res.Generation,
				"reloaded", res.Reloaded, "nginx_running", res.NginxRunning, "left_out", len(res.Skipped))
		}
		return res, err
	}
	certs = &acme.Manager{
		Store:      model,
		Config:     cfgs.Get,
		CertsDir:   paths.CertsDir,
		AccountDir: paths.AcmeDir,
		Challenges: challenges,
		Apply:      func(reason string) { applyModel("certificates") },
		Log:        logs.Service,
		Metrics:    reg,
	}
	report := func() status.Report {
		rep := buildReport(version, cfgs, model, engine, certs, reg)
		addTraffic(&rep, hostTraffic, nginxProbe)
		return rep
	}

	sock, err := status.Serve(sockPath, report)
	if err != nil {
		return err
	}
	defer sock.Close()

	sessions, err := auth.OpenSessions(paths.SessionsFile, func() time.Duration {
		return cfgs.Get().Panel.SessionTTL.Std()
	})
	if err != nil {
		return fmt.Errorf("sessions: %w", err)
	}
	// ClientIP lives on the panel, which knows the trusted proxies; the
	// API is built before the panel, so it goes through this variable.
	var web *panel.Server
	restAPI := api.New(api.Deps{
		Store:    model,
		Sessions: sessions,
		Limiter:  auth.NewLimiter(),
		Config:   cfgs.Get,
		Apply: func(dryRun bool) (nginx.Result, error) {
			if dryRun {
				return engine.Apply(context.Background(), true)
			}
			return applyModel("panel")
		},
		LastApply: engine.Last,
		Report:    report,
		ClientIP:  func(r *http.Request) string { return web.ClientIP(r) },
		Metrics:   reg,
		Log:       logs.Service,

		Certificates: certs,
		Traffic:      hostTraffic,
		Nginx:        nginxProbe,
		Logs:         logFiles(cfgs),
	})
	web = panel.New(cfgs, logs, reg, report, restAPI, ui.Handler())
	web.Handle("GET "+acme.ChallengePrefix, challenges)
	if err := web.Listen(); err != nil {
		return err
	}

	if err := proc.WritePidfile(pidfile); err != nil {
		return err
	}
	defer os.Remove(pidfile)

	stop := make(chan struct{})
	if err := cfgs.Watch(stop,
		func(err error) {
			logs.Service.Error("config reload failed", "error", err.Error())
		},
		func(c *config.Config) {
			reg.ConfigReload()
			logs.Service.Info("config reloaded", "path", cfgs.Path(), "warnings", len(c.Warnings))
			for _, w := range c.Warnings {
				logs.Service.Warn("config warning", "detail", w)
			}
			applyModel("config.yaml changed")
		}); err != nil {
		logs.Service.Warn("config watch unavailable", "error", err.Error())
	}

	logs.Service.Info("starting",
		"version", version,
		"config", cfgPath,
		"pid", os.Getpid(),
		"panel", web.Addr(),
		"socket", sock.Addr(),
	)
	for _, w := range cfg.Warnings {
		logs.Service.Warn("config warning", "detail", w)
	}
	logModel(logs, model, "model loaded")
	applyModel("startup")
	certCtx, stopCerts := context.WithCancel(context.Background())
	defer stopCerts()
	go certs.Run(certCtx)
	go hostTraffic.Run(stop, 2*time.Second)
	go nginxProbe.Run(stop, 5*time.Second)
	metricsSrv := serveMetrics(cfgs, logs, reg, hostTraffic, nginxProbe, certs, model)
	defer metricsSrv.close()

	serveErr := make(chan error, 1)
	go func() { serveErr <- web.Serve() }()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer signal.Stop(sigs)

	for {
		select {
		case err := <-serveErr:
			close(stop)
			if err != nil {
				return fmt.Errorf("panel: %w", err)
			}
			return nil

		case sig := <-sigs:
			if sig == syscall.SIGHUP {
				// logrotate hook, and a manual way to re-read the
				// configuration without restarting.
				if err := logs.Reopen(); err != nil {
					logs.Service.Error("log reopen failed", "error", err.Error())
				}
				// The per-host logs are nginx's: it reopens them itself,
				// once told. logrotate's hook for them is this reload.
				if err := proc.Reopen(cfgs.Get().Nginx.PIDFile); err != nil && !errors.Is(err, proc.ErrNotRunning) {
					logs.Service.Warn("nginx log reopen", "error", err.Error())
				}
				if _, err := cfgs.Reload(); err != nil {
					logs.Service.Error("config reload failed", "error", err.Error())
				} else {
					reg.ConfigReload()
					logs.Service.Info("reloaded on SIGHUP")
				}
				// The command line edits the model on disk and then
				// signals: this is where its changes come in.
				if err := model.Reload(); err != nil {
					logs.Service.Error("model reload failed, keeping the previous one", "error", err.Error())
				} else {
					logModel(logs, model, "model reloaded")
				}
				applyModel("reload")
				continue
			}

			logs.Service.Info("shutting down", "signal", sig.String())
			close(stop)
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			err := web.Shutdown(ctx)
			cancel()
			if err != nil {
				logs.Service.Error("shutdown", "error", err.Error())
			}
			<-serveErr
			logs.Service.Info("shutdown complete")
			return nil
		}
	}
}

// logModel records the size of the model and every document skipped
// while loading it.
func logModel(logs *logging.Logs, m *store.Store, msg string) {
	c := m.Counts()
	logs.Service.Info(msg,
		"hosts", c.ProxyHosts, "redirects", c.Redirects, "streams", c.Streams,
		"access_lists", c.AccessLists, "users", c.Users, "revision", m.Revision())
	for _, w := range m.Warnings() {
		logs.Service.Warn("model warning", "detail", w)
	}
}

// buildReport is the single source of truth for `limen status`, for
// the status socket and for /healthz.
func buildReport(version string, cfgs *config.Manager, m *store.Store, engine *nginx.Engine, certs *acme.Manager, reg *metrics.Registry) status.Report {
	cfg := cfgs.Get()
	snap := reg.Snapshot()
	counts := m.Counts()

	rep := status.Report{
		Version: version,
		Service: status.Service{
			Active:        true,
			PID:           os.Getpid(),
			UptimeSeconds: snap.UptimeSeconds,
		},
		Config: status.ConfigState{
			Path:     cfgs.Path(),
			Valid:    true,
			Warnings: cfg.Warnings,
		},
		Nginx: status.NginxState{
			ConfDir:     cfg.Nginx.ConfDir,
			LastApplyOK: true,
		},
		Model: status.ModelState{
			Hosts:       counts.ProxyHosts,
			Redirects:   counts.Redirects,
			Streams:     counts.Streams,
			AccessLists: counts.AccessLists,
			Users:       counts.Users,
			Certs:       counts.Certificates,
		},
		Live: &snap,
	}

	// Certificates: expiring, expired or failing is degraded, never an
	// outage of limen itself — nginx keeps serving what it has.
	var troubled []string
	for _, c := range store.All[*model.Certificate](m, model.KindCertificate) {
		sum := certs.Describe(c)
		switch sum.State {
		case acme.StateExpiring:
			rep.Model.CertsExpiry++
			if c.Provider == model.ProviderCustom {
				troubled = append(troubled, c.Name+": "+sum.Detail)
			}
		case acme.StateExpired, acme.StateFailed, acme.StateInvalid:
			troubled = append(troubled, c.Name+": "+sum.Detail)
		}
	}
	switch {
	case len(troubled) > 0:
		detail := troubled[0]
		if len(troubled) > 1 {
			detail += fmt.Sprintf(" (and %d more: limen cert list)", len(troubled)-1)
		}
		rep.Add("certificates", status.StatusWarn, detail)
	case counts.Certificates > 0:
		rep.Add("certificates", status.StatusOK, fmt.Sprintf("%d certificate(s)", counts.Certificates))
	}

	if last, ok := engine.Last(); ok {
		rep.Nginx.LastApplyUnix = last.At.Unix()
		rep.Nginx.LastApplyOK = last.OK()
		rep.Nginx.LastApplyErr = last.Error
		rep.Nginx.Generation = last.Generation
		// The model moved on since the last apply that went through: what
		// nginx serves is behind what the model says.
		rep.Nginx.Pending = !last.OK() || m.Revision() > last.Revision
		switch {
		case !last.OK():
			rep.Add("apply", status.StatusWarn, "the last apply failed, nginx serves the previous configuration: "+last.Error)
		case len(last.Skipped) > 0:
			s := last.Skipped[0]
			detail := fmt.Sprintf("%s %q left out: %s", model.Kind(s.Kind), s.Name, s.Reason)
			if len(last.Skipped) > 1 {
				detail += fmt.Sprintf(" (and %d more: limen apply --dry-run)", len(last.Skipped)-1)
			}
			rep.Add("apply", status.StatusWarn, detail)
		default:
			rep.Add("apply", status.StatusOK, "generation "+last.Generation)
		}
		for _, w := range last.Warnings {
			rep.Config.Warnings = append(rep.Config.Warnings, w)
		}
	}

	if pid, err := proc.ReadPidfile(cfg.Nginx.PIDFile); err == nil && proc.Alive(pid) {
		rep.Nginx.Running = true
		rep.Nginx.PID = pid
		rep.Add("nginx", status.StatusOK, fmt.Sprintf("running, pid %d", pid))
	} else {
		rep.Add("nginx", status.StatusWarn, "nginx is not running: nothing is being served")
	}

	if len(cfg.Warnings) > 0 {
		rep.Add("config", status.StatusWarn, cfg.Warnings[0])
	} else {
		rep.Add("config", status.StatusOK, "valid")
	}

	// A skipped document is something the operator asked for and is not
	// getting: worth a warning, never an outage.
	if warns := m.Warnings(); len(warns) > 0 {
		detail := warns[0]
		if len(warns) > 1 {
			detail = fmt.Sprintf("%s (and %d more: see limen.log)", detail, len(warns)-1)
		}
		rep.Add("model", status.StatusWarn, detail)
	} else {
		rep.Add("model", status.StatusOK, fmt.Sprintf("%d document(s)",
			counts.ProxyHosts+counts.Redirects+counts.Streams+counts.AccessLists+counts.Certificates+counts.Users))
	}

	if err := writable(paths.LogDir); err != nil {
		rep.Add("logdir", status.StatusCritical, err.Error())
	} else {
		rep.Add("logdir", status.StatusOK, paths.LogDir)
	}

	if !cfgs.Watching() {
		rep.Add("config-watch", status.StatusWarn, "not watching config.yaml: reload with SIGHUP")
	}

	rep.Finish()
	return rep
}

// writable proves the directory can still be written to, which is the
// one thing the daemon cannot recover from on its own.
func writable(dir string) error {
	f, err := os.CreateTemp(dir, ".limen-write-*")
	if err != nil {
		return fmt.Errorf("%s is not writable: %w", dir, err)
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}

// checkConfig parses the configuration and reports what it found,
// without starting anything.
func checkConfig(cfgPath string, out *os.File) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "%s: syntax OK\n", cfgPath)
	fmt.Fprintf(out, "  panel      %s", cfg.Panel.Listen)
	if cfg.Panel.Hostname != "" {
		fmt.Fprintf(out, " (published as %s)", cfg.Panel.Hostname)
	}
	fmt.Fprintln(out)
	fmt.Fprintf(out, "  nginx      %s, tree %s\n", cfg.Nginx.Bin, cfg.Nginx.ConfDir)
	if cfg.ACME.Enabled {
		fmt.Fprintf(out, "  acme       %s, renew %s before expiry\n",
			cfg.ACME.Directory, cfg.ACME.RenewBefore.Std())
	} else {
		fmt.Fprintln(out, "  acme       disabled")
	}
	for _, w := range cfg.Warnings {
		fmt.Fprintf(out, "  warning: %s\n", w)
	}

	m, err := store.Open(store.DefaultDirs())
	if err != nil {
		return fmt.Errorf("model: %w", err)
	}
	c := m.Counts()
	fmt.Fprintf(out, "  model      %d host(s), %d redirect(s), %d stream(s), %d access list(s), %d user(s)\n",
		c.ProxyHosts, c.Redirects, c.Streams, c.AccessLists, c.Users)
	for _, w := range m.Warnings() {
		fmt.Fprintf(out, "  warning: %s\n", w)
	}
	return nil
}

func fatalIf(err error) {
	if err == nil {
		return
	}
	if errors.Is(err, proc.ErrNotRunning) {
		fmt.Fprintln(os.Stderr, "limen: service not running")
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "limen:", err)
	os.Exit(1)
}

func usage(w *os.File) {
	fmt.Fprint(w, `limen - nginx manager with a web panel

Service (bare verbs, no dashes):
  start          run the daemon in the foreground (what systemd does)
  stop           signal the running daemon to shut down
  reload         re-read the configuration and the model, reopen the logs
  restart        stop the running daemon, then start it again
  status         query the running daemon and print what it is doing
                 (--json, --watch 2s)

Objects (bare nouns, then a verb; limen host -h for the details):
  host           proxy hosts:  list, show, add, set, rm, enable, disable, location, logs
  redirect       redirects:    list, show, add, set, rm, enable, disable
  stream         TCP/UDP:      list, show, add, set, rm, enable, disable
  access         access lists: list, show, add, set, rm, passwd, deluser
  cert           certificates: list, show, add, set, rm, renew, import
  user           panel users:  list, show, add, set, rm, enable, disable, passwd
  history        history KIND NAME: past revisions of an object
  rollback       rollback KIND NAME REVISION: put one back
  apply          render the model, test it with nginx -t, install, reload
                 (--dry-run: stop after the test; --json)
  logs           nginx-error, nginx-access, limen, apply, api (-n, --follow, --grep)

Everything else (leading -- required):
  --init         install layout, binary, systemd unit and logrotate policy
  --purge        remove config, data and logs (asks for confirmation)
  --check-config parse the configuration, print what it says, then exit
  --import       bring an existing nginx configuration into the model
                 (shows the plan; --write to do it; --from <nginx.conf>)
  --version      print the version and exit
  --help         print this text

Common flags: --config <file>, --socket <path>, --pidfile <path>

Exit codes of 'status' follow the Nagios convention:
  0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN
`)
}
