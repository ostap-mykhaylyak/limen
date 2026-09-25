// Package paths centralizes the hardcoded FHS layout of limen.
//
// Production code relies ONLY on these constants; overrides (e.g. the
// -config flag) exist solely for testing.
package paths

const (
	// Binary is where the installed executable lives.
	Binary = "/usr/sbin/limen"

	// ConfigDir holds the daemon configuration and the whole managed
	// model: one YAML file per proxy host, redirect, stream, access
	// list and panel user. Unlike most services of this family the
	// directory is writable at runtime, because the panel is the
	// primary way to edit it; every write is atomic and validated.
	ConfigDir  = "/etc/limen"
	ConfigFile = ConfigDir + "/config.yaml"

	// Model directories, one YAML document per object.
	HostsDir     = ConfigDir + "/hosts"
	RedirectsDir = ConfigDir + "/redirects"
	StreamsDir   = ConfigDir + "/streams"
	AccessDir    = ConfigDir + "/access"
	CertDocsDir  = ConfigDir + "/certificates"
	UsersDir     = ConfigDir + "/users"

	// HistoryDir keeps the previous revision of every document the
	// panel rewrites, so any change can be rolled back.
	HistoryDir = ConfigDir + "/history"

	// DataDir holds runtime state that is not configuration:
	// certificates, ACME account keys, session secrets.
	DataDir    = "/var/lib/limen"
	CertsDir   = DataDir + "/certs"
	AcmeDir    = DataDir + "/acme"
	SecretFile = DataDir + "/session.key"

	// SessionsFile keeps the panel's sessions across restarts, by the
	// hash of their ids only.
	SessionsFile = DataDir + "/sessions.json"
	BackupDir    = DataDir + "/backup"
	RenderedDir  = DataDir + "/rendered"

	// ApplyLock serializes applies to nginx across processes: the
	// daemon and the command line both apply.
	ApplyLock = DataDir + "/.apply.lock"

	// LogDir holds all log files.
	LogDir = "/var/log/limen"

	// RunDir holds the pidfile and the local status socket (tmpfs,
	// managed by systemd via RuntimeDirectory=).
	RunDir  = "/run/limen"
	Socket  = RunDir + "/limen.sock"
	Pidfile = RunDir + "/limen.pid"

	// The nginx tree limen owns. Everything under NginxConfDir is
	// generated from the model; --init backs up whatever was there
	// before touching it.
	NginxConfDir  = "/etc/nginx"
	NginxConfFile = NginxConfDir + "/nginx.conf"
	NginxBin      = "/usr/sbin/nginx"

	// Deploy targets used by `limen init`.
	UnitFile      = "/etc/systemd/system/limen.service"
	LogrotateFile = "/etc/logrotate.d/limen"
)

// Log file names, to be joined with LogDir.
const (
	ServiceLog = "limen.log"
	APILog     = "api.log"
	ApplyLog   = "apply.log"
)
