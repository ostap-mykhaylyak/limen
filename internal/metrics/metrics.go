// Package metrics keeps the live counters of the running daemon.
//
// They live in memory, are updated on the hot path with atomics, and
// are published through the local status socket: a second process
// (limen status) cannot see this memory, so the daemon has to hand the
// snapshot out. The same Snapshot is what the REST API serves.
package metrics

import (
	"sync/atomic"
	"time"
)

// Registry is the set of counters a daemon keeps. The zero value is
// ready to use, but New sets the start time.
type Registry struct {
	start time.Time

	requests     atomic.Int64
	requestsErr  atomic.Int64
	inFlight     atomic.Int64
	logins       atomic.Int64
	loginsFailed atomic.Int64

	applies       atomic.Int64
	appliesFailed atomic.Int64
	reloads       atomic.Int64
	rollbacks     atomic.Int64
	lastApplyUnix atomic.Int64

	certsIssued  atomic.Int64
	certsRenewed atomic.Int64
	certsFailed  atomic.Int64
	lastCertUnix atomic.Int64

	configReloads atomic.Int64
}

// New returns a registry started now.
func New() *Registry { return &Registry{start: time.Now()} }

// Start returns the moment the registry was created, i.e. the daemon
// start time.
func (r *Registry) Start() time.Time { return r.start }

// Request counting. Begin is paired with End through a defer, so that
// in-flight is decremented even when a handler panics.
func (r *Registry) Begin() { r.inFlight.Add(1); r.requests.Add(1) }

// End closes a request; failed marks it as an error response.
func (r *Registry) End(failed bool) {
	r.inFlight.Add(-1)
	if failed {
		r.requestsErr.Add(1)
	}
}

// Login records a panel authentication attempt.
func (r *Registry) Login(ok bool) {
	if ok {
		r.logins.Add(1)
		return
	}
	r.loginsFailed.Add(1)
}

// Apply records an apply that changed something, or failed. An apply
// with nothing to do is not counted: it did not happen, as far as
// nginx is concerned.
func (r *Registry) Apply(ok, reloaded bool) {
	r.applies.Add(1)
	if !ok {
		r.appliesFailed.Add(1)
		return
	}
	r.lastApplyUnix.Store(time.Now().Unix())
	if reloaded {
		r.reloads.Add(1)
	}
}

// Rollback records a candidate tree that was discarded because nginx
// refused it.
func (r *Registry) Rollback() { r.rollbacks.Add(1) }

// Cert records the outcome of an ACME order.
func (r *Registry) Cert(kind string, ok bool) {
	if !ok {
		r.certsFailed.Add(1)
		return
	}
	switch kind {
	case "renew":
		r.certsRenewed.Add(1)
	default:
		r.certsIssued.Add(1)
	}
	r.lastCertUnix.Store(time.Now().Unix())
}

// ConfigReload records a successful reload of config.yaml.
func (r *Registry) ConfigReload() { r.configReloads.Add(1) }

// Snapshot is the serializable view of the counters. Field names are
// part of the public contract of `limen status --json`: dashboards are
// built on them, so they do not change between releases.
type Snapshot struct {
	UptimeSeconds int64 `json:"uptime_seconds"`

	RequestsTotal     int64 `json:"requests_total"`
	RequestsFailed    int64 `json:"requests_failed"`
	RequestsInFlight  int64 `json:"requests_in_flight"`
	LoginsTotal       int64 `json:"logins_total"`
	LoginsFailed      int64 `json:"logins_failed"`
	ConfigReloads     int64 `json:"config_reloads"`
	AppliesTotal      int64 `json:"applies_total"`
	AppliesFailed     int64 `json:"applies_failed"`
	NginxReloads      int64 `json:"nginx_reloads"`
	Rollbacks         int64 `json:"rollbacks"`
	LastApplyUnix     int64 `json:"last_apply_unix"`
	CertsIssued       int64 `json:"certs_issued"`
	CertsRenewed      int64 `json:"certs_renewed"`
	CertsFailed       int64 `json:"certs_failed"`
	LastCertIssueUnix int64 `json:"last_cert_issue_unix"`
}

// Snapshot reads every counter. The read is not a single atomic
// transaction, and does not need to be: these are counters, not
// invariants.
func (r *Registry) Snapshot() Snapshot {
	return Snapshot{
		UptimeSeconds:     int64(time.Since(r.start).Seconds()),
		RequestsTotal:     r.requests.Load(),
		RequestsFailed:    r.requestsErr.Load(),
		RequestsInFlight:  r.inFlight.Load(),
		LoginsTotal:       r.logins.Load(),
		LoginsFailed:      r.loginsFailed.Load(),
		ConfigReloads:     r.configReloads.Load(),
		AppliesTotal:      r.applies.Load(),
		AppliesFailed:     r.appliesFailed.Load(),
		NginxReloads:      r.reloads.Load(),
		Rollbacks:         r.rollbacks.Load(),
		LastApplyUnix:     r.lastApplyUnix.Load(),
		CertsIssued:       r.certsIssued.Load(),
		CertsRenewed:      r.certsRenewed.Load(),
		CertsFailed:       r.certsFailed.Load(),
		LastCertIssueUnix: r.lastCertUnix.Load(),
	}
}

// Rate returns the per-second change of a counter between two
// snapshots taken dt apart. It is how `limen status --watch` turns
// monotonic counters into live rates.
func Rate(prev, cur int64, dt time.Duration) float64 {
	if dt <= 0 || cur < prev {
		return 0
	}
	return float64(cur-prev) / dt.Seconds()
}
