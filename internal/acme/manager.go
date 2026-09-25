package acme

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/config"
	"github.com/ostap-mykhaylyak/limen/internal/metrics"
	"github.com/ostap-mykhaylyak/limen/internal/model"
	"github.com/ostap-mykhaylyak/limen/internal/store"
)

// backoff is the wait after the n-th failure in a row. Let's Encrypt
// allows five failed validations per hour per name: an order that keeps
// failing must not keep asking.
var backoff = []time.Duration{10 * time.Minute, time.Hour, 6 * time.Hour, 24 * time.Hour}

// States of a certificate, as the API and the interface show them.
const (
	StateValid    = "valid"
	StateExpiring = "expiring" // within renew_before
	StateExpired  = "expired"
	StatePending  = "pending" // not issued yet
	StateFailed   = "failed"  // the last attempt failed
	StateInvalid  = "invalid" // files that do not parse
)

// Manager keeps the ACME certificates of the model issued and fresh.
type Manager struct {
	Store      *store.Store
	Config     func() *config.Config
	CertsDir   string
	AccountDir string
	Challenges *Challenges
	// Apply is called after a run that issued something, so nginx picks
	// the new files up.
	Apply   func(reason string)
	Log     *slog.Logger
	Metrics *metrics.Registry

	// obtain is Issuer.Obtain; tests replace it.
	obtain func(ctx context.Context, c *config.Config, o Order) ([]byte, []byte, error)
	now    func() time.Time

	run  sync.Mutex
	poke chan struct{}
	once sync.Once
}

func (m *Manager) init() {
	m.once.Do(func() {
		m.poke = make(chan struct{}, 1)
		if m.now == nil {
			m.now = time.Now
		}
		if m.Log == nil {
			m.Log = slog.New(slog.DiscardHandler)
		}
		if m.obtain == nil {
			m.obtain = func(ctx context.Context, c *config.Config, o Order) ([]byte, []byte, error) {
				is := &Issuer{
					Directory: c.ACME.Directory, Contact: c.ACME.ContactEmail, DirectoryCA: c.ACME.DirectoryCA,
					AccountDir: m.AccountDir, HTTP: m.Challenges,
					DNSHook: c.ACME.DNSHook, DNSWait: c.ACME.DNSWait.Std(), Log: m.Log,
				}
				return is.Obtain(ctx, o)
			}
		}
	})
}

// Poke asks for a run soon: after a change of the model, a reload, a
// renewal requested from the command line.
func (m *Manager) Poke() {
	m.init()
	select {
	case m.poke <- struct{}{}:
	default:
	}
}

// Run checks the certificates at start, every acme.check_every, and when
// poked, until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	m.init()
	m.RunOnce(ctx)
	for {
		every := m.Config().ACME.CheckEvery.Std()
		if every <= 0 {
			every = 12 * time.Hour
		}
		// Wake at least hourly: a backoff or a renewal request may come
		// due long before the next full check.
		if every > time.Hour {
			every = time.Hour
		}
		select {
		case <-ctx.Done():
			return
		case <-m.poke:
		case <-time.After(every):
		}
		m.RunOnce(ctx)
	}
}

// RunOnce goes through every ACME certificate once and issues the ones
// that are due, one at a time, applying nginx after each. It reports
// whether anything was issued.
func (m *Manager) RunOnce(ctx context.Context) bool {
	m.init()
	m.run.Lock()
	defer m.run.Unlock()

	cfg := m.Config()
	if !cfg.ACME.Enabled {
		return false
	}
	issued := 0
	for _, c := range store.All[*model.Certificate](m.Store, model.KindCertificate) {
		if c.Provider != model.ProviderACME {
			continue
		}
		info := ReadInfo(m.CertsDir, c.Name)
		st := ReadStatus(m.CertsDir, c.Name)
		due, why := Due(c, info, st, m.now(), cfg.ACME.RenewBefore.Std())
		if !due {
			continue
		}
		if m.issue(ctx, cfg, c, info, st, why) {
			issued++
			// Served at once, not at the end of the run: the next order
			// may take minutes, and a certificate that says "valid" must
			// be the one nginx presents.
			if m.Apply != nil {
				m.Apply("certificate " + c.Name + " issued")
			}
		}
		if ctx.Err() != nil {
			break
		}
	}
	return issued > 0
}

// Due decides whether a certificate must be (re)issued now, and why.
func Due(c *model.Certificate, info Info, st Status, now time.Time, renewBefore time.Duration) (bool, string) {
	switch {
	case st.RenewRequested:
		return true, "renewal requested"
	case now.Before(st.NextAttempt):
		return false, "waiting after a failure"
	case !info.Present || info.Error != "":
		return true, "not issued yet"
	case !sameNames(info.Names, c.Domains):
		return true, "its domains changed"
	case info.NotAfter.Sub(now) < renewBefore:
		return true, "it expires on " + info.NotAfter.Format(time.DateOnly)
	}
	return false, ""
}

func sameNames(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	for i := range x {
		x[i] = strings.ToLower(x[i])
	}
	for i := range y {
		y[i] = strings.ToLower(y[i])
	}
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

func (m *Manager) issue(ctx context.Context, cfg *config.Config, c *model.Certificate, info Info, st Status, why string) bool {
	kind := "issue"
	if info.Present {
		kind = "renew"
	}
	m.Log.Info("certificate order", "certificate", c.Name, "domains", strings.Join(c.Domains, ","), "why", why)

	keyType := c.KeyType
	if keyType == "" {
		keyType = cfg.ACME.KeyType
	}
	octx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	chain, key, err := m.obtain(octx, cfg, Order{Domains: c.Domains, Challenge: c.Challenge, KeyType: keyType})
	cancel()

	now := m.now().UTC()
	st.LastAttempt = now
	st.RenewRequested = false
	if err == nil {
		// Never install what nginx would refuse, whatever the CA said.
		if _, verr := ValidatePair(chain, key, now); verr != nil {
			err = fmt.Errorf("the CA returned an unusable certificate: %w", verr)
		} else {
			err = WriteCert(m.CertsDir, c.Name, chain, key)
		}
	}
	if err != nil {
		st.Failures++
		st.LastError = err.Error()
		st.NextAttempt = now.Add(backoff[min(st.Failures, len(backoff))-1])
		WriteStatus(m.CertsDir, c.Name, st)
		m.Log.Error("certificate order failed", "certificate", c.Name, "error", err.Error(),
			"failures", st.Failures, "next_attempt", st.NextAttempt)
		if m.Metrics != nil {
			m.Metrics.Cert(kind, false)
		}
		return false
	}
	st.Failures, st.LastError, st.NextAttempt = 0, "", time.Time{}
	st.LastSuccess = now
	WriteStatus(m.CertsDir, c.Name, st)
	fresh := ReadInfo(m.CertsDir, c.Name)
	m.Log.Info("certificate issued", "certificate", c.Name, "not_after", fresh.NotAfter, "serial", fresh.Serial)
	if m.Metrics != nil {
		m.Metrics.Cert(kind, true)
	}
	return true
}

// ---------------------------------------------------------------------
// What the API and the status report show
// ---------------------------------------------------------------------

// Summary is the state of one certificate.
type Summary struct {
	State    string `json:"state"`
	Detail   string `json:"detail,omitempty"`
	DaysLeft int    `json:"days_left,omitempty"`
	Info     Info   `json:"files"`
	Status   Status `json:"attempts"`
}

// Describe returns the state of a certificate.
func (m *Manager) Describe(c *model.Certificate) Summary {
	m.init()
	info := ReadInfo(m.CertsDir, c.Name)
	st := ReadStatus(m.CertsDir, c.Name)
	return Summarize(c, info, st, m.now(), m.Config().ACME.RenewBefore.Std())
}

// Summarize is Describe without the files: what the state is, given
// what is on disk.
func Summarize(c *model.Certificate, info Info, st Status, now time.Time, renewBefore time.Duration) Summary {
	s := Summary{Info: info, Status: st}
	if info.Present && info.Error == "" {
		s.DaysLeft = int(info.NotAfter.Sub(now).Hours() / 24)
	}
	switch {
	case info.Error != "":
		s.State, s.Detail = StateInvalid, info.Error
	case !info.Present && st.LastError != "":
		s.State, s.Detail = StateFailed, st.LastError
	case !info.Present:
		s.State, s.Detail = StatePending, "not issued yet"
		if c.Provider == model.ProviderCustom {
			s.Detail = "no file uploaded yet"
		}
	case now.After(info.NotAfter):
		s.State, s.Detail = StateExpired, "expired on "+info.NotAfter.Format(time.DateOnly)
	case st.LastError != "" && c.Provider == model.ProviderACME:
		s.State, s.Detail = StateFailed, "the last renewal failed: "+st.LastError
	case info.NotAfter.Sub(now) < renewBefore:
		s.State = StateExpiring
		s.Detail = "expires on " + info.NotAfter.Format(time.DateOnly)
		if c.Provider == model.ProviderCustom {
			s.Detail += ": upload a new one, limen does not renew custom certificates"
		}
	default:
		s.State = StateValid
	}
	if info.Present && info.Error == "" && !sameNames(info.Names, c.Domains) && c.Provider == model.ProviderACME && s.State == StateValid {
		s.State, s.Detail = StatePending, "its domains changed: a new one is on its way"
	}
	return s
}

// Request asks for a certificate to be issued again now.
func (m *Manager) Request(name string) error {
	m.init()
	doc, err := m.Store.Get(model.KindCertificate, name)
	if err != nil {
		return err
	}
	if doc.(*model.Certificate).Provider != model.ProviderACME {
		return fmt.Errorf("certificate %q: %w: it is uploaded, limen does not issue it", name, store.ErrConflict)
	}
	if err := RequestRenewal(m.CertsDir, name); err != nil {
		return err
	}
	m.Poke()
	return nil
}

// Upload installs a certificate and its key for a custom certificate.
func (m *Manager) Upload(name string, chainPEM, keyPEM []byte) (Info, error) {
	m.init()
	doc, err := m.Store.Get(model.KindCertificate, name)
	if err != nil {
		return Info{}, err
	}
	c := doc.(*model.Certificate)
	if c.Provider != model.ProviderCustom {
		return Info{}, fmt.Errorf("certificate %q: %w: limen issues it, there is nothing to upload", name, store.ErrConflict)
	}
	info, err := ValidatePair(chainPEM, keyPEM, m.now())
	if err != nil {
		return Info{}, fmt.Errorf("%w: %v", store.ErrInvalid, err)
	}
	if missing := Uncovered(info.Names, c.Domains); len(missing) > 0 {
		return Info{}, fmt.Errorf("%w: the certificate does not cover %s", store.ErrInvalid, strings.Join(missing, ", "))
	}
	if err := WriteCert(m.CertsDir, name, chainPEM, keyPEM); err != nil {
		return Info{}, err
	}
	if m.Apply != nil {
		m.Apply("certificate " + name + " uploaded")
	}
	return info, nil
}

// Removed moves the files of a deleted certificate aside.
func (m *Manager) Removed(name string) error { return Trash(m.CertsDir, name) }

// Uncovered lists the domains a set of certificate names does not serve.
func Uncovered(names, domains []string) []string {
	var out []string
	for _, d := range domains {
		if !model.Covers(names, d) {
			out = append(out, d)
		}
	}
	return out
}
