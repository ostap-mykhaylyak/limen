package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/config"
	"github.com/ostap-mykhaylyak/limen/internal/model"
	"github.com/ostap-mykhaylyak/limen/internal/store"
)

// makeCert returns a self-signed chain and key for names, valid from
// notBefore to notAfter.
func makeCert(t *testing.T, notBefore, notAfter time.Time, names ...string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: notBefore, NotAfter: notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := encodeKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM
}

func cert(name string, domains ...string) *model.Certificate {
	c := model.NewCertificate(name)
	c.Domains = domains
	return c
}

var now = time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

const month = 30 * 24 * time.Hour

func TestDue(t *testing.T) {
	c := cert("app", "app.example.com", "www.app.example.com")
	fresh := Info{Present: true, NotAfter: now.Add(80 * 24 * time.Hour), Names: []string{"www.app.example.com", "app.example.com"}}
	cases := []struct {
		name string
		info Info
		st   Status
		want bool
	}{
		{"never issued", Info{}, Status{}, true},
		{"fresh, same names in another order", fresh, Status{}, false},
		{"inside the renewal window", Info{Present: true, NotAfter: now.Add(20 * 24 * time.Hour), Names: fresh.Names}, Status{}, true},
		{"a name was added", Info{Present: true, NotAfter: fresh.NotAfter, Names: []string{"app.example.com"}}, Status{}, true},
		{"renewal requested on a fresh one", fresh, Status{RenewRequested: true}, true},
		{"never issued, but waiting after a failure", Info{}, Status{NextAttempt: now.Add(time.Minute)}, false},
		{"unreadable files", Info{Present: true, Error: "no PEM"}, Status{}, true},
	}
	for _, tc := range cases {
		if got, why := Due(c, tc.info, tc.st, now, month); got != tc.want {
			t.Errorf("%s: due = %v (%s), want %v", tc.name, got, why, tc.want)
		}
	}
}

func TestSummarize(t *testing.T) {
	c := cert("app", "app.example.com")
	names := []string{"app.example.com"}
	cases := []struct {
		name string
		info Info
		st   Status
		want string
	}{
		{"valid", Info{Present: true, NotAfter: now.Add(60 * 24 * time.Hour), Names: names}, Status{}, StateValid},
		{"expiring", Info{Present: true, NotAfter: now.Add(10 * 24 * time.Hour), Names: names}, Status{}, StateExpiring},
		{"expired", Info{Present: true, NotAfter: now.Add(-time.Hour), Names: names}, Status{}, StateExpired},
		{"pending", Info{}, Status{}, StatePending},
		{"first order failed", Info{}, Status{LastError: "rate limited"}, StateFailed},
		{"renewal failed, still valid", Info{Present: true, NotAfter: now.Add(20 * 24 * time.Hour), Names: names}, Status{LastError: "timeout"}, StateFailed},
		{"broken files", Info{Present: true, Error: "no PEM"}, Status{}, StateInvalid},
	}
	for _, tc := range cases {
		if got := Summarize(c, tc.info, tc.st, now, month); got.State != tc.want {
			t.Errorf("%s: state = %s (%s), want %s", tc.name, got.State, got.Detail, tc.want)
		}
	}
}

func TestValidatePair(t *testing.T) {
	chain, key := makeCert(t, now.Add(-time.Hour), now.Add(month), "app.example.com")
	if _, err := ValidatePair(chain, key, now); err != nil {
		t.Fatalf("a good pair: %v", err)
	}
	_, otherKey := makeCert(t, now.Add(-time.Hour), now.Add(month), "app.example.com")
	if _, err := ValidatePair(chain, otherKey, now); err == nil {
		t.Error("a key that does not match was accepted: nginx would refuse to start")
	}
	old, oldKey := makeCert(t, now.Add(-2*month), now.Add(-time.Hour), "app.example.com")
	if _, err := ValidatePair(old, oldKey, now); err == nil {
		t.Error("an expired certificate was accepted")
	}
	if _, err := ValidatePair([]byte("garbage"), key, now); err == nil {
		t.Error("garbage was accepted as a certificate")
	}
}

func TestWriteCertKeepsTheKeyPrivate(t *testing.T) {
	dir := t.TempDir()
	chain, key := makeCert(t, now.Add(-time.Hour), now.Add(month), "app.example.com")
	if err := WriteCert(dir, "app", chain, key); err != nil {
		t.Fatal(err)
	}
	info := ReadInfo(dir, "app")
	if !info.Present || info.Names[0] != "app.example.com" || info.Fingerprint == "" {
		t.Errorf("info = %+v", info)
	}
	if runtime.GOOS != "windows" {
		for _, f := range []string{"privkey.pem", "fullchain.pem"} {
			st, _ := os.Stat(filepath.Join(dir, "app", f))
			if st.Mode().Perm() != 0o600 {
				t.Errorf("%s has mode %o", f, st.Mode().Perm())
			}
		}
	}
	if _, err := PathsOf(dir, "../etc"); err == nil {
		t.Error("a traversing certificate name was accepted")
	}
}

func TestChallengesAnswerOnlyKnownTokens(t *testing.T) {
	c := NewChallenges()
	c.Put("tok123", "tok123.thumb")
	get := func(path string) (int, string) {
		w := httptest.NewRecorder()
		c.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		return w.Code, w.Body.String()
	}
	if code, body := get(ChallengePrefix + "tok123"); code != 200 || body != "tok123.thumb" {
		t.Errorf("known token: %d %q", code, body)
	}
	for _, p := range []string{ChallengePrefix + "nope", ChallengePrefix, ChallengePrefix + "tok123/x"} {
		if code, _ := get(p); code != 404 {
			t.Errorf("%s: %d, want 404", p, code)
		}
	}
	c.Delete("tok123")
	if code, _ := get(ChallengePrefix + "tok123"); code != 404 {
		t.Error("a withdrawn token is still answered")
	}
}

// managerWith builds a manager over a temporary store whose orders are
// answered by obtain.
func managerWith(t *testing.T, obtain func(Order) ([]byte, []byte, error), certs ...*model.Certificate) (*Manager, *int) {
	t.Helper()
	root := t.TempDir()
	s, err := store.Open(store.Under(filepath.Join(root, "model")))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range certs {
		if _, err := s.Put(c, store.Change{}); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Default()
	applies := 0
	m := &Manager{
		Store: s, Config: func() *config.Config { return cfg }, CertsDir: filepath.Join(root, "certs"),
		Apply: func(string) { applies++ },
		obtain: func(_ context.Context, _ *config.Config, o Order) ([]byte, []byte, error) {
			return obtain(o)
		},
		now: func() time.Time { return now },
	}
	return m, &applies
}

func TestRunIssuesWhatIsDueAndAppliesAfterEach(t *testing.T) {
	var orders []Order
	m, applies := managerWith(t, func(o Order) ([]byte, []byte, error) {
		orders = append(orders, o)
		chain, key := makeCert(t, now.Add(-time.Hour), now.Add(3*month), o.Domains...)
		return chain, key, nil
	}, cert("a", "a.example.com"), cert("b", "b.example.com"))

	if !m.RunOnce(context.Background()) {
		t.Fatal("nothing issued")
	}
	// One apply per certificate: a certificate reported valid must be
	// the one nginx serves, without waiting for the next order.
	if len(orders) != 2 || *applies != 2 {
		t.Errorf("orders = %d, applies = %d: want 2 of each", len(orders), *applies)
	}
	if orders[0].KeyType != "ec256" || orders[0].Challenge != "http" {
		t.Errorf("order = %+v", orders[0])
	}
	// A second run finds them fresh and does nothing.
	if m.RunOnce(context.Background()) || len(orders) != 2 || *applies != 2 {
		t.Error("a run with nothing due issued or applied")
	}
}

// A failing order must not be retried at once: Let's Encrypt counts
// failed validations, and an order that keeps failing gets the account
// rate limited.
func TestFailuresBackOff(t *testing.T) {
	calls := 0
	m, applies := managerWith(t, func(Order) ([]byte, []byte, error) {
		calls++
		return nil, nil, errors.New("urn:ietf:params:acme:error:connection: timeout")
	}, cert("a", "a.example.com"))

	m.RunOnce(context.Background())
	m.RunOnce(context.Background())
	if calls != 1 {
		t.Errorf("the failed order was retried at once: %d calls", calls)
	}
	st := ReadStatus(m.CertsDir, "a")
	if st.Failures != 1 || !strings.Contains(st.LastError, "timeout") || !st.NextAttempt.Equal(now.Add(10*time.Minute)) {
		t.Errorf("status = %+v", st)
	}
	if *applies != 0 {
		t.Error("a failure triggered an apply")
	}

	// Time passes: the next attempt comes, fails again, and waits longer.
	later := now.Add(11 * time.Minute)
	m.now = func() time.Time { return later }
	m.RunOnce(context.Background())
	if st := ReadStatus(m.CertsDir, "a"); st.Failures != 2 || !st.NextAttempt.Equal(later.Add(time.Hour)) {
		t.Errorf("second failure: %+v", st)
	}
}

func TestARenewalRequestBeatsTheBackoff(t *testing.T) {
	calls := 0
	m, _ := managerWith(t, func(o Order) ([]byte, []byte, error) {
		calls++
		chain, key := makeCert(t, now.Add(-time.Hour), now.Add(3*month), o.Domains...)
		return chain, key, nil
	}, cert("a", "a.example.com"))
	WriteStatus(m.CertsDir, "a", Status{Failures: 3, NextAttempt: now.Add(6 * time.Hour)})

	if err := m.Request("a"); err != nil {
		t.Fatal(err)
	}
	m.RunOnce(context.Background())
	if calls != 1 {
		t.Errorf("an operator's renewal waited for the backoff: %d calls", calls)
	}
	if st := ReadStatus(m.CertsDir, "a"); st.RenewRequested || st.Failures != 0 {
		t.Errorf("status after success = %+v", st)
	}
}

// Whatever the CA sends, nginx must never be handed a pair it would
// refuse: that would take every host down at the next reload.
func TestAnUnusableCertificateIsNeverInstalled(t *testing.T) {
	m, applies := managerWith(t, func(o Order) ([]byte, []byte, error) {
		chain, _ := makeCert(t, now.Add(-time.Hour), now.Add(3*month), o.Domains...)
		_, otherKey := makeCert(t, now.Add(-time.Hour), now.Add(3*month), o.Domains...)
		return chain, otherKey, nil
	}, cert("a", "a.example.com"))
	m.RunOnce(context.Background())
	if ReadInfo(m.CertsDir, "a").Present || *applies != 0 {
		t.Error("a certificate with the wrong key was installed")
	}
	if !strings.Contains(ReadStatus(m.CertsDir, "a").LastError, "unusable") {
		t.Errorf("status = %+v", ReadStatus(m.CertsDir, "a"))
	}
}

func TestCustomCertificatesAreNeverOrdered(t *testing.T) {
	custom := cert("up", "up.example.com")
	custom.Provider, custom.Challenge = model.ProviderCustom, ""
	m, _ := managerWith(t, func(Order) ([]byte, []byte, error) {
		t.Fatal("a custom certificate was ordered")
		return nil, nil, nil
	}, custom)
	m.RunOnce(context.Background())
	if err := m.Request("up"); !errors.Is(err, store.ErrConflict) {
		t.Errorf("a renewal of a custom certificate: %v", err)
	}
}

func TestUpload(t *testing.T) {
	custom := cert("up", "up.example.com", "www.up.example.com")
	custom.Provider, custom.Challenge = model.ProviderCustom, ""
	m, applies := managerWith(t, nil, custom, cert("auto", "auto.example.com"))

	partial, pkey := makeCert(t, now.Add(-time.Hour), now.Add(month), "up.example.com")
	if _, err := m.Upload("up", partial, pkey); !errors.Is(err, store.ErrInvalid) || !strings.Contains(err.Error(), "www.up.example.com") {
		t.Errorf("a certificate missing a name: %v", err)
	}
	wild, wkey := makeCert(t, now.Add(-time.Hour), now.Add(month), "up.example.com", "*.up.example.com")
	if _, err := m.Upload("up", wild, wkey); err != nil {
		t.Errorf("a wildcard covering www: %v", err)
	}
	if !ReadInfo(m.CertsDir, "up").Present || *applies != 1 {
		t.Error("the upload was not installed and applied")
	}
	if _, err := m.Upload("auto", wild, wkey); !errors.Is(err, store.ErrConflict) {
		t.Errorf("an upload over an ACME certificate: %v", err)
	}
}

func TestCovers(t *testing.T) {
	names := []string{"example.com", "*.example.com"}
	for d, want := range map[string]bool{
		"example.com": true, "a.example.com": true, "a.b.example.com": false,
		"other.com": false, "*.example.com": true, "notexample.com": false,
	} {
		if got := model.Covers(names, d); got != want {
			t.Errorf("Covers(%s) = %v, want %v", d, got, want)
		}
	}
}
