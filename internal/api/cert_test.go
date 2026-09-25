package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/acme"
	"github.com/ostap-mykhaylyak/limen/internal/config"
)

// withCerts gives the API a real certificate manager over temporary
// directories; applied counts what it asks nginx to pick up.
func withCerts(e *env) (m *acme.Manager, applied *int) {
	n := 0
	m = &acme.Manager{
		Store:      e.store,
		Config:     func() *config.Config { return e.cfg },
		CertsDir:   filepath.Join(e.dir, "certs"),
		AccountDir: filepath.Join(e.dir, "acme"),
		Challenges: acme.NewChallenges(),
		Apply:      func(string) { n++ },
	}
	e.api = e.build()
	e.api.d.Certificates = m
	return m, &n
}

// selfSigned is a certificate and key for names, PEM.
func selfSigned(t *testing.T, names ...string) (chain, key []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(60 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd})
}

func TestCertificatesCarryTheirStateAndWhoUsesThem(t *testing.T) {
	e := newEnv(t)
	withCerts(e)
	c := e.login("olga")

	r := c.do("POST", "/certificates", map[string]any{"domains": []string{"*.apps.example.com"}, "challenge": "dns"})
	if r.code != 201 {
		t.Fatalf("create: %d %s", r.code, r.raw)
	}
	if name := r.body["item"].(map[string]any)["name"]; name != "wildcard.apps.example.com" {
		t.Errorf("name from the domains = %v", name)
	}
	h := host("one.apps.example.com", 80)
	h["tls"] = map[string]any{"certificate": "wildcard.apps.example.com"}
	if r := c.do("POST", "/hosts", h); r.code != 201 {
		t.Fatalf("host: %d %s", r.code, r.raw)
	}

	got := c.do("GET", "/certificates/wildcard.apps.example.com", nil)
	st := got.body["state"].(map[string]any)
	if st["state"] != acme.StatePending {
		t.Errorf("state before any file = %v", st)
	}
	if u := got.body["used_by"].([]any); len(u) != 1 || u[0] != "proxy host one.apps.example.com" {
		t.Errorf("used_by = %v", u)
	}

	// What GET returns, PUT accepts: an editor sends it all back.
	got.body["description"] = "for the apps"
	if r := c.do("PUT", "/certificates/wildcard.apps.example.com", got.body); r.code != 200 {
		t.Fatalf("round trip: %d %s", r.code, r.raw)
	}
	// And a wildcard still needs DNS.
	got.body["challenge"] = "http"
	if r := c.do("PUT", "/certificates/wildcard.apps.example.com", got.body); r.code != 422 {
		t.Errorf("wildcard over http-01: %d %s", r.code, r.raw)
	}

	// In use: not deleted.
	if r := c.do("DELETE", "/certificates/wildcard.apps.example.com", nil); r.code != 409 {
		t.Errorf("delete in use: %d %s", r.code, r.raw)
	}
	// A host cannot point at a certificate that does not exist.
	h2 := host("two.example.com", 80)
	h2["tls"] = map[string]any{"certificate": "nope"}
	if r := c.do("POST", "/hosts", h2); r.code != 409 {
		t.Errorf("host on a missing certificate: %d %s", r.code, r.raw)
	}
}

func TestRenewIsForOperatorsAndForACMECertificates(t *testing.T) {
	e := newEnv(t)
	m, _ := withCerts(e)
	operator, viewer := e.login("olga"), e.login("vic")

	operator.do("POST", "/certificates", map[string]any{"name": "app", "domains": []string{"app.example.com"}})
	operator.do("POST", "/certificates", map[string]any{"name": "bought", "domains": []string{"shop.example.com"}, "provider": "custom"})

	if r := viewer.do("POST", "/certificates/app/renew", map[string]any{}); r.code != 403 {
		t.Errorf("viewer renews: %d", r.code)
	}
	r := operator.do("POST", "/certificates/app/renew", map[string]any{})
	if r.code != 202 {
		t.Fatalf("renew: %d %s", r.code, r.raw)
	}
	if st := acme.ReadStatus(m.CertsDir, "app"); !st.RenewRequested {
		t.Errorf("the request was not recorded: %+v", st)
	}
	if r := operator.do("POST", "/certificates/bought/renew", map[string]any{}); r.code != 409 {
		t.Errorf("renew an uploaded certificate: %d %s", r.code, r.raw)
	}
	if r := operator.do("POST", "/certificates/ghost/renew", map[string]any{}); r.code != 404 {
		t.Errorf("renew a missing certificate: %d %s", r.code, r.raw)
	}
}

func TestUploadChecksBeforeWriting(t *testing.T) {
	e := newEnv(t)
	m, applied := withCerts(e)
	c := e.login("olga")
	c.do("POST", "/certificates", map[string]any{"name": "bought", "domains": []string{"shop.example.com", "www.shop.example.com"}, "provider": "custom"})
	c.do("POST", "/certificates", map[string]any{"name": "app", "domains": []string{"app.example.com"}})
	files, _ := acme.PathsOf(m.CertsDir, "bought")

	chain, key := selfSigned(t, "shop.example.com", "www.shop.example.com")
	otherChain, otherKey := selfSigned(t, "shop.example.com")

	// Each refused for its own reason: one check must not hide the
	// absence of another.
	bad := []struct {
		name  string
		chain []byte
		key   []byte
		why   string
	}{
		{"key of another certificate", chain, otherKey, "does not match"},
		{"not PEM", []byte("hello"), key, "no PEM certificate"},
		{"does not cover www", otherChain, otherKey, "does not cover www.shop.example.com"},
	}
	for _, b := range bad {
		r := c.do("POST", "/certificates/bought/upload", map[string]string{"chain": string(b.chain), "key": string(b.key)})
		if r.code != 422 || !strings.Contains(r.raw, b.why) {
			t.Errorf("%s: %d %s, want 422 %q", b.name, r.code, r.raw, b.why)
		}
		if _, err := os.Stat(files.Chain); err == nil {
			t.Fatalf("%s: written anyway", b.name)
		}
	}
	if *applied != 0 {
		t.Errorf("applied %d times for refused uploads", *applied)
	}

	r := c.do("POST", "/certificates/bought/upload", map[string]string{"chain": string(chain), "key": string(key)})
	if r.code != 200 {
		t.Fatalf("upload: %d %s", r.code, r.raw)
	}
	if st := r.body["state"].(map[string]any); st["state"] != acme.StateValid {
		t.Errorf("after upload = %v", st)
	}
	if *applied != 1 {
		t.Errorf("applied %d times, want 1", *applied)
	}
	if fi, err := os.Stat(files.Key); err != nil || fi.Mode().Perm()&0o077 != 0 && runtime.GOOS != "windows" {
		t.Errorf("key file: %v %v", fi, err)
	}
	if r := c.do("POST", "/certificates/app/upload", map[string]string{"chain": string(chain), "key": string(key)}); r.code != 409 {
		t.Errorf("upload onto an ACME certificate: %d %s", r.code, r.raw)
	}

	// Deleted: the files move aside, they are not destroyed.
	if r := c.do("DELETE", "/certificates/bought", nil); r.code != 200 {
		t.Fatalf("delete: %d %s", r.code, r.raw)
	}
	if _, err := os.Stat(files.Chain); err == nil {
		t.Error("the files are still in place")
	}
	trash, _ := filepath.Glob(filepath.Join(m.CertsDir, ".trash", "bought-*"))
	if len(trash) != 1 {
		t.Errorf("trash = %v", trash)
	}
}
