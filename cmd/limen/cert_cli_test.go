package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/acme"
	"github.com/ostap-mykhaylyak/limen/internal/model"
	"github.com/ostap-mykhaylyak/limen/internal/store"
)

// pemPair writes a certificate and its key for names into dir.
func pemPair(t *testing.T, dir string, days int, names ...string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Duration(days) * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	chain, keyFile := filepath.Join(dir, "chain.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600)
	return chain, keyFile
}

func (h *harness) cert(t *testing.T, name string) *model.Certificate {
	t.Helper()
	doc, err := h.store.Get(model.KindCertificate, name)
	if err != nil {
		t.Fatal(err)
	}
	return doc.(*model.Certificate)
}

func TestCertAddDefaultsAndWildcards(t *testing.T) {
	h := newHarness(t)
	h.must(t, "cert add app --domain app.example.com")
	if c := h.cert(t, "app"); c.Provider != "acme" || c.Challenge != "http" {
		t.Errorf("defaults = %+v", c)
	}
	// A wildcard can only be proven through DNS: that is the default for one.
	h.must(t, "cert add wild --domain *.example.com")
	if c := h.cert(t, "wild"); c.Challenge != "dns" {
		t.Errorf("wildcard challenge = %q", c.Challenge)
	}
	if err := h.do(t, "cert add bad --domain *.example.org --challenge http"); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("a wildcard over http: %v", err)
	}
	out := h.must(t, "cert list")
	for _, want := range []string{"app.example.com", "acme/http", "pending", "*.example.com", "acme/dns"} {
		if !strings.Contains(out, want) {
			t.Errorf("list is missing %q:\n%s", want, out)
		}
	}
}

func TestCertInUseCannotBeDeletedAndDeletionKeepsTheFiles(t *testing.T) {
	h := newHarness(t)
	chain, key := pemPair(t, t.TempDir(), 60, "app.example.com")
	h.must(t, "cert import app --chain "+chain+" --key "+key)
	h.must(t, "host add app --domain app.example.com --forward 10.0.0.5 --certificate app")

	if err := h.do(t, "cert rm app"); !errors.Is(err, store.ErrConflict) || !strings.Contains(err.Error(), "proxy host app") {
		t.Fatalf("deleting a certificate in use: %v", err)
	}
	h.must(t, "host set app --certificate=")
	h.must(t, "cert rm app")
	if acme.ReadInfo(h.certs, "app").Present {
		t.Error("the files are still where nginx would read them")
	}
	trashed, _ := filepath.Glob(filepath.Join(h.certs, ".trash", "app-*", "fullchain.pem"))
	if len(trashed) != 1 {
		t.Error("the files of an uploaded certificate were destroyed, not set aside")
	}
}

func TestCertImport(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	chain, key := pemPair(t, dir, 60, "shop.example.com", "www.shop.example.com")
	out := h.must(t, "cert import shop --chain "+chain+" --key "+key)
	if !strings.Contains(out, "valid until") {
		t.Errorf("import said %q", out)
	}
	c := h.cert(t, "shop")
	if c.Provider != "custom" || strings.Join(c.Domains, ",") != "shop.example.com,www.shop.example.com" {
		t.Errorf("imported certificate = %+v", c)
	}
	if !strings.Contains(h.must(t, "cert show shop"), "state: valid") {
		t.Error("show does not report the state")
	}

	// A key that does not match never reaches nginx.
	_, otherKey := pemPair(t, t.TempDir(), 60, "shop.example.com")
	if err := h.do(t, "cert import shop2 --chain "+chain+" --key "+otherKey); err == nil {
		t.Error("a mismatched pair was imported")
	}
	// A replacement must still cover what the model wants.
	short, shortKey := pemPair(t, t.TempDir(), 60, "shop.example.com")
	if err := h.do(t, "cert import shop --chain "+short+" --key "+shortKey); err == nil || !strings.Contains(err.Error(), "www.shop.example.com") {
		t.Errorf("a replacement missing a name: %v", err)
	}
	// And limen's own certificates are not overwritten by an import.
	h.must(t, "cert add auto --domain auto.example.com")
	auto, autoKey := pemPair(t, t.TempDir(), 60, "auto.example.com")
	if err := h.do(t, "cert import auto --chain "+auto+" --key "+autoKey); err == nil {
		t.Error("an import replaced an ACME certificate")
	}
}

func TestCertRenewAsksTheDaemon(t *testing.T) {
	h := newHarness(t)
	h.must(t, "cert add app --domain app.example.com")
	out := h.must(t, "cert renew app")
	if !acme.ReadStatus(h.certs, "app").RenewRequested || !strings.Contains(out, "nudged") {
		t.Errorf("renew: %q, status %+v", out, acme.ReadStatus(h.certs, "app"))
	}
	chain, key := pemPair(t, t.TempDir(), 60, "up.example.com")
	h.must(t, "cert import up --chain "+chain+" --key "+key)
	if err := h.do(t, "cert renew up"); err == nil {
		t.Error("a renewal of an uploaded certificate was accepted")
	}
}
