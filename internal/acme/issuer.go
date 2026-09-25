package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

// Issuer obtains certificates from an ACME directory.
type Issuer struct {
	Directory string
	Contact   string
	// DirectoryCA is an extra PEM bundle to trust for the directory's
	// own TLS (a private CA, Pebble in a test).
	DirectoryCA string
	// AccountDir holds one account per directory.
	AccountDir string

	HTTP    *Challenges
	DNSHook string
	DNSWait time.Duration

	Log *slog.Logger
}

// Order is what one certificate asks for.
type Order struct {
	Domains   []string
	Challenge string // "http" or "dns"
	KeyType   string // ec256, ec384, rsa2048, rsa4096
}

// Obtain runs a whole order and returns the chain and the key, PEM.
func (i *Issuer) Obtain(ctx context.Context, o Order) (chainPEM, keyPEM []byte, err error) {
	client, err := i.client(ctx)
	if err != nil {
		return nil, nil, err
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(o.Domains...))
	if err != nil {
		return nil, nil, fmt.Errorf("new order: %w", explain(err))
	}
	// Kept apart: later answers about the order may not carry its URL.
	orderURL := order.URI
	for _, zurl := range order.AuthzURLs {
		if err := i.authorize(ctx, client, zurl, o.Challenge); err != nil {
			return nil, nil, err
		}
	}
	order, err = client.WaitOrder(ctx, orderURL)
	if err != nil {
		return nil, nil, fmt.Errorf("order: %w", explain(err))
	}

	key, err := newKey(o.KeyType)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: o.Domains[0]},
		DNSNames: o.Domains,
	}, key)
	if err != nil {
		return nil, nil, err
	}
	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		// A CA may answer the finalize without the order's Location
		// header (Pebble does, and RFC 8555 does not require it); the
		// client then waits on an empty URL although the finalize went
		// through. Wait on the order we know: if it turns valid, the
		// certificate is there to fetch; if not, the finalize really
		// failed and its error stands.
		if done, werr := client.WaitOrder(ctx, orderURL); werr == nil && done.Status == acme.StatusValid && done.CertURL != "" {
			der, err = client.FetchCert(ctx, done.CertURL, true)
		}
	}
	if err != nil {
		return nil, nil, fmt.Errorf("finalize: %w", explain(err))
	}
	keyPEM, err = encodeKey(key)
	if err != nil {
		return nil, nil, err
	}
	return encodeChain(der), keyPEM, nil
}

// authorize proves control of one identifier.
func (i *Issuer) authorize(ctx context.Context, client *acme.Client, zurl, kind string) error {
	z, err := client.GetAuthorization(ctx, zurl)
	if err != nil {
		return fmt.Errorf("authorization: %w", explain(err))
	}
	if z.Status == acme.StatusValid {
		return nil // proven recently, the CA remembers
	}
	want := "http-01"
	if kind == "dns" {
		want = "dns-01"
	}
	var chal *acme.Challenge
	for _, c := range z.Challenges {
		if c.Type == want {
			chal = c
		}
	}
	if chal == nil {
		return fmt.Errorf("%s: the CA offers no %s challenge", z.Identifier.Value, want)
	}

	switch want {
	case "http-01":
		answer, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return err
		}
		i.HTTP.Put(chal.Token, answer)
		defer i.HTTP.Delete(chal.Token)
	case "dns-01":
		value, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return err
		}
		record := "_acme-challenge." + strings.TrimPrefix(z.Identifier.Value, "*.") + "."
		if err := i.dnsHook(ctx, "present", record, value); err != nil {
			return fmt.Errorf("%s: dns_hook present: %w", z.Identifier.Value, err)
		}
		defer i.dnsHook(context.WithoutCancel(ctx), "cleanup", record, value)
		i.waitTXT(ctx, record, value)
	}

	if _, err := client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("%s: %w", z.Identifier.Value, explain(err))
	}
	if _, err := client.WaitAuthorization(ctx, z.URI); err != nil {
		// explain names the identifier already.
		return explain(err)
	}
	return nil
}

func (i *Issuer) dnsHook(ctx context.Context, verb, record, value string) error {
	if i.DNSHook == "" {
		return errors.New("acme.dns_hook is not set: a DNS challenge needs a program that writes the record")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, i.DNSHook, verb, record, value).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// waitTXT waits for the record to be visible, up to DNSWait. Not seeing
// it is not an error: this machine's resolver may not be the one the CA
// uses, and the CA will say so itself.
func (i *Issuer) waitTXT(ctx context.Context, record, value string) {
	deadline := time.Now().Add(i.DNSWait)
	for time.Now().Before(deadline) {
		lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		txts, _ := net.DefaultResolver.LookupTXT(lctx, record)
		cancel()
		if slices.Contains(txts, value) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}
	if i.Log != nil {
		i.Log.Info("dns record not seen locally, asking the CA anyway", "record", record)
	}
}

// ---------------------------------------------------------------------
// Account
// ---------------------------------------------------------------------

type accountFile struct {
	Directory string `json:"directory"`
	URI       string `json:"uri"`
	Contact   string `json:"contact,omitempty"`
}

// client returns a client with its account, registering one on first
// use. Accounts are kept per directory: staging and production, or two
// CAs, never share a key.
func (i *Issuer) client(ctx context.Context) (*acme.Client, error) {
	hc, err := i.httpClient()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(i.Directory))
	dir := filepath.Join(i.AccountDir, hex.EncodeToString(sum[:6]))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	key, err := loadOrCreateKey(filepath.Join(dir, "account.key"))
	if err != nil {
		return nil, err
	}
	client := &acme.Client{Key: key, DirectoryURL: i.Directory, HTTPClient: hc, UserAgent: "limen"}

	metaPath := filepath.Join(dir, "account.json")
	var meta accountFile
	if b, err := os.ReadFile(metaPath); err == nil && json.Unmarshal(b, &meta) == nil && meta.URI != "" && meta.Contact == i.Contact {
		client.KID = acme.KeyID(meta.URI)
		return client, nil
	}

	acct := &acme.Account{}
	if i.Contact != "" {
		acct.Contact = []string{"mailto:" + i.Contact}
	}
	got, err := client.Register(ctx, acct, acme.AcceptTOS)
	if errors.Is(err, acme.ErrAccountAlreadyExists) {
		got, err = client.GetReg(ctx, "")
	}
	if err != nil {
		return nil, fmt.Errorf("account: %w", explain(err))
	}
	b, _ := json.MarshalIndent(accountFile{Directory: i.Directory, URI: got.URI, Contact: i.Contact}, "", "  ")
	if err := writeAtomic(metaPath, append(b, '\n'), 0o600); err != nil {
		return nil, err
	}
	client.KID = acme.KeyID(got.URI)
	return client, nil
}

func (i *Issuer) httpClient() (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if i.DirectoryCA != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		b, err := os.ReadFile(i.DirectoryCA)
		if err != nil {
			return nil, fmt.Errorf("acme.directory_ca: %w", err)
		}
		if !pool.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("acme.directory_ca %s: no certificate in it", i.DirectoryCA)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: tr, Timeout: 60 * time.Second}, nil
}

func loadOrCreateKey(path string) (crypto.Signer, error) {
	if b, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, fmt.Errorf("%s: not PEM", path)
		}
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		signer, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("%s: not a signing key", path)
		}
		return signer, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pemKey, err := encodeKey(key)
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(path, pemKey, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func newKey(kind string) (crypto.Signer, error) {
	switch kind {
	case "", "ec256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ec384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "rsa2048":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "rsa4096":
		return rsa.GenerateKey(rand.Reader, 4096)
	}
	return nil, fmt.Errorf("key type %q", kind)
}

// explain turns an ACME problem into the sentence an operator needs:
// the CA's own detail, not the Go type around it.
func explain(err error) error {
	if ae, ok := errors.AsType[*acme.Error](err); ok {
		msg := ae.Detail
		if msg == "" {
			msg = ae.ProblemType
		}
		for _, sub := range ae.Subproblems {
			msg += "; " + sub.Identifier.Value + ": " + sub.Detail
		}
		return errors.New(msg)
	}
	if oe, ok := errors.AsType[*acme.OrderError](err); ok {
		return fmt.Errorf("the order ended as %s", oe.Status)
	}
	if ze, ok := errors.AsType[*acme.AuthorizationError](err); ok {
		parts := []string{}
		for _, e := range ze.Errors {
			parts = append(parts, explain(e).Error())
		}
		return fmt.Errorf("%s: %s", ze.Identifier, strings.Join(parts, "; "))
	}
	return err
}
