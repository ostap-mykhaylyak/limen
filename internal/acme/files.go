// Package acme issues and renews the certificates of the model, and
// keeps the files nginx reads.
//
// A certificate lives in /var/lib/limen/certs/<name>/:
//
//	fullchain.pem   the certificate and its chain, as nginx wants it
//	privkey.pem     its key, 0600
//	status.json     limen's record of the attempts: when, how it went,
//	                when to try again
//
// The files are state, not configuration: the model says what a
// certificate is for; these say what it is now.
package acme

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// Files are the paths of one certificate.
type Files struct {
	Dir, Chain, Key, Status string
}

var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$`)

// PathsOf returns the files of a certificate. The name is checked
// again here: it becomes a directory.
func PathsOf(certsDir, name string) (Files, error) {
	if !nameRe.MatchString(name) || name == "." || name == ".." {
		return Files{}, fmt.Errorf("certificate name %q", name)
	}
	dir := filepath.Join(certsDir, name)
	return Files{
		Dir:    dir,
		Chain:  filepath.Join(dir, "fullchain.pem"),
		Key:    filepath.Join(dir, "privkey.pem"),
		Status: filepath.Join(dir, "status.json"),
	}, nil
}

// Info is what the certificate on disk says about itself.
type Info struct {
	Present     bool      `json:"present"`
	NotBefore   time.Time `json:"not_before,omitzero"`
	NotAfter    time.Time `json:"not_after,omitzero"`
	Issuer      string    `json:"issuer,omitempty"`
	Serial      string    `json:"serial,omitempty"`
	Names       []string  `json:"names,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Error       string    `json:"error,omitempty"`
}

// ReadInfo reads the certificate of a name. A missing certificate is
// not an error: Present says so.
func ReadInfo(certsDir, name string) Info {
	f, err := PathsOf(certsDir, name)
	if err != nil {
		return Info{Error: err.Error()}
	}
	b, err := os.ReadFile(f.Chain)
	if err != nil {
		if os.IsNotExist(err) {
			return Info{}
		}
		return Info{Error: err.Error()}
	}
	info, err := parseChain(b)
	if err != nil {
		return Info{Present: true, Error: err.Error()}
	}
	return info
}

func parseChain(chainPEM []byte) (Info, error) {
	block, _ := pem.Decode(chainPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return Info{}, errors.New("no PEM certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Info{}, err
	}
	sum := sha256.Sum256(leaf.Raw)
	return Info{
		Present:     true,
		NotBefore:   leaf.NotBefore,
		NotAfter:    leaf.NotAfter,
		Issuer:      leaf.Issuer.CommonName,
		Serial:      leaf.SerialNumber.Text(16),
		Names:       leaf.DNSNames,
		Fingerprint: hex.EncodeToString(sum[:]),
	}, nil
}

// ValidatePair checks that a chain and a key belong together and that
// the certificate is usable now: what nginx would otherwise refuse at
// the next reload, or serve to browsers that refuse it.
func ValidatePair(chainPEM, keyPEM []byte, now time.Time) (Info, error) {
	info, err := parseChain(chainPEM)
	if err != nil {
		return Info{}, fmt.Errorf("certificate: %w", err)
	}
	if _, err := tls.X509KeyPair(chainPEM, keyPEM); err != nil {
		return Info{}, fmt.Errorf("the key does not match the certificate: %w", err)
	}
	if now.After(info.NotAfter) {
		return Info{}, fmt.Errorf("the certificate expired on %s", info.NotAfter.Format(time.DateOnly))
	}
	if now.Before(info.NotBefore) {
		return Info{}, fmt.Errorf("the certificate is not valid before %s", info.NotBefore.Format(time.DateOnly))
	}
	return info, nil
}

// WriteCert installs a chain and a key. The key goes first: a reload
// catching the new chain with the old key would fail, one catching the
// old chain with the new key likewise — limen reloads only after both,
// and each file is replaced whole.
func WriteCert(certsDir, name string, chainPEM, keyPEM []byte) error {
	f, err := PathsOf(certsDir, name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return err
	}
	if err := writeAtomic(f.Key, keyPEM, 0o600); err != nil {
		return err
	}
	return writeAtomic(f.Chain, chainPEM, 0o600)
}

// Trash moves the files of a deleted certificate aside, instead of
// deleting them: an uploaded certificate cannot be issued again.
func Trash(certsDir, name string) error {
	f, err := PathsOf(certsDir, name)
	if err != nil {
		return err
	}
	if _, err := os.Stat(f.Dir); os.IsNotExist(err) {
		return nil
	}
	trash := filepath.Join(certsDir, ".trash")
	if err := os.MkdirAll(trash, 0o700); err != nil {
		return err
	}
	return os.Rename(f.Dir, filepath.Join(trash, name+"-"+time.Now().UTC().Format("20060102T150405Z")))
}

// Status is limen's record of the attempts at a certificate.
type Status struct {
	LastAttempt    time.Time `json:"last_attempt,omitzero"`
	LastSuccess    time.Time `json:"last_success,omitzero"`
	Failures       int       `json:"failures,omitzero"`
	NextAttempt    time.Time `json:"next_attempt,omitzero"`
	LastError      string    `json:"last_error,omitempty"`
	RenewRequested bool      `json:"renew_requested,omitempty"`
}

// ReadStatus reads the status of a certificate; a missing one is empty.
func ReadStatus(certsDir, name string) Status {
	var st Status
	f, err := PathsOf(certsDir, name)
	if err != nil {
		return st
	}
	if b, err := os.ReadFile(f.Status); err == nil {
		json.Unmarshal(b, &st)
	}
	return st
}

// WriteStatus records the status of a certificate.
func WriteStatus(certsDir, name string, st Status) error {
	f, err := PathsOf(certsDir, name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(f.Status, append(b, '\n'), 0o600)
}

// RequestRenewal marks a certificate to be issued again at the next
// run, whatever its expiry. The command line uses it: the daemon is the
// one that answers challenges.
func RequestRenewal(certsDir, name string) error {
	st := ReadStatus(certsDir, name)
	st.RenewRequested = true
	st.NextAttempt = time.Time{}
	return WriteStatus(certsDir, name, st)
}

// encodeKey renders a private key the way nginx reads it.
func encodeKey(key crypto.Signer) ([]byte, error) {
	switch key.(type) {
	case *ecdsa.PrivateKey, *rsa.PrivateKey, ed25519.PrivateKey:
	default:
		return nil, fmt.Errorf("unsupported key %T", key)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func encodeChain(der [][]byte) []byte {
	var buf bytes.Buffer
	for _, c := range der {
		pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c})
	}
	return buf.Bytes()
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(data)
	serr := tmp.Sync()
	cerr := tmp.Close()
	if err := errors.Join(werr, serr, cerr, os.Chmod(name, mode)); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}
