package secret

import (
	"errors"
	"strings"
	"testing"
)

// The reference hashes come from `openssl passwd -apr1` (OpenSSL
// 3.5.6), not from this package: nginx is the one that checks these,
// and a hash only this code understands would lock everyone out of a
// guarded host in production.
var apr1Vectors = []struct {
	password, salt, want string
}{
	{"correct horse", "Zq3.x9Ab", "$apr1$Zq3.x9Ab$5rGuPlizGh.BXpJzPdKHt1"},
	{"p@ss:w0rd!", "Zq3.x9Ab", "$apr1$Zq3.x9Ab$0LkPGDrB2BnB3G3RmpB43."},
	{"a-very-long-password-longer-than-sixteen-bytes", "Zq3.x9Ab", "$apr1$Zq3.x9Ab$wPIWKLSA9IjpkWO.tAjVZ0"},
	{"àccénted-é", "Zq3.x9Ab", "$apr1$Zq3.x9Ab$5gNoBlXolRgEH.v5AtdsU/"},
	{"short-salt", "ab12", "$apr1$ab12$V7oy4Q.NUOe9BGYaTHm2n."},
}

func TestApr1MatchesOpenSSL(t *testing.T) {
	for _, v := range apr1Vectors {
		if got := apr1(v.password, v.salt); got != v.want {
			t.Errorf("apr1(%q, %q) = %q, want %q", v.password, v.salt, got, v.want)
		}
	}
}

func TestVerifyBasicAcceptsOpenSSLHashes(t *testing.T) {
	for _, v := range apr1Vectors {
		if err := VerifyBasic(v.want, v.password); err != nil {
			t.Errorf("the OpenSSL hash of %q was rejected: %v", v.password, err)
		}
		if err := VerifyBasic(v.want, v.password+"x"); !errors.Is(err, ErrMismatch) {
			t.Errorf("a wrong password for %q was accepted", v.password)
		}
	}
}

func TestHashBasicRoundTripsWithAFreshSalt(t *testing.T) {
	a, err := HashBasic("gate-password")
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashBasic("gate-password")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("two hashes of the same password are identical: the salt is not random")
	}
	if !strings.HasPrefix(a, "$apr1$") {
		t.Errorf("hash %q is not apr1", a)
	}
	if err := VerifyBasic(a, "gate-password"); err != nil {
		t.Errorf("a fresh hash does not verify: %v", err)
	}
}

func TestShortPasswordsAreRefused(t *testing.T) {
	if _, err := HashBasic("1234567"); err == nil {
		t.Error("a 7-character access-list password was accepted")
	}
	if _, err := HashPanel("eleven-char"); err == nil {
		t.Error("an 11-character panel password was accepted")
	}
}

func TestPanelHashRoundTrips(t *testing.T) {
	h, err := HashPanel("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "pbkdf2-sha256$600000$") {
		t.Errorf("hash %q does not carry the scheme and the iteration count", h)
	}
	if err := VerifyPanel(h, "correct horse battery"); err != nil {
		t.Errorf("the right password was rejected: %v", err)
	}
	if err := VerifyPanel(h, "correct horse batterY"); !errors.Is(err, ErrMismatch) {
		t.Errorf("a wrong password gave %v, want ErrMismatch", err)
	}
	if NeedsRehash(h) {
		t.Error("a hash made today reports that it needs a rehash")
	}
}

// A hash made with fewer iterations must still verify — otherwise
// raising the cost would lock every existing user out — and must be
// flagged for an upgrade.
func TestOlderPanelHashesVerifyAndAskForARehash(t *testing.T) {
	old, err := encodePanel("correct horse battery", []byte("0123456789abcdef"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPanel(old, "correct horse battery"); err != nil {
		t.Errorf("an older hash no longer verifies: %v", err)
	}
	if !NeedsRehash(old) {
		t.Error("an older hash is not flagged for a rehash")
	}
}

func TestMalformedPanelHashesAreErrorsNotMatches(t *testing.T) {
	for _, h := range []string{
		"",
		"plain-text-password",
		"pbkdf2-sha256$x$c2FsdA$a2V5",
		"pbkdf2-sha256$1000$$a2V5",
		"pbkdf2-sha1$1000$c2FsdA$a2V5",
		"$apr1$Zq3.x9Ab$5rGuPlizGh.BXpJzPdKHt1",
	} {
		err := VerifyPanel(h, "anything")
		if err == nil {
			t.Errorf("malformed hash %q verified", h)
		}
		if errors.Is(err, ErrMismatch) {
			t.Errorf("malformed hash %q reported as a mere mismatch", h)
		}
	}
}
