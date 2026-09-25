// Package secret hashes the two kinds of password limen stores.
//
// They are hashed differently on purpose, because they are checked by
// different programs:
//
//   - panel users are checked by limen itself, so they get the
//     strongest hash the standard library offers without cgo or a new
//     dependency: PBKDF2-HMAC-SHA256 at 600 000 iterations (the OWASP
//     recommendation for that function);
//   - access-list users are checked by nginx, from an htpasswd file, so
//     they must be in a format nginx verifies on its own on every
//     platform: apr1, the Apache MD5-crypt that `htpasswd -m` writes.
//     It is a weak hash by modern standards; these credentials guard a
//     basic-auth gate, and the file that holds them is readable only by
//     root and nginx.
package secret

import (
	"crypto/md5"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Panel password parameters.
const (
	panelScheme     = "pbkdf2-sha256"
	PanelIterations = 600_000
	panelSaltLen    = 16
	panelKeyLen     = 32

	// MinPanelPassword is the shortest password accepted for a panel
	// account: the panel is the control plane of the machine.
	MinPanelPassword = 12

	// MinBasicPassword is the shortest password accepted for an
	// access-list user.
	MinBasicPassword = 8
)

// iterations is the cost of a new panel hash. It is PanelIterations in
// production; SetIterationsForTesting lowers it, because 600 000 rounds
// per login make a suite of login tests crawl under the race detector.
var iterations = PanelIterations

// SetIterationsForTesting lowers the cost of new panel hashes. It exists
// for other packages' tests only, and returns the function restoring
// the production value.
func SetIterationsForTesting(n int) func() {
	iterations = n
	return func() { iterations = PanelIterations }
}

// ErrMismatch is returned when a password does not match its hash.
var ErrMismatch = errors.New("password does not match")

// HashPanel hashes a panel password into
// "pbkdf2-sha256$<iterations>$<salt>$<key>" (base64, no padding).
func HashPanel(password string) (string, error) {
	if len(password) < MinPanelPassword {
		return "", fmt.Errorf("password too short: at least %d characters", MinPanelPassword)
	}
	salt := make([]byte, panelSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return encodePanel(password, salt, iterations)
}

func encodePanel(password string, salt []byte, iter int) (string, error) {
	key, err := pbkdf2.Key(sha256.New, password, salt, iter, panelKeyLen)
	if err != nil {
		return "", err
	}
	enc := base64.RawStdEncoding
	return fmt.Sprintf("%s$%d$%s$%s", panelScheme, iter, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

// VerifyPanel checks a password against an encoded panel hash, in
// constant time.
func VerifyPanel(encoded, password string) error {
	iter, salt, want, err := decodePanel(encoded)
	if err != nil {
		return err
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrMismatch
	}
	return nil
}

// NeedsRehash reports whether a hash was made with weaker parameters
// than today's, so that it can be upgraded at the next login.
func NeedsRehash(encoded string) bool {
	iter, _, _, err := decodePanel(encoded)
	return err != nil || iter < iterations
}

func decodePanel(encoded string) (int, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != panelScheme {
		return 0, nil, nil, errors.New("not a pbkdf2-sha256 hash")
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 {
		return 0, nil, nil, errors.New("malformed iteration count")
	}
	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[2])
	if err != nil || len(salt) == 0 {
		return 0, nil, nil, errors.New("malformed salt")
	}
	key, err := enc.DecodeString(parts[3])
	if err != nil || len(key) == 0 {
		return 0, nil, nil, errors.New("malformed key")
	}
	return iter, salt, key, nil
}

// ---------------------------------------------------------------------
// apr1
// ---------------------------------------------------------------------

const (
	apr1Magic = "$apr1$"
	itoa64    = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// HashBasic hashes an access-list password in apr1 with a random salt.
func HashBasic(password string) (string, error) {
	if len(password) < MinBasicPassword {
		return "", fmt.Errorf("password too short: at least %d characters", MinBasicPassword)
	}
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	salt := make([]byte, 8)
	for i, b := range raw {
		salt[i] = itoa64[int(b)&0x3f]
	}
	return apr1(password, string(salt)), nil
}

// VerifyBasic checks a password against an apr1 hash, in constant time.
// nginx is the one that checks these in production; this exists so
// that limen can test what it writes.
func VerifyBasic(encoded, password string) error {
	rest, ok := strings.CutPrefix(encoded, apr1Magic)
	if !ok {
		return errors.New("not an apr1 hash")
	}
	salt, _, ok := strings.Cut(rest, "$")
	if !ok {
		return errors.New("malformed apr1 hash")
	}
	if subtle.ConstantTimeCompare([]byte(apr1(password, salt)), []byte(encoded)) != 1 {
		return ErrMismatch
	}
	return nil
}

// apr1 is Poul-Henning Kamp's MD5-crypt with the Apache magic string,
// as implemented by APR and htpasswd.
func apr1(password, salt string) string {
	if len(salt) > 8 {
		salt = salt[:8]
	}
	pw := []byte(password)

	alt := md5.New()
	alt.Write(pw)
	alt.Write([]byte(salt))
	alt.Write(pw)
	altSum := alt.Sum(nil)

	ctx := md5.New()
	ctx.Write(pw)
	ctx.Write([]byte(apr1Magic))
	ctx.Write([]byte(salt))
	for i := len(pw); i > 0; i -= 16 {
		ctx.Write(altSum[:min(i, 16)])
	}
	for i := len(pw); i > 0; i >>= 1 {
		if i&1 != 0 {
			ctx.Write([]byte{0})
		} else {
			ctx.Write(pw[:1])
		}
	}
	final := ctx.Sum(nil)

	// A thousand rounds, to slow a brute force down a little.
	for i := range 1000 {
		round := md5.New()
		if i&1 != 0 {
			round.Write(pw)
		} else {
			round.Write(final)
		}
		if i%3 != 0 {
			round.Write([]byte(salt))
		}
		if i%7 != 0 {
			round.Write(pw)
		}
		if i&1 != 0 {
			round.Write(final)
		} else {
			round.Write(pw)
		}
		final = round.Sum(nil)
	}

	var b strings.Builder
	b.WriteString(apr1Magic)
	b.WriteString(salt)
	b.WriteByte('$')
	to64 := func(v uint32, n int) {
		for ; n > 0; n-- {
			b.WriteByte(itoa64[v&0x3f])
			v >>= 6
		}
	}
	for _, g := range [][3]int{{0, 6, 12}, {1, 7, 13}, {2, 8, 14}, {3, 9, 15}, {4, 10, 5}} {
		to64(uint32(final[g[0]])<<16|uint32(final[g[1]])<<8|uint32(final[g[2]]), 4)
	}
	to64(uint32(final[11]), 2)
	return b.String()
}
