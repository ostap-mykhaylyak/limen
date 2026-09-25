package auth

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var born = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func openTokens(t *testing.T, dir string) *Tokens {
	t.Helper()
	tk, err := OpenTokens(filepath.Join(dir, "tokens.json"), filepath.Join(dir, ".tokens.lock"))
	if err != nil {
		t.Fatal(err)
	}
	return tk
}

func spec(name string) TokenSpec {
	return TokenSpec{Name: name, User: "alice", UserCreated: born, Role: "operator", CreatedBy: "test", TTL: 24 * time.Hour}
}

func TestATokenIsShownOnceAndKeptAsAHash(t *testing.T) {
	dir := t.TempDir()
	tk := openTokens(t, dir)
	token, made, err := tk.Create(spec("ci"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, "limen_"+made.ID+"_") || !IsTokenLike(token) || TokenID(token) != made.ID {
		t.Fatalf("token %q, id %q", token, made.ID)
	}
	b, err := os.ReadFile(filepath.Join(dir, "tokens.json"))
	if err != nil {
		t.Fatal(err)
	}
	secret := strings.TrimPrefix(token, "limen_"+made.ID+"_")
	if strings.Contains(string(b), secret) {
		t.Error("the file holds the secret")
	}
	if !strings.Contains(string(b), hashSecret(secret)) {
		t.Error("the file does not hold the secret's hash")
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(filepath.Join(dir, "tokens.json"))
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("mode %v", fi.Mode().Perm())
		}
	}
	for _, l := range tk.List() {
		if l.Hash != "" {
			t.Error("List shows the hash")
		}
	}

	got, err := tk.Verify(token, "192.0.2.1")
	if err != nil || got.Name != "ci" || got.Role != "operator" || got.User != "alice" {
		t.Fatalf("Verify = %+v, %v", got, err)
	}
}

func TestWrongTokensAreRefused(t *testing.T) {
	tk := openTokens(t, t.TempDir())
	token, made, err := tk.Create(spec("ci"))
	if err != nil {
		t.Fatal(err)
	}
	other, _, _ := tk.Create(spec("other"))
	secret := strings.TrimPrefix(token, "limen_"+made.ID+"_")
	flipped := []byte(secret)
	flipped[10] ^= 1
	if flipped[10] == '_' || flipped[10] == '-' {
		flipped[10] = 'A'
	}
	bad := []string{
		"",
		"nonsense",
		token + "x",
		strings.TrimPrefix(token, "limen_"),
		"limen_" + made.ID + "_" + string(flipped),
		// Another token's secret under this one's id.
		"limen_" + made.ID + "_" + other[len(other)-43:],
		"limen_0000000000000000_" + secret,
		strings.ToUpper(token),
	}
	for _, b := range bad {
		if _, err := tk.Verify(b, "x"); !errors.Is(err, ErrTokenInvalid) {
			t.Errorf("Verify(%q) = %v, want ErrTokenInvalid", b, err)
		}
	}
}

func TestAnExpiredTokenIsRefused(t *testing.T) {
	tk := openTokens(t, t.TempDir())
	now := time.Now()
	tk.now = func() time.Time { return now }
	token, _, err := tk.Create(spec("ci"))
	if err != nil {
		t.Fatal(err)
	}
	tk.now = func() time.Time { return now.Add(24*time.Hour - time.Minute) }
	if _, err := tk.Verify(token, "x"); err != nil {
		t.Fatalf("a minute before expiry: %v", err)
	}
	tk.now = func() time.Time { return now.Add(24*time.Hour + time.Second) }
	if _, err := tk.Verify(token, "x"); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("after expiry: %v", err)
	}

	s := spec("forever")
	s.TTL = 0
	forever, made, err := tk.Create(s)
	if err != nil || !made.Expires.IsZero() {
		t.Fatalf("a token without expiry: %+v %v", made, err)
	}
	tk.now = func() time.Time { return now.AddDate(20, 0, 0) }
	if _, err := tk.Verify(forever, "x"); err != nil {
		t.Errorf("a token that never expires, 20 years on: %v", err)
	}
}

// The daemon and the command line are two processes: what one revokes,
// the other must refuse at once.
func TestARevocationElsewhereTakesEffectAtOnce(t *testing.T) {
	dir := t.TempDir()
	daemon := openTokens(t, dir)
	cli := openTokens(t, dir)

	token, _, err := cli.Create(spec("ci"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := daemon.Verify(token, "x"); err != nil {
		t.Fatalf("a token made elsewhere: %v", err)
	}
	if _, err := cli.Delete("ci"); err != nil {
		t.Fatal(err)
	}
	if _, err := daemon.Verify(token, "x"); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("a token revoked elsewhere: %v", err)
	}
	// And a write by the daemon does not bring it back.
	if _, _, err := daemon.Create(spec("other")); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.Get("ci"); err == nil {
		t.Error("the daemon's write resurrected the revoked token")
	}
}

func TestTokenNamesAreUniqueAndChecked(t *testing.T) {
	tk := openTokens(t, t.TempDir())
	if _, _, err := tk.Create(spec("ci")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tk.Create(spec("ci")); err == nil {
		t.Error("two tokens named ci")
	}
	for _, s := range []TokenSpec{
		{Name: "../x", User: "alice", UserCreated: born, Role: "viewer"},
		{Name: "ok", User: "alice", UserCreated: born, Role: "root"},
		{Name: "ok", User: "", UserCreated: born, Role: "viewer"},
		{Name: "ok", User: "alice", Role: "viewer"},
		{Name: "ok", User: "alice", UserCreated: born, Role: "viewer", TTL: -time.Hour},
		{Name: "ok", User: "alice", UserCreated: born, Role: "viewer", Description: strings.Repeat("x", 201)},
	} {
		if _, _, err := tk.Create(s); err == nil {
			t.Errorf("Create(%+v) succeeded", s)
		}
	}
}

func TestACorruptTokensFileIsAnError(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "tokens.json"), []byte("{not json"), 0o600)
	if _, err := OpenTokens(filepath.Join(dir, "tokens.json"), filepath.Join(dir, ".lock")); err == nil {
		t.Fatal("a corrupt file opened as an empty set: the next write would drop every token")
	}
}

func TestTheLastUseIsWrittenNowAndThen(t *testing.T) {
	dir := t.TempDir()
	tk := openTokens(t, dir)
	now := time.Now().UTC()
	tk.now = func() time.Time { return now }
	token, _, err := tk.Create(spec("ci"))
	if err != nil {
		t.Fatal(err)
	}
	onDisk := func() Token {
		t.Helper()
		l, err := openTokens(t, dir).Get("ci")
		if err != nil {
			t.Fatal(err)
		}
		return l
	}

	tk.Verify(token, "192.0.2.1")
	if got := onDisk(); got.LastClient != "192.0.2.1" || got.LastUsed.IsZero() {
		t.Fatalf("the first use was not written: %+v", got)
	}
	first := onDisk().LastUsed

	// A minute later: noted, not written yet.
	tk.now = func() time.Time { return now.Add(time.Minute) }
	tk.Verify(token, "192.0.2.2")
	if got := onDisk(); !got.LastUsed.Equal(first) {
		t.Errorf("a use a minute later was written at once: %+v", got)
	}
	if got, _ := tk.Get("ci"); got.LastClient != "192.0.2.2" {
		t.Errorf("List does not show the use not yet written: %+v", got)
	}

	// Past the interval: written, with the latest client.
	tk.now = func() time.Time { return now.Add(lastUsedEvery + time.Minute) }
	tk.Verify(token, "192.0.2.3")
	if got := onDisk(); got.LastClient != "192.0.2.3" || !got.LastUsed.After(first) {
		t.Errorf("a use past the interval was not written: %+v", got)
	}
}
