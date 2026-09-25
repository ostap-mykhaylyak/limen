package main

import (
	"strings"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/auth"
	"github.com/ostap-mykhaylyak/limen/internal/nginx"
)

func (h *harness) user(t *testing.T, name, role string) {
	t.Helper()
	h.passwords = append(h.passwords, "correct horse battery")
	h.must(t, "user add "+name+" --role "+role+" --password-stdin")
}

func TestTokenAddPrintsTheTokenAloneOnStdout(t *testing.T) {
	h := newHarness(t)
	h.user(t, "ostap", "admin")
	out := h.must(t, "token add ci --user ostap --role operator --expires 30d --description deploys")
	token := strings.TrimSpace(out)
	if !auth.IsTokenLike(token) || strings.Count(out, "\n") != 1 {
		t.Fatalf("stdout = %q: a script reading it must get the token and nothing else", out)
	}
	if !strings.Contains(h.errOut.String(), "shown this once") {
		t.Errorf("stderr = %q", h.errOut)
	}
	got, err := h.tokens.Verify(token, "x")
	if err != nil || got.Role != "operator" || got.User != "ostap" || got.CreatedBy != "cli:tester" || got.Description != "deploys" {
		t.Fatalf("token = %+v, %v", got, err)
	}
	if d := time.Until(got.Expires); d < 29*24*time.Hour || d > 30*24*time.Hour {
		t.Errorf("expires in %v, want 30 days", d)
	}

	list := h.must(t, "token list")
	if !strings.Contains(list, "ci") || !strings.Contains(list, "active") || strings.Contains(list, token[len(token)-43:]) {
		t.Errorf("list = %s", list)
	}
}

func TestTokenAddRefusesWhatCannotWork(t *testing.T) {
	h := newHarness(t)
	h.user(t, "ostap", "admin")
	h.user(t, "vic", "viewer")
	for _, line := range []string{
		"token add ci",                            // no user
		"token add ci --user nobody",              // no such user
		"token add ci --user vic --role operator", // above the user
		"token add ci --user vic --role root",     // no such role
		"token add ci --user vic --expires 0d",    // nonsense
		"token add ci --user vic --expires soon",  // nonsense
		"token add ci --user vic --expires 4000d", // too long
		"token add ci --user vic --expires -1h",   // the past
		"token add ../ci --user vic",              // a name that is a path
		"token add ci --user vic extra",           // stray argument
	} {
		if err := h.do(t, line); err == nil {
			t.Errorf("limen %s succeeded", line)
		}
	}
	h.must(t, "user disable vic")
	if err := h.do(t, "token add ci --user vic"); err == nil {
		t.Error("a token for a disabled user")
	}
	if n := len(h.tokens.List()); n != 0 {
		t.Errorf("%d tokens made", n)
	}

	h.must(t, "token add forever --user ostap --expires never")
	if got, _ := h.tokens.Get("forever"); !got.Expires.IsZero() || got.Role != "admin" {
		t.Errorf("--expires never, no --role: %+v", got)
	}
}

func TestTokenRmAndUserRmRevoke(t *testing.T) {
	h := newHarness(t)
	h.user(t, "ostap", "admin")
	h.user(t, "olga", "operator")
	a := strings.TrimSpace(h.must(t, "token add a --user olga"))
	b := strings.TrimSpace(h.must(t, "token add b --user olga"))
	c := strings.TrimSpace(h.must(t, "token add c --user ostap"))

	h.must(t, "token rm a")
	if _, err := h.tokens.Verify(a, "x"); err == nil {
		t.Error("a removed token still works")
	}
	if err := h.do(t, "token rm a"); err == nil {
		t.Error("removing a missing token succeeded")
	}

	out := h.must(t, "user rm olga")
	if !strings.Contains(out, "1 API token(s) of olga revoked") {
		t.Errorf("user rm said %q", out)
	}
	if _, err := h.tokens.Verify(b, "x"); err == nil {
		t.Error("the token of a removed user is still there")
	}
	if _, err := h.tokens.Verify(c, "x"); err != nil {
		t.Errorf("another user's token went too: %v", err)
	}
}

func TestParseLifetime(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"90d": 90 * 24 * time.Hour, "1d": 24 * time.Hour, "12h": 12 * time.Hour, "1h30m": 90 * time.Minute,
		"never": 0, "0": 0,
	} {
		if got, err := parseLifetime(in); err != nil || got != want {
			t.Errorf("parseLifetime(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
}

// A panel user is nothing nginx sees. On a fresh install the first admin
// is made before limen is started, and that must not be the moment nginx
// is taken over; any change nginx does see is applied at once.
func TestOnlyWhatNginxSeesIsApplied(t *testing.T) {
	h := newHarness(t)
	applies := 0
	h.apply = func(bool) (nginx.Result, error) {
		applies++
		return nginx.Result{Changed: true, Generation: "test"}, nil
	}
	h.user(t, "ostap", "admin")
	h.passwords = append(h.passwords, "another long password")
	h.must(t, "user passwd ostap")
	h.must(t, "user set ostap --email ostap@example.com")
	h.user(t, "vic", "viewer")
	h.must(t, "user disable vic")
	h.must(t, "user rm vic")
	if applies != 0 {
		t.Errorf("user changes applied nginx %d times", applies)
	}
	h.must(t, "host add --domain app.example.com --forward 10.0.0.5:8080")
	if applies != 1 {
		t.Errorf("a host change applied nginx %d times, want 1", applies)
	}
}
