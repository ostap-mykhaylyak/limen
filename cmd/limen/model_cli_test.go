package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ostap-mykhaylyak/limen/internal/model"
	"github.com/ostap-mykhaylyak/limen/internal/secret"
	"github.com/ostap-mykhaylyak/limen/internal/store"
)

type harness struct {
	*cli
	out, errOut *bytes.Buffer
	nudges      int
	passwords   []string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	s, err := store.Open(store.Under(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{out: &bytes.Buffer{}, errOut: &bytes.Buffer{}}
	h.cli = &cli{
		certs:  t.TempDir(),
		store:  s,
		out:    h.out,
		errOut: h.errOut,
		author: "cli:tester",
		nudge: func() string {
			h.nudges++
			return "nudged"
		},
		readPassword: func(string) (string, error) {
			if len(h.passwords) == 0 {
				return "", errors.New("no password queued")
			}
			pw := h.passwords[0]
			h.passwords = h.passwords[1:]
			return pw, nil
		},
	}
	return h
}

// do runs one command line ("host add app --domain ...").
func (h *harness) do(t *testing.T, line string) error {
	t.Helper()
	h.out.Reset()
	h.errOut.Reset()
	args := strings.Fields(line)
	return h.run(args[0], args[1:])
}

func (h *harness) must(t *testing.T, line string) string {
	t.Helper()
	if err := h.do(t, line); err != nil {
		t.Fatalf("limen %s: %v\n%s", line, err, h.errOut)
	}
	return h.out.String()
}

func (h *harness) host(t *testing.T, name string) *model.ProxyHost {
	t.Helper()
	doc, err := h.store.Get(model.KindProxyHost, name)
	if err != nil {
		t.Fatal(err)
	}
	return doc.(*model.ProxyHost)
}

func TestHostAddStoresWhatTheFlagsSay(t *testing.T) {
	h := newHarness(t)
	h.must(t, "cert add app --domain app.example.com --domain www.app.example.com")
	h.must(t, "host add app --domain app.example.com --domain www.app.example.com --forward https://10.0.0.5:8443 --websockets --max-body 200m --certificate app --force-https")

	got := h.host(t, "app")
	if strings.Join(got.Domains, ",") != "app.example.com,www.app.example.com" {
		t.Errorf("domains = %v", got.Domains)
	}
	if got.Forward != (model.Upstream{Scheme: "https", Host: "10.0.0.5", Port: 8443}) {
		t.Errorf("forward = %+v", got.Forward)
	}
	if !got.Websockets || got.ClientMaxBodySize != "200m" || got.TLS.Certificate != "app" || !got.TLS.ForceHTTPS {
		t.Errorf("flags lost: %+v", got)
	}
	// Flags not passed keep the model's defaults.
	if !got.Enabled || !got.BlockExploits || !got.TLS.HTTP2 {
		t.Errorf("defaults lost: %+v", got)
	}
	if h.nudges != 2 {
		t.Errorf("the daemon was nudged %d times, want 2: one per write", h.nudges)
	}
}

func TestHostAddNamesTheHostAfterItsFirstDomain(t *testing.T) {
	h := newHarness(t)
	h.must(t, "host add --domain Shop.Example.com --forward 10.0.0.7:3000")
	got := h.host(t, "shop.example.com")
	if got.Domains[0] != "shop.example.com" {
		t.Errorf("the domain was not lowercased: %v", got.Domains)
	}

	h.must(t, "host add --domain *.apps.example.com --forward 10.0.0.8")
	h.host(t, "wildcard.apps.example.com")
}

// `set` must touch only what is passed: re-typing the whole host to
// change one option is how options get lost.
func TestHostSetChangesOnlyThePassedFlags(t *testing.T) {
	h := newHarness(t)
	h.must(t, "host add app --domain app.example.com --forward http://10.0.0.5:8080 --websockets")
	h.must(t, "host set app --forward 10.0.0.6:9090 --note move")

	got := h.host(t, "app")
	if got.Forward.Host != "10.0.0.6" || got.Forward.Port != 9090 {
		t.Errorf("forward = %+v", got.Forward)
	}
	if !got.Websockets || got.Domains[0] != "app.example.com" {
		t.Errorf("set changed what it was not asked to: %+v", got)
	}

	h.must(t, "host set app --websockets=false")
	if h.host(t, "app").Websockets {
		t.Error("--websockets=false did not switch websockets off")
	}
}

func TestHostAddRefusesToOverwrite(t *testing.T) {
	h := newHarness(t)
	h.must(t, "host add app --domain app.example.com --forward 10.0.0.5")
	err := h.do(t, "host add app --domain other.example.com --forward 10.0.0.6")
	if err == nil || !strings.Contains(err.Error(), "limen host set app") {
		t.Errorf("err = %v, want a pointer to `set`", err)
	}
}

func TestHostAddSurfacesTheStoreChecks(t *testing.T) {
	h := newHarness(t)
	h.must(t, "host add app --domain app.example.com --forward 10.0.0.5")
	if err := h.do(t, "host add dup --domain app.example.com --forward 10.0.0.6"); !errors.Is(err, store.ErrConflict) {
		t.Errorf("a duplicate domain: err = %v, want ErrConflict", err)
	}
	if err := h.do(t, "host add nodomain --forward 10.0.0.6"); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("a host without domains: err = %v, want ErrInvalid", err)
	}
	if err := h.do(t, "host add guarded --domain g.example.com --forward 10.0.0.6 --access-list nope"); !errors.Is(err, store.ErrConflict) {
		t.Errorf("a missing access list: err = %v, want ErrConflict", err)
	}
	if h.nudges != 1 {
		t.Errorf("refused writes nudged the daemon: %d nudges, want 1", h.nudges)
	}
}

func TestEnableDisable(t *testing.T) {
	h := newHarness(t)
	h.must(t, "host add app --domain app.example.com --forward 10.0.0.5 --disabled")
	if h.host(t, "app").Enabled {
		t.Fatal("--disabled created an enabled host")
	}
	h.must(t, "host enable app")
	if !h.host(t, "app").Enabled {
		t.Error("enable did not switch the host on")
	}
	h.must(t, "host disable app")
	if h.host(t, "app").Enabled {
		t.Error("disable did not switch the host off")
	}
}

func TestListShowsEveryHost(t *testing.T) {
	h := newHarness(t)
	if out := h.must(t, "host list"); !strings.Contains(out, "no proxy hosts yet") {
		t.Errorf("empty list = %q", out)
	}
	h.must(t, "host add app --domain app.example.com --forward 10.0.0.5:8080")
	h.must(t, "host add api --domain api.example.com --forward 10.0.0.6:9000 --disabled")
	out := h.must(t, "host list")
	for _, want := range []string{"NAME", "app.example.com", "http://10.0.0.5:8080", "api", "disabled"} {
		if !strings.Contains(out, want) {
			t.Errorf("list is missing %q:\n%s", want, out)
		}
	}

	out = h.must(t, "host list --json")
	var docs []map[string]any
	if err := json.Unmarshal([]byte(out), &docs); err != nil {
		t.Fatalf("list --json is not JSON: %v\n%s", err, out)
	}
	if len(docs) != 2 || docs[0]["name"] != "api" {
		t.Errorf("list --json = %v", docs)
	}
}

func TestDeleteHistoryAndRollback(t *testing.T) {
	h := newHarness(t)
	h.must(t, "host add app --domain app.example.com --forward 10.0.0.5:8080")
	h.must(t, "host set app --forward 10.0.0.5:9090 --note bump")
	h.must(t, "host rm app --note gone")
	if err := h.do(t, "host show app"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("show after rm: err = %v", err)
	}

	out := h.must(t, "history host app")
	for _, want := range []string{"delete", "update", "cli:tester", "bump", "gone", "limen rollback host app"} {
		if !strings.Contains(out, want) {
			t.Errorf("history is missing %q:\n%s", want, out)
		}
	}

	revs, err := h.store.History(model.KindProxyHost, "app")
	if err != nil {
		t.Fatal(err)
	}
	h.must(t, "rollback host app "+revs[0].ID)
	if h.host(t, "app").Forward.Port != 9090 {
		t.Errorf("rollback restored port %d, want 9090", h.host(t, "app").Forward.Port)
	}
}

func TestUserNeedsAPasswordAndNeverShowsItsHash(t *testing.T) {
	h := newHarness(t)
	if err := h.do(t, "user add ostap --role admin"); err == nil {
		t.Fatal("a user without a password was created")
	}

	h.passwords = []string{"correct horse battery"}
	h.must(t, "user add ostap --role admin --email ostap@example.com --password-stdin")

	doc, err := h.store.Get(model.KindUser, "ostap")
	if err != nil {
		t.Fatal(err)
	}
	if err := secret.VerifyPanel(doc.(*model.User).Password, "correct horse battery"); err != nil {
		t.Errorf("the stored hash does not verify the password: %v", err)
	}

	out := h.must(t, "user show ostap")
	if strings.Contains(out, "pbkdf2") || !strings.Contains(out, "(hidden)") {
		t.Errorf("show leaks the hash:\n%s", out)
	}
	out = h.must(t, "user show ostap --json")
	if strings.Contains(out, "pbkdf2") || strings.Contains(out, "password") {
		t.Errorf("show --json leaks the hash:\n%s", out)
	}

	h.passwords = []string{"short"}
	if err := h.do(t, "user passwd ostap"); err == nil {
		t.Error("a too-short password was accepted")
	}
}

func TestTheLastAdminIsDefendedFromTheCommandLine(t *testing.T) {
	h := newHarness(t)
	h.passwords = []string{"correct horse battery"}
	h.must(t, "user add ostap --role admin --password-stdin")
	if err := h.do(t, "user disable ostap"); !errors.Is(err, store.ErrConflict) {
		t.Errorf("disabling the only admin: err = %v", err)
	}
	if err := h.do(t, "user rm ostap"); !errors.Is(err, store.ErrConflict) {
		t.Errorf("deleting the only admin: err = %v", err)
	}
}

func TestAccessListRulesKeepTheirOrder(t *testing.T) {
	h := newHarness(t)
	h.must(t, "access add office --rule allow:192.168.1.0/24 --rule deny:192.168.1.66 --rule deny:all")
	doc, err := h.store.Get(model.KindAccessList, "office")
	if err != nil {
		t.Fatal(err)
	}
	rules := doc.(*model.AccessList).Rules
	got := []string{}
	for _, r := range rules {
		got = append(got, r.Action+":"+r.Address)
	}
	// nginx stops at the first match: reordering these changes who gets in.
	if want := "allow:192.168.1.0/24,deny:192.168.1.66,deny:all"; strings.Join(got, ",") != want {
		t.Errorf("rules = %s, want %s", strings.Join(got, ","), want)
	}
	if err := h.do(t, "access add bad --rule permit:10.0.0.0/8"); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("an unknown action: err = %v", err)
	}
}

func TestAccessListUsers(t *testing.T) {
	h := newHarness(t)
	h.passwords = []string{"gate-password"}
	h.must(t, "access add staff --user ops")

	h.passwords = []string{"second-password"}
	h.must(t, "access passwd staff dev")
	h.passwords = []string{"changed-password"}
	out := h.must(t, "access passwd staff ops")
	if !strings.Contains(out, "changed") {
		t.Errorf("changing an existing user said %q", out)
	}

	doc, _ := h.store.Get(model.KindAccessList, "staff")
	a := doc.(*model.AccessList)
	if len(a.Users) != 2 {
		t.Fatalf("users = %+v", a.Users)
	}
	if err := secret.VerifyBasic(a.Users[0].Password, "changed-password"); err != nil {
		t.Errorf("ops's new password does not verify: %v", err)
	}
	if err := secret.VerifyBasic(a.Users[1].Password, "second-password"); err != nil {
		t.Errorf("dev's password does not verify: %v", err)
	}
	if out := h.must(t, "access show staff"); strings.Contains(out, "$apr1$") {
		t.Errorf("show leaks the hashes:\n%s", out)
	}

	h.must(t, "access deluser staff dev")
	if err := h.do(t, "access deluser staff dev"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("removing a missing user: err = %v", err)
	}
}

func TestAccessListInUseSaysWhoUsesIt(t *testing.T) {
	h := newHarness(t)
	h.must(t, "access add office --rule allow:10.0.0.0/8 --rule deny:all")
	h.must(t, "host add admin --domain admin.example.com --forward 10.0.0.5 --access-list office")
	out := h.must(t, "access list")
	if !strings.Contains(out, "admin") {
		t.Errorf("the list does not show what the access list guards:\n%s", out)
	}
	if err := h.do(t, "access rm office"); !errors.Is(err, store.ErrConflict) {
		t.Errorf("deleting a list in use: err = %v", err)
	}
}

func TestRedirectAndStream(t *testing.T) {
	h := newHarness(t)
	h.must(t, "redirect add old --domain old.example.com --to https://new.example.com --code 308 --preserve-path=false")
	doc, err := h.store.Get(model.KindRedirect, "old")
	if err != nil {
		t.Fatal(err)
	}
	r := doc.(*model.Redirect)
	if r.Target != (model.Target{Scheme: "https", Domain: "new.example.com"}) || r.Code != 308 {
		t.Errorf("redirect = %+v", r)
	}
	h.must(t, "redirect add keep --domain keep.example.com --to new.example.com:8443")
	doc, _ = h.store.Get(model.KindRedirect, "keep")
	if got := doc.(*model.Redirect).Target; got.Scheme != "auto" || !got.PreservePath {
		t.Errorf("a target without scheme = %+v, want auto and the path preserved", got)
	}
	if err := h.do(t, "redirect add bad --domain bad.example.com --to https://x.example.com/path"); err == nil {
		t.Error("a redirect target with a path was accepted")
	}

	h.must(t, "stream add pg --listen 5432 --forward 10.0.0.9:5432")
	h.must(t, "stream add dns --listen 53 --forward 10.0.0.53:53 --protocol tcp,udp")
	doc, _ = h.store.Get(model.KindStream, "dns")
	if s := doc.(*model.Stream); !s.Has("tcp") || !s.Has("udp") {
		t.Errorf("protocols = %v", s.Protocols)
	}
	if err := h.do(t, "stream add clash --listen 5432 --forward 10.0.0.10:5432"); !errors.Is(err, store.ErrConflict) {
		t.Errorf("a second stream on the same port: err = %v", err)
	}
}

func TestUnknownVerbsAndMissingNames(t *testing.T) {
	h := newHarness(t)
	if err := h.do(t, "host frobnicate app"); err == nil {
		t.Error("an unknown verb was accepted")
	}
	if err := h.do(t, "access enable staff"); err == nil {
		t.Error("enable on an access list was accepted: it has no switch")
	}
	if err := h.do(t, "host show"); err == nil {
		t.Error("show without a name was accepted")
	}
	if err := h.do(t, "host set --forward 10.0.0.5"); err == nil {
		t.Error("set without a name was accepted")
	}
	if err := h.do(t, "host"); !errors.Is(err, errUsage) {
		t.Errorf("a bare noun: err = %v, want the usage", err)
	}
	if err := h.do(t, "rollback host app ../../../etc/passwd"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a traversing revision id: err = %v", err)
	}
}
