package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/model"
)

const (
	apr1Hash  = "$apr1$Zq3.x9Ab$5rGuPlizGh.BXpJzPdKHt1"
	panelHash = "pbkdf2-sha256$600000$c2FsdHNhbHRzYWx0$a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2U"
)

var cli = Change{Author: "test", Source: "cli"}

func open(t *testing.T) (*Store, Dirs) {
	t.Helper()
	dirs := Under(t.TempDir())
	s, err := Open(dirs)
	if err != nil {
		t.Fatal(err)
	}
	return s, dirs
}

func host(name string, domains ...string) *model.ProxyHost {
	h := model.NewProxyHost(name)
	h.Domains = domains
	h.Forward = model.Upstream{Scheme: "http", Host: "10.0.0.5", Port: 8080}
	return h
}

func redirect(name string, domains ...string) *model.Redirect {
	r := model.NewRedirect(name)
	r.Domains = domains
	r.Target.Domain = "target.example.org"
	return r
}

func stream(name string, port int, protos ...string) *model.Stream {
	s := model.NewStream(name)
	s.Listen = port
	s.Protocols = protos
	s.Forward = model.Endpoint{Host: "10.0.0.9", Port: port}
	return s
}

func user(name, role string) *model.User {
	u := model.NewUser(name)
	u.Role = role
	u.Password = panelHash
	return u
}

func acl(name string) *model.AccessList {
	a := model.NewAccessList(name)
	a.Rules = []model.Rule{{Action: "allow", Address: "10.0.0.0/8"}, {Action: "deny", Address: "all"}}
	return a
}

func mustPut(t *testing.T, s *Store, doc model.Document) model.Document {
	t.Helper()
	got, err := s.Put(doc, cli)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestPutWritesAFileThatAReloadReadsBack(t *testing.T) {
	s, dirs := open(t)
	stored := mustPut(t, s, host("app", "app.example.com"))

	if stored.Header().Created.IsZero() || stored.Header().Updated.IsZero() {
		t.Error("Put did not stamp the timestamps")
	}
	if _, err := os.Stat(filepath.Join(dirs.ProxyHosts, "app.yaml")); err != nil {
		t.Fatalf("no file on disk: %v", err)
	}

	fresh, err := Open(dirs)
	if err != nil {
		t.Fatal(err)
	}
	got, err := fresh.Get(model.KindProxyHost, "app")
	if err != nil {
		t.Fatalf("a second store does not see the host: %v", err)
	}
	if got.(*model.ProxyHost).Domains[0] != "app.example.com" {
		t.Errorf("reloaded host = %+v", got)
	}
	if len(fresh.Warnings()) != 0 {
		t.Errorf("a clean model loaded with warnings: %v", fresh.Warnings())
	}
}

func TestUpdateKeepsCreatedAndBumpsTheRevision(t *testing.T) {
	s, _ := open(t)
	first := mustPut(t, s, host("app", "app.example.com"))
	rev := s.Revision()

	h := host("app", "app.example.com", "www.app.example.com")
	second := mustPut(t, s, h)
	if !second.Header().Created.Equal(first.Header().Created) {
		t.Error("an update rewrote the creation time")
	}
	if s.Revision() <= rev {
		t.Error("the revision did not grow: the renderer would never notice the change")
	}
}

func TestInvalidDocumentIsRefusedAndNothingIsWritten(t *testing.T) {
	s, dirs := open(t)
	h := host("app") // no domains
	_, err := s.Put(h, cli)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
	if _, err := os.Stat(filepath.Join(dirs.ProxyHosts, "app.yaml")); !os.IsNotExist(err) {
		t.Error("a refused document reached the disk")
	}
}

// Two documents answering on the same name would make nginx pick one
// of them silently.
func TestADomainIsServedByOneDocumentOnly(t *testing.T) {
	s, _ := open(t)
	mustPut(t, s, host("app", "app.example.com"))

	if _, err := s.Put(host("other", "www.example.com", "app.example.com"), cli); !errors.Is(err, ErrConflict) {
		t.Errorf("a second host on the same domain: err = %v, want ErrConflict", err)
	}
	if _, err := s.Put(redirect("old", "app.example.com"), cli); !errors.Is(err, ErrConflict) {
		t.Errorf("a redirect on a host's domain: err = %v, want ErrConflict", err)
	}
	// Replacing the host that owns the domain is not a conflict with
	// itself.
	if _, err := s.Put(host("app", "app.example.com", "api.example.com"), cli); err != nil {
		t.Errorf("updating the owner was refused: %v", err)
	}
	// A wildcard and an exact name coexist: nginx prefers the exact one.
	if _, err := s.Put(host("wild", "*.example.com"), cli); err != nil {
		t.Errorf("a wildcard next to an exact name was refused: %v", err)
	}
}

func TestDisabledDocumentsKeepTheirDomainsReserved(t *testing.T) {
	s, _ := open(t)
	h := host("app", "app.example.com")
	h.Enabled = false
	mustPut(t, s, h)
	if _, err := s.Put(host("other", "app.example.com"), cli); !errors.Is(err, ErrConflict) {
		t.Errorf("a disabled host's domain was handed out: err = %v", err)
	}
}

func TestStreamPortsArePerProtocol(t *testing.T) {
	s, _ := open(t)
	mustPut(t, s, stream("dns-tcp", 5353, "tcp"))
	if _, err := s.Put(stream("dns-udp", 5353, "udp"), cli); err != nil {
		t.Errorf("tcp and udp on the same port were refused: %v", err)
	}
	if _, err := s.Put(stream("clash", 5353, "tcp"), cli); !errors.Is(err, ErrConflict) {
		t.Errorf("two tcp streams on one port: err = %v, want ErrConflict", err)
	}
}

func TestHostNeedsAnExistingAccessList(t *testing.T) {
	s, _ := open(t)
	h := host("app", "app.example.com")
	h.AccessList = "staff"
	if _, err := s.Put(h, cli); !errors.Is(err, ErrConflict) {
		t.Fatalf("a host guarded by a missing list: err = %v, want ErrConflict", err)
	}
	mustPut(t, s, acl("staff"))
	if _, err := s.Put(h, cli); err != nil {
		t.Errorf("once the list exists the host was still refused: %v", err)
	}
}

// Deleting a guard still in use would leave its hosts broken or open.
func TestAccessListInUseCannotBeDeleted(t *testing.T) {
	s, _ := open(t)
	mustPut(t, s, acl("staff"))
	h := host("app", "app.example.com")
	h.AccessList = "staff"
	mustPut(t, s, h)

	err := s.Delete(model.KindAccessList, "staff", cli)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
	if !strings.Contains(err.Error(), "app") {
		t.Errorf("error %q does not name the host that uses the list", err)
	}
}

func TestTheFirstUserMustBeAnAdmin(t *testing.T) {
	s, _ := open(t)
	if _, err := s.Put(user("viewer", model.RoleViewer), cli); !errors.Is(err, ErrConflict) {
		t.Errorf("a first user who cannot administer: err = %v, want ErrConflict", err)
	}
	mustPut(t, s, user("ostap", model.RoleAdmin))
	if _, err := s.Put(user("viewer", model.RoleViewer), cli); err != nil {
		t.Errorf("a viewer next to an admin was refused: %v", err)
	}
}

// Without an active admin nobody can create one again from the panel.
func TestTheLastAdminCannotBeRemovedDemotedOrDisabled(t *testing.T) {
	s, _ := open(t)
	mustPut(t, s, user("ostap", model.RoleAdmin))
	mustPut(t, s, user("viewer", model.RoleViewer))

	if err := s.Delete(model.KindUser, "ostap", cli); !errors.Is(err, ErrConflict) {
		t.Errorf("deleting the last admin: err = %v", err)
	}
	if _, err := s.Put(user("ostap", model.RoleOperator), cli); !errors.Is(err, ErrConflict) {
		t.Errorf("demoting the last admin: err = %v", err)
	}
	disabled := user("ostap", model.RoleAdmin)
	disabled.Disabled = true
	if _, err := s.Put(disabled, cli); !errors.Is(err, ErrConflict) {
		t.Errorf("disabling the last admin: err = %v", err)
	}

	mustPut(t, s, user("second", model.RoleAdmin))
	if err := s.Delete(model.KindUser, "ostap", cli); err != nil {
		t.Errorf("with a second admin the first could not be deleted: %v", err)
	}
}

// Deleting the only account, when it is the admin, leaves no users at
// all: technically consistent, and exactly as locked out.
func TestTheOnlyAdminCannotBeDeletedEvenAlone(t *testing.T) {
	s, _ := open(t)
	mustPut(t, s, user("ostap", model.RoleAdmin))
	if err := s.Delete(model.KindUser, "ostap", cli); !errors.Is(err, ErrConflict) {
		t.Errorf("deleting the only user, an admin: err = %v, want ErrConflict", err)
	}
}

func TestProtectedDocumentsStayPut(t *testing.T) {
	s, _ := open(t)
	h := host("panel", "limen.example.com")
	h.Protected = true
	mustPut(t, s, h)

	if err := s.Delete(model.KindProxyHost, "panel", cli); !errors.Is(err, ErrProtected) {
		t.Errorf("deleting the protected host: err = %v, want ErrProtected", err)
	}
	unprotected := host("panel", "limen.example.com")
	if _, err := s.Put(unprotected, cli); !errors.Is(err, ErrProtected) {
		t.Errorf("removing the protection: err = %v, want ErrProtected", err)
	}
	// It can still be edited, as long as it stays protected.
	edited := host("panel", "limen.example.com")
	edited.Protected = true
	edited.Forward.Port = 9187
	if _, err := s.Put(edited, cli); err != nil {
		t.Errorf("editing the protected host was refused: %v", err)
	}
}

func TestHistoryAndRollback(t *testing.T) {
	s, _ := open(t)
	mustPut(t, s, host("app", "app.example.com"))

	v2 := host("app", "app.example.com")
	v2.Forward.Port = 9090
	if _, err := s.Put(v2, Change{Author: "ostap", Source: "panel", Note: "move to 9090"}); err != nil {
		t.Fatal(err)
	}

	revs, err := s.History(model.KindProxyHost, "app")
	if err != nil {
		t.Fatal(err)
	}
	if len(revs) != 1 {
		t.Fatalf("history has %d revisions, want 1", len(revs))
	}
	if revs[0].Author != "ostap" || revs[0].Note != "move to 9090" || revs[0].Action != "update" {
		t.Errorf("revision metadata = %+v", revs[0])
	}

	back, err := s.Rollback(model.KindProxyHost, "app", revs[0].ID, Change{Author: "ostap"})
	if err != nil {
		t.Fatal(err)
	}
	if back.(*model.ProxyHost).Forward.Port != 8080 {
		t.Errorf("after rollback port = %d, want 8080", back.(*model.ProxyHost).Forward.Port)
	}

	// The rollback archived what it replaced: it can be undone too.
	revs, _ = s.History(model.KindProxyHost, "app")
	if len(revs) != 2 {
		t.Fatalf("after a rollback history has %d revisions, want 2", len(revs))
	}
	if revs[0].Source != "rollback" {
		t.Errorf("newest revision source = %q, want rollback", revs[0].Source)
	}
	undo, err := s.Rollback(model.KindProxyHost, "app", revs[0].ID, cli)
	if err != nil {
		t.Fatal(err)
	}
	if undo.(*model.ProxyHost).Forward.Port != 9090 {
		t.Errorf("undoing the rollback gave port %d, want 9090", undo.(*model.ProxyHost).Forward.Port)
	}
}

func TestADeletedDocumentCanBeBroughtBack(t *testing.T) {
	s, _ := open(t)
	orig := mustPut(t, s, host("app", "app.example.com"))
	if err := s.Delete(model.KindProxyHost, "app", cli); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(model.KindProxyHost, "app"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: err = %v, want ErrNotFound", err)
	}

	revs, err := s.History(model.KindProxyHost, "app")
	if err != nil || len(revs) != 1 || revs[0].Action != "delete" {
		t.Fatalf("history after delete = %+v, %v", revs, err)
	}
	back, err := s.Rollback(model.KindProxyHost, "app", revs[0].ID, cli)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Header().Created.Equal(orig.Header().Created) {
		t.Error("the restored host lost its original creation time")
	}
}

// A rollback must not force back a revision that no longer fits: the
// domain it used may have been taken since.
func TestRollbackGoesThroughTheSameChecks(t *testing.T) {
	s, _ := open(t)
	mustPut(t, s, host("app", "app.example.com"))
	if err := s.Delete(model.KindProxyHost, "app", cli); err != nil {
		t.Fatal(err)
	}
	mustPut(t, s, host("newcomer", "app.example.com"))

	revs, _ := s.History(model.KindProxyHost, "app")
	if _, err := s.Rollback(model.KindProxyHost, "app", revs[0].ID, cli); !errors.Is(err, ErrConflict) {
		t.Errorf("rolling back onto a taken domain: err = %v, want ErrConflict", err)
	}
}

func TestRevisionIDsCannotWalkThePath(t *testing.T) {
	s, _ := open(t)
	mustPut(t, s, host("app", "app.example.com"))
	// "../../../hosts/app" resolves, from history/proxy_host/app, to the
	// live hosts/app.yaml: without the check it would be read and
	// "rolled back". The others lead nowhere, and prove less.
	for _, id := range []string{"../../../hosts/app", "../../hosts/app", "..", "", "20260924T101500.000000000Z/../../x"} {
		if _, err := s.Rollback(model.KindProxyHost, "app", id, cli); !errors.Is(err, ErrNotFound) {
			t.Errorf("revision id %q: err = %v, want ErrNotFound", id, err)
		}
	}
	if _, err := s.History(model.KindProxyHost, "../users/ostap"); !errors.Is(err, ErrInvalid) {
		t.Errorf("history of a traversing name: err = %v, want ErrInvalid", err)
	}
}

func TestHistoryIsPruned(t *testing.T) {
	s, _ := open(t)
	s.keep = 3
	for port := 8000; port < 8010; port++ {
		h := host("app", "app.example.com")
		h.Forward.Port = port
		mustPut(t, s, h)
	}
	revs, err := s.History(model.KindProxyHost, "app")
	if err != nil {
		t.Fatal(err)
	}
	if len(revs) != 3 {
		t.Errorf("history keeps %d revisions, want 3", len(revs))
	}
}

// A hand edit made since the last reload is what gets archived, not
// the stale copy in memory: otherwise the edit would be lost for good.
func TestAHandEditIsArchivedBeforeBeingOverwritten(t *testing.T) {
	s, dirs := open(t)
	mustPut(t, s, host("app", "app.example.com"))

	path := filepath.Join(dirs.ProxyHosts, "app.yaml")
	b, _ := os.ReadFile(path)
	edited := strings.Replace(string(b), "port: 8080", "port: 7777", 1)
	if edited == string(b) {
		t.Fatalf("could not simulate the hand edit in:\n%s", b)
	}
	if err := os.WriteFile(path, []byte(edited), 0o640); err != nil {
		t.Fatal(err)
	}

	mustPut(t, s, host("app", "app.example.com"))
	revs, _ := s.History(model.KindProxyHost, "app")
	archived, err := os.ReadFile(filepath.Join(dirs.History, "proxy_host", "app", revs[0].ID+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(archived), "port: 7777") {
		t.Errorf("the archived revision is not the hand edit:\n%s", archived)
	}
}

func write(t *testing.T, dir, file, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, file), []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
}

// One bad hand edit must not take every other host down with it.
func TestLoadSkipsBrokenFilesAndKeepsTheRest(t *testing.T) {
	dirs := Under(t.TempDir())
	write(t, dirs.ProxyHosts, "good.yaml", "kind: proxy_host\nname: good\ndomains: [good.example.com]\nforward: {host: 10.0.0.1, port: 80}\n")
	write(t, dirs.ProxyHosts, "broken.yaml", "kind: proxy_host\nname: broken\ndomains: [\n")
	write(t, dirs.ProxyHosts, "invalid.yaml", "kind: proxy_host\nname: invalid\ndomains: []\nforward: {host: 10.0.0.1, port: 80}\n")
	write(t, dirs.ProxyHosts, "mismatch.yaml", "kind: proxy_host\nname: somebody-else\ndomains: [m.example.com]\nforward: {host: 10.0.0.1, port: 80}\n")
	write(t, dirs.ProxyHosts, "Bad Name.yaml", "kind: proxy_host\n")
	write(t, dirs.ProxyHosts, ".good.yaml.123", "garbage from an interrupted write")
	write(t, dirs.ProxyHosts, "notes.txt", "not a document")

	s, err := Open(dirs)
	if err != nil {
		t.Fatalf("a broken file made the whole load fail: %v", err)
	}
	if s.Counts().ProxyHosts != 1 {
		t.Errorf("loaded %d hosts, want only the good one", s.Counts().ProxyHosts)
	}
	warns := strings.Join(s.Warnings(), "\n")
	for _, want := range []string{"broken.yaml", "invalid.yaml", "mismatch.yaml", "Bad Name.yaml"} {
		if !strings.Contains(warns, want) {
			t.Errorf("no warning about %s in:\n%s", want, warns)
		}
	}
	if strings.Contains(warns, "notes.txt") || strings.Contains(warns, ".good.yaml.123") {
		t.Errorf("non-documents were reported:\n%s", warns)
	}
}

// A host whose guard is missing must not be served at all: serving it
// without the guard would expose what the list was protecting.
func TestLoadFailsClosedOnAMissingAccessList(t *testing.T) {
	dirs := Under(t.TempDir())
	write(t, dirs.ProxyHosts, "admin.yaml", "kind: proxy_host\nname: admin\ndomains: [admin.example.com]\nforward: {host: 10.0.0.1, port: 80}\naccess_list: staff\n")

	s, err := Open(dirs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(model.KindProxyHost, "admin"); !errors.Is(err, ErrNotFound) {
		t.Error("a host whose access list is missing was loaded, and would be served unguarded")
	}
	if !strings.Contains(strings.Join(s.Warnings(), "\n"), "staff") {
		t.Errorf("warnings do not explain why: %v", s.Warnings())
	}
}

func TestLoadResolvesDuplicateDomainsDeterministically(t *testing.T) {
	dirs := Under(t.TempDir())
	write(t, dirs.ProxyHosts, "b.yaml", "kind: proxy_host\nname: b\ndomains: [same.example.com]\nforward: {host: 10.0.0.2, port: 80}\n")
	write(t, dirs.ProxyHosts, "a.yaml", "kind: proxy_host\nname: a\ndomains: [same.example.com]\nforward: {host: 10.0.0.1, port: 80}\n")
	write(t, dirs.Redirects, "r.yaml", "kind: redirect\nname: r\ndomains: [same.example.com]\ntarget: {domain: x.example.org}\n")

	for i := range 3 {
		s, err := Open(dirs)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Get(model.KindProxyHost, "a"); err != nil {
			t.Fatalf("load %d: the first host by name lost the domain", i)
		}
		if s.Counts().ProxyHosts != 1 || s.Counts().Redirects != 0 {
			t.Fatalf("load %d: counts = %+v, want only host a", i, s.Counts())
		}
	}
}

func TestLoadWarnsWhenNoAdminIsLeft(t *testing.T) {
	dirs := Under(t.TempDir())
	write(t, dirs.Users, "viewer.yaml", fmt.Sprintf("kind: user\nname: viewer\nrole: viewer\npassword: %q\n", panelHash))

	s, err := Open(dirs)
	if err != nil {
		t.Fatal(err)
	}
	if s.Counts().Users != 1 {
		t.Error("a user without an admin beside it was dropped; it should only be warned about")
	}
	if !strings.Contains(strings.Join(s.Warnings(), "\n"), "no active admin") {
		t.Errorf("no warning about the missing admin: %v", s.Warnings())
	}
}

func TestReloadPicksUpHandEdits(t *testing.T) {
	s, dirs := open(t)
	write(t, dirs.Streams, "db.yaml", "kind: stream\nname: db\nlisten_port: 5432\nforward: {host: 10.0.0.9, port: 5432}\n")
	if s.Counts().Streams != 0 {
		t.Fatal("the stream was visible before the reload")
	}
	rev := s.Revision()
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if s.Counts().Streams != 1 {
		t.Error("the reload did not pick up the new file")
	}
	if s.Revision() <= rev {
		t.Error("a reload did not bump the revision")
	}
}

func TestGetReturnsACopy(t *testing.T) {
	s, _ := open(t)
	mustPut(t, s, host("app", "app.example.com"))
	doc, _ := s.Get(model.KindProxyHost, "app")
	doc.(*model.ProxyHost).Domains[0] = "hijacked.example.com"

	again, _ := s.Get(model.KindProxyHost, "app")
	if again.(*model.ProxyHost).Domains[0] != "app.example.com" {
		t.Error("mutating a returned document changed the store")
	}
}

func TestConcurrentWritersDoNotRace(t *testing.T) {
	s, _ := open(t)
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("h%02d", i)
			if _, err := s.Put(host(name, name+".example.com"), cli); err != nil {
				t.Error(err)
			}
			s.List(model.KindProxyHost)
			s.Counts()
		}(i)
	}
	wg.Wait()
	if s.Counts().ProxyHosts != 16 {
		t.Errorf("hosts = %d, want 16", s.Counts().ProxyHosts)
	}
}

func TestUserAndAccessListFilesAreOwnerOnly(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("POSIX permissions are not enforced on Windows")
	}
	s, dirs := open(t)
	mustPut(t, s, user("ostap", model.RoleAdmin))
	a := acl("staff")
	a.Users = []model.BasicUser{{Username: "ops", Password: apr1Hash}}
	mustPut(t, s, a)
	for _, p := range []string{filepath.Join(dirs.Users, "ostap.yaml"), filepath.Join(dirs.AccessLists, "staff.yaml")} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s has mode %04o, want 0600: it holds password hashes", p, perm)
		}
	}
}

// Two processes each holding a stale index would both see a domain as
// free and both take it. Locked re-reads the disk first.
func TestLockedSeesWhatAnotherProcessWrote(t *testing.T) {
	first, dirs := open(t)
	second, err := Open(dirs)
	if err != nil {
		t.Fatal(err)
	}
	mustPut(t, second, host("theirs", "shared.example.com"))

	err = first.Locked(func() error {
		_, err := first.Put(host("ours", "shared.example.com"), cli)
		return err
	})
	if !errors.Is(err, ErrConflict) {
		t.Errorf("a write under the lock missed the other process's host: err = %v", err)
	}
}

func TestLockedSerializesWriters(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("flock does not exist on Windows")
	}
	first, dirs := open(t)
	second, err := Open(dirs)
	if err != nil {
		t.Fatal(err)
	}

	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go first.Locked(func() error {
		close(entered)
		<-release
		return nil
	})
	<-entered
	go func() {
		second.Locked(func() error { return nil })
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("a second writer got in while the first held the lock")
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the second writer never got the lock after it was released")
	}
}

// Saving a form without touching it must not fill the history with
// revisions identical to the document, nor bother nginx.
func TestSavingTheSameDocumentChangesNothing(t *testing.T) {
	s, dirs := open(t)
	first := mustPut(t, s, host("app", "app.example.com"))
	rev := s.Revision()
	info, _ := os.Stat(filepath.Join(dirs.ProxyHosts, "app.yaml"))

	again := mustPut(t, s, host("app", "app.example.com"))
	if revs, _ := s.History(model.KindProxyHost, "app"); len(revs) != 0 {
		t.Errorf("an identical save left %d revision(s) in the history", len(revs))
	}
	if s.Revision() != rev {
		t.Error("an identical save bumped the model revision")
	}
	if !again.Header().Updated.Equal(first.Header().Updated) {
		t.Error("an identical save moved the update time")
	}
	if after, _ := os.Stat(filepath.Join(dirs.ProxyHosts, "app.yaml")); !after.ModTime().Equal(info.ModTime()) {
		t.Error("an identical save rewrote the file")
	}

	// A real change still goes through.
	changed := host("app", "app.example.com")
	changed.Websockets = true
	mustPut(t, s, changed)
	if revs, _ := s.History(model.KindProxyHost, "app"); len(revs) != 1 {
		t.Errorf("a real change left %d revision(s), want 1", len(revs))
	}
}
