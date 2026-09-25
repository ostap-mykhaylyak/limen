package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/auth"
	"github.com/ostap-mykhaylyak/limen/internal/config"
	"github.com/ostap-mykhaylyak/limen/internal/model"
	"github.com/ostap-mykhaylyak/limen/internal/nginx"
	"github.com/ostap-mykhaylyak/limen/internal/secret"
	"github.com/ostap-mykhaylyak/limen/internal/store"
)

const password = "correct horse battery"

var (
	hashOnce sync.Once
	pwHash   string
)

// knownHash is the hash of password, computed once: 600 000 PBKDF2
// rounds per user would make the suite crawl.
func knownHash(t *testing.T) string {
	hashOnce.Do(func() {
		var err error
		if pwHash, err = secret.HashPanel(password); err != nil {
			t.Fatal(err)
		}
	})
	return pwHash
}

type env struct {
	t        *testing.T
	api      *API
	store    *store.Store
	sessions *auth.Sessions
	tokens   *auth.Tokens
	dir      string
	cfg      *config.Config
	applies  int
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(store.Under(filepath.Join(dir, "model")))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, store: s, dir: dir, cfg: config.Default()}
	e.sessions, err = auth.OpenSessions(filepath.Join(dir, "sessions.json"), func() time.Duration { return e.cfg.Panel.SessionTTL.Std() })
	if err != nil {
		t.Fatal(err)
	}
	e.tokens, err = auth.OpenTokens(filepath.Join(dir, "tokens.json"), filepath.Join(dir, ".tokens.lock"))
	if err != nil {
		t.Fatal(err)
	}
	e.api = e.build()
	for _, u := range []struct{ name, role string }{{"alice", model.RoleAdmin}, {"olga", model.RoleOperator}, {"vic", model.RoleViewer}} {
		e.putUser(u.name, u.role, knownHash(t))
	}
	return e
}

func (e *env) build() *API {
	return New(Deps{
		Store:    e.store,
		Sessions: e.sessions,
		Tokens:   e.tokens,
		Limiter:  auth.NewLimiter(),
		Config:   func() *config.Config { return e.cfg },
		Apply: func(bool) (nginx.Result, error) {
			e.applies++
			return nginx.Result{Changed: true, Generation: "test"}, nil
		},
		ClientIP: func(r *http.Request) string { return "203.0.113.9" },
	})
}

func (e *env) putUser(name, role, hash string) {
	e.t.Helper()
	u := model.NewUser(name)
	u.Role, u.Password = role, hash
	if _, err := e.store.Put(u, store.Change{Author: "test"}); err != nil {
		e.t.Fatal(err)
	}
}

// client is a logged-in browser: a cookie and a CSRF token.
type client struct {
	e      *env
	cookie string
	csrf   string
}

type reply struct {
	code   int
	header http.Header
	body   map[string]any
	raw    string
}

func (e *env) do(method, path string, body any, set func(*http.Request)) reply {
	e.t.Helper()
	var rd *bytes.Reader
	switch b := body.(type) {
	case nil:
		rd = bytes.NewReader(nil)
	case string:
		rd = bytes.NewReader([]byte(b))
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	r := httptest.NewRequest(method, "http://limen.example.com"+Prefix+path, rd)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if set != nil {
		set(r)
	}
	w := httptest.NewRecorder()
	e.api.ServeHTTP(w, r)
	out := reply{code: w.Code, header: w.Header(), raw: w.Body.String()}
	json.Unmarshal(w.Body.Bytes(), &out.body)
	return out
}

func (e *env) login(user string) *client {
	e.t.Helper()
	r := e.do("POST", "/session", map[string]string{"username": user, "password": password}, nil)
	if r.code != 200 {
		e.t.Fatalf("login %s: %d %s", user, r.code, r.raw)
	}
	c := &client{e: e, csrf: r.body["csrf_token"].(string)}
	for _, ck := range (&http.Response{Header: r.header}).Cookies() {
		if strings.Contains(ck.Name, "limen_session") {
			c.cookie = ck.Name + "=" + ck.Value
		}
	}
	return c
}

func (c *client) do(method, path string, body any) reply {
	c.e.t.Helper()
	return c.e.do(method, path, body, func(r *http.Request) {
		r.Header.Set("Cookie", c.cookie)
		if method != "GET" {
			r.Header.Set("X-CSRF-Token", c.csrf)
		}
	})
}

func host(domain string, port int) map[string]any {
	return map[string]any{
		"domains": []string{domain},
		"forward": map[string]any{"scheme": "http", "host": "10.0.0.5", "port": port},
	}
}

// ---------------------------------------------------------------------

func TestLoginSetsAHardenedCookie(t *testing.T) {
	e := newEnv(t)
	r := e.do("POST", "/session", map[string]string{"username": "alice", "password": password}, nil)
	if r.code != 200 {
		t.Fatalf("login: %d %s", r.code, r.raw)
	}
	cookies := (&http.Response{Header: r.header}).Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %v", cookies)
	}
	c := cookies[0]
	// __Host-: the browser refuses it from a subdomain, another path, or
	// plain HTTP.
	if c.Name != "__Host-limen_session" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Errorf("cookie = %+v", c)
	}
	if r.body["csrf_token"] == "" || r.body["user"].(map[string]any)["role"] != "admin" {
		t.Errorf("body = %s", r.raw)
	}
}

// The answer must not say which usernames exist.
func TestWrongPasswordAndUnknownUserLookTheSame(t *testing.T) {
	e := newEnv(t)
	a := e.do("POST", "/session", map[string]string{"username": "alice", "password": "wrong password!"}, nil)
	b := e.do("POST", "/session", map[string]string{"username": "nobody", "password": "wrong password!"}, nil)
	if a.code != 401 || b.code != 401 || a.raw != b.raw {
		t.Errorf("wrong password: %d %s / unknown user: %d %s", a.code, a.raw, b.code, b.raw)
	}
}

func TestDisabledUserCannotLogIn(t *testing.T) {
	e := newEnv(t)
	u, _ := e.store.Get(model.KindUser, "vic")
	u.(*model.User).Disabled = true
	e.store.Put(u, store.Change{})
	if r := e.do("POST", "/session", map[string]string{"username": "vic", "password": password}, nil); r.code != 401 {
		t.Errorf("a disabled user logged in: %d", r.code)
	}
}

func TestRepeatedFailuresAreThrottled(t *testing.T) {
	e := newEnv(t)
	for range 5 {
		e.do("POST", "/session", map[string]string{"username": "alice", "password": "nope nope nope"}, nil)
	}
	r := e.do("POST", "/session", map[string]string{"username": "alice", "password": password}, nil)
	if r.code != http.StatusTooManyRequests || r.header.Get("Retry-After") == "" {
		t.Errorf("sixth attempt, right password: %d Retry-After=%q, want 429", r.code, r.header.Get("Retry-After"))
	}
}

func TestEveryWriteNeedsTheTokenTheOriginAndJSON(t *testing.T) {
	e := newEnv(t)
	c := e.login("alice")
	body, _ := json.Marshal(host("app.example.com", 80))

	cases := []struct {
		name string
		set  func(*http.Request)
		want int
	}{
		{"no token", func(r *http.Request) { r.Header.Set("Cookie", c.cookie) }, 403},
		{"wrong token", func(r *http.Request) {
			r.Header.Set("Cookie", c.cookie)
			r.Header.Set("X-CSRF-Token", "guess")
		}, 403},
		{"cross-site origin", func(r *http.Request) {
			r.Header.Set("Cookie", c.cookie)
			r.Header.Set("X-CSRF-Token", c.csrf)
			r.Header.Set("Origin", "https://evil.example.org")
		}, 403},
		{"cross-site fetch", func(r *http.Request) {
			r.Header.Set("Cookie", c.cookie)
			r.Header.Set("X-CSRF-Token", c.csrf)
			r.Header.Set("Sec-Fetch-Site", "cross-site")
		}, 403},
		{"form body", func(r *http.Request) {
			r.Header.Set("Cookie", c.cookie)
			r.Header.Set("X-CSRF-Token", c.csrf)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}, 415},
		{"everything right", func(r *http.Request) {
			r.Header.Set("Cookie", c.cookie)
			r.Header.Set("X-CSRF-Token", c.csrf)
			r.Header.Set("Origin", "http://limen.example.com")
			r.Header.Set("Sec-Fetch-Site", "same-origin")
		}, 201},
	}
	for _, tc := range cases {
		r := e.do("POST", "/hosts", string(body), tc.set)
		if r.code != tc.want {
			t.Errorf("%s: %d %s, want %d", tc.name, r.code, r.raw, tc.want)
		}
	}
}

// A login form on another site must not log a victim into the panel.
func TestLoginRefusesCrossSiteRequests(t *testing.T) {
	e := newEnv(t)
	r := e.do("POST", "/session", map[string]string{"username": "alice", "password": password}, func(r *http.Request) {
		r.Header.Set("Origin", "https://evil.example.org")
	})
	if r.code != 403 {
		t.Errorf("cross-site login: %d", r.code)
	}
}

func TestRoles(t *testing.T) {
	e := newEnv(t)
	viewer, operator, admin := e.login("vic"), e.login("olga"), e.login("alice")

	checks := []struct {
		who  *client
		name string
		meth string
		path string
		body any
		want int
	}{
		{viewer, "viewer reads hosts", "GET", "/hosts", nil, 200},
		{viewer, "viewer writes a host", "POST", "/hosts", host("v.example.com", 80), 403},
		{viewer, "viewer lists users", "GET", "/users", nil, 403},
		{viewer, "viewer applies", "POST", "/apply", map[string]any{}, 403},
		{operator, "operator writes a host", "POST", "/hosts", host("o.example.com", 80), 201},
		{operator, "operator creates a user", "POST", "/users", map[string]any{"name": "x", "role": "admin", "password": password}, 403},
		{admin, "admin creates a user", "POST", "/users", map[string]any{"name": "newbie", "role": "viewer", "password": password}, 201},
	}
	for _, c := range checks {
		if r := c.who.do(c.meth, c.path, c.body); r.code != c.want {
			t.Errorf("%s: %d %s, want %d", c.name, r.code, r.raw, c.want)
		}
	}
}

func TestHostLifecycle(t *testing.T) {
	e := newEnv(t)
	c := e.login("olga")

	body := host("app.example.com", 8080)
	body["websockets"] = true
	r := c.do("POST", "/hosts", body)
	if r.code != 201 {
		t.Fatalf("create: %d %s", r.code, r.raw)
	}
	item := r.body["item"].(map[string]any)
	if item["name"] != "app.example.com" || item["websockets"] != true {
		t.Errorf("created = %v", item)
	}
	if r.body["apply"] == nil || e.applies != 1 {
		t.Errorf("the write was not applied: %s", r.raw)
	}

	// GET returns what PUT accepts: the round trip must not trip over
	// the read-only fields.
	got := c.do("GET", "/hosts/app.example.com", nil)
	got.body["forward"].(map[string]any)["port"] = 9090
	delete(got.body, "websockets") // a full replacement: back to the default
	r = c.do("PUT", "/hosts/app.example.com", got.body)
	if r.code != 200 {
		t.Fatalf("replace: %d %s", r.code, r.raw)
	}
	item = r.body["item"].(map[string]any)
	if item["forward"].(map[string]any)["port"].(float64) != 9090 || item["websockets"] != false {
		t.Errorf("replaced = %v", item)
	}

	hist := c.do("GET", "/hosts/app.example.com/history", nil)
	revs := hist.body["items"].([]any)
	if len(revs) != 1 || revs[0].(map[string]any)["author"] != "panel:olga" {
		t.Fatalf("history = %s", hist.raw)
	}
	r = c.do("POST", "/hosts/app.example.com/rollback", map[string]string{"revision": revs[0].(map[string]any)["id"].(string)})
	if r.code != 200 || r.body["item"].(map[string]any)["forward"].(map[string]any)["port"].(float64) != 8080 {
		t.Errorf("rollback: %d %s", r.code, r.raw)
	}

	if r := c.do("DELETE", "/hosts/app.example.com", nil); r.code != 200 {
		t.Errorf("delete: %d %s", r.code, r.raw)
	}
	if r := c.do("GET", "/hosts/app.example.com", nil); r.code != 404 {
		t.Errorf("after delete: %d", r.code)
	}
}

func TestBodiesAreStrict(t *testing.T) {
	e := newEnv(t)
	c := e.login("olga")
	c.do("POST", "/hosts", host("app.example.com", 80))

	typo := host("typo.example.com", 80)
	typo["acess_list"] = "staff"
	if r := c.do("POST", "/hosts", typo); r.code != 422 || !strings.Contains(r.raw, "acess_list") {
		t.Errorf("unknown field: %d %s", r.code, r.raw)
	}
	renamed := host("app.example.com", 80)
	renamed["name"] = "other"
	if r := c.do("PUT", "/hosts/app.example.com", renamed); r.code != 422 {
		t.Errorf("rename through PUT: %d %s", r.code, r.raw)
	}
	if r := c.do("POST", "/hosts", host("app.example.com", 81)); r.code != 409 {
		t.Errorf("create over an existing one: %d %s", r.code, r.raw)
	}
	dup := host("dup.example.com", 80)
	dup["domains"] = []string{"app.example.com"}
	dup["name"] = "dup"
	if r := c.do("POST", "/hosts", dup); r.code != 409 {
		t.Errorf("a domain served twice: %d %s", r.code, r.raw)
	}
}

// An operator must not be able to publish a local socket — Docker's,
// say — through nginx: that would be root on the machine.
func TestForwardSocketIsRefused(t *testing.T) {
	e := newEnv(t)
	c := e.login("alice")
	b := host("sock.example.com", 80)
	b["forward"] = map[string]any{"scheme": "http", "socket": "/var/run/docker.sock"}
	if r := c.do("POST", "/hosts", b); r.code != 422 || !strings.Contains(r.raw, "socket") {
		t.Errorf("socket forward: %d %s", r.code, r.raw)
	}
}

func TestProtectedDocumentsAreReadOnlyHere(t *testing.T) {
	e := newEnv(t)
	panelHost := model.NewProxyHost("limen-panel")
	panelHost.Protected = true
	panelHost.Domains = []string{"limen.example.com"}
	panelHost.Forward = model.Upstream{Scheme: "http", Host: "127.0.0.1", Port: 9187}
	e.store.Put(panelHost, store.Change{})

	c := e.login("alice")
	got := c.do("GET", "/hosts/limen-panel", nil)
	if r := c.do("PUT", "/hosts/limen-panel", got.body); r.code != 409 {
		t.Errorf("PUT on the panel host: %d %s", r.code, r.raw)
	}
	if r := c.do("DELETE", "/hosts/limen-panel", nil); r.code != 409 {
		t.Errorf("DELETE of the panel host: %d %s", r.code, r.raw)
	}
	// And a body cannot make a document protected.
	b := host("p.example.com", 80)
	b["protected"] = true
	r := c.do("POST", "/hosts", b)
	if r.code != 201 || r.body["item"].(map[string]any)["protected"] == true {
		t.Errorf("a request made a document protected: %s", r.raw)
	}
}

func TestHashesNeverLeave(t *testing.T) {
	e := newEnv(t)
	c := e.login("alice")
	c.do("POST", "/access-lists", map[string]any{"name": "staff", "users": []map[string]string{{"username": "ops", "password": "gate-password"}}})
	for _, path := range []string{"/users", "/users/alice", "/access-lists", "/access-lists/staff", "/session"} {
		r := c.do("GET", path, nil)
		if strings.Contains(r.raw, "pbkdf2") || strings.Contains(r.raw, "$apr1$") || strings.Contains(r.raw, `"password"`) {
			t.Errorf("GET %s leaks a hash:\n%s", path, r.raw)
		}
	}
}

func TestAccessListUsersKeepTheirPasswordUnlessGivenOne(t *testing.T) {
	e := newEnv(t)
	c := e.login("olga")
	r := c.do("POST", "/access-lists", map[string]any{"name": "staff", "users": []map[string]string{{"username": "ops", "password": "gate-password"}}})
	if r.code != 201 {
		t.Fatalf("create: %d %s", r.code, r.raw)
	}
	before, _ := e.store.Get(model.KindAccessList, "staff")

	// The body a client gets back has no passwords: sending it back
	// must keep them, not wipe them.
	got := c.do("GET", "/access-lists/staff", nil)
	got.body["rules"] = []map[string]string{{"action": "allow", "address": "10.0.0.0/8"}}
	if r := c.do("PUT", "/access-lists/staff", got.body); r.code != 200 {
		t.Fatalf("replace: %d %s", r.code, r.raw)
	}
	after, _ := e.store.Get(model.KindAccessList, "staff")
	if after.(*model.AccessList).Users[0].Password != before.(*model.AccessList).Users[0].Password {
		t.Error("a PUT without passwords changed a user's password")
	}

	got.body["users"] = []map[string]string{{"username": "ops"}, {"username": "newcomer"}}
	if r := c.do("PUT", "/access-lists/staff", got.body); r.code != 422 || !strings.Contains(r.raw, "newcomer") {
		t.Errorf("a new user without a password: %d %s", r.code, r.raw)
	}
}

// A password changed from the command line must end the sessions opened
// with the old one; a disabled user must be out at the next click; a
// demotion must bite at once.
func TestSessionsFollowTheUser(t *testing.T) {
	e := newEnv(t)

	c := e.login("olga")
	fresh, _ := secret.HashPanel("another long password")
	e.putUser("olga", model.RoleOperator, fresh)
	if r := c.do("GET", "/hosts", nil); r.code != 401 {
		t.Errorf("after a password change elsewhere: %d, want 401", r.code)
	}

	c = e.login("vic")
	u, _ := e.store.Get(model.KindUser, "vic")
	u.(*model.User).Disabled = true
	e.store.Put(u, store.Change{})
	if r := c.do("GET", "/hosts", nil); r.code != 401 {
		t.Errorf("after being disabled: %d, want 401", r.code)
	}

	e.putUser("dan", model.RoleOperator, knownHash(t))
	c = e.login("dan")
	if r := c.do("POST", "/hosts", host("d.example.com", 80)); r.code != 201 {
		t.Fatalf("as operator: %d", r.code)
	}
	e.putUser("dan", model.RoleViewer, knownHash(t))
	if r := c.do("POST", "/hosts", host("d2.example.com", 80)); r.code != 403 {
		t.Errorf("after a demotion: %d, want 403", r.code)
	}
}

func TestChangingOwnPassword(t *testing.T) {
	e := newEnv(t)
	here, elsewhere := e.login("olga"), e.login("olga")

	if r := here.do("PUT", "/session/password", map[string]string{"current": "wrong wrong wrong", "new": "a brand new password"}); r.code != 403 {
		t.Errorf("wrong current password: %d", r.code)
	}
	r := here.do("PUT", "/session/password", map[string]string{"current": password, "new": "a brand new password"})
	if r.code != 200 {
		t.Fatalf("change: %d %s", r.code, r.raw)
	}
	for _, ck := range (&http.Response{Header: r.header}).Cookies() {
		here.cookie = ck.Name + "=" + ck.Value
	}
	here.csrf = r.body["csrf_token"].(string)

	if r := here.do("GET", "/session", nil); r.code != 200 {
		t.Errorf("the session that changed the password was logged out: %d", r.code)
	}
	if r := elsewhere.do("GET", "/session", nil); r.code != 401 {
		t.Errorf("another session survived the password change: %d", r.code)
	}
	if r := e.do("POST", "/session", map[string]string{"username": "olga", "password": "a brand new password"}, nil); r.code != 200 {
		t.Errorf("the new password does not work: %d", r.code)
	}
}

func TestLogout(t *testing.T) {
	e := newEnv(t)
	c := e.login("alice")
	if r := c.do("DELETE", "/session", nil); r.code != 204 {
		t.Fatalf("logout: %d", r.code)
	}
	if r := c.do("GET", "/session", nil); r.code != 401 {
		t.Errorf("after logout: %d", r.code)
	}
}

// A restart must not log everyone out — and the file that makes that
// possible must not contain anything that opens a session.
func TestSessionsSurviveARestartAndTheFileHoldsNoSecret(t *testing.T) {
	e := newEnv(t)
	c := e.login("alice")

	raw, err := os.ReadFile(filepath.Join(e.dir, "sessions.json"))
	if err != nil {
		t.Fatal(err)
	}
	id := strings.SplitN(c.cookie, "=", 2)[1]
	if strings.Contains(string(raw), id) {
		t.Fatal("the sessions file holds the session id itself")
	}

	e.sessions, err = auth.OpenSessions(filepath.Join(e.dir, "sessions.json"), func() time.Duration { return time.Hour })
	if err != nil {
		t.Fatal(err)
	}
	e.api = e.build()
	if r := c.do("GET", "/session", nil); r.code != 200 {
		t.Errorf("after a restart: %d", r.code)
	}
}

func TestExpiredSessionIsRefused(t *testing.T) {
	e := newEnv(t)
	e.cfg.Panel.SessionTTL = config.Duration(20 * time.Millisecond)
	c := e.login("alice")
	time.Sleep(40 * time.Millisecond)
	if r := c.do("GET", "/session", nil); r.code != 401 {
		t.Errorf("an expired session: %d", r.code)
	}
}

func TestTheLastAdminIsDefendedHereToo(t *testing.T) {
	e := newEnv(t)
	c := e.login("alice")
	if r := c.do("DELETE", "/users/alice", nil); r.code != 409 {
		t.Errorf("deleting the only admin: %d %s", r.code, r.raw)
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t)
	r := e.do("GET", "/session", nil, nil)
	for k, want := range map[string]string{
		"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
	} {
		if got := r.header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if r.code != 401 {
		t.Errorf("unauthenticated whoami: %d", r.code)
	}
}

// The daemon's index is refreshed by a SIGHUP the command line sends
// after writing; a request can arrive before it is processed. Who a
// request is made by must come from the disk, not from that index.
func TestAuthenticationDoesNotWaitForAReload(t *testing.T) {
	e := newEnv(t)
	c := e.login("vic")

	// Another process (the command line) disables vic: the file
	// changes, this store's index does not.
	other, err := store.Open(store.Under(filepath.Join(e.dir, "model")))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := other.Get(model.KindUser, "vic")
	u.(*model.User).Disabled = true
	if _, err := other.Put(u, store.Change{}); err != nil {
		t.Fatal(err)
	}
	if doc, _ := e.store.Get(model.KindUser, "vic"); doc.(*model.User).Disabled {
		t.Fatal("setup: the index already knows")
	}
	if r := c.do("GET", "/hosts", nil); r.code != 401 {
		t.Errorf("a user disabled on disk still got in: %d", r.code)
	}
}

// Raising the cost of the hash must reach existing users too: their
// hash is upgraded at the next login, while the password is at hand.
func TestLoginUpgradesAWeakerHash(t *testing.T) {
	e := newEnv(t)
	restore := secret.SetIterationsForTesting(500)
	weak, err := secret.HashPanel(password)
	restore()
	secret.SetIterationsForTesting(1000)
	if err != nil {
		t.Fatal(err)
	}
	e.putUser("olga", model.RoleOperator, weak)

	e.login("olga")
	doc, _ := e.store.Get(model.KindUser, "olga")
	got := doc.(*model.User).Password
	if !strings.HasPrefix(got, "pbkdf2-sha256$1000$") {
		t.Errorf("hash after login = %s, want it upgraded to the current cost", got[:24])
	}
	if secret.VerifyPanel(got, password) != nil {
		t.Error("the upgraded hash does not verify the password")
	}
}

// nginx hands the panel "Host: limen.example.com"; a browser on a
// non-standard port sends "Origin: https://limen.example.com:8443".
// That is the same site, and a login from it must work.
func TestOriginOnAnotherPortOfTheSameHost(t *testing.T) {
	e := newEnv(t)
	r := e.do("POST", "/session", map[string]string{"username": "alice", "password": password}, func(r *http.Request) {
		r.Header.Set("Origin", "https://limen.example.com:8443")
	})
	if r.code != 200 {
		t.Errorf("same host, other port: %d %s", r.code, r.raw)
	}
	r = e.do("POST", "/session", map[string]string{"username": "alice", "password": password}, func(r *http.Request) {
		r.Header.Set("Origin", "https://limen.example.com.evil.org")
	})
	if r.code != 403 {
		t.Errorf("a look-alike host: %d", r.code)
	}
}
