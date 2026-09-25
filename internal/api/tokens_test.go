package api

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/model"
	"github.com/ostap-mykhaylyak/limen/internal/store"
)

// mint makes a token from the panel, as a logged-in user would.
func (c *client) mint(name, role string) string {
	c.e.t.Helper()
	r := c.do("POST", "/tokens", map[string]any{"name": name, "role": role, "expires_days": 30, "password": password})
	if r.code != 201 {
		c.e.t.Fatalf("mint %s: %d %s", name, r.code, r.raw)
	}
	return r.body["token"].(string)
}

// bearer is a script: a token, no cookie, no CSRF token, no Origin.
func (e *env) bearer(token, method, path string, body any) reply {
	e.t.Helper()
	return e.do(method, path, body, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+token)
	})
}

func TestAScriptWritesWithAToken(t *testing.T) {
	e := newEnv(t)
	token := e.login("olga").mint("deploy", "")

	r := e.bearer(token, "POST", "/hosts", host("app.example.com", 3000))
	if r.code != 201 {
		t.Fatalf("POST /hosts with a token: %d %s", r.code, r.raw)
	}
	if _, err := e.store.Get(model.KindProxyHost, "app.example.com"); err != nil {
		t.Fatalf("the host was not stored: %v", err)
	}
	// The history says which token made a change: change it again, and
	// read the revision that archived.
	if r := e.bearer(token, "PUT", "/hosts/app.example.com", host("app.example.com", 3001)); r.code != 200 {
		t.Fatalf("PUT with a token: %d %s", r.code, r.raw)
	}
	revs, _ := e.store.History(model.KindProxyHost, "app.example.com")
	if len(revs) == 0 || revs[0].Author != "api:olga:deploy" || revs[0].Source != "api" || revs[0].Note != "changed through the API" {
		t.Errorf("history = %+v, want the author api:olga:deploy", revs)
	}
	if r := e.bearer(token, "POST", "/apply", nil); r.code != 200 {
		t.Errorf("POST /apply with a token: %d %s", r.code, r.raw)
	}
}

func TestATokenNeverExceedsItsUser(t *testing.T) {
	e := newEnv(t)
	alice := e.login("alice")
	viewerToken := alice.mint("read-only", model.RoleViewer)
	if r := e.bearer(viewerToken, "GET", "/hosts", nil); r.code != 200 {
		t.Fatalf("a viewer token reads: %d %s", r.code, r.raw)
	}
	if r := e.bearer(viewerToken, "POST", "/hosts", host("a.example.com", 1)); r.code != 403 {
		t.Errorf("a viewer token of an admin wrote: %d %s", r.code, r.raw)
	}

	// Demote alice: her admin token can now do what an operator can.
	adminToken := alice.mint("admin", model.RoleAdmin)
	if r := e.bearer(adminToken, "GET", "/users", nil); r.code != 200 {
		t.Fatalf("an admin token lists users: %d %s", r.code, r.raw)
	}
	e.putUser("root2", model.RoleAdmin, knownHash(t)) // someone must stay admin
	doc, _ := e.store.Get(model.KindUser, "alice")
	u := doc.(*model.User)
	u.Role = model.RoleOperator
	if _, err := e.store.Put(u, store.Change{Author: "test"}); err != nil {
		t.Fatal(err)
	}
	if r := e.bearer(adminToken, "GET", "/users", nil); r.code != 403 {
		t.Errorf("the admin token of a demoted user still lists users: %d %s", r.code, r.raw)
	}
	if r := e.bearer(adminToken, "POST", "/hosts", host("b.example.com", 1)); r.code != 201 {
		t.Errorf("the token of a demoted user cannot do what its user can: %d %s", r.code, r.raw)
	}

	// Nobody mints a token above their own role.
	r := e.login("olga").do("POST", "/tokens", map[string]any{"name": "up", "role": "admin", "password": password})
	if r.code != 403 {
		t.Errorf("an operator minted an admin token: %d %s", r.code, r.raw)
	}
}

func TestATokenDiesWithItsUser(t *testing.T) {
	e := newEnv(t)
	token := e.login("vic").mint("mine", "")
	if r := e.bearer(token, "GET", "/status", nil); r.code == 401 {
		t.Fatalf("a fresh token: %d %s", r.code, r.raw)
	}

	doc, _ := e.store.Get(model.KindUser, "vic")
	u := doc.(*model.User)
	u.Disabled = true
	e.store.Put(u, store.Change{Author: "test"})
	if r := e.bearer(token, "GET", "/hosts", nil); r.code != 401 {
		t.Errorf("the token of a disabled user: %d %s", r.code, r.raw)
	}

	// Enabled again, the token works again: disabling is a pause.
	u.Disabled = false
	e.store.Put(u, store.Change{Author: "test"})
	if r := e.bearer(token, "GET", "/hosts", nil); r.code != 200 {
		t.Fatalf("the token of a user enabled again: %d %s", r.code, r.raw)
	}

	// Removed from the panel: the tokens go with the user, and rolling
	// the user back does not bring them back.
	alice := e.login("alice")
	if r := alice.do("DELETE", "/users/vic", nil); r.code != 200 {
		t.Fatalf("delete vic: %d %s", r.code, r.raw)
	}
	if len(e.tokens.List()) != 0 {
		t.Errorf("the tokens of a removed user are still there: %+v", e.tokens.List())
	}
	revs, _ := e.store.History(model.KindUser, "vic")
	if r := alice.do("POST", "/users/vic/rollback", map[string]any{"revision": revs[0].ID}); r.code != 200 {
		t.Fatalf("rollback vic: %d %s", r.code, r.raw)
	}
	if r := e.bearer(token, "GET", "/hosts", nil); r.code != 401 {
		t.Errorf("the token of a user rolled back: %d %s", r.code, r.raw)
	}
}

// A user removed by hand, behind limen's back, and made again: the new
// one is someone else, and does not inherit the tokens of the first.
func TestATokenIsBoundToTheUserItWasMadeFor(t *testing.T) {
	e := newEnv(t)
	token := e.login("vic").mint("mine", "")
	fresh := model.NewUser("vic")
	fresh.Role, fresh.Password = model.RoleViewer, knownHash(t)
	fresh.Created = time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	e.store.Delete(model.KindUser, "vic", store.Change{Author: "test"})
	if _, err := e.store.Put(fresh, store.Change{Author: "test"}); err != nil {
		t.Fatal(err)
	}
	if r := e.bearer(token, "GET", "/hosts", nil); r.code != 401 {
		t.Errorf("the token of a user made again: %d %s", r.code, r.raw)
	}
	r := e.login("alice").do("GET", "/tokens", nil)
	if !strings.Contains(r.raw, `"state": "orphaned"`) {
		t.Errorf("the token is not shown as orphaned: %s", r.raw)
	}
}

// What manages credentials is for sessions: a leaked token must not be
// able to open itself another way in.
func TestATokenCannotManageCredentials(t *testing.T) {
	e := newEnv(t)
	token := e.login("alice").mint("admin", model.RoleAdmin)
	user := map[string]any{"name": "mallory", "role": "admin", "password": "pbkdf2-sha256$1$c2FsdA$aGFzaA"}
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/tokens", map[string]any{"name": "more", "password": password}},
		{"GET", "/tokens", nil},
		{"DELETE", "/tokens/admin", nil},
		{"POST", "/users", user},
		{"PUT", "/users/vic", map[string]any{"role": "admin"}},
		{"DELETE", "/users/vic", nil},
		{"POST", "/users/vic/rollback", map[string]any{"revision": "x"}},
		{"PUT", "/session/password", map[string]any{"current": password, "new": "another long password"}},
		{"GET", "/session", nil},
		{"DELETE", "/session", nil},
	} {
		if r := e.bearer(token, c.method, c.path, c.body); r.code != 403 {
			t.Errorf("%s %s with a token: %d %s", c.method, c.path, r.code, r.raw)
		}
	}
	if _, err := e.store.Get(model.KindUser, "mallory"); err == nil {
		t.Error("a token made a user")
	}
	if len(e.tokens.List()) != 1 {
		t.Errorf("tokens = %+v", e.tokens.List())
	}
}

func TestATokenIsJudgedAloneAndWrongOnesAreThrottled(t *testing.T) {
	e := newEnv(t)
	c := e.login("vic")
	token := c.mint("mine", "")

	// An admin's session cookie does not lift a viewer's token.
	admin := e.login("alice")
	r := e.do("POST", "/hosts", host("x.example.com", 1), func(r *http.Request) {
		r.Header.Set("Cookie", admin.cookie)
		r.Header.Set("X-CSRF-Token", admin.csrf)
		r.Header.Set("Authorization", "Bearer "+token)
	})
	if r.code != 403 {
		t.Errorf("a viewer token with an admin cookie wrote: %d %s", r.code, r.raw)
	}
	// A cookie with a wrong token is a wrong token.
	r = e.do("GET", "/hosts", nil, func(r *http.Request) {
		r.Header.Set("Cookie", admin.cookie)
		r.Header.Set("Authorization", "Bearer nonsense")
	})
	if r.code != 401 || !strings.Contains(r.header.Get("WWW-Authenticate"), "invalid_token") {
		t.Errorf("an admin cookie with a wrong token: %d %s %v", r.code, r.raw, r.header)
	}

	id := strings.Split(token, "_")[1]
	for i := range 25 {
		wrong := fmt.Sprintf("limen_%s_%043d", id, i)
		if r := e.bearer(wrong, "GET", "/hosts", nil); r.code != 401 && r.code != 429 {
			t.Fatalf("attempt %d: %d %s", i, r.code, r.raw)
		}
	}
	if r := e.bearer(token, "GET", "/hosts", nil); r.code != 429 || r.header.Get("Retry-After") == "" {
		t.Errorf("after 25 wrong tries the right token is not throttled: %d %s", r.code, r.raw)
	}
}

func TestMintingATokenAsksForThePassword(t *testing.T) {
	e := newEnv(t)
	c := e.login("olga")
	r := c.do("POST", "/tokens", map[string]any{"name": "ci", "password": "not it"})
	if r.code != 403 || len(e.tokens.List()) != 0 {
		t.Fatalf("a token without the password: %d %s", r.code, r.raw)
	}
	for _, days := range []int{-1, maxTokenDays + 1} {
		r = c.do("POST", "/tokens", map[string]any{"name": "ci", "password": password, "expires_days": days})
		if r.code != 422 {
			t.Errorf("expires_days %d: %d %s", days, r.code, r.raw)
		}
	}
	// And without the CSRF token, not at all.
	r = e.do("POST", "/tokens", map[string]any{"name": "ci", "password": password}, func(r *http.Request) {
		r.Header.Set("Cookie", c.cookie)
	})
	if r.code != 403 || len(e.tokens.List()) != 0 {
		t.Errorf("a token minted without the CSRF token: %d %s", r.code, r.raw)
	}

	r = c.do("POST", "/tokens", map[string]any{"name": "ci", "password": password, "expires_days": 0})
	if r.code != 201 {
		t.Fatalf("mint: %d %s", r.code, r.raw)
	}
	item := r.body["item"].(map[string]any)
	if item["role"] != "operator" || item["expires"] != nil || item["state"] != "active" || item["user"] != "olga" {
		t.Errorf("item = %v", item)
	}
	if strings.Contains(r.raw, "hash") {
		t.Errorf("the answer shows a hash: %s", r.raw)
	}
}

func TestEverybodyManagesTheirOwnTokensAndAdminsAll(t *testing.T) {
	e := newEnv(t)
	olga, vic, alice := e.login("olga"), e.login("vic"), e.login("alice")
	olga.mint("olga-ci", "")
	vicToken := vic.mint("vic-ci", "")

	names := func(c *client) string {
		r := c.do("GET", "/tokens", nil)
		var out []string
		for _, it := range r.body["items"].([]any) {
			out = append(out, it.(map[string]any)["name"].(string))
		}
		return strings.Join(out, ",")
	}
	if got := names(olga); got != "olga-ci" {
		t.Errorf("olga sees %s", got)
	}
	if got := names(alice); got != "olga-ci,vic-ci" {
		t.Errorf("the admin sees %s", got)
	}
	if r := olga.do("DELETE", "/tokens/vic-ci", nil); r.code != 404 {
		t.Errorf("olga revoked vic's token: %d %s", r.code, r.raw)
	}
	if r := alice.do("DELETE", "/tokens/vic-ci", nil); r.code != 204 {
		t.Errorf("the admin could not revoke vic's token: %d %s", r.code, r.raw)
	}
	if r := e.bearer(vicToken, "GET", "/hosts", nil); r.code != 401 {
		t.Errorf("a revoked token still works: %d %s", r.code, r.raw)
	}
	if r := olga.do("DELETE", "/tokens/olga-ci", nil); r.code != 204 {
		t.Errorf("olga could not revoke her own token: %d %s", r.code, r.raw)
	}
}
