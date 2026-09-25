// Package api is the REST interface of the panel: sessions, the model,
// applies. The web interface is one of its clients.
//
// Every request is authenticated against a server-side session, and
// the user behind it is read again from the model on every request: a
// user disabled, deleted or demoted from the command line loses those
// rights at their next click, not at the end of their session.
// Every write is protected against cross-site requests three ways — a
// per-session token in a header, the Origin of the request, and a JSON
// body a form cannot send — and goes through the same store, the same
// checks and the same apply as the command line.
package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/acme"
	"github.com/ostap-mykhaylyak/limen/internal/audit"
	"github.com/ostap-mykhaylyak/limen/internal/auth"
	"github.com/ostap-mykhaylyak/limen/internal/config"
	"github.com/ostap-mykhaylyak/limen/internal/metrics"
	"github.com/ostap-mykhaylyak/limen/internal/model"
	"github.com/ostap-mykhaylyak/limen/internal/nginx"
	"github.com/ostap-mykhaylyak/limen/internal/secret"
	"github.com/ostap-mykhaylyak/limen/internal/status"
	"github.com/ostap-mykhaylyak/limen/internal/store"
	"github.com/ostap-mykhaylyak/limen/internal/traffic"
)

// Prefix is where the API is mounted.
const Prefix = "/api/v1"

// maxBody bounds a request body: the largest document is a few KiB.
const maxBody = 1 << 20

// Deps is what the API works with. Apply, Report and LastApply may be
// nil in tests that do not need them.
type Deps struct {
	Store     *store.Store
	Sessions  *auth.Sessions
	Limiter   *auth.Limiter
	Config    func() *config.Config
	Apply     func(dryRun bool) (nginx.Result, error)
	LastApply func() (nginx.Result, bool)
	Report    func() status.Report
	ClientIP  func(*http.Request) string
	Metrics   *metrics.Registry
	Log       *slog.Logger

	// Certificates is the ACME manager; nil where there is none.
	Certificates CertManager

	// Traffic counts what the hosts serve, Nginx reads nginx's own
	// counters; Logs says where the logs are. Any may be missing.
	Traffic *traffic.Collector
	Nginx   *traffic.NginxProbe
	Logs    LogSource
}

// CertManager is what the API needs of the certificate manager.
type CertManager interface {
	Describe(c *model.Certificate) acme.Summary
	Request(name string) error
	Upload(name string, chain, key []byte) (acme.Info, error)
	Removed(name string) error
}

// API serves the REST interface.
type API struct {
	d   Deps
	mux *http.ServeMux

	dummyOnce sync.Once
	dummy     string
}

// role levels, for comparisons.
var levels = map[string]int{model.RoleViewer: 1, model.RoleOperator: 2, model.RoleAdmin: 3}

// principal is who a request is made by.
type principal struct {
	user    *model.User
	session *auth.Session
}

type handler func(w http.ResponseWriter, r *http.Request, p *principal)

// New builds the API.
func New(d Deps) *API {
	if d.ClientIP == nil {
		d.ClientIP = func(r *http.Request) string { return r.RemoteAddr }
	}
	if d.Metrics == nil {
		d.Metrics = metrics.New()
	}
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	a := &API{d: d, mux: http.NewServeMux()}

	a.mux.HandleFunc("POST "+Prefix+"/session", a.login)
	a.route("GET /session", model.RoleViewer, a.whoami)
	a.route("DELETE /session", model.RoleViewer, a.logout)
	a.route("PUT /session/password", model.RoleViewer, a.changePassword)

	a.route("GET /status", model.RoleViewer, a.status)
	a.route("GET /apply", model.RoleViewer, a.lastApply)
	a.route("POST /apply", model.RoleOperator, a.apply)

	for _, c := range collections {
		a.collection(c)
	}
	a.route("POST /certificates/{name}/renew", model.RoleOperator, a.renewCert)
	a.route("POST /certificates/{name}/upload", model.RoleOperator, a.uploadCert)
	a.observeRoutes()
	a.mux.HandleFunc(Prefix+"/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "no such resource")
	})
	return a
}

// ServeHTTP sets the headers every answer carries and dispatches.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	a.mux.ServeHTTP(w, r)
}

func (a *API) route(pattern string, minRole string, h handler) {
	method, path, _ := strings.Cut(pattern, " ")
	a.mux.HandleFunc(method+" "+Prefix+path, func(w http.ResponseWriter, r *http.Request) {
		p, ok := a.authenticate(w, r)
		if !ok {
			return
		}
		audit.From(r.Context()).User = p.user.Name
		if unsafeMethod(r.Method) && !a.sameOrigin(w, r, p) {
			return
		}
		if levels[p.user.Role] < levels[minRole] {
			writeError(w, http.StatusForbidden, fmt.Sprintf("this needs the %s role", minRole))
			return
		}
		h(w, r, p)
	})
}

func unsafeMethod(m string) bool {
	return m != http.MethodGet && m != http.MethodHead && m != http.MethodOptions
}

// ---------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------

// cookieName is __Host- prefixed when the cookie is Secure: the browser
// then refuses it from any subdomain or path, and over plain HTTP.
func (a *API) cookieName() string {
	if a.d.Config().Panel.SecureCookies {
		return "__Host-limen_session"
	}
	return "limen_session"
}

func (a *API) setCookie(w http.ResponseWriter, value string, expires time.Time) {
	c := &http.Cookie{
		Name: a.cookieName(), Value: value, Path: "/",
		HttpOnly: true, Secure: a.d.Config().Panel.SecureCookies,
		SameSite: http.SameSiteStrictMode, Expires: expires,
	}
	if value == "" {
		c.MaxAge = -1
	}
	http.SetCookie(w, c)
}

// authenticate finds the session of a request and the user behind it,
// read fresh from the model.
func (a *API) authenticate(w http.ResponseWriter, r *http.Request) (*principal, bool) {
	c, err := r.Cookie(a.cookieName())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not logged in")
		return nil, false
	}
	sess, ok := a.d.Sessions.Lookup(c.Value)
	if !ok {
		a.setCookie(w, "", time.Time{})
		writeError(w, http.StatusUnauthorized, "the session has expired, log in again")
		return nil, false
	}
	doc, err := a.d.Store.Fresh(model.KindUser, sess.User)
	var u *model.User
	if err == nil {
		u = doc.(*model.User)
	}
	// The user may have been deleted, disabled, or given a new password
	// (from here or from the command line) since the login.
	if u == nil || u.Disabled || auth.PasswordTag(u.Password) != sess.PasswordTag {
		a.d.Sessions.DeleteHash(sess.Hash)
		a.setCookie(w, "", time.Time{})
		writeError(w, http.StatusUnauthorized, "the session is no longer valid, log in again")
		return nil, false
	}
	return &principal{user: u, session: sess}, true
}

// sameOrigin guards every write against cross-site requests.
func (a *API) sameOrigin(w http.ResponseWriter, r *http.Request, p *principal) bool {
	token := r.Header.Get("X-CSRF-Token")
	if p == nil || subtle.ConstantTimeCompare([]byte(token), []byte(p.session.CSRF)) != 1 {
		writeError(w, http.StatusForbidden, "missing or wrong X-CSRF-Token")
		return false
	}
	if !a.originOK(r) {
		writeError(w, http.StatusForbidden, "cross-site request refused")
		return false
	}
	return true
}

// originOK refuses a request a browser says comes from another site.
// Clients that are not browsers send neither header, and still need the
// session and the token.
func (a *API) originOK(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		// Host names only: nginx passes the Host without the port
		// ($host), while a browser's Origin keeps it when the panel is
		// published on a port other than 80 or 443.
		u, err := url.Parse(origin)
		if err != nil || u.Hostname() == "" || !strings.EqualFold(u.Hostname(), hostname(r.Host)) {
			return false
		}
	}
	return true
}

func hostname(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return strings.Trim(hostport, "[]")
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type sessionView struct {
	User      userView  `json:"user"`
	CSRFToken string    `json:"csrf_token"`
	Expires   time.Time `json:"expires"`
}

type userView struct {
	Name     string `json:"name"`
	Role     string `json:"role"`
	Email    string `json:"email,omitempty"`
	FullName string `json:"full_name,omitempty"`
}

func viewOf(u *model.User) userView {
	return userView{Name: u.Name, Role: u.Role, Email: u.Email, FullName: u.FullName}
}

// dummyHash is verified against when the user does not exist, so that
// an unknown name costs the same as a wrong password and the answer
// time does not say which names are real.
func (a *API) dummyHash() string {
	a.dummyOnce.Do(func() {
		a.dummy, _ = secret.HashPanel("limen-no-such-user-timing")
	})
	return a.dummy
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	// No session yet, so no token: the Origin check and the JSON body
	// are what stops a cross-site form from logging a victim in.
	if !a.originOK(r) {
		writeError(w, http.StatusForbidden, "cross-site request refused")
		return
	}
	var req loginRequest
	if !decode(w, r, &req) {
		return
	}
	ip := a.d.ClientIP(r)
	if ok, wait := a.d.Limiter.Allowed(req.Username, ip); !ok {
		w.Header().Set("Retry-After", fmt.Sprint(int(wait.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, "too many failed logins, try again later")
		return
	}

	var u *model.User
	if doc, err := a.d.Store.Fresh(model.KindUser, req.Username); err == nil {
		u = doc.(*model.User)
	}
	hash := a.dummyHash()
	if u != nil && !u.Disabled {
		hash = u.Password
	}
	err := secret.VerifyPanel(hash, req.Password)
	if err != nil || u == nil || u.Disabled {
		a.d.Limiter.Failed(req.Username, ip)
		a.d.Metrics.Login(false)
		a.d.Log.Warn("login failed", "user", req.Username, "client", ip)
		writeError(w, http.StatusUnauthorized, "wrong username or password")
		return
	}
	a.d.Limiter.Succeeded(req.Username)
	a.d.Metrics.Login(true)

	// A hash made with fewer iterations than today's is upgraded now,
	// while the password is at hand.
	if secret.NeedsRehash(u.Password) {
		if fresh, err := secret.HashPanel(req.Password); err == nil {
			u.Password = fresh
			a.d.Store.Locked(func() error {
				_, err := a.d.Store.Put(u, store.Change{Author: "limen", Source: "panel", Note: "password hash upgraded at login"})
				return err
			})
		}
	}

	sess, err := a.d.Sessions.Create(u.Name, u.Password, ip, r.UserAgent())
	if err != nil {
		a.fail(w, err)
		return
	}
	audit.From(r.Context()).User = u.Name
	a.setCookie(w, sess.ID, sess.Expires)
	writeJSON(w, http.StatusOK, sessionView{User: viewOf(u), CSRFToken: sess.CSRF, Expires: sess.Expires})
}

func (a *API) whoami(w http.ResponseWriter, r *http.Request, p *principal) {
	writeJSON(w, http.StatusOK, sessionView{User: viewOf(p.user), CSRFToken: p.session.CSRF, Expires: p.session.Expires})
}

func (a *API) logout(w http.ResponseWriter, r *http.Request, p *principal) {
	a.d.Sessions.DeleteHash(p.session.Hash)
	a.setCookie(w, "", time.Time{})
	w.WriteHeader(http.StatusNoContent)
}

type passwordRequest struct {
	Current string `json:"current"`
	New     string `json:"new"`
}

// changePassword lets a user change their own password. The current one
// is required — a session left open on someone else's screen must not
// be enough to take the account over — and failures count as failed
// logins. Every other session of the user is closed.
func (a *API) changePassword(w http.ResponseWriter, r *http.Request, p *principal) {
	var req passwordRequest
	if !decode(w, r, &req) {
		return
	}
	ip := a.d.ClientIP(r)
	if ok, _ := a.d.Limiter.Allowed(p.user.Name, ip); !ok {
		writeError(w, http.StatusTooManyRequests, "too many failed attempts, try again later")
		return
	}
	if secret.VerifyPanel(p.user.Password, req.Current) != nil {
		a.d.Limiter.Failed(p.user.Name, ip)
		writeError(w, http.StatusForbidden, "the current password is wrong")
		return
	}
	hash, err := secret.HashPanel(req.New)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	err = a.d.Store.Locked(func() error {
		doc, err := a.d.Store.Get(model.KindUser, p.user.Name)
		if err != nil {
			return err
		}
		doc.(*model.User).Password = hash
		_, err = a.d.Store.Put(doc, a.change(r, p, "password changed by its owner"))
		return err
	})
	if err != nil {
		a.fail(w, err)
		return
	}
	a.d.Sessions.DeleteUser(p.user.Name, p.session.Hash)
	// This session carried the old password's tag: open a new one.
	a.d.Sessions.DeleteHash(p.session.Hash)
	sess, err := a.d.Sessions.Create(p.user.Name, hash, ip, r.UserAgent())
	if err != nil {
		a.fail(w, err)
		return
	}
	a.setCookie(w, sess.ID, sess.Expires)
	writeJSON(w, http.StatusOK, sessionView{User: viewOf(p.user), CSRFToken: sess.CSRF, Expires: sess.Expires})
}

// ---------------------------------------------------------------------
// Status and apply
// ---------------------------------------------------------------------

func (a *API) status(w http.ResponseWriter, r *http.Request, p *principal) {
	if a.d.Report == nil {
		writeError(w, http.StatusNotFound, "no status here")
		return
	}
	writeJSON(w, http.StatusOK, a.d.Report())
}

func (a *API) lastApply(w http.ResponseWriter, r *http.Request, p *principal) {
	if a.d.LastApply == nil {
		writeError(w, http.StatusNotFound, "no apply yet")
		return
	}
	res, ok := a.d.LastApply()
	if !ok {
		writeError(w, http.StatusNotFound, "no apply yet")
		return
	}
	writeJSON(w, http.StatusOK, res)
}

type applyRequest struct {
	DryRun bool `json:"dry_run"`
}

func (a *API) apply(w http.ResponseWriter, r *http.Request, p *principal) {
	var req applyRequest
	if r.ContentLength != 0 && !decode(w, r, &req) {
		return
	}
	if a.d.Apply == nil {
		writeError(w, http.StatusServiceUnavailable, "no nginx engine")
		return
	}
	res, err := a.d.Apply(req.DryRun)
	code := http.StatusOK
	if err != nil {
		code = http.StatusConflict
	}
	writeJSON(w, code, res)
}

// ---------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------

func (a *API) change(r *http.Request, p *principal, fallback string) store.Change {
	note := r.Header.Get("X-Limen-Note")
	if len(note) > 500 {
		note = note[:500]
	}
	if note == "" {
		note = fallback
	}
	audit.From(r.Context()).Action = note
	return store.Change{Author: "panel:" + p.user.Name, Source: "panel", Note: note}
}

// decode reads a JSON body strictly: an unknown field is an error, not
// a setting that silently does nothing.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "send application/json")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

// fail maps a store error onto an HTTP answer.
func (a *API) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, store.ErrInvalid):
		writeError(w, http.StatusUnprocessableEntity, err.Error())
	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrProtected):
		writeError(w, http.StatusConflict, err.Error())
	default:
		a.d.Log.Error("api", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "internal error, see limen.log")
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
