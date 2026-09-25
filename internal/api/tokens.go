package api

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/audit"
	"github.com/ostap-mykhaylyak/limen/internal/auth"
	"github.com/ostap-mykhaylyak/limen/internal/model"
	"github.com/ostap-mykhaylyak/limen/internal/secret"
)

// API tokens are managed with a session only: a token cannot list,
// make or revoke tokens. Everybody manages their own; an admin sees and
// revokes everybody's, but makes tokens only for themselves — a token
// for someone else is made on the command line.

// maxTokenDays bounds the lifetime asked of the panel; "never" is 0.
const maxTokenDays = 3650

func (a *API) tokenRoutes() {
	a.sessionRoute("GET /tokens", model.RoleViewer, a.listTokens)
	a.sessionRoute("POST /tokens", model.RoleViewer, a.createToken)
	a.sessionRoute("DELETE /tokens/{name}", model.RoleViewer, a.deleteToken)
}

// tokenView is a token as the API shows it: never its hash.
type tokenView struct {
	Name        string     `json:"name"`
	ID          string     `json:"id"`
	User        string     `json:"user"`
	Role        string     `json:"role"`
	Description string     `json:"description,omitempty"`
	Created     time.Time  `json:"created"`
	CreatedBy   string     `json:"created_by,omitempty"`
	Expires     *time.Time `json:"expires,omitempty"`
	LastUsed    *time.Time `json:"last_used,omitempty"`
	LastClient  string     `json:"last_client,omitempty"`
	// State is "active", "expired" or "orphaned" (its user is gone,
	// disabled, or another user of the same name).
	State string `json:"state"`
}

func (a *API) tokenView(t auth.Token) tokenView {
	v := tokenView{
		Name: t.Name, ID: t.ID, User: t.User, Role: t.Role, Description: t.Description,
		Created: t.Created, CreatedBy: t.CreatedBy, LastClient: t.LastClient, State: "active",
	}
	if !t.Expires.IsZero() {
		v.Expires = &t.Expires
	}
	if !t.LastUsed.IsZero() {
		v.LastUsed = &t.LastUsed
	}
	doc, err := a.d.Store.Get(model.KindUser, t.User)
	switch {
	case err != nil || doc.(*model.User).Disabled || !doc.Header().Created.Equal(t.UserCreated):
		v.State = "orphaned"
	case t.Expired(time.Now()):
		v.State = "expired"
	}
	return v
}

func (a *API) tokensOn(w http.ResponseWriter) bool {
	if a.d.Tokens == nil {
		writeError(w, http.StatusNotFound, "API tokens are not enabled here")
		return false
	}
	return true
}

func (a *API) listTokens(w http.ResponseWriter, r *http.Request, p *principal) {
	if !a.tokensOn(w) {
		return
	}
	items := []tokenView{}
	for _, t := range a.d.Tokens.List() {
		if t.User == p.user.Name || p.user.Role == model.RoleAdmin {
			items = append(items, a.tokenView(t))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type tokenRequest struct {
	Name        string `json:"name"`
	Role        string `json:"role"`
	Description string `json:"description"`
	// ExpiresDays is the lifetime in days; 0 is for ever.
	ExpiresDays int `json:"expires_days"`
	// Password is the user's own: a session left open on someone
	// else's screen must not be enough to mint a lasting key.
	Password string `json:"password"`
}

type tokenCreated struct {
	// Token is the secret, shown this once.
	Token string    `json:"token"`
	Item  tokenView `json:"item"`
}

func (a *API) createToken(w http.ResponseWriter, r *http.Request, p *principal) {
	if !a.tokensOn(w) {
		return
	}
	var req tokenRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Role == "" {
		req.Role = p.user.Role
	}
	if _, ok := levels[req.Role]; !ok {
		writeError(w, http.StatusUnprocessableEntity, fmt.Sprintf("role %q: want admin, operator or viewer", req.Role))
		return
	}
	if levels[req.Role] > levels[p.user.Role] {
		writeError(w, http.StatusForbidden, fmt.Sprintf("a token cannot have more than your role (%s)", p.user.Role))
		return
	}
	if req.ExpiresDays < 0 || req.ExpiresDays > maxTokenDays {
		writeError(w, http.StatusUnprocessableEntity, fmt.Sprintf("expires_days: from 1 to %d, or 0 for a token that never expires", maxTokenDays))
		return
	}

	ip := a.d.ClientIP(r)
	if ok, _ := a.d.Limiter.Allowed(p.user.Name, ip); !ok {
		writeError(w, http.StatusTooManyRequests, "too many failed attempts, try again later")
		return
	}
	if secret.VerifyPanel(p.user.Password, req.Password) != nil {
		a.d.Limiter.Failed(p.user.Name, ip)
		writeError(w, http.StatusForbidden, "the password is wrong")
		return
	}

	token, t, err := a.d.Tokens.Create(auth.TokenSpec{
		Name: req.Name, User: p.user.Name, UserCreated: p.user.Created, Role: req.Role,
		Description: req.Description, CreatedBy: "panel:" + p.user.Name,
		TTL: time.Duration(req.ExpiresDays) * 24 * time.Hour,
	})
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	audit.From(r.Context()).Action = "API token " + t.Name + " created"
	a.d.Log.Info("API token created", "token", t.Name, "user", t.User, "role", t.Role, "by", p.who())
	writeJSON(w, http.StatusCreated, tokenCreated{Token: token, Item: a.tokenView(t)})
}

func (a *API) deleteToken(w http.ResponseWriter, r *http.Request, p *principal) {
	if !a.tokensOn(w) {
		return
	}
	name := r.PathValue("name")
	t, err := a.d.Tokens.Get(name)
	// Someone else's token is not found, rather than forbidden: its name
	// is not the business of a user who cannot revoke it.
	if err != nil || (t.User != p.user.Name && p.user.Role != model.RoleAdmin) {
		writeError(w, http.StatusNotFound, fmt.Sprintf("token %q: not found", name))
		return
	}
	if _, err := a.d.Tokens.Delete(name); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, fmt.Sprintf("token %q: not found", name))
			return
		}
		a.fail(w, err)
		return
	}
	audit.From(r.Context()).Action = "API token " + name + " revoked"
	a.d.Log.Info("API token revoked", "token", name, "user", t.User, "by", p.who())
	w.WriteHeader(http.StatusNoContent)
}
