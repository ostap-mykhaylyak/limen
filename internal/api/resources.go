package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/acme"
	"github.com/ostap-mykhaylyak/limen/internal/audit"
	"github.com/ostap-mykhaylyak/limen/internal/model"
	"github.com/ostap-mykhaylyak/limen/internal/nginx"
	"github.com/ostap-mykhaylyak/limen/internal/secret"
	"github.com/ostap-mykhaylyak/limen/internal/store"
)

// collection is one kind of document, exposed as a REST collection.
type collection struct {
	path  string
	kind  model.Kind
	read  string // the least role that may read it
	write string // the least role that may change it
}

var collections = []collection{
	{"hosts", model.KindProxyHost, model.RoleViewer, model.RoleOperator},
	{"redirects", model.KindRedirect, model.RoleViewer, model.RoleOperator},
	{"streams", model.KindStream, model.RoleViewer, model.RoleOperator},
	{"access-lists", model.KindAccessList, model.RoleViewer, model.RoleOperator},
	{"certificates", model.KindCertificate, model.RoleViewer, model.RoleOperator},
	// Users are the keys to the panel: only admins see them at all.
	{"users", model.KindUser, model.RoleAdmin, model.RoleAdmin},
}

func (a *API) collection(c collection) {
	base := "/" + c.path
	a.route("GET "+base, c.read, func(w http.ResponseWriter, r *http.Request, p *principal) {
		docs := a.d.Store.List(c.kind)
		items := make([]any, len(docs))
		for i, d := range docs {
			items[i] = a.view(d)
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	})
	a.route("POST "+base, c.write, func(w http.ResponseWriter, r *http.Request, p *principal) {
		a.write(w, r, p, c, "", true)
	})
	a.route("GET "+base+"/{name}", c.read, func(w http.ResponseWriter, r *http.Request, p *principal) {
		doc, err := a.d.Store.Get(c.kind, r.PathValue("name"))
		if err != nil {
			a.fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, a.view(doc))
	})
	a.route("PUT "+base+"/{name}", c.write, func(w http.ResponseWriter, r *http.Request, p *principal) {
		a.write(w, r, p, c, r.PathValue("name"), false)
	})
	a.route("DELETE "+base+"/{name}", c.write, func(w http.ResponseWriter, r *http.Request, p *principal) {
		a.remove(w, r, p, c, r.PathValue("name"))
	})
	a.route("GET "+base+"/{name}/history", c.read, func(w http.ResponseWriter, r *http.Request, p *principal) {
		revs, err := a.d.Store.History(c.kind, r.PathValue("name"))
		if err != nil {
			a.fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": revs})
	})
	a.route("POST "+base+"/{name}/rollback", c.write, func(w http.ResponseWriter, r *http.Request, p *principal) {
		a.rollback(w, r, p, c, r.PathValue("name"))
	})
}

// writeResult is the answer to a write: what was stored, and what nginx
// made of it.
type writeResult struct {
	Item  model.Document `json:"item"`
	Apply *nginx.Result  `json:"apply,omitempty"`
}

// write creates (POST) or replaces (PUT) a document. A PUT is a full
// replacement: what the body leaves out goes back to its default, like
// a hand-written file.
func (a *API) write(w http.ResponseWriter, r *http.Request, p *principal, c collection, name string, create bool) {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "send application/json")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "the body is too large or unreadable")
		return
	}

	var current model.Document
	if !create {
		doc, err := a.d.Store.Get(c.kind, name)
		if err != nil {
			a.fail(w, err)
			return
		}
		if doc.Header().Protected {
			writeError(w, http.StatusConflict, fmt.Sprintf("%s %q is managed by config.yaml and cannot be changed here", c.kind, name))
			return
		}
		current = doc
	}

	doc, err := a.fromBody(raw, c.kind, name, current)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	name = doc.Header().Name

	var stored model.Document
	err = a.d.Store.Locked(func() error {
		exists := false
		if _, err := a.d.Store.Get(c.kind, name); err == nil {
			exists = true
		}
		switch {
		case create && exists:
			return fmt.Errorf("%s %q: %w: it already exists, PUT to change it", c.kind, name, store.ErrConflict)
		case !create && !exists:
			return fmt.Errorf("%s %q: %w", c.kind, name, store.ErrNotFound)
		}
		note := "created from the panel"
		if !create {
			note = "changed from the panel"
		}
		var err error
		stored, err = a.d.Store.Put(doc, a.change(r, p, note))
		return err
	})
	if err != nil {
		a.fail(w, err)
		return
	}
	if c.kind == model.KindUser {
		a.closeSessionsAfterUserChange(p, current, stored)
	}

	code := http.StatusOK
	if create {
		code = http.StatusCreated
	}
	writeJSON(w, code, writeResult{Item: stored, Apply: a.applyAfter(c)})
}

func (a *API) remove(w http.ResponseWriter, r *http.Request, p *principal, c collection, name string) {
	doc, err := a.d.Store.Get(c.kind, name)
	if err != nil {
		a.fail(w, err)
		return
	}
	if doc.Header().Protected {
		writeError(w, http.StatusConflict, fmt.Sprintf("%s %q is managed by config.yaml and cannot be deleted here", c.kind, name))
		return
	}
	if err := a.d.Store.Locked(func() error {
		return a.d.Store.Delete(c.kind, name, a.change(r, p, "deleted from the panel"))
	}); err != nil {
		a.fail(w, err)
		return
	}
	if c.kind == model.KindUser {
		a.d.Sessions.DeleteUser(name, "")
	}
	if c.kind == model.KindCertificate && a.d.Certificates != nil {
		// Moved aside, not destroyed: an uploaded certificate cannot be
		// issued again if the deletion is rolled back.
		if err := a.d.Certificates.Removed(name); err != nil {
			a.d.Log.Warn("certificate files", "certificate", name, "error", err.Error())
		}
	}
	writeJSON(w, http.StatusOK, writeResult{Apply: a.applyAfter(c)})
}

// view is a document as the API shows it: certificates carry the state
// of their files — expiry, last attempt, last error — next to what the
// model says of them.
func (a *API) view(doc model.Document) any {
	c, ok := doc.(*model.Certificate)
	if !ok || a.d.Certificates == nil {
		return doc
	}
	return struct {
		*model.Certificate
		State acme.Summary `json:"state"`
		Users []string     `json:"used_by"`
	}{c, a.d.Certificates.Describe(c), a.d.Store.CertUsers(c.Name)}
}

func (a *API) renewCert(w http.ResponseWriter, r *http.Request, p *principal) {
	if a.d.Certificates == nil {
		writeError(w, http.StatusServiceUnavailable, "no certificate manager")
		return
	}
	name := r.PathValue("name")
	if err := a.d.Certificates.Request(name); err != nil {
		a.fail(w, err)
		return
	}
	audit.From(r.Context()).Action = "renewal of " + name + " requested"
	doc, err := a.d.Store.Get(model.KindCertificate, name)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, a.view(doc))
}

type uploadRequest struct {
	Chain string `json:"chain"`
	Key   string `json:"key"`
}

func (a *API) uploadCert(w http.ResponseWriter, r *http.Request, p *principal) {
	if a.d.Certificates == nil {
		writeError(w, http.StatusServiceUnavailable, "no certificate manager")
		return
	}
	var req uploadRequest
	if !decode(w, r, &req) {
		return
	}
	name := r.PathValue("name")
	if _, err := a.d.Certificates.Upload(name, []byte(req.Chain), []byte(req.Key)); err != nil {
		a.fail(w, err)
		return
	}
	audit.From(r.Context()).Action = "certificate " + name + " uploaded"
	doc, err := a.d.Store.Get(model.KindCertificate, name)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a.view(doc))
}

type rollbackRequest struct {
	Revision string `json:"revision"`
}

func (a *API) rollback(w http.ResponseWriter, r *http.Request, p *principal, c collection, name string) {
	var req rollbackRequest
	if !decode(w, r, &req) {
		return
	}
	var stored model.Document
	err := a.d.Store.Locked(func() error {
		if cur, err := a.d.Store.Get(c.kind, name); err == nil && cur.Header().Protected {
			return fmt.Errorf("%s %q: %w: it is managed by config.yaml", c.kind, name, store.ErrProtected)
		}
		ch := a.change(r, p, "rollback to "+req.Revision)
		ch.Source = "rollback"
		var err error
		stored, err = a.d.Store.Rollback(c.kind, name, req.Revision, ch)
		return err
	})
	if err != nil {
		a.fail(w, err)
		return
	}
	if c.kind == model.KindUser {
		// The revision may carry an older password: sessions opened with
		// the current one end, as they would after any password change.
		a.d.Sessions.DeleteUser(name, "")
	}
	writeJSON(w, http.StatusOK, writeResult{Item: stored, Apply: a.applyAfter(c)})
}

// applyAfter pushes a change to nginx. Users do not reach nginx.
func (a *API) applyAfter(c collection) *nginx.Result {
	if a.d.Apply == nil || c.kind == model.KindUser {
		return nil
	}
	res, _ := a.d.Apply(false)
	return &res
}

// closeSessionsAfterUserChange ends the sessions a change to a user
// invalidates. authenticate would catch most of them on the next
// request anyway; closing them now keeps the sessions file honest.
func (a *API) closeSessionsAfterUserChange(p *principal, before, after model.Document) {
	if before == nil {
		return
	}
	b, u := before.(*model.User), after.(*model.User)
	if b.Password != u.Password || u.Disabled {
		// Including the session asking, when an admin changes their own
		// password here: its tag is the old password's. Changing one's
		// own password without logging out is PUT /session/password.
		a.d.Sessions.DeleteUser(u.Name, "")
	}
}

// ---------------------------------------------------------------------
// Bodies
// ---------------------------------------------------------------------

// readOnly are the fields a client sends back as it got them; the
// server decides their value.
type readOnly struct {
	Kind      model.Kind `json:"kind"`
	Protected bool       `json:"protected"`
	Created   time.Time  `json:"created"`
	Updated   time.Time  `json:"updated"`
}

// fromBody builds the document a request describes, on top of the
// defaults of its kind.
func (a *API) fromBody(raw []byte, kind model.Kind, name string, current model.Document) (model.Document, error) {
	var doc model.Document
	switch kind {
	case model.KindAccessList:
		d, err := accessFromBody(raw, name, current)
		if err != nil {
			return nil, err
		}
		doc = d
	case model.KindUser:
		d, err := userFromBody(raw, name, current)
		if err != nil {
			return nil, err
		}
		doc = d
	case model.KindCertificate:
		// What view adds is sent back by a client that edits what it got:
		// accepted, and ignored.
		var in struct {
			*model.Certificate
			State json.RawMessage `json:"state"`
			Users json.RawMessage `json:"used_by"`
		}
		d, _ := model.New(kind, name)
		in.Certificate = d.(*model.Certificate)
		if err := strictJSON(raw, &in); err != nil {
			return nil, err
		}
		doc = d
	default:
		d, _ := model.New(kind, name)
		if err := strictJSON(raw, d); err != nil {
			return nil, err
		}
		doc = d
	}

	h := doc.Header()
	if h.Kind != "" && h.Kind != kind {
		return nil, fmt.Errorf("kind %q, want %q", string(h.Kind), string(kind))
	}
	h.Kind = kind
	switch {
	case name != "" && h.Name != name:
		return nil, fmt.Errorf("renaming is not supported: create a new one and delete %q", name)
	case h.Name == "":
		h.Name = nameFromDomains(doc)
		if h.Name == "" {
			return nil, fmt.Errorf("name is required")
		}
	}
	if err := model.ValidateName(h.Name); err != nil {
		return nil, err
	}
	// Protection belongs to limen's own documents, never to a request.
	h.Protected = false
	h.Created, h.Updated = time.Time{}, time.Time{}

	if ph, ok := doc.(*model.ProxyHost); ok && ph.Forward.Socket != "" {
		// A unix socket target would let an operator publish any local
		// socket — the Docker one, say — through nginx: that is root on
		// the machine, not an operator's business.
		return nil, fmt.Errorf("forward.socket is reserved for limen's own panel")
	}
	return doc, nil
}

func nameFromDomains(doc model.Document) string {
	ds := model.Domains(doc)
	if c, ok := doc.(*model.Certificate); ok {
		ds = c.Domains
	}
	if len(ds) > 0 {
		return strings.Replace(ds[0], "*.", "wildcard.", 1)
	}
	return ""
}

func strictJSON(raw []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON: %v", err)
	}
	return nil
}

type basicUserInput struct {
	Username string `json:"username"`
	// Password is the new password; empty keeps the current one.
	Password string `json:"password,omitempty"`
}

type accessInput struct {
	readOnly
	Name        string           `json:"name"`
	Description string           `json:"description"`
	SatisfyAny  bool             `json:"satisfy_any"`
	PassAuth    bool             `json:"pass_auth"`
	Users       []basicUserInput `json:"users"`
	Rules       []model.Rule     `json:"rules"`
}

func accessFromBody(raw []byte, name string, current model.Document) (*model.AccessList, error) {
	in := accessInput{Name: name}
	if err := strictJSON(raw, &in); err != nil {
		return nil, err
	}
	a := model.NewAccessList(in.Name)
	a.Kind = in.Kind
	a.Description, a.SatisfyAny, a.PassAuth, a.Rules = in.Description, in.SatisfyAny, in.PassAuth, in.Rules

	existing := map[string]string{}
	if cur, ok := current.(*model.AccessList); ok {
		for _, u := range cur.Users {
			existing[u.Username] = u.Password
		}
	}
	for _, u := range in.Users {
		hash := existing[u.Username]
		if u.Password != "" {
			h, err := secret.HashBasic(u.Password)
			if err != nil {
				return nil, fmt.Errorf("user %q: %v", u.Username, err)
			}
			hash = h
		}
		if hash == "" {
			return nil, fmt.Errorf("user %q needs a password", u.Username)
		}
		a.Users = append(a.Users, model.BasicUser{Username: u.Username, Password: hash})
	}
	return a, nil
}

type userInput struct {
	readOnly
	Name        string `json:"name"`
	Description string `json:"description"`
	Email       string `json:"email"`
	FullName    string `json:"full_name"`
	Role        string `json:"role"`
	Disabled    bool   `json:"disabled"`
	// Password is the new password; empty keeps the current one.
	Password string `json:"password,omitempty"`
}

func userFromBody(raw []byte, name string, current model.Document) (*model.User, error) {
	in := userInput{Name: name}
	if err := strictJSON(raw, &in); err != nil {
		return nil, err
	}
	u := model.NewUser(in.Name)
	u.Kind = in.Kind
	u.Description, u.Email, u.FullName, u.Disabled = in.Description, in.Email, in.FullName, in.Disabled
	if in.Role != "" {
		u.Role = in.Role
	}
	switch {
	case in.Password != "":
		h, err := secret.HashPanel(in.Password)
		if err != nil {
			return nil, err
		}
		u.Password = h
	case current != nil:
		u.Password = current.(*model.User).Password
	default:
		return nil, fmt.Errorf("a new user needs a password")
	}
	return u, nil
}
