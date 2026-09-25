// Package store keeps the model: one YAML document per object, on
// disk, with an index of all of them in memory.
//
// The disk is the truth. The panel and the command line write through
// the store; an operator may also edit a file by hand and reload. Every
// write is validated first — on its own and against every other
// document — then the previous revision is archived, and the new one
// replaces it atomically. Nothing half-written ever sits where nginx
// or a reload could read it.
//
// Loading is forgiving, writing is strict. A broken file found at load
// time is skipped with a warning, so that one bad hand edit does not
// take every other host down with it; a write that would produce a
// broken or conflicting document is refused.
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/flock"
	"github.com/ostap-mykhaylyak/limen/internal/model"
	"github.com/ostap-mykhaylyak/limen/internal/paths"
)

// Errors a caller can tell apart (errors.Is).
var (
	ErrNotFound  = errors.New("not found")
	ErrInvalid   = errors.New("invalid")
	ErrConflict  = errors.New("conflict")
	ErrProtected = errors.New("protected")
)

// DefaultKeep is how many past revisions are kept per object.
const DefaultKeep = 20

// Dirs are the directories the model lives in.
type Dirs struct {
	ProxyHosts   string
	Redirects    string
	Streams      string
	AccessLists  string
	Users        string
	Certificates string
	History      string

	// Lock serializes writers across processes: the command line and
	// the panel both write this tree.
	Lock string
}

// DefaultDirs is the production layout.
func DefaultDirs() Dirs {
	return Dirs{
		ProxyHosts:   paths.HostsDir,
		Redirects:    paths.RedirectsDir,
		Streams:      paths.StreamsDir,
		AccessLists:  paths.AccessDir,
		Users:        paths.UsersDir,
		Certificates: paths.CertDocsDir,
		History:      paths.HistoryDir,
		Lock:         paths.ConfigDir + "/.lock",
	}
}

// Under returns a layout rooted in dir, for tests and for hand-run
// instances.
func Under(dir string) Dirs {
	return Dirs{
		ProxyHosts:   filepath.Join(dir, "hosts"),
		Redirects:    filepath.Join(dir, "redirects"),
		Streams:      filepath.Join(dir, "streams"),
		AccessLists:  filepath.Join(dir, "access"),
		Users:        filepath.Join(dir, "users"),
		Certificates: filepath.Join(dir, "certificates"),
		History:      filepath.Join(dir, "history"),
		Lock:         filepath.Join(dir, ".lock"),
	}
}

// For returns the directory of a kind.
func (d Dirs) For(k model.Kind) string {
	switch k {
	case model.KindProxyHost:
		return d.ProxyHosts
	case model.KindRedirect:
		return d.Redirects
	case model.KindStream:
		return d.Streams
	case model.KindAccessList:
		return d.AccessLists
	case model.KindUser:
		return d.Users
	case model.KindCertificate:
		return d.Certificates
	}
	panic(fmt.Sprintf("store: unknown kind %q", k))
}

// Change says who changed something, from where, and why. It is the
// audit trail kept next to every archived revision.
type Change struct {
	Author string
	Source string // "cli", "panel", "rollback"
	Note   string
}

// Revision describes one archived version of a document.
type Revision struct {
	ID     string     `json:"id"`
	Kind   model.Kind `json:"kind"`
	Name   string     `json:"name"`
	Action string     `json:"action"` // what replaced it: "update" or "delete"
	Author string     `json:"author,omitempty"`
	Source string     `json:"source,omitempty"`
	Note   string     `json:"note,omitempty"`
	Time   time.Time  `json:"time"`
}

// Counts is the size of the model, per kind.
type Counts struct {
	ProxyHosts   int
	Redirects    int
	Streams      int
	AccessLists  int
	Users        int
	Certificates int
}

// Store is the model in memory, backed by its directories.
type Store struct {
	dirs Dirs
	keep int
	now  func() time.Time

	mu       sync.RWMutex
	docs     map[model.Kind]map[string]model.Document
	revision int64
	warnings []string
}

// Open loads every document under dirs.
func Open(dirs Dirs) (*Store, error) {
	s := &Store{
		dirs: dirs,
		keep: DefaultKeep,
		now:  func() time.Time { return time.Now().UTC().Truncate(time.Second) },
	}
	if err := s.Reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// Reload re-reads the model from disk and swaps it in. A directory
// that cannot be read at all is an error and keeps the previous model
// in force; a single unreadable document is only a warning.
func (s *Store) Reload() error {
	docs, warnings, err := load(s.dirs)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.docs = docs
	s.warnings = warnings
	s.revision++
	s.mu.Unlock()
	return nil
}

// Warnings returns the problems found by the last load.
func (s *Store) Warnings() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.warnings...)
}

// Revision grows at every change of the model, whatever its source.
// The renderer compares it with the revision it last applied to know
// whether nginx is behind.
func (s *Store) Revision() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.revision
}

// Counts returns the number of documents per kind.
func (s *Store) Counts() Counts {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Counts{
		ProxyHosts:   len(s.docs[model.KindProxyHost]),
		Redirects:    len(s.docs[model.KindRedirect]),
		Streams:      len(s.docs[model.KindStream]),
		AccessLists:  len(s.docs[model.KindAccessList]),
		Users:        len(s.docs[model.KindUser]),
		Certificates: len(s.docs[model.KindCertificate]),
	}
}

// Get returns a copy of one document.
func (s *Store) Get(kind model.Kind, name string) (model.Document, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	doc, ok := s.docs[kind][name]
	if !ok {
		return nil, fmt.Errorf("%s %q: %w", kind, name, ErrNotFound)
	}
	return model.Clone(doc), nil
}

// Fresh reads one document from its file, bypassing the index. It is
// for the reads that cannot wait for the next reload: who a request is
// made by. A user disabled from the command line must be out at the
// next click, not once the daemon has processed its SIGHUP. The document
// passes the same validation as at load time; one that does not is
// treated as absent.
func (s *Store) Fresh(kind model.Kind, name string) (model.Document, error) {
	if err := model.ValidateName(name); err != nil {
		return nil, fmt.Errorf("%s %q: %w", kind, name, ErrNotFound)
	}
	b, err := os.ReadFile(s.path(kind, name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%s %q: %w", kind, name, ErrNotFound)
		}
		return nil, err
	}
	doc, err := model.Decode(kind, name, b)
	if err != nil || doc.Header().Name != name || doc.Validate() != nil {
		return nil, fmt.Errorf("%s %q: %w", kind, name, ErrNotFound)
	}
	return doc, nil
}

// List returns copies of every document of a kind, sorted by name.
func (s *Store) List(kind model.Kind) []model.Document {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Document, 0, len(s.docs[kind]))
	for _, name := range sortedNames(s.docs[kind]) {
		out = append(out, model.Clone(s.docs[kind][name]))
	}
	return out
}

// All returns every document of a kind with its concrete type, for the
// renderer: All[*model.ProxyHost](s, model.KindProxyHost).
func All[T model.Document](s *Store, kind model.Kind) []T {
	docs := s.List(kind)
	out := make([]T, 0, len(docs))
	for _, d := range docs {
		out = append(out, d.(T))
	}
	return out
}

// Locked runs fn while holding the writers' lock, after re-reading the
// model from disk. Another process (the panel, another invocation of
// the command line) may have changed it since this store was loaded,
// and the checks that span documents are only as good as the state
// they look at: two writers each seeing a free domain would both take
// it. Every write from outside a single process goes through here.
func (s *Store) Locked(fn func() error) error {
	unlock, err := flock.Lock(s.dirs.Lock)
	if err != nil {
		return fmt.Errorf("lock %s: %w", s.dirs.Lock, err)
	}
	defer unlock()
	if err := s.Reload(); err != nil {
		return err
	}
	return fn()
}

// Put creates or replaces a document and returns what was stored
// (with its timestamps set).
func (s *Store) Put(doc model.Document, ch Change) (model.Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putLocked(model.Clone(doc), ch)
}

func (s *Store) putLocked(doc model.Document, ch Change) (model.Document, error) {
	h := doc.Header()
	if err := doc.Validate(); err != nil {
		return nil, fmt.Errorf("%s %q: %w: %v", h.Kind, h.Name, ErrInvalid, err)
	}

	now := s.now()
	prev, exists := s.docs[h.Kind][h.Name]
	if exists {
		ph := prev.Header()
		if ph.Protected && !h.Protected {
			return nil, fmt.Errorf("%s %q: %w: its protection cannot be removed", h.Kind, h.Name, ErrProtected)
		}
		h.Created = ph.Created
	} else if h.Created.IsZero() {
		h.Created = now
	}
	h.Updated = now

	if err := s.checkLocked(doc); err != nil {
		return nil, err
	}
	if exists && s.unchangedLocked(doc) {
		// Saving what is already there changes nothing: no rewrite, no
		// revision in the history, no new model revision for nginx.
		return model.Clone(prev), nil
	}

	data, err := model.Encode(doc)
	if err != nil {
		return nil, err
	}
	if exists {
		if err := s.archiveLocked(prev, "update", ch); err != nil {
			return nil, err
		}
	}
	if err := writeAtomic(s.path(h.Kind, h.Name), data, fileMode(h.Kind)); err != nil {
		return nil, err
	}

	if s.docs[h.Kind] == nil {
		s.docs[h.Kind] = map[string]model.Document{}
	}
	s.docs[h.Kind][h.Name] = doc
	s.revision++
	return model.Clone(doc), nil
}

// unchangedLocked reports whether doc says exactly what its file on
// disk says, timestamps aside. The file is the reference, not the copy
// in memory: a hand edit not yet reloaded is a difference.
func (s *Store) unchangedLocked(doc model.Document) bool {
	h := doc.Header()
	b, err := os.ReadFile(s.path(h.Kind, h.Name))
	if err != nil {
		return false
	}
	onDisk, err := model.Decode(h.Kind, h.Name, b)
	if err != nil {
		return false
	}
	candidate := model.Clone(doc)
	ch, dh := candidate.Header(), onDisk.Header()
	ch.Created, ch.Updated = dh.Created, dh.Updated
	a, err1 := model.Encode(candidate)
	c, err2 := model.Encode(onDisk)
	return err1 == nil && err2 == nil && bytes.Equal(a, c)
}

// Delete removes a document. The last revision is archived first, so
// a deletion can be rolled back like any other change.
func (s *Store) Delete(kind model.Kind, name string, ch Change) error {
	return s.delete(kind, name, ch, false)
}

// DeleteProtected removes a document even when it is protected. It is
// for limen's own documents only — the panel's host when panel.hostname
// is cleared — and is never reachable from the command line or the
// panel.
func (s *Store) DeleteProtected(kind model.Kind, name string, ch Change) error {
	return s.delete(kind, name, ch, true)
}

func (s *Store) delete(kind model.Kind, name string, ch Change, force bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	prev, ok := s.docs[kind][name]
	if !ok {
		return fmt.Errorf("%s %q: %w", kind, name, ErrNotFound)
	}
	if prev.Header().Protected && !force {
		return fmt.Errorf("%s %q: %w: it cannot be deleted", kind, name, ErrProtected)
	}

	switch kind {
	case model.KindAccessList:
		// Deleting a guard still in use would leave its hosts either
		// broken or, worse, open. The hosts must let go of it first.
		if users := s.accessUsersLocked(name); len(users) > 0 {
			return fmt.Errorf("access list %q: %w: still guards %s", name, ErrConflict, strings.Join(users, ", "))
		}
	case model.KindCertificate:
		if users := s.certUsersLocked(name); len(users) > 0 {
			return fmt.Errorf("certificate %q: %w: still used by %s", name, ErrConflict, strings.Join(users, ", "))
		}
	case model.KindUser:
		if err := s.adminInvariantLocked(name, nil); err != nil {
			return err
		}
	}

	if err := s.archiveLocked(prev, "delete", ch); err != nil {
		return err
	}
	if err := os.Remove(s.path(kind, name)); err != nil && !os.IsNotExist(err) {
		return err
	}
	delete(s.docs[kind], name)
	s.revision++
	return nil
}

// ---------------------------------------------------------------------
// Invariants that span documents
// ---------------------------------------------------------------------

func (s *Store) checkLocked(doc model.Document) error {
	h := doc.Header()
	switch d := doc.(type) {
	case *model.ProxyHost:
		for _, list := range d.AccessLists() {
			if _, ok := s.docs[model.KindAccessList][list]; !ok {
				return fmt.Errorf("proxy host %q: %w: access list %q does not exist", h.Name, ErrConflict, list)
			}
		}
		if err := s.certExistsLocked(doc, d.TLS.Certificate); err != nil {
			return err
		}
		return s.domainsFreeLocked(doc)
	case *model.Redirect:
		if err := s.certExistsLocked(doc, d.TLS.Certificate); err != nil {
			return err
		}
		return s.domainsFreeLocked(doc)
	case *model.Stream:
		if d.AccessList != "" {
			other, ok := s.docs[model.KindAccessList][d.AccessList]
			if !ok {
				return fmt.Errorf("stream %q: %w: access list %q does not exist", h.Name, ErrConflict, d.AccessList)
			}
			if why := StreamGuard(other.(*model.AccessList)); why != "" {
				return fmt.Errorf("stream %q: %w: access list %q %s", h.Name, ErrConflict, d.AccessList, why)
			}
		}
		for _, other := range s.docs[model.KindStream] {
			o := other.(*model.Stream)
			if o.Name == d.Name || o.Listen != d.Listen {
				continue
			}
			for _, p := range d.Protocols {
				if o.Has(p) {
					return fmt.Errorf("stream %q: %w: %s port %d is already used by stream %q", d.Name, ErrConflict, p, d.Listen, o.Name)
				}
			}
		}
	case *model.AccessList:
		// A stream guarded by this list can only use its address rules:
		// a user added here would be a password nobody is asked for.
		if StreamGuard(d) != "" {
			for _, name := range sortedNames(s.docs[model.KindStream]) {
				if s.docs[model.KindStream][name].(*model.Stream).AccessList == d.Name {
					return fmt.Errorf("access list %q: %w: it guards stream %q, which %s", d.Name, ErrConflict, name,
						"can only check addresses: remove the users, or give the stream another list")
				}
			}
		}
	case *model.User:
		return s.adminInvariantLocked(d.Name, d)
	}
	return nil
}

// StreamGuard says why an access list cannot guard a stream, or "" when
// it can. nginx checks a TCP or UDP client by its address only: there
// is no request to carry a password.
func StreamGuard(a *model.AccessList) string {
	switch {
	case len(a.Users) > 0:
		return "has users, and a stream cannot ask for a password"
	case len(a.Rules) == 0:
		return "has no address rules"
	}
	return ""
}

// domainsFreeLocked refuses a server name another host or redirect
// already answers on. nginx would accept the duplicate with a warning
// and serve one of the two, which is exactly the kind of surprise that
// a manager must not let through. Disabled documents keep their names
// reserved, so that switching one back on never fails.
func (s *Store) domainsFreeLocked(doc model.Document) error {
	h := doc.Header()
	owners := domainOwners(s.docs, h.Kind, h.Name)
	for _, d := range model.Domains(doc) {
		if owner, taken := owners[d]; taken {
			return fmt.Errorf("%s %q: %w: domain %s is already served by %s", h.Kind, h.Name, ErrConflict, d, owner)
		}
	}
	return nil
}

// domainOwners maps every server name to the document that answers on
// it, leaving out one document (the one being replaced).
func domainOwners(docs map[model.Kind]map[string]model.Document, skipKind model.Kind, skipName string) map[string]string {
	owners := map[string]string{}
	for _, kind := range []model.Kind{model.KindProxyHost, model.KindRedirect} {
		for _, name := range sortedNames(docs[kind]) {
			if kind == skipKind && name == skipName {
				continue
			}
			for _, d := range model.Domains(docs[kind][name]) {
				if _, taken := owners[d]; !taken {
					owners[d] = fmt.Sprintf("%s %q", kind, name)
				}
			}
		}
	}
	return owners
}

// adminInvariantLocked refuses a change that would take the panel from
// having an active administrator to having none — by deleting,
// demoting or disabling the last one, even when that user is the only
// account left: nobody could then log in to create another, short of
// the command line. It also makes the first user an admin.
// replacement is the new version of the user, or nil for a deletion.
func (s *Store) adminInvariantLocked(name string, replacement *model.User) error {
	before, after, users := 0, 0, 0
	for n, doc := range s.docs[model.KindUser] {
		u := doc.(*model.User)
		if u.IsActiveAdmin() {
			before++
		}
		if n == name {
			continue
		}
		users++
		if u.IsActiveAdmin() {
			after++
		}
	}
	if replacement != nil {
		users++
		if replacement.IsActiveAdmin() {
			after++
		}
	}
	switch {
	case after > 0:
		return nil
	case before > 0:
		return fmt.Errorf("user %q: %w: the panel would be left without an active admin", name, ErrConflict)
	case users > 0:
		// No admin before either: a fresh install, or a model broken
		// by hand. Only an admin may be added to it.
		return fmt.Errorf("user %q: %w: the panel has no active admin, this user must be one", name, ErrConflict)
	}
	return nil
}

func (s *Store) accessUsersLocked(accessList string) []string {
	var out []string
	for _, name := range sortedNames(s.docs[model.KindProxyHost]) {
		if slices.Contains(s.docs[model.KindProxyHost][name].(*model.ProxyHost).AccessLists(), accessList) {
			out = append(out, "proxy host "+name)
		}
	}
	for _, name := range sortedNames(s.docs[model.KindStream]) {
		if s.docs[model.KindStream][name].(*model.Stream).AccessList == accessList {
			out = append(out, "stream "+name)
		}
	}
	return out
}

// certExistsLocked refuses a reference to a certificate the model does
// not have: it would be served over plain HTTP, forever, with nobody to
// issue the certificate it waits for.
func (s *Store) certExistsLocked(doc model.Document, name string) error {
	if name == "" {
		return nil
	}
	if _, ok := s.docs[model.KindCertificate][name]; !ok {
		h := doc.Header()
		return fmt.Errorf("%s %q: %w: certificate %q does not exist", h.Kind, h.Name, ErrConflict, name)
	}
	return nil
}

// certUsersLocked lists the hosts and redirects served with a
// certificate.
func (s *Store) certUsersLocked(cert string) []string {
	var out []string
	for _, name := range sortedNames(s.docs[model.KindProxyHost]) {
		if s.docs[model.KindProxyHost][name].(*model.ProxyHost).TLS.Certificate == cert {
			out = append(out, "proxy host "+name)
		}
	}
	for _, name := range sortedNames(s.docs[model.KindRedirect]) {
		if s.docs[model.KindRedirect][name].(*model.Redirect).TLS.Certificate == cert {
			out = append(out, "redirect "+name)
		}
	}
	return out
}

// CertUsers lists the hosts and redirects served with a certificate.
func (s *Store) CertUsers(cert string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.certUsersLocked(cert)
}

// AccessUsers lists what an access list guards: proxy hosts (for
// themselves or for one of their locations) and streams.
func (s *Store) AccessUsers(accessList string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.accessUsersLocked(accessList)
}

// ---------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------

func load(dirs Dirs) (map[model.Kind]map[string]model.Document, []string, error) {
	docs := map[model.Kind]map[string]model.Document{}
	var warns []string

	for _, kind := range model.Kinds {
		docs[kind] = map[string]model.Document{}
		dir := dirs.For(kind)
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, nil, fmt.Errorf("read %s: %w", dir, err)
		}
		for _, e := range entries {
			file := e.Name()
			// Dotfiles are the temporary files of an atomic write, or an
			// editor's swap file: never documents.
			if e.IsDir() || strings.HasPrefix(file, ".") || !strings.HasSuffix(file, ".yaml") {
				continue
			}
			path := filepath.Join(dir, file)
			name := strings.TrimSuffix(file, ".yaml")
			if err := model.ValidateName(name); err != nil {
				warns = append(warns, fmt.Sprintf("skipping %s: %v", path, err))
				continue
			}
			b, err := os.ReadFile(path)
			if err != nil {
				warns = append(warns, fmt.Sprintf("skipping %s: %v", path, err))
				continue
			}
			doc, err := model.Decode(kind, name, b)
			if err != nil {
				warns = append(warns, fmt.Sprintf("skipping %s: %v", path, err))
				continue
			}
			if got := doc.Header().Name; got != name {
				// The file name is the identity; a document that claims
				// another one is ambiguous, and guessing is how a host
				// ends up overwritten by its neighbour.
				warns = append(warns, fmt.Sprintf("skipping %s: it says name %q, the file says %q", path, got, name))
				continue
			}
			if err := doc.Validate(); err != nil {
				warns = append(warns, fmt.Sprintf("skipping %s: %v", path, err))
				continue
			}
			docs[kind][name] = doc
		}
	}

	warns = append(warns, crossCheck(docs)...)
	return docs, warns, nil
}

// crossCheck drops the documents that conflict with others, in a
// stable order (by name), and says why. It fails closed: a host whose
// access list is missing is not served at all, rather than served
// without its guard.
func crossCheck(docs map[model.Kind]map[string]model.Document) []string {
	var warns []string

	for _, name := range sortedNames(docs[model.KindProxyHost]) {
		h := docs[model.KindProxyHost][name].(*model.ProxyHost)
		for _, list := range h.AccessLists() {
			if _, ok := docs[model.KindAccessList][list]; !ok {
				warns = append(warns, fmt.Sprintf("skipping proxy host %q: access list %q does not exist, "+
					"and the host is not served without its guard", name, list))
				delete(docs[model.KindProxyHost], name)
				break
			}
		}
	}
	for _, name := range sortedNames(docs[model.KindStream]) {
		st := docs[model.KindStream][name].(*model.Stream)
		if st.AccessList == "" {
			continue
		}
		list, ok := docs[model.KindAccessList][st.AccessList]
		why := "does not exist"
		if ok {
			why = StreamGuard(list.(*model.AccessList))
		}
		if why != "" {
			warns = append(warns, fmt.Sprintf("skipping stream %q: access list %q %s, "+
				"and the stream is not served without its guard", name, st.AccessList, why))
			delete(docs[model.KindStream], name)
		}
	}

	owners := map[string]string{}
	for _, kind := range []model.Kind{model.KindProxyHost, model.KindRedirect} {
		for _, name := range sortedNames(docs[kind]) {
			doc := docs[kind][name]
			clash := ""
			for _, d := range model.Domains(doc) {
				if owner, taken := owners[d]; taken {
					clash = fmt.Sprintf("domain %s is already served by %s", d, owner)
					break
				}
			}
			if clash != "" {
				warns = append(warns, fmt.Sprintf("skipping %s %q: %s", kind, name, clash))
				delete(docs[kind], name)
				continue
			}
			for _, d := range model.Domains(doc) {
				owners[d] = fmt.Sprintf("%s %q", kind, name)
			}
		}
	}

	ports := map[string]string{}
	for _, name := range sortedNames(docs[model.KindStream]) {
		st := docs[model.KindStream][name].(*model.Stream)
		clash := ""
		for _, p := range st.Protocols {
			if owner, taken := ports[fmt.Sprintf("%s/%d", p, st.Listen)]; taken {
				clash = fmt.Sprintf("%s port %d is already used by stream %q", p, st.Listen, owner)
				break
			}
		}
		if clash != "" {
			warns = append(warns, fmt.Sprintf("skipping stream %q: %s", name, clash))
			delete(docs[model.KindStream], name)
			continue
		}
		for _, p := range st.Protocols {
			ports[fmt.Sprintf("%s/%d", p, st.Listen)] = name
		}
	}

	// A reference to a certificate the model does not know is only a
	// warning at load time: the host is served over plain HTTP until the
	// certificate exists, which is what it would get anyway.
	for _, kind := range []model.Kind{model.KindProxyHost, model.KindRedirect} {
		for _, name := range sortedNames(docs[kind]) {
			var cert string
			switch d := docs[kind][name].(type) {
			case *model.ProxyHost:
				cert = d.TLS.Certificate
			case *model.Redirect:
				cert = d.TLS.Certificate
			}
			if cert != "" {
				if _, ok := docs[model.KindCertificate][cert]; !ok {
					warns = append(warns, fmt.Sprintf("%s %q refers to certificate %q, which the model does not have: "+
						"create it with `limen cert add` or `limen cert import`", kind, name, cert))
				}
			}
		}
	}

	if len(docs[model.KindUser]) > 0 {
		admins := 0
		for _, doc := range docs[model.KindUser] {
			if doc.(*model.User).IsActiveAdmin() {
				admins++
			}
		}
		if admins == 0 {
			warns = append(warns, "no active admin among the panel users: "+
				"create one with `limen user add NAME --role admin --password-stdin`")
		}
	}
	return warns
}

// ---------------------------------------------------------------------
// History
// ---------------------------------------------------------------------

var revisionIDRe = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}\.[0-9]{9}Z(-[0-9]{1,3})?$`)

func (s *Store) historyDir(kind model.Kind, name string) string {
	return filepath.Join(s.dirs.History, string(kind), name)
}

// archiveLocked keeps the version of a document that is about to be
// replaced or removed. It copies the file as it is on disk, not a
// re-encoding of what was loaded, so a hand edit made since the last
// reload is not lost either.
func (s *Store) archiveLocked(prev model.Document, action string, ch Change) error {
	h := prev.Header()
	data, err := os.ReadFile(s.path(h.Kind, h.Name))
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if data, err = model.Encode(prev); err != nil {
			return err
		}
	}

	dir := s.historyDir(h.Kind, h.Name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("history: %w", err)
	}

	at := time.Now().UTC()
	id := at.Format("20060102T150405.000000000Z")
	for i := 1; ; i++ {
		if _, err := os.Stat(filepath.Join(dir, id+".yaml")); os.IsNotExist(err) {
			break
		}
		id = fmt.Sprintf("%s-%d", at.Format("20060102T150405.000000000Z"), i)
	}

	rev := Revision{
		ID: id, Kind: h.Kind, Name: h.Name, Action: action,
		Author: ch.Author, Source: ch.Source, Note: ch.Note, Time: at,
	}
	meta, err := json.MarshalIndent(rev, "", "  ")
	if err != nil {
		return err
	}
	// Revisions hold password hashes as they were: owner-only.
	if err := writeAtomic(filepath.Join(dir, id+".yaml"), data, 0o600); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(dir, id+".json"), append(meta, '\n'), 0o600); err != nil {
		return err
	}
	return s.pruneLocked(dir)
}

// pruneLocked keeps the newest revisions and drops the rest.
func (s *Store) pruneLocked(dir string) error {
	ids, err := revisionIDs(dir)
	if err != nil {
		return err
	}
	if len(ids) <= s.keep {
		return nil
	}
	var errs []error
	for _, id := range ids[:len(ids)-s.keep] {
		for _, ext := range []string{".yaml", ".json"} {
			if err := os.Remove(filepath.Join(dir, id+ext)); err != nil && !os.IsNotExist(err) {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// revisionIDs lists the revisions in dir, oldest first.
func revisionIDs(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".yaml")
		if ok && revisionIDRe.MatchString(id) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// History lists the archived revisions of a document, newest first. It
// works for a deleted document too: that is how one is brought back.
func (s *Store) History(kind model.Kind, name string) ([]Revision, error) {
	if err := model.ValidateName(name); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	dir := s.historyDir(kind, name)
	ids, err := revisionIDs(dir)
	if err != nil {
		return nil, err
	}
	out := make([]Revision, 0, len(ids))
	for _, id := range slices.Backward(ids) {
		rev := Revision{ID: id, Kind: kind, Name: name}
		if b, err := os.ReadFile(filepath.Join(dir, id+".json")); err == nil {
			_ = json.Unmarshal(b, &rev)
		}
		out = append(out, rev)
	}
	return out, nil
}

// Rollback puts an archived revision back. It goes through the same
// path as any other write — validation, conflicts, archiving of what
// it replaces — so a rollback can itself be rolled back, and a
// revision that no longer fits the model is refused rather than forced
// in.
func (s *Store) Rollback(kind model.Kind, name, id string, ch Change) (model.Document, error) {
	if err := model.ValidateName(name); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	// The id becomes part of a path: accept only what we generate.
	if !revisionIDRe.MatchString(id) {
		return nil, fmt.Errorf("revision %q: %w", id, ErrNotFound)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := os.ReadFile(filepath.Join(s.historyDir(kind, name), id+".yaml"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%s %q revision %s: %w", kind, name, id, ErrNotFound)
		}
		return nil, err
	}
	doc, err := model.Decode(kind, name, b)
	if err != nil {
		return nil, fmt.Errorf("%s %q revision %s: %w: %v", kind, name, id, ErrInvalid, err)
	}
	if ch.Source == "" {
		ch.Source = "rollback"
	}
	if ch.Note == "" {
		ch.Note = "rollback to " + id
	}
	return s.putLocked(doc, ch)
}

// ---------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------

func (s *Store) path(kind model.Kind, name string) string {
	return filepath.Join(s.dirs.For(kind), name+".yaml")
}

// fileMode is 0600 for the documents that hold password hashes (panel
// users and access lists) and 0640 for everything else.
func fileMode(kind model.Kind) os.FileMode {
	if kind == model.KindUser || kind == model.KindAccessList {
		return 0o600
	}
	return 0o640
}

// writeAtomic writes data to a temporary file in the same directory,
// flushes it, and renames it over path: a reader sees the old file or
// the new one, never a mix.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func() { os.Remove(name) }

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(name, path); err != nil {
		cleanup()
		return err
	}
	// Make the rename itself durable. Windows cannot open a directory
	// for syncing; limen runs on Linux, where it can.
	if runtime.GOOS != "windows" {
		if d, err := os.Open(dir); err == nil {
			d.Sync()
			d.Close()
		}
	}
	return nil
}

func sortedNames(m map[string]model.Document) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
