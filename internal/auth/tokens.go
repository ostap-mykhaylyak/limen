package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/flock"
	"github.com/ostap-mykhaylyak/limen/internal/model"
)

// API tokens are the keys scripts use instead of a session: sent as
// "Authorization: Bearer limen_<id>_<secret>", they act as their user,
// with a role that can be lower than the user's and never higher.
//
// A token is shown once, when it is made. The file keeps its id — the
// public half, which finds the token without trying every hash — and
// the SHA-256 of its secret: 32 random bytes need no slow hash, and a
// leaked file opens nothing. The file is shared by the daemon and the
// command line; the daemon reads it again whenever it changes on disk,
// so `limen token rm` takes effect on the very next request.

// TokenPrefix starts every token, so that a secret scanner — and a
// person reading a leaked log — can tell what it is.
const TokenPrefix = "limen_"

var tokenRe = regexp.MustCompile(`^limen_([0-9a-f]{16})_([A-Za-z0-9_-]{43})$`)

// lastUsedEvery is how stale the last use written to the file may be:
// writing it on every request would put a write behind every read.
const lastUsedEvery = 10 * time.Minute

// Errors of Verify.
var (
	ErrTokenInvalid = errors.New("invalid API token")
	ErrTokenExpired = errors.New("the API token has expired")
)

// Token is one API token, without its secret.
type Token struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	User string `json:"user"`
	// UserCreated is when the user was created: a user deleted and made
	// again under the same name is someone else, and must not inherit
	// the tokens of the first.
	UserCreated time.Time `json:"user_created"`
	Role        string    `json:"role"`
	Description string    `json:"description,omitempty"`
	Hash        string    `json:"hash"`
	Created     time.Time `json:"created"`
	CreatedBy   string    `json:"created_by"`
	Expires     time.Time `json:"expires,omitzero"`
	LastUsed    time.Time `json:"last_used,omitzero"`
	LastClient  string    `json:"last_client,omitempty"`
}

// Expired reports whether the token has expired at now.
func (t *Token) Expired(now time.Time) bool {
	return !t.Expires.IsZero() && !now.Before(t.Expires)
}

// TokenSpec is what a new token is made of.
type TokenSpec struct {
	Name        string
	User        string
	UserCreated time.Time
	Role        string
	Description string
	CreatedBy   string
	// TTL is how long the token lives; zero is for ever.
	TTL time.Duration
}

// Tokens is the set of API tokens, backed by a file.
type Tokens struct {
	path string
	lock string
	now  func() time.Time

	mu   sync.Mutex
	list []*Token
	info os.FileInfo // the file as last read; nil when there was none
	// used holds the last use of tokens that the file does not have yet.
	used map[string]use
}

type use struct {
	at     time.Time
	client string
}

// OpenTokens reads the tokens file; a missing one is an empty set. lock
// is the file writers serialize on, across processes.
func OpenTokens(path, lock string) (*Tokens, error) {
	t := &Tokens{path: path, lock: lock, now: time.Now, used: map[string]use{}}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.readLocked(); err != nil {
		return nil, err
	}
	return t, nil
}

// readLocked loads the file unless it is the one already loaded. An
// atomic write replaces the file, so a new write is a new file.
func (t *Tokens) readLocked() error {
	fi, err := os.Stat(t.path)
	if err != nil {
		if os.IsNotExist(err) {
			t.list, t.info = nil, nil
			return nil
		}
		return fmt.Errorf("tokens: %w", err)
	}
	if t.info != nil && os.SameFile(t.info, fi) && t.info.ModTime().Equal(fi.ModTime()) && t.info.Size() == fi.Size() {
		return nil
	}
	b, err := os.ReadFile(t.path)
	if err != nil {
		return fmt.Errorf("tokens: %w", err)
	}
	var list []*Token
	if err := json.Unmarshal(b, &list); err != nil {
		// Unlike the sessions, a corrupt file is not an empty set: that
		// would let the next write drop every token without a word.
		return fmt.Errorf("tokens: %s is corrupt: %w", t.path, err)
	}
	t.list, t.info = list, fi
	return nil
}

// modify runs fn on the tokens as they are on disk, under the
// cross-process lock, and writes the result.
func (t *Tokens) modify(fn func() error) error {
	unlock, err := flock.Lock(t.lock)
	if err != nil {
		return fmt.Errorf("tokens: lock: %w", err)
	}
	defer unlock()
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.readLocked(); err != nil {
		return err
	}
	if err := fn(); err != nil {
		return err
	}
	return t.writeLocked()
}

// IsTokenLike reports whether s has the shape of a token.
func IsTokenLike(s string) bool { return tokenRe.MatchString(s) }

// TokenID returns the public half of a token, or "" when s is not
// shaped like one.
func TokenID(s string) string {
	m := tokenRe.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1]
}

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte("limen-token:" + secret))
	return hex.EncodeToString(sum[:])
}

// Create makes a token and returns it with the one copy of its secret.
func (t *Tokens) Create(spec TokenSpec) (string, Token, error) {
	if err := model.ValidateName(spec.Name); err != nil {
		return "", Token{}, fmt.Errorf("token %w", err)
	}
	switch spec.Role {
	case model.RoleAdmin, model.RoleOperator, model.RoleViewer:
	default:
		return "", Token{}, fmt.Errorf("role %q: want admin, operator or viewer", spec.Role)
	}
	if spec.User == "" || spec.UserCreated.IsZero() {
		return "", Token{}, errors.New("a token needs a user")
	}
	if spec.TTL < 0 {
		return "", Token{}, errors.New("a token cannot expire in the past")
	}
	if len(spec.Description) > 200 {
		return "", Token{}, errors.New("the description is longer than 200 characters")
	}

	idb := make([]byte, 8)
	sb := make([]byte, 32)
	if _, err := rand.Read(idb); err != nil {
		return "", Token{}, err
	}
	if _, err := rand.Read(sb); err != nil {
		return "", Token{}, err
	}
	id := hex.EncodeToString(idb)
	secret := base64.RawURLEncoding.EncodeToString(sb)
	now := t.now().UTC().Truncate(time.Second)
	tok := &Token{
		ID: id, Name: spec.Name, User: spec.User, UserCreated: spec.UserCreated,
		Role: spec.Role, Description: spec.Description, Hash: hashSecret(secret),
		Created: now, CreatedBy: spec.CreatedBy,
	}
	if spec.TTL > 0 {
		tok.Expires = now.Add(spec.TTL)
	}
	err := t.modify(func() error {
		for _, o := range t.list {
			if o.Name == spec.Name {
				return fmt.Errorf("token %q already exists: remove it first, or pick another name", spec.Name)
			}
			if o.ID == id {
				return errors.New("token id collision, try again")
			}
		}
		t.list = append(t.list, tok)
		return nil
	})
	if err != nil {
		return "", Token{}, err
	}
	return TokenPrefix + id + "_" + secret, *tok, nil
}

// Verify finds the token a request presents. It returns a copy; the
// caller checks the user behind it.
func (t *Tokens) Verify(presented, client string) (Token, error) {
	m := tokenRe.FindStringSubmatch(presented)
	if m == nil {
		return Token{}, ErrTokenInvalid
	}
	id, secret := m[1], m[2]
	want := hashSecret(secret)

	t.mu.Lock()
	if err := t.readLocked(); err != nil {
		t.mu.Unlock()
		return Token{}, err
	}
	var found *Token
	for _, tok := range t.list {
		if tok.ID == id {
			found = tok
			break
		}
	}
	if found == nil || subtle.ConstantTimeCompare([]byte(found.Hash), []byte(want)) != 1 {
		t.mu.Unlock()
		return Token{}, ErrTokenInvalid
	}
	now := t.now().UTC()
	out := *found
	if out.Expired(now) {
		t.mu.Unlock()
		return out, ErrTokenExpired
	}
	t.used[id] = use{at: now, client: client}
	stale := now.Sub(found.LastUsed) >= lastUsedEvery
	t.mu.Unlock()

	if stale {
		// Best effort: a failure to note the last use must not refuse
		// the request.
		t.flushUsed()
	}
	return out, nil
}

// flushUsed writes the last uses noted since the last write.
func (t *Tokens) flushUsed() {
	t.modify(func() error {
		for _, tok := range t.list {
			if u, ok := t.used[tok.ID]; ok && u.at.After(tok.LastUsed) {
				tok.LastUsed, tok.LastClient = u.at.Truncate(time.Second), u.client
			}
		}
		clear(t.used)
		return nil
	})
}

// Delete removes a token by name and returns it.
func (t *Tokens) Delete(name string) (Token, error) {
	var gone Token
	err := t.modify(func() error {
		i := slices.IndexFunc(t.list, func(tok *Token) bool { return tok.Name == name })
		if i < 0 {
			return fmt.Errorf("token %q: %w", name, os.ErrNotExist)
		}
		gone = *t.list[i]
		t.list = slices.Delete(t.list, i, i+1)
		delete(t.used, gone.ID)
		return nil
	})
	return gone, err
}

// DeleteUser removes every token of a user, when the user is removed,
// and says how many there were.
func (t *Tokens) DeleteUser(user string) (int, error) {
	if !slices.ContainsFunc(t.List(), func(tok Token) bool { return tok.User == user }) {
		return 0, nil
	}
	n := 0
	err := t.modify(func() error {
		t.list = slices.DeleteFunc(t.list, func(tok *Token) bool {
			if tok.User == user {
				n++
				delete(t.used, tok.ID)
				return true
			}
			return false
		})
		return nil
	})
	return n, err
}

// Get returns a token by name.
func (t *Tokens) Get(name string) (Token, error) {
	for _, tok := range t.List() {
		if tok.Name == name {
			return tok, nil
		}
	}
	return Token{}, fmt.Errorf("token %q: %w", name, os.ErrNotExist)
}

// List returns every token, by name, with the uses not yet written and
// without the hashes.
func (t *Tokens) List() []Token {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.readLocked()
	out := make([]Token, 0, len(t.list))
	for _, tok := range t.list {
		c := *tok
		c.Hash = ""
		if u, ok := t.used[c.ID]; ok && u.at.After(c.LastUsed) {
			c.LastUsed, c.LastClient = u.at.Truncate(time.Second), u.client
		}
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b Token) int { return strings.Compare(a.Name, b.Name) })
	return out
}

func (t *Tokens) writeLocked() error {
	list := t.list
	if list == nil {
		list = []*Token{}
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(t.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tokens.*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(append(b, '\n'))
	serr := tmp.Sync()
	cerr := tmp.Close()
	if err := errors.Join(werr, serr, cerr, os.Chmod(name, 0o600)); err != nil {
		os.Remove(name)
		return fmt.Errorf("tokens: %w", err)
	}
	if err := os.Rename(name, t.path); err != nil {
		os.Remove(name)
		return fmt.Errorf("tokens: %w", err)
	}
	fi, err := os.Stat(t.path)
	if err != nil {
		return fmt.Errorf("tokens: %w", err)
	}
	t.info = fi
	return nil
}
