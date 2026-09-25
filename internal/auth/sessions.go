// Package auth keeps the panel's sessions and throttles its logins.
//
// A session lives on the server. The browser holds a random id in a
// cookie; the server keeps only the SHA-256 of that id, so the sessions
// file — kept so that a restart does not log everybody out — cannot be
// replayed if it leaks. Each session also remembers a tag of the user's
// password hash at login: when the password changes, from the panel or
// from the command line, every session opened with the old one stops
// working on its next request.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Session is one login.
type Session struct {
	// ID is the secret the cookie carries. It exists only in the
	// Session returned by Create; the store keeps its hash.
	ID string `json:"-"`

	Hash     string    `json:"hash"`
	User     string    `json:"user"`
	CSRF     string    `json:"csrf"`
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires"`
	LastSeen time.Time `json:"last_seen"`
	Client   string    `json:"client"`
	Agent    string    `json:"agent"`
	// PasswordTag identifies the password hash the user had at login.
	PasswordTag string `json:"password_tag"`
}

// Sessions is the set of open sessions.
type Sessions struct {
	path string
	ttl  func() time.Duration
	now  func() time.Time

	mu     sync.Mutex
	byHash map[string]*Session
}

// OpenSessions loads the sessions file, dropping what has expired. A
// missing file is an empty set; an unreadable one is an error, and a
// corrupt one is an empty set (everybody logs in again, nobody gets in
// who should not).
func OpenSessions(path string, ttl func() time.Duration) (*Sessions, error) {
	s := &Sessions{path: path, ttl: ttl, now: time.Now, byHash: map[string]*Session{}}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	var list []*Session
	if json.Unmarshal(b, &list) == nil {
		now := s.now()
		for _, sess := range list {
			if sess.Hash != "" && now.Before(sess.Expires) {
				s.byHash[sess.Hash] = sess
			}
		}
	}
	return s, nil
}

func hashID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

// PasswordTag identifies a password hash without being one.
func PasswordTag(passwordHash string) string {
	sum := sha256.Sum256([]byte("limen-session:" + passwordHash))
	return hex.EncodeToString(sum[:8])
}

func random(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Create opens a session and returns it with its secret id.
func (s *Sessions) Create(user, passwordHash, client, agent string) (*Session, error) {
	id, err := random(32)
	if err != nil {
		return nil, err
	}
	csrf, err := random(32)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	if len(agent) > 200 {
		agent = agent[:200]
	}
	sess := &Session{
		Hash: hashID(id), User: user, CSRF: csrf,
		Created: now, LastSeen: now, Expires: now.Add(s.ttl()),
		Client: client, Agent: agent, PasswordTag: PasswordTag(passwordHash),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.byHash[sess.Hash] = sess
	if err := s.persistLocked(); err != nil {
		delete(s.byHash, sess.Hash)
		return nil, err
	}
	out := *sess
	out.ID = id
	return &out, nil
}

// Lookup returns the session a cookie id opens, if it is still valid.
func (s *Sessions) Lookup(id string) (*Session, bool) {
	if id == "" {
		return nil, false
	}
	h := hashID(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byHash[h]
	if !ok {
		return nil, false
	}
	now := s.now()
	if !now.Before(sess.Expires) {
		delete(s.byHash, h)
		s.persistLocked()
		return nil, false
	}
	sess.LastSeen = now.UTC()
	out := *sess
	return &out, true
}

// Delete closes the session a cookie id opened.
func (s *Sessions) Delete(id string) error {
	return s.DeleteHash(hashID(id))
}

// DeleteHash closes a session by its hash.
func (s *Sessions) DeleteHash(h string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byHash[h]; !ok {
		return nil
	}
	delete(s.byHash, h)
	return s.persistLocked()
}

// DeleteUser closes every session of a user but the one whose hash is
// except (the session asking, when a user changes their own password).
func (s *Sessions) DeleteUser(user, except string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for h, sess := range s.byHash {
		if sess.User == user && h != except {
			delete(s.byHash, h)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return s.persistLocked()
}

// ForUser lists the sessions of a user, newest first, without their
// secrets.
func (s *Sessions) ForUser(user string) []Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Session
	for _, sess := range s.byHash {
		if sess.User == user {
			c := *sess
			c.CSRF = ""
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}

// Count returns the number of open sessions.
func (s *Sessions) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byHash)
}

func (s *Sessions) persistLocked() error {
	if s.path == "" {
		return nil
	}
	list := make([]*Session, 0, len(s.byHash))
	for _, sess := range s.byHash {
		list = append(list, sess)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Hash < list[j].Hash })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".sessions.*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(b)
	cerr := tmp.Close()
	if err := errors.Join(werr, cerr, os.Chmod(name, 0o600)); err != nil {
		os.Remove(name)
		return fmt.Errorf("sessions: %w", err)
	}
	if err := os.Rename(name, s.path); err != nil {
		os.Remove(name)
		return fmt.Errorf("sessions: %w", err)
	}
	return nil
}
