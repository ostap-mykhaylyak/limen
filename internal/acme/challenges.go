package acme

import (
	"net/http"
	"strings"
	"sync"
)

// ChallengePrefix is where a CA looks for HTTP-01 answers. nginx sends
// that path, on every host and on the default server, to the panel —
// where Challenges answers it.
const ChallengePrefix = "/.well-known/acme-challenge/"

// Challenges holds the HTTP-01 answers of the orders in progress.
type Challenges struct {
	mu     sync.RWMutex
	tokens map[string]string
}

// NewChallenges returns an empty set.
func NewChallenges() *Challenges { return &Challenges{tokens: map[string]string{}} }

// Put publishes the key authorization of a token.
func (c *Challenges) Put(token, keyAuth string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tokens[token] = keyAuth
}

// Delete withdraws a token.
func (c *Challenges) Delete(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.tokens, token)
}

// ServeHTTP answers a challenge, and nothing else: a token that is not
// part of an order in progress is a 404, like any other path.
func (c *Challenges) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, ChallengePrefix)
	c.mu.RLock()
	answer, ok := c.tokens[token]
	c.mu.RUnlock()
	if !ok || token == "" || strings.Contains(token, "/") {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(answer))
}
