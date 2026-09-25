package auth

import (
	"strings"
	"sync"
	"time"
)

// Limiter throttles failed logins, per username and per client
// address. Per username stops a slow guess at one account from many
// addresses; per address stops one client from trying every account.
type Limiter struct {
	Window  time.Duration
	PerUser int
	PerIP   int
	now     func() time.Time

	mu    sync.Mutex
	fails map[string][]time.Time
}

// NewLimiter allows 5 failures per user and 20 per address in 15
// minutes.
func NewLimiter() *Limiter {
	return &Limiter{Window: 15 * time.Minute, PerUser: 5, PerIP: 20, now: time.Now, fails: map[string][]time.Time{}}
}

func userKey(u string) string { return "user:" + strings.ToLower(u) }
func ipKey(ip string) string  { return "ip:" + ip }

// recent drops the failures older than the window and returns the rest.
func (l *Limiter) recent(key string) []time.Time {
	cutoff := l.now().Add(-l.Window)
	kept := l.fails[key][:0]
	for _, t := range l.fails[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(l.fails, key)
		return nil
	}
	l.fails[key] = kept
	return kept
}

// Allowed reports whether a login may be attempted, and if not, how
// long until it may.
func (l *Limiter) Allowed(user, ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var wait time.Duration
	check := func(key string, max int) {
		f := l.recent(key)
		if len(f) >= max {
			if w := f[len(f)-max].Add(l.Window).Sub(l.now()); w > wait {
				wait = w
			}
		}
	}
	check(userKey(user), l.PerUser)
	check(ipKey(ip), l.PerIP)
	return wait <= 0, wait
}

// Failed records a failed attempt.
func (l *Limiter) Failed(user, ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.fails[userKey(user)] = append(l.recent(userKey(user)), now)
	l.fails[ipKey(ip)] = append(l.recent(ipKey(ip)), now)
}

// Succeeded forgets the failures of a user. Those of the address stay:
// one right password must not reset a guessing run on other accounts.
func (l *Limiter) Succeeded(user string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, userKey(user))
}
