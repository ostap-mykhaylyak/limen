// Package audit carries, through a request, what the audit line of
// that request needs to know but only a later layer learns: who made
// it. The panel writes the line when the request ends; the API fills in
// the user once it has authenticated them.
package audit

import "context"

// Info is filled in while a request is served.
type Info struct {
	User   string
	Action string // what the request changed, when it changed something
}

type key struct{}

// With returns a context carrying a fresh Info.
func With(ctx context.Context) (context.Context, *Info) {
	info := &Info{}
	return context.WithValue(ctx, key{}, info), info
}

// From returns the Info of a request, or a throwaway one when the
// request carries none (tests, a handler mounted without the panel).
func From(ctx context.Context) *Info {
	if info, ok := ctx.Value(key{}).(*Info); ok {
		return info
	}
	return &Info{}
}
