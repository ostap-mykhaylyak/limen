# Contributing

## Before a pull request

```sh
make fmt
make vet
make test
```

CI runs the same three, plus `go mod tidy` with a clean diff, and
builds the static binary for amd64 and arm64.

## House rules

- **Standard library first.** The dependencies are `gopkg.in/yaml.v3`,
  `github.com/fsnotify/fsnotify` and `golang.org/x/crypto` — the last
  for its `acme` package alone: an ACME client (JWS signing, nonces,
  the order state machine, the CAs' quirks) is not a hundred lines, and
  this one is maintained by the Go team. A new dependency needs a reason
  that cannot be answered with a hundred lines of Go. Dependencies follow
  their latest release: CI runs `govulncheck` on every push, and limen
  ships as a static binary, so the Go version it needs to build is
  nobody else's concern.
- **The latest Go release.** `go.mod` asks for the current one (with
  `GOTOOLCHAIN=auto`, the default, an older `go` fetches it by itself),
  CI and releases build with `stable`, and `go fix ./...` has nothing to
  say: the code uses what the language and the standard library offer
  today.
- **Static binary.** `CGO_ENABLED=0`. Anything that would pull in cgo
  does not belong here.
- **Everything in English**: code, names, comments, messages,
  configuration, documentation.
- **The daemon is the source of truth about itself.** A second process
  does not reconstruct the state from disk; it asks through the status
  socket.
- **An invalid entry is not fatal.** Skip it, collect a warning, keep
  serving. Only an invariant that makes the service unable to work is
  worth refusing to start for.
- **Nothing reaches nginx unvalidated.** Any code path that writes the
  nginx tree goes through the candidate / `nginx -t` / reload /
  rollback cycle. No shortcuts, not even for a one-line change.
- **The interface stays inside its policy.** No inline script or
  style, no external resource, and no data through HTML parsing: build
  nodes with `h()`, set text with `textContent`, never `innerHTML`. The
  web package's tests enforce it.
- **Charts are drawn by hand, in SVG, and their colours are computed.**
  No chart library (nothing from elsewhere, and the policy holds). The
  status-class colours are chart tokens of their own in `app.css`
  (`--viz-*`), one set per theme, checked with a colour-vision
  validator against the panel's surfaces (#ffffff, #171a1f): lightness
  band, chroma, separation under colour blindness, contrast. Change one
  and check again. Identity never rests on colour alone: every chart has
  a legend, a tooltip that names its series, and a table view.
- **Comments say why, not what.** The code already says what.

## Tests

New behaviour comes with a test that would fail without it. The tests
are named after the property they defend, not after the function they
call: `TestPanelRefusesToBindBeyondLoopback` rather than
`TestValidate3`.

The suite must pass with `-race`. On a non-Linux development machine
the AF_UNIX tests skip themselves with a reason; do not add a skip for
anything else without one.

## Commits

Present tense, one concern per commit, and a body that explains the
reasoning when the change is not obvious from the diff.
