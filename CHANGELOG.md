# Changelog

Every release, newest first. The version follows [semantic
versioning](https://semver.org): before 1.0 a minor version may change
the model's files or the API, and says so here with the way across.

## v0.1.0

The first release.

### What it does

- **Model.** Proxy hosts, redirects, TCP/UDP streams, access lists,
  certificates and panel users, one YAML file each under `/etc/limen`.
  Writes are atomic and checked across documents. Every change is kept
  in a history it can be rolled back from, and a hand-edited file is
  welcome.
- **nginx.** limen owns `/etc/nginx` and renders it whole from the
  model, in generations: each is tested with `nginx -t`, a document that
  breaks it is left out and named, the tree is installed atomically, and
  a reload that fails is rolled back. `limen --import` brings an
  existing configuration into the model.
- **Certificates.** ACME with HTTP-01 through nginx and DNS-01 through a
  hook, renewed with backoff; certificates bought elsewhere can be
  uploaded; the panel can have its own.
- **Fine control.** Custom locations with their own backend and guard,
  proxy timeouts and headers, streams guarded by address, and snippets
  of nginx directives from a closed list.
- **Observability.** Per-host JSON access logs and error logs, a log
  viewer that follows, traffic and latency counted from the logs, charts
  in the panel, nginx's own counters, `limen status` with Nagios exit
  codes, and Prometheus metrics.
- **Panel and API.** A web panel with no build step and a strict CSP,
  published by nginx while it listens on loopback or a unix socket only.
  Behind it, a REST API with server-side sessions, CSRF and origin
  checks, roles (viewer, operator, admin), login throttling, rate limits
  and an audit log.
- **API tokens** for scripts (`limen token add`, or the panel's account
  menu), sent as `Authorization: Bearer`. A token acts as its user and
  never has more than the user's role. It cannot manage users or
  tokens, and is kept as a hash only.
- **Command line** for everything the panel does, working on the files
  even when the daemon is down.

### Install

- A Debian package (`limen_0.1.0_amd64.deb`, `_arm64.deb`) and a
  tarball per architecture, with checksums and build provenance.
- A systemd unit narrowed to two capabilities, a logrotate policy, and
  `--init`, which saves the existing nginx configuration before
  anything is replaced.

### Checked by

- **Tests.** Unit tests with `-race`, and integration tests against real
  nginx: the official image (1.30), and Debian's (1.22) and Ubuntu's
  (1.24) packages.
- **End to end.** An ACME run against Pebble, the unit under real
  systemd, and the package installed, started, upgraded and purged there.
- **Mutation testing.** 139 mutants of the security-relevant code, every
  one caught.
- **Fuzzing and vulnerabilities.** Every parser of outside input is
  fuzzed, and govulncheck runs in CI.
