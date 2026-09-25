# Security policy

## Reporting a vulnerability

Report privately, through [GitHub's private vulnerability
reporting](https://github.com/ostap-mykhaylyak/limen/security/advisories/new)
(the repository's Security tab, "Report a vulnerability"). Please do not
open a public issue for something exploitable.

Include what you did, what happened, and the version (`limen
--version`). You will get an acknowledgement within a few days, and the
fix will be released with an advisory that credits you, unless you
would rather it did not.

## Supported versions

Fixes go into the latest release only. Before 1.0 there are no
maintenance branches: upgrading to the latest release is the fix.

## What limen assumes

limen is the control plane of the machine it runs on. Two properties
carry most of the weight, and a report against either is a serious one:

- **The panel is never exposed directly.** `panel.listen` must be a
  loopback address or a unix socket; the configuration refuses to load
  otherwise. Reaching it from the network means going through the nginx
  virtual host limen generates for it, with its TLS, access lists and
  rate limits.
- **nginx never reloads a configuration that has not compiled.** Every
  candidate tree is validated with `nginx -t` before it replaces the
  live one, and put back if the reload fails.

The daemon runs as root, because it writes `/etc/nginx` and signals
nginx. The shipped systemd unit narrows that root down:
`ProtectSystem=strict` with an explicit `ReadWritePaths`, no new
privileges, private devices, other users' processes hidden, a
restricted system call filter, no address families beyond the ones it
needs, and a capability bounding set of two: `CAP_CHOWN` (the files the
nginx workers read are given to their group, and `nginx -t` hands its
temporary directories to them) and `CAP_DAC_OVERRIDE` (`nginx -t` opens
logs the workers own). It has been run under real systemd, not only
written for it.

In front of the panel, nginx applies rate limits per client address:
10 requests a second with a burst of 50 for everything, and 30 a minute
with a burst of 10 for the login, answered with 429 beyond. limen
throttles failed logins itself as well (5 per user, 20 per address in
15 minutes); the nginx limit is the part that costs it nothing, since a
login is 600 000 rounds of PBKDF2.

Private keys live under `/var/lib/limen/certs` (each `privkey.pem`
`0600`) and the ACME account keys under `/var/lib/limen/acme`, both
directories `0700`. They are never part of the model, so they never
reach its history, and the API never returns them: a certificate's page
shows its validity, issuer, serial and fingerprint, nothing more. An
upload is checked (the key matches, the certificate is valid now and
covers its domains) before anything is written, and a deleted
certificate's files are moved aside, not left where nginx looked for
them. Secrets are never written to a log, and `api.log` records who
asked for what, never the credentials they used.

Logs hold personal data — client addresses, the URLs they asked for
(with a token in a query string now and then), their user agents. The
per-host logs live in a directory closed to everyone but root and
nginx's workers (0750, their group — they reopen their logs themselves
after a rotation), the API gives
their lines to operators and above, never to viewers, who see the
numbers only, and the audit trail (`api.log`) to admins only. The
metrics name every host and its traffic: `metrics.listen`, like the
panel, accepts a loopback address or a unix socket and nothing else.
nginx's own counters are answered by the default server to loopback
clients only; any other client gets its connection closed, exactly like
a request for an unknown name, so their path gives nothing away.

The ACME HTTP-01 answer is the only route of the panel that nginx
passes on for every host: it serves the key authorizations of the
tokens being validated at that moment, and 404 for anything else. The
DNS hook is run with the record and its value as arguments — never
through a shell — and only the program named in `config.yaml`, which
only root can write.

Snippets are the one place an operator writes nginx directives, and
they are the reason the panel's operators are not root on the machine.
nginx's master runs as root and opens what the configuration names —
a log path, an included file — so a free-form snippet would be a way to
write any file as root. limen never pastes a snippet: it parses it like
nginx does, refuses any block, accepts only directives from a closed
list (nothing that reads or writes a file, loads a module, changes
access or sends traffic elsewhere; `access_log` only as `off`), and
writes each directive back with every argument quoted and escaped. The
list, the parser and the quoting are covered by tests, including
against a real nginx with an argument crafted to close its block.

Passwords are stored as hashes only: PBKDF2-HMAC-SHA256 (600 000
iterations) for panel users, apr1 for access-list users because nginx
must verify those itself. The files that hold them are `0600`, and so
are their archived revisions under `/etc/limen/history`. A host whose
access list is missing at load time is not served at all, rather than
served without its guard.

Model values are checked once more at the moment they are written into
the nginx configuration: a value carrying a space, a quote, `;`, `{`,
`}`, `#` or `$` is refused and its document left out, so a value that
slipped past validation cannot inject directives. The import of an
existing configuration never brings a host in without the guard it had:
a guard limen cannot reproduce keeps the host out.

The panel's sessions live on the server and are stored by the hash of
their ids only. Who a request is made by is read from disk at every
request, so a password change, a disabled account or a demotion takes
effect at the next request, whichever tool made it. Every write needs a
per-session CSRF token, a same-origin request and a JSON body; logins
are throttled per user and per address, and cost the same whether the
user exists or not.

API tokens are for scripts. A token is 32 random bytes behind a public
id, shown once; `/var/lib/limen/tokens.json` (`0600`) keeps the id and
the SHA-256 of the secret. A token needs no CSRF token because a
browser never sends a bearer token by itself. It acts as its user, never
above the role the user has at the moment of the request, and dies with
the user: removing a user revokes its tokens, and a user made again
under the same name does not inherit them. What manages credentials —
users, tokens, passwords, sessions — is out of a token's reach, so a
leaked one cannot open itself another way in, and making one from the
panel asks for the password again. Wrong tokens count as failed logins.
A revocation, from the panel or the command line, takes effect at the
next request.

## How it is checked

- **Tests that break the code on purpose.** Every rule above has a test,
  and every test is checked by a mutant: the rule is broken in the
  source, and the suite must fail. From M1 to M8, 139 mutants, all
  caught.
- **Against the real thing.** The renderer runs against real nginx on
  the lines limen targets (the official image, Debian's and Ubuntu's
  packages):
  proxying, basic auth checked by the workers, TLS, streams, custom
  locations, snippets — one of them written to break out of its block —
  logs, rotation and rate limits. The ACME client runs against Pebble,
  Let's Encrypt's test CA. The unit runs under real systemd, and the
  Debian package is installed, started, upgraded and purged there.
- **Fuzzing.** The snippet boundary is a fuzzed property: whatever
  snippet is accepted, rendered into a host and read back the way nginx
  reads it, is one server block holding exactly the directives that
  were accepted. The parsers of outside input — access and error log
  lines, model documents, imported configurations — are fuzzed for
  panics.
- **Known vulnerabilities.** CI runs `govulncheck` on every push, for
  the standard library of the toolchain and for the dependencies.
- **Provenance.** Release files are built by the release workflow from
  the tag, listed in `SHA256SUMS`, and attested:
  `gh attestation verify FILE --repo ostap-mykhaylyak/limen` proves where
  a file came from.

## Scope

Reports about the generated nginx configuration (a directive that
weakens TLS, a header that leaks, a location that escapes its host) are
in scope, and welcome.
