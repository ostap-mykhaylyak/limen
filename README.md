# limen

An nginx manager with a web panel and a command line, in a single
static Go binary.

limen owns the nginx configuration of the machine. Proxy hosts,
redirects, TCP/UDP streams, access lists and certificates are described
in its own model; the whole nginx tree is rendered from that model,
validated with `nginx -t` before anything is replaced, and reloaded
only once the candidate has passed.

**The panel never faces the network.** It listens on loopback, or on a
unix socket, and is published by a virtual host that limen generates
for the nginx it manages — with the same TLS, the same access lists and
the same rate limits as any other backend. The configuration refuses to
load if you point `panel.listen` anywhere else: the control plane of
the machine has no business being reachable directly.

## Status

`limen` **v0.1.0** is the first release. It drives nginx, it has its web panel, it
issues and renews its certificates, a host can be tuned part by part —
custom locations with their own backend or guard, the conversation with
the backend, hand-written directives checked against a closed list —
and it shows what nginx serves: every host's own request and error
logs, a log viewer, and traffic metrics counted from those logs, in the
panel, in `limen status` and for Prometheus. The model (proxy hosts, redirects,
streams, access lists, certificates, panel users — one YAML file each,
with history and rollback) is rendered into a complete nginx
configuration, tested with `nginx -t`, installed atomically and
reloaded, with the previous generation put back when nginx refuses it.
Certificates come from any ACME CA — HTTP-01 answered through nginx,
DNS-01 through a hook for wildcards — or are uploaded, and their expiry
is watched either way. An existing nginx configuration can be imported.
The model is managed from the command line, from the REST API, and from
the web interface built on it — with sessions, roles and an audit trail
— and scripts use it with API tokens.

Tested against a real nginx on the lines limen targets: the official
image (1.30, stream built in), and Debian's (1.22) and Ubuntu's (1.24)
packages, with stream loaded as a dynamic module — proxying, basic auth checked by the workers,
TLS with HTTP/2 and HSTS, streams guarded by address, custom locations
and snippets (including one written to break out of its block), and the
failure paths. The ACME
client is tested against [Pebble](https://github.com/letsencrypt/pebble),
Let's Encrypt's own test CA: issuance over both challenges, the panel's
certificate, renewal served by nginx without a restart, and a name the
CA cannot validate.

## Install

limen runs on Linux, next to the nginx it manages (1.22 or later). Each
[release](https://github.com/ostap-mykhaylyak/limen/releases) has a
Debian package and a tarball for amd64 and arm64, a `SHA256SUMS`, and
signed build provenance.

### Debian and Ubuntu

```sh
v=0.1.0 arch=$(dpkg --print-architecture)
base=https://github.com/ostap-mykhaylyak/limen/releases/download/v$v
curl -LO $base/limen_${v}_${arch}.deb -LO $base/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
# optional: proof that this repository's workflow built it
gh attestation verify limen_${v}_${arch}.deb --repo ostap-mykhaylyak/limen
sudo apt install ./limen_${v}_${arch}.deb
```

apt brings nginx along when it is missing. The package installs the
binary, the systemd unit and the logrotate policy, prepares the layout,
and **copies the existing `/etc/nginx` into `/var/lib/limen/backup/`**,
the way back to whatever the machine was serving before. It does not
take nginx over: that happens when limen starts, or at the first change
the command line makes to what nginx serves (a user is not one), and
it is your call.

```sh
sudoedit /etc/limen/config.yaml      # panel.hostname, acme.contact_email
sudo limen --import                  # optional: what of the current sites can come along
sudo limen user add ostap --role admin --password-stdin
sudo systemctl enable --now limen
limen status
```

### Any other Linux

```sh
tar -xzf limen-v0.1.0-linux-amd64.tar.gz
sudo ./limen-v0.1.0-linux-amd64/limen --init
sudo systemctl daemon-reload
sudo systemctl enable --now limen
```

`--init` does what the package does and, having no package to do it,
installs the binary in `/usr/sbin`, the unit in `/etc/systemd/system`
and the logrotate policy itself. Where the package is installed it
leaves those alone: a unit in `/etc` would shadow the package's, and
keep an old one in charge after every upgrade. From a checkout,
`make static` builds `bin/limen` and `make install` installs it.

The binary also provisions itself: started with no configuration at
all, it creates the default layout from its embedded skeleton, says so
on stderr, and carries on.

The unit it installs has been run under real systemd, with nginx as a
Debian service beside it: install, enable, the CLI's writes, applies by
the daemon, a forced logrotate with the shipped policy, restart and
stop. Its sandbox is narrow — `ProtectSystem=strict` with the few paths
limen writes, private devices and `/tmp`, other users' processes
hidden, a system call filter, and two capabilities out of root's forty:
`CAP_CHOWN` and `CAP_DAC_OVERRIDE`, which `nginx -t` and the per-host
logs need. `systemd-analyze security limen` rates it 2.2.

## Running in production

Before the machine takes traffic:

- `panel.hostname` on a name only you use, with `panel.certificate:
  acme` (or a certificate of the model) and `secure_cookies` left on —
  or no hostname at all, and the panel through an SSH tunnel;
- `acme.contact_email` set: the CA writes there before a certificate
  limen could not renew expires;
- two admins, so that one lost password is not a locked door;
- scripts on [API tokens](#api-tokens) with the least role they need
  and an expiry, never on a person's password;
- `limen status` in the monitoring you already have (its exit codes
  follow the Nagios convention), or `metrics.listen` scraped by
  Prometheus;
- the backups below, and a restore tried once.

### Upgrades

With the package, `sudo apt install ./limen_<version>_<arch>.deb`: a
running limen restarts on the new binary. nginx keeps running: limen
reloads it only if the new version renders a different configuration,
and tests that with `nginx -t` first, like any change. With the tarball,
replace `/usr/sbin/limen` and `systemctl restart limen`. Read the
[changelog](CHANGELOG.md) first: before 1.0 a minor version may change
the files, and says how to cross.

### Backups

Two directories are the whole state:

- `/etc/limen`: the configuration and the model, with its history;
- `/var/lib/limen`: certificates and their keys, ACME accounts, the
  sessions and the API tokens (both by hash only).

```sh
sudo tar -czf limen-$(date +%F).tar.gz -C / etc/limen var/lib/limen
```

The archive holds private keys and password hashes: keep it the way you
would keep them. The nginx configuration needs no backup, since limen
renders it from the model. To restore, on a machine with limen
installed: `systemctl stop limen`, unpack the archive in `/`, `systemctl
start limen`; it renders the nginx tree, tests it and installs it.

### Uninstall

`apt remove limen` stops limen and removes the binary; nginx keeps
serving the last configuration limen installed, except the panel's
host, which answers 502. `apt purge limen` also removes the logs, and
keeps `/etc/limen` and `/var/lib/limen`: some certificates cannot be
issued again. To go back to the nginx of before limen, copy
`/var/lib/limen/backup/nginx-<time>/` over `/etc/nginx` and reload
nginx. `limen --purge`, run before the package is removed, deletes the
configuration, the data and the logs outright.

## Command line

Service verbs and object commands are bare words; the one-shot
operations on the machine carry the dashes.

```
start          run the daemon in the foreground (what systemd does)
stop           signal the running daemon to shut down
reload         re-read the configuration and the model, reopen the logs
restart        stop the running daemon, then start it again
status         query the running daemon and print what it is doing

host           proxy hosts:  list, show, add, set, rm, enable, disable, location, logs
redirect       redirects:    list, show, add, set, rm, enable, disable
stream         TCP/UDP:      list, show, add, set, rm, enable, disable
access         access lists: list, show, add, set, rm, passwd, deluser
cert           certificates: list, show, add, set, rm, renew, import
user           panel users:  list, show, add, set, rm, enable, disable, passwd
token          API tokens:   list, add, rm
history        past revisions of an object
rollback       put a past revision back
apply          render, test with nginx -t, install, reload (--dry-run)
logs           nginx-error, nginx-access, limen, apply, api (-n, --follow, --grep)

--init         install layout, binary, systemd unit, logrotate policy
               (--packaged: the layout only, what the Debian package runs)
--purge        remove config, data and logs (asks for confirmation)
--check-config parse the configuration, print what it says, then exit
--import       bring an existing nginx configuration into the model
--version      print the version and exit
--help         print the usage
```

Common flags: `--config <file>`, `--socket <path>`, `--pidfile <path>`.

### Objects

```sh
# the first user must be an admin
limen user add ostap --role admin --email ostap@example.com --password-stdin

# a key for a script: printed once, on stdout alone
limen token add deploy --user ostap --role operator --expires 90d > deploy.token

# an access list: rules are evaluated in order, the first match wins
limen access add office --rule allow:10.0.0.0/8 --rule deny:all
limen access passwd office ops          # a basic-auth user, password from stdin

# a proxy host, named after its first domain when no name is given
limen host add --domain app.example.com --forward http://10.0.0.5:8080 \
    --websockets --access-list office

limen redirect add old --domain old.example.com --to https://app.example.com
limen stream add pg --listen 5432 --forward 10.0.0.9:5432

limen host set app.example.com --forward 10.0.0.6:8080 --note "moved backend"
limen host list

# a certificate limen issues and renews, and a host served with it
limen cert add app --domain app.example.com --domain www.app.example.com
limen host set app.example.com --certificate app --force-https

# a wildcard: DNS-01 is the only way, and needs acme.dns_hook
limen cert add apps --domain '*.apps.example.com'

# one bought elsewhere: checked, then installed; its domains come from it
limen cert import shop --chain fullchain.pem --key privkey.pem

# parts of a host: /api/ to another backend, behind another list;
# an exact path open to everyone, answered by nginx itself
limen host location add app.example.com /api/ --forward http://10.0.0.7:9000 --access-list office
limen host location add app.example.com =/health --public --snippet-file health.conf
limen host location list app.example.com

# the conversation with the backend, and a snippet for the whole host
limen host set app.example.com --read-timeout 1h --stream-responses \
    --request-header "X-Env: production" --response-header "X-Frame-Options: SAMEORIGIN" \
    --snippet-file app.conf

# a stream only some addresses may reach
limen stream set pg --access-list office
```

`set` changes only the flags you pass. Every write accepts `--note`,
kept in the history next to the revision it replaced:

```
$ limen history host api
Each revision is the document as it was just before the change on its line.
REVISION                    WHEN                 CHANGE  BY          VIA  NOTE
20260924T045408.396937204Z  2026-09-24 04:54:08  update  cli:ostap   cli  new port

$ limen rollback host api 20260924T045408.396937204Z
```

A rollback is a write like any other: it is validated, it archives
what it replaces (so it can be undone), and it is refused if the old
revision no longer fits — say, its domain has been taken since. A
deleted object has a history too, and comes back the same way.

The command line works on the files, not through the daemon, so it
keeps working when the panel is down. It takes the same lock the panel
takes, re-reads the model under it, applies the change to nginx at once
— so you see right away whether nginx took it — and then asks the
running daemon to reload.

```
$ limen host add --domain new.example.com --forward 127.0.0.1:3000
proxy host "new.example.com" saved
nginx: generation 20260924T081045-21008c19038b installed and reloaded
the running daemon has been asked to reload the model
```

What the model refuses, and why:

| refused | because |
|---|---|
| a domain served by two hosts or redirects | nginx would pick one silently |
| a host guarded by an access list that does not exist | on load, such a host is **not served at all**: serving it without its guard would expose what it protects |
| deleting an access list still in use | its hosts would be left broken or open |
| a host or redirect on a certificate that does not exist | a typo would otherwise serve plain HTTP for good |
| deleting a certificate still in use | its hosts would lose HTTPS |
| a wildcard certificate over HTTP-01 | the CA cannot prove a wildcard that way |
| a location on an access list that does not exist | on load, **the whole host** is not served: a part of it would be open |
| a stream on an access list with users | a TCP client cannot be asked for a password; the list must be address rules only |
| a user added to a list that guards a stream | the stream would silently ignore the password |
| a snippet directive outside the list | see [Snippets](#snippets) |
| two streams on the same port and protocol | the configuration would fail to bind |
| removing, demoting or disabling the last active admin | nobody could log in to create another |
| deleting, disabling or unprotecting a protected object | it is the panel's own door |
| an unknown field in a hand-written file | `acess_list: office` would otherwise publish the host unguarded |

Loading is forgiving, writing is strict: a broken file found at load
time is skipped with a warning (in `limen status`, in `limen.log`, in
`limen --check-config`) and every other object keeps being served.

Passwords never reach the files in clear. Panel users are hashed with
PBKDF2-HMAC-SHA256 at 600 000 iterations, from the standard library;
access-list users with apr1, the format `htpasswd -m` writes, because
nginx is the one that checks them. Neither hash is ever printed:
`show` hides them and `--json` leaves them out.

### status

`limen status` is a **client**, not a disk scan. It connects to the
local socket the daemon serves and prints the snapshot it gets back:
the daemon is the only thing that knows what it has in memory, what it
last applied, and how many requests are in flight. If the socket does
not answer, the service is down — and the command says exactly that,
adding only whether a valid configuration exists on disk, so that
"installed but stopped" is distinguishable from "never installed".

```
$ limen status
limen OK - active, pid 2208, up 4h 12m, config valid, 7 host(s) / 5 cert(s), nginx up

SERVICE
  version        v0.1.0
  uptime         4h 12m
  config         /etc/limen/config.yaml
  nginx          running (/etc/nginx)
  last apply     3m12s ago (ok)

MODEL
  hosts 7  redirects 2  streams 1  access lists 3  users 2  certs 5

LIVE
  requests       1841 total, 3 failed, 0 in flight  (0.4 req/s)
  logins         12 ok, 1 failed
  applies        31 ok, 0 failed, 0 rollback(s)
  certificates   5 issued, 4 renewed, 0 failed

TRAFFIC (last 5 minutes)
  nginx          14 connection(s): 1 reading, 3 writing, 10 waiting; 7.4 req/s
  app.example.com                 5.12 req/s    0.4% 5xx  p95 182ms
  api.example.com                 0.38 req/s    0.0% 5xx  p95 1.21s
```

`--json` prints a stable machine-readable object (the field names are a
contract: dashboards are built on them), and `--watch 2s` redraws the
report like `top`, turning the counters into live rates. In JSON mode
`--watch` streams one object per tick, ready to pipe into a collector.

Exit codes follow the Nagios convention, so the command is a drop-in
check for any monitor: `0` OK, `1` WARNING, `2` CRITICAL, `3` UNKNOWN.
The worst check wins.

## Configuration

`/etc/limen/config.yaml` describes the daemon itself and nothing else.
Every field has a production default, so the file may be sparse or
empty. It is re-read when it changes, and on `SIGHUP`; a file that does
not validate is rejected and the previous configuration stays in force.

```yaml
panel:
  listen: "127.0.0.1:9187"   # loopback or a unix socket path. Nothing else.
  hostname: "limen.example.com"
  trusted_proxies: ["127.0.0.1/32", "::1/128"]
  session_ttl: "12h"

nginx:
  bin: "/usr/sbin/nginx"
  conf_dir: "/etc/nginx"
  user: "www-data"
  worker_processes: "auto"

acme:
  enabled: true
  directory: "https://acme-v02.api.letsencrypt.org/directory"
  contact_email: "you@example.com"
  renew_before: "720h"
  dns_hook: "/usr/local/bin/limen-dns-hook"   # for wildcards

metrics:
  listen: "127.0.0.1:9188"   # Prometheus, loopback or a unix socket; empty: off

log:
  level: "info"
```

The objects limen manages are **not** in this file. Each one is a YAML
document of its own, so the model stays readable — and editable — from
a shell when the panel is down:

```
/etc/limen/hosts/app.example.com.yaml
/etc/limen/redirects/old.example.com.yaml
/etc/limen/streams/postgres.yaml
/etc/limen/access/staff-only.yaml
/etc/limen/certificates/app.yaml
/etc/limen/users/ostap.yaml
```

`panel.hostname` is the virtual host limen generates for itself. It is
**protected**: the interface cannot delete or rename it, because that
is the door you would be locking yourself out of. Leave it empty to
publish nothing and reach the panel through an SSH tunnel instead.
`panel.certificate: acme` has limen issue the panel's own certificate
(a protected certificate named `limen-panel`); a certificate name uses
one of the model.

## Certificates

A certificate is a document like the others — its domains, its
provider, and for ACME the challenge and the key type — and hosts and
redirects refer to it by name. Its files live apart, under
`/var/lib/limen/certs/<name>/` (`fullchain.pem`, `privkey.pem` 0600,
`status.json`), because keys have no place in a history that is kept
forever.

```
$ limen cert list
NAME   DOMAINS                               PROVIDER   STATE     EXPIRES           USED BY
app    app.example.com,www.app.example.com   acme/http  valid     2026-12-23 (89d)  proxy host app.example.com
apps   *.apps.example.com                    acme/dns   valid     2026-12-23 (89d)  proxy host one.apps.example.com
shop   shop.example.com                      custom     expiring  2026-10-14 (19d)  proxy host shop.example.com
```

**ACME.** The renewal loop orders what is missing, what is due
(`acme.renew_before` before expiry, 30 days by default) and what an
operator asked for (`limen cert renew`, "Renew now" in the panel), one
certificate at a time, and has nginx pick up each one as soon as it is
written — a renewed certificate is served without waiting for the rest.
A failure is kept with the CA's own words and retried after 10 minutes,
then 1 hour, 6 hours, 24 hours; a request from an operator skips the
wait. A chain and key that do not form a valid pair are never
installed, whatever the CA sent. One ACME account per directory, so
staging and production never share a key.

- **HTTP-01** is answered by limen through nginx: every server,
  including the default one and those behind an access list, passes
  `/.well-known/acme-challenge/` to the panel's listener. Nothing else
  is exposed, and a token that is not being validated answers 404.
- **DNS-01** — the only way to a wildcard — runs `acme.dns_hook`:
  `hook present <record> <value>` before asking the CA, `hook cleanup
  <record> <value>` afterwards, whatever happened. `<record>` is the
  full name, `_acme-challenge.example.com.`. The hook is yours: a few
  lines around your DNS provider's API. limen waits up to
  `acme.dns_wait` to see the record itself, then lets the CA decide.

**Uploaded certificates** (`provider: custom`) are never ordered. They
are installed with `limen cert import` or the panel's upload form,
after the same checks — the key matches, the certificate is valid now
and covers every domain of the document — and their expiry is watched
like the others: `limen status` warns once one is within
`acme.renew_before` of its end.

nginx is never pointed at files that are not there: a host whose
certificate has not been issued yet is served over plain HTTP, with a
warning, and switches to HTTPS at the apply that follows its issuance.
Each host file records the serial and fingerprint of the certificate it
was rendered with, so a renewal is a change of the tree and nginx is
reloaded. A deleted certificate's files move to
`/var/lib/limen/certs/.trash/`, since an uploaded one cannot be issued
again if the deletion is rolled back.

## Locations, proxy options and snippets

A proxy host sends everything to its backend. A **custom location**
takes a part of it — a prefix like `/api/`, or one exact path — and
changes what happens there: another backend, websockets, another
access list or none at all (`public`: a webhook under a guarded admin
site), and a snippet of its own.

```yaml
locations:
  - path: /api/
    forward: {scheme: http, host: 10.0.0.7, port: 9000}
    access_list: office
  - path: /health
    exact: true
    public: true
    snippet: |
      access_log off;
      return 200 "ok";
```

When the host caches static assets, the rule lives inside each location,
so a stylesheet under `/api/` still goes to `/api/`'s backend.

Guards are complete wherever they are written. An access list's file
states both mechanisms — `satisfy`, its rules or `allow all`, its
passwords or `auth_basic off` — so a location that uses its own list
does not inherit half of the host's: a list of addresses under a host
guarded by passwords stops asking for them, and `satisfy any` is only
written when a list really has both halves. A location that has lost
its list fails closed: the whole host is left out, not just that part.

**Proxy options** (`proxy:` in the file, "Advanced" in the panel) say how
nginx talks to the backend: connect, read and send timeouts, responses
and uploads streamed instead of buffered (server-sent events, long
polling, large uploads), the `Host` the backend sees (the client's, the
backend's own address, or a name), and headers set on the request or
added to every response — values may use nginx variables
(`$request_id`). They apply to every location of the host.

### Snippets

A snippet is nginx directives written by hand, for a whole host (every
one of its locations) or for one location: the escape hatch for what the
model does not say. It is not pasted into the configuration:

- limen reads it the way nginx reads a configuration, and refuses a
  block — `{` where nginx would open one, `}` where it would close the
  enclosing one;
- every directive must be on a closed list: headers (`add_header`,
  `proxy_set_header`, `proxy_hide_header`, ...), timeouts and buffers,
  `client_max_body_size`, `gzip*`, `sub_filter*`, `expires`, `return`,
  `rewrite`, `error_page`, `set`, redirects' ports and names,
  `access_log off` — nothing that reads or writes a file (`include`,
  `root`, a log path, which nginx's root master would open), loads code,
  opens or closes access (`allow`, `auth_basic`: that is an access
  list's job), or sends the traffic elsewhere (`proxy_pass`, `mirror`);
  a refusal names the line and says why;
- limen writes every directive back itself, every argument quoted and
  escaped, so a `;` or a `}` inside an argument is data. The integration
  test gives a location `return 200 "ok;} server { listen 8081; \"";` and
  checks that nginx answers exactly that string and opens nothing on
  8081;
- a directive replaces the one limen would have written for the same
  thing — `proxy_read_timeout`, `proxy_set_header Host`, an `add_header`
  of the same name — instead of repeating it: nginx refuses a duplicate
  timeout and sends a header set twice twice. A location's snippet comes
  after the host's, so it wins.

What nginx still refuses (an unknown variable, a bad regular
expression) is caught by `nginx -t` like everything else, and only that
host is left out.

**Streams** take an access list too, of address rules only: nginx checks
a TCP or UDP client by its address, there is no request to carry a
password. A stream whose list has gained users, or lost its rules, is
not served.

## Logs and traffic

Every proxy host has **its own logs**, under `nginx.host_logs`
(`/var/log/nginx/limen`): `<name>.access.log`, one JSON object per
request, and `<name>.error.log`, nginx's errors for that host only. The
access log is written with `escape=json`, so whatever a client puts in
a URL, a user agent or a referer comes back as the string it sent,
never as a broken line. A host can keep its requests out of the logs
(`log_requests: false`, "Log requests" in the panel); it keeps its error
log.

```
$ limen host logs app.example.com --status 5xx -n 3
2026-09-25 05:17:39  502  GET    app.example.com/page/3  3ms  0B  203.0.113.9  -> 10.0.0.5:8080
$ limen host logs app.example.com --errors --follow
$ limen logs apply --grep reload
```

`limen logs` reads the logs that are not a host's: `nginx-error`,
`nginx-access` (requests for no known name), and limen's own `limen`,
`apply` and `api`. Every one takes `-n`, `--follow`, `--grep` and
`--json`.

**The traffic is counted from those logs.** The daemon follows every
host's access log and keeps, in memory, a minute-by-minute hour and a
five-minute day: requests by status class, bytes, and a latency
histogram for p50, p95 and p99. When it starts it reads back the last
day from the end of the files — the current one and yesterday's
rotation, which the shipped policy leaves uncompressed — so a restart
does not blank the charts;
those requests are not added to the Prometheus counters, which count
only what limen saw arrive. A rotation loses nothing and counts nothing
twice: logrotate puts the new file in place before nginx is told to
reopen, so the old one is read on until it falls quiet. nginx's own counters — connections reading, writing and waiting,
requests per second — come from its `stub_status`, which the default
server answers to loopback clients only (anyone else gets the
connection closed, like any request for an unknown name).

`limen status` shows the busiest hosts of the last five minutes and
warns when one answers more than 5% of 5xx (with 20 requests or more).
With `metrics.listen` set, `/metrics` serves the Prometheus text format:
requests by host and status class, bytes, the latency histogram,
nginx's connections, limen's applies, reloads and certificate orders,
and when each certificate expires.

## The web panel

The panel is published at `panel.hostname` by the protected virtual
host limen writes for itself, and lives in the binary: one page, one
stylesheet, one script, no build step, no framework, nothing fetched
from anywhere else.

- **Overview**: what nginx serves and whether it serves what the model
  says — the live generation, the last apply, every document the last
  apply had to leave out and why, the health checks.
- **Proxy hosts, redirects, streams, access lists, certificates,
  users**: lists with a filter, a page per document with its settings
  and its history, an editor, enable and disable, delete, and "Restore"
  on any past revision.
- **Certificates** show their state (valid, expiring, expired, pending,
  failed), their validity, issuer and serial, the last attempt, the
  CA's reason for a failure and the next try — with "Renew now" for
  ACME and an upload form for the others. A host's editor offers the
  model's certificates, or a new one for the host's domains, requested
  on save.
- **Traffic**: the overview has nginx's connections, the requests of
  every host per minute stacked by status class, and the busiest hosts;
  a host's page has its own requests, error rate, p50/p95/p99 and a
  latency chart, over 5 minutes, an hour or a day. Every chart has a
  table view and a tooltip, by pointer or keyboard.
- **Logs**: a host's requests and errors, and the system logs, filtered
  by text or status, followed live. Operators only: logs hold client
  addresses and URLs. The audit log is the admins'.
- A host's editor has its **custom locations** (path, exact or prefix,
  the host's backend or its own, the host's access list, another one or
  none, websockets, a snippet), its **advanced** proxy options and
  headers, and its snippet; the save answers with the line a refused
  snippet stumbled on.
- Saving applies at once. What nginx made of the change comes back as a
  notice: installed and reloaded, nothing to change, or left out — with
  the reason nginx gave.
- A document the last apply left out says so in its list ("Left out")
  and on its page, instead of looking enabled.
- What a role may not do is not offered: viewers get no edit buttons,
  only admins see users. The API enforces the same on its own.
- Light and dark themes, following the system or chosen; usable on a
  phone.

The interface runs under a Content-Security-Policy that allows this
origin only and nothing inline (`default-src 'none'; script-src 'self';
style-src 'self'; ...`). No data ever reaches the page through HTML
parsing: every node is built with `createElement`, every text set with
`textContent`, so a hostname or a description containing markup is shown
as text. A test fails the build if `innerHTML`, `eval`, an inline style,
an inline script or an external URL ever appears in the sources.

The design system is the one of the other panels (tokens, components,
the distinction between interface text and machine data in monospace).

## The panel's API

The API lives under `/api/v1` on the panel's address, and is published
with it by the protected virtual host limen writes for `panel.hostname`.
It speaks JSON both ways and is what the web interface uses; a script
uses it the same way, with an [API token](#api-tokens).

```
POST   /api/v1/session                 log in {username, password}
GET    /api/v1/session                 who am I, and the CSRF token
DELETE /api/v1/session                 log out
PUT    /api/v1/session/password        change my password {current, new}
GET    /api/v1/status                  the full report of `limen status`
GET    /api/v1/apply                   the last apply
POST   /api/v1/apply                   apply now {dry_run}

GET    /api/v1/{collection}            hosts, redirects, streams,
POST   /api/v1/{collection}            access-lists, certificates, users
GET    /api/v1/{collection}/{name}
PUT    /api/v1/{collection}/{name}     a full replacement, like a file
DELETE /api/v1/{collection}/{name}
GET    /api/v1/{collection}/{name}/history
POST   /api/v1/{collection}/{name}/rollback   {revision}

POST   /api/v1/certificates/{name}/renew      issue again now (ACME)
POST   /api/v1/certificates/{name}/upload     {chain, key} (custom)

GET    /api/v1/traffic?window=5m|1h|24h       nginx, every host, the sum over time
GET    /api/v1/hosts/{name}/traffic?window=   a host: summary and series
GET    /api/v1/hosts/{name}/logs/access|error ?lines= &q= &status=5xx &after=OFFSET
GET    /api/v1/logs/{stream}                  nginx-error, nginx-access, limen, apply, api

GET    /api/v1/tokens                  my API tokens (an admin: everybody's)
POST   /api/v1/tokens                  {name, role, expires_days, description, password}
DELETE /api/v1/tokens/{name}           revoke
```

A log page answers its lines, oldest first, and an `offset`: asking
again with `after=` that offset returns what was written since, which is
how the panel follows a log. Traffic is for every role; logs need an
operator, and the `api` stream an admin.

A certificate comes with `state` — the state, the files' validity,
issuer, serial and names, the attempts and the last error — and
`used_by`. Both are ignored when sent back.

A write answers with what was stored and with what nginx made of it
(`item`, `apply`). `X-Limen-Note` sets the note kept in the history.

**Roles.** A *viewer* reads; an *operator* also writes hosts, redirects,
streams, access lists and certificates, renews, uploads, and applies; an *admin* also manages users,
whom nobody else can even list. The role is read from the model at every
request: a demotion bites at the next click.

**Sessions.** Logging in sets a `__Host-limen_session` cookie (HttpOnly,
Secure, SameSite=Strict) and returns a CSRF token. The session lives on
the server; its file keeps only the hash of the id, so it opens nothing
if it leaks, and a restart logs nobody out. A session ends at its
`panel.session_ttl`, at logout — and as soon as its user's password
changes, or the user is disabled or deleted, **from the panel or from the
command line**: who a request is made by is read from disk at every
request, not from an index that waits for a reload.

**Writes.** Every write needs the session's token in `X-CSRF-Token`, a
same-origin request (`Origin`, `Sec-Fetch-Site`), and a JSON body — a
cross-site form can send none of the three. Bodies are strict: an
unknown field is an error, not a setting that silently does nothing.

<a id="api-tokens"></a>**API tokens.** A script sends `Authorization: Bearer limen_<id>_<secret>`,
and needs no cookie, no CSRF token and no `Origin`: a browser never
sends a bearer token by itself, so there is no cross-site request to
guard against. Make one with `limen token add NAME --user USER` or from
the panel's account menu, which asks for your password again. It is
shown once; limen keeps the id, which finds it, and the SHA-256 of the
secret, which opens nothing.

```sh
curl -H "Authorization: Bearer $(cat deploy.token)" https://limen.example.com/api/v1/status
```

A token acts as its user, with its own role or a lower one — never above
what the user can do *now*, so a demotion bites the user's tokens too.
It stops working when it expires, when it is revoked (from the panel, or
`limen token rm`, effective at the next request), when its user is
disabled, and for good when its user is removed: the tokens go with the
user, and a new user of the same name inherits nothing. A token cannot
manage users or tokens, change a password, or open a session: a leaked
token must not be able to make itself another way in. Wrong tokens count
as failed logins, and every request made with one lands in `api.log` as
`user (token name)`, and in the history as `api:user:name`.

**Logins.** A wrong password and an unknown user get the same answer,
at the same cost. Five failures per user or twenty per address in
fifteen minutes and further attempts wait (`429`, `Retry-After`). A
password hash made with fewer iterations than today's is upgraded at
the next login.

What the API will not do:

- touch a protected document — the panel's own host comes from
  `config.yaml`, and an edit here would be undone at the next reload;
- make a document protected;
- point a host at a unix socket: that would let an operator publish
  `/var/run/docker.sock` through nginx, which is root on the machine;
- return a password hash, of either kind, anywhere.

`/healthz` is the only route without a login, and once the panel is
published it answers anyone: it returns `{"status": "ok"}` (or `warn`,
`crit` with a 503) and nothing else.

Every request lands in `api.log` with the user behind it and, for a
write, its note.

## Importing an existing configuration

`limen --init` backs up `/etc/nginx` before limen takes it over.
`limen --import` reads that backup and brings into the model what it can
bring **faithfully**; without `--write` it only shows the plan.

```
$ limen --import
Reading /var/lib/limen/backup/nginx-20260924T081041Z/nginx.conf

Would import:
  access list  admin.example.com-access   1 user(s), 0 rule(s)
  proxy host   admin.example.com          admin.example.com -> http://127.0.0.1:8081 guarded by admin.example.com-access
  proxy host   app.example.com            app.example.com -> http://127.0.0.1:3000 (TLS, forced)

Certificates to copy into limen:
  app.example.com                  from /etc/letsencrypt/live/app.example.com/fullchain.pem

Left out:
  - server shop.example.com (.../sites-enabled/shop:1): .../sites-enabled/shop:5: location ~ \.php$: limen keeps prefix and exact locations, not regular expressions or named ones

Nothing was written. Run again with --write to import.
```

It understands proxy servers (with websockets, body size, single-server
upstreams, unix sockets), redirects, streams, TLS certificates (copied
into limen's store), HSTS, HTTP/2, basic auth with its users and
address rules — and the configuration certbot leaves behind, `if ($host
= ...)` redirects included. Prefix and exact locations that proxy or
answer become custom locations; what they hold besides their backend
and websockets becomes their snippet, when every directive is on the
list. It never approximates:

- a server that serves files, runs PHP, balances across backends,
  rewrites paths, has a regular-expression location, or a location with
  a directive a snippet may not hold, is **left out**, with the file,
  the line and the reason;
- a location with a guard of its own is left out too: give it an access
  list after the import;
- a server guarded in a way limen cannot keep (`auth_request`, client
  certificates, an `if` it cannot read, passwords hashed with anything
  but apr1) is **not imported at all**: imported without its guard, it
  would be open;
- nothing already in the model is overwritten;
- what is dropped on the way (gzip, tuning, extra headers) is listed.

## Layout

```
/usr/sbin/limen               the binary
/usr/lib/systemd/system/limen.service
                              the unit, from the package (--init: /etc/systemd/system)
/etc/limen/config.yaml        daemon configuration
/etc/limen/{hosts,redirects,streams,access,certificates,users}/
                              one YAML document per managed object
/etc/limen/history/           previous revision of every rewritten document
/var/lib/limen/certs/         certificate files, keys and attempts, per certificate (0700)
/var/lib/limen/acme/          ACME account keys (0700)
/var/lib/limen/sessions.json  the panel's sessions, by the hash of their ids (0600)
/var/lib/limen/tokens.json    the API tokens, by the hash of their secrets (0600)
/var/lib/limen/backup/        the nginx tree as it was before limen
/etc/nginx/nginx.conf         generated by limen
/etc/nginx/limen -> limen.d/<generation>
                              the live tree (a symlink, swapped atomically)
/etc/nginx/limen.d/           the last generations, to roll back to
/etc/nginx/nginx.conf.before-limen
                              the distribution's nginx.conf, kept on first install
/var/log/limen/limen.log      daemon lifecycle, reloads, renewals
/var/log/limen/api.log        every panel request: the audit trail
/var/log/limen/apply.log      every render, test and reload of nginx
/var/log/nginx/limen/         each host's <name>.access.log (JSON) and <name>.error.log
                              (0750, root and the nginx workers' group)
/run/limen/limen.sock         local status socket
/run/limen/limen.pid          pidfile
```

Rotation is logrotate's job, not the binary's: the shipped policy sends
`SIGHUP`, and limen reopens every stream in place — and tells nginx to
reopen the per-host logs (`SIGUSR1`), which the same policy rotates.

## How a change reaches nginx

1. The model is edited: from the command line, by hand (then `limen
   reload`), or — from M3 — from the panel.
2. limen renders the **whole** tree into a new generation under
   `/etc/nginx/limen.d/`. Every include is relative, and nginx resolves
   relative includes against the directory of the file it is started
   with: the same bytes are tested where they are and later run from
   `/etc/nginx`. There is one rendering, never a second one "for real".
3. If the rendering is byte for byte the one already live, nothing
   happens — the daily `SIGHUP` of logrotate does not reload nginx.
4. `nginx -t` runs against the generation. When it pins an error on a
   file, the document that file came from is **left out** and the rest
   is tried again: one host whose backend does not resolve does not keep
   every other change from reaching nginx. An error nobody owns (the
   worker user does not exist) stops the apply, and nothing moves.
5. The generation becomes live: the `limen` symlink and `nginx.conf` are
   each replaced by a rename, and nginx is reloaded.
6. The reload is watched in nginx's error log. The one failure `nginx
   -t` cannot see is a port another program holds — it binds nothing.
   When that happens the previous generation is put back at once; if
   the port belongs to a stream, that stream is left out and the rest is
   applied.

Model values never reach the configuration unchecked: anything with a
space, a quote, `;`, `{`, `}`, `#` or `$` is refused at the last moment
and its document left out, so a value that slipped past validation
cannot write directives for the whole machine.

Every apply lands in `apply.log`, and `limen status` shows the live
generation, whether the model is ahead of it, and what was left out.

What the generated configuration does on purpose:

- **Unknown names get nothing**: port 80 closes the connection (444),
  port 443 refuses the TLS handshake instead of showing some host's
  certificate.
- **`X-Forwarded-For` is the client's address**, not appended to what
  the client sent: nginx is the edge, and a backend reading the first
  entry would otherwise believe whatever the client wrote there.
- **ACME challenges reach limen** on every host, even one behind an
  access list, or its certificate could never be issued.
- **nginx's counters answer loopback only**, at a path of the default
  server: another client is closed on like any unknown request.
- **A host whose access list is missing is not served at all.**
- **A host whose certificate files do not exist yet is served over plain
  HTTP**, with a warning, until they do.
- The modules the distribution loads dynamically (`stream` on Debian)
  keep loading: `nginx.conf` includes `/etc/nginx/modules-enabled/`.
- If nginx's workers cannot traverse the path to the htpasswd files —
  something `nginx -t` cannot see, since only the master reads the
  configuration — limen says so, instead of letting every guarded host
  answer 500.

## Roadmap

| | | |
|---|---|---|
| **M0** | skeleton | build, config + hot reload, logs, status socket, CLI, systemd, panel plumbing — **done** |
| **M1** | model and store | one YAML document per object, atomic writes, history and rollback, cross-document checks, writers' lock, CLI verbs — **done** |
| **M2** | nginx renderer | full tree from the model, generations, `nginx -t` with per-document isolation, atomic install, reload with rollback, import of an existing configuration — **done** |
| **M3** | API and authentication | REST resources, server-side sessions, PBKDF2 with rehash at login, CSRF + origin checks, roles, login throttling, audit log — **done** |
| **M4** | web panel | overview, lists, editors and history for every kind, restore, apply, themes; no build step, no framework, strict CSP, no HTML parsing of data — **done** |
| **M5** | certificates | ACME with HTTP-01 through nginx and DNS-01 through a hook, renewal loop with backoff, uploaded certificates, the panel's own certificate, expiry in status and in the UI; tested against Pebble — **done** |
| **M6** | fine control | custom locations with their own backend and guard, access lists that override what they inherit, streams guarded by address, proxy options and headers, snippets on a closed list, locations in the import — **done** |
| **M7** | observability | per-host JSON access logs and error logs, a log viewer that follows, traffic counted from the logs (read back at start, rotation-proof), nginx's counters, charts in the panel, a 5xx check in status, Prometheus — **done** |
| **M8** | release | hardening — the unit proven under real systemd and narrowed to two capabilities, rate limits in front of the panel, fuzzing of every parser of outside input, govulncheck in CI, bounded reads and timeouts; API tokens for scripts; a Debian package tested on Debian and Ubuntu, release artifacts with checksums and build provenance — **done**, released as v0.1.0 |

## Development

```sh
make build            # quick build for the host
make test             # go test ./... -race -count=1
make vet
make fmt
```

The daemon is a Linux service. On a Windows or macOS development
machine everything builds and the suite runs, except the AF_UNIX round
trips, which are skipped with a reason and exercised in CI.

The integration tests drive a real nginx and run when
`LIMEN_TEST_NGINX` names its binary, as root. CI runs them on the
official image, Debian and Ubuntu; by hand:

```sh
CGO_ENABLED=0 go test -c -o nginx.test ./internal/nginx/
docker run --rm -v "$PWD:/t" -e LIMEN_TEST_NGINX=/usr/sbin/nginx nginx:stable /t/nginx.test -test.run RealNginx -test.v
```

The ACME client is exercised end to end against Pebble and
`pebble-challtestsrv` (Let's Encrypt's test CA and its companion DNS),
with limen, nginx and both on one Docker network; the unit tests replace
only the CA call, never the files, the renderer or nginx.

## License

MIT. See [LICENSE](LICENSE).
