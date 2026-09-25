// limen panel.
//
// No framework and no build step. The Content-Security-Policy allows
// scripts and styles from this origin only, and nothing inline; and no
// piece of data ever reaches the page through HTML parsing: every node
// is built with createElement, every text goes in as textContent. A
// hostname that says <script> is displayed as a hostname that says
// <script>.
'use strict';

(function () {
  // ─────────────────────────────────────────────────────────────────
  // DOM
  // ─────────────────────────────────────────────────────────────────

  // h builds an element. attrs: class, text, on<event> (functions),
  // anything else as an attribute. Children: nodes, strings, arrays;
  // null and false are skipped.
  function h(tag, attrs) {
    var el = document.createElement(tag);
    attrs = attrs || {};
    Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (v === null || v === undefined || v === false) return;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k.slice(0, 2) === 'on' && typeof v === 'function') el.addEventListener(k.slice(2), v);
      else if (k === 'style' || k.slice(0, 2) === 'on') throw new Error('refusing attribute ' + k);
      else if (k === 'value') el.value = v;
      else if (k === 'checked') el.checked = !!v;
      else el.setAttribute(k, v === true ? '' : String(v));
    });
    for (var i = 2; i < arguments.length; i++) append(el, arguments[i]);
    return el;
  }

  // append adds every child after el: nodes, strings, arrays.
  function append(el) {
    for (var i = 1; i < arguments.length; i++) {
      var kid = arguments[i];
      if (kid === null || kid === undefined || kid === false) continue;
      if (Array.isArray(kid)) { kid.forEach(function (k) { append(el, k); }); continue; }
      el.appendChild(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
  }

  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }

  var ICONS = {
    dashboard: ['M3 3h7v9H3z', 'M14 3h7v5h-7z', 'M14 12h7v9h-7z', 'M3 16h7v5H3z'],
    hosts: ['M4 5h16v6H4z', 'M4 13h16v6H4z', 'M8 8h.01', 'M8 16h.01'],
    redirects: ['M4 12h13', 'M13 6l6 6-6 6'],
    streams: ['M3 7h18', 'M3 12h18', 'M3 17h18'],
    access: ['M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z'],
    users: ['M16 19v-1a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v1', 'M9 10a3 3 0 1 0 0-6 3 3 0 0 0 0 6', 'M22 19v-1a4 4 0 0 0-3-3.9', 'M16 4.1a3 3 0 0 1 0 5.8'],
    plus: ['M12 5v14', 'M5 12h14'],
    x: ['M6 6l12 12', 'M18 6L6 18'],
    up: ['M12 19V5', 'M6 11l6-6 6 6'],
    down: ['M12 5v14', 'M18 13l-6 6-6-6'],
    search: ['M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14', 'M20 20l-4-4'],
    play: ['M7 5l12 7-12 7z'],
    check: ['M5 12l5 5 9-10'],
    door: ['M3 10.5V1.5h6v9', 'M1.5 10.5h9', 'M7 6.2h.01'],
    lock: ['M6 11h12v10H6z', 'M8 11V7a4 4 0 0 1 8 0v4'],
    refresh: ['M20 11a8 8 0 1 0-2.3 5.7', 'M20 5v6h-6'],
    logs: ['M5 4h14v16H5z', 'M9 8h6', 'M9 12h6', 'M9 16h3']
  };

  function icon(name, size) {
    var ns = 'http://www.w3.org/2000/svg';
    var s = document.createElementNS(ns, 'svg');
    s.setAttribute('viewBox', name === 'door' ? '0 0 12 12' : '0 0 24 24');
    s.setAttribute('aria-hidden', 'true');
    if (size) { s.setAttribute('width', size); s.setAttribute('height', size); }
    (ICONS[name] || []).forEach(function (d) {
      var p = document.createElementNS(ns, 'path');
      p.setAttribute('d', d);
      s.appendChild(p);
    });
    return s;
  }

  // ─────────────────────────────────────────────────────────────────
  // API
  // ─────────────────────────────────────────────────────────────────

  var state = { user: null, csrf: null, status: null, lastApply: null };
  var uid = 0; // ids tying labels to their inputs

  function ApiError(status, message) { this.status = status; this.message = message; }

  function api(method, path, body, note) {
    var opt = { method: method, headers: {}, credentials: 'same-origin' };
    if (body !== undefined) {
      opt.headers['Content-Type'] = 'application/json';
      opt.body = JSON.stringify(body);
    }
    if (method !== 'GET') opt.headers['X-CSRF-Token'] = state.csrf || '';
    if (note) opt.headers['X-Limen-Note'] = note;
    return fetch('/api/v1' + path, opt).then(function (r) {
      return r.text().then(function (text) {
        var data = null;
        try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
        if (r.status === 401 && path !== '/session') {
          state.user = null;
          location.hash = '#/login';
        }
        if (!r.ok) throw new ApiError(r.status, (data && data.error) || r.statusText);
        return data;
      });
    });
  }

  function can(role) {
    var levels = { viewer: 1, operator: 2, admin: 3 };
    return !!state.user && levels[state.user.role] >= levels[role];
  }

  // ─────────────────────────────────────────────────────────────────
  // Small things
  // ─────────────────────────────────────────────────────────────────

  function ago(when) {
    var t = typeof when === 'number' ? when * 1000 : Date.parse(when);
    if (!t) return '—';
    var s = Math.max(0, Math.round((Date.now() - t) / 1000));
    if (s < 60) return s + 's ago';
    if (s < 3600) return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm ago';
    return Math.floor(s / 86400) + 'd ago';
  }

  // stamp renders a time as 2026-09-24 12:41:46, in the viewer's zone.
  function stamp(when) {
    var d = new Date(when);
    if (isNaN(d)) return '—';
    function two(n) { return (n < 10 ? '0' : '') + n; }
    return d.getFullYear() + '-' + two(d.getMonth() + 1) + '-' + two(d.getDate()) + ' ' +
      two(d.getHours()) + ':' + two(d.getMinutes()) + ':' + two(d.getSeconds());
  }

  function pill(kind, text, pulse) {
    return h('span', { class: 'pill ' + kind }, h('span', { class: 'dot' + (pulse ? ' pulse' : '') }), text);
  }

  var STATUS_PILL = { ok: 'success', warn: 'warning', crit: 'failed', unknown: 'idle' };
  var STATUS_WORD = { ok: 'Healthy', warn: 'Degraded', crit: 'Critical', unknown: 'Unknown' };

  function toast(kind, title, detail) {
    var box = document.querySelector('.toasts');
    if (!box) { box = h('div', { class: 'toasts', role: 'status', 'aria-live': 'polite' }); document.body.appendChild(box); }
    var t = h('div', { class: 'toast ' + kind }, h('strong', { text: title }), detail ? h('div', { class: 'detail', text: detail }) : null);
    box.appendChild(t);
    setTimeout(function () { t.remove(); }, kind === 'success' ? 4000 : 9000);
  }

  // applyToast tells what nginx made of a change.
  function applyToast(what, res, kind, name) {
    if (!res) { toast('success', what); return; }
    if (res.error) { toast('failed', what + ', but nginx was not updated', res.error); return; }
    var mine = (res.skipped || []).filter(function (s) { return s.kind === kind && s.name === name; })[0];
    if (mine) { toast('warning', what + ', but nginx left it out', mine.reason); return; }
    if (!res.changed) toast('success', what, 'nginx already serves exactly this.');
    else if (res.reloaded) toast('success', what, 'Generation ' + res.generation + ' installed and reloaded.');
    else toast('success', what, 'Generation ' + res.generation + ' installed; nginx is not running.');
  }

  // dialog asks for a confirmation; with alone, it only shows something
  // and has no Cancel.
  function dialog(title, body, confirmText, danger, alone) {
    return new Promise(function (resolve) {
      var d = h('dialog', { class: 'dialog' });
      var ok = h('button', { class: 'btn ' + (danger ? 'danger' : 'primary'), text: confirmText, onclick: function () { d.close('ok'); } });
      append(d, [
        h('div', { class: 'dialog-body' }, h('div', { class: 'dialog-title', text: title }), body),
        h('div', { class: 'dialog-actions' },
          alone ? null : h('button', { class: 'btn', text: 'Cancel', onclick: function () { d.close('cancel'); } }), ok)
      ]);
      d.addEventListener('close', function () { resolve(d.returnValue === 'ok'); d.remove(); });
      document.body.appendChild(d);
      d.showModal();
      ok.focus();
    });
  }

  function confirmDanger(title, text, button) {
    return dialog(title, h('p', { class: 'note', text: text }), button, true);
  }

  // Deep get/set on dotted paths ("tls.force_https").
  function getPath(obj, path) {
    return path.split('.').reduce(function (o, k) { return o == null ? undefined : o[k]; }, obj);
  }
  function setPath(obj, path, value) {
    var keys = path.split('.');
    var last = keys.pop();
    var o = keys.reduce(function (o, k) { if (o[k] == null) o[k] = {}; return o[k]; }, obj);
    o[last] = value;
  }

  // ─────────────────────────────────────────────────────────────────
  // The kinds of document
  // ─────────────────────────────────────────────────────────────────

  var TLS_FIELDS = [
    { section: 'HTTPS' },
    { key: 'tls.certificate', label: 'Certificate', type: 'certref', hint: 'None: plain HTTP only. "New" asks limen to issue one for the domains above, through ACME.' },
    { key: 'tls.force_https', label: 'Force HTTPS', type: 'bool', hint: 'Send plain HTTP to HTTPS.' },
    { key: 'tls.http2', label: 'HTTP/2', type: 'bool' },
    { key: 'tls.hsts', label: 'HSTS', type: 'bool', hint: 'Browsers refuse plain HTTP for two years.' },
    { key: 'tls.hsts_subdomains', label: 'HSTS for subdomains', type: 'bool' }
  ];

  var HOST_M6_FIELDS = [
    { section: 'Custom locations' },
    { key: 'locations', label: 'Locations', type: 'locations', hint: 'Parts of the host sent to another backend or guarded differently. Everything else goes to the host\'s backend.' },
    { section: 'Advanced' },
    { key: 'proxy.connect_timeout', label: 'Connect timeout', type: 'text', mono: true, placeholder: '60s' },
    { key: 'proxy.read_timeout', label: 'Read timeout', type: 'text', mono: true, placeholder: '300s', hint: 'Longest wait between two reads from the backend.' },
    { key: 'proxy.send_timeout', label: 'Send timeout', type: 'text', mono: true, placeholder: '300s' },
    { key: 'proxy.stream_responses', label: 'Stream responses', type: 'bool', hint: 'Pass responses on as they arrive: server-sent events, long polling, large downloads.' },
    { key: 'proxy.stream_requests', label: 'Stream uploads', type: 'bool', hint: 'Pass request bodies on as they arrive instead of reading them whole first.' },
    { key: 'proxy.host_header', label: 'Host header', type: 'text', mono: true, placeholder: 'the client\'s', hint: 'Empty: the name the client asked for. "upstream": the backend\'s address. Or a host name.' },
    { key: 'proxy.request_headers', label: 'Request headers', type: 'headers', hint: 'Set on every request to the backend. nginx variables work: $request_id.' },
    { key: 'proxy.response_headers', label: 'Response headers', type: 'headers', hint: 'Added to every response, errors included.' },
    { key: 'snippet', label: 'Snippet', type: 'snippet', hint: 'nginx directives for every location of the host. limen checks them against a list (headers, timeouts, buffers, gzip, rewrite, return...) and replaces its own where they overlap.' }
  ];

  var KINDS = {
    hosts: {
      kind: 'proxy_host', title: 'Proxy hosts', one: 'proxy host', icon: 'hosts', toggle: 'enabled',
      blurb: 'Domains nginx answers on, and the backend it sends them to.',
      columns: [
        { label: 'Name', cell: function (d) { return d.name; }, name: true },
        { label: 'Domains', cell: function (d) { return tags(d.domains); } },
        { label: 'Forward', cell: function (d) { return upstream(d.forward); }, mono: true },
        { label: 'TLS', cell: function (d) { return tlsCell(d.tls); } },
        { label: 'Access', cell: function (d) { return d.access_list || '—'; }, mono: true },
        { label: 'State', cell: function (d) { return statePill(d.enabled, d.protected, 'proxy_host', d.name); } }
      ],
      fields: [
        { key: 'name', label: 'Name', type: 'name', hint: 'Leave empty to use the first domain.' },
        { key: 'description', label: 'Description', type: 'text' },
        { key: 'domains', label: 'Domains', type: 'list', mono: true, placeholder: 'app.example.com', hint: 'One per row. *.example.com works too.' },
        { key: 'forward', label: 'Forward to', type: 'upstream' },
        { key: 'forward.verify_tls', label: 'Verify backend certificate', type: 'bool', hint: 'For https backends with a certificate the machine trusts.' },
        { key: 'access_list', label: 'Access list', type: 'ref', ref: 'access-lists', hint: 'Who may reach the host at all.' },
        { key: 'websockets', label: 'Websockets', type: 'bool' },
        { key: 'block_exploits', label: 'Block common exploits', type: 'bool' },
        { key: 'cache_assets', label: 'Cache static assets', type: 'bool', hint: 'Tells browsers to keep images, scripts and fonts for a week.' },
        { key: 'client_max_body_size', label: 'Largest upload', type: 'text', mono: true, placeholder: '100m', hint: 'Empty: the global default.' },
        { key: 'log_requests', label: 'Log requests', type: 'bool', hint: 'Its access log: the log viewer and the traffic charts come from it.' },
        { key: 'enabled', label: 'Enabled', type: 'bool' }
      ].concat(TLS_FIELDS, HOST_M6_FIELDS),
      defaults: { enabled: true, domains: [], forward: { scheme: 'http', host: '', port: 80 }, tls: { http2: true }, block_exploits: true, log_requests: true, locations: [], proxy: {} }
    },
    redirects: {
      kind: 'redirect', title: 'Redirects', one: 'redirect', icon: 'redirects', toggle: 'enabled',
      blurb: 'Domains whose every request is sent somewhere else.',
      columns: [
        { label: 'Name', cell: function (d) { return d.name; }, name: true },
        { label: 'Domains', cell: function (d) { return tags(d.domains); } },
        { label: 'Target', cell: function (d) { return targetText(d.target); }, mono: true },
        { label: 'Code', cell: function (d) { return String(d.code); }, mono: true },
        { label: 'State', cell: function (d) { return statePill(d.enabled, d.protected, 'redirect', d.name); } }
      ],
      fields: [
        { key: 'name', label: 'Name', type: 'name', hint: 'Leave empty to use the first domain.' },
        { key: 'description', label: 'Description', type: 'text' },
        { key: 'domains', label: 'Domains', type: 'list', mono: true, placeholder: 'old.example.com' },
        { key: 'target.scheme', label: 'Target scheme', type: 'select', options: [['auto', 'keep the request\'s'], ['https', 'https'], ['http', 'http']] },
        { key: 'target.domain', label: 'Target host', type: 'text', mono: true, placeholder: 'new.example.com', hint: 'A host and an optional port, no path.' },
        { key: 'target.preserve_path', label: 'Keep the path', type: 'bool', hint: 'Append the original path and query.' },
        { key: 'code', label: 'Status code', type: 'select', number: true, options: [['301', '301 permanent'], ['302', '302 temporary'], ['307', '307 temporary, same method'], ['308', '308 permanent, same method']] },
        { key: 'block_exploits', label: 'Block common exploits', type: 'bool' },
        { key: 'enabled', label: 'Enabled', type: 'bool' }
      ].concat(TLS_FIELDS),
      defaults: { enabled: true, domains: [], target: { scheme: 'auto', domain: '', preserve_path: true }, code: 301, tls: { http2: true }, block_exploits: true }
    },
    streams: {
      kind: 'stream', title: 'Streams', one: 'stream', icon: 'streams', toggle: 'enabled',
      blurb: 'Raw TCP and UDP ports forwarded to a backend.',
      columns: [
        { label: 'Name', cell: function (d) { return d.name; }, name: true },
        { label: 'Listen', cell: function (d) { return String(d.listen_port); }, mono: true },
        { label: 'Protocols', cell: function (d) { return (d.protocols || []).join(', '); }, mono: true },
        { label: 'Forward', cell: function (d) { return d.forward.host + ':' + d.forward.port; }, mono: true },
        { label: 'Access', cell: function (d) { return d.access_list || '—'; }, mono: true },
        { label: 'State', cell: function (d) { return statePill(d.enabled, d.protected, 'stream', d.name); } }
      ],
      fields: [
        { key: 'name', label: 'Name', type: 'name', required: true },
        { key: 'description', label: 'Description', type: 'text' },
        { key: 'listen_port', label: 'Listen port', type: 'number', hint: 'Not 80 or 443: those belong to the HTTP hosts.' },
        { key: 'protocols', label: 'Protocols', type: 'protocols' },
        { key: 'forward.host', label: 'Forward host', type: 'text', mono: true, placeholder: '10.0.0.9' },
        { key: 'forward.port', label: 'Forward port', type: 'number' },
        { key: 'access_list', label: 'Access list', type: 'ref', ref: 'access-lists', hint: 'Who may connect, by address. A stream cannot ask for a password: the list must have rules only.' },
        { key: 'enabled', label: 'Enabled', type: 'bool' }
      ],
      defaults: { enabled: true, protocols: ['tcp'], forward: { host: '', port: 0 } }
    },
    'access-lists': {
      kind: 'access_list', title: 'Access lists', one: 'access list', icon: 'access',
      blurb: 'Who may reach a host: address rules, passwords, or both.',
      columns: [
        { label: 'Name', cell: function (d) { return d.name; }, name: true },
        { label: 'Users', cell: function (d) { return String((d.users || []).length); }, mono: true },
        { label: 'Rules', cell: function (d) { return String((d.rules || []).length); }, mono: true },
        { label: 'Satisfy', cell: function (d) { return d.satisfy_any ? 'any' : 'all'; }, mono: true }
      ],
      fields: [
        { key: 'name', label: 'Name', type: 'name', required: true },
        { key: 'description', label: 'Description', type: 'text' },
        { key: 'rules', label: 'Address rules', type: 'rules', hint: 'In order: the first match wins. End with "deny all" to let only the listed ones in.' },
        { key: 'users', label: 'Users', type: 'basicusers', hint: 'Basic authentication. Leave a password empty to keep it.' },
        { key: 'satisfy_any', label: 'Either is enough', type: 'bool', hint: 'Let a request in when it passes the rules or the password; otherwise it must pass both.' },
        { key: 'pass_auth', label: 'Pass credentials on', type: 'bool', hint: 'Forward the Authorization header to the backend.' }
      ],
      defaults: { rules: [], users: [] }
    },
    certificates: {
      kind: 'certificate', title: 'Certificates', one: 'certificate', icon: 'lock',
      blurb: 'TLS certificates: issued and renewed by limen through ACME, or uploaded.',
      columns: [
        { label: 'Name', cell: function (d) { return d.name; }, name: true },
        { label: 'Domains', cell: function (d) { return tags(d.domains); } },
        { label: 'Provider', cell: function (d) { return d.provider === 'acme' ? 'acme/' + d.challenge : 'custom'; }, mono: true },
        { label: 'State', cell: function (d) { return certPill(d.state); } },
        { label: 'Expires', cell: function (d) { return expires(d.state); }, mono: true },
        { label: 'Used by', cell: function (d) { return (d.used_by || []).length ? String(d.used_by.length) : '—'; }, mono: true }
      ],
      fields: [
        { key: 'name', label: 'Name', type: 'name', hint: 'Leave empty to use the first domain.' },
        { key: 'description', label: 'Description', type: 'text' },
        { key: 'domains', label: 'Domains', type: 'list', mono: true, placeholder: 'app.example.com', hint: 'One per row, up to 100. *.example.com needs the DNS challenge.' },
        { key: 'provider', label: 'Provider', type: 'select', options: [['acme', 'ACME — limen issues and renews it'], ['custom', 'custom — uploaded, limen watches its expiry']] },
        { key: 'challenge', label: 'Challenge', type: 'select', options: [['http', 'HTTP-01 — answered through nginx'], ['dns', 'DNS-01 — through acme.dns_hook (wildcards)']], hint: 'For ACME certificates only.', shown: isACME },
        { key: 'key_type', label: 'Key type', type: 'select', options: [['', 'the default (acme.key_type)'], ['ec256', 'ECDSA P-256'], ['ec384', 'ECDSA P-384'], ['rsa2048', 'RSA 2048'], ['rsa4096', 'RSA 4096']], shown: isACME }
      ],
      defaults: { domains: [], provider: 'acme', challenge: 'http', key_type: '' }
    },
    users: {
      kind: 'user', title: 'Users', one: 'user', icon: 'users', toggle: 'disabled', role: 'admin',
      blurb: 'Who may log in to this panel, and what they may do.',
      columns: [
        { label: 'Name', cell: function (d) { return d.name; }, name: true },
        { label: 'Role', cell: function (d) { return d.role; }, mono: true },
        { label: 'E-mail', cell: function (d) { return d.email || '—'; }, mono: true },
        { label: 'State', cell: function (d) { return d.disabled ? pill('idle', 'Disabled') : pill('success', 'Active'); } }
      ],
      fields: [
        { key: 'name', label: 'Name', type: 'name', required: true },
        { key: 'full_name', label: 'Full name', type: 'text' },
        { key: 'email', label: 'E-mail', type: 'text', mono: true },
        { key: 'role', label: 'Role', type: 'select', options: [['viewer', 'viewer — reads'], ['operator', 'operator — manages hosts'], ['admin', 'admin — also manages users']] },
        { key: 'password', label: 'Password', type: 'password', hint: 'At least 12 characters. Leave empty to keep the current one.' },
        { key: 'disabled', label: 'Disabled', type: 'bool' },
        { key: 'description', label: 'Description', type: 'text' }
      ],
      defaults: { role: 'viewer' }
    }
  };

  function isACME(d) { return d.provider === 'acme'; }

  var CERT_PILL = { valid: 'success', expiring: 'warning', expired: 'failed', failed: 'failed', invalid: 'failed', pending: 'running' };

  function certPill(st) {
    if (!st) return '—';
    var p = pill(CERT_PILL[st.state] || 'idle', st.state.charAt(0).toUpperCase() + st.state.slice(1), st.state === 'pending');
    if (st.detail) p.setAttribute('title', st.detail);
    return p;
  }

  function expires(st) {
    if (!st || !st.files || !st.files.present || !st.files.not_after) return '—';
    return stamp(st.files.not_after).slice(0, 10) + ' (' + st.days_left + 'd)';
  }

  function tags(list) { return h('span', { class: 'tags' }, (list || []).map(function (d) { return h('span', { class: 'tag', text: d }); })); }
  function upstream(f) {
    if (!f) return '—';
    if (f.socket) return f.scheme + '://unix:' + f.socket;
    var host = f.host && f.host.indexOf(':') >= 0 ? '[' + f.host + ']' : f.host;
    return f.scheme + '://' + host + ':' + f.port;
  }
  function targetText(t) {
    return (t.scheme === 'auto' ? '$scheme' : t.scheme) + '://' + t.domain + (t.preserve_path ? '/…' : '');
  }
  function tlsCell(t) {
    if (!t || !t.certificate) return h('span', { class: 'muted', text: '—' });
    return h('span', { class: 'mono', text: t.certificate + (t.force_https ? ' (forced)' : '') });
  }
  // leftOut returns why nginx left a document out at the last apply.
  function leftOut(kind, name) {
    var s = ((state.lastApply && state.lastApply.skipped) || []).filter(function (x) { return x.kind === kind && x.name === name; })[0];
    return s ? s.reason : '';
  }

  // statePill says what nginx actually does with a document: an enabled
  // host the last apply had to leave out is not "Enabled" for anyone
  // trying to reach it.
  function statePill(enabled, prot, kind, name) {
    var why = enabled && kind ? leftOut(kind, name) : '';
    var main = !enabled ? pill('idle', 'Disabled') : why ? pill('warning', 'Left out') : pill('success', 'Enabled');
    if (why) main.setAttribute('title', why);
    return h('span', { class: 'inline' }, main, prot ? pill('running', 'Protected') : null);
  }

  // ─────────────────────────────────────────────────────────────────
  // Shell
  // ─────────────────────────────────────────────────────────────────

  var NAV = [
    { href: '#/', label: 'Overview', icon: 'dashboard' },
    { href: '#/hosts', label: 'Proxy hosts', icon: 'hosts', count: 'hosts' },
    { href: '#/redirects', label: 'Redirects', icon: 'redirects', count: 'redirects' },
    { href: '#/streams', label: 'Streams', icon: 'streams', count: 'streams' },
    { href: '#/access-lists', label: 'Access lists', icon: 'access', count: 'access_lists' },
    { href: '#/certificates', label: 'Certificates', icon: 'lock', count: 'certificates' },
    { href: '#/logs', label: 'Logs', icon: 'logs', role: 'operator' },
    { href: '#/users', label: 'Users', icon: 'users', count: 'users', role: 'admin' }
  ];

  function brand(sub) {
    return h('div', { class: 'brand' },
      h('span', { class: 'brand-mark' }, icon('door', 12)),
      h('span', { class: 'brand-text' }, h('span', { class: 'brand-name', text: 'limen' }), h('span', { class: 'brand-host', text: sub })));
  }

  function shell(active, crumbs, content) {
    document.body.className = '';
    var st = state.status || {};
    var model = st.model || {};
    var nav = h('nav', { class: 'nav-group', 'aria-label': 'Sections' }, h('span', { class: 'label', text: 'Manage' }),
      NAV.filter(function (n) { return !n.role || can(n.role); }).map(function (n) {
        return h('a', { class: 'nav-item' + (active === n.href ? ' active' : ''), href: n.href, 'aria-current': active === n.href ? 'page' : null },
          icon(n.icon), n.label, n.count && model[n.count] !== undefined ? h('span', { class: 'count', text: String(model[n.count]) }) : null);
      }));
    var ng = st.nginx || {};
    var sidebar = h('aside', { class: 'sidebar' },
      brand(location.host),
      nav,
      h('div', { class: 'sidebar-foot' },
        h('div', { class: 'row' }, h('span', { text: 'limen' }), h('span', { class: 'mono', text: st.version || '—' })),
        h('div', { class: 'row' }, h('span', { text: 'nginx' }), h('span', { class: 'mono', text: state.lastApply && state.lastApply.nginx_version || (ng.running ? 'running' : '—') })),
        h('div', { class: 'row' }, h('span', { text: 'generation' }), h('span', { class: 'mono', text: ng.generation ? ng.generation.slice(-12) : '—' }))));

    var crumbEl = h('div', { class: 'crumb' });
    crumbs.forEach(function (c, i) {
      if (i) append(crumbEl, h('span', { class: 'sep', text: '/' }));
      append(crumbEl, c.href ? h('a', { href: c.href, text: c.label }) : h('span', { class: 'here', text: c.label }));
    });

    var header = h('header', { class: 'header' }, crumbEl,
      h('div', { class: 'header-right' },
        st.status ? pill(STATUS_PILL[st.status] || 'idle', STATUS_WORD[st.status] || st.status) : null,
        can('operator') ? h('button', { class: 'btn', onclick: function () { applyNow(false); } }, icon('play'), 'Apply') : null,
        accountMenu()));

    var app = h('div', { class: 'app' }, sidebar, h('div', { class: 'main' }, header, h('main', { class: 'content' }, content)));
    var root = clear(document.getElementById('root'));
    root.appendChild(app);
  }

  function accountMenu() {
    var u = state.user;
    var menu = h('div', { class: 'account-menu', role: 'menu' },
      h('div', { class: 'menu-head' }, h('span', { class: 'who', text: u.full_name || u.name }), h('span', { class: 'where', text: u.role })),
      h('div', { class: 'menu-sep' }),
      h('div', { class: 'menu-row' }, h('span', { text: 'Theme' }), themeSeg()),
      h('button', { class: 'menu-row', role: 'menuitem', onclick: changePassword }, h('span', { text: 'Change password' })),
      h('button', { class: 'menu-row', role: 'menuitem', onclick: function () { closeMenus(); location.hash = '#/tokens'; } }, h('span', { text: 'API tokens' })),
      h('div', { class: 'menu-sep' }),
      h('button', { class: 'menu-row', role: 'menuitem', onclick: logout }, h('span', { text: 'Log out' })));
    var btn = h('button', { class: 'account-btn', 'aria-haspopup': 'menu', 'aria-expanded': 'false', onclick: function (e) {
      e.stopPropagation();
      var open = menu.getAttribute('data-open') !== 'true';
      menu.setAttribute('data-open', String(open));
      btn.setAttribute('aria-expanded', String(open));
    } }, h('span', { class: 'avatar', text: (u.name || '?').slice(0, 2).toUpperCase() }), h('span', { class: 'mono', text: u.name }));
    menu.addEventListener('click', function (e) { e.stopPropagation(); });
    return h('div', { class: 'account' }, btn, menu);
  }

  function storedTheme() { try { return localStorage.getItem('limen-theme') || 'system'; } catch (e) { return 'system'; } }
  function applyTheme(mode) {
    if (mode === 'system') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', mode);
    try { localStorage.setItem('limen-theme', mode); } catch (e) { /* private mode */ }
  }
  function themeSeg() {
    var seg = h('div', { class: 'seg', role: 'group', 'aria-label': 'Theme' });
    ['system', 'light', 'dark'].forEach(function (m) {
      append(seg, h('button', { 'aria-pressed': String(storedTheme() === m), text: m[0].toUpperCase() + m.slice(1), onclick: function () {
        applyTheme(m);
        Array.prototype.forEach.call(seg.children, function (b) { b.setAttribute('aria-pressed', String(b === this)); }, this);
      } }));
    });
    return seg;
  }

  function logout() {
    api('DELETE', '/session').catch(function () {}).then(function () {
      state.user = null; state.csrf = null;
      location.hash = '#/login';
    });
  }

  function changePassword() {
    var cur = h('input', { class: 'input', type: 'password', autocomplete: 'current-password' });
    var next = h('input', { class: 'input', type: 'password', autocomplete: 'new-password' });
    var again = h('input', { class: 'input', type: 'password', autocomplete: 'new-password' });
    var body = h('div', { class: 'stack' },
      field('Current password', cur), field('New password', next), field('Again', again),
      h('p', { class: 'note', text: 'Every other session of yours ends when the password changes.' }));
    dialog('Change password', body, 'Change', false).then(function (ok) {
      if (!ok) return;
      if (next.value !== again.value) { toast('failed', 'The two new passwords differ'); return; }
      api('PUT', '/session/password', { current: cur.value, new: next.value }).then(function (s) {
        state.csrf = s.csrf_token;
        toast('success', 'Password changed');
      }).catch(function (e) { toast('failed', 'Password not changed', e.message); });
    });
  }

  function field(label, input) {
    if (!input.id) input.id = 'f' + (++uid);
    return h('div', { class: 'field' }, h('label', { class: 'label', for: input.id, text: label }), input);
  }

  function applyNow(dryRun) {
    api('POST', '/apply', { dry_run: dryRun }).then(function (res) {
      state.lastApply = res;
      if (dryRun) {
        var left = (res.skipped || []).length;
        toast(left ? 'warning' : 'success', res.changed ? 'The model passes nginx -t' : 'Nothing to change',
          left ? left + ' document(s) would be left out.' : 'Nothing was installed.');
      } else {
        applyToast('Applied', res);
      }
      render();
    }).catch(function (e) {
      if (e.status === 409 && e.message) toast('failed', 'nginx refused the configuration', e.message);
      else toast('failed', 'Apply failed', e.message);
    });
  }

  // ─────────────────────────────────────────────────────────────────
  // Pages
  // ─────────────────────────────────────────────────────────────────

  function loginPage(message) {
    document.body.className = 'auth';
    var user = h('input', { class: 'input mono', name: 'username', autocomplete: 'username', required: true });
    var pass = h('input', { class: 'input', type: 'password', name: 'password', autocomplete: 'current-password', required: true });
    var err = h('div', { class: 'form-error', role: 'alert', hidden: !message, text: message || '' });
    var btn = h('button', { class: 'btn primary', type: 'submit', text: 'Log in' });
    var form = h('form', { class: 'stack', onsubmit: function (e) {
      e.preventDefault();
      btn.disabled = true;
      api('POST', '/session', { username: user.value, password: pass.value }).then(function (s) {
        state.user = s.user; state.csrf = s.csrf_token;
        location.hash = '#/';
        refreshStatus().then(render);
      }).catch(function (e) {
        err.hidden = false;
        err.textContent = e.message;
        btn.disabled = false;
        pass.value = '';
        pass.focus();
      });
    } }, field('Username', user), field('Password', pass), err, btn);
    var card = h('main', { class: 'auth-card' }, brand(location.host), h('h1', { class: 'auth-title', text: 'Log in' }),
      h('p', { class: 'note', text: 'The panel manages the nginx of this machine. Accounts are created with `limen user add` or by an admin here.' }),
      form);
    clear(document.getElementById('root')).appendChild(card);
    user.focus();
  }

  function refreshStatus() {
    return Promise.all([
      api('GET', '/status').then(function (s) { state.status = s; }).catch(function () {}),
      api('GET', '/apply').then(function (r) { state.lastApply = r; }).catch(function () {})
    ]);
  }

  function dashboard() {
    var st = state.status || {};
    var model = st.model || {};
    var ng = st.nginx || {};
    var last = state.lastApply;

    var kpis = h('div', { class: 'grid-kpi' },
      [['Proxy hosts', model.hosts, '#/hosts'], ['Redirects', model.redirects, '#/redirects'], ['Streams', model.streams, '#/streams'], ['Certificates', model.certificates, '#/certificates']]
        .map(function (k) {
          return h('a', { class: 'kpi', href: k[2] }, h('span', { class: 'label', text: k[0] }), h('span', { class: 'value', text: String(k[1] === undefined ? '—' : k[1]) }));
        }));

    var nginxCard = h('section', { class: 'card' },
      h('div', { class: 'card-head' }, h('span', { class: 'title', text: 'nginx' }),
        h('span', { class: 'right' }, ng.running ? pill('success', 'Running') : pill('failed', 'Not running'))),
      h('div', { class: 'kv compact' },
        kv('Version', last && last.nginx_version || '—'),
        kv('Live generation', ng.generation || '—'),
        kv('Last apply', ng.last_apply_unix ? ago(ng.last_apply_unix) + (ng.last_apply_ok ? '' : ' — failed') : '—'),
        kv('Configuration', ng.conf_dir || '—'),
        ng.pending ? kv('Pending', 'the model has changes nginx does not serve yet', true) : null),
      can('operator') ? h('div', { class: 'inline' },
        h('button', { class: 'btn primary', onclick: function () { applyNow(false); } }, icon('play'), 'Apply now'),
        h('button', { class: 'btn', onclick: function () { applyNow(true); } }, 'Dry run')) : null);

    var skipped = (last && last.skipped) || [];
    var leftOut = h('section', { class: 'card' },
      h('div', { class: 'card-head' }, h('span', { class: 'title', text: 'Left out of nginx' }),
        h('span', { class: 'right' }, skipped.length ? pill('warning', String(skipped.length)) : pill('success', 'None'))),
      skipped.length ? h('div', { class: 'log' }, skipped.map(function (s) {
        return h('div', { class: 'log-row' }, h('span', { class: 'kind warn', text: s.kind.replace('_', ' ').toUpperCase() }),
          h('span', { class: 'msg' }, h('span', { class: 'mono', text: s.name }), ' — ' + s.reason));
      })) : h('p', { class: 'note', text: 'Every enabled document of the model is served.' }));

    var checks = h('section', { class: 'card' },
      h('div', { class: 'card-head' }, h('span', { class: 'title', text: 'Checks' })),
      h('div', { class: 'log' }, (st.checks || []).map(function (c) {
        var k = { ok: 'ok', warn: 'warn', crit: 'fail' }[c.status] || 'idle';
        return h('div', { class: 'log-row' }, h('span', { class: 'kind ' + k, text: c.status.toUpperCase() }),
          h('span', { class: 'msg' }, h('span', { class: 'mono', text: c.name }), c.detail ? ' — ' + c.detail : ''));
      })),
      (st.config && st.config.warnings || []).length ? h('div', { class: 'stack' }, h('span', { class: 'label', text: 'Warnings' }),
        st.config.warnings.map(function (w) { return h('div', { class: 'notice warn', text: w }); })) : null);

    shell('#/', [{ label: 'Overview' }], [
      h('div', { class: 'page-head' }, h('div', {}, h('h1', { class: 'page-title', text: 'Overview' }),
        h('p', { class: 'page-sub', text: 'What nginx serves, and whether it serves what the model says.' }))),
      kpis, trafficSection(), h('div', { class: 'grid-2' }, nginxCard, leftOut), checks
    ]);
  }

  function kv(k, v, sans) {
    return h('div', { class: 'kv-row' }, h('span', { class: 'k', text: k }), h('span', { class: 'v' + (sans ? ' sans' : ''), text: v }));
  }

  function listPage(coll) {
    var K = KINDS[coll];
    shell('#/' + coll, [{ label: K.title }], h('div', { class: 'loading', text: 'Loading…' }));
    api('GET', '/' + coll).then(function (data) {
      var items = data.items || [];
      var search = h('input', { type: 'search', placeholder: 'Filter', 'aria-label': 'Filter' });
      var tbody = h('tbody');
      var rows = items.map(function (d) {
        var tr = h('tr', { 'data-href': '#/' + coll + '/' + encodeURIComponent(d.name), tabindex: '0',
          onclick: function () { location.hash = '#/' + coll + '/' + encodeURIComponent(d.name); },
          onkeydown: function (e) { if (e.key === 'Enter') location.hash = '#/' + coll + '/' + encodeURIComponent(d.name); } },
        K.columns.map(function (c) {
          return h('td', { class: c.name ? 'name' : (c.mono ? 'mono' : null) }, c.cell(d));
        }));
        tr._text = JSON.stringify(d).toLowerCase();
        return tr;
      });
      append(tbody, rows);
      search.addEventListener('input', function () {
        var q = search.value.toLowerCase();
        rows.forEach(function (r) { r.hidden = q && r._text.indexOf(q) < 0; });
      });

      var table = items.length ? h('div', { class: 'table-wrap' }, h('table', { class: 'table' },
        h('thead', {}, h('tr', {}, K.columns.map(function (c) { return h('th', { text: c.label }); }))), tbody))
        : h('div', { class: 'empty' }, h('span', { class: 'headline', text: 'No ' + K.title.toLowerCase() + ' yet.' }));

      var writable = can(K.role || 'operator');
      shell('#/' + coll, [{ label: K.title }], [
        h('div', { class: 'page-head' },
          h('div', {}, h('h1', { class: 'page-title', text: K.title }), h('p', { class: 'page-sub', text: K.blurb })),
          h('div', { class: 'page-actions' }, writable ? h('a', { class: 'btn primary', href: '#/' + coll + '/new' }, icon('plus'), 'New ' + K.one) : null)),
        h('section', { class: 'card flush' },
          h('div', { class: 'toolbar' }, h('label', { class: 'search' }, icon('search'), search),
            h('span', { class: 'right note', text: items.length + ' total' })),
          table)
      ]);
    }).catch(pageError(K.title));
  }

  function pageError(title) {
    return function (e) {
      if (e.status === 401) return;
      shell('', [{ label: title }], h('div', { class: 'form-error', text: e.message || String(e) }));
    };
  }

  function detailPage(coll, name) {
    var K = KINDS[coll];
    var crumbs = [{ label: K.title, href: '#/' + coll }, { label: name }];
    shell('#/' + coll, crumbs, h('div', { class: 'loading', text: 'Loading…' }));
    Promise.all([api('GET', '/' + coll + '/' + encodeURIComponent(name)), api('GET', '/' + coll + '/' + encodeURIComponent(name) + '/history')])
      .then(function (r) {
        var doc = r[0], history = r[1].items || [];
        var writable = can(K.role || 'operator') && !doc.protected;

        var actions = h('div', { class: 'page-actions' });
        if (writable) {
          append(actions, h('a', { class: 'btn', href: '#/' + coll + '/' + encodeURIComponent(name) + '/edit', text: 'Edit' }));
          if (K.toggle) {
            var on = K.toggle === 'enabled' ? doc.enabled : !doc.disabled;
            append(actions, h('button', { class: 'btn', text: on ? 'Disable' : 'Enable', onclick: function () {
              var next = JSON.parse(JSON.stringify(doc));
              next[K.toggle] = K.toggle === 'enabled' ? !on : on;
              api('PUT', '/' + coll + '/' + encodeURIComponent(name), next, (on ? 'disabled' : 'enabled') + ' from the panel').then(function (res) {
                applyToast(K.one + ' ' + (on ? 'disabled' : 'enabled'), res.apply, K.kind, name);
                render();
              }).catch(function (e) { toast('failed', 'Not changed', e.message); });
            } }));
          }
          append(actions, h('button', { class: 'btn danger', text: 'Delete', onclick: function () {
            confirmDanger('Delete ' + name + '?', 'The ' + K.one + ' is removed, and nginx stops serving it. It stays in the history: it can be brought back.', 'Delete')
              .then(function (ok) {
                if (!ok) return;
                api('DELETE', '/' + coll + '/' + encodeURIComponent(name), undefined, 'deleted from the panel').then(function (res) {
                  applyToast(K.one + ' deleted', res.apply);
                  location.hash = '#/' + coll;
                }).catch(function (e) { toast('failed', 'Not deleted', e.message); });
              });
          } }));
        }

        var why = leftOut(K.kind, doc.name);
        var overview = h('section', { class: 'card' },
          h('div', { class: 'card-head' }, h('span', { class: 'title', text: 'Settings' })),
          why ? h('div', { class: 'notice warn', text: 'nginx does not serve this ' + K.one + ' right now: ' + why }) : null,
          doc.protected ? h('div', { class: 'notice', text: 'This ' + K.one + ' is limen\'s own, generated from config.yaml: change it there.' }) : null,
          h('div', { class: 'kv' }, K.fields.filter(function (f) { return f.key && f.type !== 'password' && f.type !== 'name' && (!f.shown || f.shown(doc)); }).map(function (f) {
            return h('div', { class: 'kv-row' }, h('span', { class: 'k', text: f.label }), h('span', { class: 'v' }, display(f, doc)));
          })));

        var hist = h('section', { class: 'card' },
          h('div', { class: 'card-head' }, h('span', { class: 'title', text: 'History' }),
            h('span', { class: 'right note', text: 'Each revision is the ' + K.one + ' as it was just before the change on its line.' })),
          history.length ? h('div', { class: 'log' }, history.map(function (rev) {
            return h('div', { class: 'log-row' },
              h('span', { class: 'ts wide', text: stamp(rev.time) }),
              h('span', { class: 'kind ' + (rev.action === 'delete' ? 'fail' : 'idle'), text: rev.action.toUpperCase() }),
              h('span', { class: 'msg' }, h('span', { class: 'mono', text: rev.author || '—' }), rev.note ? ' — ' + rev.note : ''),
              writable ? h('span', { class: 'times' }, h('button', { class: 'btn', text: 'Restore', onclick: function () {
                confirmDanger('Restore this revision?', 'The current ' + K.one + ' is replaced by the revision of ' + stamp(rev.time) + '. What it replaces goes to the history too.', 'Restore')
                  .then(function (ok) {
                    if (!ok) return;
                    api('POST', '/' + coll + '/' + encodeURIComponent(name) + '/rollback', { revision: rev.id }).then(function (res) {
                      applyToast('Revision restored', res.apply, K.kind, name);
                      render();
                    }).catch(function (e) { toast('failed', 'Not restored', e.message); });
                  });
              } })) : null);
          })) : h('p', { class: 'note', text: 'No earlier revisions.' }));

        shell('#/' + coll, crumbs, [
          h('div', { class: 'page-head' },
            h('div', {}, h('h1', { class: 'page-title mono', text: doc.name }), doc.description ? h('p', { class: 'page-sub', text: doc.description }) : null),
            actions),
          coll === 'certificates' ? certCard(doc) : null,
          coll === 'hosts' ? hostTrafficCard(doc.name, doc) : null,
          overview, hist
        ]);
      }).catch(pageError(K.title));
  }

  // certCard is what the files of a certificate say, and the two things
  // an operator does with one: ask for it again, or upload it.
  function certCard(doc) {
    var st = doc.state || {};
    var f = st.files || {};
    var a = st.attempts || {};
    var name = doc.name;
    var acts = h('div', { class: 'inline' });
    if (can('operator') && doc.provider === 'acme') {
      append(acts, h('button', { class: 'btn', onclick: function () {
        api('POST', '/certificates/' + encodeURIComponent(name) + '/renew', {}).then(function () {
          toast('success', 'Renewal requested', 'limen orders it now. The page shows how it went.');
          setTimeout(render, 4000);
        }).catch(function (e) { toast('failed', 'Not requested', e.message); });
      } }, icon('refresh'), f.present ? 'Renew now' : 'Issue now'));
    }
    if (can('operator') && doc.provider === 'custom') {
      append(acts, h('button', { class: 'btn', text: f.present ? 'Upload a new one' : 'Upload', onclick: function () { uploadCert(name); } }));
    }
    return h('section', { class: 'card' },
      h('div', { class: 'card-head' }, h('span', { class: 'title', text: 'Certificate' }), h('span', { class: 'right' }, certPill(st))),
      st.detail && st.state !== 'valid' ? h('div', { class: 'notice' + (st.state === 'pending' ? '' : ' warn'), text: st.detail }) : null,
      h('div', { class: 'kv' },
        f.present ? [
          kv('Valid', stamp(f.not_before).slice(0, 10) + ' → ' + stamp(f.not_after).slice(0, 10) + ' (' + st.days_left + ' days left)'),
          kv('Issuer', f.issuer || '—'),
          kv('Covers', (f.names || []).join(', ')),
          kv('Serial', f.serial || '—')
        ] : kv('Files', 'none yet', true),
        a.last_attempt ? kv('Last attempt', stamp(a.last_attempt) + (a.last_error ? ' — failed ' + a.failures + ' time(s) in a row' : ' — ok')) : null,
        a.last_error && a.last_error !== st.detail && st.detail.indexOf(a.last_error) < 0 ? kv('Last error', a.last_error, true) : null,
        a.next_attempt ? kv('Next attempt', stamp(a.next_attempt)) : null,
        (doc.used_by || []).length ? kv('Used by', doc.used_by.join(', '), true) : null),
      acts.children.length ? acts : null);
  }

  function uploadCert(name) {
    var chain = h('textarea', { class: 'input mono', rows: '6', placeholder: '-----BEGIN CERTIFICATE-----' });
    var key = h('textarea', { class: 'input mono', rows: '6', placeholder: '-----BEGIN PRIVATE KEY-----' });
    var body = h('div', { class: 'stack' },
      field('Certificate and chain (fullchain.pem)', chain), field('Private key (privkey.pem)', key),
      h('p', { class: 'note', text: 'Checked before anything is written: the key must match, the certificate be valid now and cover every domain.' }));
    dialog('Upload ' + name, body, 'Upload', false).then(function (ok) {
      if (!ok) return;
      api('POST', '/certificates/' + encodeURIComponent(name) + '/upload', { chain: chain.value, key: key.value }).then(function () {
        toast('success', 'Certificate installed', 'nginx serves it from now on.');
        render();
      }).catch(function (e) { toast('failed', 'Not uploaded', e.message); });
    });
  }

  // locationText is one line saying what a custom location does.
  function locationText(l, host) {
    var parts = [(l.exact ? '= ' : '') + l.path, '→', l.forward ? upstream(l.forward) : 'the host\'s backend'];
    if (l.public) parts.push('· public');
    else if (l.access_list) parts.push('· access ' + l.access_list);
    else if (host.access_list) parts.push('· access ' + host.access_list + ' (the host\'s)');
    if (l.websockets) parts.push('· websockets');
    if (l.snippet) parts.push('· snippet');
    return parts.join(' ');
  }

  // display renders a field's value on the detail page.
  function display(f, doc) {
    var v = getPath(doc, f.key);
    switch (f.type) {
      case 'bool': return v ? h('span', { class: 'mono', text: 'yes' }) : h('span', { class: 'muted', text: 'no' });
      case 'list': return v && v.length ? tags(v) : '—';
      case 'upstream': return upstream(v);
      case 'protocols': return (v || []).join(', ');
      case 'rules': return v && v.length ? h('div', { class: 'stack' }, v.map(function (r) { return h('span', { text: r.action + ' ' + r.address }); })) : '—';
      case 'basicusers': return v && v.length ? tags(v.map(function (u) { return u.username; })) : '—';
      case 'headers': return v && v.length ? h('div', { class: 'stack' }, v.map(function (x) { return h('span', { class: 'mono', text: x.name + ': ' + x.value }); })) : '—';
      case 'snippet': return v ? h('pre', { class: 'code', text: v }) : '—';
      case 'locations': return v && v.length ? h('div', { class: 'stack' }, v.map(function (l) { return h('span', { class: 'mono', text: locationText(l, doc) }); })) : '—';
      case 'certref': return v ? h('a', { class: 'inline-link mono', href: '#/certificates/' + encodeURIComponent(v), text: v }) : '—';
      case 'select':
        var opt = (f.options || []).filter(function (o) { return o[0] === String(v === undefined ? '' : v); })[0];
        return opt ? opt[1] : (v === undefined ? '—' : String(v));
      default: return v === undefined || v === '' || v === null ? '—' : String(v);
    }
  }

  // ─────────────────────────────────────────────────────────────────
  // Editor
  // ─────────────────────────────────────────────────────────────────

  function editPage(coll, name) {
    var K = KINDS[coll];
    var creating = !name;
    var crumbs = [{ label: K.title, href: '#/' + coll }].concat(creating ? [{ label: 'New' }] : [{ label: name, href: '#/' + coll + '/' + encodeURIComponent(name) }, { label: 'Edit' }]);
    shell('#/' + coll, crumbs, h('div', { class: 'loading', text: 'Loading…' }));

    var loads = [creating ? Promise.resolve(JSON.parse(JSON.stringify(K.defaults))) : api('GET', '/' + coll + '/' + encodeURIComponent(name))];
    var refs = {};
    K.fields.forEach(function (f) {
      var from = f.type === 'ref' ? f.ref : f.type === 'certref' ? 'certificates' : f.type === 'locations' ? 'access-lists' : null;
      if (from) loads.push(api('GET', '/' + from).then(function (d) { refs[from] = (d.items || []).map(function (x) { return x.name; }); }));
    });

    Promise.all(loads).then(function (r) {
      var doc = r[0];
      var readers = [];
      var certControl = null;
      var err = h('div', { class: 'form-error', role: 'alert', hidden: true });
      var form = h('form', { class: 'form', novalidate: true });

      K.fields.forEach(function (f) {
        if (f.section) { append(form, h('div', { class: 'form-section' }, h('span', { class: 'label', text: f.section }))); return; }
        if (f.type === 'name' && !creating) return;
        var control = buildControl(f, doc, refs, creating);
        readers.push(control.read);
        if (control.adopt) certControl = control;
        append(form, h('div', { class: 'form-row' },
          h('label', { class: 'k', for: control.id || null }, f.label, f.hint ? h('span', { class: 'hint', text: f.hint }) : null),
          h('div', { class: 'v' }, control.el)));
      });

      var save = h('button', { class: 'btn primary', type: 'submit', text: creating ? 'Create' : 'Save' });
      append(form, err, h('div', { class: 'form-actions' },
        h('a', { class: 'btn', href: creating ? '#/' + coll : '#/' + coll + '/' + encodeURIComponent(name), text: 'Cancel' }), save));

      form.addEventListener('submit', function (e) {
        e.preventDefault();
        var out = JSON.parse(JSON.stringify(doc));
        readers.forEach(function (read) { read(out); });
        err.hidden = true;
        save.disabled = true;
        var first = Promise.resolve();
        if (out.__newCert) {
          delete out.__newCert;
          var domains = out.domains || [];
          var certName = (name || out.name || (domains[0] || '').replace('*.', 'wildcard.'));
          var wildcard = domains.some(function (d) { return d.indexOf('*.') === 0; });
          first = api('POST', '/certificates', { name: certName, domains: domains, provider: 'acme', challenge: wildcard ? 'dns' : 'http' },
            'created with ' + K.one + ' ' + certName).then(function (res) {
            setPath(out, 'tls.certificate', res.item.name);
            certControl.adopt(res.item.name);
            toast('success', 'Certificate requested', 'limen orders it now; the ' + K.one + ' is served over HTTPS as soon as it arrives.');
          });
        }
        var req = first.then(function () {
          return creating ? api('POST', '/' + coll, out) : api('PUT', '/' + coll + '/' + encodeURIComponent(name), out);
        });
        req.then(function (res) {
          var saved = res.item.name;
          applyToast(K.one + (creating ? ' created' : ' saved'), res.apply, K.kind, saved);
          location.hash = '#/' + coll + '/' + encodeURIComponent(saved);
        }).catch(function (e) {
          err.textContent = e.message;
          err.hidden = false;
          save.disabled = false;
          err.scrollIntoView({ block: 'nearest' });
        });
      });

      shell('#/' + coll, crumbs, [
        h('div', { class: 'page-head' }, h('div', {},
          h('h1', { class: 'page-title', text: creating ? 'New ' + K.one : 'Edit ' + name }),
          h('p', { class: 'page-sub', text: 'Saving applies the change to nginx at once. If nginx refuses it, nothing it serves changes.' }))),
        h('section', { class: 'card' }, form)
      ]);
    }).catch(pageError(K.title));
  }

  // buildControl returns {el, read(out), id}: the input(s) of a field and
  // how to copy their value into the document being saved.
  function buildControl(f, doc, refs, creating) {
    var id = 'f' + (++uid);
    var v = getPath(doc, f.key);
    var input;
    switch (f.type) {
      case 'name':
      case 'text':
        input = h('input', { class: 'input' + (f.mono || f.type === 'name' ? ' mono' : ''), id: id, value: v || '', placeholder: f.placeholder || null, required: f.required || null });
        return { el: input, id: id, read: function (out) { setPath(out, f.key, input.value.trim()); } };
      case 'password':
        input = h('input', { class: 'input', type: 'password', id: id, autocomplete: 'new-password', placeholder: creating ? 'required' : 'unchanged' });
        return { el: input, id: id, read: function (out) { if (input.value) out.password = input.value; else delete out.password; } };
      case 'number':
        input = h('input', { class: 'input mono', type: 'number', id: id, value: v === undefined || v === 0 ? '' : String(v), min: '1', max: '65535' });
        return { el: input, id: id, read: function (out) { setPath(out, f.key, parseInt(input.value, 10) || 0); } };
      case 'bool':
        var sw = h('button', { class: 'switch', type: 'button', role: 'switch', id: id, 'aria-pressed': String(!!v), 'aria-checked': String(!!v), onclick: function () {
          var now = sw.getAttribute('aria-pressed') !== 'true';
          sw.setAttribute('aria-pressed', String(now));
          sw.setAttribute('aria-checked', String(now));
        } });
        return { el: sw, id: id, read: function (out) { setPath(out, f.key, sw.getAttribute('aria-pressed') === 'true'); } };
      case 'select':
        input = h('select', { class: 'input', id: id }, f.options.map(function (o) { return h('option', { value: o[0], text: o[1], selected: String(v) === o[0] || null }); }));
        return { el: input, id: id, read: function (out) { setPath(out, f.key, f.number ? parseInt(input.value, 10) : input.value); } };
      case 'ref':
        input = h('select', { class: 'input mono', id: id }, h('option', { value: '', text: 'none' }),
          (refs[f.ref] || []).map(function (n) { return h('option', { value: n, text: n, selected: v === n || null }); }));
        return { el: input, id: id, read: function (out) { setPath(out, f.key, input.value); } };
      case 'certref':
        var certs = refs.certificates || [];
        input = h('select', { class: 'input mono', id: id }, h('option', { value: '', text: 'none' }),
          certs.map(function (n) { return h('option', { value: n, text: n, selected: v === n || null }); }),
          h('option', { value: '__new__', text: '+ new certificate for these domains' }));
        return { el: input, id: id, read: function (out) {
          if (input.value === '__new__') { out.__newCert = true; setPath(out, f.key, ''); }
          else setPath(out, f.key, input.value);
        }, adopt: function (name) {
          // The certificate exists now: a second submit must not ask again.
          input.insertBefore(h('option', { value: name, text: name }), input.lastChild);
          input.value = name;
        } };
      case 'upstream':
        var up = v || {};
        var scheme = h('select', { class: 'input narrow', 'aria-label': 'Scheme' }, ['http', 'https'].map(function (s) { return h('option', { value: s, text: s, selected: up.scheme === s || null }); }));
        var host = h('input', { class: 'input mono', id: id, value: up.host || '', placeholder: '10.0.0.5', 'aria-label': 'Host' });
        var port = h('input', { class: 'input mono narrow', type: 'number', value: up.port ? String(up.port) : '', placeholder: 'port', 'aria-label': 'Port' });
        return { el: h('div', { class: 'inline' }, scheme, host, port), id: id, read: function (out) {
          out.forward = out.forward || {};
          out.forward.scheme = scheme.value;
          out.forward.host = host.value.trim();
          out.forward.port = parseInt(port.value, 10) || 0;
        } };
      case 'protocols':
        var protos = v || [];
        var boxes = ['tcp', 'udp'].map(function (p) {
          var b = h('input', { type: 'checkbox', checked: protos.indexOf(p) >= 0 });
          return { p: p, el: h('label', { class: 'toggle' }, b, p.toUpperCase()), box: b };
        });
        return { el: h('div', { class: 'inline' }, boxes.map(function (b) { return b.el; })), read: function (out) {
          out.protocols = boxes.filter(function (b) { return b.box.checked; }).map(function (b) { return b.p; });
        } };
      case 'list':
        return listEditor(v || [], function (item) {
          return h('input', { class: 'input' + (f.mono ? ' mono' : ''), value: item, placeholder: f.placeholder || null });
        }, function (el) { return el.value.trim(); }, '', function (out, items) {
          setPath(out, f.key, items.filter(function (x) { return x; }));
        });
      case 'rules':
        return listEditor(v || [], function (rule) {
          var action = h('select', { class: 'input', 'aria-label': 'Action' }, ['allow', 'deny'].map(function (a) { return h('option', { value: a, text: a, selected: rule.action === a || null }); }));
          var addr = h('input', { class: 'input mono', value: rule.address || '', placeholder: '10.0.0.0/8 or all', 'aria-label': 'Address' });
          var row = h('span', { class: 'inline' }, action, addr);
          row._read = function () { return { action: action.value, address: addr.value.trim() }; };
          return row;
        }, function (el) { return el._read(); }, { action: 'allow', address: '' }, function (out, items) {
          out.rules = items.filter(function (r) { return r.address; });
        });
      case 'snippet':
        input = h('textarea', { class: 'input mono', id: id, rows: '5', spellcheck: 'false', placeholder: 'proxy_read_timeout 1h;\nadd_header X-Robots-Tag noindex always;' });
        input.value = v || '';
        return { el: input, id: id, read: function (out) { setPath(out, f.key, input.value.trim() ? input.value : ''); } };
      case 'headers':
        return listEditor(v || [], function (hd) {
          var name = h('input', { class: 'input mono', value: hd.name || '', placeholder: 'X-Header', 'aria-label': 'Header name' });
          var value = h('input', { class: 'input mono', value: hd.value || '', placeholder: 'value', 'aria-label': 'Header value' });
          var row = h('span', { class: 'inline grow' }, name, value);
          row._read = function () { return { name: name.value.trim(), value: value.value.trim() }; };
          return row;
        }, function (el) { return el._read(); }, { name: '', value: '' }, function (out, items) {
          setPath(out, f.key, items.filter(function (x) { return x.name; }));
        });
      case 'locations':
        return listEditor(v || [], function (l) { return locationRow(l, refs['access-lists'] || []); },
          function (el) { return el._read(); }, { path: '', exact: false, forward: null, websockets: false }, function (out, items) {
            out.locations = items.filter(function (l) { return l.path; });
          });
      case 'basicusers':
        return listEditor(v || [], function (u) {
          var name = h('input', { class: 'input mono', value: u.username || '', placeholder: 'username', 'aria-label': 'Username' });
          var pw = h('input', { class: 'input', type: 'password', autocomplete: 'new-password', placeholder: u.username ? 'unchanged' : 'password', 'aria-label': 'Password' });
          var row = h('span', { class: 'inline' }, name, pw);
          row._read = function () { var o = { username: name.value.trim() }; if (pw.value) o.password = pw.value; return o; };
          return row;
        }, function (el) { return el._read(); }, { username: '' }, function (out, items) {
          out.users = items.filter(function (u) { return u.username; });
        });
    }
    throw new Error('unknown field type ' + f.type);
  }

  // locationRow edits one custom location: where it starts, where it
  // goes, who may reach it, and its snippet.
  function locationRow(l, lists) {
    var path = h('input', { class: 'input mono', value: l.path || '', placeholder: '/api/', 'aria-label': 'Path' });
    var exact = h('input', { type: 'checkbox', checked: !!l.exact });
    var own = h('select', { class: 'input', 'aria-label': 'Backend' },
      h('option', { value: 'host', text: 'the host\'s backend', selected: !l.forward || null }),
      h('option', { value: 'own', text: 'its own backend', selected: l.forward ? true : null }));
    var up = l.forward || { scheme: 'http', host: '', port: 80 };
    var scheme = h('select', { class: 'input narrow', 'aria-label': 'Scheme' }, ['http', 'https'].map(function (x) { return h('option', { value: x, text: x, selected: up.scheme === x || null }); }));
    var host = h('input', { class: 'input mono', value: up.host || '', placeholder: '10.0.0.7', 'aria-label': 'Backend host' });
    var port = h('input', { class: 'input mono narrow', type: 'number', value: up.port ? String(up.port) : '', placeholder: 'port', 'aria-label': 'Backend port' });
    var backend = h('span', { class: 'inline grow' }, scheme, host, port);
    var where = h('span', { class: 'inline grow' }, own, backend);
    function showBackend() { backend.hidden = own.value !== 'own'; }
    own.addEventListener('change', showBackend);
    showBackend();

    var access = h('select', { class: 'input', 'aria-label': 'Access' },
      h('option', { value: '', text: 'the host\'s access list', selected: !l.public && !l.access_list || null }),
      h('option', { value: '!public', text: 'public: no access list', selected: l.public || null }),
      lists.map(function (n) { return h('option', { value: n, text: 'access list ' + n, selected: l.access_list === n || null }); }));
    var ws = h('input', { type: 'checkbox', checked: !!l.websockets });
    var snippet = h('textarea', { class: 'input mono', rows: '2', spellcheck: 'false', placeholder: 'snippet: nginx directives for this location', 'aria-label': 'Snippet' });
    snippet.value = l.snippet || '';

    var row = h('div', { class: 'loc' },
      h('span', { class: 'inline grow' }, path, h('label', { class: 'toggle' }, exact, 'Exact')),
      where,
      h('span', { class: 'inline grow' }, access, h('label', { class: 'toggle' }, ws, 'Websockets')),
      snippet);
    row._read = function () {
      var out = { path: path.value.trim(), exact: exact.checked, websockets: ws.checked, forward: null, public: access.value === '!public' };
      if (own.value === 'own') {
        out.forward = { scheme: scheme.value, host: host.value.trim(), port: parseInt(port.value, 10) || 0, verify_tls: !!(l.forward && l.forward.verify_tls) };
      }
      if (access.value && access.value !== '!public') out.access_list = access.value;
      if (snippet.value.trim()) out.snippet = snippet.value;
      return out;
    };
    return row;
  }

  // listEditor edits an ordered list: add, remove, move up and down —
  // order matters for access rules, where the first match wins.
  function listEditor(items, make, readOne, blank, write) {
    var box = h('div', { class: 'list-edit' });
    var list = h('div', { class: 'stack' });
    function row(item) {
      var el = make(item);
      var r = h('div', { class: 'item' }, el,
        h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'Move up', onclick: function () { if (r.previousSibling) list.insertBefore(r, r.previousSibling); } }, icon('up')),
        h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'Move down', onclick: function () { if (r.nextSibling) list.insertBefore(r.nextSibling, r); } }, icon('down')),
        h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'Remove', onclick: function () { r.remove(); } }, icon('x')));
      r._el = el;
      return r;
    }
    items.forEach(function (it) { list.appendChild(row(it)); });
    if (!items.length) list.appendChild(row(blank));
    append(box, list, h('button', { class: 'btn add', type: 'button', onclick: function () {
      var r = row(typeof blank === 'object' ? JSON.parse(JSON.stringify(blank)) : blank);
      list.appendChild(r);
      var first = r.querySelector('input') || r.querySelector('select');
      if (first) first.focus();
    } }, icon('plus'), 'Add'));
    return { el: box, read: function (out) {
      write(out, Array.prototype.map.call(list.children, function (r) { return readOne(r._el); }));
    } };
  }

  // ─────────────────────────────────────────────────────────────────
  // Traffic
  // ─────────────────────────────────────────────────────────────────

  var SVGNS = 'http://www.w3.org/2000/svg';

  // svg builds an SVG element: attributes only, never a style.
  function svg(name, attrs, kids) {
    var el = document.createElementNS(SVGNS, name);
    Object.keys(attrs || {}).forEach(function (k) {
      if (attrs[k] !== null && attrs[k] !== undefined) el.setAttribute(k, String(attrs[k]));
    });
    (kids || []).forEach(function (k) { if (k) el.appendChild(k); });
    return el;
  }

  function svgText(attrs, text) { var t = svg('text', attrs); t.textContent = text; return t; }

  function two(n) { return (n < 10 ? '0' : '') + n; }
  function hhmm(when) { var d = new Date(when); return two(d.getHours()) + ':' + two(d.getMinutes()); }
  function compact(n) {
    if (n >= 1e6) return (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + 'M';
    if (n >= 1e3) return (n / 1e3).toFixed(n >= 1e4 ? 0 : 1) + 'K';
    return String(Math.round(n));
  }
  function seconds(s) {
    if (!s) return '—';
    return s < 1 ? Math.round(s * 1000) + ' ms' : s.toFixed(2) + ' s';
  }
  function byteSize(n) {
    if (n < 1024) return n + ' B';
    if (n < 1 << 20) return (n / 1024).toFixed(1) + ' kB';
    if (n < 1 << 30) return (n / (1 << 20)).toFixed(1) + ' MB';
    return (n / (1 << 30)).toFixed(2) + ' GB';
  }
  function percent(x) { return x ? (x * 100).toFixed(x < 0.01 ? 2 : 1) + '%' : '0%'; }
  function perSecond(x) { return x >= 10 ? x.toFixed(0) : x >= 0.1 ? x.toFixed(1) : x ? x.toFixed(2) : '0'; }

  // niceMax rounds a maximum up to 1, 2 or 5 times a power of ten: the
  // top tick of an axis.
  function niceMax(v) {
    if (!(v > 0)) return 1;
    var p = Math.pow(10, Math.floor(Math.log10(v)));
    var m = v / p;
    return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * p;
  }

  // The status classes, stacked from the baseline. Their colours are
  // chart tokens of their own (app.css, --viz-*), validated for both
  // themes; the legend and the table name every one.
  var REQ_SERIES = [
    { label: '2xx–3xx answered', cls: 'viz-ok', value: function (p) { return p.status[0] + p.status[1] + p.status[2]; } },
    { label: '4xx client errors', cls: 'viz-4xx', value: function (p) { return p.status[3]; } },
    { label: '5xx server errors', cls: 'viz-5xx', value: function (p) { return p.status[4]; } }
  ];

  var WINDOWS = [['5m', '5 min'], ['1h', '1 hour'], ['24h', '24 hours']];
  var STEP = { '5m': 'minute', '1h': 'minute', '24h': '5 minutes' };

  function storedWindow() {
    try { var w = localStorage.getItem('limen.window'); if (STEP[w]) return w; } catch (e) { /* no storage */ }
    return '1h';
  }

  // windowSeg is the time range, above what it scopes.
  function windowSeg(onChange) {
    var seg = h('div', { class: 'seg', role: 'group', 'aria-label': 'Time range' });
    WINDOWS.forEach(function (w) {
      append(seg, h('button', { type: 'button', 'aria-pressed': String(storedWindow() === w[0]), text: w[1], onclick: function () {
        try { localStorage.setItem('limen.window', w[0]); } catch (e) { /* no storage */ }
        Array.prototype.forEach.call(seg.children, function (b) { b.setAttribute('aria-pressed', String(b === this)); }, this);
        onChange(w[0]);
      } }));
    });
    return seg;
  }

  function legend(series, shape) {
    return h('div', { class: 'viz-legend' }, series.map(function (se) {
      return h('span', { class: 'item' }, h('span', { class: 'key ' + shape + ' ' + se.cls }), se.label);
    }));
  }

  function tiles(list) {
    return h('div', { class: 'grid-kpi viz-tiles' }, list.map(function (t) {
      return h('div', { class: 'kpi static' }, h('span', { class: 'label', text: t[0] }), h('span', { class: 'value', text: t[1] }),
        t[2] ? h('span', { class: 'foot', text: t[2] }) : null);
    }));
  }

  // chartBox holds a chart, its legend, its tooltip and its table view.
  // The drawing follows the width of its box and is redone when that
  // changes.
  function chartBox(title, legendEl, draw, table) {
    var tip = h('div', { class: 'viz-tip', role: 'status', hidden: true });
    var plot = h('div', { class: 'viz-plot' });
    var tableWrap = table ? h('div', { class: 'viz-table table-wrap', hidden: true }, table) : null;
    var toggle = table ? h('button', { class: 'btn small', type: 'button', 'aria-pressed': 'false', text: 'Table', onclick: function () {
      var on = tableWrap.hidden;
      tableWrap.hidden = !on;
      plot.hidden = on;
      toggle.setAttribute('aria-pressed', String(on));
      toggle.textContent = on ? 'Chart' : 'Table';
    } }) : null;
    var box = h('div', { class: 'viz' },
      h('div', { class: 'viz-head' }, h('span', { class: 'viz-title', text: title }), legendEl, toggle), plot, tip, tableWrap);
    var lastW = 0;
    function redraw() {
      var w = plot.clientWidth;
      if (!w || w === lastW) return;
      lastW = w;
      clear(plot);
      plot.appendChild(draw(w, tip, box));
    }
    if (window.ResizeObserver) new ResizeObserver(redraw).observe(plot);
    requestAnimationFrame(redraw);
    return box;
  }

  function fillTip(tip, title, rows) {
    clear(tip);
    append(tip, h('div', { class: 'viz-tip-title', text: title }), rows.map(function (r) {
      // The value leads: the reader has the series and wants the number.
      return h('div', { class: 'viz-tip-row' }, r[2] ? h('span', { class: 'key line ' + r[2] }) : h('span', { class: 'key' }),
        h('strong', { text: r[0] }), h('span', { class: 'lbl', text: r[1] }));
    }));
    tip.hidden = false;
  }

  // placeTip moves the tooltip beside x. Through the CSSOM: the policy
  // refuses style attributes, not the object model.
  function placeTip(tip, box, x) {
    var width = tip.offsetWidth;
    var left = x + 14;
    if (left + width > box.clientWidth) left = x - width - 14;
    tip.style.left = Math.max(0, left) + 'px';
  }

  function roundTop(x, y, w, hgt, r) {
    return 'M' + x + ',' + (y + hgt) + 'V' + (y + r) + 'Q' + x + ',' + y + ' ' + (x + r) + ',' + y +
      'H' + (x + w - r) + 'Q' + (x + w) + ',' + y + ' ' + (x + w) + ',' + (y + r) + 'V' + (y + hgt) + 'Z';
  }

  // yAxis draws three recessive gridlines, the baseline and their ticks.
  function yAxis(root, W, mt, ph, ml, mr, top, fmt) {
    [0, 0.5, 1].forEach(function (f) {
      var y = mt + ph - f * ph;
      root.appendChild(svg('line', { class: f === 0 ? 'viz-base' : 'viz-grid', x1: ml, x2: W - mr, y1: y, y2: y }));
      root.appendChild(svgText({ class: 'viz-tick', x: ml - 6, y: y + 4, 'text-anchor': 'end' }, fmt(top * f)));
    });
  }

  function xTicks(root, points, ml, band, y) {
    var every = Math.max(1, Math.round(points.length / 6));
    points.forEach(function (p, i) {
      if ((points.length - 1 - i) % every) return;
      root.appendChild(svgText({ class: 'viz-tick', x: ml + i * band + band / 2, y: y, 'text-anchor': 'middle' }, hhmm(p.start)));
    });
  }

  // hover wires the pointer and the keyboard to one index at a time.
  function hover(root, hit, count, pick, show) {
    var cur = -1;
    hit.addEventListener('pointermove', function (e) { cur = pick(e); show(cur); });
    hit.addEventListener('pointerleave', function () { show(-1); });
    root.addEventListener('focus', function () { if (cur < 0) cur = count - 1; show(cur); });
    root.addEventListener('blur', function () { show(-1); });
    root.addEventListener('keydown', function (e) {
      if (e.key === 'ArrowLeft') cur = Math.max(0, (cur < 0 ? count : cur) - 1);
      else if (e.key === 'ArrowRight') cur = Math.min(count - 1, cur + 1);
      else return;
      e.preventDefault();
      show(cur);
    });
  }

  // requestsChart stacks the status classes per period: thin columns, a
  // surface gap between segments, the top one rounded.
  function requestsChart(points, win) {
    return function (W, tip, box) {
      var H = 180, ml = 44, mr = 8, mt = 10, mb = 22, pw = W - ml - mr, ph = H - mt - mb;
      var top = niceMax(Math.max.apply(null, points.map(function (p) {
        return REQ_SERIES.reduce(function (a, se) { return a + se.value(p); }, 0);
      }).concat([0])));
      var root = svg('svg', { class: 'viz-svg', width: W, height: H, viewBox: '0 0 ' + W + ' ' + H, tabindex: 0,
        role: 'img', 'aria-label': 'Requests per ' + STEP[win] + ', by status class. Arrow keys read each period.' });
      yAxis(root, W, mt, ph, ml, mr, top, compact);
      var band = pw / points.length;
      var bw = Math.max(1, Math.min(24, band - 2));
      var cols = points.map(function (p, i) {
        var x = ml + i * band + (band - bw) / 2;
        var g = svg('g', { class: 'viz-col' });
        var values = REQ_SERIES.map(function (se) { return se.value(p); });
        var last = -1;
        values.forEach(function (v, k) { if (v > 0) last = k; });
        var y = mt + ph;
        values.forEach(function (v, k) {
          if (!v) return;
          var gap = y < mt + ph ? 2 : 0;
          var hgt = Math.max(v / top * ph - gap, 1);
          var yTop = y - gap - hgt;
          g.appendChild(k === last
            ? svg('path', { class: REQ_SERIES[k].cls, d: roundTop(x, yTop, bw, hgt, Math.min(4, bw / 2, hgt)) })
            : svg('rect', { class: REQ_SERIES[k].cls, x: x, y: yTop, width: bw, height: hgt }));
          y = yTop;
        });
        root.appendChild(g);
        return g;
      });
      xTicks(root, points, ml, band, H - 6);
      var hit = svg('rect', { class: 'viz-hit', x: ml, y: mt, width: pw, height: ph });
      root.appendChild(hit);
      hover(root, hit, points.length, function (e) {
        var i = Math.floor((e.clientX - root.getBoundingClientRect().left - ml) / band);
        return Math.max(0, Math.min(points.length - 1, i));
      }, function (i) {
        cols.forEach(function (c, k) { c.classList.toggle('dim', i >= 0 && k !== i); });
        if (i < 0) { tip.hidden = true; return; }
        var p = points[i];
        fillTip(tip, stamp(p.start).slice(0, 16) + ' · ' + STEP[win], REQ_SERIES.map(function (se) {
          return [compact(se.value(p)), se.label, se.cls];
        }));
        placeTip(tip, box, ml + i * band + band / 2);
      });
      return root;
    };
  }

  // latencyChart draws the p95 of each period: a 2px line over a wash,
  // broken where nothing was served, the last value marked.
  function latencyChart(points) {
    return function (W, tip, box) {
      var H = 140, ml = 52, mr = 12, mt = 10, mb = 22, pw = W - ml - mr, ph = H - mt - mb;
      var vals = points.map(function (p) { return p.requests ? p.p95 : null; });
      var top = niceMax(Math.max.apply(null, vals.filter(function (v) { return v !== null; }).concat([0])));
      var root = svg('svg', { class: 'viz-svg', width: W, height: H, viewBox: '0 0 ' + W + ' ' + H, tabindex: 0,
        role: 'img', 'aria-label': 'p95 latency per period. Arrow keys read each period.' });
      yAxis(root, W, mt, ph, ml, mr, top, function (v) { return v ? seconds(v) : '0'; });
      var band = pw / points.length;
      var X = function (i) { return ml + i * band + band / 2; };
      var Y = function (v) { return mt + ph - v / top * ph; };
      var runs = [], run = [];
      vals.forEach(function (v, i) {
        if (v === null) { if (run.length) runs.push(run); run = []; return; }
        run.push([X(i), Y(v)]);
      });
      if (run.length) runs.push(run);
      runs.forEach(function (r) {
        var line = r.map(function (pt, k) { return (k ? 'L' : 'M') + pt[0].toFixed(1) + ',' + pt[1].toFixed(1); }).join('');
        root.appendChild(svg('path', { class: 'viz-area', d: line + 'L' + r[r.length - 1][0].toFixed(1) + ',' + (mt + ph) + 'L' + r[0][0].toFixed(1) + ',' + (mt + ph) + 'Z' }));
        root.appendChild(svg('path', { class: 'viz-line', d: r.length > 1 ? line : line + 'l0.01,0' }));
      });
      var lastRun = runs[runs.length - 1];
      if (lastRun) {
        var end = lastRun[lastRun.length - 1];
        root.appendChild(svg('circle', { class: 'viz-dot', cx: end[0], cy: end[1], r: 4 }));
      }
      xTicks(root, points, ml, band, H - 6);
      var cross = svg('line', { class: 'viz-cross', x1: 0, x2: 0, y1: mt, y2: mt + ph, visibility: 'hidden' });
      root.appendChild(cross);
      var hit = svg('rect', { class: 'viz-hit', x: ml, y: mt, width: pw, height: ph });
      root.appendChild(hit);
      hover(root, hit, points.length, function (e) {
        var i = Math.round((e.clientX - root.getBoundingClientRect().left - ml - band / 2) / band);
        return Math.max(0, Math.min(points.length - 1, i));
      }, function (i) {
        if (i < 0) { tip.hidden = true; cross.setAttribute('visibility', 'hidden'); return; }
        var p = points[i];
        cross.setAttribute('x1', X(i));
        cross.setAttribute('x2', X(i));
        cross.setAttribute('visibility', 'visible');
        fillTip(tip, stamp(p.start).slice(0, 16), p.requests
          ? [[seconds(p.p95), 'p95', 'viz-line'], [seconds(p.p50), 'p50', null], [compact(p.requests), 'requests', null]]
          : [['—', 'nothing served', null]]);
        placeTip(tip, box, X(i));
      });
      return root;
    };
  }

  // seriesTable is the chart as a table: every value reachable without
  // a pointer.
  function seriesTable(points) {
    return h('table', { class: 'table compact' },
      h('thead', {}, h('tr', {}, ['Period', '2xx–3xx', '4xx', '5xx', 'p50', 'p95'].map(function (c, i) {
        return h('th', { class: i ? 'num' : null, text: c });
      }))),
      h('tbody', {}, points.slice().reverse().map(function (p) {
        return h('tr', {}, h('td', { class: 'mono', text: stamp(p.start).slice(0, 16) }),
          REQ_SERIES.map(function (se) { return h('td', { class: 'num mono', text: String(se.value(p)) }); }),
          h('td', { class: 'num mono', text: p.requests ? seconds(p.p50) : '—' }),
          h('td', { class: 'num mono', text: p.requests ? seconds(p.p95) : '—' }));
      })));
  }

  // live keeps a section current: it reloads every interval while it is
  // in the page, and stops once it is gone. A reload keeps the frame.
  function live(el, load, every) {
    load();
    var t = setInterval(function () {
      if (!el.isConnected) { clearInterval(t); return; }
      if (!document.hidden) load();
    }, every);
  }

  function hostTrafficCard(name, host) {
    var body = h('div', { class: 'stack' }, h('div', { class: 'loading', text: 'Loading…' }));
    var win = storedWindow();
    function load() {
      body.classList.add('refreshing');
      api('GET', '/hosts/' + encodeURIComponent(name) + '/traffic?window=' + win).then(function (t) {
        var parts = [];
        if (!t.logged) {
          parts.push(h('div', { class: 'notice', text: host.enabled
            ? 'This host does not log its requests (Log requests is off): there is nothing to count.'
            : 'This host is disabled: it serves nothing.' }));
        }
        if (t.summary) {
          var s = t.summary;
          parts.push(tiles([
            ['Requests', compact(s.requests), perSecond(s.per_second) + ' per second'],
            ['Server errors', percent(s.error_rate), compact(s.status[4]) + ' answered 5xx'],
            ['Latency p95', seconds(s.p95), 'p50 ' + seconds(s.p50) + ', p99 ' + seconds(s.p99)],
            ['Sent', byteSize(s.bytes), compact(s.status[3]) + ' answered 4xx']
          ]));
          parts.push(chartBox('Requests per ' + STEP[win], legend(REQ_SERIES, 'rect'), requestsChart(t.series, win), seriesTable(t.series)));
          parts.push(chartBox('Latency, p95 per ' + STEP[win], null, latencyChart(t.series), null));
        }
        clear(body);
        body.classList.remove('refreshing');
        append(body, parts);
      }).catch(function (e) {
        body.classList.remove('refreshing');
        clear(body);
        append(body, h('div', { class: 'form-error', text: e.message }));
      });
    }
    var card = h('section', { class: 'card' },
      h('div', { class: 'card-head' }, h('span', { class: 'title', text: 'Traffic' }),
        h('span', { class: 'right inline' }, windowSeg(function (w) { win = w; load(); }),
          can('operator') ? h('a', { class: 'btn small', href: '#/hosts/' + encodeURIComponent(name) + '/logs', text: 'Logs' }) : null)),
      body);
    live(card, load, 30000);
    return card;
  }

  function trafficSection() {
    var body = h('div', { class: 'stack' }, h('div', { class: 'loading', text: 'Loading…' }));
    var win = storedWindow();
    function load() {
      body.classList.add('refreshing');
      api('GET', '/traffic?window=' + win).then(function (t) {
        var ng = t.nginx || {};
        var hosts = t.hosts || [];
        var total = hosts.reduce(function (a, r) {
          a.requests += r.summary.requests;
          a.errors += r.summary.status[4];
          return a;
        }, { requests: 0, errors: 0 });
        var parts = [tiles([
          ['Connections', ng.ok ? compact(ng.active) : '—', ng.ok ? ng.reading + ' reading, ' + ng.writing + ' writing, ' + ng.waiting + ' idle' : (ng.error ? 'nginx counters unavailable' : 'waiting for the first reading')],
          ['Requests per second', ng.ok ? perSecond(ng.per_second) : '—', 'every server, now'],
          ['Requests', compact(total.requests), 'by the proxy hosts'],
          ['Server errors', percent(total.requests ? total.errors / total.requests : 0), compact(total.errors) + ' answered 5xx']
        ])];
        parts.push(chartBox('Requests per ' + STEP[win] + ', every host', legend(REQ_SERIES, 'rect'), requestsChart(t.series || [], win), seriesTable(t.series || [])));
        var busy = hosts.filter(function (r) { return r.summary.requests > 0; });
        parts.push(busy.length ? h('div', { class: 'table-wrap' }, h('table', { class: 'table' },
          h('thead', {}, h('tr', {}, ['Host', 'Requests', 'Per second', '5xx', 'p95', 'Last request'].map(function (c, i) {
            return h('th', { class: i ? 'num' : null, text: c });
          }))),
          h('tbody', {}, busy.slice(0, 10).map(function (r) {
            var go = '#/hosts/' + encodeURIComponent(r.name);
            return h('tr', { 'data-href': go, tabindex: '0', onclick: function () { location.hash = go; },
              onkeydown: function (e) { if (e.key === 'Enter') location.hash = go; } },
            h('td', { class: 'name', text: r.name }),
            h('td', { class: 'num mono', text: compact(r.summary.requests) }),
            h('td', { class: 'num mono', text: perSecond(r.summary.per_second) }),
            h('td', { class: 'num mono', text: percent(r.summary.error_rate) }),
            h('td', { class: 'num mono', text: seconds(r.summary.p95) }),
            h('td', { class: 'num mono', text: r.last_request ? ago(r.last_request) : '—' }));
          }))))
          : h('p', { class: 'note', text: 'No host logged a request in this range.' }));
        clear(body);
        body.classList.remove('refreshing');
        append(body, parts);
      }).catch(function (e) {
        body.classList.remove('refreshing');
        clear(body);
        append(body, h('div', { class: 'form-error', text: e.message }));
      });
    }
    var card = h('section', { class: 'card' },
      h('div', { class: 'card-head' }, h('span', { class: 'title', text: 'Traffic' }),
        h('span', { class: 'right' }, windowSeg(function (w) { win = w; load(); }))),
      body);
    live(card, load, 30000);
    return card;
  }

  // ─────────────────────────────────────────────────────────────────
  // Logs
  // ─────────────────────────────────────────────────────────────────

  var LEVEL_KIND = { emerg: 'fail', alert: 'fail', crit: 'fail', error: 'fail', warn: 'warn', notice: 'idle', info: 'idle', debug: 'idle',
    ERROR: 'fail', WARN: 'warn', INFO: 'idle', DEBUG: 'idle' };

  function statusCode(n) {
    return h('span', { class: 'code c' + Math.floor(n / 100), text: String(n) });
  }

  // logRow renders one line of a log, whatever its format.
  function logRow(line, format) {
    if (line.raw !== undefined) {
      if (format === 'access') return h('tr', {}, h('td', { class: 'mono wrap', colspan: '8', text: line.raw }));
      return h('div', { class: 'log-row' }, h('span', { class: 'msg mono', text: line.raw }));
    }
    switch (format) {
      case 'access':
        return h('tr', {},
          h('td', { class: 'mono', text: stamp(line.time) }),
          h('td', {}, statusCode(line.status)),
          h('td', { class: 'mono', text: line.method }),
          h('td', { class: 'mono wrap', title: line.host + line.uri }, h('span', { class: 'muted', text: line.host }), line.uri),
          h('td', { class: 'num mono', text: seconds(line.duration) }),
          h('td', { class: 'num mono', text: byteSize(line.bytes) }),
          h('td', { class: 'mono', text: line.remote }),
          h('td', { class: 'mono', text: line.upstream ? line.upstream + (line.upstream_status && line.upstream_status !== String(line.status) ? ' (' + line.upstream_status + ')' : '') : '—' }));
      case 'error':
        return h('div', { class: 'log-row' },
          h('span', { class: 'ts wide', text: line.time && line.time.indexOf('0001') !== 0 ? stamp(line.time) : '' }),
          line.level ? h('span', { class: 'kind ' + (LEVEL_KIND[line.level] || 'idle'), text: line.level.toUpperCase() }) : null,
          h('span', { class: 'msg mono', text: line.message }));
      case 'json':
        var rest = Object.keys(line).filter(function (k) { return k !== 'time' && k !== 'level' && k !== 'msg'; });
        return h('div', { class: 'log-row' },
          h('span', { class: 'ts wide', text: line.time ? stamp(line.time) : '' }),
          h('span', { class: 'kind ' + (LEVEL_KIND[line.level] || 'idle'), text: String(line.level || '').toUpperCase() }),
          h('span', { class: 'msg' }, h('span', { class: 'mono', text: line.msg || '' }),
            rest.map(function (k) { return h('span', { class: 'field', text: k + '=' + (typeof line[k] === 'string' ? line[k] : JSON.stringify(line[k])) }); })));
      default:
        return h('div', { class: 'log-row' }, h('span', { class: 'msg mono', text: line.raw || String(line) }));
    }
  }

  // logViewer shows the end of a log, filtered, and follows it on
  // request: every two seconds it asks for what came after the last
  // offset, and stops when the page goes.
  function logViewer(base, format) {
    var offset = 0, following = false, timer = null;
    var q = h('input', { type: 'search', placeholder: 'Filter', 'aria-label': 'Filter the lines' });
    var status = format === 'access' ? h('select', { class: 'input narrow', 'aria-label': 'Status' },
      [['', 'any status'], ['2xx', '2xx'], ['3xx', '3xx'], ['4xx', '4xx'], ['5xx', '5xx']].map(function (o) { return h('option', { value: o[0], text: o[1] }); })) : null;
    var lines = h('select', { class: 'input narrow', 'aria-label': 'Lines' },
      [['100', '100 lines'], ['500', '500 lines'], ['2000', '2000 lines']].map(function (o) { return h('option', { value: o[0], text: o[1] }); }));
    var follow = h('button', { class: 'btn small', type: 'button', 'aria-pressed': 'false', text: 'Follow' });
    var note = h('span', { class: 'right note' });
    var rows, holder;
    if (format === 'access') {
      rows = h('tbody');
      holder = h('div', { class: 'table-wrap' }, h('table', { class: 'table compact logs' },
        h('thead', {}, h('tr', {}, ['Time', 'Status', 'Method', 'Request', 'Time taken', 'Size', 'Client', 'Upstream'].map(function (c, i) {
          return h('th', { class: i === 4 || i === 5 ? 'num' : null, text: c });
        }))), rows));
    } else {
      rows = h('div', { class: 'log logs' });
      holder = rows;
    }
    var view = h('div', { class: 'stack' },
      h('div', { class: 'toolbar' }, h('label', { class: 'search' }, icon('search'), q), status, lines, follow, note), holder);

    function query(extra) {
      var p = ['lines=' + lines.value];
      if (q.value) p.push('q=' + encodeURIComponent(q.value));
      if (status && status.value) p.push('status=' + status.value);
      return base + '?' + p.concat(extra || []).join('&');
    }
    function put(list, replace) {
      if (replace) clear(rows);
      var atBottom = window.innerHeight + window.scrollY >= document.body.scrollHeight - 40;
      append(rows, list.map(function (l) { return logRow(l, format); }));
      while (rows.children.length > 2000) rows.removeChild(rows.firstChild);
      if (!replace && following && atBottom) window.scrollTo(0, document.body.scrollHeight);
    }
    function load() {
      api('GET', query()).then(function (page) {
        offset = page.offset;
        put(page.lines, true);
        note.textContent = page.missing ? 'Nothing logged yet.' : page.lines.length + ' line(s), the latest last';
        if (!page.lines.length && !page.missing) note.textContent = 'No line matches.';
      }).catch(function (e) { note.textContent = e.message; });
    }
    function tick() {
      if (!view.isConnected) { clearInterval(timer); timer = null; return; }
      api('GET', query(['after=' + offset])).then(function (page) {
        offset = page.offset;
        if (page.lines.length) put(page.lines, false);
      }).catch(function () { /* the next tick tries again */ });
    }
    follow.addEventListener('click', function () {
      following = !following;
      follow.setAttribute('aria-pressed', String(following));
      follow.textContent = following ? 'Following' : 'Follow';
      if (following && !timer) timer = setInterval(tick, 2000);
      if (!following && timer) { clearInterval(timer); timer = null; }
    });
    var debounce = null;
    q.addEventListener('input', function () { clearTimeout(debounce); debounce = setTimeout(load, 300); });
    [status, lines].forEach(function (s) { if (s) s.addEventListener('change', load); });
    load();
    return view;
  }

  function hostLogsPage(name) {
    var crumbs = [{ label: 'Proxy hosts', href: '#/hosts' }, { label: name, href: '#/hosts/' + encodeURIComponent(name) }, { label: 'Logs' }];
    if (!can('operator')) {
      shell('#/hosts', crumbs, h('div', { class: 'empty' }, h('span', { class: 'headline', text: 'Logs are for operators: they hold client addresses and URLs.' })));
      return;
    }
    var slot = h('div');
    var seg = h('div', { class: 'seg', role: 'group', 'aria-label': 'Log' });
    [['access', 'Requests'], ['error', 'Errors']].forEach(function (k, i) {
      append(seg, h('button', { type: 'button', 'aria-pressed': String(i === 0), text: k[1], onclick: function () {
        Array.prototype.forEach.call(seg.children, function (b) { b.setAttribute('aria-pressed', String(b === this)); }, this);
        clear(slot).appendChild(logViewer('/hosts/' + encodeURIComponent(name) + '/logs/' + k[0], k[0]));
      } }));
    });
    slot.appendChild(logViewer('/hosts/' + encodeURIComponent(name) + '/logs/access', 'access'));
    shell('#/hosts', crumbs, [
      h('div', { class: 'page-head' }, h('div', {}, h('h1', { class: 'page-title mono', text: name }),
        h('p', { class: 'page-sub', text: 'What nginx wrote about this host: its requests, and its errors.' })), h('div', { class: 'page-actions' }, seg)),
      h('section', { class: 'card' }, slot)
    ]);
  }

  var STREAMS = [
    ['nginx-error', 'nginx errors', 'error', 'operator'],
    ['nginx-access', 'Unknown hosts', 'text', 'operator'],
    ['limen', 'limen', 'json', 'operator'],
    ['apply', 'Applies', 'json', 'operator'],
    ['api', 'Audit', 'json', 'admin']
  ];

  function systemLogsPage(stream) {
    var pick = STREAMS.filter(function (s) { return s[0] === stream && can(s[3]); })[0] || STREAMS[0];
    var seg = h('div', { class: 'seg', role: 'group', 'aria-label': 'Log' },
      STREAMS.filter(function (s) { return can(s[3]); }).map(function (s) {
        return h('button', { type: 'button', 'aria-pressed': String(s === pick), text: s[1], onclick: function () { location.hash = '#/logs/' + s[0]; } });
      }));
    var blurb = {
      'nginx-error': 'nginx\'s own error log: reloads, and what no host\'s log holds.',
      'nginx-access': 'Requests for a name no host answers on.',
      limen: 'The daemon: starts, reloads, renewals, what went wrong.',
      apply: 'Every render of the model, every nginx -t, every reload.',
      api: 'Every request to the panel and who made it.'
    }[pick[0]];
    shell('#/logs', [{ label: 'Logs' }, { label: pick[1] }], [
      h('div', { class: 'page-head' }, h('div', {}, h('h1', { class: 'page-title', text: 'Logs' }), h('p', { class: 'page-sub', text: blurb })),
        h('div', { class: 'page-actions' }, seg)),
      h('section', { class: 'card' }, logViewer('/logs/' + pick[0], pick[2]))
    ]);
  }

  // ─────────────────────────────────────────────────────────────────
  // API tokens
  // ─────────────────────────────────────────────────────────────────

  var TOKEN_STATE = { active: ['success', 'Active'], expired: ['idle', 'Expired'], orphaned: ['warning', 'Orphaned'] };

  function tokensPage() {
    var crumbs = [{ label: 'API tokens' }];
    shell('', crumbs, h('div', { class: 'loading', text: 'Loading…' }));
    api('GET', '/tokens').then(function (data) {
      var items = data.items || [];
      var cols = [
        ['Name', function (t) { return h('span', { title: t.description || '', text: t.name }); }, 'name'],
        can('admin') ? ['User', function (t) { return t.user; }, 'mono'] : null,
        ['Role', function (t) { return t.role; }],
        ['State', function (t) { var st = TOKEN_STATE[t.state] || ['idle', t.state]; return pill(st[0], st[1]); }],
        ['Expires', function (t) { return t.expires ? stamp(t.expires).slice(0, 10) : 'never'; }, 'mono'],
        ['Last used', function (t) { return t.last_used ? ago(t.last_used) + ' · ' + t.last_client : 'never'; }, 'mono'],
        ['', function (t) {
          return h('button', { class: 'btn small danger', text: 'Revoke', onclick: function () { revokeToken(t); } });
        }, 'actions']
      ].filter(Boolean);
      var table = items.length ? h('div', { class: 'table-wrap' }, h('table', { class: 'table' },
        h('thead', {}, h('tr', {}, cols.map(function (c) { return h('th', { text: c[0] }); }))),
        h('tbody', {}, items.map(function (t) {
          return h('tr', { class: t.state === 'active' ? null : 'dim' }, cols.map(function (c) { return h('td', { class: c[2] || null }, c[1](t)); }));
        }))))
        : h('div', { class: 'empty' }, h('span', { class: 'headline', text: 'No API tokens yet.' }),
          h('span', { class: 'note', text: 'A token lets a script use the API as you, without your password.' }));
      shell('', crumbs, [
        h('div', { class: 'page-head' },
          h('div', {}, h('h1', { class: 'page-title', text: 'API tokens' }),
            h('p', { class: 'page-sub', text: 'Keys for scripts, sent as Authorization: Bearer. A token acts as its user, never with more than their role, and cannot manage users or tokens.' })),
          h('div', { class: 'page-actions' }, h('button', { class: 'btn primary', onclick: newToken }, icon('plus'), 'New token'))),
        h('section', { class: 'card flush' }, table)
      ]);
    }).catch(pageError('API tokens'));
  }

  function newToken() {
    var name = h('input', { class: 'input mono', autocomplete: 'off', placeholder: 'deploy-ci' });
    var role = h('select', { class: 'input' }, ['viewer', 'operator', 'admin'].filter(can).map(function (r) {
      return h('option', { value: r, text: r, selected: r === state.user.role });
    }));
    var expires = h('select', { class: 'input' },
      [['30', '30 days'], ['90', '90 days'], ['365', 'One year'], ['0', 'Never']].map(function (o) {
        return h('option', { value: o[0], text: o[1], selected: o[0] === '90' });
      }));
    var description = h('input', { class: 'input', autocomplete: 'off', placeholder: 'What it is for' });
    var pass = h('input', { class: 'input', type: 'password', autocomplete: 'current-password' });
    var body = h('div', { class: 'stack' }, field('Name', name), field('Role', role), field('Expires', expires),
      field('Description', description), field('Your password', pass),
      h('p', { class: 'note', text: 'The token is shown once, right after this.' }));
    dialog('New API token', body, 'Create', false).then(function (ok) {
      if (!ok) return;
      api('POST', '/tokens', { name: name.value.trim(), role: role.value, expires_days: Number(expires.value),
        description: description.value.trim(), password: pass.value }).then(function (res) {
        showToken(res);
        tokensPage();
      }).catch(function (e) { toast('failed', 'Token not created', e.message); });
    });
  }

  function showToken(res) {
    var box = h('input', { class: 'input mono', readonly: true, value: res.token, 'aria-label': 'API token' });
    var copy = h('button', { class: 'btn', type: 'button', text: 'Copy', onclick: function () {
      box.select();
      var done = function () { copy.textContent = 'Copied'; };
      if (navigator.clipboard) navigator.clipboard.writeText(res.token).then(done, function () { document.execCommand('copy'); done(); });
      else { document.execCommand('copy'); done(); }
    } });
    var body = h('div', { class: 'stack' },
      h('p', { class: 'note', text: 'Copy it now: limen keeps only its hash, and cannot show it again.' }),
      h('div', { class: 'token-row' }, box, copy),
      h('p', { class: 'note mono', text: 'curl -H "Authorization: Bearer $LIMEN_TOKEN" ' + location.origin + '/api/v1/status' }));
    dialog('Token ' + res.item.name, body, 'Done', false, true);
    setTimeout(function () { box.select(); }, 0);
  }

  function revokeToken(t) {
    confirmDanger('Revoke ' + t.name + '?', 'Scripts using it are refused from their next request. This cannot be undone.', 'Revoke').then(function (ok) {
      if (!ok) return;
      api('DELETE', '/tokens/' + encodeURIComponent(t.name)).then(function () {
        toast('success', 'Token ' + t.name + ' revoked');
        tokensPage();
      }).catch(function (e) { toast('failed', 'Not revoked', e.message); });
    });
  }

  // ─────────────────────────────────────────────────────────────────
  // Router
  // ─────────────────────────────────────────────────────────────────

  var lastRoute = null;

  function render() {
    // A new page starts at the top; a refresh of the same one stays put.
    if (location.hash !== lastRoute) { window.scrollTo(0, 0); lastRoute = location.hash; }
    var parts = location.hash.replace(/^#\/?/, '').split('/').map(decodeURIComponent);
    if (parts[0] === 'login') { loginPage(); return; }
    if (!state.user) {
      api('GET', '/session').then(function (s) {
        state.user = s.user; state.csrf = s.csrf_token;
        return refreshStatus();
      }).then(render).catch(function () { loginPage(); });
      return;
    }
    var coll = parts[0];
    if (!coll) { refreshStatus().then(dashboard); return; }
    if (coll === 'logs' && can('operator')) { systemLogsPage(parts[1]); return; }
    if (coll === 'tokens') { tokensPage(); return; }
    if (coll === 'hosts' && parts[2] === 'logs') { hostLogsPage(parts[1]); return; }
    if (!KINDS[coll] || (KINDS[coll].role && !can(KINDS[coll].role))) {
      shell('', [{ label: 'Not found' }], h('div', { class: 'empty' }, h('span', { class: 'headline', text: 'There is nothing here.' })));
      return;
    }
    if (parts[1] === 'new') editPage(coll, null);
    else if (parts[2] === 'edit') editPage(coll, parts[1]);
    else refreshStatus().then(function () {
      if (parts.length === 1) listPage(coll);
      else detailPage(coll, parts[1]);
    });
  }

  applyTheme(storedTheme());
  window.addEventListener('hashchange', render);
  // One listener for the whole life of the page: a click anywhere else
  // closes an open account menu, and so does Escape.
  function closeMenus() {
    Array.prototype.forEach.call(document.querySelectorAll('.account-menu[data-open="true"]'), function (m) {
      m.setAttribute('data-open', 'false');
    });
  }
  document.addEventListener('click', closeMenus);
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeMenus(); });
  // Keep the header's health and the counts current without a reload.
  setInterval(function () {
    if (state.user && !document.hidden) refreshStatus();
  }, 20000);
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', render);
  else render();
})();
