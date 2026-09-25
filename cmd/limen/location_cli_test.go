package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ostap-mykhaylyak/limen/internal/model"
)

func TestHostLocations(t *testing.T) {
	h := newHarness(t)
	h.must(t, "access add office --rule allow:10.0.0.0/8 --rule deny:all")
	h.must(t, "host add app --domain app.example.com --forward 10.0.0.5:8080 --websockets")

	h.must(t, "host location add app /api/ --forward http://10.0.0.7:9000 --access-list office")
	h.must(t, "host location add app =/health --public")
	if err := h.do(t, "host location add app /api/"); err == nil {
		t.Error("the same location added twice")
	}
	if err := h.do(t, "host location add app /x/ --access-list nope"); err == nil {
		t.Error("a location on a missing access list accepted")
	}

	got := h.host(t, "app").Locations
	if len(got) != 2 {
		t.Fatalf("locations = %+v", got)
	}
	api, health := got[0], got[1]
	if api.Path != "/api/" || api.Forward == nil || api.Forward.Port != 9000 || api.AccessList != "office" || !api.Websockets {
		t.Errorf("/api/ = %+v (websockets defaults to the host's)", api)
	}
	if !health.Exact || health.Path != "/health" || !health.Public || health.Forward != nil {
		t.Errorf("=/health = %+v", health)
	}

	// set changes only what is passed; the access list and public are
	// one or the other.
	h.must(t, "host location set app /api/ --public --forward=")
	api = h.host(t, "app").Locations[0]
	if !api.Public || api.AccessList != "" || api.Forward != nil || api.Path != "/api/" {
		t.Errorf("after set: %+v", api)
	}

	out := h.must(t, "host location list app")
	for _, want := range []string{"= /health", "/api/", "public", "the host's (http://10.0.0.5:8080)"} {
		if !strings.Contains(out, want) {
			t.Errorf("list is missing %q:\n%s", want, out)
		}
	}

	h.must(t, "host location rm app =/health")
	if n := len(h.host(t, "app").Locations); n != 1 {
		t.Errorf("%d locations after rm", n)
	}
	if err := h.do(t, "host location rm app /nope/"); err == nil {
		t.Error("removing a location that is not there succeeded")
	}
	// Each change is a revision of the host, with its history.
	revs, err := h.store.History(model.KindProxyHost, "app")
	if err != nil || len(revs) < 4 {
		t.Errorf("history: %d revisions, %v", len(revs), err)
	}
}

func TestHostProxyOptionsAndSnippets(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	good := filepath.Join(dir, "good.conf")
	os.WriteFile(good, []byte("# long polling\nproxy_read_timeout 1h;\nadd_header X-Robots-Tag noindex always;\n"), 0o644)
	bad := filepath.Join(dir, "bad.conf")
	os.WriteFile(bad, []byte("gzip on;\ninclude /etc/shadow;\n"), 0o644)

	h.must(t, "host add app --domain app.example.com --forward 10.0.0.5:8080 --read-timeout 1h --stream-responses "+
		"--host-header upstream --request-header X-Env:prod --response-header X-Frame-Options:DENY --snippet-file "+good)
	got := h.host(t, "app")
	p := got.Proxy
	if p.ReadTimeout != "1h" || !p.StreamResponses || p.HostHeader != "upstream" ||
		len(p.RequestHeaders) != 1 || p.RequestHeaders[0] != (model.Header{Name: "X-Env", Value: "prod"}) ||
		len(p.ResponseHeaders) != 1 || p.ResponseHeaders[0].Value != "DENY" {
		t.Errorf("proxy options = %+v", p)
	}
	if !strings.Contains(got.Snippet, "proxy_read_timeout 1h;") {
		t.Errorf("snippet = %q", got.Snippet)
	}

	err := h.do(t, "host set app --snippet-file "+bad)
	if err == nil || !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), "include") {
		t.Errorf("a snippet with include: err = %v", err)
	}
	if !strings.Contains(h.host(t, "app").Snippet, "X-Robots-Tag") {
		t.Error("a refused snippet replaced the good one")
	}

	h.must(t, "host set app --no-snippet --request-header= --read-timeout=")
	got = h.host(t, "app")
	if got.Snippet != "" || len(got.Proxy.RequestHeaders) != 0 || got.Proxy.ReadTimeout != "" || len(got.Proxy.ResponseHeaders) != 1 {
		t.Errorf("after clearing: snippet %q, proxy %+v", got.Snippet, got.Proxy)
	}
	if err := h.do(t, "host set app --request-header NoColon"); err == nil {
		t.Error("a header without a colon accepted")
	}
}

func TestStreamAccessList(t *testing.T) {
	h := newHarness(t)
	h.must(t, "access add office --rule allow:10.0.0.0/8 --rule deny:all")
	h.passwords = []string{"gate-password"}
	h.must(t, "access add gate --user ops")

	h.must(t, "stream add pg --listen 5432 --forward 10.0.0.9:5432 --access-list office")
	doc, _ := h.store.Get(model.KindStream, "pg")
	if doc.(*model.Stream).AccessList != "office" {
		t.Error("the stream's access list was not stored")
	}
	if err := h.do(t, "stream set pg --access-list gate"); err == nil || !strings.Contains(err.Error(), "password") {
		t.Errorf("a stream on a list with users: err = %v", err)
	}
	out := h.must(t, "access list")
	if !strings.Contains(out, "stream pg") {
		t.Errorf("the list does not say it guards the stream:\n%s", out)
	}
}
