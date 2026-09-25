package api

import (
	"strings"
	"testing"
)

func TestHostLocationsAndSnippetsThroughTheAPI(t *testing.T) {
	e := newEnv(t)
	c := e.login("olga")
	if r := c.do("POST", "/access-lists", map[string]any{"name": "office", "rules": []map[string]string{{"action": "allow", "address": "10.0.0.0/8"}}}); r.code != 201 {
		t.Fatalf("access list: %d %s", r.code, r.raw)
	}

	b := host("app.example.com", 8080)
	b["proxy"] = map[string]any{"read_timeout": "1h", "stream_responses": true,
		"request_headers": []map[string]string{{"name": "X-Env", "value": "prod"}}}
	b["snippet"] = "add_header X-Robots-Tag noindex always;"
	b["locations"] = []map[string]any{
		{"path": "/api/", "forward": map[string]any{"scheme": "http", "host": "10.0.0.7", "port": 9000}, "access_list": "office"},
		{"path": "/health", "exact": true, "public": true},
	}
	r := c.do("POST", "/hosts", b)
	if r.code != 201 {
		t.Fatalf("create: %d %s", r.code, r.raw)
	}

	// What GET returns, PUT accepts.
	got := c.do("GET", "/hosts/app.example.com", nil)
	locs := got.body["locations"].([]any)
	if len(locs) != 2 || locs[1].(map[string]any)["forward"] != nil {
		t.Errorf("locations = %v", locs)
	}
	if r := c.do("PUT", "/hosts/app.example.com", got.body); r.code != 200 {
		t.Errorf("round trip: %d %s", r.code, r.raw)
	}

	refused := map[string]func(map[string]any){
		"a snippet that includes a file":  func(m map[string]any) { m["snippet"] = "include /etc/shadow;" },
		"a snippet that leaves its block": func(m map[string]any) { m["snippet"] = "} server { listen 8080; }" },
		"a location on a socket": func(m map[string]any) {
			m["locations"] = []map[string]any{{"path": "/x/", "forward": map[string]any{"scheme": "http", "socket": "/var/run/docker.sock"}}}
		},
		"a location snippet that opens access": func(m map[string]any) {
			m["locations"] = []map[string]any{{"path": "/x/", "snippet": "allow all;"}}
		},
		"an unknown location field": func(m map[string]any) {
			m["locations"] = []map[string]any{{"path": "/x/", "acess_list": "office"}}
		},
	}
	for name, mutate := range refused {
		m := host("app.example.com", 8080)
		mutate(m)
		if r := c.do("PUT", "/hosts/app.example.com", m); r.code != 422 {
			t.Errorf("%s: %d %s", name, r.code, r.raw)
		}
	}
	missing := host("app.example.com", 8080)
	missing["locations"] = []map[string]any{{"path": "/x/", "access_list": "nope"}}
	if r := c.do("PUT", "/hosts/app.example.com", missing); r.code != 409 || !strings.Contains(r.raw, "nope") {
		t.Errorf("a location on a missing list: %d %s", r.code, r.raw)
	}
}
