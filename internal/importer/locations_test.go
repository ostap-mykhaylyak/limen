package importer

import (
	"strings"
	"testing"

	"github.com/ostap-mykhaylyak/limen/internal/model"
)

func TestCustomLocationsAreImported(t *testing.T) {
	p := plan(t, map[string]string{
		"nginx.conf": debianMain,
		"sites-enabled/app": `
server {
    listen 80;
    server_name app.example.com;
    location / { proxy_pass http://127.0.0.1:3000; }
    location /api/ {
        proxy_pass http://10.0.0.7:9000;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 1h;
        add_header X-Api "v1; beta" always;
        rewrite "^/api/v0/(.*)\.json$" /api/v1/$1 break;
    }
    location = /health {
        access_log off;
        return 200 "ok";
    }
    location /same/ { proxy_pass http://127.0.0.1:3000; }
}
`,
	})
	h, ok := find[*model.ProxyHost](p, "app.example.com")
	if !ok {
		t.Fatalf("not imported: %v", p.Skipped)
	}
	if len(h.Locations) != 3 {
		t.Fatalf("locations = %+v", h.Locations)
	}
	api, health, same := h.Locations[0], h.Locations[1], h.Locations[2]
	if api.Path != "/api/" || api.Forward == nil || api.Forward.Port != 9000 || !api.Websockets {
		t.Errorf("/api/ = %+v", api)
	}
	// X-Forwarded-For and Connection are limen's own; the rest is kept,
	// with the regular expression's \. untouched.
	ds, err := model.ParseSnippet(api.Snippet)
	if err != nil {
		t.Fatalf("/api/ snippet does not parse back: %v\n%s", err, api.Snippet)
	}
	var got []string
	for _, d := range ds {
		got = append(got, d.Name+" "+strings.Join(d.Args, "|"))
	}
	want := []string{"proxy_read_timeout 1h", "add_header X-Api|v1; beta|always", `rewrite ^/api/v0/(.*)\.json$|/api/v1/$1|break`}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("/api/ snippet:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if !health.Exact || health.Forward != nil || !strings.Contains(health.Snippet, "return") {
		t.Errorf("= /health = %+v", health)
	}
	if same.Forward != nil {
		t.Errorf("a location proxying to the host's own backend should say so: %+v", same.Forward)
	}
	if err := h.Validate(); err != nil {
		t.Errorf("the imported host does not validate: %v", err)
	}
}

func TestLocationsLimenCannotKeep(t *testing.T) {
	cases := map[string]string{
		"a regular expression":           `location ~ \.php$ { proxy_pass http://127.0.0.1:2; }`,
		"a named location":               `location @fallback { proxy_pass http://127.0.0.1:2; }`,
		"a directive outside the list":   `location /x/ { proxy_pass http://127.0.0.1:2; proxy_cache zone; }`,
		"files":                          `location /x/ { alias /var/www/; }`,
		"a guard of its own":             `location /x/ { auth_basic "x"; auth_basic_user_file /etc/x; proxy_pass http://127.0.0.1:2; }`,
		"a nested location":              `location /x/ { location /x/y/ { return 404; } proxy_pass http://127.0.0.1:2; }`,
		"a path rewritten by proxy_pass": `location /x/ { proxy_pass http://127.0.0.1:2/y/; }`,
	}
	for name, loc := range cases {
		p := plan(t, map[string]string{
			"nginx.conf":      debianMain,
			"sites-enabled/x": "server {\n listen 80;\n server_name x.example.com;\n location / { proxy_pass http://127.0.0.1:1; }\n " + loc + "\n}\n",
		})
		if _, ok := find[*model.ProxyHost](p, "x.example.com"); ok {
			t.Errorf("%s: imported", name)
		}
		reason := skippedAbout(p, "x.example.com")
		if reason == "" {
			t.Errorf("%s: no reason given: %v", name, p.Skipped)
		}
		if name == "a guard of its own" && !strings.Contains(reason, "access list after the import") {
			t.Errorf("the reason does not say what to do: %s", reason)
		}
	}
}

func TestQuotedStringsKeepTheirBackslashes(t *testing.T) {
	toks := tokenize(`rewrite "^/a\.b$" "say \"hi\"" 'it\'s' "c:\\d";`)
	var words []string
	for _, tk := range toks {
		words = append(words, tk.text)
	}
	want := []string{"rewrite", `^/a\.b$`, `say "hi"`, "it's", `c:\d`, ";"}
	if strings.Join(words, "|") != strings.Join(want, "|") {
		t.Errorf("tokens %q, want %q", words, want)
	}
}
