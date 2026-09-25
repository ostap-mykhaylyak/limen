package nginx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ostap-mykhaylyak/limen/internal/config"
	"github.com/ostap-mykhaylyak/limen/internal/importer"
	"github.com/ostap-mykhaylyak/limen/internal/model"
)

// FuzzSnippetStaysInItsBlock is the snippet boundary as a property:
// whatever is accepted, once rendered into a host and read back the way
// nginx reads it, is one server block whose location / holds exactly
// the directives that were accepted, argument for argument. A snippet
// that escaped its block, or reached nginx meaning something else than
// what was checked, breaks it.
func FuzzSnippetStaysInItsBlock(f *testing.F) {
	for _, seed := range []string{
		`add_header X-A "b" always;`,
		`return 200 "a;} server { listen 8081; \"";`,
		`rewrite "^/a\.b$" /c last; sub_filter "a;b{c}" "x\\y";`,
		"proxy_set_header X-Id ${request_id}-a#b;",
		`return 200 'it\'s "fine"';`,
		"gzip on; # } server {",
		`set $x "\\"; }";`,
		"expires 7d;\nerror_page 404 =200 /x;",
	} {
		f.Add(seed)
	}
	cfg := config.Default()
	cfg.Nginx.User = "nginx"
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, src string) {
		want, err := model.ParseSnippet(src)
		if err != nil || len(want) == 0 {
			return
		}
		h := model.NewProxyHost("app")
		h.Domains = []string{"app.example.com"}
		h.Forward = model.Upstream{Scheme: "http", Host: "10.0.0.5", Port: 8080}
		h.Snippet = src
		out, err := Render(Input{Nginx: cfg.Nginx, Panel: cfg.Panel, CertsDir: dir, Features: modern, Exclude: map[Ref]string{}, Hosts: []*model.ProxyHost{h}})
		if err != nil {
			t.Fatal(err)
		}
		f, ok := out.Tree.Files["hosts/app.conf"]
		if !ok {
			// Left out, whole, is safe; the reason must say so.
			if len(out.Skipped) == 0 {
				t.Fatalf("host neither rendered nor skipped for %q", src)
			}
			return
		}
		path := filepath.Join(t.TempDir(), "app.conf")
		os.WriteFile(path, f.Data, 0o644)
		var p importer.Parser
		top, err := p.ParseFile(path)
		if err != nil {
			t.Fatalf("snippet %q made a file nginx cannot read: %v\n%s", src, err, f.Data)
		}
		if len(top) != 1 || top[0].Name != "server" {
			t.Fatalf("snippet %q: %d top-level directives, want one server block\n%s", src, len(top), f.Data)
		}
		var root *importer.Directive
		for _, d := range top[0].Block {
			if d.Name == "location" && strings.Join(d.Args, " ") == "/" {
				root = d
			}
			if d.Name != "location" && d.Name != "listen" && d.Name != "server_name" && d.Name != "access_log" &&
				d.Name != "error_log" && d.Name != "include" {
				t.Fatalf("snippet %q put %s in the server block\n%s", src, d.Name, f.Data)
			}
		}
		if root == nil {
			t.Fatalf("no location /\n%s", f.Data)
		}
		// Every accepted directive is there, with its arguments intact.
		for _, w := range want {
			found := false
			for _, d := range root.Block {
				if d.Name == w.Name && strings.Join(d.Args, "\x00") == strings.Join(w.Args, "\x00") {
					found = true
				}
				if len(d.Block) > 0 || d.HasBlock {
					t.Fatalf("snippet %q opened a block in location /\n%s", src, f.Data)
				}
			}
			if !found {
				t.Fatalf("snippet %q: %s %q is not in location / as accepted\n%s", src, w.Name, w.Args, f.Data)
			}
		}
	})
}
