package importer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ostap-mykhaylyak/limen/internal/model"
)

// --import reads whatever /etc/nginx holds: parsing it and planning an
// import from it must not panic or hang.
func FuzzImport(f *testing.F) {
	f.Add("http { server { listen 80; server_name a.example.com; location / { proxy_pass http://127.0.0.1:1; } location = /x { return 200 \"a\\\"b\"; } } }")
	f.Add("http { server { listen 443 ssl; server_name *.a.b; if ($host = a) { return 301 https://$host$request_uri; } } }")
	f.Add("stream { server { listen 5432; proxy_pass 10.0.0.1:5432; } }")
	f.Add("http { server { location /a { location /b { } } }")
	f.Fuzz(func(t *testing.T, conf string) {
		dir := t.TempDir()
		path := filepath.Join(dir, "nginx.conf")
		os.WriteFile(path, []byte(conf), 0o644)
		p := &Parser{Rebase: func(s string) string { return filepath.Join(dir, "nothing", filepath.Base(s)) }}
		top, err := p.ParseFile(path)
		if err != nil {
			return
		}
		plan := Build(top, Options{Exists: func(model.Kind, string) bool { return false }, ReadFile: os.ReadFile})
		for _, d := range plan.Docs {
			// Whatever the import proposes, the model accepts.
			if err := d.Validate(); err != nil {
				t.Fatalf("the import proposes a document the model refuses: %v\n%s", err, conf)
			}
		}
	})
}
