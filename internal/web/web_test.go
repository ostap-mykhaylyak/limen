package web

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func get(t *testing.T, path string, header ...string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	w := httptest.NewRecorder()
	Handler().ServeHTTP(w, r)
	return w
}

func TestTheInterfaceIsServedWithAStrictPolicy(t *testing.T) {
	for _, p := range []string{"/", "/assets/app.js", "/assets/app.css", "/assets/favicon.svg"} {
		w := get(t, p)
		if w.Code != 200 {
			t.Errorf("%s: %d", p, w.Code)
			continue
		}
		if got := w.Header().Get("Content-Security-Policy"); got != Policy {
			t.Errorf("%s: CSP = %q", p, got)
		}
		if w.Header().Get("X-Frame-Options") != "DENY" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: missing hardening headers: %v", p, w.Header())
		}
	}
	if ct := get(t, "/assets/app.js").Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("app.js content type = %q", ct)
	}
	for _, directive := range []string{"script-src 'self'", "style-src 'self'", "frame-ancestors 'none'", "default-src 'none'"} {
		if !strings.Contains(Policy, directive) {
			t.Errorf("the policy lacks %q", directive)
		}
	}
	if strings.Contains(Policy, "unsafe") {
		t.Error("the policy allows something unsafe")
	}
}

func TestUnknownPathsAndMethods(t *testing.T) {
	for _, p := range []string{"/nope", "/assets/../web.go", "/static/index.html"} {
		if w := get(t, p); w.Code != 404 {
			t.Errorf("%s: %d, want 404", p, w.Code)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	Handler().ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /: %d", w.Code)
	}
}

func TestETagSavesTheBody(t *testing.T) {
	first := get(t, "/assets/app.js")
	etag := first.Header().Get("ETag")
	if etag == "" || first.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("headers = %v", first.Header())
	}
	if w := get(t, "/assets/app.js", "If-None-Match", etag); w.Code != http.StatusNotModified || w.Body.Len() != 0 {
		t.Errorf("revalidation: %d, %d bytes", w.Code, w.Body.Len())
	}
}

// The policy forbids inline code and styles, and the script never
// parses HTML out of strings: this keeps both true as the interface
// grows. A violation of the first breaks the page; of the second, it
// opens it to whatever a hostname or a description contains.
func TestTheSourcesStayInsideThePolicy(t *testing.T) {
	sub, _ := fs.Sub(static, "static")
	checks := map[string][]*regexp.Regexp{
		".html": {
			regexp.MustCompile(`(?i)<script(?:\s[^>]*)?>\s*[^<\s]`), // a script with a body
			regexp.MustCompile(`(?i)<style`),
			regexp.MustCompile(`(?i)\sstyle\s*=`),
			regexp.MustCompile(`(?i)\son[a-z]+\s*=`),
			regexp.MustCompile(`(?i)https?://`),
		},
		".js": {
			regexp.MustCompile(`\.innerHTML|\.outerHTML|insertAdjacentHTML|document\.write`),
			regexp.MustCompile(`\beval\s*\(|new\s+Function\s*\(`),
			regexp.MustCompile(`setAttribute\(\s*['"]style`),
			// Any URL but the SVG namespace, which is a name, not a fetch.
			regexp.MustCompile(`(?i)https?://(?:[^w'"]|w[^w]|ww[^w]|www[^.]|www\.[^w]|www\.w[^3])`),
		},
		".css": {
			regexp.MustCompile(`@import|url\(\s*['"]?https?:`),
		},
	}
	fs.WalkDir(sub, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := fs.ReadFile(sub, p)
		for ext, res := range checks {
			if !strings.HasSuffix(p, ext) {
				continue
			}
			for _, re := range res {
				if loc := re.FindIndex(b); loc != nil {
					line := strings.Count(string(b[:loc[0]]), "\n") + 1
					t.Errorf("%s:%d breaks the policy: %q matches %s", p, line, b[loc[0]:loc[1]], re)
				}
			}
		}
		return nil
	})
}
