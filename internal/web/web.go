// Package web serves the panel's interface: one HTML page, one
// stylesheet, one script, compiled into the binary.
//
// The Content-Security-Policy allows nothing but this origin, and
// nothing inline. That is only possible because the interface was
// written for it — no inline style, no inline script, no HTML built from
// strings — and a test keeps it that way.
package web

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"mime"
	"net/http"
	"path"
)

//go:embed static
var static embed.FS

// Policy is the Content-Security-Policy of every page and asset.
const Policy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; " +
	"connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

type file struct {
	data  []byte
	ctype string
	etag  string
}

// Handler serves the interface. Only GET and HEAD, only the files that
// exist; everything else is a 404.
func Handler() http.Handler {
	sub, err := fs.Sub(static, "static")
	if err != nil {
		panic(err)
	}
	files := map[string]file{}
	fs.WalkDir(sub, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(sub, p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		ctype := mime.TypeByExtension(path.Ext(p))
		if ctype == "" {
			ctype = "application/octet-stream"
		}
		files["/"+p] = file{data: b, ctype: ctype, etag: `"` + hex.EncodeToString(sum[:8]) + `"`}
		return nil
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", Policy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")

		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			h.Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := r.URL.Path
		if p == "/" {
			p = "/index.html"
		}
		// An exact lookup among the embedded files: "../" or any other
		// path outside them cannot match anything.
		f, ok := files[p]
		if !ok {
			h.Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"not found"}` + "\n"))
			return
		}
		h.Set("Content-Type", f.ctype)
		// Revalidate every time: after an upgrade the new script must be
		// the one that runs, and the ETag keeps it cheap.
		h.Set("Cache-Control", "no-cache")
		h.Set("ETag", f.etag)
		if r.Header.Get("If-None-Match") == f.etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if r.Method == http.MethodHead {
			return
		}
		w.Write(f.data)
	})
}
