package model

import "testing"

// A document is a file anyone with a shell may have edited: decoding
// and validating one must never panic, whatever it holds.
func FuzzDecodeProxyHost(f *testing.F) {
	f.Add("kind: proxy_host\nname: app\ndomains: [app.example.com]\nforward: {host: 10.0.0.5, port: 80}\n")
	f.Add("locations:\n  - path: /x/\n    forward: {scheme: http, host: a, port: 1}\n    snippet: \"return 200 x;\"\n")
	f.Add("proxy: {request_headers: [{name: X, value: \"$x\"}]}\n")
	f.Fuzz(func(t *testing.T, s string) {
		doc, err := Decode(KindProxyHost, "app", []byte(s))
		if err != nil {
			return
		}
		doc.Validate()
		Clone(doc)
	})
}

func FuzzParseSnippet(f *testing.F) {
	f.Add(`return 200 "a;} server {";`)
	f.Add("proxy_set_header X ${a}\\;b;")
	f.Fuzz(func(t *testing.T, s string) {
		ds, err := ParseSnippet(s)
		if err != nil {
			return
		}
		for _, d := range ds {
			d.Key()
			if _, ok := snippetDirectives[d.Name]; !ok {
				t.Fatalf("%q accepted a directive off the list: %s", s, d.Name)
			}
		}
	})
}
