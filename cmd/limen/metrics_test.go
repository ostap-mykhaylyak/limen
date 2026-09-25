package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ostap-mykhaylyak/limen/internal/acme"
	"github.com/ostap-mykhaylyak/limen/internal/config"
	"github.com/ostap-mykhaylyak/limen/internal/logging"
	"github.com/ostap-mykhaylyak/limen/internal/metrics"
	"github.com/ostap-mykhaylyak/limen/internal/store"
	"github.com/ostap-mykhaylyak/limen/internal/traffic"
)

func TestPrometheusListener(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	os.WriteFile(cfgPath, []byte("metrics:\n  listen: \"127.0.0.1:0\"\n"), 0o600)
	cfgs, err := config.NewManager(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(store.Under(filepath.Join(dir, "model")))
	if err != nil {
		t.Fatal(err)
	}
	c := traffic.NewCollector(func(h string) string { return filepath.Join(dir, h) }, nil)
	defer c.Close()
	certs := &acme.Manager{Store: s, Config: cfgs.Get, CertsDir: filepath.Join(dir, "certs")}
	m := serveMetrics(cfgs, logging.Discard(), metrics.New(), c, &traffic.NginxProbe{}, certs, s)
	if m == nil {
		t.Fatal("no listener")
	}
	defer m.close()

	resp, err := http.Get("http://" + m.addr.String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Errorf("content type %q", ct)
	}
	for _, want := range []string{"limen_up 1", "# TYPE limen_applies_total counter", "limen_nginx_up 0"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %q in:\n%s", want, b)
		}
	}
	if resp, err := http.Get("http://" + m.addr.String() + "/"); err == nil {
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("/ answers %d: the listener serves /metrics only", resp.StatusCode)
		}
		resp.Body.Close()
	}
}
