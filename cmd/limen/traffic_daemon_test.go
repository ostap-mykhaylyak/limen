package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/status"
	"github.com/ostap-mykhaylyak/limen/internal/traffic"
)

func TestTrafficInTheReport(t *testing.T) {
	dir := t.TempDir()
	c := traffic.NewCollector(func(h string) string { return filepath.Join(dir, h+".log") }, nil)
	defer c.Close()
	now := time.Now()
	var b strings.Builder
	for i := range 30 {
		code := 200
		if i%3 == 0 {
			code = 503
		}
		b.WriteString(accessLine(now, code, "/x"))
	}
	os.WriteFile(filepath.Join(dir, "shop.log"), []byte(b.String()), 0o644)
	// Two failures out of three requests: too few to alert on.
	os.WriteFile(filepath.Join(dir, "tiny.log"), []byte(accessLine(now, 500, "/")+accessLine(now, 500, "/")+accessLine(now, 200, "/")), 0o644)
	c.Watch([]string{"shop", "tiny"})
	c.Poll()

	var rep status.Report
	rep.Add("nginx", status.StatusOK, "running")
	addTraffic(&rep, c, &traffic.NginxProbe{})
	if rep.Status != status.StatusWarn {
		t.Fatalf("status %s, checks %+v", rep.Status, rep.Checks)
	}
	var detail string
	for _, ch := range rep.Checks {
		if ch.Name == "errors" {
			detail = ch.Detail
		}
	}
	// tiny fails two requests out of three: noise, not an alert.
	if detail != "shop answers 33% 5xx over the last 5 minutes" {
		t.Errorf("errors check = %q", detail)
	}

	var out bytes.Buffer
	rep.Service.Active = true
	rep.WriteText(&out, nil)
	if !strings.Contains(out.String(), "TRAFFIC (last 5 minutes)") || !strings.Contains(out.String(), "33.3% 5xx") {
		t.Errorf("text report:\n%s", out.String())
	}
}
