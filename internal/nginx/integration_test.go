package nginx

// These tests drive a real nginx. They run when LIMEN_TEST_NGINX names
// its binary (the Docker check does, as root, against both the official
// image and Debian's package) and are skipped otherwise: a renderer is
// only as good as what the real binary accepts, and a fake nginx would
// accept whatever limen writes.

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/config"
	"github.com/ostap-mykhaylyak/limen/internal/model"
	"github.com/ostap-mykhaylyak/limen/internal/proc"
	"github.com/ostap-mykhaylyak/limen/internal/secret"
	"github.com/ostap-mykhaylyak/limen/internal/store"
)

type rig struct {
	t      *testing.T
	root   string
	cfg    *config.Config
	store  *store.Store
	engine *Engine
}

func newRig(t *testing.T) *rig {
	bin := os.Getenv("LIMEN_TEST_NGINX")
	if bin == "" {
		t.Skip("LIMEN_TEST_NGINX is not set: no real nginx to test against")
	}
	root := t.TempDir()
	// t.TempDir is 0700 all the way down, and the workers read the
	// htpasswd files through it: open it the way /etc/nginx is open.
	os.Chmod(root, 0o755)
	os.Chmod(filepath.Dir(root), 0o755)
	cfg := config.Default()
	n := &cfg.Nginx
	n.Bin = bin
	n.ConfDir = filepath.Join(root, "nginx")
	n.ConfFile = filepath.Join(n.ConfDir, "nginx.conf")
	n.PIDFile = filepath.Join(root, "nginx.pid")
	n.ErrorLog = filepath.Join(root, "error.log")
	n.AccessLog = filepath.Join(root, "access.log")
	n.HostLogs = filepath.Join(root, "hostlogs")
	n.KeepGenerations = 2
	cfg.Panel.Listen = "127.0.0.1:19187"

	if err := os.MkdirAll(n.ConfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// What the distribution shipped, which the first install must keep.
	if err := os.WriteFile(n.ConfFile, []byte("# the distribution's file\nevents {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := store.Open(store.Under(filepath.Join(root, "model")))
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, root: root, cfg: cfg, store: s}
	r.engine = &Engine{
		Store:    s,
		Config:   func() *config.Config { return cfg },
		CertsDir: filepath.Join(root, "certs"),
		LockPath: filepath.Join(root, "apply.lock"),
	}
	t.Cleanup(r.stopNginx)
	return r
}

func (r *rig) put(doc model.Document) {
	r.t.Helper()
	if _, err := r.store.Put(doc, store.Change{Author: "test"}); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) apply() Result {
	r.t.Helper()
	res, err := r.engine.Apply(context.Background(), false)
	if err != nil {
		log, _ := os.ReadFile(r.cfg.Nginx.ErrorLog)
		r.t.Fatalf("apply: %v\nresult: %+v\nnginx error log:\n%s", err, res, log)
	}
	return res
}

func (r *rig) startNginx() {
	r.t.Helper()
	out, err := exec.Command(r.cfg.Nginx.Bin, "-c", r.cfg.Nginx.ConfFile).CombinedOutput()
	if err != nil {
		r.t.Fatalf("start nginx: %v\n%s", err, out)
	}
	for range 50 {
		if nginxRunning(r.cfg.Nginx) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	r.t.Fatal("nginx did not start")
}

func (r *rig) stopNginx() {
	if pid, err := proc.ReadPidfile(r.cfg.Nginx.PIDFile); err == nil {
		exec.Command(r.cfg.Nginx.Bin, "-c", r.cfg.Nginx.ConfFile, "-s", "quit").Run()
		for i := 0; i < 50 && proc.Alive(pid); i++ {
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// get sends a request to nginx on :80 for the given host.
func get(host, path string, header http.Header) (int, string, error) {
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil)
	req.Host = host
	maps.Copy(req.Header, header)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}

// backend answers with what it received, so the tests can see what
// nginx forwarded.
func backend(t *testing.T) (*httptest.Server, int) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "path=%s xff=%s auth=%q", r.URL.Path, r.Header.Get("X-Forwarded-For"), r.Header.Get("Authorization"))
	}))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	var p int
	fmt.Sscan(port, &p)
	return srv, p
}

func host(name string, port int, domains ...string) *model.ProxyHost {
	h := model.NewProxyHost(name)
	h.Domains = domains
	h.Forward = model.Upstream{Scheme: "http", Host: "127.0.0.1", Port: port}
	return h
}

func TestRealNginxFullCycle(t *testing.T) {
	r := newRig(t)
	_, port := backend(t)

	// 1. First install, nginx not running yet.
	r.put(host("app", port, "app.example.com"))
	res := r.apply()
	if !res.Changed || res.Reloaded || res.NginxRunning {
		t.Fatalf("first apply = %+v", res)
	}
	before, err := os.ReadFile(filepath.Join(r.cfg.Nginx.ConfDir, beforeFile))
	if err != nil || !strings.Contains(string(before), "the distribution's file") {
		t.Fatalf("the distribution's nginx.conf was not kept: %v", err)
	}
	t.Logf("nginx %s, generation %s", res.NginxVersion, res.Generation)

	r.startNginx()
	code, body, err := get("app.example.com", "/hello", http.Header{"X-Forwarded-For": {"6.6.6.6"}})
	if err != nil || code != 200 || !strings.HasPrefix(body, "path=/hello") {
		t.Fatalf("app: %d %q %v", code, body, err)
	}
	if !strings.Contains(body, "xff=127.0.0.1") {
		t.Errorf("the client's forged X-Forwarded-For reached the backend: %s", body)
	}
	if _, _, err := get("unknown.example.com", "/", nil); err == nil {
		t.Error("an unknown host got an answer: the default server should close the connection")
	}

	// 2. Nothing changed: nothing is done, nginx is not touched.
	if res := r.apply(); res.Changed || res.Reloaded {
		t.Errorf("an apply with no change touched nginx: %+v", res)
	}

	// 3. A host behind basic auth, checked by real nginx workers
	// reading the htpasswd file limen wrote.
	hash, err := secret.HashBasic("gate-password")
	if err != nil {
		t.Fatal(err)
	}
	acl := model.NewAccessList("staff")
	acl.Users = []model.BasicUser{{Username: "ops", Password: hash}}
	r.put(acl)
	admin := host("admin", port, "admin.example.com")
	admin.AccessList = "staff"
	r.put(admin)
	if res := r.apply(); !res.Reloaded {
		t.Fatalf("apply after adding a host = %+v", res)
	}
	if code, _, _ := get("admin.example.com", "/", nil); code != 401 {
		t.Errorf("guarded host without credentials: %d, want 401", code)
	}
	if code, _, _ := get("admin.example.com", "/", http.Header{"Authorization": {basic("ops", "wrong-password")}}); code != 401 {
		t.Errorf("guarded host with a wrong password: %d, want 401", code)
	}
	code, body, _ = get("admin.example.com", "/", http.Header{"Authorization": {basic("ops", "gate-password")}})
	if code != 200 {
		t.Fatalf("guarded host with the right password: %d %s — the workers cannot read or verify the htpasswd", code, body)
	}
	if !strings.Contains(body, `auth=""`) {
		t.Errorf("the gate's credentials reached the backend: %s", body)
	}

	// 4. A host nginx cannot load is left out; everything else goes on.
	b := host("broken", 80, "broken.example.com")
	b.Forward.Host = "no-such-host.invalid"
	r.put(b)
	res = r.apply()
	if !res.OK() {
		t.Fatalf("one broken host failed the whole apply: %+v", res)
	}
	// Without the broken host the tree is the one already live, so
	// nginx is rightly left alone.
	if res.Changed || res.Reloaded {
		t.Errorf("excluding the only new host still changed nginx: %+v", res)
	}
	reason := skipReason(res, "broken")
	if !strings.Contains(reason, "host not found") {
		t.Errorf("broken host skip reason = %q", reason)
	}
	if code, _, _ := get("app.example.com", "/", nil); code != 200 {
		t.Errorf("after excluding a broken host, app answers %d", code)
	}

	// 5. A stream on a port another program holds: nginx -t binds
	// nothing and passes; the reload fails; limen puts the previous
	// configuration back, leaves the stream out, and applies the rest.
	if r.engineHasStream(t) {
		taken, err := net.Listen("tcp", "0.0.0.0:15432")
		if err != nil {
			t.Fatal(err)
		}
		defer taken.Close()
		clash := model.NewStream("clash")
		clash.Listen = 15432
		clash.Forward = model.Endpoint{Host: "127.0.0.1", Port: 1}
		r.put(clash)

		echo := echoServer(t)
		pg := model.NewStream("echo")
		pg.Listen = 15433
		pg.Forward = model.Endpoint{Host: "127.0.0.1", Port: echo}
		r.put(pg)

		res = r.apply()
		if !res.OK() || !res.Reloaded {
			t.Fatalf("a taken port failed the whole apply: %+v", res)
		}
		if !strings.Contains(skipReason(res, "clash"), "already in use") {
			t.Errorf("clash skip reason = %q; skipped: %+v", skipReason(res, "clash"), res.Skipped)
		}
		if got := roundTrip(t, "127.0.0.1:15433", "ping\n"); got != "ping" {
			t.Errorf("stream echo = %q, want ping", got)
		}
		if code, _, _ := get("app.example.com", "/", nil); code != 200 {
			t.Errorf("after the reload rollback, app answers %d", code)
		}
	}

	// 6. Old generations are pruned.
	gens, _ := os.ReadDir(filepath.Join(r.cfg.Nginx.ConfDir, gensDir))
	if len(gens) > r.cfg.Nginx.KeepGenerations+1 {
		t.Errorf("%d generations kept, want at most %d", len(gens), r.cfg.Nginx.KeepGenerations+1)
	}
}

func TestRealNginxDryRunChangesNothing(t *testing.T) {
	r := newRig(t)
	_, port := backend(t)
	r.put(host("app", port, "app.example.com"))
	r.apply()
	link, _ := os.Readlink(filepath.Join(r.cfg.Nginx.ConfDir, linkName))

	r.put(host("app", port, "app.example.com", "www.example.com"))
	res, err := r.engine.Apply(context.Background(), true)
	if err != nil || !res.Changed {
		t.Fatalf("dry run = %+v, %v", res, err)
	}
	after, _ := os.Readlink(filepath.Join(r.cfg.Nginx.ConfDir, linkName))
	if after != link {
		t.Error("a dry run changed the live tree")
	}
	if entries, _ := os.ReadDir(filepath.Join(r.cfg.Nginx.ConfDir, gensDir)); len(entries) != 1 {
		t.Errorf("a dry run left its candidate behind: %d generations", len(entries))
	}
}

// An error nobody owns must stop the apply and leave nginx as it was.
func TestRealNginxSharedErrorStopsEverything(t *testing.T) {
	r := newRig(t)
	_, port := backend(t)
	r.put(host("app", port, "app.example.com"))
	r.apply()
	link, _ := os.Readlink(filepath.Join(r.cfg.Nginx.ConfDir, linkName))

	r.cfg.Nginx.User = "no-such-user-limen"
	r.put(host("app", port, "app.example.com", "www.example.com"))
	_, err := r.engine.Apply(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "no-such-user-limen") {
		t.Fatalf("err = %v, want nginx's complaint about the user", err)
	}
	if after, _ := os.Readlink(filepath.Join(r.cfg.Nginx.ConfDir, linkName)); after != link {
		t.Error("a refused configuration was installed")
	}
}

// The permission problem that turns every guarded host into a 500 is
// invisible to nginx -t: limen has to say so itself.
func TestRealNginxWarnsWhenWorkersCannotReachTheTree(t *testing.T) {
	r := newRig(t)
	os.Chmod(r.root, 0o700)
	defer os.Chmod(r.root, 0o755)

	acl := model.NewAccessList("staff")
	hash, _ := secret.HashBasic("gate-password")
	acl.Users = []model.BasicUser{{Username: "ops", Password: hash}}
	r.put(acl)
	h := host("admin", 8080, "admin.example.com")
	h.AccessList = "staff"
	r.put(h)

	res := r.apply()
	if !strings.Contains(strings.Join(res.Warnings, " | "), "cannot get through "+r.root) {
		t.Errorf("no warning about the unreachable tree: %v", res.Warnings)
	}
}

func (r *rig) engineHasStream(t *testing.T) bool {
	f, err := Probe(context.Background(), r.cfg.Nginx.Bin)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Stream {
		t.Log("this nginx has no stream module: skipping the stream part")
	}
	return f.Stream
}

func skipReason(res Result, name string) string {
	for _, s := range res.Skipped {
		if s.Name == name {
			return s.Reason
		}
	}
	return ""
}

func basic(user, pass string) string {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth(user, pass)
	return req.Header.Get("Authorization")
}

func echoServer(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadString('\n')
				c.Write([]byte(strings.TrimSpace(line)))
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func roundTrip(t *testing.T, addr, msg string) string {
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Errorf("dial %s: %v", addr, err)
		return ""
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte(msg))
	b, err := io.ReadAll(c)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Errorf("read %s: %v", addr, err)
	}
	return string(b)
}

// selfSigned writes a certificate for the given names where M5 will
// put the real ones.
func selfSigned(t *testing.T, dir string, names ...string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "fullchain.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(filepath.Join(dir, "privkey.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
}

// TLS is where the two nginx lines differ most (http2 as a listen
// parameter before 1.25.1, as a directive after), so it is checked end
// to end: redirect, HTTP/2, HSTS, and the refusal of unknown names.
func TestRealNginxTLS(t *testing.T) {
	r := newRig(t)
	_, port := backend(t)
	selfSigned(t, filepath.Join(r.engine.CertsDir, "app"), "app.example.com")
	c := model.NewCertificate("app")
	c.Provider, c.Challenge, c.Domains = model.ProviderCustom, "", []string{"app.example.com"}
	r.put(c)

	h := host("app", port, "app.example.com")
	h.TLS = model.TLS{Certificate: "app", ForceHTTPS: true, HTTP2: true, HSTS: true}
	r.put(h)
	r.apply()
	r.startNginx()

	// Plain HTTP is sent to HTTPS.
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1/x?y=1", nil)
	req.Host = "app.example.com"
	noFollow := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 301 || resp.Header.Get("Location") != "https://app.example.com/x?y=1" {
		t.Errorf("http: %d Location=%q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// HTTPS, over HTTP/2, with HSTS.
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{ServerName: "app.example.com", InsecureSkipVerify: true},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	req, _ = http.NewRequest(http.MethodGet, "https://127.0.0.1/secure", nil)
	req.Host = "app.example.com"
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(string(body), "path=/secure") {
		t.Errorf("https: %d %s", resp.StatusCode, body)
	}
	if resp.Proto != "HTTP/2.0" {
		t.Errorf("https protocol = %s, want HTTP/2.0", resp.Proto)
	}
	if !strings.HasPrefix(resp.Header.Get("Strict-Transport-Security"), "max-age=63072000") {
		t.Errorf("HSTS = %q", resp.Header.Get("Strict-Transport-Security"))
	}

	// A name nobody serves does not even get a certificate to look at.
	conn, err := tls.Dial("tcp", "127.0.0.1:443", &tls.Config{ServerName: "other.example.com", InsecureSkipVerify: true})
	if err == nil {
		conn.Close()
		t.Error("the TLS handshake for an unknown name succeeded: it leaks a host's certificate")
	}
}
