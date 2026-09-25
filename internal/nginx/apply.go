package nginx

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/config"
	"github.com/ostap-mykhaylyak/limen/internal/flock"
	"github.com/ostap-mykhaylyak/limen/internal/model"
	"github.com/ostap-mykhaylyak/limen/internal/proc"
	"github.com/ostap-mykhaylyak/limen/internal/store"
)

// Layout on disk, under nginx.conf_dir:
//
//	nginx.conf                 the live main file (written atomically)
//	limen -> limen.d/<gen>     the live tree (a symlink, swapped atomically)
//	limen.d/<gen>/             one rendered generation, complete
//	limen.d/<gen>/limen -> .   so that "limen/..." resolves inside it too
//	nginx.conf.before-limen    the distribution's file, kept on first install
const (
	linkName   = "limen"
	gensDir    = "limen.d"
	beforeFile = "nginx.conf.before-limen"
)

var genNameRe = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}-[0-9a-f]{12}$`)

// Result describes one apply.
type Result struct {
	At           time.Time     `json:"at"`
	Duration     time.Duration `json:"duration_ns"`
	DryRun       bool          `json:"dry_run"`
	Revision     int64         `json:"revision"`
	Generation   string        `json:"generation"`
	Changed      bool          `json:"changed"`
	Reloaded     bool          `json:"reloaded"`
	NginxRunning bool          `json:"nginx_running"`
	NginxVersion string        `json:"nginx_version"`
	Skipped      []SkipInfo    `json:"skipped,omitempty"`
	// RolledBack counts the reloads nginx refused, after which the
	// previous generation was put back.
	RolledBack int      `json:"rolled_back,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
	Error      string   `json:"error,omitempty"`
}

// SkipInfo is a skipped document in serializable form.
type SkipInfo struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// OK reports whether the apply succeeded.
func (r Result) OK() bool { return r.Error == "" }

// Engine renders the model and puts it in front of nginx.
type Engine struct {
	Store    *store.Store
	Config   func() *config.Config
	CertsDir string
	// LockPath serializes applies across processes: the daemon and the
	// command line may both apply.
	LockPath string
	Log      *slog.Logger

	// ReloadWait is how long a reload is watched for an error.
	ReloadWait time.Duration

	mu   sync.Mutex
	last *Result
}

// Last returns the most recent apply of this engine.
func (e *Engine) Last() (Result, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.last == nil {
		return Result{}, false
	}
	return *e.last, true
}

// Apply renders the model, tests it, installs it and reloads nginx.
// With dryRun it stops after the test and changes nothing.
func (e *Engine) Apply(ctx context.Context, dryRun bool) (Result, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	start := time.Now()
	res := Result{At: start.UTC(), DryRun: dryRun, Revision: e.Store.Revision()}
	err := e.apply(ctx, dryRun, &res)
	res.Duration = time.Since(start)
	if err != nil {
		res.Error = err.Error()
	}
	e.last = &res
	e.logResult(res)
	return res, err
}

func (e *Engine) apply(ctx context.Context, dryRun bool, res *Result) error {
	cfg := e.Config()
	n := cfg.Nginx

	unlock, err := flock.Lock(e.LockPath)
	if err != nil {
		return fmt.Errorf("apply lock: %w", err)
	}
	defer unlock()

	feat, err := Probe(ctx, n.Bin)
	if err != nil {
		return fmt.Errorf("nginx is not usable: %w", err)
	}
	res.NginxVersion = feat.VersionString()
	n.User = WorkerUser(n.User, feat)

	in := Input{
		Hosts:     store.All[*model.ProxyHost](e.Store, model.KindProxyHost),
		Redirects: store.All[*model.Redirect](e.Store, model.KindRedirect),
		Streams:   store.All[*model.Stream](e.Store, model.KindStream),
		Access:    store.All[*model.AccessList](e.Store, model.KindAccessList),
		Nginx:     n,
		Panel:     cfg.Panel,
		CertsDir:  e.CertsDir,
		Features:  feat,
		IPv6:      n.IPv6 == "on" || n.IPv6 == "auto" && HasIPv6(),

		StreamModule: StreamLoadable(feat, n.Modules),
		Exclude:      map[Ref]string{},
	}

	gens := filepath.Join(n.ConfDir, gensDir)
	if err := os.MkdirAll(gens, 0o755); err != nil {
		return err
	}
	// nginx opens the per-host logs when it tests a candidate, and
	// fails if their directory is not there. They hold client
	// addresses and URLs, so nobody else may look in; but the workers
	// must: on SIGUSR1 (logrotate) every worker reopens its logs itself,
	// as the worker user, and one that cannot reach them goes on writing
	// to the rotated file. Root's, the workers' group, 0750 — set again
	// at every apply, whatever an earlier version or a hand left there.
	if err := os.MkdirAll(n.HostLogs, 0o750); err != nil {
		return err
	}
	if err := os.Chmod(n.HostLogs, 0o750); err != nil {
		return err
	}
	var logsWarning []string
	if err := chownGroup(n.HostLogs, n.User); err != nil {
		logsWarning = append(logsWarning, fmt.Sprintf("%s: %v: nginx's workers cannot reopen the host logs after a rotation", n.HostLogs, err))
	}
	live := liveGeneration(n.ConfDir)

	// Each round renders, tests, and — when nginx pins an error on a
	// document — leaves that document out and tries again. One broken
	// host must not keep every other change from reaching nginx.
	maxRounds := len(in.Hosts) + len(in.Redirects) + len(in.Streams) + len(in.Access) + 2
	for range maxRounds {
		out, err := Render(in)
		if err != nil {
			return err
		}
		res.Skipped = skipInfo(out.Skipped)
		res.Warnings = append(append([]string(nil), logsWarning...), out.Warnings...)

		hash := treeHash(out.Tree)
		name := time.Now().UTC().Format("20060102T150405") + "-" + hash[:12]
		if live != "" && strings.HasSuffix(live, "-"+hash[:12]) {
			res.Generation = live
			res.NginxRunning = nginxRunning(n)
			return nil // what is live is exactly this: nothing to do
		}

		dir := filepath.Join(gens, name)
		if err := writeTree(dir, out.Tree); err != nil {
			os.RemoveAll(dir)
			return err
		}
		if blocked := unreachable(dir, out.Tree); blocked != "" {
			res.Warnings = append(res.Warnings, fmt.Sprintf("the nginx workers (%s) cannot get through %s: "+
				"every host behind basic auth will answer 500 until they can", n.User, blocked))
		}
		testOut, testErr := e.test(ctx, n, filepath.Join(dir, "nginx.conf"))
		if testErr != nil {
			blamed := blame(testOut, dir, out.Tree, e.CertsDir)
			os.RemoveAll(dir)
			if len(blamed) == 0 {
				return fmt.Errorf("nginx -t refused the configuration, in a part no single document owns:\n%s", strings.TrimSpace(testOut))
			}
			for ref, reason := range blamed {
				in.Exclude[ref] = "nginx -t: " + reason
			}
			continue
		}

		if dryRun {
			os.RemoveAll(dir)
			res.Generation = name
			res.Changed = true
			return nil
		}

		prev, err := install(n, name)
		if err != nil {
			return err
		}
		res.Generation, res.Changed = name, true

		res.NginxRunning = nginxRunning(n)
		if !res.NginxRunning {
			// Nothing to reload; nginx reads this tree when it starts.
			e.prune(n, name, prev)
			return nil
		}
		emerg, err := e.reload(ctx, n)
		if err == nil {
			res.Reloaded = true
			e.prune(n, name, prev)
			return nil
		}

		// The reload failed: nginx keeps running the previous
		// configuration, and so must the files on disk.
		res.RolledBack++
		if rerr := restore(n, prev); rerr != nil {
			return fmt.Errorf("reload failed (%v) and the previous configuration could not be put back: %w", err, rerr)
		}
		os.RemoveAll(dir)
		blamed := blameBind(emerg, in.Streams)
		if len(blamed) == 0 {
			return fmt.Errorf("nginx refused to reload, the previous configuration is back in place: %v", err)
		}
		for ref, reason := range blamed {
			in.Exclude[ref] = "reload: " + reason
		}
		live = prev
	}
	return fmt.Errorf("gave up after %d rounds of excluding documents", maxRounds)
}

// ---------------------------------------------------------------------
// Testing and blaming
// ---------------------------------------------------------------------

func (e *Engine) test(ctx context.Context, n config.Nginx, confPath string) (string, error) {
	argv := []string{n.Bin, "-t", "-q", "-c", "{config}"}
	if len(n.TestCommand) > 0 {
		argv = append([]string(nil), n.TestCommand...)
		if !containsPlaceholder(argv) {
			argv = append(argv, "-c", "{config}")
		}
	}
	for i := range argv {
		argv[i] = strings.ReplaceAll(argv[i], "{config}", confPath)
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
	return string(out), err
}

func containsPlaceholder(argv []string) bool {
	for _, a := range argv {
		if strings.Contains(a, "{config}") {
			return true
		}
	}
	return false
}

var (
	// The optional "1234#1234: " is nginx's pid and thread id: noise
	// in a reason shown to a person.
	emergRe  = regexp.MustCompile(`\[(?:emerg|crit|alert)\] (?:\d+#\d+: )?(.*)`)
	fileRe   = regexp.MustCompile(` in (\S+):\d+$`)
	quotedRe = regexp.MustCompile(`"([^"]+)"`)
)

// blame finds the documents an nginx error belongs to: by the file and
// line nginx names, or — for the errors reported without one, like a
// certificate that does not load — by a quoted value of the message
// that only some documents' files contain.
func blame(output, genDir string, tree Tree, certsDir string) map[Ref]string {
	blamed := map[Ref]string{}
	for line := range strings.SplitSeq(output, "\n") {
		m := emergRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		msg := m[1]

		if fm := fileRe.FindStringSubmatch(msg); fm != nil {
			rel := relativeToGen(fm[1], genDir)
			if ref, ok := tree.Owners[rel]; ok {
				blamed[ref] = strings.TrimSuffix(msg, fm[0])
				continue
			}
		}

		for _, q := range quotedRe.FindAllStringSubmatch(msg, -1) {
			for _, p := range tree.Paths() {
				ref, owned := tree.Owners[p]
				if owned && inDirectives(tree.Files[p].Data, q[1]) {
					blamed[ref] = msg
				}
			}
		}
	}
	return blamed
}

// inDirectives reports whether a value appears in the directives of a
// file, comments aside: a comment is not what nginx complained about,
// and "stream" in "# limen stream pg" must not take the stream down
// for an error in nginx.conf.
func inDirectives(data []byte, value string) bool {
	for line := range strings.SplitSeq(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.Contains(line, value) {
			return true
		}
	}
	return false
}

// relativeToGen turns the path nginx reports into a tree path. nginx
// does not resolve the "limen -> ." link, so the same file may show up
// as <gen>/hosts/a.conf or <gen>/limen/hosts/a.conf.
func relativeToGen(p, genDir string) string {
	p = filepath.ToSlash(p)
	g := strings.TrimSuffix(filepath.ToSlash(genDir), "/") + "/"
	if !strings.HasPrefix(p, g) {
		return ""
	}
	rel := strings.TrimPrefix(p, g)
	for strings.HasPrefix(rel, linkName+"/") {
		rel = strings.TrimPrefix(rel, linkName+"/")
	}
	return rel
}

var bindRe = regexp.MustCompile(`bind\(\) to \S*:(\d+) failed`)

// blameBind handles the one error `nginx -t` cannot see, because it
// binds nothing: a port already taken by another program. When the
// port is a stream's, the stream is the one to leave out; 80 and 443
// belong to everyone and cannot be pinned on anybody.
func blameBind(emerg string, streams []*model.Stream) map[Ref]string {
	blamed := map[Ref]string{}
	for _, m := range bindRe.FindAllStringSubmatch(emerg, -1) {
		port, _ := strconv.Atoi(m[1])
		for _, s := range streams {
			if s.Enabled && s.Listen == port {
				blamed[Ref{model.KindStream, s.Name}] = fmt.Sprintf("port %d is already in use by another program", port)
			}
		}
	}
	return blamed
}

// ---------------------------------------------------------------------
// Installing, reloading, restoring
// ---------------------------------------------------------------------

func liveGeneration(confDir string) string {
	target, err := os.Readlink(filepath.Join(confDir, linkName))
	if err != nil {
		return ""
	}
	name := filepath.Base(target)
	if !genNameRe.MatchString(name) {
		return ""
	}
	return name
}

// install makes a generation live and returns the one it replaced ("" on
// the first install). The link and the main file are each replaced by
// a rename, so a reader sees either the old tree or the new one; nginx
// reads them only when told to reload, which happens after both.
func install(n config.Nginx, name string) (string, error) {
	link := filepath.Join(n.ConfDir, linkName)
	if info, err := os.Lstat(link); err == nil && info.Mode()&os.ModeSymlink == 0 {
		return "", fmt.Errorf("%s exists and is not limen's link: move it away first", link)
	}
	prev := liveGeneration(n.ConfDir)

	// First install: keep the distribution's nginx.conf next to ours.
	if prev == "" {
		before := filepath.Join(n.ConfDir, beforeFile)
		if _, err := os.Stat(before); os.IsNotExist(err) {
			if b, err := os.ReadFile(n.ConfFile); err == nil {
				if err := os.WriteFile(before, b, 0o644); err != nil {
					return "", err
				}
			}
		}
	}

	if err := swapLink(link, filepath.Join(gensDir, name)); err != nil {
		return "", err
	}
	main, err := os.ReadFile(filepath.Join(n.ConfDir, gensDir, name, "nginx.conf"))
	if err == nil {
		err = writeFileAtomic(n.ConfFile, main, 0o644)
	}
	if err != nil {
		if prev != "" {
			swapLink(link, filepath.Join(gensDir, prev))
		}
		return "", err
	}
	return prev, nil
}

// restore puts a previous generation back, or the distribution's file
// when there was none.
func restore(n config.Nginx, prev string) error {
	link := filepath.Join(n.ConfDir, linkName)
	if prev == "" {
		b, err := os.ReadFile(filepath.Join(n.ConfDir, beforeFile))
		if err != nil {
			return err
		}
		if err := writeFileAtomic(n.ConfFile, b, 0o644); err != nil {
			return err
		}
		return os.Remove(link)
	}
	if err := swapLink(link, filepath.Join(gensDir, prev)); err != nil {
		return err
	}
	main, err := os.ReadFile(filepath.Join(n.ConfDir, gensDir, prev, "nginx.conf"))
	if err != nil {
		return err
	}
	return writeFileAtomic(n.ConfFile, main, 0o644)
}

func swapLink(link, target string) error {
	tmp := link + ".new"
	os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, link); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func nginxRunning(n config.Nginx) bool {
	pid, err := proc.ReadPidfile(n.PIDFile)
	return err == nil && proc.Alive(pid)
}

// reload asks nginx to load the installed tree and watches its error
// log: a reload that fails (a port taken by another program is the one
// thing `nginx -t` cannot catch) leaves nginx on the old configuration,
// and the only trace is an [emerg] line there.
func (e *Engine) reload(ctx context.Context, n config.Nginx) (string, error) {
	var offset int64
	if info, err := os.Stat(n.ErrorLog); err == nil {
		offset = info.Size()
	}

	if len(n.ReloadCommand) > 0 {
		out, err := exec.CommandContext(ctx, n.ReloadCommand[0], n.ReloadCommand[1:]...).CombinedOutput()
		if err != nil {
			return string(out), fmt.Errorf("%s: %v: %s", strings.Join(n.ReloadCommand, " "), err, strings.TrimSpace(string(out)))
		}
	} else if err := proc.Reload(n.PIDFile); err != nil {
		return "", fmt.Errorf("signal nginx: %w", err)
	}

	wait := e.ReloadWait
	if wait <= 0 {
		wait = 1500 * time.Millisecond
	}
	deadline := time.Now().Add(wait)
	for {
		if emerg := emergSince(n.ErrorLog, offset); emerg != "" {
			// nginx is still writing the story of the failed reload
			// (five bind attempts, then "still could not bind()"). Wait
			// for it to finish: a tail that lands after the next
			// attempt has taken its offset would make that attempt
			// look failed too.
			settle(n.ErrorLog)
			emerg = emergSince(n.ErrorLog, offset)
			return emerg, errors.New(firstLine(emerg))
		}
		if !nginxRunning(n) {
			return "", errors.New("nginx is no longer running after the reload")
		}
		if time.Now().After(deadline) {
			return "", nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// settle waits until the log has been quiet for a second, or six
// seconds at most. A second, because nginx retries a failed bind five
// times with half a second of sleep in between — and without updating
// its clock, so the lines all carry the same timestamp while actually
// arriving over two seconds. A shorter quiet period ends in one of the
// pauses and misses the rest.
func settle(path string) {
	size := int64(-1)
	for deadline := time.Now().Add(6 * time.Second); time.Now().Before(deadline); {
		info, err := os.Stat(path)
		if err != nil {
			return
		}
		if info.Size() == size {
			return
		}
		size = info.Size()
		time.Sleep(time.Second)
	}
}

func firstLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[0]
}

// emergSince returns the [emerg] lines written to the log after offset.
func emergSince(path string, offset int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	if info, err := f.Stat(); err == nil && info.Size() < offset {
		offset = 0 // rotated in the meantime
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(f, 1<<20))
	var lines []string
	for l := range strings.SplitSeq(string(b), "\n") {
		if strings.Contains(l, "[emerg]") {
			lines = append(lines, strings.TrimSpace(l))
		}
	}
	return strings.Join(lines, "\n")
}

// prune keeps the newest generations, and always the live one and the
// one it replaced.
func (e *Engine) prune(n config.Nginx, live, prev string) {
	gens := filepath.Join(n.ConfDir, gensDir)
	entries, err := os.ReadDir(gens)
	if err != nil {
		return
	}
	var names []string
	for _, en := range entries {
		if en.IsDir() && genNameRe.MatchString(en.Name()) {
			names = append(names, en.Name())
		}
	}
	sort.Strings(names)
	keep := n.KeepGenerations
	for i, name := range names {
		if i >= len(names)-keep || name == live || name == prev {
			continue
		}
		os.RemoveAll(filepath.Join(gens, name))
	}
}

// ---------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------

// treeHash identifies a rendering by its content alone.
func treeHash(t Tree) string {
	h := sha256.New()
	for _, p := range t.Paths() {
		f := t.Files[p]
		fmt.Fprintf(h, "%s\x00%o\x00%s\x00%d\x00", p, f.Mode, f.Group, len(f.Data))
		h.Write(f.Data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writeTree(dir string, t Tree) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, p := range t.Paths() {
		f := t.Files[p]
		path := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, f.Data, f.Mode); err != nil {
			return err
		}
		if err := os.Chmod(path, f.Mode); err != nil {
			return err
		}
		if f.Group != "" {
			if err := chownGroup(path, f.Group); err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
		}
	}
	// "limen/..." must resolve inside the generation too, where it is
	// tested before it is installed.
	return os.Symlink(".", filepath.Join(dir, linkName))
}

// unreachable returns the first directory on the way to the tree that
// others cannot traverse, when the tree holds files the workers read
// at request time (the htpasswd files). nginx -t passes regardless —
// only the master reads the configuration — and the failure shows up
// later as a 500 on every guarded host.
func unreachable(dir string, t Tree) string {
	needed := false
	for _, f := range t.Files {
		if f.Group != "" {
			needed = true
		}
	}
	if !needed || runtime.GOOS == "windows" {
		return ""
	}
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		if info, err := os.Stat(d); err == nil && info.Mode().Perm()&0o001 == 0 {
			return fmt.Sprintf("%s (mode %04o)", d, info.Mode().Perm())
		}
		if parent := filepath.Dir(d); parent == d {
			return ""
		}
	}
}

// chownGroup gives a file to the primary group of the worker user, so
// that workers can read it and nobody else can.
func chownGroup(path, userName string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	u, err := user.Lookup(userName)
	if err != nil {
		return fmt.Errorf("worker user %q: %w", userName, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}
	return os.Chown(path, 0, gid)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	tmp.Close()
	if err := os.Chmod(name, mode); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

func skipInfo(skips []Skip) []SkipInfo {
	out := make([]SkipInfo, 0, len(skips))
	for _, s := range skips {
		out = append(out, SkipInfo{Kind: string(s.Ref.Kind), Name: s.Ref.Name, Reason: s.Reason})
	}
	return out
}

func (e *Engine) logResult(r Result) {
	if e.Log == nil {
		return
	}
	attrs := []any{
		"generation", r.Generation, "changed", r.Changed, "reloaded", r.Reloaded,
		"nginx_running", r.NginxRunning, "dry_run", r.DryRun, "revision", r.Revision,
		"duration_ms", r.Duration.Milliseconds(), "skipped", len(r.Skipped),
	}
	if r.Error != "" {
		e.Log.Error("apply failed", append(attrs, "error", r.Error)...)
	} else {
		e.Log.Info("apply", attrs...)
	}
	for _, s := range r.Skipped {
		e.Log.Warn("document left out", "kind", s.Kind, "name", s.Name, "reason", s.Reason)
	}
	for _, w := range r.Warnings {
		e.Log.Warn("apply warning", "detail", w)
	}
}
