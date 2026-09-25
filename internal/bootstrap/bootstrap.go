// Package bootstrap owns the filesystem side of limen: creating the
// layout, installing the service, and removing everything again.
//
// These are the only operations that make sense on a bare binary, run
// by hand as root. Everything else (status, reload) talks to a daemon
// that is already running.
package bootstrap

import (
	"bufio"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/paths"
	"github.com/ostap-mykhaylyak/limen/internal/proc"
)

//go:embed skel
var skelFS embed.FS

//go:embed limen.service
var unitFile []byte

// Layout is the set of directories and files limen owns. Production
// always uses DefaultLayout; tests build one under a temporary root.
type Layout struct {
	ConfigDir   string
	ConfigFile  string
	ModelDirs   []string
	HistoryDir  string
	DataDir     string
	CertsDir    string
	AcmeDir     string
	BackupDir   string
	RenderedDir string
	LogDir      string
	RunDir      string
}

// DefaultLayout is the FHS layout from the paths package.
func DefaultLayout() Layout {
	return Layout{
		ConfigDir:  paths.ConfigDir,
		ConfigFile: paths.ConfigFile,
		ModelDirs: []string{
			paths.HostsDir,
			paths.RedirectsDir,
			paths.StreamsDir,
			paths.AccessDir,
			paths.UsersDir,
			paths.CertDocsDir,
		},
		HistoryDir:  paths.HistoryDir,
		DataDir:     paths.DataDir,
		CertsDir:    paths.CertsDir,
		AcmeDir:     paths.AcmeDir,
		BackupDir:   paths.BackupDir,
		RenderedDir: paths.RenderedDir,
		LogDir:      paths.LogDir,
		RunDir:      paths.RunDir,
	}
}

// Under returns the same layout rebased under root, for tests.
func (l Layout) Under(root string) Layout {
	join := func(p string) string { return filepath.Join(root, filepath.FromSlash(p)) }
	out := Layout{
		ConfigDir:   join(l.ConfigDir),
		ConfigFile:  join(l.ConfigFile),
		HistoryDir:  join(l.HistoryDir),
		DataDir:     join(l.DataDir),
		CertsDir:    join(l.CertsDir),
		AcmeDir:     join(l.AcmeDir),
		BackupDir:   join(l.BackupDir),
		RenderedDir: join(l.RenderedDir),
		LogDir:      join(l.LogDir),
		RunDir:      join(l.RunDir),
	}
	for _, d := range l.ModelDirs {
		out.ModelDirs = append(out.ModelDirs, join(d))
	}
	return out
}

// dirSpec is a directory and the mode it must be created with.
type dirSpec struct {
	path string
	mode fs.FileMode
}

func (l Layout) dirs() []dirSpec {
	specs := []dirSpec{
		{l.ConfigDir, 0o750},
		{l.HistoryDir, 0o750},
		{l.DataDir, 0o750},
		// Private keys live here: not even the group reads them.
		{l.CertsDir, 0o700},
		{l.AcmeDir, 0o700},
		{l.BackupDir, 0o700},
		{l.RenderedDir, 0o750},
		{l.LogDir, 0o750},
	}
	for _, d := range l.ModelDirs {
		specs = append(specs, dirSpec{d, 0o750})
	}
	return specs
}

// Ensure creates every directory and drops the default config.yaml
// when it is missing. An existing config is never overwritten. It
// reports whether anything had to be created, so that the daemon can
// tell the operator it provisioned itself on first run.
func (l Layout) Ensure() (bool, error) {
	changed := false
	for _, d := range l.dirs() {
		if _, err := os.Stat(d.path); err == nil {
			continue
		}
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			return changed, fmt.Errorf("create %s: %w", d.path, err)
		}
		// MkdirAll applies the umask; set the mode we mean.
		if err := os.Chmod(d.path, d.mode); err != nil {
			return changed, fmt.Errorf("chmod %s: %w", d.path, err)
		}
		changed = true
	}

	if _, err := os.Stat(l.ConfigFile); err != nil {
		if !os.IsNotExist(err) {
			return changed, err
		}
		b, err := skelFS.ReadFile("skel/etc/limen/config.yaml")
		if err != nil {
			return changed, err
		}
		if err := os.WriteFile(l.ConfigFile, b, 0o640); err != nil {
			return changed, fmt.Errorf("write %s: %w", l.ConfigFile, err)
		}
		changed = true
	}
	return changed, nil
}

// PurgeTargets lists everything limen creates at runtime. Deriving the
// list here, from the layout, is what keeps `limen purge` aligned with
// the layout as it grows.
func (l Layout) PurgeTargets() []string {
	return []string{l.ConfigDir, l.DataDir, l.LogDir, l.RunDir}
}

// Init installs limen on this machine: layout, configuration, binary,
// systemd unit and logrotate policy. It is idempotent.
//
// Packaged is for the Debian package, which owns the binary, the unit
// (under /usr/lib/systemd/system) and the logrotate policy: Init then
// prepares the layout and saves the nginx tree only. A unit written to
// /etc/systemd/system would shadow the package's, and every upgrade of
// the package would leave the old one in charge. Init notices the
// package by itself, so that an operator who runs --init by habit does
// not do that damage.
func Init(version string, out io.Writer, packaged bool) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("limen installs on Linux only (this is %s)", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		return errors.New("init must run as root")
	}

	l := DefaultLayout()
	if _, err := l.Ensure(); err != nil {
		return err
	}
	fmt.Fprintf(out, "layout ready under %s, %s and %s\n", l.ConfigDir, l.DataDir, l.LogDir)

	// Before limen takes the nginx tree over, keep a copy of whatever
	// the operator had there. The generated configuration replaces it
	// wholesale, and this backup is the only way back.
	if backup, err := BackupNginx(paths.NginxConfDir, l.BackupDir); err != nil {
		fmt.Fprintf(out, "warning: could not back up %s: %v\n", paths.NginxConfDir, err)
	} else if backup != "" {
		fmt.Fprintf(out, "existing nginx configuration backed up to %s\n", backup)
	}

	if !packaged {
		if _, err := os.Stat(paths.PackagedUnitFile); err == nil {
			packaged = true
			fmt.Fprintf(out, "%s belongs to the limen package: binary, unit and logrotate policy are left to it\n", paths.PackagedUnitFile)
		}
	}
	if packaged {
		fmt.Fprintf(out, "\nlimen %s is ready, not started: starting it takes nginx over. Next steps:\n", version)
		fmt.Fprintf(out, "  1. review %s (the panel stays on loopback: nginx publishes it)\n", l.ConfigFile)
		fmt.Fprintln(out, "  2. optionally, limen --import to bring the current nginx sites into the model")
		fmt.Fprintln(out, "  3. limen user add NAME --role admin --password-stdin")
		fmt.Fprintln(out, "  4. systemctl enable --now limen")
		return nil
	}

	if err := installSelf(paths.Binary); err != nil {
		return err
	}
	fmt.Fprintf(out, "binary installed at %s\n", paths.Binary)

	for _, dir := range []string{filepath.Dir(paths.UnitFile), filepath.Dir(paths.LogrotateFile)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(paths.UnitFile, unitFile, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", paths.UnitFile, err)
	}
	logrotate, err := skelFS.ReadFile("skel/etc/logrotate.d/limen")
	if err != nil {
		return err
	}
	if err := os.WriteFile(paths.LogrotateFile, logrotate, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", paths.LogrotateFile, err)
	}

	fmt.Fprintf(out, "\nlimen %s installed. Next steps:\n", version)
	fmt.Fprintf(out, "  1. review %s (the panel stays on loopback: nginx publishes it)\n", l.ConfigFile)
	fmt.Fprintln(out, "  2. systemctl daemon-reload")
	fmt.Fprintln(out, "  3. systemctl enable --now limen")
	fmt.Fprintln(out, "  4. limen status")
	return nil
}

// installSelf copies the running executable to dst.
func installSelf(dst string) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate own binary: %w", err)
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		return err
	}
	if same, _ := sameFile(self, dst); same {
		return nil
	}
	src, err := os.Open(self)
	if err != nil {
		return err
	}
	defer src.Close()

	// Write next to the target and rename: replacing a running binary
	// in place fails with ETXTBSY.
	tmp := dst + ".new"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, src); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("install %s: %w", dst, err)
	}
	return nil
}

func sameFile(a, b string) (bool, error) {
	fa, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	fb, err := os.Stat(b)
	if err != nil {
		return false, err
	}
	return os.SameFile(fa, fb), nil
}

// BackupNginx copies the whole nginx configuration tree into a
// timestamped directory under backupDir and returns its path. An
// absent tree is not an error: there is simply nothing to save.
func BackupNginx(confDir, backupDir string) (string, error) {
	info, err := os.Stat(confDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", confDir)
	}
	dst := filepath.Join(backupDir, "nginx-"+time.Now().UTC().Format("20060102T150405Z"))
	if err := copyTree(confDir, dst); err != nil {
		return "", err
	}
	return dst, nil
}

// copyTree copies a directory recursively, preserving file modes.
// Symlinks are recreated as symlinks: an nginx tree is full of them
// (sites-enabled), and following them would duplicate the targets.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)

		switch {
		case d.IsDir():
			info, err := d.Info()
			if err != nil {
				return err
			}
			return os.MkdirAll(target, info.Mode().Perm())
		case d.Type()&fs.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			os.Remove(target)
			return os.Symlink(link, target)
		case !d.Type().IsRegular():
			// Sockets and devices have no business in a config tree.
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	})
}

// Purge removes configuration, data and logs, taking the machine back
// to "limen was never installed". It does not touch the binary or the
// systemd unit: that is what `make uninstall` is for.
func Purge(assumeYes bool, in io.Reader, out io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("purge must run as root")
	}
	if running() {
		return errors.New("the service is active: stop it first (systemctl stop limen)")
	}

	l := DefaultLayout()
	targets := l.PurgeTargets()
	for _, t := range targets {
		if err := guard(t); err != nil {
			return err
		}
	}

	fmt.Fprintln(out, "This removes, permanently:")
	for _, t := range targets {
		fmt.Fprintf(out, "  %s\n", t)
	}
	fmt.Fprintln(out, "The nginx configuration limen generated is left in place.")

	if !assumeYes {
		f, isFile := in.(*os.File)
		if !isFile {
			return errors.New("refusing to purge without a terminal: pass --yes")
		}
		if info, err := f.Stat(); err != nil || info.Mode()&os.ModeCharDevice == 0 {
			return errors.New("refusing to purge without a terminal: pass --yes")
		}
		fmt.Fprint(out, "\nType 'yes' to confirm: ")
		answer, _ := bufio.NewReader(in).ReadString('\n')
		if strings.TrimSpace(answer) != "yes" {
			return errors.New("aborted")
		}
	}

	var errs []error
	removed := 0
	for _, t := range targets {
		if _, err := os.Stat(t); os.IsNotExist(err) {
			continue
		}
		if err := os.RemoveAll(t); err != nil {
			errs = append(errs, fmt.Errorf("remove %s: %w", t, err))
			continue
		}
		fmt.Fprintf(out, "removed %s\n", t)
		removed++
	}
	fmt.Fprintf(out, "removed %d path(s); run `limen init` to provision again\n", removed)
	return errors.Join(errs...)
}

// guard refuses to remove anything outside the paths limen owns, so
// that a mistyped constant in a custom build cannot wipe a system
// directory.
func guard(path string) error {
	clean := filepath.ToSlash(filepath.Clean(path))
	if clean == "" || clean == "/" || clean == "." {
		return fmt.Errorf("refusing to remove %q", path)
	}
	allowed := []string{paths.ConfigDir, paths.DataDir, paths.LogDir, paths.RunDir}
	for _, prefix := range allowed {
		if clean == prefix || strings.HasPrefix(clean, prefix+"/") {
			return nil
		}
	}
	return fmt.Errorf("refusing to remove %q: outside the limen layout", path)
}

// running reports whether a limen daemon is active, asking systemd
// first and falling back to the pidfile when systemd is not the one
// running the service.
func running() bool {
	if _, err := proc.Running(paths.Pidfile); err == nil {
		return true
	}
	if path, err := exec.LookPath("systemctl"); err == nil {
		if err := exec.Command(path, "is-active", "--quiet", "limen.service").Run(); err == nil {
			return true
		}
	}
	return false
}
