package bootstrap

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ostap-mykhaylyak/limen/internal/config"
	"github.com/ostap-mykhaylyak/limen/internal/paths"
)

func TestEnsureCreatesTheLayoutAndTheDefaultConfig(t *testing.T) {
	root := t.TempDir()
	l := DefaultLayout().Under(root)

	created, err := l.Ensure()
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Error("Ensure reported nothing created on an empty root")
	}

	for _, dir := range append([]string{
		l.ConfigDir, l.HistoryDir, l.DataDir, l.CertsDir,
		l.AcmeDir, l.BackupDir, l.RenderedDir, l.LogDir,
	}, l.ModelDirs...) {
		info, err := os.Stat(dir)
		if err != nil {
			t.Errorf("missing directory %s", dir)
			continue
		}
		if !info.IsDir() {
			t.Errorf("%s is not a directory", dir)
		}
	}

	if _, err := os.Stat(l.ConfigFile); err != nil {
		t.Fatalf("default config was not written: %v", err)
	}
}

// The shipped skeleton must be a configuration the daemon accepts;
// otherwise a fresh install refuses to start.
func TestShippedConfigIsValid(t *testing.T) {
	root := t.TempDir()
	l := DefaultLayout().Under(root)
	if _, err := l.Ensure(); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(l.ConfigFile)
	if err != nil {
		t.Fatalf("the shipped config.yaml does not validate: %v", err)
	}
	if cfg.Panel.Listen == "" {
		t.Error("the shipped config has no panel.listen")
	}
}

func TestEnsureIsIdempotentAndKeepsAnEditedConfig(t *testing.T) {
	root := t.TempDir()
	l := DefaultLayout().Under(root)
	if _, err := l.Ensure(); err != nil {
		t.Fatal(err)
	}

	edited := "log:\n  level: \"debug\"\n"
	if err := os.WriteFile(l.ConfigFile, []byte(edited), 0o640); err != nil {
		t.Fatal(err)
	}

	created, err := l.Ensure()
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Error("a second Ensure reported changes on a complete layout")
	}
	b, err := os.ReadFile(l.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != edited {
		t.Error("Ensure overwrote the operator's configuration")
	}
}

// Private keys must not be readable by the group that reaches the
// panel socket.
func TestKeyDirectoriesAreNotGroupReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions are not enforced on Windows")
	}
	root := t.TempDir()
	l := DefaultLayout().Under(root)
	if _, err := l.Ensure(); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{l.CertsDir, l.AcmeDir} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o700 {
			t.Errorf("%s has mode %04o, want 0700", dir, perm)
		}
	}
}

func TestPurgeTargetsCoverEverythingTheLayoutCreates(t *testing.T) {
	l := DefaultLayout()
	targets := l.PurgeTargets()

	// Every directory the layout creates must fall under a target,
	// otherwise a purge would leave state behind.
	all := append([]string{
		l.ConfigDir, l.ConfigFile, l.HistoryDir, l.DataDir, l.CertsDir,
		l.AcmeDir, l.BackupDir, l.RenderedDir, l.LogDir, l.RunDir,
	}, l.ModelDirs...)

	for _, path := range all {
		covered := false
		for _, target := range targets {
			if path == target || strings.HasPrefix(path, target+"/") {
				covered = true
				break
			}
		}
		if !covered {
			t.Errorf("%s survives a purge: no target covers it", path)
		}
	}
}

func TestGuardRefusesPathsOutsideTheLayout(t *testing.T) {
	for _, path := range []string{"/", "", "/etc", "/var", "/etc/nginx", "/home/ostap", "/etc/limenx"} {
		if err := guard(path); err == nil {
			t.Errorf("guard accepted %q", path)
		}
	}
	for _, path := range []string{paths.ConfigDir, paths.DataDir, paths.LogDir, paths.RunDir, paths.CertsDir} {
		if err := guard(path); err != nil {
			t.Errorf("guard refused %q, which limen owns: %v", path, err)
		}
	}
}

// Taking the nginx tree over is irreversible for whatever was there;
// the backup is the only way back, so it has to copy the whole tree.
func TestBackupNginxCopiesTheWholeTree(t *testing.T) {
	src := filepath.Join(t.TempDir(), "nginx")
	if err := os.MkdirAll(filepath.Join(src, "sites-available"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "nginx.conf"), []byte("worker_processes 1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "sites-available", "site"), []byte("server {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	backupDir := t.TempDir()
	dst, err := BackupNginx(src, backupDir)
	if err != nil {
		t.Fatal(err)
	}
	if dst == "" {
		t.Fatal("no backup was made of an existing tree")
	}
	for _, rel := range []string{"nginx.conf", filepath.Join("sites-available", "site")} {
		if _, err := os.Stat(filepath.Join(dst, rel)); err != nil {
			t.Errorf("%s is missing from the backup", rel)
		}
	}
}

func TestBackupNginxToleratesAnAbsentTree(t *testing.T) {
	dst, err := BackupNginx(filepath.Join(t.TempDir(), "absent"), t.TempDir())
	if err != nil {
		t.Fatalf("an absent nginx tree must not be an error: %v", err)
	}
	if dst != "" {
		t.Errorf("backup path = %q, want empty", dst)
	}
}

// The sandbox of the unit was proven under real systemd; each line of
// it is a promise SECURITY.md makes. Loosening one must be a decision,
// not an accident of an edit.
func TestTheUnitKeepsItsSandbox(t *testing.T) {
	unit := string(unitFile)
	for _, want := range []string{
		"ProtectSystem=strict",
		"ReadWritePaths=/etc/limen /var/lib/limen /var/log/limen /etc/nginx",
		"CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE\n",
		"NoNewPrivileges=true",
		"PrivateDevices=true",
		"PrivateTmp=true",
		"ProtectHome=true",
		"ProtectProc=invisible",
		"SystemCallFilter=@system-service",
		"SystemCallArchitectures=native",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n",
		"RestrictNamespaces=true",
		"MemoryDenyWriteExecute=true",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("the unit lost %q", strings.TrimSpace(want))
		}
	}
	if strings.Contains(unit, "\nUMask=") {
		t.Error("a UMask: the workers read htpasswd files through the rendered tree, a tighter mask shuts them out")
	}
}
