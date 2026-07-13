package scope

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/philband/dotenvsec/internal/config"
)

func TestResolveNearestIndependentScope(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init")
	writeScope(t, root, "")
	write(t, filepath.Join(root, ".env.sops.yaml"))
	nested := filepath.Join(root, "services", "api")
	if err := os.MkdirAll(nested, 0755); err != nil {
		t.Fatal(err)
	}
	writeScope(t, filepath.Join(root, "services"), "")
	id, err := Resolve(nested)
	if err != nil {
		t.Fatal(err)
	}
	if id.RelativePath != "services" {
		t.Fatalf("selected %q", id.RelativePath)
	}
	source, err := ResolveSource(id, "../.env.sops.yaml")
	if err == nil || source != "" {
		t.Fatal("scope escape should fail")
	}
}

func TestNestedRepositoryBoundary(t *testing.T) {
	outer := t.TempDir()
	runGit(t, outer, "init")
	writeScope(t, outer, "")
	inner := filepath.Join(outer, "nested")
	if err := os.MkdirAll(inner, 0755); err != nil {
		t.Fatal(err)
	}
	runGit(t, inner, "init")
	if _, err := Resolve(inner); !os.IsNotExist(err) {
		t.Fatalf("nested repository inherited outer scope: %v", err)
	}
}

func TestResolveSourceRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.yaml")
	write(t, target)
	link := filepath.Join(root, ".env.sops.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	id := Identity{Mode: config.ScopeModeLocal, WorktreeRoot: root, StorageRoot: root, Directory: root}
	if _, err := ResolveSource(id, ".env.sops.yaml"); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink source error = %v", err)
	}
}

func TestResolveLocalOutsideGit(t *testing.T) {
	root := t.TempDir()
	writeScope(t, root, config.ScopeModeLocal)
	nested := filepath.Join(root, "one", "two")
	if err := os.MkdirAll(nested, 0755); err != nil {
		t.Fatal(err)
	}
	id, err := Resolve(nested)
	if err != nil {
		t.Fatal(err)
	}
	if id.Mode != config.ScopeModeLocal || id.Directory != canonical(t, root) || id.ReadOnly || id.CommonGitDir != "" {
		t.Fatalf("unexpected local identity: %#v", id)
	}
}

func TestResolveGitLocalFromLinkedWorktree(t *testing.T) {
	main := t.TempDir()
	runGit(t, main, "init")
	runGit(t, main, "config", "user.name", "dotenvsec test")
	runGit(t, main, "config", "user.email", "dotenvsec@example.invalid")
	runGit(t, main, "config", "commit.gpgsign", "false")
	write(t, filepath.Join(main, "README.md"))
	runGit(t, main, "add", "README.md")
	runGit(t, main, "commit", "-m", "initial")
	writeScope(t, main, config.ScopeModeGitLocal)
	if err := RegisterGitLocal(main); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(t.TempDir(), "feature")
	runGit(t, main, "worktree", "add", "-b", "feature", linked)
	id, err := Resolve(linked)
	if err != nil {
		t.Fatal(err)
	}
	if id.Mode != config.ScopeModeGitLocal || !id.ReadOnly || id.Directory != canonical(t, main) || id.WorktreeRoot != canonical(t, linked) || id.StorageRoot != canonical(t, main) {
		t.Fatalf("unexpected inherited identity: %#v", id)
	}
	if id.RepositoryID == "" || !strings.Contains(id.ConfigPath, main) {
		t.Fatalf("inherited identity is incomplete: %#v", id)
	}
}

func TestLinkedWorktreeLocalOverrideWins(t *testing.T) {
	main := t.TempDir()
	runGit(t, main, "init")
	runGit(t, main, "config", "user.name", "dotenvsec test")
	runGit(t, main, "config", "user.email", "dotenvsec@example.invalid")
	runGit(t, main, "config", "commit.gpgsign", "false")
	write(t, filepath.Join(main, "README.md"))
	runGit(t, main, "add", "README.md")
	runGit(t, main, "commit", "-m", "initial")
	writeScope(t, main, config.ScopeModeGitLocal)
	if err := RegisterGitLocal(main); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(t.TempDir(), "feature")
	runGit(t, main, "worktree", "add", "-b", "feature-override", linked)
	writeScope(t, linked, config.ScopeModeLocal)
	id, err := Resolve(linked)
	if err != nil {
		t.Fatal(err)
	}
	if id.Mode != config.ScopeModeLocal || id.ReadOnly || id.Directory != canonical(t, linked) {
		t.Fatalf("unexpected override identity: %#v", id)
	}
}

func TestRepairGitLocalOwner(t *testing.T) {
	main := t.TempDir()
	runGit(t, main, "init")
	writeScope(t, main, config.ScopeModeGitLocal)
	if err := RegisterGitLocal(main); err != nil {
		t.Fatal(err)
	}
	context, err := InspectGit(main)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := loadGitLocalRegistry(context.CommonGitDir)
	if err != nil {
		t.Fatal(err)
	}
	registry.OwnerWorktree = filepath.Join(filepath.Dir(canonical(t, main)), "old-main")
	if err := saveGitLocalRegistry(context.CommonGitDir, registry); err != nil {
		t.Fatal(err)
	}
	if err := RepairGitLocalOwner(main); err != nil {
		t.Fatal(err)
	}
	repaired, err := loadGitLocalRegistry(context.CommonGitDir)
	if err != nil {
		t.Fatal(err)
	}
	if repaired.OwnerWorktree != canonical(t, main) {
		t.Fatalf("owner = %q", repaired.OwnerWorktree)
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git: %v: %s", err, out)
	}
}
func write(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
}

func writeScope(t *testing.T, directory, mode string) {
	t.Helper()
	if err := os.MkdirAll(directory, 0755); err != nil {
		t.Fatal(err)
	}
	scope := config.Scope{Schema: 1, Mode: mode, Provider: "sops", Source: ".env.sops.yaml", Environment: []string{"TOKEN"}}
	data, err := config.Marshal(scope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, ConfigName), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func canonical(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}
