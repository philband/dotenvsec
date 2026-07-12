package scope

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestResolveNearestIndependentScope(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init")
	write(t, filepath.Join(root, ConfigName))
	write(t, filepath.Join(root, ".env.sops.yaml"))
	nested := filepath.Join(root, "services", "api")
	if err := os.MkdirAll(nested, 0755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "services", ConfigName))
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
	write(t, filepath.Join(outer, ConfigName))
	inner := filepath.Join(outer, "nested")
	if err := os.MkdirAll(inner, 0755); err != nil {
		t.Fatal(err)
	}
	runGit(t, inner, "init")
	if _, err := Resolve(inner); !os.IsNotExist(err) {
		t.Fatalf("nested repository inherited outer scope: %v", err)
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
