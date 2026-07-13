package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/philband/dotenvsec/internal/config"
	"github.com/philband/dotenvsec/internal/scope"
)

func TestEnvironmentOverlay(t *testing.T) {
	loaded := Loaded{Environment: map[string]string{"A": "new", "C": "three"}, Unset: []string{"B"}}
	got := Environment([]string{"A=old", "B=two", "PATH=/bin"}, loaded)
	want := []string{"A=new", "C=three", "PATH=/bin"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestEffectiveTTLDefaultsOffAndBounds(t *testing.T) {
	if got := effectiveTTL(time.Minute, 0); got != 0 {
		t.Fatalf("default user maximum must disable cache: %v", got)
	}
	if got := effectiveTTL(time.Hour, 5*time.Minute); got != 5*time.Minute {
		t.Fatalf("TTL not bounded: %v", got)
	}
	if got := effectiveTTL(time.Minute, 5*time.Minute); got != time.Minute {
		t.Fatalf("TTL unexpectedly changed: %v", got)
	}
}

func TestMarkerIncludesInvalidationKey(t *testing.T) {
	prepared := Prepared{ScopeKey: "repo:path", TrustHash: "trust", CacheKey: "cipher:provider:identity", Config: config.Scope{}}
	got := Marker(prepared)
	if got != "repo:path:trust:cipher:provider:identity" {
		t.Fatal(got)
	}
}

func TestScopeKeyModes(t *testing.T) {
	repository := scopeKey(scope.Identity{RepositoryID: "repo", RelativePath: "infra", Mode: config.ScopeModeRepository})
	local := scopeKey(scope.Identity{RepositoryID: "repo", RelativePath: "infra", Mode: config.ScopeModeLocal})
	gitLocal := scopeKey(scope.Identity{RepositoryID: "repo", RelativePath: "infra", Mode: config.ScopeModeGitLocal})
	if repository != "repo:infra" || local != "local:repo:infra" || gitLocal != "git-local:repo:infra" {
		t.Fatalf("unexpected keys: %q %q %q", repository, local, gitLocal)
	}
}

func TestRequireIgnoredUntracked(t *testing.T) {
	repository := t.TempDir()
	runLoadGit(t, repository, "init")
	path := filepath.Join(repository, ".dotenv-sec.yaml")
	if err := os.WriteFile(path, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	exclude := filepath.Join(repository, ".git", "info", "exclude")
	if err := os.WriteFile(exclude, []byte("/.dotenv-sec.yaml\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := requireIgnoredUntracked(repository, path); err != nil {
		t.Fatal(err)
	}
	runLoadGit(t, repository, "add", "-f", ".dotenv-sec.yaml")
	if err := requireIgnoredUntracked(repository, path); err == nil || !strings.Contains(err.Error(), "must not be tracked") {
		t.Fatalf("forced tracked file error = %v", err)
	}
}

func TestEnsureWritableRejectsInheritedScope(t *testing.T) {
	prepared := Prepared{Identity: scope.Identity{ReadOnly: true, Directory: "/main/infra"}}
	if err := EnsureWritable(prepared); err == nil || !strings.Contains(err.Error(), "/main/infra") {
		t.Fatalf("read-only error = %v", err)
	}
}

func runLoadGit(t *testing.T, directory string, arguments ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", directory}, arguments...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", arguments, err, output)
	}
}
