package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/philband/dotenvsec/internal/environment"
)

func TestActivateQuietWithoutConfiguredScope(t *testing.T) {
	tests := map[string]func(*testing.T) string{
		"outside Git": func(t *testing.T) string {
			return t.TempDir()
		},
		"unconfigured Git worktree": func(t *testing.T) string {
			directory := t.TempDir()
			command := exec.Command("git", "-C", directory, "init")
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("git init: %v: %s", err, output)
			}
			return directory
		},
	}

	for name, directory := range tests {
		t.Run(name, func(t *testing.T) {
			stdout, stderr, err := executeActivate(directory(t))
			if err != nil {
				t.Fatal(err)
			}
			if stdout != environment.ClearScript() {
				t.Fatalf("stdout = %q, want clear script", stdout)
			}
			if stderr != "" {
				t.Fatalf("unexpected activation noise: %q", stderr)
			}
		})
	}
}

func TestActivateReportsBrokenConfiguredScope(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, ".dotenv-sec.yaml"), []byte("not: [valid"), 0600); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := executeActivate(directory)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != environment.ClearScript() {
		t.Fatalf("stdout = %q, want clear script", stdout)
	}
	if !strings.Contains(stderr, "dotenvsec:") || !strings.Contains(stderr, "scope config") {
		t.Fatalf("configured-scope error was not reported: %q", stderr)
	}
}

func TestActivateReportsMissingConfiguredScopeFile(t *testing.T) {
	directory := t.TempDir()
	policy := "schema: 2\nmode: local\nprovider: sops\nsource: .env.sops.yaml\nenvironment: [TOKEN]\n"
	if err := os.WriteFile(filepath.Join(directory, ".dotenv-sec.yaml"), []byte(policy), 0600); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := executeActivate(directory)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != environment.ClearScript() {
		t.Fatalf("stdout = %q, want clear script", stdout)
	}
	if !strings.Contains(stderr, "dotenvsec:") || !strings.Contains(stderr, ".env.sops.yaml") {
		t.Fatalf("missing configured file was not reported: %q", stderr)
	}
}

func executeActivate(path string) (string, string, error) {
	command := newActivate()
	var stdout, stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetArgs([]string{"--shell", "zsh", path})
	err := command.Execute()
	return stdout.String(), stderr.String(), err
}
