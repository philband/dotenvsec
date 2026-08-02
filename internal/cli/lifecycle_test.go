package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/philband/dotenvsec/internal/app"
	"github.com/philband/dotenvsec/internal/config"
	"github.com/philband/dotenvsec/internal/recipients"
	"github.com/philband/dotenvsec/internal/scope"
)

func TestInitMultipleRecipients(t *testing.T) {
	repository := t.TempDir()
	initTestGit(t, repository)
	sops, arguments := fakeSOPS(t, false)
	command := newInit()
	command.SetArgs([]string{
		repository,
		"-n", "TF_HTTP_USERNAME,TF_HTTP_PASSWORD,TF_ENCRYPTION",
		"-s", sops,
		"-p", "yubikey",
		"-r", "pb-yk-main=age1yubikey1primary",
		"-r", "pb-yk-dr-red=age1yubikey1recovery",
		"-r", "dm-main=age1yubikey1delegate",
		"-r", "dm-dr=age1yubikey1delegaterecovery",
	})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}

	manifest, err := config.LoadRecipients(filepath.Join(repository, ".dotenv-sec", "recipients.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Recipients) != 4 {
		t.Fatalf("got %d recipients, want 4", len(manifest.Recipients))
	}
	wantIDs := []string{"pb-yk-main", "pb-yk-dr-red", "dm-main", "dm-dr"}
	for index, want := range wantIDs {
		if manifest.Recipients[index].ID != want || manifest.Recipients[index].Plugin != "yubikey" {
			t.Fatalf("recipient %d = %#v", index, manifest.Recipients[index])
		}
	}
	sopsRules, err := os.ReadFile(filepath.Join(repository, ".sops.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := recipients.MatchesSOPS(sopsRules, manifest, ".env.sops.yaml"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(repository, ".env.sops.yaml")); err != nil {
		t.Fatal(err)
	}
	scopeConfig, err := config.LoadScope(filepath.Join(repository, ".dotenv-sec.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(scopeConfig.ProviderConfig["plugin_path"], filepath.Dir(sops)) {
		t.Fatalf("plugin path does not include detected plugin directory: %q", scopeConfig.ProviderConfig["plugin_path"])
	}

	args, err := os.ReadFile(arguments)
	if err != nil {
		t.Fatal(err)
	}
	joined := string(args)
	if !strings.HasPrefix(joined, "--config\n") || !strings.Contains(joined, "\nencrypt\n--filename-override\n") {
		t.Fatalf("SOPS global/subcommand argument order is invalid:\n%s", joined)
	}
	for _, expected := range []string{"--filename-override\n.env.sops.yaml\n", "--age\n", "age1yubikey1primary,age1yubikey1recovery,age1yubikey1delegate,age1yubikey1delegaterecovery\n"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("SOPS arguments do not contain %q:\n%s", expected, joined)
		}
	}
}

func TestRekeyOverridesFilenameForCreationRules(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	repository := t.TempDir()
	initTestGit(t, repository)
	sops, arguments := fakeSOPS(t, false)

	initialize := newInit()
	initialize.SetArgs([]string{repository, "-n", "TOKEN", "-s", sops, "-p", "age", "-r", "primary=age1primary", "-r", "backup=age1backup"})
	if err := initialize.Execute(); err != nil {
		t.Fatal(err)
	}
	runTestGit(t, repository, "add", ".")
	if _, err := app.RegisterProvider("sops", sops, ""); err != nil {
		t.Fatal(err)
	}
	allow := newAllow()
	allow.SetArgs([]string{repository})
	if err := allow.Execute(); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(arguments, 0); err != nil {
		t.Fatal(err)
	}

	rekey := newRekey()
	rekey.SetArgs([]string{repository})
	if err := rekey.Execute(); err != nil {
		t.Fatal(err)
	}

	args, err := os.ReadFile(arguments)
	if err != nil {
		t.Fatal(err)
	}
	// Without --filename-override, SOPS matches the /dev/stdin input path against
	// the scope creation rule and fails with "no matching creation rules found".
	if !strings.Contains(string(args), "encrypt\n--filename-override\n.env.sops.yaml\n") {
		t.Fatalf("rekey does not override the encryption filename:\n%s", args)
	}
}

func TestInitEncryptionFailureLeavesNoScope(t *testing.T) {
	repository := t.TempDir()
	initTestGit(t, repository)
	sops, _ := fakeSOPS(t, true)
	command := newInit()
	command.SetArgs([]string{repository, "-n", "TOKEN", "-r", "primary=age1test", "-s", sops})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "synthetic SOPS failure") {
		t.Fatalf("got error %v", err)
	}
	assertNoInitFiles(t, repository)
}

func TestInitRejectsDuplicateRecipientInputsBeforeWriting(t *testing.T) {
	tests := map[string][]string{
		"duplicate ID":        {"-r", "primary=age1first", "-r", "primary=age1second"},
		"duplicate recipient": {"-r", "primary=age1same", "-r", "backup=age1same"},
		"missing ID":          {"-r", "age1missingpair"},
		"unsupported plugin":  {"-r", "primary=age1test", "-p", "unknown"},
	}
	for name, flags := range tests {
		t.Run(name, func(t *testing.T) {
			repository := t.TempDir()
			initTestGit(t, repository)
			sops, _ := fakeSOPS(t, false)
			args := append([]string{repository, "-n", "TOKEN", "-s", sops}, flags...)
			command := newInit()
			command.SetArgs(args)
			if err := command.Execute(); err == nil {
				t.Fatal("expected validation error")
			}
			assertNoInitFiles(t, repository)
		})
	}
}

func TestInitLocalOutsideGit(t *testing.T) {
	directory := t.TempDir()
	sops, _ := fakeSOPS(t, false)
	command := newInit()
	command.SetArgs([]string{directory, "--local", "-n", "TOKEN", "-r", "primary=age1test", "-s", sops})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	scopeConfig, err := config.LoadScope(filepath.Join(directory, ".dotenv-sec.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if scopeConfig.EffectiveMode() != config.ScopeModeLocal {
		t.Fatalf("mode = %q", scopeConfig.EffectiveMode())
	}
	for _, path := range []string{".dotenv-sec.yaml", ".dotenv-sec/recipients.yaml", ".sops.yaml", ".env.sops.yaml"} {
		info, err := os.Stat(filepath.Join(directory, path))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode = %o", path, info.Mode().Perm())
		}
	}
}

func TestInitLocalInsideGitAddsPrivateExcludes(t *testing.T) {
	repository := t.TempDir()
	initTestGit(t, repository)
	nested := filepath.Join(repository, "infra", "prod")
	if err := os.MkdirAll(nested, 0755); err != nil {
		t.Fatal(err)
	}
	sops, _ := fakeSOPS(t, false)
	command := newInit()
	command.SetArgs([]string{nested, "--local", "-n", "TOKEN", "-r", "primary=age1test", "-s", sops})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"infra/prod/.dotenv-sec.yaml", "infra/prod/.dotenv-sec/recipients.yaml", "infra/prod/.sops.yaml", "infra/prod/.env.sops.yaml"} {
		git := exec.Command("git", "-C", repository, "check-ignore", "--quiet", "--", path)
		if output, err := git.CombinedOutput(); err != nil {
			t.Fatalf("%s is not ignored: %v: %s", path, err, output)
		}
	}
}

func TestInitGitLocalInheritedReadOnly(t *testing.T) {
	repository := t.TempDir()
	initTestGit(t, repository)
	writeTestFile(t, filepath.Join(repository, "README.md"), "test\n")
	runTestGit(t, repository, "add", "README.md")
	runTestGit(t, repository, "commit", "-m", "initial")
	sops, _ := fakeSOPS(t, false)
	command := newInit()
	command.SetArgs([]string{repository, "--git-local", "-n", "TOKEN", "-r", "primary=age1test", "-s", sops})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(t.TempDir(), "feature")
	runTestGit(t, repository, "worktree", "add", "-b", "test-feature", linked)
	id, err := scope.Resolve(linked)
	if err != nil {
		t.Fatal(err)
	}
	if id.Mode != config.ScopeModeGitLocal || !id.ReadOnly || id.Directory != canonicalTestPath(t, repository) {
		t.Fatalf("unexpected inherited identity: %#v", id)
	}
	prepared := app.Prepared{Identity: id}
	if err := app.EnsureWritable(prepared); err == nil || !strings.Contains(err.Error(), "inherited read-only") {
		t.Fatalf("expected read-only rejection, got %v", err)
	}
}

func TestInitGitLocalRejectedInLinkedWorktree(t *testing.T) {
	repository := t.TempDir()
	initTestGit(t, repository)
	writeTestFile(t, filepath.Join(repository, "README.md"), "test\n")
	runTestGit(t, repository, "add", "README.md")
	runTestGit(t, repository, "commit", "-m", "initial")
	linked := filepath.Join(t.TempDir(), "feature")
	runTestGit(t, repository, "worktree", "add", "-b", "test-linked-init", linked)
	sops, _ := fakeSOPS(t, false)
	command := newInit()
	command.SetArgs([]string{linked, "--git-local", "-n", "TOKEN", "-r", "primary=age1test", "-s", sops})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "main worktree") {
		t.Fatalf("expected main-worktree rejection, got %v", err)
	}
	assertNoInitFiles(t, linked)
}

func TestStableLocaleEnvironment(t *testing.T) {
	environment := stableLocaleEnvironment([]string{"PATH=/bin", "LANG=C.UTF-8", "LC_ALL=en_US.UTF-8", "HOME=/tmp"})
	joined := strings.Join(environment, "\n")
	if strings.Contains(joined, "C.UTF-8") || strings.Count(joined, "LANG=") != 1 || strings.Count(joined, "LC_ALL=") != 1 {
		t.Fatalf("unexpected locale environment:\n%s", joined)
	}
	if !strings.Contains(joined, "LANG=C") || !strings.Contains(joined, "LC_ALL=C") {
		t.Fatalf("portable locale is missing:\n%s", joined)
	}
}

func TestSOPSEnvironmentUsesConfiguredIdentities(t *testing.T) {
	environment := sopsEnvironment(
		[]string{"PATH=/bin", "SOPS_AGE_KEY_FILE=/untrusted/fallback"},
		[]string{"/private/identities.txt"},
		"",
	)
	joined := strings.Join(environment, "\n")
	if strings.Contains(joined, "/untrusted/fallback") {
		t.Fatalf("fallback identity path was not replaced:\n%s", joined)
	}
	if !strings.Contains(joined, "SOPS_AGE_KEY_FILE=/private/identities.txt") {
		t.Fatalf("configured identity path is missing:\n%s", joined)
	}
}

func TestSOPSEnvironmentPreservesFallbackWithoutSettings(t *testing.T) {
	environment := sopsEnvironment([]string{"SOPS_AGE_KEY_FILE=/explicit/fallback"}, nil, "")
	if !strings.Contains(strings.Join(environment, "\n"), "SOPS_AGE_KEY_FILE=/explicit/fallback") {
		t.Fatal("explicit fallback identity path was removed")
	}
}

func TestSOPSEnvironmentUsesConfiguredEditor(t *testing.T) {
	environment := sopsEnvironment(
		[]string{"EDITOR=vim", "SOPS_EDITOR=nano"},
		nil,
		"code --wait --reuse-window",
	)
	joined := strings.Join(environment, "\n")
	if strings.Contains(joined, "SOPS_EDITOR=nano") {
		t.Fatalf("ambient SOPS editor was not replaced:\n%s", joined)
	}
	if !strings.Contains(joined, "SOPS_EDITOR=code --wait --reuse-window") {
		t.Fatalf("configured editor is missing:\n%s", joined)
	}
	if !strings.Contains(joined, "EDITOR=vim") {
		t.Fatalf("unrelated editor fallback was removed:\n%s", joined)
	}
}

func TestSOPSEnvironmentPreservesEditorFallbackWithoutSetting(t *testing.T) {
	environment := sopsEnvironment([]string{"SOPS_EDITOR=nvim --wait"}, nil, "")
	if !strings.Contains(strings.Join(environment, "\n"), "SOPS_EDITOR=nvim --wait") {
		t.Fatal("ambient SOPS editor was removed")
	}
}

func TestNormalizeEditor(t *testing.T) {
	for _, preset := range []string{"vscode", "code", " VSCode "} {
		actual, err := normalizeEditor(preset)
		if err != nil {
			t.Fatal(err)
		}
		if actual != "code --wait --reuse-window" {
			t.Fatalf("normalizeEditor(%q) = %q", preset, actual)
		}
	}
	custom, err := normalizeEditor("nvim --nofork")
	if err != nil || custom != "nvim --nofork" {
		t.Fatalf("custom editor = %q, %v", custom, err)
	}
	if _, err := normalizeEditor("bad\ncommand"); err == nil {
		t.Fatal("expected control-character rejection")
	}
}

func fakeSOPS(t *testing.T, fail bool) (string, string) {
	t.Helper()
	directory := t.TempDir()
	executable := filepath.Join(directory, "sops")
	arguments := filepath.Join(directory, "arguments")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$SOPS_TEST_ARGUMENTS\"\ncat >/dev/null\n"
	if fail {
		script += "echo 'synthetic SOPS failure' >&2\nexit 1\n"
	} else {
		script += "printf '%s\\n' 'sops: synthetic-ciphertext'\n"
	}
	if err := os.WriteFile(executable, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	plugin := filepath.Join(directory, "age-plugin-yubikey")
	if err := os.WriteFile(plugin, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SOPS_TEST_ARGUMENTS", arguments)
	return executable, arguments
}

func assertNoInitFiles(t *testing.T, repository string) {
	t.Helper()
	for _, path := range []string{".dotenv-sec", ".dotenv-sec.yaml", ".sops.yaml", ".env.sops.yaml"} {
		if _, err := os.Stat(filepath.Join(repository, path)); !os.IsNotExist(err) {
			t.Fatalf("partial init path remains: %s", path)
		}
	}
}

func initTestGit(t *testing.T, directory string) {
	t.Helper()
	runTestGit(t, directory, "init")
	runTestGit(t, directory, "config", "user.name", "dotenvsec test")
	runTestGit(t, directory, "config", "user.email", "dotenvsec@example.invalid")
	runTestGit(t, directory, "config", "commit.gpgsign", "false")
}

func runTestGit(t *testing.T, directory string, arguments ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", directory}, arguments...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", arguments, err, output)
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func canonicalTestPath(t *testing.T, path string) string {
	t.Helper()
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}
