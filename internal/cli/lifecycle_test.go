package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/philband/dotenvsec/internal/config"
	"github.com/philband/dotenvsec/internal/recipients"
)

func TestInitMultipleRecipients(t *testing.T) {
	repository := t.TempDir()
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

func TestInitEncryptionFailureLeavesNoScope(t *testing.T) {
	repository := t.TempDir()
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
	environment := sopsEnvironment([]string{"SOPS_AGE_KEY_FILE=/explicit/fallback"}, nil)
	if !strings.Contains(strings.Join(environment, "\n"), "SOPS_AGE_KEY_FILE=/explicit/fallback") {
		t.Fatal("explicit fallback identity path was removed")
	}
}

func fakeSOPS(t *testing.T, fail bool) (string, string) {
	t.Helper()
	directory := t.TempDir()
	executable := filepath.Join(directory, "sops")
	arguments := filepath.Join(directory, "arguments")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$SOPS_TEST_ARGUMENTS\"\ncat >/dev/null\n"
	if fail {
		script += "echo 'synthetic SOPS failure' >&2\nexit 1\n"
	} else {
		script += "printf '%s\\n' 'sops: synthetic-ciphertext'\n"
	}
	if err := os.WriteFile(executable, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
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
