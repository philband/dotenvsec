package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/philband/dotenvsec/internal/config"
	"github.com/philband/dotenvsec/internal/scope"
	"github.com/philband/dotenvsec/internal/trust"
)

func TestRegisterProviderCanonicalizesSymlink(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	directory := t.TempDir()
	target := filepath.Join(directory, "provider-v1")
	if err := os.WriteFile(target, []byte("provider"), 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "provider")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	checksum, err := RegisterProvider("sops", link, "")
	if err != nil {
		t.Fatal(err)
	}
	settings, err := config.LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	entry := settings.Providers["sops"]
	canonical, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Executable != canonical {
		t.Fatalf("stored executable = %q, want canonical target %q", entry.Executable, canonical)
	}
	if entry.SHA256 != checksum {
		t.Fatalf("stored checksum = %q, returned %q", entry.SHA256, checksum)
	}
	if entry.Source != "manual" {
		t.Fatalf("provider source = %q, want manual", entry.Source)
	}
}

func TestRefreshBundledProviderFreshInstallAndNoop(t *testing.T) {
	configureTestHome(t)
	directory := t.TempDir()
	main := writeAppExecutable(t, directory, "dotenvsec", "main")
	provider := writeAppExecutable(t, directory, "dotenvsec-provider-sops", "provider-v1")

	changed, err := RefreshBundledProviderFrom(main)
	if err != nil || !changed {
		t.Fatalf("first refresh changed=%t err=%v", changed, err)
	}
	settings, err := config.LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	entry := settings.Providers["sops"]
	canonicalProvider, err := filepath.EvalSymlinks(provider)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Executable != canonicalProvider || entry.Source != "bundled" {
		t.Fatalf("unexpected bundled entry: %#v", entry)
	}

	changed, err = RefreshBundledProviderFrom(main)
	if err != nil || changed {
		t.Fatalf("second refresh changed=%t err=%v", changed, err)
	}
}

func TestRefreshBundledProviderUpgradePreservesApprovals(t *testing.T) {
	configureTestHome(t)
	root := t.TempDir()
	v1 := filepath.Join(root, "Cellar", "dotenvsec", "0.3.0", "bin")
	v2 := filepath.Join(root, "Cellar", "dotenvsec", "0.4.0", "bin")
	if err := os.MkdirAll(v1, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(v2, 0755); err != nil {
		t.Fatal(err)
	}
	oldProvider := writeAppExecutable(t, v1, "dotenvsec-provider-sops", "provider-v1")
	main := writeAppExecutable(t, v2, "dotenvsec", "main-v2")
	newProvider := writeAppExecutable(t, v2, "dotenvsec-provider-sops", "provider-v2")
	identity := scope.Identity{RepositoryID: "repo", RelativePath: ""}
	scopeConfig := config.Scope{Schema: 1, Provider: "sops", Source: ".env.sops.yaml", Environment: []string{"TOKEN"}}
	manifest := config.RecipientManifest{Schema: 1, Recipients: []config.Recipient{{ID: "primary", Owner: "owner", Status: "active", Plugin: "age", Recipient: "age1test"}}}
	oldTrust, err := trust.Hash(identity, scopeConfig, manifest, "old")
	if err != nil {
		t.Fatal(err)
	}
	settings := config.Settings{
		Schema:    config.SettingsSchemaVersion,
		Providers: map[string]config.ProviderEntry{"sops": {Executable: oldProvider, SHA256: "old"}},
		Approvals: map[string]config.Approval{"repo:": {Hash: oldTrust}},
	}
	if err := config.SaveSettings(settings); err != nil {
		t.Fatal(err)
	}

	changed, err := RefreshBundledProviderFrom(main)
	if err != nil || !changed {
		t.Fatalf("upgrade changed=%t err=%v", changed, err)
	}
	settings, err = config.LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	canonicalProvider, err := filepath.EvalSymlinks(newProvider)
	if err != nil {
		t.Fatal(err)
	}
	if settings.Providers["sops"].Executable != canonicalProvider || settings.Providers["sops"].Source != "bundled" {
		t.Fatalf("provider was not upgraded: %#v", settings.Providers["sops"])
	}
	if settings.Approvals["repo:"].Hash != oldTrust {
		t.Fatal("existing approval record was removed instead of being invalidated by trust hashing")
	}
	newTrust, err := trust.Hash(identity, scopeConfig, manifest, settings.Providers["sops"].SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if newTrust == settings.Approvals["repo:"].Hash {
		t.Fatal("provider upgrade did not invalidate the retained approval hash")
	}
}

func TestRefreshBundledProviderPreservesManualOverride(t *testing.T) {
	configureTestHome(t)
	directory := t.TempDir()
	main := writeAppExecutable(t, directory, "dotenvsec", "main")
	writeAppExecutable(t, directory, "dotenvsec-provider-sops", "bundled")
	manual := writeAppExecutable(t, t.TempDir(), "custom-provider", "manual")
	settings := config.Settings{Schema: config.SettingsSchemaVersion, Providers: map[string]config.ProviderEntry{
		"sops": {Executable: manual, SHA256: "manual", Source: "manual"},
	}}
	if err := config.SaveSettings(settings); err != nil {
		t.Fatal(err)
	}
	changed, err := RefreshBundledProviderFrom(main)
	if err != nil || changed {
		t.Fatalf("manual override changed=%t err=%v", changed, err)
	}
	settings, err = config.LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if settings.Providers["sops"].Executable != manual {
		t.Fatal("manual provider was overwritten")
	}
}

func configureTestHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
}

func writeAppExecutable(t *testing.T, directory, name, contents string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(contents), 0755); err != nil {
		t.Fatal(err)
	}
	return path
}
