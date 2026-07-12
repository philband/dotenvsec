package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/philband/dotenvsec/internal/config"
)

func TestPrepareSOPSIdentitiesFillsSettingsFromConnectedYubiKey(t *testing.T) {
	configureTestHome(t)
	pluginDirectory := t.TempDir()
	plugin := filepath.Join(pluginDirectory, "age-plugin-yubikey")
	script := "#!/bin/sh\nprintf '%s\\n' '# Recipient: age1yubikey1test' 'AGE-PLUGIN-YUBIKEY-1TEST'\n"
	if err := os.WriteFile(plugin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), ".env.sops.yaml")
	if err := os.WriteFile(source, []byte("ciphertext"), 0600); err != nil {
		t.Fatal(err)
	}
	prepared := Prepared{
		Config: config.Scope{ProviderConfig: map[string]string{"plugin_path": pluginDirectory}},
		Manifest: config.RecipientManifest{Recipients: []config.Recipient{{
			Status: "active", Plugin: "yubikey", Recipient: "age1yubikey1test",
		}}},
		Settings:  config.Settings{Schema: config.SettingsSchemaVersion, Providers: map[string]config.ProviderEntry{}},
		Provider:  config.ProviderEntry{SHA256: "provider"},
		Source:    source,
		TrustHash: "trust",
	}
	effective, cleanup, err := PrepareSOPSIdentities(context.Background(), &prepared)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if effective == "" || len(prepared.Settings.IdentityPaths) != 1 {
		t.Fatalf("identity paths were not prepared: %q %#v", effective, prepared.Settings.IdentityPaths)
	}
	settings, err := config.LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if len(settings.IdentityPaths) != 1 || settings.IdentityPaths[0] != prepared.Settings.IdentityPaths[0] {
		t.Fatal("managed identity path was not persisted")
	}
}
