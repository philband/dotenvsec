package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/philband/dotenvsec/internal/config"
)

func TestMigrateMovesMachineLocalConfigIntoRegistry(t *testing.T) {
	repository := t.TempDir()
	initTestGit(t, repository)
	sops, _ := fakeSOPS(t, false)
	canonical, err := filepath.EvalSymlinks(sops)
	if err != nil {
		t.Fatal(err)
	}
	pluginDirectory := filepath.Dir(canonical)
	legacy := "schema: 1\nprovider: sops\nsource: .env.sops.yaml\nenvironment:\n    - TOKEN\nprovider_config:\n" +
		"    sops_executable: " + sops + "\n" +
		"    sops_sha256: unused\n" +
		"    plugin_path: " + pluginDirectory + "\n" +
		"    sops_min_version: \"3.10.0\"\n"
	scopePath := filepath.Join(repository, ".dotenv-sec.yaml")
	if err := os.WriteFile(scopePath, []byte(legacy), 0644); err != nil {
		t.Fatal(err)
	}

	migrate := newMigrate()
	migrate.SetArgs([]string{repository})
	if err := migrate.Execute(); err != nil {
		t.Fatal(err)
	}

	migrated, err := config.LoadScope(scopePath)
	if err != nil {
		t.Fatal(err)
	}
	if migrated.Schema != config.ScopeSchemaVersion {
		t.Fatalf("schema not bumped: %d", migrated.Schema)
	}
	for _, key := range config.MachineLocalProviderKeys {
		if _, present := migrated.ProviderConfig[key]; present {
			t.Fatalf("machine-local key %q survived migration", key)
		}
	}
	if migrated.ProviderConfig["sops_min_version"] != "3.10.0" {
		t.Fatalf("portable policy was dropped: %#v", migrated.ProviderConfig)
	}
	settings, err := config.LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	entry := settings.Providers["sops"]
	if entry.Tools["sops"].Executable != canonical {
		t.Fatalf("sops was not bound locally: %#v", entry.Tools)
	}
	if entry.PluginPath != pluginDirectory {
		t.Fatalf("plugin path was not migrated: %q", entry.PluginPath)
	}

	// Migration is not idempotent by design: a second run must refuse rather
	// than silently rewrite an already-current file.
	again := newMigrate()
	again.SetArgs([]string{repository})
	if err := again.Execute(); err == nil || !strings.Contains(err.Error(), "already at the current schema") {
		t.Fatalf("second migration returned %v", err)
	}
}

func TestScopeRejectsMachineLocalProviderConfig(t *testing.T) {
	for _, key := range config.MachineLocalProviderKeys {
		scope := config.Scope{Schema: config.ScopeSchemaVersion, Provider: "sops", Source: ".env.sops.yaml", Environment: []string{"TOKEN"}, ProviderConfig: map[string]string{key: "value"}}
		err := config.ValidateScope(scope)
		if err == nil || !strings.Contains(err.Error(), "machine-local") {
			t.Fatalf("key %q was accepted in a tracked scope file: %v", key, err)
		}
	}
}

func TestScopeRejectsMalformedVersionFloor(t *testing.T) {
	scope := config.Scope{Schema: config.ScopeSchemaVersion, Provider: "sops", Source: ".env.sops.yaml", Environment: []string{"TOKEN"}, ProviderConfig: map[string]string{"sops_min_version": "latest"}}
	if err := config.ValidateScope(scope); err == nil {
		t.Fatal("malformed sops_min_version accepted")
	}
}

func TestCheckSOPSVersionEnforcesFloor(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "sops")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\necho 'sops 3.9.1'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := checkSOPSVersion(t.Context(), executable, "3.10.0"); err == nil {
		t.Fatal("version floor was not enforced")
	}
	if err := checkSOPSVersion(t.Context(), executable, "3.9"); err != nil {
		t.Fatalf("satisfied floor rejected: %v", err)
	}
	if err := checkSOPSVersion(t.Context(), executable, ""); err != nil {
		t.Fatalf("absent floor rejected: %v", err)
	}
}
