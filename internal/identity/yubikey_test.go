package identity

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	recipientA = "age1yubikey1aaaaaaaa"
	recipientB = "age1yubikey1bbbbbbbb"
	identityA  = "AGE-PLUGIN-YUBIKEY-1AAAAAAAA"
	identityB  = "AGE-PLUGIN-YUBIKEY-1BBBBBBBB"
)

func TestPrepareConnectedYubiKeysCreatesManagedFileAndFiltersScope(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	pluginDirectory := fakeYubiKeyPlugin(t, pluginOutput())

	prepared, err := PrepareConnectedYubiKeys(context.Background(), "", pluginDirectory, []string{recipientA})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Cleanup()
	if !prepared.Changed {
		t.Fatal("managed identity file was not reported as changed")
	}
	assertPrivateFile(t, prepared.PersistentPath)
	assertPrivateFile(t, prepared.EffectivePath)
	persistent := readFile(t, prepared.PersistentPath)
	effective := readFile(t, prepared.EffectivePath)
	if !strings.Contains(persistent, identityA) || strings.Contains(persistent, identityB) {
		t.Fatalf("persistent identities were not scope-filtered")
	}
	if !strings.Contains(effective, identityA) || strings.Contains(effective, identityB) {
		t.Fatalf("effective identities were not connected/scope-filtered")
	}
	temporary := prepared.EffectivePath
	prepared.Cleanup()
	if _, err := os.Stat(temporary); !os.IsNotExist(err) {
		t.Fatal("effective identity file was not cleaned up")
	}
}

func TestPrepareConnectedYubiKeysPreservesNonYubiKeyAndExcludesDisconnected(t *testing.T) {
	directory := t.TempDir()
	configured := filepath.Join(directory, "identities.txt")
	existing := "AGE-SECRET-KEY-1STANDARD\n" + identityA + "\n" + identityB + "\n"
	if err := os.WriteFile(configured, []byte(existing), 0600); err != nil {
		t.Fatal(err)
	}
	pluginDirectory := fakeYubiKeyPlugin(t, singlePluginOutput(recipientA, identityA))
	prepared, err := PrepareConnectedYubiKeys(context.Background(), configured, pluginDirectory, []string{recipientA, recipientB})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Cleanup()
	effective := readFile(t, prepared.EffectivePath)
	if !strings.Contains(effective, "AGE-SECRET-KEY-1STANDARD") || !strings.Contains(effective, identityA) || strings.Contains(effective, identityB) {
		t.Fatalf("effective identity filtering failed")
	}
	if readFile(t, configured) != existing {
		t.Fatal("persistent identity file changed without a newly discovered identity")
	}
}

func TestPrepareConnectedYubiKeysRejectsNoMatchingConnectedKey(t *testing.T) {
	pluginDirectory := fakeYubiKeyPlugin(t, singlePluginOutput(recipientB, identityB))
	if _, err := PrepareConnectedYubiKeys(context.Background(), "", pluginDirectory, []string{recipientA}); err == nil || !strings.Contains(err.Error(), "no connected YubiKey matches") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func pluginOutput() string {
	return singlePluginOutput(recipientA, identityA) + singlePluginOutput(recipientB, identityB)
}

func singlePluginOutput(recipient, identity string) string {
	return "# Recipient: " + recipient + "\n" + identity + "\n"
}

func fakeYubiKeyPlugin(t *testing.T, output string) string {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "age-plugin-yubikey")
	script := "#!/bin/sh\nprintf '%s' '" + output + "'\n"
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func assertPrivateFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("unsafe private file mode: %v", info.Mode())
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
