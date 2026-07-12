package provider

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverBundled(t *testing.T) {
	directory := t.TempDir()
	main := writeExecutable(t, directory, "dotenvsec", "main")
	provider := writeExecutable(t, directory, "dotenvsec-provider-sops", "provider")

	entry, found, err := DiscoverBundled(main, "dotenvsec-provider-sops")
	if err != nil {
		t.Fatal(err)
	}
	canonicalProvider, err := filepath.EvalSymlinks(provider)
	if err != nil {
		t.Fatal(err)
	}
	if !found || entry.Executable != canonicalProvider || entry.Source != "bundled" {
		t.Fatalf("unexpected discovery result: found=%t entry=%#v", found, entry)
	}
}

func TestDiscoverBundledMissingSiblingIsNoop(t *testing.T) {
	main := writeExecutable(t, t.TempDir(), "dotenvsec", "main")
	_, found, err := DiscoverBundled(main, "dotenvsec-provider-sops")
	if err != nil || found {
		t.Fatalf("found=%t err=%v", found, err)
	}
}

func TestDiscoverBundledRejectsProviderSymlink(t *testing.T) {
	directory := t.TempDir()
	main := writeExecutable(t, directory, "dotenvsec", "main")
	target := writeExecutable(t, t.TempDir(), "provider", "provider")
	if err := os.Symlink(target, filepath.Join(directory, "dotenvsec-provider-sops")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := DiscoverBundled(main, "dotenvsec-provider-sops"); err == nil {
		t.Fatal("expected symlink rejection")
	}
}

func TestDiscoverBundledRejectsWritableMain(t *testing.T) {
	directory := t.TempDir()
	main := writeExecutable(t, directory, "dotenvsec", "main")
	if err := os.Chmod(main, 0775); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, directory, "dotenvsec-provider-sops", "provider")
	if _, _, err := DiscoverBundled(main, "dotenvsec-provider-sops"); err == nil {
		t.Fatal("expected writable main rejection")
	}
}

func writeExecutable(t *testing.T, directory, name, contents string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(contents), 0755); err != nil {
		t.Fatal(err)
	}
	return path
}
