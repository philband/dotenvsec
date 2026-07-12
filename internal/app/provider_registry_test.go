package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/philband/dotenvsec/internal/config"
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
}
