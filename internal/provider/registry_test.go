package provider

import (
	"os"
	"path/filepath"
	"testing"
)

// Homebrew exposes every binary as a symlink from <prefix>/bin into a versioned
// Cellar directory. Rejecting symlinks outright made those installations
// unusable while a weaker os.Stat check elsewhere still reported them healthy.
func TestFindInPathResolvesPackageManagerSymlinks(t *testing.T) {
	root := t.TempDir()
	cellar := filepath.Join(root, "Cellar", "age-plugin-yubikey", "0.5.0", "bin")
	if err := os.MkdirAll(cellar, 0755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(cellar, "age-plugin-yubikey")
	if err := os.WriteFile(target, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(bin, "age-plugin-yubikey")
	if err := os.Symlink("../Cellar/age-plugin-yubikey/0.5.0/bin/age-plugin-yubikey", link); err != nil {
		t.Fatal(err)
	}

	resolved, err := FindInPath("age-plugin-yubikey", bin)
	if err != nil {
		t.Fatalf("symlinked plugin was not found: %v", err)
	}
	canonical, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != canonical {
		t.Fatalf("resolved %q, want canonical %q", resolved, canonical)
	}
}

func TestResolveExecutableRejectsUnsafeTargets(t *testing.T) {
	directory := t.TempDir()
	worldWritable := filepath.Join(directory, "loose")
	if err := os.WriteFile(worldWritable, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	// Chmod explicitly: the process umask would otherwise strip the write bits
	// the test needs to assert on.
	if err := os.Chmod(worldWritable, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveExecutable(worldWritable); err == nil {
		t.Fatal("group/world writable executable accepted")
	}
	notExecutable := filepath.Join(directory, "data")
	if err := os.WriteFile(notExecutable, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveExecutable(notExecutable); err == nil {
		t.Fatal("non-executable file accepted")
	}
	if _, err := ResolveExecutable(filepath.Join(directory, "absent")); err == nil {
		t.Fatal("missing file accepted")
	}
}
