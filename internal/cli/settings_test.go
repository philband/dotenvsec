package cli

import (
	"path/filepath"
	"testing"

	"github.com/philband/dotenvsec/internal/config"
)

func TestSettingsEditorPersistsAndClearsGlobalDefault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	set := newSettings()
	set.SetArgs([]string{"editor", "vscode"})
	if err := set.Execute(); err != nil {
		t.Fatal(err)
	}
	settings, err := config.LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if settings.Editor != "code --wait --reuse-window" {
		t.Fatalf("stored editor = %q", settings.Editor)
	}

	clear := newSettings()
	clear.SetArgs([]string{"editor", "--clear"})
	if err := clear.Execute(); err != nil {
		t.Fatal(err)
	}
	settings, err = config.LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if settings.Editor != "" {
		t.Fatalf("editor was not cleared: %q", settings.Editor)
	}
}
