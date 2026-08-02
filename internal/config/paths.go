package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

func SettingsPath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "dotenvsec", "settings.yaml"), nil
}

func LoadSettings() (Settings, error) {
	path, err := SettingsPath()
	if err != nil {
		return Settings{}, err
	}
	var settings Settings
	if err := DecodeFile(path, &settings); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Settings{Schema: SettingsSchemaVersion, Providers: map[string]ProviderEntry{}, Approvals: map[string]Approval{}, DangerousApprovals: map[string][]string{}}, nil
		}
		return settings, err
	}
	if settings.Schema != SettingsSchemaVersion {
		return settings, errors.New("unsupported user settings schema")
	}
	if settings.Providers == nil {
		settings.Providers = map[string]ProviderEntry{}
	}
	for id, entry := range settings.Providers {
		if entry.Source != "" && entry.Source != "manual" && entry.Source != "bundled" {
			return settings, errors.New("provider " + id + " has unsupported source")
		}
		for _, part := range filepath.SplitList(entry.PluginPath) {
			if !filepath.IsAbs(part) {
				return settings, errors.New("provider " + id + " plugin_path entries must be absolute")
			}
		}
		for tool, binding := range entry.Tools {
			if !filepath.IsAbs(binding.Executable) {
				return settings, errors.New("provider " + id + " tool " + tool + " executable must be absolute")
			}
			if len(binding.SHA256) != 64 {
				return settings, errors.New("provider " + id + " tool " + tool + " requires a SHA-256 checksum")
			}
		}
	}
	if settings.Approvals == nil {
		settings.Approvals = map[string]Approval{}
	}
	if settings.DangerousApprovals == nil {
		settings.DangerousApprovals = map[string][]string{}
	}
	if len(settings.IdentityPaths) > 1 {
		return settings, errors.New("SOPS supports one consolidated age identity file")
	}
	for _, identity := range settings.IdentityPaths {
		if !filepath.IsAbs(identity) {
			return settings, errors.New("identity file path must be absolute")
		}
		info, err := os.Lstat(identity)
		if err != nil {
			return settings, err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
			return settings, errors.New("identity file must be regular, non-symlink, and private")
		}
	}
	if strings.IndexFunc(settings.Editor, unicode.IsControl) >= 0 {
		return settings, errors.New("editor command must not contain control characters")
	}
	return settings, nil
}

func SaveSettings(settings Settings) error {
	path, err := SettingsPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := yamlMarshal(settings)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".settings-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
