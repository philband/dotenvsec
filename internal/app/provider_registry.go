package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/philband/dotenvsec/internal/config"
	localprovider "github.com/philband/dotenvsec/internal/provider"
)

func RegisterProvider(id, executable, expectedSHA string) (string, error) {
	absolute, err := filepath.Abs(executable)
	if err != nil {
		return "", err
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	actual, err := localprovider.FileSHA256(canonical)
	if err != nil {
		return "", err
	}
	if expectedSHA != "" && expectedSHA != actual {
		return "", errors.New("supplied checksum does not match executable")
	}
	settings, err := config.LoadSettings()
	if err != nil {
		return "", err
	}
	entry := config.ProviderEntry{Executable: canonical, SHA256: actual, Source: "manual"}
	if err := localprovider.Verify(entry); err != nil {
		return "", err
	}
	settings.Providers[id] = entry
	if err := config.SaveSettings(settings); err != nil {
		return "", err
	}
	return actual, nil
}

func RefreshBundledProvider() (bool, error) {
	executable, err := os.Executable()
	if err != nil {
		return false, err
	}
	return RefreshBundledProviderFrom(executable)
}

func RefreshBundledProviderFrom(mainExecutable string) (bool, error) {
	entry, found, err := localprovider.DiscoverBundled(mainExecutable, "dotenvsec-provider-sops")
	if err != nil || !found {
		return false, err
	}
	settings, err := config.LoadSettings()
	if err != nil {
		return false, err
	}
	current, exists := settings.Providers["sops"]
	if exists && current.Source == "manual" {
		return false, nil
	}
	if exists && current.Source == "" && !legacyBundledProvider(current.Executable, entry.Executable) {
		return false, nil
	}
	entry.Source = "bundled"
	if exists && current.Executable == entry.Executable && current.SHA256 == entry.SHA256 && current.Source == entry.Source {
		return false, nil
	}
	settings.Providers["sops"] = entry
	if err := config.SaveSettings(settings); err != nil {
		return false, err
	}
	return true, nil
}

func legacyBundledProvider(oldPath, bundledPath string) bool {
	if filepath.Base(oldPath) != "dotenvsec-provider-sops" {
		return false
	}
	if filepath.Dir(oldPath) == filepath.Dir(bundledPath) {
		return true
	}
	oldParts := strings.Split(filepath.ToSlash(oldPath), "/")
	newParts := strings.Split(filepath.ToSlash(bundledPath), "/")
	return homebrewDotenvsecPath(oldParts) && homebrewDotenvsecPath(newParts)
}

func homebrewDotenvsecPath(parts []string) bool {
	for index := 0; index+3 < len(parts); index++ {
		if parts[index] == "Cellar" && parts[index+1] == "dotenvsec" && parts[index+3] == "bin" {
			return true
		}
	}
	return false
}

func RevokeProvider(id string) error {
	settings, err := config.LoadSettings()
	if err != nil {
		return err
	}
	delete(settings.Providers, id)
	return config.SaveSettings(settings)
}
