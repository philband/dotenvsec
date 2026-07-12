package app

import (
	"errors"
	"path/filepath"

	"github.com/philband/dotenvsec/internal/config"
	localprovider "github.com/philband/dotenvsec/internal/provider"
)

func RegisterProvider(id, executable, expectedSHA string) (string, error) {
	absolute, err := filepath.Abs(executable)
	if err != nil {
		return "", err
	}
	actual, err := localprovider.FileSHA256(absolute)
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
	entry := config.ProviderEntry{Executable: absolute, SHA256: actual}
	if err := localprovider.Verify(entry); err != nil {
		return "", err
	}
	settings.Providers[id] = entry
	if err := config.SaveSettings(settings); err != nil {
		return "", err
	}
	return actual, nil
}

func RevokeProvider(id string) error {
	settings, err := config.LoadSettings()
	if err != nil {
		return err
	}
	delete(settings.Providers, id)
	return config.SaveSettings(settings)
}
