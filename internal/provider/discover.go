package provider

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/philband/dotenvsec/internal/config"
)

func DiscoverBundled(mainExecutable, providerName string) (config.ProviderEntry, bool, error) {
	canonicalMain, err := filepath.EvalSymlinks(mainExecutable)
	if err != nil {
		return config.ProviderEntry{}, false, err
	}
	mainInfo, err := os.Lstat(canonicalMain)
	if err != nil {
		return config.ProviderEntry{}, false, err
	}
	if !mainInfo.Mode().IsRegular() || mainInfo.Mode()&os.ModeSymlink != 0 {
		return config.ProviderEntry{}, false, os.ErrInvalid
	}
	if mainInfo.Mode().Perm()&0022 != 0 {
		return config.ProviderEntry{}, false, errors.New("main executable must not be group/world writable")
	}
	providerPath := filepath.Join(filepath.Dir(canonicalMain), providerName)
	if _, err := os.Lstat(providerPath); os.IsNotExist(err) {
		return config.ProviderEntry{}, false, nil
	} else if err != nil {
		return config.ProviderEntry{}, false, err
	}
	checksum, err := FileSHA256(providerPath)
	if err != nil {
		return config.ProviderEntry{}, false, err
	}
	entry := config.ProviderEntry{Executable: providerPath, SHA256: checksum, Source: "bundled"}
	if err := Verify(entry); err != nil {
		return config.ProviderEntry{}, false, err
	}
	providerInfo, err := os.Lstat(providerPath)
	if err != nil {
		return config.ProviderEntry{}, false, err
	}
	mainStat, mainOK := mainInfo.Sys().(*syscall.Stat_t)
	providerStat, providerOK := providerInfo.Sys().(*syscall.Stat_t)
	if mainOK && providerOK && mainStat.Uid != providerStat.Uid {
		return config.ProviderEntry{}, false, errors.New("main executable and bundled provider must have the same owner")
	}
	return entry, true, nil
}
