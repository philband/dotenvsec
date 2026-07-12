package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/philband/dotenvsec/internal/config"
)

func Verify(entry config.ProviderEntry) error {
	if !filepath.IsAbs(entry.Executable) {
		return errors.New("provider executable must be an absolute path")
	}
	info, err := os.Lstat(entry.Executable)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("provider executable must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0022 != 0 {
		return errors.New("provider executable must not be group/world writable")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Getuid() && stat.Uid != 0 {
		return errors.New("provider executable must be owned by the user or root")
	}
	actual, err := FileSHA256(entry.Executable)
	if err != nil {
		return err
	}
	if !strings.EqualFold(actual, entry.SHA256) {
		return fmt.Errorf("provider checksum mismatch: got %s", actual)
	}
	return nil
}

func FileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, 256<<20)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func SafePath(extra string) (string, error) {
	parts := []string{"/usr/local/bin", "/usr/bin", "/bin"}
	if runtime.GOOS == "darwin" {
		parts = append([]string{"/opt/homebrew/bin"}, parts...)
	}
	if extra != "" {
		for _, part := range filepath.SplitList(extra) {
			if !filepath.IsAbs(part) {
				return "", errors.New("provider plugin_path entries must be absolute")
			}
			parts = append([]string{part}, parts...)
		}
	}
	return strings.Join(parts, string(os.PathListSeparator)), nil
}
