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
	"sort"
	"strings"
	"syscall"

	"github.com/philband/dotenvsec/internal/config"
)

// Verify checks the provider executable only. Tool bindings are checked by
// VerifyTools immediately before dispatch: folding them in here would make a
// stale tool break read-only commands such as status and doctor, which are what
// an operator reaches for to diagnose exactly that.
func Verify(entry config.ProviderEntry) error {
	return VerifyExecutable("provider", entry.Executable, entry.SHA256)
}

func VerifyTools(entry config.ProviderEntry) error {
	names := make([]string, 0, len(entry.Tools))
	for name := range entry.Tools {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := VerifyExecutable("tool "+name, entry.Tools[name].Executable, entry.Tools[name].SHA256); err != nil {
			return err
		}
	}
	return nil
}

// VerifyExecutable applies the launch preconditions from the threat model:
// absolute path, regular non-symlink file, not group/world writable, owned by
// this user or root, and matching its pinned checksum.
func VerifyExecutable(label, path, expected string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s executable must be an absolute path", label)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s executable must be a regular non-symlink file", label)
	}
	if info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("%s executable must not be group/world writable", label)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Getuid() && stat.Uid != 0 {
		return fmt.Errorf("%s executable must be owned by the user or root", label)
	}
	actual, err := FileSHA256(path)
	if err != nil {
		return err
	}
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("%s checksum mismatch: got %s; re-pin with dotenvsec provider retool", label, actual)
	}
	return nil
}

// FindInPath resolves an executable in a search path, following symlinks before
// applying the launch preconditions. Package managers such as Homebrew install
// every binary as a symlink into a versioned Cellar directory, so rejecting
// symlinks outright would make those installations unusable.
func FindInPath(name, path string) (string, error) {
	for _, directory := range filepath.SplitList(path) {
		if resolved, err := ResolveExecutable(filepath.Join(directory, name)); err == nil {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("%s not found in provider plugin path", name)
}

// ResolveExecutable canonicalizes a candidate and applies the launch
// preconditions to the resolved target. Callers store the canonical path so the
// file that is checksummed is the file that is executed, with no symlink left
// in between to be repointed afterwards.
func ResolveExecutable(candidate string) (string, error) {
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", resolved)
	}
	if info.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("%s is not executable", resolved)
	}
	if info.Mode().Perm()&0022 != 0 {
		return "", fmt.Errorf("%s is group/world writable", resolved)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Getuid() && stat.Uid != 0 {
		return "", fmt.Errorf("%s is not owned by the user or root", resolved)
	}
	return resolved, nil
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
