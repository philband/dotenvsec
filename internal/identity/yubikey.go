package identity

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/philband/dotenvsec/internal/config"
	"github.com/philband/dotenvsec/internal/provider"
)

const (
	yubiKeyIdentityPrefix = "AGE-PLUGIN-YUBIKEY-"
	maxIdentityBytes      = 1 << 20
)

type Prepared struct {
	PersistentPath string
	EffectivePath  string
	Changed        bool
	cleanup        func()
}

func (p Prepared) Cleanup() {
	if p.cleanup != nil {
		p.cleanup()
	}
}

func PrepareConnectedYubiKeys(ctx context.Context, configuredPath, pluginPath string, allowedRecipients []string) (Prepared, error) {
	if len(allowedRecipients) == 0 {
		return Prepared{PersistentPath: configuredPath, EffectivePath: configuredPath}, nil
	}
	safePath, err := provider.SafePath(pluginPath)
	if err != nil {
		return Prepared{}, err
	}
	plugin, err := findExecutable("age-plugin-yubikey", safePath)
	if err != nil {
		return Prepared{}, err
	}
	connected, err := connectedIdentities(ctx, plugin, safePath, allowedRecipients)
	if err != nil {
		return Prepared{}, err
	}
	if len(connected) == 0 {
		return Prepared{}, errors.New("no connected YubiKey matches an active repository recipient")
	}
	if configuredPath == "" {
		settingsPath, err := config.SettingsPath()
		if err != nil {
			return Prepared{}, err
		}
		configuredPath = filepath.Join(filepath.Dir(settingsPath), "identities.txt")
	}
	persistent, err := readOptionalPrivateFile(configuredPath)
	if err != nil {
		return Prepared{}, err
	}
	merged := mergePersistent(persistent, connected)
	changed := !bytes.Equal(persistent, merged)
	if changed {
		if err := atomicPrivateWrite(configuredPath, merged); err != nil {
			return Prepared{}, err
		}
	}
	effective := filterEffective(merged, connected)
	temporary, err := writePrivateTemp(filepath.Dir(configuredPath), effective)
	if err != nil {
		return Prepared{}, err
	}
	return Prepared{
		PersistentPath: configuredPath,
		EffectivePath:  temporary,
		Changed:        changed,
		cleanup:        func() { _ = os.Remove(temporary) },
	}, nil
}

func connectedIdentities(ctx context.Context, plugin, pluginPath string, allowedRecipients []string) ([]string, error) {
	allowed := make(map[string]bool, len(allowedRecipients))
	for _, recipient := range allowedRecipients {
		allowed[recipient] = true
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, plugin, "-i")
	command.Env = []string{
		"HOME=" + os.Getenv("HOME"),
		"USER=" + os.Getenv("USER"),
		"PATH=" + pluginPath,
		"LANG=C",
		"LC_ALL=C",
	}
	command.Stderr = io.Discard
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(stdout, maxIdentityBytes+1))
	waitErr := command.Wait()
	if ctx.Err() != nil {
		return nil, errors.New("YubiKey identity discovery timed out")
	}
	if readErr != nil {
		return nil, errors.New("cannot read YubiKey identity discovery output")
	}
	if len(data) > maxIdentityBytes {
		return nil, errors.New("YubiKey identity discovery output is too large")
	}
	if waitErr != nil {
		return nil, errors.New("YubiKey identity discovery failed")
	}
	return parseConnected(data, allowed)
}

func parseConnected(data []byte, allowed map[string]bool) ([]string, error) {
	var currentRecipient string
	var identities []string
	seen := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") && strings.Contains(line, "Recipient:") {
			_, value, _ := strings.Cut(line, "Recipient:")
			currentRecipient = strings.TrimSpace(value)
			continue
		}
		if !strings.HasPrefix(line, yubiKeyIdentityPrefix) {
			continue
		}
		if currentRecipient == "" {
			return nil, errors.New("YubiKey identity discovery output lacks recipient metadata")
		}
		if allowed[currentRecipient] && !seen[line] {
			identities = append(identities, line)
			seen[line] = true
		}
		currentRecipient = ""
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.New("cannot parse YubiKey identity discovery output")
	}
	return identities, nil
}

func findExecutable(name, path string) (string, error) {
	for _, directory := range filepath.SplitList(path) {
		candidate := filepath.Join(directory, name)
		info, err := os.Lstat(candidate)
		if err != nil {
			continue
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 {
			continue
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Getuid() && stat.Uid != 0 {
			continue
		}
		return candidate, nil
	}
	return "", fmt.Errorf("%s not found in provider plugin path", name)
}

func readOptionalPrivateFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("identity file must be regular, non-symlink, and private")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxIdentityBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxIdentityBytes {
		return nil, errors.New("identity file is too large")
	}
	return data, nil
}

func mergePersistent(existing []byte, connected []string) []byte {
	merged := append([]byte(nil), existing...)
	if len(merged) > 0 && merged[len(merged)-1] != '\n' {
		merged = append(merged, '\n')
	}
	known := map[string]bool{}
	for _, line := range strings.Split(string(existing), "\n") {
		known[strings.TrimSpace(line)] = true
	}
	for _, identity := range connected {
		if known[identity] {
			continue
		}
		merged = append(merged, identity...)
		merged = append(merged, '\n')
		known[identity] = true
	}
	return merged
}

func filterEffective(persistent []byte, connected []string) []byte {
	var lines []string
	for _, line := range strings.Split(string(persistent), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, yubiKeyIdentityPrefix) {
			continue
		}
		lines = append(lines, line)
	}
	lines = append(lines, connected...)
	return []byte(strings.Join(lines, "\n") + "\n")
}

func atomicPrivateWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	temporary, err := writePrivateTemp(filepath.Dir(path), data)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(temporary) }()
	return os.Rename(temporary, path)
}

func writePrivateTemp(directory string, data []byte) (string, error) {
	file, err := os.CreateTemp(directory, ".dotenvsec-identities-*")
	if err != nil {
		return "", err
	}
	name := file.Name()
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return "", err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	return name, nil
}
