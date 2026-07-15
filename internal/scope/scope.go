package scope

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/philband/dotenvsec/internal/config"
)

const ConfigName = ".dotenv-sec.yaml"

var ErrNotConfigured = fmt.Errorf("scope is not configured: %w", os.ErrNotExist)

type Identity struct {
	RepositoryID string
	RelativePath string
	Mode         string
	WorktreeRoot string
	StorageRoot  string
	CommonGitDir string
	Directory    string
	ConfigPath   string
	ReadOnly     bool
}

func Resolve(start string) (Identity, error) {
	physical, err := canonicalDirectory(start)
	if err != nil {
		return Identity{}, err
	}
	gitContext, gitErr := InspectGit(physical)
	if gitErr != nil {
		identity, localErr := resolveFilesystemLocal(physical)
		if errors.Is(localErr, os.ErrNotExist) {
			return identity, ErrNotConfigured
		}
		return identity, localErr
	}
	if !contained(gitContext.WorktreeRoot, physical) {
		return Identity{}, errors.New("start path is outside active worktree")
	}
	filesystemDirectory, filesystemConfig, filesystemErr := nearestConfig(physical, gitContext.WorktreeRoot)
	if filesystemErr != nil && !errors.Is(filesystemErr, os.ErrNotExist) {
		return Identity{}, filesystemErr
	}
	inherited, inheritedErr := resolveInherited(physical, gitContext)
	if inheritedErr != nil && !errors.Is(inheritedErr, os.ErrNotExist) {
		return Identity{}, inheritedErr
	}
	if filesystemErr == nil && (inheritedErr != nil || scopeDepth(gitContext.WorktreeRoot, filesystemDirectory) >= scopeDepth(gitContext.WorktreeRoot, inherited.virtualDirectory)) {
		return identityForFilesystemScope(filesystemDirectory, filesystemConfig, gitContext)
	}
	if inheritedErr == nil {
		return inherited.identity, nil
	}
	return Identity{RepositoryID: repositoryID(gitContext.CommonGitDir), Mode: config.ScopeModeRepository, WorktreeRoot: gitContext.WorktreeRoot, StorageRoot: gitContext.WorktreeRoot, CommonGitDir: gitContext.CommonGitDir}, ErrNotConfigured
}

func ResolveSource(id Identity, relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) {
		return "", errors.New("source must be a non-empty relative path")
	}
	joined := filepath.Join(id.Directory, filepath.Clean(relative))
	joinedInfo, err := os.Lstat(joined)
	if err != nil {
		return "", err
	}
	if !joinedInfo.Mode().IsRegular() || joinedInfo.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("source must be a regular non-symlink file")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(joined))
	if err != nil {
		return "", err
	}
	resolved := filepath.Join(parent, filepath.Base(joined))
	if !contained(id.StorageRoot, resolved) || !contained(id.Directory, resolved) {
		return "", errors.New("source escapes selected scope/worktree")
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("source must be a regular non-symlink file")
	}
	if info.Size() > 16<<20 {
		return "", errors.New("source exceeds size limit")
	}
	return resolved, nil
}

func resolveFilesystemLocal(physical string) (Identity, error) {
	directory, configPath, err := nearestConfig(physical, volumeRoot(physical))
	if err != nil {
		return Identity{}, err
	}
	cfg, err := config.LoadScope(configPath)
	if err != nil {
		return Identity{}, fmt.Errorf("scope config: %w", err)
	}
	if cfg.EffectiveMode() != config.ScopeModeLocal {
		return Identity{}, errors.New("repository and git-local scopes require a Git worktree")
	}
	return Identity{RepositoryID: localRepositoryID(directory), Mode: config.ScopeModeLocal, WorktreeRoot: directory, StorageRoot: directory, Directory: directory, ConfigPath: configPath}, nil
}

func identityForFilesystemScope(directory, configPath string, gitContext GitContext) (Identity, error) {
	cfg, err := config.LoadScope(configPath)
	if err != nil {
		return Identity{}, fmt.Errorf("scope config: %w", err)
	}
	relative, err := filepath.Rel(gitContext.WorktreeRoot, directory)
	if err != nil {
		return Identity{}, err
	}
	if relative == "." {
		relative = ""
	}
	mode := cfg.EffectiveMode()
	repository := repositoryID(gitContext.CommonGitDir)
	if mode == config.ScopeModeLocal {
		repository = localRepositoryID(directory)
	}
	if mode == config.ScopeModeGitLocal {
		if gitContext.LinkedWorktree {
			return Identity{}, errors.New("git-local scope files may only be stored in the main worktree")
		}
		registered, err := GitLocalScopeRegistered(gitContext.CommonGitDir, filepath.ToSlash(relative), gitContext.WorktreeRoot)
		if err != nil {
			return Identity{}, err
		}
		if !registered {
			return Identity{}, errors.New("git-local scope is missing from the shared registry")
		}
	}
	return Identity{RepositoryID: repository, RelativePath: filepath.ToSlash(relative), Mode: mode, WorktreeRoot: gitContext.WorktreeRoot, StorageRoot: gitContext.WorktreeRoot, CommonGitDir: gitContext.CommonGitDir, Directory: directory, ConfigPath: configPath}, nil
}

func nearestConfig(start, boundary string) (string, string, error) {
	for directory := start; contained(boundary, directory); directory = filepath.Dir(directory) {
		candidate := filepath.Join(directory, ConfigName)
		if info, err := os.Lstat(candidate); err == nil {
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return "", "", errors.New("scope config must be a regular non-symlink file")
			}
			return directory, candidate, nil
		} else if !os.IsNotExist(err) {
			return "", "", err
		}
		if directory == boundary {
			break
		}
	}
	return "", "", os.ErrNotExist
}

func volumeRoot(path string) string {
	volume := filepath.VolumeName(path)
	return volume + string(filepath.Separator)
}

func scopeDepth(root, directory string) int {
	relative, err := filepath.Rel(root, directory)
	if err != nil || relative == "." {
		return 0
	}
	return len(strings.Split(filepath.Clean(relative), string(filepath.Separator)))
}

func canonicalDirectory(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		abs = filepath.Dir(abs)
	}
	return filepath.EvalSymlinks(abs)
}

func git(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(out)), nil
}

func repositoryID(common string) string {
	// Preserve the v0.1 repository identity so existing approvals remain valid.
	sum := sha256.Sum256([]byte(filepath.Clean(common)))
	return hex.EncodeToString(sum[:])
}

func localRepositoryID(directory string) string {
	sum := sha256.Sum256([]byte("local\x00" + filepath.Clean(directory)))
	return hex.EncodeToString(sum[:])
}

func contained(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
