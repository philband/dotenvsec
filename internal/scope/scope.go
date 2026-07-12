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
)

const ConfigName = ".dotenv-sec.yaml"

type Identity struct {
	RepositoryID string
	RelativePath string
	WorktreeRoot string
	CommonGitDir string
	Directory    string
	ConfigPath   string
}

func Resolve(start string) (Identity, error) {
	physical, err := canonicalDirectory(start)
	if err != nil {
		return Identity{}, err
	}
	root, err := git(physical, "rev-parse", "--show-toplevel")
	if err != nil {
		return Identity{}, errors.New("not inside a Git worktree")
	}
	common, err := git(physical, "rev-parse", "--git-common-dir")
	if err != nil {
		return Identity{}, fmt.Errorf("resolve Git common directory: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return Identity{}, err
	}
	root = filepath.Clean(root)
	if !contained(root, physical) {
		return Identity{}, errors.New("start path is outside active worktree")
	}
	if !filepath.IsAbs(common) {
		common = filepath.Join(physical, common)
	}
	common, err = filepath.Abs(common)
	if err != nil {
		return Identity{}, err
	}
	common, err = filepath.EvalSymlinks(common)
	if err != nil {
		return Identity{}, err
	}
	repoID := repositoryID(common)
	for dir := physical; contained(root, dir); dir = filepath.Dir(dir) {
		candidate := filepath.Join(dir, ConfigName)
		if info, statErr := os.Lstat(candidate); statErr == nil {
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return Identity{}, errors.New("scope config must be a regular non-symlink file")
			}
			rel, _ := filepath.Rel(root, dir)
			if rel == "." {
				rel = ""
			}
			return Identity{repoID, filepath.ToSlash(rel), root, common, dir, candidate}, nil
		} else if !os.IsNotExist(statErr) {
			return Identity{}, statErr
		}
		if dir == root {
			break
		}
	}
	return Identity{RepositoryID: repoID, WorktreeRoot: root, CommonGitDir: common}, os.ErrNotExist
}

func ResolveSource(id Identity, relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) {
		return "", errors.New("source must be a non-empty relative path")
	}
	joined := filepath.Join(id.Directory, filepath.Clean(relative))
	parent, err := filepath.EvalSymlinks(filepath.Dir(joined))
	if err != nil {
		return "", err
	}
	resolved := filepath.Join(parent, filepath.Base(joined))
	if target, evalErr := filepath.EvalSymlinks(joined); evalErr == nil {
		resolved = target
	}
	if !contained(id.WorktreeRoot, resolved) || !contained(id.Directory, resolved) {
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
	sum := sha256.Sum256([]byte(filepath.Clean(common)))
	return hex.EncodeToString(sum[:])
}

func contained(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
