package scope

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/philband/dotenvsec/internal/config"
)

const gitLocalRegistrySchema = 1

type GitContext struct {
	WorktreeRoot   string
	CommonGitDir   string
	GitDir         string
	LinkedWorktree bool
}

type gitLocalRegistry struct {
	Schema        int      `yaml:"schema"`
	OwnerWorktree string   `yaml:"owner_worktree"`
	Scopes        []string `yaml:"scopes"`
}

type inheritedScope struct {
	virtualDirectory string
	identity         Identity
}

func InspectGit(path string) (GitContext, error) {
	physical, err := canonicalDirectory(path)
	if err != nil {
		return GitContext{}, err
	}
	root, err := git(physical, "rev-parse", "--show-toplevel")
	if err != nil {
		return GitContext{}, errors.New("not inside a Git worktree")
	}
	common, err := git(physical, "rev-parse", "--git-common-dir")
	if err != nil {
		return GitContext{}, fmt.Errorf("resolve Git common directory: %w", err)
	}
	gitDirectory, err := git(physical, "rev-parse", "--git-dir")
	if err != nil {
		return GitContext{}, fmt.Errorf("resolve Git directory: %w", err)
	}
	root, err = canonicalPathFrom(physical, root)
	if err != nil {
		return GitContext{}, err
	}
	common, err = canonicalPathFrom(physical, common)
	if err != nil {
		return GitContext{}, err
	}
	gitDirectory, err = canonicalPathFrom(physical, gitDirectory)
	if err != nil {
		return GitContext{}, err
	}
	return GitContext{WorktreeRoot: root, CommonGitDir: common, GitDir: gitDirectory, LinkedWorktree: gitDirectory != common}, nil
}

func RegisterGitLocal(directory string) error {
	directory, err := canonicalDirectory(directory)
	if err != nil {
		return err
	}
	context, err := InspectGit(directory)
	if err != nil {
		return err
	}
	if context.LinkedWorktree {
		return errors.New("git-local scopes can only be initialized or modified from the main worktree")
	}
	cfg, err := config.LoadScope(filepath.Join(directory, ConfigName))
	if err != nil {
		return fmt.Errorf("git-local scope config: %w", err)
	}
	if cfg.EffectiveMode() != config.ScopeModeGitLocal {
		return errors.New("only a mode: git-local scope can be registered")
	}
	relative, err := filepath.Rel(context.WorktreeRoot, directory)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("git-local scope is outside the main worktree")
	}
	if relative == "." {
		relative = ""
	}
	relative = filepath.ToSlash(relative)
	registry, err := loadGitLocalRegistry(context.CommonGitDir)
	if errors.Is(err, os.ErrNotExist) {
		registry = gitLocalRegistry{Schema: gitLocalRegistrySchema, OwnerWorktree: context.WorktreeRoot}
	} else if err != nil {
		return err
	}
	if registry.OwnerWorktree != context.WorktreeRoot {
		return errors.New("git-local registry belongs to a different main worktree")
	}
	for _, existing := range registry.Scopes {
		if existing == relative {
			return nil
		}
	}
	registry.Scopes = append(registry.Scopes, relative)
	sort.Strings(registry.Scopes)
	return saveGitLocalRegistry(context.CommonGitDir, registry)
}

func EnsureLocalIgnored(directory string) error {
	directory, err := canonicalDirectory(directory)
	if err != nil {
		return err
	}
	context, err := InspectGit(directory)
	if err != nil {
		return err
	}
	if context.LinkedWorktree {
		cfg, cfgErr := config.LoadScope(filepath.Join(directory, ConfigName))
		if cfgErr == nil && cfg.EffectiveMode() == config.ScopeModeGitLocal {
			return errors.New("git-local scopes can only be initialized or modified from the main worktree")
		}
	}
	relative, err := filepath.Rel(context.WorktreeRoot, directory)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("local scope is outside its active worktree")
	}
	if relative == "." {
		relative = ""
	}
	prefix := "/"
	if relative != "" {
		prefix += filepath.ToSlash(relative) + "/"
	}
	patterns := []string{
		prefix + ConfigName,
		prefix + ".dotenv-sec/",
		prefix + ".sops.yaml",
		prefix + ".env.sops.yaml",
	}
	excludePath := filepath.Join(context.CommonGitDir, "info", "exclude")
	data, err := os.ReadFile(excludePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	existing := string(data)
	var additions []string
	for _, pattern := range patterns {
		if !lineExists(existing, pattern) {
			additions = append(additions, pattern)
		}
	}
	if len(additions) == 0 {
		return nil
	}
	if len(existing) > 0 && !strings.HasSuffix(existing, "\n") {
		existing += "\n"
	}
	existing += "# dotenvsec local scope: " + displayRelative(relative) + "\n" + strings.Join(additions, "\n") + "\n"
	if err := os.MkdirAll(filepath.Dir(excludePath), 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(excludePath), ".exclude-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer func() { _ = os.Remove(name) }()
	if err := temporary.Chmod(0644); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.WriteString(existing); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, excludePath)
}

func UnregisterGitLocal(directory string) error {
	directory, err := canonicalDirectory(directory)
	if err != nil {
		return err
	}
	context, err := InspectGit(directory)
	if err != nil {
		return err
	}
	if context.LinkedWorktree {
		return errors.New("git-local scopes can only be unregistered from the main worktree")
	}
	relative, err := filepath.Rel(context.WorktreeRoot, directory)
	if err != nil {
		return err
	}
	if relative == "." {
		relative = ""
	}
	relative = filepath.ToSlash(relative)
	registry, err := loadGitLocalRegistry(context.CommonGitDir)
	if err != nil {
		return err
	}
	if registry.OwnerWorktree != context.WorktreeRoot {
		return errors.New("git-local registry belongs to a different main worktree; repair its owner first")
	}
	filtered := registry.Scopes[:0]
	for _, existing := range registry.Scopes {
		if existing != relative {
			filtered = append(filtered, existing)
		}
	}
	registry.Scopes = filtered
	return saveGitLocalRegistry(context.CommonGitDir, registry)
}

func RepairGitLocalOwner(directory string) error {
	context, err := InspectGit(directory)
	if err != nil {
		return err
	}
	if context.LinkedWorktree {
		return errors.New("git-local registry ownership can only be repaired from the main worktree")
	}
	registry, err := loadGitLocalRegistry(context.CommonGitDir)
	if err != nil {
		return err
	}
	for _, relative := range registry.Scopes {
		cfg, err := config.LoadScope(filepath.Join(context.WorktreeRoot, filepath.FromSlash(relative), ConfigName))
		if err != nil {
			return fmt.Errorf("registered scope %q is unavailable in the current main worktree: %w", displayRelative(relative), err)
		}
		if cfg.EffectiveMode() != config.ScopeModeGitLocal {
			return fmt.Errorf("registered scope %q is not mode: git-local", displayRelative(relative))
		}
	}
	registry.OwnerWorktree = context.WorktreeRoot
	return saveGitLocalRegistry(context.CommonGitDir, registry)
}

func GitLocalScopeRegistered(common, relative, owner string) (bool, error) {
	registry, err := loadGitLocalRegistry(common)
	if err != nil {
		return false, err
	}
	if registry.OwnerWorktree != owner {
		return false, errors.New("git-local registry owner does not match the main worktree")
	}
	for _, candidate := range registry.Scopes {
		if candidate == relative {
			return true, nil
		}
	}
	return false, nil
}

func resolveInherited(physical string, context GitContext) (inheritedScope, error) {
	if !context.LinkedWorktree {
		return inheritedScope{}, os.ErrNotExist
	}
	registry, err := loadGitLocalRegistry(context.CommonGitDir)
	if err != nil {
		return inheritedScope{}, err
	}
	ownerContext, err := InspectGit(registry.OwnerWorktree)
	if err != nil || ownerContext.LinkedWorktree || ownerContext.CommonGitDir != context.CommonGitDir {
		return inheritedScope{}, errors.New("git-local registry owner is not the active main worktree")
	}
	currentRelative, err := filepath.Rel(context.WorktreeRoot, physical)
	if err != nil {
		return inheritedScope{}, err
	}
	currentRelative = filepath.ToSlash(currentRelative)
	selected := ""
	found := false
	for _, candidate := range registry.Scopes {
		if relativeContains(candidate, currentRelative) && (!found || pathDepth(candidate) > pathDepth(selected)) {
			selected, found = candidate, true
		}
	}
	if !found {
		return inheritedScope{}, os.ErrNotExist
	}
	ownerDirectory := filepath.Join(registry.OwnerWorktree, filepath.FromSlash(selected))
	configPath := filepath.Join(ownerDirectory, ConfigName)
	cfg, err := config.LoadScope(configPath)
	if err != nil {
		return inheritedScope{}, fmt.Errorf("inherited scope config: %w", err)
	}
	if cfg.EffectiveMode() != config.ScopeModeGitLocal {
		return inheritedScope{}, errors.New("registered inherited scope is not git-local")
	}
	virtualDirectory := filepath.Join(context.WorktreeRoot, filepath.FromSlash(selected))
	identity := Identity{RepositoryID: repositoryID(context.CommonGitDir), RelativePath: selected, Mode: config.ScopeModeGitLocal, WorktreeRoot: context.WorktreeRoot, StorageRoot: registry.OwnerWorktree, CommonGitDir: context.CommonGitDir, Directory: ownerDirectory, ConfigPath: configPath, ReadOnly: true}
	return inheritedScope{virtualDirectory: virtualDirectory, identity: identity}, nil
}

func loadGitLocalRegistry(common string) (gitLocalRegistry, error) {
	if err := validateRegistryDirectory(common, false); err != nil {
		return gitLocalRegistry{}, err
	}
	path := gitLocalRegistryPath(common)
	info, err := os.Lstat(path)
	if err != nil {
		return gitLocalRegistry{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return gitLocalRegistry{}, errors.New("git-local registry must be a private regular non-symlink file")
	}
	var registry gitLocalRegistry
	if err := config.DecodeFile(path, &registry); err != nil {
		return registry, err
	}
	if registry.Schema != gitLocalRegistrySchema {
		return registry, fmt.Errorf("unsupported git-local registry schema %d", registry.Schema)
	}
	if !filepath.IsAbs(registry.OwnerWorktree) || filepath.Clean(registry.OwnerWorktree) != registry.OwnerWorktree || strings.IndexFunc(registry.OwnerWorktree, func(character rune) bool { return character < ' ' || character == 0x7f }) >= 0 {
		return registry, errors.New("git-local registry owner must be a canonical absolute path")
	}
	seen := map[string]bool{}
	for _, candidate := range registry.Scopes {
		if err := validateRelativeScope(candidate); err != nil {
			return registry, err
		}
		if seen[candidate] {
			return registry, errors.New("git-local registry contains a duplicate scope")
		}
		seen[candidate] = true
	}
	return registry, nil
}

func saveGitLocalRegistry(common string, registry gitLocalRegistry) error {
	directory := filepath.Join(common, "dotenvsec")
	if err := validateRegistryDirectory(common, true); err != nil {
		return err
	}
	data, err := config.Marshal(registry)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".registry-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer func() { _ = os.Remove(name) }()
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, gitLocalRegistryPath(common))
}

func validateRegistryDirectory(common string, create bool) error {
	directory := filepath.Join(common, "dotenvsec")
	if create {
		if err := os.Mkdir(directory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return errors.New("git-local registry directory must be a private non-symlink directory")
	}
	return nil
}

func gitLocalRegistryPath(common string) string {
	return filepath.Join(common, "dotenvsec", "registry.yaml")
}

func canonicalPathFrom(base, path string) (string, error) {
	if !filepath.IsAbs(path) {
		path = filepath.Join(base, path)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	evaluated, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	return filepath.Clean(evaluated), nil
}

func validateRelativeScope(path string) error {
	if path == "" {
		return nil
	}
	if filepath.IsAbs(path) || filepath.ToSlash(filepath.Clean(filepath.FromSlash(path))) != path || path == ".." || strings.HasPrefix(path, "../") {
		return fmt.Errorf("invalid git-local relative scope %q", path)
	}
	return nil
}

func relativeContains(parent, child string) bool {
	if parent == "" {
		return true
	}
	return child == parent || strings.HasPrefix(child, parent+"/")
}

func pathDepth(path string) int {
	if path == "" {
		return 0
	}
	return len(strings.Split(path, "/"))
}

func lineExists(content, expected string) bool {
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == expected {
			return true
		}
	}
	return false
}

func displayRelative(path string) string {
	if path == "" {
		return "."
	}
	return filepath.ToSlash(path)
}
