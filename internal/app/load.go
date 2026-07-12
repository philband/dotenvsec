package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/philband/dotenvsec/internal/agent"
	"github.com/philband/dotenvsec/internal/config"
	"github.com/philband/dotenvsec/internal/environment"
	localprovider "github.com/philband/dotenvsec/internal/provider"
	"github.com/philband/dotenvsec/internal/recipients"
	"github.com/philband/dotenvsec/internal/scope"
	"github.com/philband/dotenvsec/internal/trust"
	protocol "github.com/philband/dotenvsec/pkg/provider"
)

type Loaded struct {
	Identity    scope.Identity
	Config      config.Scope
	Manifest    config.RecipientManifest
	Environment map[string]string
	Unset       []string
	TrustHash   string
	ScopeKey    string
}

type Prepared struct {
	Identity  scope.Identity
	Config    config.Scope
	Manifest  config.RecipientManifest
	Settings  config.Settings
	Provider  config.ProviderEntry
	Source    string
	TrustHash string
	ScopeKey  string
	CacheKey  string
	CacheTTL  time.Duration
}

func Prepare(path string, requireApproval bool) (Prepared, error) {
	id, err := scope.Resolve(path)
	if err != nil {
		return Prepared{}, err
	}
	cfg, err := config.LoadScope(id.ConfigPath)
	if err != nil {
		return Prepared{}, fmt.Errorf("scope config: %w", err)
	}
	source, err := scope.ResolveSource(id, cfg.Source)
	if err != nil {
		return Prepared{}, fmt.Errorf("source: %w", err)
	}
	manifestPath := filepath.Join(id.Directory, ".dotenv-sec", "recipients.yaml")
	manifest, err := config.LoadRecipients(manifestPath)
	if err != nil {
		return Prepared{}, fmt.Errorf("recipient manifest: %w", err)
	}
	sopsPath := filepath.Join(id.Directory, ".sops.yaml")
	for _, tracked := range []string{id.ConfigPath, source, manifestPath, sopsPath} {
		if err := requireTracked(id.WorktreeRoot, tracked); err != nil {
			return Prepared{}, err
		}
		if err := requireSafeFile(tracked); err != nil {
			return Prepared{}, err
		}
	}
	sopsRules, err := os.ReadFile(sopsPath)
	if err != nil {
		return Prepared{}, err
	}
	if err := recipients.MatchesSOPS(sopsRules, manifest, cfg.Source); err != nil {
		return Prepared{}, err
	}
	settings, err := config.LoadSettings()
	if err != nil {
		return Prepared{}, err
	}
	entry, ok := settings.Providers[cfg.Provider]
	if !ok {
		return Prepared{}, fmt.Errorf("provider %q is not registered locally", cfg.Provider)
	}
	if err := localprovider.Verify(entry); err != nil {
		return Prepared{}, err
	}
	hash, err := trust.Hash(id, cfg, manifest, entry.SHA256)
	if err != nil {
		return Prepared{}, err
	}
	key := id.RepositoryID + ":" + id.RelativePath
	if requireApproval {
		approval, ok := settings.Approvals[key]
		if !ok || approval.Hash != hash {
			return Prepared{}, errors.New("scope is not locally approved; run dotenvsec allow")
		}
	}
	if err := environment.ValidatePolicy(cfg.Environment, cfg.AllowDangerous, settings.DangerousApprovals[key]); err != nil {
		return Prepared{}, err
	}
	sourceHash, err := localprovider.FileSHA256(source)
	if err != nil {
		return Prepared{}, err
	}
	identityHash := sha256.Sum256([]byte(strings.Join(settings.IdentityPaths, "\x00")))
	cacheKey := hash + ":" + sourceHash + ":" + entry.SHA256 + ":" + hex.EncodeToString(identityHash[:])
	return Prepared{Identity: id, Config: cfg, Manifest: manifest, Settings: settings, Provider: entry, Source: source, TrustHash: hash, ScopeKey: key, CacheKey: cacheKey, CacheTTL: effectiveTTL(cfg.CacheTTL.Duration, settings.MaximumCacheTTL.Duration)}, nil
}

func Load(ctx context.Context, path string) (Loaded, error) {
	prepared, err := Prepare(path, true)
	if err != nil {
		return Loaded{}, err
	}
	if prepared.CacheTTL > 0 {
		values, unset, found, cacheErr := agent.Client("get", prepared.CacheKey, nil, nil, 0)
		cached := protocol.Response{Version: protocol.ProtocolVersion, Environment: values, Unset: unset}
		if cacheErr == nil && found && localprovider.ValidateResponse(cached, prepared.Config.Environment, prepared.Config.Unset) == nil {
			return Loaded{prepared.Identity, prepared.Config, prepared.Manifest, values, unset, prepared.TrustHash, prepared.ScopeKey}, nil
		}
	}
	providerConfig := make(map[string]string, len(prepared.Config.ProviderConfig)+1)
	for key, value := range prepared.Config.ProviderConfig {
		providerConfig[key] = value
	}
	if len(prepared.Settings.IdentityPaths) > 0 {
		providerConfig["identity_paths"] = strings.Join(prepared.Settings.IdentityPaths, ",")
	}
	req := protocol.Request{Version: protocol.ProtocolVersion, Scope: protocol.Scope{RepositoryID: prepared.Identity.RepositoryID, RelativePath: prepared.Identity.RelativePath, WorktreeRoot: prepared.Identity.WorktreeRoot}, Source: prepared.Source, ExpectedNames: prepared.Config.Environment, Unset: prepared.Config.Unset, Config: providerConfig}
	response, err := localprovider.Run(ctx, prepared.Provider, req)
	if err != nil {
		return Loaded{}, err
	}
	if err := localprovider.ValidateResponse(response, prepared.Config.Environment, prepared.Config.Unset); err != nil {
		return Loaded{}, err
	}
	if prepared.CacheTTL > 0 {
		_, _, _, _ = agent.Client("put", prepared.CacheKey, response.Environment, response.Unset, prepared.CacheTTL)
	}
	return Loaded{prepared.Identity, prepared.Config, prepared.Manifest, response.Environment, response.Unset, prepared.TrustHash, prepared.ScopeKey}, nil
}

func Marker(prepared Prepared) string {
	return prepared.ScopeKey + ":" + prepared.TrustHash + ":" + prepared.CacheKey
}

func effectiveTTL(repository, maximum time.Duration) time.Duration {
	if repository <= 0 || maximum <= 0 {
		return 0
	}
	if repository > maximum {
		return maximum
	}
	return repository
}

func Environment(base []string, loaded Loaded) []string {
	values := map[string]string{}
	for _, item := range base {
		if idx := strings.IndexByte(item, '='); idx > 0 {
			values[item[:idx]] = item[idx+1:]
		}
	}
	for _, name := range loaded.Unset {
		delete(values, name)
	}
	for name, value := range loaded.Environment {
		values[name] = value
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+values[key])
	}
	return out
}

func requireTracked(root, path string) error {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return err
	}
	cmd := exec.Command("git", "-C", root, "ls-files", "--error-unmatch", "--", filepath.ToSlash(rel))
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("required file is not tracked by Git: %s", rel)
	}
	return nil
}

func requireSafeFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("unsafe non-regular file: %s", path)
	}
	if info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("file is group/world writable: %s", path)
	}
	return nil
}
