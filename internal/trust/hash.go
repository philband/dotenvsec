package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/philband/dotenvsec/internal/config"
	"github.com/philband/dotenvsec/internal/scope"
)

type policy struct {
	Version        int                      `json:"version"`
	Mode           string                   `json:"mode,omitempty"`
	RepositoryID   string                   `json:"repository_id"`
	RelativeScope  string                   `json:"relative_scope"`
	Provider       string                   `json:"provider"`
	Source         string                   `json:"source"`
	Environment    []string                 `json:"environment"`
	Unset          []string                 `json:"unset"`
	AllowDangerous []string                 `json:"allow_dangerous"`
	CacheTTL       string                   `json:"cache_ttl"`
	ProviderConfig map[string]string        `json:"provider_config"`
	Manifest       config.RecipientManifest `json:"manifest"`
	ProviderSHA256 string                   `json:"provider_sha256"`
}

func Hash(id scope.Identity, cfg config.Scope, manifest config.RecipientManifest, providerSHA256 string) (string, error) {
	// Hash the serialized mode, not EffectiveMode. Legacy repository scopes omit
	// mode, and omitempty preserves their pre-mode approval hash exactly.
	p := policy{
		Version:        cfg.Schema,
		Mode:           cfg.Mode,
		RepositoryID:   id.RepositoryID,
		RelativeScope:  id.RelativePath,
		Provider:       cfg.Provider,
		Source:         cfg.Source,
		Environment:    append([]string(nil), cfg.Environment...),
		Unset:          append([]string(nil), cfg.Unset...),
		AllowDangerous: append([]string(nil), cfg.AllowDangerous...),
		CacheTTL:       cfg.CacheTTL.String(),
		ProviderConfig: cfg.ProviderConfig,
		Manifest:       manifest,
		ProviderSHA256: providerSHA256,
	}
	sort.Strings(p.Environment)
	sort.Strings(p.Unset)
	sort.Strings(p.AllowDangerous)
	sort.Slice(p.Manifest.Recipients, func(i, j int) bool { return p.Manifest.Recipients[i].ID < p.Manifest.Recipients[j].ID })
	encoded, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("encode trust policy: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
