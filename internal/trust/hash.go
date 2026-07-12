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
	p := policy{cfg.Schema, id.RepositoryID, id.RelativePath, cfg.Provider, cfg.Source,
		append([]string(nil), cfg.Environment...), append([]string(nil), cfg.Unset...),
		append([]string(nil), cfg.AllowDangerous...), cfg.CacheTTL.String(), cfg.ProviderConfig, manifest, providerSHA256}
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
