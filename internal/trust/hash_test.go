package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/philband/dotenvsec/internal/config"
	"github.com/philband/dotenvsec/internal/scope"
)

func TestHashCanonicalAndPolicySensitive(t *testing.T) {
	id := scope.Identity{RepositoryID: "repo", RelativePath: "infra"}
	cfg := config.Scope{Schema: 1, Provider: "sops", Source: ".env.sops.yaml", Environment: []string{"B", "A"}, CacheTTL: config.Duration{Duration: time.Minute}}
	manifest := config.RecipientManifest{Schema: 1, Recipients: []config.Recipient{{ID: "b", Owner: "B", Status: "active", Plugin: "age", Recipient: "age-b"}, {ID: "a", Owner: "A", Status: "active", Plugin: "age", Recipient: "age-a"}}}
	first, err := Hash(id, cfg, manifest, "provider")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Environment = []string{"A", "B"}
	manifest.Recipients[0], manifest.Recipients[1] = manifest.Recipients[1], manifest.Recipients[0]
	second, err := Hash(id, cfg, manifest, "provider")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("canonical ordering changed hash")
	}
	cfg.CacheTTL = config.Duration{Duration: 2 * time.Minute}
	third, _ := Hash(id, cfg, manifest, "provider")
	if third == first {
		t.Fatal("cache policy did not invalidate trust")
	}
	fourth, _ := Hash(id, cfg, manifest, "different-provider")
	if fourth == third {
		t.Fatal("provider checksum did not invalidate trust")
	}
	cfg.Mode = config.ScopeModeLocal
	local, _ := Hash(id, cfg, manifest, "different-provider")
	if local == fourth {
		t.Fatal("scope mode did not isolate trust")
	}
}

func TestLegacyRepositoryHashRemainsCompatible(t *testing.T) {
	id := scope.Identity{RepositoryID: "repo", RelativePath: "infra", Mode: config.ScopeModeRepository}
	cfg := config.Scope{Schema: 1, Provider: "sops", Source: ".env.sops.yaml", Environment: []string{"TOKEN"}}
	manifest := config.RecipientManifest{Schema: 1, Recipients: []config.Recipient{{ID: "primary", Owner: "Owner", Status: "active", Plugin: "age", Recipient: "age1test"}}}
	actual, err := Hash(id, cfg, manifest, "provider")
	if err != nil {
		t.Fatal(err)
	}
	legacy := legacyPolicy{
		Version:        cfg.Schema,
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
		ProviderSHA256: "provider",
	}
	sort.Strings(legacy.Environment)
	sort.Strings(legacy.Unset)
	sort.Strings(legacy.AllowDangerous)
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(encoded)
	expected := hex.EncodeToString(sum[:])
	if actual != expected {
		t.Fatalf("legacy approval changed: got %s want %s", actual, expected)
	}
}

type legacyPolicy struct {
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
