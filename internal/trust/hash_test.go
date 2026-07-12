package trust

import (
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
}
