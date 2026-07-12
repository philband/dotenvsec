package recipients

import (
	"github.com/philband/dotenvsec/internal/config"
	"strings"
	"testing"
)

func TestGenerateAndValidateSOPS(t *testing.T) {
	manifest := config.RecipientManifest{Schema: 1, Recipients: []config.Recipient{{ID: "b", Status: "active", Recipient: "age-b"}, {ID: "a", Status: "active", Recipient: "age-a"}, {ID: "old", Status: "revoked", Recipient: "age-old"}}}
	data, err := GenerateSOPS(manifest, ".env.sops.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "age-a,age-b") || strings.Contains(text, "age-old") {
		t.Fatal(text)
	}
	if err := MatchesSOPS(data, manifest, ".env.sops.yaml"); err != nil {
		t.Fatal(err)
	}
	if err := MatchesSOPS([]byte("creation_rules: []\n"), manifest, ".env.sops.yaml"); err == nil {
		t.Fatal("drift accepted")
	}
}
