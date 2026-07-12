package app

import (
	"testing"
	"time"

	"github.com/philband/dotenvsec/internal/config"
)

func TestEnvironmentOverlay(t *testing.T) {
	loaded := Loaded{Environment: map[string]string{"A": "new", "C": "three"}, Unset: []string{"B"}}
	got := Environment([]string{"A=old", "B=two", "PATH=/bin"}, loaded)
	want := []string{"A=new", "C=three", "PATH=/bin"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestEffectiveTTLDefaultsOffAndBounds(t *testing.T) {
	if got := effectiveTTL(time.Minute, 0); got != 0 {
		t.Fatalf("default user maximum must disable cache: %v", got)
	}
	if got := effectiveTTL(time.Hour, 5*time.Minute); got != 5*time.Minute {
		t.Fatalf("TTL not bounded: %v", got)
	}
	if got := effectiveTTL(time.Minute, 5*time.Minute); got != time.Minute {
		t.Fatalf("TTL unexpectedly changed: %v", got)
	}
}

func TestMarkerIncludesInvalidationKey(t *testing.T) {
	prepared := Prepared{ScopeKey: "repo:path", TrustHash: "trust", CacheKey: "cipher:provider:identity", Config: config.Scope{}}
	got := Marker(prepared)
	if got != "repo:path:trust:cipher:provider:identity" {
		t.Fatal(got)
	}
}
