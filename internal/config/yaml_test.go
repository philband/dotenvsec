package config

import (
	"strings"
	"testing"
)

func TestParseEnvironment(t *testing.T) {
	doc, err := ParseEnvironment([]byte("environment:\n  SAFE: 'true'\n  EMPTY: \"\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Environment["SAFE"] != "true" || doc.Environment["EMPTY"] != "" {
		t.Fatalf("unexpected environment: %#v", doc.Environment)
	}
}

func TestParseEnvironmentRejectsUnsafeYAML(t *testing.T) {
	tests := map[string]string{
		"non-string value":   "environment:\n  SAFE: true\n",
		"duplicate":          "environment:\n  SAFE: one\n  SAFE: two\n",
		"extra root":         "environment:\n  SAFE: one\nother: value\n",
		"multiple documents": "environment: {}\n---\nenvironment: {}\n",
		"alias":              "environment:\n  SAFE: &value secret\n  OTHER: *value\n",
		"custom tag":         "environment:\n  SAFE: !secret value\n",
		"invalid name":       "environment:\n  BAD-NAME: value\n",
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseEnvironment([]byte(input)); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestLoadScopeStrictAndExactNames(t *testing.T) {
	var scope Scope
	err := DecodeStrict([]byte("schema: 1\nprovider: sops\nsource: file\nenvironment: [A]\nunknown: true\n"), &scope)
	if err == nil || !strings.Contains(err.Error(), "field unknown") {
		t.Fatalf("expected unknown-field error, got %v", err)
	}
	if err := ValidateExactEnvironment(map[string]string{"A": "x"}, []string{"A"}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateExactEnvironment(map[string]string{"B": "x"}, []string{"A"}); err == nil {
		t.Fatal("expected exact-name mismatch")
	}
}

// The offending names are already cleartext in the scope file and in the
// encrypted document's keys, so reporting them costs nothing and turns an
// opaque failure into a self-service fix.
func TestValidateExactEnvironmentNamesTheMismatch(t *testing.T) {
	err := ValidateExactEnvironment(map[string]string{"A": "1", "EXTRA": "2"}, []string{"A", "GONE"})
	if err == nil {
		t.Fatal("mismatch accepted")
	}
	for _, want := range []string{"undeclared: EXTRA", "missing: GONE"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not report %q", err, want)
		}
	}
	if strings.Contains(err.Error(), `"1"`) || strings.Contains(err.Error(), `"2"`) {
		t.Fatalf("error leaked a value: %v", err)
	}
	if err := ValidateExactEnvironment(map[string]string{"A": "1"}, []string{"A"}); err != nil {
		t.Fatalf("exact match rejected: %v", err)
	}
}

func TestValidateScopeModes(t *testing.T) {
	for _, mode := range []string{"", ScopeModeRepository, ScopeModeLocal, ScopeModeGitLocal} {
		scope := Scope{Schema: ScopeSchemaVersion, Mode: mode, Provider: "sops", Source: ".env.sops.yaml", Environment: []string{"TOKEN"}}
		if err := ValidateScope(scope); err != nil {
			t.Fatalf("mode %q rejected: %v", mode, err)
		}
	}
	scope := Scope{Schema: ScopeSchemaVersion, Mode: "remote", Provider: "sops", Source: ".env.sops.yaml"}
	if err := ValidateScope(scope); err == nil || !strings.Contains(err.Error(), "unsupported scope mode") {
		t.Fatalf("invalid mode error = %v", err)
	}
}

func FuzzParseEnvironment(f *testing.F) {
	f.Add([]byte("environment:\n  A: value\n"))
	f.Add([]byte("environment: {}\n"))
	f.Add([]byte("---\n"))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = ParseEnvironment(data) })
}
