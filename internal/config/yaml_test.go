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

func FuzzParseEnvironment(f *testing.F) {
	f.Add([]byte("environment:\n  A: value\n"))
	f.Add([]byte("environment: {}\n"))
	f.Add([]byte("---\n"))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = ParseEnvironment(data) })
}
