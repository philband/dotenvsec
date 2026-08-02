package config

import (
	"os"
	"testing"
)

// TestMain redirects HOME for the whole package. Commands in this package write
// to local user settings, and a single test that forgot to isolate HOME once
// wrote temporary-directory paths into a developer's real registry, breaking
// every dotenvsec invocation on that machine. Isolating per test relies on each
// test remembering; isolating here cannot be forgotten.
func TestMain(m *testing.M) {
	os.Exit(runIsolated(m))
}

func runIsolated(m *testing.M) int {
	home, err := os.MkdirTemp("", "dotenvsec-config-test-home-*")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(home) }()
	for key, value := range map[string]string{"HOME": home, "XDG_CONFIG_HOME": home + "/.config"} {
		if err := os.Setenv(key, value); err != nil {
			panic(err)
		}
	}
	return m.Run()
}
