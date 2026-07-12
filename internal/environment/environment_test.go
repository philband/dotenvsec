package environment

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestDangerousPolicyRequiresBothApprovals(t *testing.T) {
	if err := ValidatePolicy([]string{"SAFE"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePolicy([]string{"PATH"}, []string{"PATH"}, nil); err == nil {
		t.Fatal("repository approval alone must fail")
	}
	if err := ValidatePolicy([]string{"PATH"}, nil, []string{"PATH"}); err == nil {
		t.Fatal("local approval alone must fail")
	}
	if err := ValidatePolicy([]string{"PATH"}, []string{"PATH"}, []string{"PATH"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "BASH_ENV", "GIT_CONFIG_COUNT", "NODE_OPTIONS"} {
		if !IsDangerous(name) {
			t.Errorf("%s should be dangerous", name)
		}
	}
}

func TestTransitionIsDeterministicAndEncoded(t *testing.T) {
	secret := "line 1\nquote ' and $HOME"
	script, err := Transition("bash", "marker", map[string]string{"Z": secret, "A": "first"}, []string{"OLD"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(script, secret) {
		t.Fatal("raw value leaked into shell protocol")
	}
	if !strings.Contains(script, base64.StdEncoding.EncodeToString([]byte(secret))) {
		t.Fatal("encoded value absent")
	}
	if strings.Index(script, "_dotenv_sec_set 'A'") > strings.Index(script, "_dotenv_sec_set 'Z'") {
		t.Fatal("output is not deterministic")
	}
	if !strings.HasPrefix(script, "_dotenv_sec_clear\n") {
		t.Fatal("transition must clear first")
	}
}

func TestHooksDoNotSourceRepositoryCode(t *testing.T) {
	for _, shell := range []string{"bash", "zsh"} {
		hook, err := Hook(shell, "/usr/local/bin/dotenvsec")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(hook, "source ") || strings.Contains(hook, ".dotenv-sec.yaml") {
			t.Fatalf("%s hook references repository code", shell)
		}
		if !strings.Contains(hook, "--current") {
			t.Fatalf("%s hook does not reconcile scope marker", shell)
		}
	}
}
