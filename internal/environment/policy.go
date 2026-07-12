package environment

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var dangerousExact = map[string]bool{
	"PATH": true, "CDPATH": true, "ENV": true, "BASH_ENV": true, "ZDOTDIR": true,
	"SHELLOPTS": true, "BASHOPTS": true, "PROMPT_COMMAND": true,
	"LD_PRELOAD": true, "LD_LIBRARY_PATH": true, "DYLD_INSERT_LIBRARIES": true,
	"DYLD_LIBRARY_PATH": true, "PYTHONPATH": true, "PYTHONSTARTUP": true,
	"RUBYOPT": true, "PERL5OPT": true, "NODE_OPTIONS": true, "GEM_HOME": true,
	"GIT_EXEC_PATH": true, "GIT_TEMPLATE_DIR": true, "GIT_CONFIG_SYSTEM": true,
	"GIT_CONFIG_GLOBAL": true, "SSH_ASKPASS": true, "GIT_ASKPASS": true,
}

var dangerousPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^BASH_FUNC_`), regexp.MustCompile(`^GIT_CONFIG_(COUNT|KEY_[0-9]+|VALUE_[0-9]+)$`),
	regexp.MustCompile(`^(LD|DYLD)_`), regexp.MustCompile(`^(PYTHON|RUBY|PERL|NODE)_?(PATH|STARTUP|OPT|OPTIONS)$`),
}

func IsDangerous(name string) bool {
	if dangerousExact[name] {
		return true
	}
	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(name) {
			return true
		}
	}
	return false
}

func ValidatePolicy(names, declaredExceptions, locallyApproved []string) error {
	declared := set(declaredExceptions)
	approved := set(locallyApproved)
	var denied []string
	for _, name := range names {
		if IsDangerous(name) && (!declared[name] || !approved[name]) {
			denied = append(denied, name)
		}
	}
	if len(denied) > 0 {
		sort.Strings(denied)
		return fmt.Errorf("dangerous variables require declaration and local approval: %s", strings.Join(denied, ", "))
	}
	return nil
}

func set(values []string) map[string]bool {
	out := map[string]bool{}
	for _, value := range values {
		out[value] = true
	}
	return out
}
