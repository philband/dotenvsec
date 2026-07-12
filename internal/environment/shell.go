package environment

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
)

func Transition(shell, marker string, values map[string]string, unset []string) (string, error) {
	if shell != "bash" && shell != "zsh" {
		return "", fmt.Errorf("unsupported shell %q", shell)
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	var out strings.Builder
	out.WriteString("_dotenv_sec_clear\n")
	for _, name := range unset {
		fmt.Fprintf(&out, "_dotenv_sec_unset %s\n", singleQuote(name))
	}
	for _, name := range names {
		encoded := base64.StdEncoding.EncodeToString([]byte(values[name]))
		fmt.Fprintf(&out, "_dotenv_sec_set %s %s\n", singleQuote(name), singleQuote(encoded))
	}
	fmt.Fprintf(&out, "export DOTENV_SEC_SCOPE=%s\n", singleQuote(marker))
	return out.String(), nil
}

func ClearScript() string { return "_dotenv_sec_clear\nunset DOTENV_SEC_SCOPE\n" }

func Hook(shell, executable string) (string, error) {
	exe := singleQuote(executable)
	switch shell {
	case "zsh":
		return zshHook(exe), nil
	case "bash":
		return bashHook(exe), nil
	default:
		return "", fmt.Errorf("unsupported shell %q", shell)
	}
}

func singleQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }

func commonHook() string {
	return `
_dotenv_sec_clear() {
  local _ds_name
  for _ds_name in "${_DOTENV_SEC_MANAGED[@]}"; do
    if [[ ${_DOTENV_SEC_PRESENT[$_ds_name]:-0} == 1 ]]; then
      export "$_ds_name=${_DOTENV_SEC_AMBIENT[$_ds_name]}"
    else
      unset "$_ds_name"
    fi
  done
  _DOTENV_SEC_MANAGED=()
  _DOTENV_SEC_AMBIENT=()
  _DOTENV_SEC_PRESENT=()
}
_dotenv_sec_remember() {
  local _ds_name=$1
  if [[ -z ${_DOTENV_SEC_PRESENT[$_ds_name]+x} ]]; then
    if [[ -n ${!_ds_name+x} ]]; then _DOTENV_SEC_PRESENT[$_ds_name]=1; _DOTENV_SEC_AMBIENT[$_ds_name]=${!_ds_name}; else _DOTENV_SEC_PRESENT[$_ds_name]=0; fi
    _DOTENV_SEC_MANAGED+=("$_ds_name")
  fi
}
_dotenv_sec_set() {
  local _ds_name=$1 _ds_value
  _dotenv_sec_remember "$_ds_name"
  if ! _ds_value=$(printf '%s' "$2" | base64 --decode 2>/dev/null); then _dotenv_sec_clear; return 1; fi
  export "$_ds_name=$_ds_value"
}
_dotenv_sec_unset() { _dotenv_sec_remember "$1"; unset "$1"; }
`
}

func bashHook(exe string) string {
	return `declare -gA _DOTENV_SEC_AMBIENT=() _DOTENV_SEC_PRESENT=()
declare -ga _DOTENV_SEC_MANAGED=()
` + commonHook() + `
_dotenv_sec_refresh() {
  [[ ${_DOTENV_SEC_BUSY:-0} == 1 ]] && return
  _DOTENV_SEC_BUSY=1
  local _ds_script
	_ds_script=$(` + exe + ` activate --shell bash --current "${DOTENV_SEC_SCOPE:-}" -- "$PWD")
  eval "$_ds_script"
  _DOTENV_SEC_BUSY=0
}
case ";${PROMPT_COMMAND:-};" in *";_dotenv_sec_refresh;"*) ;; *) PROMPT_COMMAND="_dotenv_sec_refresh${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;; esac
_dotenv_sec_refresh
`
}

func zshHook(exe string) string {
	return `typeset -gA _DOTENV_SEC_AMBIENT _DOTENV_SEC_PRESENT
typeset -ga _DOTENV_SEC_MANAGED
` + strings.NewReplacer("${!_ds_name+x}", "${(P)+_ds_name}", "${!_ds_name}", "${(P)_ds_name}").Replace(commonHook()) + `
_dotenv_sec_refresh() {
  [[ ${_DOTENV_SEC_BUSY:-0} == 1 ]] && return
  _DOTENV_SEC_BUSY=1
  local _ds_script
	_ds_script=$(` + exe + ` activate --shell zsh --current "${DOTENV_SEC_SCOPE:-}" -- "$PWD")
  eval "$_ds_script"
  _DOTENV_SEC_BUSY=0
}
autoload -Uz add-zsh-hook
add-zsh-hook chpwd _dotenv_sec_refresh
add-zsh-hook precmd _dotenv_sec_refresh
_dotenv_sec_refresh
`
}
