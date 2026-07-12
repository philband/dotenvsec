#!/bin/sh
set -eu
failed=0
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  list_files() { git ls-files --cached --others --exclude-standard "$1"; }
else
  list_files() { find . -type f -name "$1" -not -path './.git/*' -not -path './dist/*' -not -path './bin/*' | sed 's#^./##'; }
fi
for pattern in '*.tfstate' '*.tfstate.*' '*.tfplan' '*.dec.yaml' '*.plaintext' '.env.yaml'; do
  matches=$(list_files "$pattern" || true)
  if [ -n "$matches" ]; then printf 'forbidden tracked plaintext/state artifact:\n%s\n' "$matches" >&2; failed=1; fi
done
for file in $(list_files '*.sops.yaml' || true); do
  case "$file" in .sops.yaml|*/.sops.yaml) continue;; esac
  if ! grep -q '^[[:space:]]*sops:' "$file"; then echo "encrypted YAML lacks SOPS metadata: $file" >&2; failed=1; fi
done
exit "$failed"
