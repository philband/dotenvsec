# Provider protocol v2

Providers are one-shot executables. The parent writes exactly one JSON request to stdin and reads exactly one JSON response from stdout, each bounded to 1 MiB. Stdout is protocol-only; diagnostics and hardware prompts use stderr/controlling TTY.

Requests contain `version`, canonical non-secret scope metadata, provider configuration, expected variable names, explicit unsets, and source path. Responses contain `version` and either a complete `environment` map plus `unset`, or a structured redacted error (`code`, `message`). Values may never appear in errors.

The local registry maps a symbolic provider ID to an absolute executable and SHA-256 checksum. Repository configuration cannot provide argv, executable paths, shell fragments, or inherited environment. Providers run without a shell, from the worktree root, with a minimal sanitized environment and a bounded timeout.

## Tools and identities

`config` carries repository policy only. Any external executable a provider
launches is supplied separately in `tools`, as an absolute path plus its pinned
SHA-256, and the consolidated age identity file is supplied in `identity_path`.
Both are resolved by the parent from the local registry and overwritten on the
request immediately before dispatch, so a value placed in `config` by a
repository can never reach them.

```json
{
  "version": 2,
  "config": {"sops_min_version": "3.10.0"},
  "tools": {"sops": {"executable": "/opt/homebrew/Cellar/sops/3.13.3/bin/sops", "sha256": "..."}},
  "identity_path": "/Users/example/Library/Application Support/dotenvsec/yubikey-identities.txt"
}
```

Providers must verify a tool's checksum before launching it and must fail closed
when a required tool is absent from `tools`. Falling back to a `PATH` lookup is
prohibited: it would run whichever binary happens to be first on the path.

Protocol v1 passed `sops_executable`, `sops_sha256`, `plugin_path`, and
`identity_paths` inside `config`, which came from the tracked scope file. That
contradicted the rule above and is no longer accepted.
