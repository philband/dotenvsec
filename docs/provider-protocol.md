# Provider protocol v1

Providers are one-shot executables. The parent writes exactly one JSON request to stdin and reads exactly one JSON response from stdout, each bounded to 1 MiB. Stdout is protocol-only; diagnostics and hardware prompts use stderr/controlling TTY.

Requests contain `version`, canonical non-secret scope metadata, provider configuration, expected variable names, explicit unsets, and source path. Responses contain `version` and either a complete `environment` map plus `unset`, or a structured redacted error (`code`, `message`). Values may never appear in errors.

The local registry maps a symbolic provider ID to an absolute executable and SHA-256 checksum. Repository configuration cannot provide argv, executable paths, shell fragments, or inherited environment. Providers run without a shell, from the worktree root, with a minimal sanitized environment and a bounded timeout.
