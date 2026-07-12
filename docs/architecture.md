# Architecture

1. `internal/scope` asks Git for the active worktree and common Git directory, then walks canonical ancestors to find the nearest `.dotenv-sec.yaml` without crossing the worktree root.
2. `internal/config` strictly decodes scope, recipient, user-settings, and encrypted environment YAML with bounded input and semantic validation.
3. `internal/trust` hashes canonical policy inputs while intentionally excluding ciphertext values.
4. `internal/provider` resolves a symbolic provider from the local registry, verifies the executable on every launch, and exchanges one bounded JSON request/response over stdio.
5. The bundled SOPS provider invokes pinned `sops`, keeps stderr/TTY available for hardware interaction, validates plaintext in memory, and returns only declared outputs.
6. `internal/environment` validates dangerous names and generates atomic, shell-escaped transitions.
7. `internal/agent` optionally caches complete validated maps in a private UID-authenticated Unix-socket process with absolute expiry.

Cryptographic formats and primitives are delegated to maintained SOPS/age implementations. Scopes and providers do not chain or merge in v1.
