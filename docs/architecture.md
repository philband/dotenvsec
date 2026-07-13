# Architecture

1. `internal/scope` walks canonical ancestors for filesystem scopes. Inside Git it also resolves the active worktree, shared common Git directory, and main-worktree Git-local registry, then selects the nearest scope without crossing the applicable boundary. Outside Git only explicit `mode: local` scopes are accepted.
2. `internal/config` strictly decodes scope, recipient, user-settings, and encrypted environment YAML with bounded input and semantic validation.
3. `internal/trust` hashes canonical policy inputs while intentionally excluding ciphertext values.
4. `internal/provider` resolves a symbolic provider from the local registry, verifies the executable on every launch, and exchanges one bounded JSON request/response over stdio.
5. The bundled SOPS provider invokes pinned `sops`, keeps stderr/TTY available for hardware interaction, validates plaintext in memory, and returns only declared outputs.
6. `internal/environment` validates dangerous names and generates atomic, shell-escaped transitions.
7. `internal/agent` optionally caches complete validated maps in a private UID-authenticated Unix-socket process with absolute expiry.

Cryptographic formats and primitives are delegated to maintained SOPS/age implementations. Scopes and providers do not chain or merge in v1.

Repository identity remains the SHA-256 of the canonical Git common directory,
preserving existing approvals and sharing identity across linked worktrees.
Directory-local identity is mode-separated and derived from the canonical scope
directory. Scope approval keys are mode-qualified except for legacy repository
keys. Ciphertext and identity-path hashes remain in the cache/transition key.

Git-local files stay in the main worktree. The shared private registry under
`$GIT_COMMON_DIR/dotenvsec/` contains discovery metadata only. Provider
decryption reads the owner's encrypted source while the provider process still
runs from the active worktree root. Linked worktrees are therefore consumers,
not writers, of inherited scopes.
