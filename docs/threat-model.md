# Threat model

## Assets and goals

The tool protects environment secrets at rest in Git and during validated injection into a shell or child process. It prevents a repository from selecting arbitrary executables, emitting undeclared variables, escaping its worktree, silently changing trusted policy, or retaining credentials after a failed scope transition.

Plaintext must remain in process memory only. It must not be written to logs, command-line arguments, temporary files, cache files, shell history, or provider stdout outside the framed protocol. Cache is disabled by default and, when enabled, is held by a UID-authenticated local memory agent with absolute non-sliding expiry.

## Trust boundaries

- Repository files are untrusted until their policy hash is explicitly approved locally.
- Encrypted value rotation alone does not invalidate approval; schema, provider selection, source path, expected names, dangerous-variable exceptions, or recipient/config policy changes do.
- Provider executables are selected only through a per-user registry and checked for absolute path, ownership, regular-file status, safe permissions, and SHA-256 before every launch.
- Shell hooks are static output from this binary and never source repository code.
- Git defines the worktree/repository boundary. Nested repositories are independent.

## Explicit exclusions

This tool cannot protect against:

- root or an administrator;
- a fully compromised process running as the same user;
- malicious shell startup files, debuggers, ptrace, memory inspection, or swap capture;
- malicious OpenTofu binaries/providers or other child programs;
- secrets deliberately printed, persisted, or transmitted by a child program;
- compromised hardware-token firmware, OS biometric services, SOPS, age plugins, or the Go runtime;
- plaintext already present in Git history or external logs.

## Fail-closed behavior

Malformed/ambiguous YAML, unknown fields, duplicate keys, unsafe paths/files, trust mismatch, provider failure/cancellation/timeout, undeclared output, dangerous variable denial, or cache-agent authentication failure yields no new environment. Shell transitions first restore/remove all variables managed by the previous scope, so stale credentials are not retained after failure.

## Residual risks

Environment variables are inherited by descendants and may be observable through same-user process inspection on some systems. Memory zeroing is best effort because Go may copy strings. The memory agent makes no swap-resistance claim. Imported public hardware recipients cannot cryptographically prove PIN/touch/biometry policy; operator attestation is recorded instead.
