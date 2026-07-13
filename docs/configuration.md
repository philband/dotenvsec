# Configuration

For the complete provider, identity, initialization, Git tracking, and approval
sequence, start with [Getting started](getting-started.md).

## Scope

```yaml
schema: 1
mode: local
provider: sops
source: .env.sops.yaml
environment:
  - AWS_ACCESS_KEY_ID
  - AWS_SECRET_ACCESS_KEY
unset:
  - AWS_PROFILE
allow_dangerous: []
cache_ttl: 0s
provider_config:
  sops_executable: /opt/homebrew/bin/sops
  sops_sha256: <sha256>
  plugin_path: /opt/homebrew/bin
```

`mode` is optional only for backward-compatible repository scopes. Values:

- omitted or `repository` — all four scope files must be tracked in the active
  Git worktree;
- `local` — files must be mode `0600` and, when inside Git, ignored and
  untracked;
- `git-local` — the same private-file rules plus main-worktree ownership and
  linked-worktree read-only inheritance.

Use `dotenvsec init`, `init --local`, or `init --git-local` rather than changing
the field manually. Mode is part of trusted policy and changing it invalidates
approval. See [Scope modes and worktrees](scope-modes.md).

All fields are strict. Unknown fields, duplicate keys, custom tags, aliases/anchors, multiple documents, invalid variable names, undeclared provider outputs, NUL values, path escapes, symlinks, and oversized documents are rejected.

Dangerous variables must appear in `allow_dangerous` and be separately approved in local user settings. Repository declarations alone are insufficient.

## Recipient manifest

```yaml
schema: 1
recipients:
  - id: phil-yubikey-1
    owner: Phil
    status: active
    plugin: yubikey
    recipient: AGE-PLUGIN-YUBIKEY-...
    policy:
      pin: always
      touch: always
    attestation: enrolled locally on 2026-07-12
```

Supported plugin values are `yubikey`, `secure-enclave`, and `age` (offline recovery). Active recipients generate `.sops.yaml`; revoked entries remain visible for governance but are excluded.

## Encrypted document

The decrypted YAML shape must be exactly a single flat string mapping:

```yaml
environment:
  AWS_ACCESS_KEY_ID: value
  AWS_SECRET_ACCESS_KEY: value
```

The encrypted form is `.env.sops.yaml`. It is tracked only in repository mode;
local modes require it to remain ignored and untracked. Plaintext forms and
editor artifacts must never be persisted and should be rejected by pre-commit
scanning.

## Local identity file

User settings accept at most one absolute `identity_paths` entry. It must be a regular, non-symlink file with no group/world permissions. Put all age and plugin identity stanzas needed by SOPS in that consolidated file; the tool passes it explicitly as `SOPS_AGE_KEY_FILE`. Repository files cannot select identity paths.
