# Configuration

For the complete provider, identity, initialization, Git tracking, and approval
sequence, start with [Getting started](getting-started.md).

## Scope

```yaml
schema: 2
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
  sops_min_version: "3.10.0"
```

A scope file describes policy only, and stays portable across machines and
platforms. It cannot name an executable, a checksum, or a search path:
`sops_executable`, `sops_sha256`, `plugin_path`, and `identity_paths` are
rejected. Those are per-machine facts and live in the local provider registry;
see [Provider registry and tools](#provider-registry-and-tools). Schema 1 scopes
that still carry them are converted by `dotenvsec migrate`.

`sops_min_version` is optional. It is portable policy: it constrains encryption
format compatibility without binding the scope to one machine's install.

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

## Provider registry and tools

Everything machine-specific lives in local user settings, never in a tracked
scope file:

```yaml
schema: 1
providers:
  sops:
    executable: /opt/homebrew/Cellar/dotenvsec/0.7.0/bin/dotenvsec-provider-sops
    sha256: <sha256>
    source: bundled
    plugin_path: /Users/example/.cargo/bin:/opt/homebrew/bin
    tools:
      sops:
        executable: /opt/homebrew/Cellar/sops/3.13.3/bin/sops
        sha256: <sha256>
```

Bind or re-pin a tool after upgrading it:

```sh
dotenvsec provider retool sops sops "$(command -v sops)"
dotenvsec provider retool sops sops /opt/homebrew/bin/sops --plugin-path /opt/homebrew/bin
```

Paths are canonicalized on binding. Package managers such as Homebrew publish
every binary as a symlink into a versioned directory, so the resolved target is
recorded and the file that is checksummed is the file that is executed. A tool
upgrade therefore invalidates the binding by design; re-pinning is one local
command that touches no tracked file and affects no other machine.

Tool checksums are verified before every launch but are deliberately absent from
the approval hash. Re-approving a scope after a routine `brew upgrade sops` would
add friction without review value; drift is surfaced by `dotenvsec doctor`
instead.

## Local identity file

User settings accept at most one absolute `identity_paths` entry. It must be a regular, non-symlink file with no group/world permissions. Put all age and plugin identity stanzas needed by SOPS in that consolidated file; the tool passes it explicitly as `SOPS_AGE_KEY_FILE`. Repository files cannot select identity paths.
