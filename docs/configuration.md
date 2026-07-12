# Configuration

## Scope

```yaml
schema: 1
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

The encrypted tracked form is `.env.sops.yaml`; plaintext forms and editor artifacts are ignored and should be rejected by pre-commit scanning.

## Local identity file

User settings accept at most one absolute `identity_paths` entry. It must be a regular, non-symlink file with no group/world permissions. Put all age and plugin identity stanzas needed by SOPS in that consolidated file; the tool passes it explicitly as `SOPS_AGE_KEY_FILE`. Repository files cannot select identity paths.
