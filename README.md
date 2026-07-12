# dotenvsec

[![CI](https://github.com/philband/dotenvsec/actions/workflows/ci.yml/badge.svg)](https://github.com/philband/dotenvsec/actions/workflows/ci.yml)
[![CodeQL](https://github.com/philband/dotenvsec/actions/workflows/codeql.yml/badge.svg)](https://github.com/philband/dotenvsec/actions/workflows/codeql.yml)
[![Release](https://github.com/philband/dotenvsec/actions/workflows/release.yml/badge.svg)](https://github.com/philband/dotenvsec/actions/workflows/release.yml)

`dotenvsec` is a fail-closed environment loader for SOPS-encrypted YAML. It discovers the nearest independent scope inside the active Git worktree, validates local trust and policy, decrypts through a checksum-pinned provider, and applies an atomic environment transition to bash or zsh.

> **Security status:** pre-production. Automatic shell loading requires an independent security review and real-hardware verification.

## Scope files

- `.dotenv-sec.yaml` — strict scope declaration.
- `.dotenv-sec/recipients.yaml` — repository-authoritative recipient manifest.
- `.sops.yaml` — generated recipient rules.
- `.env.sops.yaml` — encrypted document containing exactly one flat `environment` string map.

Scopes never merge. The nearest configured ancestor wins, discovery stops at the active Git worktree root, and failed transitions remove previously managed secrets.

## Quick start

1. Install `sops` and an age identity plugin (`age-plugin-yubikey` or `age-plugin-se`).
2. Register the bundled SOPS provider or an absolute checksum-pinned provider executable.
3. Run `dotenvsec init`, then `dotenvsec allow`.
4. Install `eval "$(dotenvsec hook zsh)"` (or `bash`) in the shell startup file.

Run `dotenvsec --help` and read `docs/threat-model.md`, `docs/configuration.md`, and `docs/recovery.md` before use.

Release artifacts are immutable, checksum-signed with keyless Cosign, accompanied by SPDX SBOMs, and recorded with GitHub build-provenance attestations. Maintainers should follow `docs/releasing.md`.

## Development

Install [Aqua](https://aquaproj.github.io/) 2.56.0, then bootstrap the checksum-pinned toolchain and list available tasks:

```sh
AQUA_CONFIG="$PWD/aqua/aqua.yaml" aqua install
AQUA_CONFIG="$PWD/aqua/aqua.yaml" aqua exec -- just --list
```

Run tasks through pinned Just, for example `AQUA_CONFIG="$PWD/aqua/aqua.yaml" aqua exec -- just test` or `AQUA_CONFIG="$PWD/aqua/aqua.yaml" aqua exec -- just verify`. Tool versions and integrity locks live together in `aqua/`.
