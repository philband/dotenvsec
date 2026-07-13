# dotenvsec

[![CI](https://github.com/philband/dotenvsec/actions/workflows/ci.yml/badge.svg)](https://github.com/philband/dotenvsec/actions/workflows/ci.yml)
[![CodeQL](https://github.com/philband/dotenvsec/actions/workflows/codeql.yml/badge.svg)](https://github.com/philband/dotenvsec/actions/workflows/codeql.yml)
[![Release](https://github.com/philband/dotenvsec/actions/workflows/release.yml/badge.svg)](https://github.com/philband/dotenvsec/actions/workflows/release.yml)

`dotenvsec` is a fail-closed environment loader for SOPS-encrypted YAML. It discovers the nearest independent repository, local, or Git-local scope, validates local trust and policy, decrypts through a checksum-pinned provider, and applies an atomic environment transition to bash or zsh.

> **Security status:** pre-production. Automatic shell loading requires an independent security review and real-hardware verification.

## Scope files

- `.dotenv-sec.yaml` — strict scope declaration.
- `.dotenv-sec/recipients.yaml` — repository-authoritative recipient manifest.
- `.sops.yaml` — generated recipient rules.
- `.env.sops.yaml` — encrypted document containing exactly one flat `environment` string map.

Scopes never merge. The nearest configured ancestor wins and failed transitions remove previously managed secrets. Repository scopes are tracked in Git, local scopes are private and untracked, and main-worktree Git-local scopes are inherited read-only by linked worktrees. See [Scope modes and worktrees](docs/scope-modes.md).

## Quick start

1. Install dotenvsec, its SOPS provider, SOPS, and an age implementation/plugin.
2. Register `dotenvsec-provider-sops` locally and configure the private identity path.
3. Choose a [scope mode](docs/scope-modes.md), then initialize explicitly with names and paired public recipients, for example `dotenvsec i -n API_TOKEN -r primary=age1...`.
4. Review the four generated files. Stage them only in repository mode, then run `dotenvsec allow` and `dotenvsec edit`.
5. Verify with `dotenvsec doctor` and child-only `dotenvsec exec` before installing a shell hook.

Follow the complete [repository onboarding guide](docs/getting-started.md). Run
`dotenvsec --help` and read `docs/threat-model.md`, `docs/configuration.md`, and
`docs/recovery.md` before use.

Release artifacts are immutable, checksum-signed with keyless Cosign, accompanied by SPDX SBOMs, and recorded with GitHub build-provenance attestations. Maintainers should follow `docs/releasing.md`.

## Development

Install [Aqua](https://aquaproj.github.io/) 2.56.0, then bootstrap the checksum-pinned toolchain and list available tasks:

```sh
AQUA_CONFIG="$PWD/aqua/aqua.yaml" aqua install
AQUA_CONFIG="$PWD/aqua/aqua.yaml" aqua exec -- just --list
```

Run tasks through pinned Just, for example `AQUA_CONFIG="$PWD/aqua/aqua.yaml" aqua exec -- just test` or `AQUA_CONFIG="$PWD/aqua/aqua.yaml" aqua exec -- just verify`. Tool versions and integrity locks live together in `aqua/`.
