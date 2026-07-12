# Installation

V1 supports macOS arm64 and Linux amd64 with bash or zsh.

## Homebrew

Install both dotenvsec binaries and the required SOPS dependency from the
reviewed tap:

```sh
brew install philband/tap/dotenvsec
```

The tap formula is generated only after independently verifying the immutable
GitHub release, annotated SSH tag signature, keyless Cosign bundle, GitHub build
provenance, checksums, and archive contents. Formula updates are merged through
reviewed pull requests rather than written directly to the tap's `main` branch.
The tap discovers the latest stable published tag automatically; no release tag
is supplied manually to its update workflow.

YubiKey and Secure Enclave age plugins remain optional and must be installed
separately.

## Manual installation

Download the matching release archive, `checksums.txt`, and Sigstore bundle. Verify the bundle and archive checksum before extracting. Install both `dotenvsec` and `dotenvsec-provider-sops` in a user/root-owned non-writable directory, then register the provider with its release SHA-256.

Alternatively, install directly from source:

```sh
go install github.com/philband/dotenvsec/cmd/dotenvsec@latest
go install github.com/philband/dotenvsec/cmd/dotenvsec-provider-sops@latest
```

Linux users can extract the archive to `/usr/local/bin` with root ownership and mode `0755`.

The optional cache agent is not started automatically. Run `dotenvsec agent serve` from a per-user service manager only after setting a nonzero user maximum TTL in settings. Repository TTL cannot enable caching by itself. Use `agent flush` or `agent lock` on demand.
