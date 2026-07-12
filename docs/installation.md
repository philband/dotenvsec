# Installation

V1 supports macOS arm64 and Linux amd64 with bash or zsh.

Download the matching release archive, `checksums.txt`, and Sigstore bundle. Verify the bundle and archive checksum before extracting. Install both `dotenvsec` and `dotenvsec-provider-sops` in a user/root-owned non-writable directory, then register the provider with its release SHA-256.

Alternatively, install directly from source:

```sh
go install github.com/philband/dotenvsec/cmd/dotenvsec@latest
go install github.com/philband/dotenvsec/cmd/dotenvsec-provider-sops@latest
```

The Homebrew formula under `Formula/` is a template whose checksum must be replaced from the release before publication. Linux users can extract the archive to `/usr/local/bin` with root ownership and mode `0755`.

The optional cache agent is not started automatically. Run `dotenvsec agent serve` from a per-user service manager only after setting a nonzero user maximum TTL in settings. Repository TTL cannot enable caching by itself. Use `agent flush` or `agent lock` on demand.
