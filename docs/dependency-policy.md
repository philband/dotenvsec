# Dependency and release policy

- Go dependencies are minimized, committed through `go.mod`/`go.sum`, reviewed for maintainer health and license, and scanned with `govulncheck`.
- Every build/release CLI—including Go itself—is pinned in `aqua/aqua.yaml`. Aqua verifies upstream checksums/attestations and enforces the committed `aqua/aqua-checksums.json` lock. The `govulncheck` Go installation is version-pinned and verified through the Go checksum database.
- Aqua is the sole bootstrap exception because it cannot manage itself through the standard registry. CI installs exact Aqua through Aqua Installer pinned to an immutable commit; the installer verifies the Aqua release before execution.
- Cryptography and encrypted-file formats are delegated to pinned SOPS and age plugins; this project does not implement cryptographic primitives.
- Provider, SOPS, and plugin executables must be installed from trusted sources. Provider and SOPS checksums are pinned and verified before use.
- CI bootstraps only checksum-verified Aqua, then runs race tests, vet, golangci-lint, vulnerability scanning, plaintext scanning, and both target cross-builds through Aqua.
- Tagged releases contain checksums, SPDX SBOMs, and a keyless Sigstore bundle for the checksum file. Verify these before installation.
- Dependency updates that affect YAML, process execution, Git discovery, socket authentication, SOPS, or age plugins require security-focused review.

To update tools, run `cd aqua && aqua up`, review version changes, then run `aqua upc --prune` in the same directory and review the checksum diff. CI regenerates the pruned lock and fails on drift.
