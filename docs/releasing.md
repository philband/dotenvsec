# Releasing

Releases are built only by GitHub Actions from annotated, SSH-signed semantic version tags such as `v0.1.0`. Do not upload or replace release artifacts manually.

## One-time repository setup

1. Enable **Settings → General → Releases → Enable release immutability** before creating the first release. GitHub enforces immutability when the completed draft is published.
2. Enable private vulnerability reporting, Dependabot alerts, secret scanning, push protection, and CodeQL default/setup alerts.
3. Protect `main`: require pull requests, require the CI and CodeQL checks, require conversation resolution, disallow force pushes/deletion, and require linear history.
4. Keep Actions permissions at the restrictive default. The release workflow declares only `contents: write`, `id-token: write`, and `attestations: write` for keyless signing, release upload, and GitHub provenance.
5. Keep `aqua/aqua.yaml` and `aqua/aqua-checksums.json` reviewed together. All workflow tools are installed by the immutable-SHA-pinned Aqua Installer action; tool-specific installer actions are forbidden.
6. Create a tag ruleset for `v*` that restricts tag creation to the maintainer and blocks tag updates/deletion. Immutable releases additionally lock the published release tag.
7. Create a dedicated GitHub App for Homebrew tap automation and install it only on `philband/homebrew-tap`. Grant Metadata read, Contents read/write, and Pull requests read/write. Store its App ID and complete private-key PEM as `HOMEBREW_TAP_APP_ID` and `HOMEBREW_TAP_APP_PRIVATE_KEY` Actions secrets in both repositories. Never put credentials in dispatch payloads or logs.

## Publishing flow

1. Submit changes through a pull request and wait for all required checks.
2. Merge the pull request into `main`.
3. Update local `main` with a fast-forward-only pull and ensure the worktree is clean.
4. Create an annotated signed tag with the configured hardware-backed SSH signing key, for example `git tag -s v0.1.0 -m "dotenvsec v0.1.0"`.
5. Verify it locally with `git verify-tag v0.1.0`.
6. Push only that tag with `git push origin v0.1.0`. Do not use `git push --tags`.
7. The tag push triggers the release workflow. The workflow rejects lightweight/unsigned tags, validates the signer against `philband` SSH signing keys published by GitHub, and requires the tagged commit to be merged into `main`.
8. Publishing the completed immutable release triggers the separate Homebrew tap workflow. It sends only a `dotenvsec` project wake-up to `philband/homebrew-tap`. The tap independently discovers the newest stable published tag, reverifies the release, and opens a formula update pull request for review.

## Release transaction

1. Update documentation and verify the full test suite on `main`.
2. Receive and cryptographically verify the annotated semantic-version tag.
3. The release workflow reruns race tests, vet, plaintext scanning, and vulnerability scanning.
4. GoReleaser cross-builds macOS arm64 and Linux amd64 archives, creates SPDX SBOMs and checksums, and uses Cosign keyless signing to create `checksums.txt.bundle` before uploading anything.
5. GoReleaser uploads a **draft** release. GitHub Actions creates build-provenance attestations for every checksum-listed artifact.
6. Only after all prior steps pass does the workflow publish the draft. With immutable releases enabled, the tag and release assets are then permanently locked.

If any step before publication fails, the release remains a mutable draft and may be deleted or rerun. Never work around a failure by disabling immutable releases or manually replacing an artifact. Once published, issue a new version for every correction.

The Homebrew dispatch is deliberately outside this transaction and contains no
tag or checksum. If dispatch or tap PR generation fails, rerun **Trigger
Homebrew tap discovery** or manually run the tap's input-free **Update formulas**
workflow. The tap also polls automatically, rediscovers the latest tag on every
run, and never falls back if that newest release fails verification. The tap
never writes directly to `main`; branch protection and required CI remain the
final publication gate.

## Updating build tools

From the repository root, enter `aqua/`, run `aqua up`, review every version and registry change, then run `aqua upc --prune`. Commit the manifest and checksum lock together. The standard Aqua registry itself is version-pinned, and CI rejects a stale or modified checksum lock.

## Consumer verification

Download an archive, `checksums.txt`, and `checksums.txt.bundle`, then verify the checksum and the keyless Cosign bundle against the repository identity. GitHub CLI can additionally verify the build provenance attestation for a downloaded artifact.
