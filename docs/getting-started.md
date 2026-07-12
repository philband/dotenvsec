# Getting started

`dotenvsec init` is non-interactive. It cannot infer which environment variable
names belong in a scope or which public recipients should encrypt them. A bare
`dotenvsec init` therefore returns `at least one --name and --recipient are
required`.

This guide uses the compact form:

- `i` is an alias for `init`.
- `-n`/`--name` accepts a comma-separated list or may be repeated.
- `-r`/`--recipient` accepts `ID=PUBLIC_RECIPIENT` and may be repeated.
- `-p`, `-s`, and `-o` are shorthand for `--plugin`, `--sops`, and `--owner`.

## Understand the three local components

Do not interchange these executables or keys:

1. `sops` encrypts and edits `.env.sops.yaml`. Its absolute path and SHA-256
   are pinned in the repository's `.dotenv-sec.yaml`.
2. `dotenvsec-provider-sops` implements the restricted dotenvsec provider
   protocol. Register it locally under provider ID `sops`.
3. An age or age-plugin identity decrypts the file. Commit only public
   recipients; keep private identity material in a private local file.

## 1. Install the required tools

Install dotenvsec and SOPS as described in [Installation](installation.md). The
Homebrew formula installs both dotenvsec binaries and SOPS:

```sh
brew install philband/tap/dotenvsec
```

Install the age implementation or hardware plugin that owns your identities.
For YubiKey and Apple Secure Enclave requirements, read
[Hardware enrollment](enrollment.md).

## 2. Register the local provider

Register `dotenvsec-provider-sops`, not the `sops` executable:

```sh
PROVIDER="$(command -v dotenvsec-provider-sops)"
PROVIDER_SHA256="$(shasum -a 256 "$PROVIDER" | awk '{print $1}')"
dotenvsec provider register sops "$PROVIDER" --sha256 "$PROVIDER_SHA256"
dotenvsec provider list
```

Provider registration is per user and writes the checksum-pinned executable to
dotenvsec's local settings. Registration resolves package-manager symlinks and
stores only the canonical regular executable.

## 3. Configure decryption identities

SOPS accepts one consolidated age identity file. It may contain standard age
identities and supported plugin identity stanzas. The file must be absolute,
regular, non-symlinked, and accessible only by its owner (`0600`).

Local settings are stored at:

- macOS: `~/Library/Application Support/dotenvsec/settings.yaml`
- Linux: `${XDG_CONFIG_HOME:-$HOME/.config}/dotenvsec/settings.yaml`

After provider registration has created the file, add the identity path without
removing the generated `providers` section:

```yaml
schema: 1
identity_paths:
  - /absolute/path/to/consolidated-age-identities.txt
editor: code --wait --reuse-window
providers:
  sops:
    executable: /absolute/path/to/dotenvsec-provider-sops
    sha256: <provider-sha256>
```

Never commit local settings or private identities.

For YubiKey identities, connect only a locally authorized key and export its
plugin identity reference into the consolidated file. This output is private
local configuration even though the hardware still protects the key:

```sh
IDENTITY_DIR="$HOME/Library/Application Support/dotenvsec"
IDENTITY_FILE="$IDENTITY_DIR/yubikey-identities.txt"
mkdir -p "$IDENTITY_DIR"
umask 077
LANG=C LC_ALL=C age-plugin-yubikey -i > "$IDENTITY_FILE"
chmod 0600 "$IDENTITY_FILE"
```

If this user controls more than one authorized YubiKey, connect each additional
key separately and append its `-i` output. A user does not need private identity
references for every public recipient in the repository—only for devices that
user is authorized to operate. Set `identity_paths` to the absolute value of
`IDENTITY_FILE`.

## 4. Initialize a repository scope

Run initialization inside an existing Git worktree. For one standard age
recipient:

```sh
RECIPIENT="$(age-keygen -y "$HOME/.config/sops/age/keys.txt")"

dotenvsec i \
  -n API_TOKEN,DATABASE_URL \
  -r "primary=$RECIPIENT" \
  -s "$(command -v sops)"
```

For multiple YubiKeys, pair every stable device ID and public recipient in one
repeatable flag:

```sh
dotenvsec i \
  -n TF_HTTP_USERNAME,TF_HTTP_PASSWORD,TF_ENCRYPTION \
  -s "$(command -v sops)" \
  -p yubikey \
  -r 'pb-yk-main=age1yubikey1...' \
  -r 'pb-yk-dr-red=age1yubikey1...' \
  -r 'dm-main=age1yubikey1...' \
  -r 'dm-dr=age1yubikey1...'
```

The owner and plugin flags apply to every recipient in that invocation. IDs and
public recipients must both be unique. Initialization encrypts to public
recipients and should not request a YubiKey PIN or touch. For hardware plugins,
initialization locates the corresponding `age-plugin-*` executable in `PATH` and
records its directory in the repository's checksum-approved provider policy.

Initialization is transactional. It creates all four files or none:

- `.dotenv-sec.yaml` — scope policy and checksum-pinned SOPS path
- `.dotenv-sec/recipients.yaml` — public recipient governance
- `.sops.yaml` — creation rule generated from active recipients
- `.env.sops.yaml` — encrypted environment with `CHANGE_ME` placeholders

It never writes plaintext environment values to the repository.

## 5. Review, track, and approve

Inspect the policy and public metadata before trusting it:

```sh
git diff --no-index /dev/null .dotenv-sec.yaml || true
git diff --no-index /dev/null .dotenv-sec/recipients.yaml || true
git diff --no-index /dev/null .sops.yaml || true
```

Stage all four generated files. `dotenvsec allow` deliberately rejects
untracked scope inputs:

```sh
git add .dotenv-sec.yaml .dotenv-sec/recipients.yaml .sops.yaml .env.sops.yaml
dotenvsec allow
```

Approval stores a local trust hash in `settings.yaml`; it does not modify the
repository. Changes to recipients, declared variable names, provider checksum,
or scope policy invalidate that approval and require another review and
`dotenvsec allow`.

## 6. Enter values and verify

Choose the editor once in local user settings. From a VS Code integrated
terminal, the `vscode` preset opens the temporary decrypted document in the
current VS Code window and waits until that tab is closed:

```sh
dotenvsec settings editor vscode
```

The preset stores `code --wait --reuse-window`. Any other SOPS-compatible editor
command can be selected globally by passing it as one quoted argument:

```sh
dotenvsec settings editor 'nvim --nofork'
```

Show the current default with `dotenvsec settings editor`. Clear it and return
to the ambient `SOPS_EDITOR` or `EDITOR` environment with:

```sh
dotenvsec settings editor --clear
```

Editor selection is local per user and is never controlled by repository files.

Open the encrypted document through the pinned SOPS executable:

```sh
dotenvsec edit
```

Replace every `CHANGE_ME`, save, and then verify the complete setup:

```sh
dotenvsec doctor
dotenvsec exec -- sh -c 'test -n "$API_TOKEN"'
```

Use a test that checks presence without printing secret values. Commit only the
encrypted/configuration files after review.

For interactive use, prefer an isolated child shell:

```sh
dotenvsec shell
```

Install the automatic zsh or bash hook only after `doctor` and child-only
loading work. Add the matching command to `~/.zshrc` or `~/.bashrc`:

```sh
eval "$(dotenvsec hook zsh)"
```

## Troubleshooting initialization

### `at least one --name and --recipient are required`

`init` is non-interactive. Pass `-n NAME` and at least one
`-r ID=PUBLIC_RECIPIENT`.

### `no matching creation rules found`

Older dotenvsec releases encrypted stdin without telling SOPS that the intended
filename was `.env.sops.yaml`. They could leave three partial files and no
ciphertext. Upgrade dotenvsec, verify those files are untracked failed-init
output, remove only `.dotenv-sec`, `.dotenv-sec.yaml`, and `.sops.yaml`, then
retry. Current initialization supplies the filename and rolls back on failure.

### `provider "sops" is not registered locally`

Register the absolute `dotenvsec-provider-sops` path with
`dotenvsec provider register sops ...`. Do not register the `sops` binary as the
provider.

### `required file is not tracked by Git`

Review and stage all four generated files before `dotenvsec allow` or other
trusted operations.

### `scope is not locally approved`

Review the tracked policy and run `dotenvsec allow`. Policy changes invalidate
the previous local approval.

### `sops checksum mismatch`

The repository pins the SOPS executable used during initialization. Review the
package upgrade, update the pinned path/checksum through a trusted process, and
approve the changed policy again. Never bypass the mismatch.

### Provider invalid after `brew upgrade`

Homebrew removes the old versioned Cellar directory after upgrading dotenvsec.
Re-register the newly installed provider, review the changed provider checksum,
and approve each affected repository again:

```sh
PROVIDER="$(command -v dotenvsec-provider-sops)"
PROVIDER_SHA256="$(shasum -a 256 "$PROVIDER" | awk '{print $1}')"
dotenvsec provider register sops "$PROVIDER" --sha256 "$PROVIDER_SHA256"
dotenvsec provider list

cd /path/to/repository
dotenvsec status
dotenvsec allow
```

Re-approval is intentional: the locally trusted executable and its checksum
changed. Do not automate `allow` as part of a package upgrade.

### Decryption cannot find an identity

Check that `identity_paths` points to the correct consolidated private identity
file, its mode is `0600`, and the required hardware plugin is installed. For
YubiKeys, decryption may require the configured PIN and touch policy.

### `age-plugin-yubikey` is not found during `exec` or `shell`

Provider-based loading uses a restricted `PATH`. Run `dotenvsec doctor`; it
checks every age plugin required by active recipients. Scopes initialized by
older releases may contain only the SOPS directory in `provider_config.plugin_path`.
After review, add the absolute directory containing the plugin to that path
list, stage the scope change, and run `dotenvsec allow` again. For example on
macOS with a Cargo-installed plugin:

```yaml
provider_config:
  plugin_path: /Users/example/.cargo/bin:/opt/homebrew/bin
```

New initialization detects this path automatically. Repository plugin paths are
trusted policy; do not copy an unreviewed path or point them at writable project
directories.

### `refusing to overwrite`

Initialization never overwrites a scope. If a valid scope exists, use `edit`,
update its recipient manifest, and `rekey`. Remove files only when you have
confirmed they are untracked partial output from a failed initialization.
