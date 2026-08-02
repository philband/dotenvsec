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

## 2. Verify the bundled provider

Official archives and the Homebrew formula install `dotenvsec-provider-sops`
beside the main `dotenvsec` binary. On every CLI invocation, dotenvsec locates
that canonical sibling, verifies its ownership and permissions, calculates its
SHA-256, and creates or refreshes the local `sops` provider entry automatically:

```sh
dotenvsec provider list
```

The entry should report `ok` and `source: bundled` in local settings. Automatic
refresh applies only to the official sibling named `dotenvsec-provider-sops`.
External/custom providers remain explicit and require `provider register` with
an absolute path and reviewed checksum.

## 3. Configure decryption identities

SOPS accepts one consolidated age identity file. It may contain standard age
identities and supported plugin identity stanzas. The file must be absolute,
regular, non-symlinked, and accessible only by its owner (`0600`).

Local settings are stored at:

- macOS: `~/Library/Application Support/dotenvsec/settings.yaml`
- Linux: `${XDG_CONFIG_HOME:-$HOME/.config}/dotenvsec/settings.yaml`

For standard age or Secure Enclave identities, add the private consolidated file
path without removing generated settings:

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

YubiKey identities are managed automatically. On the first `edit`, `exec`,
`shell`, or hook activation that needs decryption, dotenvsec:

1. Runs the trusted `age-plugin-yubikey -i` executable from the repository's
  approved plugin path.
2. Matches connected identity metadata against active public recipients in the
  repository manifest.
3. Atomically adds newly discovered matching identity references to a private
  managed identity file and configures its absolute path in local settings.
4. Gives SOPS a temporary mode-`0600` identity file containing non-YubiKey
  identities plus only the matching YubiKeys connected for that operation.
5. Deletes the temporary file immediately after SOPS exits.

Connect one locally authorized YubiKey before the first decryption. Connect a
different authorized key on a later operation to enroll it automatically. No
manual `age-plugin-yubikey -i` command is needed. Discovery does not request a
PIN or touch; SOPS prompts only when it decrypts with a connected matching key.
If no connected key matches an active recipient, dotenvsec fails before SOPS
instead of prompting for absent devices.

## 4. Choose and initialize a scope mode

dotenvsec supports three storage modes:

- **Repository** (default): tracked scope files inside a Git worktree.
- **Local** (`--local`): private untracked files in the selected directory;
  Git is optional.
- **Git-local** (`--git-local`): private untracked files in the main worktree,
  inherited read-only at the same relative path by every linked worktree.

Read [Scope modes and worktrees](scope-modes.md) before choosing local storage.
Repository mode is the safest default for shared, reviewed configuration.

### Repository mode

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

### Local mode

Use local mode for a scope that must stay on one filesystem and must not be
tracked. It also works outside Git:

```sh
dotenvsec i --local \
  -n API_TOKEN,DATABASE_URL \
  -r "primary=$RECIPIENT" \
  -s "$(command -v sops)"
```

Inside a Git worktree, initialization adds exact entries to the worktree's Git
exclude mechanism so all four files remain ignored. dotenvsec subsequently
rejects a local file that is not ignored, is force-added to Git, has group/world
permissions, or is a symlink. Outside Git, the selected local directory is the
scope boundary and moving it requires a new local approval.

### Git-local mode

Run Git-local initialization only from the main worktree:

```sh
dotenvsec i --git-local \
  -n API_TOKEN,DATABASE_URL \
  -r "primary=$RECIPIENT" \
  -s "$(command -v sops)"
```

The four private files remain in that main-worktree directory. A private
registry at `$GIT_COMMON_DIR/dotenvsec/registry.yaml` records only the owner
worktree and relative scope paths. Linked worktrees resolve the same encrypted
scope at the corresponding relative path without copying or symlinking files.
They may run `status`, `doctor`, `exec`, `shell`, and hook activation, but
`allow`, `edit`, and `rekey` must run from the main worktree. `status` reports
the inherited owner path.

Initialization is transactional. It creates all four files or none:

- `.dotenv-sec.yaml` — scope policy and checksum-pinned SOPS path
- `.dotenv-sec/recipients.yaml` — public recipient governance
- `.sops.yaml` — creation rule generated from active recipients
- `.env.sops.yaml` — encrypted environment with `CHANGE_ME` placeholders

It never writes plaintext environment values to the scope directory.

## 5. Review, optionally track, and approve

Inspect the policy and public metadata before trusting it:

```sh
git diff --no-index /dev/null .dotenv-sec.yaml || true
git diff --no-index /dev/null .dotenv-sec/recipients.yaml || true
git diff --no-index /dev/null .sops.yaml || true
```

For repository mode, stage all four generated files. `dotenvsec allow`
deliberately rejects untracked repository scope inputs:

```sh
git add .dotenv-sec.yaml .dotenv-sec/recipients.yaml .sops.yaml .env.sops.yaml
dotenvsec allow
```

For local and Git-local mode, do **not** stage anything. Confirm the files are
ignored/private, review them from the owner directory, and approve:

```sh
git status --ignored --short  # when inside Git
dotenvsec status
dotenvsec allow
```

Git-local approval is shared by linked worktrees because they represent the
same repository and relative scope. Linked worktrees cannot create or replace
that approval; review and approve only in the main worktree.

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

`exec` launches a real executable directly; shell aliases and functions are not
available. For example, if `tf` is an alias for OpenTofu, invoke the actual
binary:

```sh
dotenvsec exec -- tofu plan
```

The `--` separator is optional for simple commands but recommended so command
arguments beginning with `-` are unambiguous. Use `dotenvsec shell` when an
interactive shell with its aliases and functions is specifically required.

For interactive use, prefer an isolated child shell:

```sh
dotenvsec shell
```

Install the automatic zsh or bash hook only after `doctor` and child-only
loading work. Add the matching command to `~/.zshrc` or `~/.bashrc`:

```sh
eval "$(dotenvsec hook zsh)"
```

The global hook is silent in directories without a configured scope, whether
or not they are inside Git. Entering an unconfigured directory still clears any
environment values managed by the previous scope. Errors from a discovered but
broken or unapproved scope remain visible.

## Upgrading a schema 1 scope

Schema 1 stored `sops_executable`, `sops_sha256`, and `plugin_path` in the
tracked scope file. That made one committed file unable to describe more than a
single machine, and turned every SOPS upgrade into a tracked-file edit that broke
the scope for everyone else. Schema 2 keeps only portable policy in the scope
file and holds the binding in the local provider registry.

Run once per scope, from the main worktree:

```sh
dotenvsec migrate
git diff .dotenv-sec.yaml
```

`migrate` binds the recorded SOPS executable and plugin path into local settings,
rewrites the scope file as schema 2, and preserves portable keys such as
`sops_min_version`. It refuses to run twice.

In repository mode, review and commit the rewritten scope file. Then, on **every
machine** that uses the scope, bind the local tool and re-approve — the trust
hash changes, and the binding is per-machine by design:

```sh
dotenvsec provider retool sops sops "$(command -v sops)"
dotenvsec allow
dotenvsec doctor
```

Colleagues on other platforms now bind their own paths without touching the
repository. If a machine has no SOPS recorded to migrate, `migrate` says so; bind
it with `provider retool` first.

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

The official provider sibling is missing or dotenvsec is running from a custom
layout. Reinstall the official archive/formula and ensure `dotenvsec` and
`dotenvsec-provider-sops` share one canonical directory. Explicit registration
is reserved for external providers; do not register the `sops` binary itself as
a provider.

### `required file is not tracked by Git`

Review and stage all four generated files before `dotenvsec allow` or other
trusted operations.

### `local scope file must be ignored by Git`

Local and Git-local files inside Git must be ignored and untracked. Do not force
add them. Initialization normally writes exact entries to Git's local exclude
file; inspect `.git/info/exclude` through the main repository's common Git
directory if an entry was removed.

### `scope is inherited read-only`

The selected Git-local scope belongs to the main worktree. Run `allow`, `edit`,
or `rekey` from the owner path printed by `dotenvsec status`. Read/decrypt
operations remain available from the linked worktree.

### `scope is not locally approved`

Review the tracked policy and run `dotenvsec allow`. Policy changes invalidate
the previous local approval.

### `sops checksum mismatch`

The repository pins the SOPS executable used during initialization. Review the
package upgrade, update the pinned path/checksum through a trusted process, and
approve the changed policy again. Never bypass the mismatch.

### Scope unapproved after `brew upgrade`

Homebrew removes the old versioned Cellar directory after upgrading dotenvsec.
The next dotenvsec invocation automatically discovers and checksum-pins the new
bundled provider. Since the trusted provider checksum changed, each repository's
approval becomes invalid until it is reviewed again:

```sh
dotenvsec provider list

cd /path/to/repository
dotenvsec status
dotenvsec allow
```

Re-approval is intentional: the locally trusted executable and its checksum
changed. Provider refresh is automatic; do not automate `allow` as part of a
package upgrade.

### Decryption cannot find an identity

Check that `identity_paths` points to the correct consolidated private identity
file, its mode is `0600`, and the required hardware plugin is installed. For
standard age or Secure Enclave identities, configure the private file explicitly.
For YubiKeys, connect a device whose public recipient is active in the repository;
dotenvsec discovers and enrolls its identity reference automatically. Decryption
may then require the configured PIN and touch policy.

### `age-plugin-yubikey` is not found during `exec` or `shell`

Provider-based loading uses a restricted `PATH`. Run `dotenvsec doctor`; it
checks every age plugin required by active recipients, resolving them exactly as
the loading path does.

The search path is local machine state, so widening it needs no scope edit, no
commit, and no re-approval:

```sh
dotenvsec provider retool sops sops "$(command -v sops)" \
  --plugin-path /Users/example/.cargo/bin:/opt/homebrew/bin
```

`init` detects the directory automatically when the plugin is already installed.
The default search path covers `/opt/homebrew/bin` on macOS plus the standard
system directories; Homebrew on Linux (`/home/linuxbrew/.linuxbrew/bin`) and
other non-standard prefixes must be added explicitly.

Releases before this one skipped any plugin installed as a symlink, which is how
Homebrew publishes every binary, so a Homebrew `age-plugin-yubikey` was reported
as missing while `doctor` still passed. Symlinks are now resolved and the
canonical target is checked.

### `refusing to overwrite`

Initialization never overwrites a scope. If a valid scope exists, use `edit`,
update its recipient manifest, and `rekey`. Remove files only when you have
confirmed they are untracked partial output from a failed initialization.
