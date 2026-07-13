# Scope modes and Git worktrees

dotenvsec supports three explicit storage and discovery models. They share the
same strict policy, recipient, SOPS, provider, identity, approval, and exact
environment validation. They differ only in storage, Git requirements, and
ownership.

| Mode | Init flag | Storage | Git required | Linked worktrees |
| --- | --- | --- | ---: | --- |
| Repository | none | selected worktree directory | yes | each checkout reads its tracked files |
| Local | `--local` | selected directory | no | no inheritance; a physical local override wins |
| Git-local | `--git-local` | selected directory in main worktree | yes | inherited read-only at the same relative path |

## Repository mode

Repository mode remains the default and is backward compatible with scopes that
omit `mode`. All four files must be tracked in the active worktree. Linked
worktrees with identical policy share repository identity and approval; branch
policy differences fail approval until the selected branch is reviewed.

```sh
dotenvsec init -n TOKEN -r primary=age1...
git add .dotenv-sec.yaml .dotenv-sec/recipients.yaml .sops.yaml .env.sops.yaml
dotenvsec allow
```

## Local mode

Local mode stores all four mode-`0600` files in the selected directory. Outside
Git, discovery walks canonical parents and accepts only an explicit
`mode: local` scope. Its canonical directory determines local identity, so a
move/copy requires approval at the new location.

Inside Git, dotenvsec writes exact ignore patterns to Git's local exclude file.
Every operation verifies that local files are ignored and not tracked. Local
mode does not inherit between worktrees because each worktree has its own
physical files. A linked worktree may intentionally create a local scope at a
path that otherwise inherits Git-local data; the physical local scope wins at
that same depth.

```sh
dotenvsec init --local -n TOKEN -r primary=age1...
dotenvsec allow
```

## Git-local mode

Git-local mode is for secrets that remain inside the main repository checkout
but must be available from linked worktrees without commits, copies, or
symlinks.

Initialize it from the main worktree only:

```sh
dotenvsec init --git-local -n TOKEN -r primary=age1...
dotenvsec allow
```

The encrypted scope remains at the selected path in the main worktree. dotenvsec
stores a private registry at:

```text
$GIT_COMMON_DIR/dotenvsec/registry.yaml
```

The registry contains a canonical owner-worktree path and normalized relative
scope paths—never plaintext, ciphertext, private identities, or approvals.
Every linked worktree uses the same Git common directory. Its current relative
path maps to the corresponding owner path, and nearest-scope discovery works for
nested scopes.

From a linked worktree:

- `status`, `doctor`, `exec`, `shell`, and shell-hook activation are allowed;
- `allow`, `edit`, and `rekey` fail with the owner path;
- the encrypted source is read from the main worktree;
- the provider process runs from the active linked worktree root;
- approval and cache identity are shared with the owner scope;
- ciphertext changes invalidate the cache/transition marker.

`dotenvsec status` makes ownership explicit:

```text
scope: infrastructure/prod
mode: git-local
ownership: inherited, read-only
owner: /absolute/main-worktree/infrastructure/prod
```

## Precedence and boundaries

Scopes never merge. dotenvsec compares the nearest physical scope in the active
worktree with the nearest registered inherited Git-local scope and chooses the
deeper relative path. A physical scope wins at equal depth. Discovery never
reads a tracked/local scope from another worktree and never crosses a nested Git
repository boundary.

Examples:

- tracked repository root + inherited Git-local `infra/prod`: Git-local wins
  below `infra/prod`;
- inherited Git-local root + physical local `infra/dev`: local wins below
  `infra/dev`;
- physical repository/local scope and inherited scope at the same path:
  physical scope wins.

## Local Git metadata and backup

Git-local registry data and ignore entries are local Git administration state:
they are not cloned, fetched, pushed, bundled, or archived by Git. A separate
clone has a different common Git directory and does not inherit the scope.

Back up local/Git-local encrypted files separately. Removing the main worktree,
its `.git` directory, or the only local ciphertext can make the scope
unrecoverable even when private recipient identities still exist. See
[Recovery and device replacement](recovery.md).

For restored or moved Git-local data, use the supported metadata commands from
the main worktree:

```sh
dotenvsec scope git-local register /path/to/existing/scope
dotenvsec scope git-local repair-owner
dotenvsec scope git-local unregister /path/to/scope
```

`unregister` removes discovery metadata only and deliberately leaves encrypted
scope files untouched.
