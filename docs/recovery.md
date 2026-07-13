# Recovery and device replacement

## Scope-data backup

Repository-mode ciphertext is recovered through normal Git history. Local and
Git-local scope files are intentionally absent from Git and require a separate
encrypted backup of these four files:

- `.dotenv-sec.yaml`
- `.dotenv-sec/recipients.yaml`
- `.sops.yaml`
- `.env.sops.yaml`

The first three contain policy/public metadata; the fourth remains SOPS
encrypted. Never include local settings, private age identities, temporary
effective identity files, cache data, or decrypted values in that backup.

A Git-local backup must also record the intended relative scope path. After
restoring the four files into the main worktree at that path, recreate discovery
metadata and review the scope before approval:

```sh
dotenvsec scope git-local register /path/to/restored/scope
dotenvsec status /path/to/restored/scope
dotenvsec allow /path/to/restored/scope
```

If the repository and its common Git directory were moved together, repair the
canonical owner path from the current main worktree:

```sh
dotenvsec scope git-local repair-owner
```

The repair validates every registered scope at its relative path before writing
the new owner. Deleting `.git`, deleting the main worktree, or restoring only a
linked worktree loses the shared registry and owner files. A fresh clone does
not inherit Git-local scopes.

Create a separate standard age identity protected by a strong, unique passphrase. Store it offline, outside normal laptops and hardware tokens, with documented custody and periodic recovery testing. Add only its public recipient to the repository manifest. V1 intentionally does not implement custom threshold/Shamir cryptography.

## New device

1. Use offline recovery or another active device to decrypt in a controlled session.
2. Enroll the new YubiKey/Secure Enclave identity with the required policy.
3. Add its public recipient and stable device ID to the manifest.
4. Run `rekey`, verify all intended devices and recovery can decrypt, then commit/review manifest, `.sops.yaml`, and ciphertext changes.
5. Mark the old recipient `revoked`; do not merely delete governance history.
6. Rekey again, confirm the old device cannot decrypt, flush the memory agent, and rotate exposed application credentials if device compromise is suspected.

## Lost or invalidated Secure Enclave identity

Biometric enrollment changes or device replacement can permanently invalidate the identity. Recover with another listed recipient, enroll the replacement, rekey, and revoke the old recipient. Without another active recipient or offline recovery, ciphertext is unrecoverable by design.

## Incident response

Stop automatic hooks, run `dotenvsec agent lock`, terminate descendant processes that inherited secrets, revoke application/backend credentials, inspect Git/log history for plaintext, remove compromised recipients, rekey, and independently verify raw OpenTofu backend ciphertext and recovery.
