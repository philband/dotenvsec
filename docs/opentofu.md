# OpenTofu state and plan encryption

OpenTofu owns state/plan encryption. `dotenvsec` only supplies complete `TF_ENCRYPTION` HCL and backend credential environment variables. Repository configuration must set `enforced = true` for both state and plan encryption.

Do not pass secrets via `-backend-config` or other CLI arguments: they can survive in shell history, process listings, `.terraform` metadata, and plans. Supply standard backend environment variables inside the encrypted scope instead. Backend locking and object versioning remain separate controls and must both be configured.

## Plaintext migration

1. Stop concurrent writers and verify backend locking.
2. Back up the state in a separately protected location and record its checksum.
3. Create a high-entropy encryption passphrase, place it only in encrypted `.env.sops.yaml`, and configure `TF_ENCRYPTION` with enforced state/plan methods.
4. Add an explicit plaintext fallback only for the migration window, then run `tofu init -migrate-state` and force a state rewrite.
5. Inspect the raw backend object—not `tofu state pull`—and confirm resources/secrets are not readable plaintext.
6. Verify an authorized `tofu state pull` succeeds and a process without `TF_ENCRYPTION` fails.
7. Remove plaintext fallback, rewrite state again, and repeat raw-ciphertext and authorized/unauthorized checks.
8. Retain the protected backup only for the approved recovery period, then securely dispose of it.

## Passphrase rotation

1. Add a new PBKDF2 key provider/method as primary and retain the old method as a decryption fallback.
2. Run an authorized state rewrite and verify the raw backend object changed.
3. Test recovery with the new secret and a controlled rollback with the old fallback.
4. Remove the old fallback, rewrite again, and verify the old secret no longer decrypts.
5. Rekey `.env.sops.yaml`, review manifest changes, and preserve backend versions according to policy.

Wrong or absent keys must fail closed. Test encrypted plan files separately from state. Never interpret successful locking/versioning as proof of encryption.
