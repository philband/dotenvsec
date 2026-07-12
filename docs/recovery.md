# Recovery and device replacement

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
