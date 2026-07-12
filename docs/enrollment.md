# Hardware enrollment

After obtaining public hardware recipients and storing their private plugin
identity stanzas locally, return to [Getting started](getting-started.md) to
initialize the repository with repeatable `-r ID=PUBLIC_RECIPIENT` flags.

## YubiKey

Use a current, checksum-verified `age-plugin-yubikey`. Generate the identity directly on the intended device with PIN policy `always` and touch policy `always`; record the public recipient in `.dotenv-sec/recipients.yaml` with a stable device ID and operator attestation. Test uncached decryption, cancellation, wrong/missing hardware, and a second authorized device before production use.

A public recipient imported from elsewhere cannot prove its PIN/touch policy. Treat manifest policy as operator attestation unless independently inspected on the hardware.

## Apple Secure Enclave

Requires macOS 14+ and a pinned `age-plugin-se` compatible with the pinned SOPS release. Enroll with access control `current-biometry`. The identity is bound to that physical device, and changing biometric enrollment may invalidate it. Add and test another device plus offline recovery before relying on it.

## Compatibility gate

Reject `age1tag…` and `age1tagpq…` recipients until the exact pinned SOPS release is verified with those plugin formats. `doctor` should be supplemented by real-hardware tests because public recipients cannot establish all device policy.

## Shell setup

Install the static hook only from the trusted binary:

```sh
eval "$(/absolute/path/dotenvsec hook zsh)"
```

Use `bash` instead of `zsh` where appropriate. The hook never sources repository files. For safer child-only use, prefer `dotenvsec exec -- command`; for an isolated interactive session, use `dotenvsec shell`.
