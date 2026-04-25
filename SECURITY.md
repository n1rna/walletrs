# Security Policy

walletrs is a Bitcoin wallet service that holds keys, signs transactions, and broadcasts them. Treat it like the rest of your hot infrastructure.

## Reporting a vulnerability

**Do not open public GitHub issues for security bugs.**

Use GitHub's [private vulnerability reporting](https://github.com/n1rna/walletrs/security/advisories/new) or email **security@n1rna.net** with:

- A description of the issue and the impact you observed.
- Reproduction steps or a proof-of-concept.
- The walletrs version (`walletrs --version` or the image tag) and your storage backend (`local` / `s3`).
- Whether the report is coordinated with any other party.

Acknowledgement target: 72 hours. We aim to ship a fix or a documented mitigation within 14 days for high-impact issues. Critical Bitcoin-key-exposure or remote-code-execution bugs get treated as drop-everything.

We don't run a paid bug-bounty program. We do credit reporters in the release notes unless asked to stay anonymous.

## Supported versions

Active patch support tracks the most recent minor release. Once a new minor ships, the prior one gets two more weeks of patch-level support, then drops.

| Version | Status |
|---|---|
| `0.1.x` | active |

## Threat model

### What walletrs holds

- **Customer-managed keys.** xpub + fingerprint + derivation path. Public material only — leaking these doesn't expose funds.
- **System-managed keys.** xpub + fingerprint + derivation path **plus** mnemonic + xpriv + account-level tpriv, all wrapped under `WALLETRS_KEK` via ChaCha20-Poly1305 envelope encryption. Funds are at risk only if both the storage tier and the KEK are compromised.
- **Wallet state.** BDK file-store: chain state, transaction history, address index. No private material; useful to an attacker mostly for transaction analysis.
- **PSBTs in flight.** Not signed → unsigned tx + outputs. Signed → partial signatures collected during a multisig ceremony.

### Tiers of access and what they expose

| Access an attacker has | What's exposed |
|---|---|
| **gRPC port without bearer token** | Nothing — auth is enforced. Only `Ping` answers. |
| **gRPC port with bearer token** | Full wallet ops, including signing under system-managed keys. Treat the token as a key-equivalent. |
| **Filesystem read on the storage tier** (local FS or stolen S3 dump) | Customer xpubs, wallet metadata, encrypted system-key blobs. Without the KEK, system private material stays opaque. |
| **Filesystem read + KEK** | Full system-key recovery. Funds at risk. |
| **Code execution on the walletrs host** | Same as filesystem + KEK; effectively total compromise of system-managed funds. |

### Where each secret lives

- **`WALLETRS_AUTH_TOKEN`** — env var on the walletrs process. Rotate by regenerating the env value and restarting; clients must update their bearer in lockstep. Constant-time comparison via `subtle::ConstantTimeEq`.
- **`WALLETRS_KEK`** — env var on the walletrs process. Use a secrets manager (AWS KMS / GCP KMS / Vault / 1Password Connect) and inject at start. Don't bake into images, don't commit to git.
- **System-managed private material** — encrypted at rest in the storage tier; only decrypted in-process during signing.

### Plaintext gRPC

walletrs does not terminate TLS. Plaintext gRPC over a non-loopback network is a credential-exposure bug. Two acceptable deployment shapes:

1. **Loopback-only** (`WALLETRS_HOST=127.0.0.1`) with the client on the same host, OR
2. **Behind a TLS-terminating reverse proxy** (Caddy / Traefik / nginx) so the wire to clients is encrypted.

Internet-exposed plaintext gRPC ships your bearer token to anyone on the path.

### What is **not** in the threat model

- **Malicious upstream code.** We trust BDK, rust-miniscript, the `bitcoin` crate, the AWS SDK, Liana, and tonic. A supply-chain compromise of any of those is a separate problem class.
- **A compromised host kernel or hypervisor.** If your VM is rooted, walletrs cannot defend itself.
- **Operator error around backups or KEK custody.** Lose the KEK, lose access to system-managed funds — there's no recovery path.
- **Hardware-wallet device security.** HWW signing happens client-side; walletrs only ingests pre-signed PSBTs.

## Hardening checklist

For production deployments:

- [ ] `WALLETRS_AUTH_TOKEN` set explicitly, stored in a secrets manager, rotated when staff churns.
- [ ] `WALLETRS_AUTH_DISABLED` is **not** set.
- [ ] `WALLETRS_KEK` is provided by a secrets manager and never in shell history, image layers, or git.
- [ ] gRPC reachable only via a TLS-terminating reverse proxy with a valid certificate.
- [ ] Storage tier (local volume or S3 bucket) has access policies scoped to the walletrs identity.
- [ ] Container or service is not running as root inside its sandbox.
- [ ] Pin a specific image tag (`ghcr.io/n1rna/walletrs:0.1.0`), not `:latest`.
- [ ] Backups of the KEK and storage tier exist and are tested.
- [ ] Logs are shipped to a place an attacker on the box can't easily wipe.

## Known absences

- No append-only audit log. Every mutation prints a log line, but the logs themselves are mutable.
- No native TLS. Reverse-proxy required for non-localhost.
- No KEK rotation primitive. Manual procedure documented in [`docs/OPERATING.md`](docs/OPERATING.md).
- No rate limiting. If exposed publicly, front with a proxy that can shed load on the bearer-token-failure path.

These are tracked as v0.x roadmap items. None of them prevent shipping today, but operators should know they're absent.
