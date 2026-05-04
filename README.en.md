# arpass-spec

**Arpass client-side cryptography code and specification — public portion.**

> 🌐 日本語版は [README.md](README.md) を参照してください。

This repository exists so third parties can independently verify the trustworthiness of [Arpass](https://arpass.io) (a zero-knowledge password manager run by Technoblest Inc., using Arweave permanent storage).

Anyone can verify at the code level whether the claim "**operations cannot see your passwords**" actually holds.

---

## What's in this repository

| Path | Contents |
|---|---|
| [`lib/vault-crypto.js`](lib/vault-crypto.js) | All cryptographic operations (v5 envelope construction/decryption, KEK derivation, outer AES-GCM, deterministic ECDSA key derivation from HKDF(MEK), Recovery Secret string format, etc.) |
| [`lib/vault-client.js`](lib/vault-client.js) | High-level vault operations (createVault / 3 unlock paths / saveVault / addCredential / changePassword / Recovery rotation Case A & B / Stripe Checkout) |
| [`lib/client-auth.js`](lib/client-auth.js) | API authentication (X-Public-Key + ECDSA signature), Arweave data fetching (Turbo + arweave.net in parallel, outer AES-GCM decryption), tx status (GraphQL + L1 status) |
| [`lib/vendor/noble-curves-and-hashes.mjs`](lib/vendor/noble-curves-and-hashes.mjs) | The required portions of @noble/curves v2 + @noble/hashes v2 bundled with esbuild into one file (~70 KB). Provides p256 / sha256 / hkdf / hmac / mod. MIT (Paul Miller). Required because the Web Crypto API cannot deterministically derive ECDSA P-256 keys from seed bytes. |
| [`lib/vendor/LICENSE-noble`](lib/vendor/LICENSE-noble) | Full @noble license text |
| [`docs/envelope-v5.md`](docs/envelope-v5.md) | (Japanese) **Current** v5 envelope JSON structure + outer encryption specification |
| [`docs/en/envelope-v5.md`](docs/en/envelope-v5.md) | English version |
| [`docs/envelope-v4.md`](docs/envelope-v4.md) | (Japanese, historical) v4 envelope spec — referenceable since past v4 envelopes remain on Arweave |
| [`docs/arweave-tags.md`](docs/arweave-tags.md) | (Japanese) Meaning and anonymization policy of Arweave transaction tags (v4.1 / v5) |
| [`docs/en/arweave-tags.md`](docs/en/arweave-tags.md) | English version |
| [`docs/crypto-rationale.md`](docs/crypto-rationale.md) | (Japanese) Rationale for the chosen algorithms (including v5 additions) |
| [`docs/en/crypto-rationale.md`](docs/en/crypto-rationale.md) | English version |

These alone are enough to fully trace "what Arpass encrypts in the browser and what it sends to the server."

---

## What is **NOT** in this repository (intentionally)

- **Server-side code** (`/api/*` Cloudflare Pages Functions) — by design the Arpass server only handles encrypted envelopes (opaque ciphertext) and anonymous IDs. The fact that the server cannot see plaintext is **verifiable from the client-side code alone**, so there is no need to publish the server implementation. Stripe Webhook, KV Ledger, and other operational logic are kept private.
- **Marketing pages and the entire UI** (`web/*.html`) — these are business assets and are not needed for technical verification.
- **Private keys and operational configuration** — the Turbo wallet, Stripe secrets, and other secrets are obviously not published.

---

## Trust model summary

Arpass uses a **"2-of-3 recovery"** key management scheme.

```
Out of three factors, any 2 can decrypt the vault:

  P  Master password   (memorized by the user)
  K  Passkey PRF       (device biometric)
  R  Recovery Secret   (stored on paper; QR-capable since Phase 4.95)

Three kinds of "wrap":

  wraps.pr   = AES-GCM(MEK, KEK(P, R))    1 per vault
  wraps.pk[] = AES-GCM(MEK, KEK(P, K))    1 per device
  wraps.kr[] = AES-GCM(MEK, KEK(K, R))    1 per device

Unwrapping any wrap yields the same MEK (Master Encryption Key).
Body ciphertext = AES-256-GCM(MEK, iv, vault_json), one per vault.

In v5, the entire envelope above is additionally encrypted with
AES-256-GCM(HKDF(vault-id), iv) before being written to Arweave (so
the bytes on Arweave look like completely random bytes).
```

What the server (Cloudflare KV) can see (v5 onwards):
- The user's public key (ECDSA P-256 — a value designed to be public)
- Balance information (credit count)
- Operational statistics like write counts

What does **NOT** exist on the server:
- vault-id (fully removed server-side in v5 — even compromising Cloudflare ops would not reveal it)
- ciphertext / encrypted envelopes (written directly to Arweave; server does not relay)
- Any of the Master password / Passkey PRF / Recovery Secret material

→ **The MEK exists only on the device** and never reaches the server.
See [`docs/envelope-v5.md`](docs/envelope-v5.md) (Japanese) or [`docs/en/envelope-v5.md`](docs/en/envelope-v5.md) (English) for details.

---

## Algorithms used

| Purpose | Algorithm | Parameters |
|---|---|---|
| Password key derivation | PBKDF2-SHA256 | 600,000 iterations |
| KEK derivation | HKDF-SHA256 | 32-byte info label per wrap |
| Symmetric encryption | AES-256-GCM | 12-byte IV, 16-byte tag |
| Device authentication | WebAuthn PRF extension | 32-byte PRF output |
| API signing | ECDSA P-256 (SHA-256) | per-vault keypair |
| Recovery string | base32, 160-bit entropy | 8 groups of 4 characters (RS1- prefix, QR-capable since Phase 4.95) |
| Signing key (v5) | ECDSA P-256, deterministically derived via HKDF(MEK) | Not stored on Arweave; re-derived each session |
| Outer encryption (v5) | AES-256-GCM, HKDF(vault-id) | Hides JSON structure on Arweave |

Everything is implemented with the **browser-standard Web Crypto API**. No dependency on external crypto libraries.

For the rationale, see [`docs/crypto-rationale.md`](docs/crypto-rationale.md) (Japanese) or [`docs/en/crypto-rationale.md`](docs/en/crypto-rationale.md) (English).

---

## License

[GNU Affero General Public License v3.0](LICENSE).

If you operate a derivative service publicly, you must also make the source code of that derivative server available to its users (AGPL's network use clause).

Non-commercial, private verification, and audit uses are freely permitted under the standard AGPL terms.

---

## Contact

- Issues: this repository's GitHub Issues
- Commercial licensing / inquiries: [support@arpass.io](mailto:support@arpass.io)
- Service: [arpass.io](https://arpass.io)
- Operator: [Technoblest Inc.](https://technoblest.com)
