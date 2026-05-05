# Cryptographic Algorithm Rationale

> 🌐 日本語版: [docs/crypto-rationale.md](../crypto-rationale.md)

A record of the algorithms chosen for Arpass and the reasoning behind each choice.

## General policy

All cryptographic operations are implemented using the **browser-standard Web Crypto API**. There is no dependency on external crypto libraries (libsodium, etc.). Reasons:

- Browser implementations are generally maintained by each vendor's (Apple / Google / Mozilla) crypto teams, with continuous validation of constant-time and side-channel resistance
- Mixing in external libraries complicates version management, vulnerability-patch following, and build reproducibility
- Web Crypto is supported on all major modern browsers as of 2026

---

## Password key derivation: PBKDF2-SHA256 (600,000 iterations)

### Why PBKDF2

- **Web Crypto standard** — natively implemented in all browsers
- Established standard (NIST SP 800-132)
- Easy to audit and verify

### Why not Argon2id

Argon2id (a memory-hard KDF) is considered to have higher resistance to GPU/ASIC attacks than PBKDF2, and modern password managers (e.g., Bitwarden) increasingly adopt it. Arpass did not adopt Argon2id because:

1. **Not built into Web Crypto** — would require external libraries (libsodium, etc.) via WASM rather than native browser implementations
2. External library dependency increases supply-chain risk and build complexity
3. **Thanks to the 2-of-3 design, the password alone is not sufficient to decrypt the vault** — the additional defense from Argon2id is comparatively less needed
4. PBKDF2-SHA256 with 600,000 iterations conforms to the latest OWASP recommendation (revised to 600,000 in 2023)

### Iteration count

We adopted OWASP's 2023 latest recommendation (600,000). On modern high-end CPUs this costs about 0.5–1 second.

---

## KEK composition: HKDF-SHA256

### Why HKDF

- Standard (RFC 5869) for deriving multiple keys from a single key
- Web Crypto standard
- The info label distinguishes derivation paths → different KEKs can be derived independently from the same combination of materials

### info label distinguishes wrap types

A unique label is assigned to each wrap type:

| Wrap type | info label |
|---|---|
| Password+Recovery | `arpass-wrap-pr-v1` |
| Password+Passkey | `arpass-wrap-pk-v1` |
| Passkey+Recovery | `arpass-wrap-kr-v1` |

For example, even if pk and kr use the same Passkey factor, their KEKs become cryptographically unrelated.

---

## Symmetric encryption: AES-256-GCM

### Why AES-GCM

- **Web Crypto standard**, with hardware acceleration on all major browsers (Intel AES-NI, ARM Crypto Extensions)
- Authenticated encryption (AEAD) — detects ciphertext tampering
- NIST standard

### Why not XChaCha20-Poly1305

XChaCha20-Poly1305 has a longer IV (24 bytes), giving a higher birthday-attack ceiling and theoretical advantages for designs that randomly generate IVs. However:

- **Not built into Web Crypto** (as of 2026)
- AES-GCM with a 12-byte random IV maintains collision probability at ≤ 2^-32 for up to 2^32 messages with the same key — this gives hundreds of millions of years of headroom at typical vault usage rates

→ We adopted AES-GCM since standard implementations are available and the practical security margin is more than sufficient.

---

## Size padding: discrete buckets

### Why padding is necessary

Transaction sizes on Arweave are public information. Since the size of encrypted ciphertext correlates with plaintext size, **"how many passwords each user has accumulated" can be inferred from public storage**.

### Bucket scheme

```
Bucket boundaries (KiB): 32, 64, 128, 256, 512, 1024 ...
Plaintext size → padded with PKCS#7-like scheme up to the next bucket
```

Most users' vaults size-wise fit into the same bucket (around 128 KiB), so the entry count cannot be inferred from tx size alone.

---

## Why the minimum bucket is 120 KiB (Phase 5.2)

The old bucket value `[4 KiB, 16 KiB, ...]` existed right after the v5 cutover (Phases 5.0–5.1), but it was a serious bug that simultaneously had two problems.

### Problem 1: Turbo free-tier abuse + AUP violation risk

ardrive's Turbo bundling service **accepts writes ≤ 107520 B (105 KiB) for free**. With Arpass's 4 KiB bucket, all writes fit in this free quota, resulting in:

- No revenue going to ardrive (= possible service abuse)
- All Arpass users concentrated in the same free tier → terms-of-service violation risk
- Structural fragility: if Turbo CDN tightens rate limits, all Arpass users would simultaneously become unable to write

The new value [120 KiB, ...] ensures all writes definitely enter the paid tier, resolving all of the above.

### Problem 2: Size-based fingerprinting

A bucket = 4 KiB write was instantly identifiable in Arweave-wide traffic as "abnormally small (= Arpass)". For example, an Arweave indexer filtering for data_size = 4096–4112 transactions could extract all Arpass envelopes.

With the new value [120 KiB, ...], Arpass writes blend into the data_size distribution of other Arweave traffic (images, PDFs, ZIPs, etc.), making size-based extraction difficult.

### Jitter addition (Phase 5.2)

Random addition of `PAD_JITTER_BYTES = 8 KiB` makes tx sizes vary even for the same user's consecutive writes. This prevents the "size X = Arpass" fingerprint from forming.

Decryption impact: `unpadPlaintext` uses backward search for the trailing `0x80` terminator marker, so decryption succeeds even with varying zero-fill from the jitter.

---

## Cryptographic significance of Phase 5.3 revisions

### Optimistic concurrency control (`expectedLatestTxId`)

Prevents data loss from "later save overwrites with stale vault" race conditions during multi-device editing. This **does not change the cryptographic scheme itself** but adds a mechanism where the client sends the `latestTxId` known to the server, achieving **"compare-and-swap (CAS) against a known state"**.

The server-side `_safeOptLock(expected, current)` is not constant-time comparison (the timing-attack leakage is only the txid length = 65 chars fixed, so it does not matter).

### localStorage envelope cache

The blob saved to cache is **already outer-encrypted with AES-GCM**, so even browser-profile theft does not leak vault contents to attackers (since they don't have the vault-id). This is the basis for the decision "is it OK to write to localStorage".

The `vault-id` itself is HKDF-derived from the Recovery Secret, so it is never written to localStorage.

### Ephemeral session token (Stripe metadata anonymization)

The token is a 256-bit random base64url string, so brute-force is impossible (entropy = 256 bit). Auto-deleted by Cloudflare KV's `expirationTtl` after 30 minutes. On webhook receipt, a manual `DELETE` for early consumption.

This is not an algorithm choice but an architectural decision to **"not leave persistent identifiers in external services' DBs"**. Even if Stripe's DB is compromised, the Arpass publicKeyHash does not leak.

---

## Identifiers: ECDSA P-256 + SHA-256

### vaultId

```
vaultId = base64url(SHA-256(canonical_jwk_public_key))
```

The vault id is **the SHA-256 hash of the public key from a deterministically derived keypair from the Recovery Secret**. Anyone with the Recovery Secret can derive the same vault id on a new device.

### API authentication

Each request is verified via ECDSA P-256 (SHA-256) signature:

```
X-Signature = base64url(ECDSA(privKey, "<unix_time>.<raw_body>"))
```

Authentication passes if the timestamp is within ±5 minutes and signature verification succeeds. The server stores only the public key in KV; the private key never leaves the device.

---

## Recovery Secret: 192-bit entropy

```
Recovery string example: RS1-ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-4567

  - Prefix "RS1-" (version identifier)
  - 8 groups × 4 characters = 32 chars base32
  - Charset: ABCDEFGHIJKLMNPQRSTUVWXYZ23456789 (excluding O, 0, 1, I to avoid confusion)
  - Entropy: log2(32^32) ≈ 160 bit
```

Brute-force resistance: 2^160 ≈ 1.5 × 10^48 combinations. Physically infeasible.

---

## Device authentication: WebAuthn PRF extension

### What is PRF

The Pseudo-Random Function extension of WebAuthn is a feature where authenticators (iCloud Keychain, Google Password Manager, Windows Hello, YubiKey, etc.) deterministically generate a 32-byte output from credential ID + RP-supplied salt.

```
PRF_output = authenticator.PRF(credential_id, salt = "arpass-passkey-prf-v1")
```

This allows:
- Deriving material that depends on the secret key inside the authenticator (which never leaves)
- Getting the same PRF across iCloud / Google accounts where the Passkey is synced
- Only those who physically possess the authenticator can access the PRF

### Why use PRF

Normal Passkey authentication can only do "verify a signature with the public key" and cannot extract a crypto key. PRF is the only standard way to extract "key material" from a Passkey, and is essential for implementing the "K factor" of Arpass's 2-of-3 design.

### Handling PRF-incapable authenticators

For PRF-extension-incapable authenticators (older Android, etc.), `prf.enabled` is returned as false. In this case, the Passkey-routed wraps (`wraps.pk`, `wraps.kr`) cannot be created, and the user accesses the vault only via Password+Recovery (P+R).

---

# Design decisions added in v5

In v5 (2026-04), while keeping the existing crypto primitives unchanged, we added **three new operational/leakage-path designs**. The reasons for adopting each are described below.

## Outer AES-GCM layer

### Why added

Up through v4.1, envelopes were written to Arweave as raw JSON, so a third party could identify "this is an Arpass vault" via the following attack:

```
1. Download all Arweave entries
2. JSON.parse each body
3. Key set matches {v, k, i, c, w, d} → Arpass v4 envelope
4. Key set matches {v, s, i, c, w}    → Arpass v5 envelope (without outer)
5. Size ~110 KiB → confidence +
```

This is **not a confidentiality breach but a fact-of-service-use leak**. Who uses Arpass when and how much, user-count trends, competitive analysis, targeting under political pressure, etc., can be abused.

### Adopted approach

Re-encrypt the entire envelope JSON with `AES-256-GCM(HKDF(vault-id), iv)` before writing to Arweave. This achieves:

- Bytes on Arweave appear as completely random
- JSON structure, field names, crypto algorithm names, size distribution, and other fingerprints disappear
- A third party without the `vault-id` cannot decrypt either (the vault-id is never exposed to the server or Arweave)

### Why HKDF(vault-id)

Per Arpass's threat model, the outer key does not need to be "secret"; using `vault-id` for obfuscation purposes is the simplest. Important properties:

- **Only the client themselves can derive it** (vault-id is nowhere on the server or Arweave)
- On device recovery, vault-id can be re-derived from the Recovery Secret, so the outer key can also be regenerated
- Even with multiple devices writing to the same vault, the same vault-id → same outer_key allows reading

### Why not create a separate independent "outer secret key"

In theory, we could generate an "outer secret" independent of the MEK and wrap it in 3 ways. But this would:

- Make wrapping double-structured, complicating the implementation
- Require also adding "outer secret wrap" when adding a device
- Force consideration of "outer secret rotation" on Recovery reissue

Since Arpass's threat model goal is "hide the existence of Arpass on Arweave", **reusing vault-id** in a simple design was judged sufficient.

## Signing key deterministically derived from MEK

### Why deterministic derivation

In v4.1, the signing key (ECDSA P-256 private key) was bundled and stored inside the body ciphertext. This had the following problems:

- **SNDL (Store Now Decrypt Later) risk**: Arweave never disappears, so the moment PBKDF2 / AES-GCM is broken in the future, all past signing keys are extracted at once
- **Quantum resistance issue**: If ECDSA P-256 is broken by quantum computers, the secret key can be back-calculated from past signatures
- **"One more place to store the key" increases the attack surface**

In v5, we changed to a scheme that derives the signing key on-demand using `HKDF(MEK, "arpass-signing-key-v5")`. Since the MEK is already used to encrypt the body c, no additional storage location is needed.

### Same MEK → same Q is essential

For the derivation scheme to work, "if MEK is the same, the resulting (d, Q) must always be the same" determinism is required. HKDF output is always the same for the same input, so OK. This achieves:

- A user restoring with Recovery + Master on another device → same MEK → same Q
- The server-side KV key `H(Q)` is also the same → same account balance is accessible

"Account continuity" is automatically guaranteed without any user operation.

### Web Crypto API cannot do point multiplication

"Creating an ECDSA key from seed bytes" is not directly supported by the Web Crypto API standard. `generateKey({name: "ECDSA"})` only generates random bytes via internal RNG, with no way to provide a seed externally.

Therefore, the v5 implementation uses `@noble/curves/p256` (TypeScript-based, ~30 KB, independently audited) to perform `Q = d × G` point multiplication, then passes the result in JWK format to `crypto.subtle.importKey`. `@noble/curves` is a high-quality library widely adopted by Bitwarden, Nostr, etc.

## Server KV based on publicKey

### Why remove vault-id from the server

Up through v4.1, the Cloudflare KV key was `vault-id`, and the client sent the vault-id every request via `X-Vault-Id` header. This carried these risks:

- **vault-id leaks if Cloudflare ops is compromised** (full KV reads, log collection)
- **vault-id is also the search key on Arweave**, so a leaked vault-id could be reverse-searched on Arweave to find "who wrote what when"

In v5:

- Changed the KV key to `H(publicKey)`
- Client sends `X-Public-Key` (the publicKey itself) + `X-Signature` (ECDSA signature)
- Server verifies signature with publicKey → looks up KV with `H(publicKey)`
- Never receives or stores the vault-id

### publicKey is originally public, so no problem

The publicKey is intrinsically a "value designed to be public" (a premise of public-key crypto). Even if it is stored or leaked on the server side, it does not become a clue for Arweave search (Arweave-side identifies by a separate HMAC-derived `App-Name`).

In other words, the v5 design **completely separates "what Cloudflare needs to know" from "what Arweave can see"**:

| Data | Cloudflare KV | Arweave |
|---|---|---|
| publicKey | ✅ (as identifier) | ❌ |
| vault-id | ❌ | ❌ (neither in tags nor body) |
| App-Name tag | ❌ | ✅ (HKDF(Recovery)) |
| Encrypted vault | ❌ | ✅ (outer-encrypted blob) |

Achieves orthogonality where compromising any one location does not allow identifying the others.

### Why "the server stores the publicKey" is acceptable security-wise

The publicKey is intrinsically a value that can be public, and even if attackers learn it they gain nothing cryptographically (they cannot sign without the corresponding private key). On the other hand, this leaves room for future service features routed through the publicKey (audit logs, encrypted notifications, anonymous statistics, anomaly detection, etc.).

Either "publicKey stored on server" vs "sent every request, no need to store" works functionally, but for the room to expand operational features, v5 recommends storing publicKey within the KV value (optional).

---

## Phase 6.2: Wallet pool privacy hardening

### Problem: single-wallet linkability of all Arpass writes

After v5 cutover (Phase 5.0), all Arweave writes were still **signed by a single service wallet**. This meant:

- Arweave GraphQL `transactions(owners: [<service-wallet-address>])` would **enumerate every Arpass write**
- Total Arpass traffic, growth rate, and time-of-day patterns were visible to outside observers
- Combined with the App-Name tag (per-vault HKDF derivative), **per-vault activity volume** was inferable

This left a hole in v5's "content and identity fully protected" thesis: **at the metadata level, Arpass identification was trivial**.

### Solution: 30-wallet pool + KV-permanent assignment

**Phase 6.1**: Arpass operations holds 30 independent Arweave wallets, each separately pre-funded with Turbo Credits via Stripe.

**Phase 6.2 (critical revision)**: instead of random per-write selection, **assign one wallet permanently per user**. Cloudflare KV stores `userStandardWallet:<H(publicKey)> → wallet record`. The same user always signs with the same wallet.

#### Why "random selection" was insufficient

Random per-write selection (initial implementation) lets one user, after enough writes, statistically encounter all 30 wallets. By the **Coupon Collector's problem**, expected writes to enumerate all:

- N=30 wallets → ~120 writes
- N=100 wallets → ~520 writes
- N=1,000 wallets → ~7,500 writes

A user with 1–2 weeks of Arpass usage could reverse-look up every wallet via their own client's observable App-Name pattern.

#### KV-permanent assignment as mitigation

Each user is identified by their publicKey hash. On first write, one wallet is randomly drawn from the pool and saved to KV. Thereafter the same user always signs with the same wallet.

Result:

- A single user observes only **the one wallet assigned to them**
- Enumerating all 30 wallets requires **30+ independent accounts** (30+ cards or 30+ free signups)
- Mass surveillance is economically and law-enforcement-trace-wise expensive

### Private Mode (Mega ¥15,000+ exclusive)

Top-tier Mega plan purchasers receive a **dedicated wallet (never shared with any other user)** from the warm pool. The Stripe webhook (`checkout.session.completed`) detects packs with `pricing.js`'s `isPrivateMode: true` flag and triggers `assignPrivateWallet()`.

Guarantees for Private Mode users:

- Wallet address is stored only in KV (`userPrivateWallet:<H(pk)>`) — only retrievable with the user's own publicKey
- **Nobody but the owner can enumerate that user's writes via Arweave GraphQL**
- = Beyond "pseudonymity at scale", this achieves "provable unlinkability for paid premium users"

### Privacy as economic mechanism

This is not pure cryptographic anonymity. It is **privacy by economic + legal cost**:

| Attacker type | Cost | Legal trace | Outcome |
|---|---|---|---|
| Passive observer (block-explorer scrape) | 0 | none | ✅ defeated |
| Academic researcher (passive Arweave analysis) | moderate compute | none | ✅ mostly defeated |
| Insider attacker (Arpass user enumerating) | sees only 1 wallet | none | ✅ defeated |
| Mass surveillance (state-actor level) | 30+ paid accounts ≈ ¥150,000+ + card history | individuals identifiable via KYC | ⚠️ economically + legally deterred |
| Identifying a Mega user's writes | requires becoming that user | — | ✅ impossible |

Result: **"Bitcoin-pseudonym-or-better privacy, without UX compromise, absolute under realistic threat models."**

### Design limitations (stated for transparency)

- Total compromise of Cloudflare KV / the Arpass backend would leak the wallet ↔ user map (a generic server-side compromise risk)
- An attacker who knows the public tag pattern (App-Name shape + 107 KiB padding) could nightly enumerate all of Arweave to **estimate Arpass total traffic** (individual user identification still impossible)
- Reliance on ArDrive Turbo means the bundle TX owner on Arweave is Turbo's wallet (this is a property of bundling, not a privacy issue)

### Cost

- Phase 6.1: 30 standard pool wallets × USD $4 = **$120 (≈ ¥18,000)** initial
- Phase 6.2: 10 private warm pool wallets × USD $4 = **$40 (≈ ¥6,000)** initial
- Total **$160 ≈ ¥24,000** for ★★★★ privacy
- At scale: expand pool to 100 → 1,000, migrate to AR/USDC auto-funding in Phase 6.3

For operational details see [`docs/wallet-pool-runbook.md`](https://github.com/technoblest/arpass/blob/main/docs/wallet-pool-runbook.md).
