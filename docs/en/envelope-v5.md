# Envelope v5 Specification

> 🌐 日本語版: [docs/envelope-v5.md](../envelope-v5.md)

The v5 storage format for Arpass. Defines the encrypted envelope structure that each device assembles in the browser, writes to Arweave, and reconstructs on decryption.

There are **three major changes** from v4:

1. **Outer AES-GCM layer** — the entire envelope JSON is additionally encrypted before being written to Arweave (hides the JSON structure from Arweave scrapers)
2. **Signing key not stored** — the ECDSA P-256 keypair is deterministically derived from the MEK (no "private key" or "public key" is written to Arweave)
3. **No vault-id on the server** — the Cloudflare KV key is `H(publicKey)`, and the `X-Vault-Id` header is removed

Everything else (2-of-3 key management, PBKDF2-SHA256 600K, AES-256-GCM, HKDF-SHA256, Recovery Secret format) is inherited from v4.1.

---

## Overview

`vault` (= the user's plaintext list of entries) is converted into an **envelope** as follows, then outer-encrypted before being saved to Arweave.

```
plaintext vault JSON
    │
    ├─► AES-256-GCM(MEK, iv) ──► body ciphertext (with padding)
    │
    └─► MEK is held via 3 wrap routes:
         • wraps.pr   = AES-GCM(MEK, KEK(P, R))            1
         • wraps.pk[] = AES-GCM(MEK, KEK(P, K_device))     per device
         • wraps.kr[] = AES-GCM(MEK, KEK(K_device, R))     per device

After the envelope JSON is complete:
    │
    └─► AES-256-GCM(HKDF(vault-id), iv) ──► written to Arweave
                                            (the bytes appear as random)
```

The vault-id never reaches the server; it is derived from the Recovery Secret on the device.

---

## JSON structure (inner — after decryption)

```jsonc
{
  "v": 5,
  "createdAt": 1730000000000,
  "wraps": {
    "pr":  { "iv": "...", "ct": "..." },
    "pk":  [ { "deviceId": "...", "iv": "...", "ct": "..." }, ... ],
    "kr":  [ { "deviceId": "...", "iv": "...", "ct": "..." }, ... ]
  },
  "salt": {
    "p":  "base64url(16 bytes)",   // PBKDF2 salt for password
    "r":  "base64url(16 bytes)"    // KEK info-label salt for recovery
  },
  "credentials": [
    { "deviceId": "...", "credentialId": "base64url(...)", "createdAt": ..., "name": "iPhone 15" }
  ],
  "body": {
    "iv": "base64url(12 bytes)",
    "ct": "base64url(padded ciphertext + AES-GCM tag)"
  }
}
```

### Fields removed from v4

- `meta.vaultId` — replaced by H(publicKey) on the server side
- `signing.publicKey` / `signing.encrypted` — derived from HKDF(MEK) at runtime; not stored

---

## Outer encryption layer (the blob written to Arweave)

The inner envelope JSON is itself encrypted before being placed on Arweave.

### Key derivation

```
outerKey = HKDF-SHA256(
  ikm  = vault-id (32 bytes, derived from Recovery Secret),
  info = "arpass:outer-envelope:v5",
  L    = 32
)
```

The `vault-id` is never transmitted to any server. It is derived locally from the Recovery Secret each session.

### Write procedure

```
inner_json   = canonical JSON (inner envelope)
outer_iv     = randomBytes(12)
outer_ct     = AES-256-GCM(outerKey, outer_iv, inner_json)
arweave_blob = outer_iv || outer_ct  (= 12 bytes IV || ciphertext || tag)
```

Write `arweave_blob` to Arweave via Turbo bundling.

### Read procedure

```
arweave_blob = fetch from Arweave
outer_iv     = arweave_blob[0..12]
outer_ct     = arweave_blob[12..]
inner_json   = AES-256-GCM-decrypt(outerKey, outer_iv, outer_ct)
```

### Purpose of this layer

- **JSON structure hiding**: An Arweave indexer scraping by data shape cannot identify Arpass envelopes. Field names like `wraps`, `body`, `credentials` are not externally visible.
- **Algorithm name hiding**: Constants like `"v":5` and `"AES-256-GCM"` are not visible from outside.
- **Defense in depth**: Even if there were a future hypothetical bug in the inner AES-GCM, the outer layer also requires the vault-id-derived key.

---

## Key derivation

### 1. Password material `pMat`

```
pMat = PBKDF2-SHA256(
  password = master_password (UTF-8 NFC),
  salt     = salt.p,
  iter     = 600000,
  L        = 32
)
```

### 2. Passkey material `kMat`

WebAuthn PRF extension is used to obtain a 32-byte output from the device's authenticator.

```
prfInput = "arpass:prf:v1:" || H(salt.p)
kMat     = WebAuthn-PRF(credentialId, prfInput)
```

`kMat` differs per device (since the Passkey credential is bound to the Secure Enclave). This is the basis of "device authentication".

### 3. Recovery material `rMat`

```
rMat = HKDF-SHA256(
  ikm  = decode_base32(recovery_secret_string),  // 20 bytes (160 bits)
  info = "arpass:rmat:v1",
  L    = 32
)
```

The recovery_secret_string is the user-facing format like `RS1-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` (8 groups of 4 base32 characters).

### 4. KEK derivation

For each wrap, a separate KEK is derived using HKDF with a wrap-specific info label. This way the same input materials produce different keys for different wraps.

```
KEK_pr = HKDF-SHA256(ikm = pMat || rMat, info = "arpass:kek:pr:v1", L = 32)
KEK_pk = HKDF-SHA256(ikm = pMat || kMat, info = "arpass:kek:pk:v1:" || deviceId, L = 32)
KEK_kr = HKDF-SHA256(ikm = kMat || rMat, info = "arpass:kek:kr:v1:" || deviceId, L = 32)
```

The `deviceId` in the info label ensures that pk/kr wraps are also unique per device.

### 5. wrap

Each wrap encrypts the same MEK using its corresponding KEK.

```
wraps.pr   = AES-256-GCM(KEK_pr, iv_pr, MEK)
wraps.pk[i] = AES-256-GCM(KEK_pk_i, iv_pk_i, MEK)
wraps.kr[i] = AES-256-GCM(KEK_kr_i, iv_kr_i, MEK)
```

### 6. Body encryption

```
body.iv = randomBytes(12)
body.ct = AES-256-GCM(MEK, body.iv, padPlaintext(canonical(vault_entries)))
```

For the padding scheme, see "Size padding" below.

### 7. Signing key (new in v5 — not stored on Arweave)

The API request signing key is deterministically derived from the MEK each session, eliminating the need to write any private key data to Arweave.

```
seed       = HKDF-SHA256(ikm = MEK, info = "arpass:signing-seed:v5", L = 32)
privateKey = clamp_p256(seed)   // mod n with P-256 curve order
publicKey  = privateKey * G     // P-256 base-point multiplication
```

Web Crypto API cannot perform raw point multiplication, so `@noble/curves` is used. Public/private keys are reconstructed in memory at every unlock from the same MEK; nothing is persisted.

The H(publicKey) value (= account identifier on the server) is what Cloudflare KV uses as the lookup key.

---

## Size padding (Phase 5.2 revised)

To prevent the entry count from being inferred from the body `c` size, content is padded to **discrete buckets + jitter** before AES-GCM encryption.

```
buckets = [120 KiB, 240 KiB, 480 KiB, 960 KiB, 4 MiB]
jitter  = random addition in 0..8 KiB
target  = smallest bucket s.t. plaintext.length + 16 <= bucket
        + jitter
padded  = plaintext || 0x80 || 0x00 * (target - plaintext.length - 17)
```

On decryption, the trailing `0x80` marker is found by backward scan to strip the padding (the zero-fill from the jitter does not affect decryption since the scan continues through zeros).

Because of the outer encryption layer, the final blob size on Arweave is in the range `12 + (bucket + jitter) + 16`.

### Why the minimum bucket is 120 KiB (Phase 5.2)

The 120 KiB minimum bucket is designed to **simultaneously achieve three goals**.

| Goal | Old [4 KiB, ...] | New [120 KiB, ...] |
|---|---|---|
| (a) Fingerprint resistance | tx size could extract Arpass vaults in one pass | All writes ≥ 120 KiB are indistinguishable from other Arweave traffic |
| (b) Avoid Turbo free-tier abuse | 4 KiB writes fit in Turbo's free quota (107520 B / 105 KiB), so all Arpass users wrote for free = AUP-violation risk | All writes definitely exceed the free quota and enter Turbo's paid tier |
| (c) Size hiding | Bucket changed often as entries grew, leaking entry count | Bucket changes are rare, so entry-count growth is undetectable from outside |

The old values [4 KiB, 16 KiB, 64 KiB, 256 KiB, 1 MiB, 4 MiB] existed right after the v5 cutover (Phases 5.0–5.1), but they simultaneously broke (a) and (b). Phase 5.2 was a full revision.

The jitter (`PAD_JITTER_BYTES = 8 KiB`) provides additional defense by making tx sizes vary even for the same user's consecutive writes, so "size X = Arpass" fingerprinting cannot establish.

---

## Phase 5.3 revisions: client resilience and server anonymization

Four important improvements added after v5 was published.

### 5.3-A: Optimistic concurrency control (`expectedLatestTxId`)

Prevents a later save with stale data from overwriting a newer save during multi-device editing.

```
1. On unlock, fetch latestTxId from the server and store in session.
2. saveVault: signedFetch("/api/save", { ..., expectedLatestTxId: session.latestTxId })
3. Server-side: if it does not match the current latestTxId in KV, return 409 version_conflict.
4. Client-side: on 409, show toast "Updated on another device. Please unlock again." + keep the edit pending (do not discard).
```

Server-side `_safeOptLock(expected, current)` performs the comparison. If `expected === undefined`, treat as an old client and warn only (compatibility).

### 5.3-B: localStorage envelope cache (cache-first fetch)

Designed so the user is not made to wait 30 seconds during the bundling 0–2-minute window (when Turbo CDN has received but arweave.net still returns 404).

```
fetchEnvelope():
  1. localStorage cache lookup (effectively synchronous, immediate)
     a. hit → return immediately + fire a network probe in the background (background fresh)
     b. compare cache's latestTxId to server's latestTxId; update if different
  2. cache miss → network fetch (Turbo + arweave.net in parallel, 30s timeout)
```

Cache key: `arpass.cache.envelope.<txid>`, value: outer-encrypted blob (= the plaintext vault is **not** in localStorage).
The cache persists even after the client returns to a locked state, so the next unlock's initial fetch is fast.
**The localStorage contents are also outer-encrypted**, so even browser-profile theft does not reveal the vault to anyone without the vault-id.

### 5.3-AA: Ephemeral session token (Stripe metadata anonymization)

Old design: passed `publicKeyHash` directly in Stripe Checkout's `metadata` → risk that a persistent Arpass identifier remains in Stripe's DB.

New design: issue a single-use 30-minute-valid token in Cloudflare KV; pass only the token in Stripe metadata. On webhook receipt, resolve from KV and consume (delete).

```
checkout.js (POST /api/checkout):
  sessionToken = randomBase64Url(32)  // 256-bit, 43 chars
  ARPASS_LEDGER.put(`checkout:${sessionToken}`, { publicKeyHash, pack, credits, createdAt },
                    { expirationTtl: 30 * 60 })  // KV-side auto delete
  form.append("metadata[sessionToken]", sessionToken)

webhook.js (POST /api/webhook/stripe):
  sessionToken = event.data.object.metadata.sessionToken
  data = ARPASS_LEDGER.get(`checkout:${sessionToken}`)
  ARPASS_LEDGER.delete(`checkout:${sessionToken}`)  // consume
  // credit the account
```

This means no persistent Arpass identifier remains in Stripe's DB.

### 5.3-J: Passkey hint + picker hybrid

When multiple Passkeys are registered for the same Relying Party, using only `allowCredentials = [{ id: hintId }]` causes lockout if the hint is gone or the user wants to choose a different Passkey.

```
authenticateWithPasskey(hint, options = {}):
  if hint && !options.forcePicker:
    allowCredentials = [{ id: hint }]    // 1 click (auto-fill)
  else:
    allowCredentials = []                 // full picker
```

Caller side: if the hint path fails (NotAllowedError, etc.), catch and re-call with `forcePicker: true`. The "Unlock with a different Passkey" UI button also calls the same function with `forcePicker: true`.

---

## Decryption logic

### Path AB: Master + Passkey (daily unlock)

```
1. Take pMat (PBKDF2 of master)
2. Take kMat (Passkey PRF) for this device
3. KEK_pk = HKDF(pMat || kMat, "arpass:kek:pk:v1:" || thisDeviceId)
4. MEK = AES-GCM-decrypt(KEK_pk, wraps.pk[i].iv, wraps.pk[i].ct)
   where i is this device's wrap entry
5. body_plaintext = AES-GCM-decrypt(MEK, body.iv, body.ct)
6. Strip padding → vault_entries
```

### Path AC: Master + Recovery (recovery on lost device)

```
1. pMat (PBKDF2 of master)
2. rMat (HKDF of decoded recovery secret)
3. KEK_pr = HKDF(pMat || rMat, "arpass:kek:pr:v1")
4. MEK = AES-GCM-decrypt(KEK_pr, wraps.pr.iv, wraps.pr.ct)
5. (proceed as Path AB from here)
```

### Path BC: Passkey + Recovery (Master forgotten)

```
1. kMat (Passkey PRF)
2. rMat (HKDF of recovery secret)
3. KEK_kr = HKDF(kMat || rMat, "arpass:kek:kr:v1:" || thisDeviceId)
4. MEK = AES-GCM-decrypt(KEK_kr, wraps.kr[i].iv, wraps.kr[i].ct)
5. (proceed as Path AB from here)
```

After the Master is reset via this path, the user is prompted to set a new Master and the wraps are rebuilt accordingly.

---

## Add device (`addDevice`)

When registering a new device to an existing vault:

```
Pre-conditions: at least one of Path AB/AC/BC succeeds (= this session has the MEK)
On the new device:
  1. Register a new Passkey (Touch ID / Face ID) → credentialId obtained
  2. Acquire kMat_new via PRF
  3. Build new wraps:
     • wraps.pk[new] = AES-GCM(MEK, KEK(pMat || kMat_new))
     • wraps.kr[new] = AES-GCM(MEK, KEK(kMat_new || rMat))
  4. Add credentials[new]
  5. saveVault: write the updated envelope to Arweave
```

The MEK itself is unchanged. Other devices' wraps are preserved.

---

## Change password (`changePassword`)

```
Pre-conditions: the unlocked session, plus the user-supplied Recovery Secret
  1. New pMat' = PBKDF2(new_password, salt.p)
  2. Rebuild wraps.pr with the new KEK_pr (uses pMat' || rMat)
  3. Rebuild wraps.pk[i] for THIS device with the new KEK_pk (uses pMat' || kMat for this device)
  4. wraps.kr[*] is unchanged (no Master factor in there)
  5. saveVault
```

Other devices' `wraps.pk` cannot be re-derived without the user re-entering the new Master on each device, so they continue working with the OLD Master temporarily. To propagate, the user must run "Change password" with the same new Master on each other device. (See the "Important if you use this on other devices" warning in Settings.)

---

## Recovery reissue

### Case A — keep MEK

Issue a new Recovery Secret but keep the existing MEK. Past Arweave envelopes can still be decrypted by anyone with the OLD Recovery + Master. Fastest, server-uninvolved (consumes 1 write).

```
  1. New rMat' from new Recovery Secret
  2. Rebuild wraps.pr with the new KEK_pr (uses pMat || rMat')
  3. Rebuild wraps.kr[*] for ALL devices with the new KEK_kr (uses kMat || rMat' per device)
  4. wraps.pk[*] is unchanged
  5. saveVault
```

### Case B — rotate MEK fully

Generate a new MEK, re-encrypt the body, issue a new Recovery, and migrate the server balance to a new account identifier. Past Arweave envelopes are permanently undecryptable by anyone without the OLD MEK. The OLD Arweave envelopes themselves remain forever (Arweave is immutable).

```
  1. Generate new MEK', new Recovery Secret, new salt.p, new salt.r
  2. New pMat (with the new salt.p), new rMat'
  3. Rebuild ALL wraps with MEK' (pr / pk[*] / kr[*])
  4. Re-encrypt body with MEK'
  5. Derive new signing key from HKDF(MEK')
  6. Server side: request migrate-balance from H(oldPublicKey) to H(newPublicKey)
  7. saveVault under the new account
```

After Case B:
- Other devices need Master + new Recovery on next unlock (Master + Passkey / AB path no longer works).
- Old Arweave envelopes remain forever, but only decryptable to anyone holding the OLD MEK.
- To protect passwords stored in the old envelopes, you must rotate them on each external site (outside Arweave).

---

## Compatibility

- The `v` field (`5`) is checked at decode time. v4 envelopes still on Arweave are handled by the legacy reader path defined in `envelope-v4.md`.
- The outer encryption is a v5 addition; v4 has only the inner.
- Both the writer and reader paths recognize v5 only since the v5-cutover commit; v4 → v5 migration is one-shot per vault.

---

## Related

- [crypto-rationale.md](crypto-rationale.md) — algorithm selection rationale (Japanese: [../crypto-rationale.md](../crypto-rationale.md))
- [arweave-tags.md](arweave-tags.md) — Arweave transaction tag schema (Japanese: [../arweave-tags.md](../arweave-tags.md))
- [envelope-v4.md](../envelope-v4.md) — v4 legacy spec (Japanese only)
