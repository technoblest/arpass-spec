# Arweave Transaction Tag Specification

> 🌐 日本語版: [docs/arweave-tags.md](../arweave-tags.md)

Transactions written to Arweave by Arpass carry tags (name/value pairs). This document defines the tags applied and their respective anonymization policies.

In Phase 7.0w-AR (2026-05), **tag anonymization reached its final stage**. Until then, a fixed tag name `App-Name` was kept and only the value was per-user anonymized. The current design **randomizes both the tag name and the tag value per user**. No recognizable string remains on Arweave at all. This document describes the current state (Phase 7.x). For differences from past formats, see the last section.

---

## Design goals

1. **Make it possible to find one's own vault transactions via GraphQL** — must be searchable by information only the user has (key material derived from the Recovery Secret)
2. **Prevent third parties from identifying "which tx is from Arpass" at a glance via scanning** — no common identifier like `App-Name = "Arpass"`, and not even the tag name `App-Name` itself
3. **Do not expose vault contents (version, crypto algorithm, owner attributes, etc.) in tags** — write only inside the encrypted envelope blob
4. **Never expose vault-id on Arweave** (Phase 7.0w-AR abolished the vault-id concept entirely)
5. **Do not let the write kind (vault body / attached record) be inferred from tags** — the kind is conveyed to the server via the HTTP body, never as an Arweave tag

---

## Applied tags (current)

| Tag name | Value | Origin |
|---|---|---|
| `<anonymous tag name>` | `<anonymous tag value>` | Computed by the client and included in the request (both name and value derived from rMat) |
| `Content-Type` | `application/octet-stream` | Fixed by the server (outer encryption hides JSON structure) |
| `Unix-Time` | epoch seconds | Server adds the write timestamp |

Only the **single anonymous tag** carries meaning, and neither its name nor value is a recognizable string like `"App-Name"`. `Content-Type` and `Unix-Time` are generic Arweave-spec tags and carry no Arpass-specific information.

The server is conservative and strictly constrains client-supplied tags: tag names are ASCII alphanumerics plus `-_` only, name + value combined ≤ 64 characters, at most 4 tags. `Content-Type` / `Unix-Time` sent by the client are ignored.

---

## Randomizing both the name and value of the anonymous tag

### Why the name is also randomized

Arweave's GraphQL can filter by tag name as well as by tag value. Even if the value is per-user anonymized, if the tag **name** remains a fixed string like `App-Name`, an attacker can filter with `tags: [{ name: "App-Name" }]` and obtain the set of "txs with an App-Name tag" in a single query. This is a foothold for observing the overall traffic volume of Arpass users.

Phase 7.0w-AR closed this foothold by **deriving the tag name itself from rMat**. No tag name on Arweave contains a recognizable string such as `arpass` or `vault`.

### Derivation

The anonymous tag derives its name and value separately from the Recovery material `rMat` (a 32-byte value derived from the Recovery Secret via HKDF).

```
name  = base64url( HKDF-SHA256(
            ikm  = rMat,
            salt = "arpass-app-tag-name-v6",
            info = "app-tag-name" + tierSuffix,
            L    = 8 ) )                          // 8 bytes → 11 base64url chars

value = base64url( HKDF-SHA256(
            ikm  = rMat,
            salt = "arpass-app-tag-value-v6",
            info = "app-tag-value" + tierSuffix,
            L    = 16 ) )                         // 16 bytes → 22 base64url chars
```

- The name is 8 bytes (11 base64url chars), the value is 16 bytes (22 base64url chars). Neither has a fixed prefix; both look like fully random strings
- The same Recovery Secret always derives the same name / value (devices recovering or multiple devices can discover the same tx)
- A different user's Recovery yields a different name / value
- Since it is HKDF, a third party without the Recovery cannot predict the values

→ **Only devices that know the same Recovery can discover each other's txs.** At the same time, enumerating all transactions of the service is impossible even at the tag-name level.

### Per-tier tag separation (`tierSuffix`)

Appending `tierSuffix` to the `info` label makes the tag differ per membership tier even for the same user:

| tier | `tierSuffix` |
|---|---|
| legacy (no tier specified) | (empty string) |
| free | `::free` |
| paid | `::paid` |
| private | `::private` |
| corp (Business mode) | `::corp::<companyId>` |

When unlocking on a new device, the tier is unknown, so the client computes the tags for all tiers (legacy / free / paid / private, plus corp if known) and searches them in parallel in a single GraphQL query, adopting the latest tx.

---

## Meaning of Content-Type

`Content-Type` is fixed to `application/octet-stream`. Arpass additionally encrypts the envelope JSON with an [outer AES-GCM layer](./envelope-v5.md) before writing, so the bytes on Arweave look like fully random byte strings. Claiming `application/json` would give an attacker the hint "this should be JSON → analyze the structure and identify Arpass", so the value correctly matches the actual content as `octet-stream`.

Arweave explorers such as ViewBlock display it as "unknown binary data" (also intentional).

---

## Information not emitted

Tags intentionally **not** applied:

| Item | Reason |
|---|---|
| The tag name `App-Name` | A fixed-string tag name is a foothold for cross-cutting enumeration via GraphQL. Phase 7.0w-AR randomized the name itself |
| Envelope version (`v: 5`) | Written only in the inner (post outer-decryption) JSON to anonymize the format |
| Crypto algorithm names | Same as above |
| Write kind (vault body / record) | Not inferable from tags. Conveyed to the server via the `kind` field in the HTTP body |
| Number of devices, user attributes | Never leaked externally at all |
| User identifiers (email, name, etc.) | Not even the server holds them, so of course not emitted |
| `vault-id` | Abolished as a concept in Phase 7.0w-AR |
| Operational info such as `Arpass-Phase` | Operational implementation details are not exposed externally |
| `publicKey` / `H(publicKey)` | The server KV key, but not emitted to Arweave |

---

## Server-side tag handling

On receiving a write request (`/api/write`), the server **always adds** the following on top of the client-supplied tags:

- `Content-Type` — fixed to `application/octet-stream`
- `Unix-Time` — from server time

Of the `tags` the client sends, only the **single anonymous tag** carries meaning. The server forwards it as-is and does not overwrite. The write kind is received not as a tag but as the `kind` field in the HTTP body (to maintain anti-fingerprinting).

Client authentication uses the `X-Public-Key` header + an ECDSA signature; the server derives the KV key `H(publicKey)` from the authenticated publicKey to manage balances. It never receives `vault-id` and never adds it to Arweave tags.

---

## Legacy values (history)

For compatibility, past formats had the following:

| Version | Tag name | Tag value | Removed |
|---|---|---|---|
| v3 and earlier | fixed `App-Name` | fixed `"Arpass-Vault"` | value per-user anonymized in v4.0 |
| v4.0 | fixed `App-Name` | per-user anonymized + legacy value, both searched | legacy-value fallback removed in v4.1 |
| v4.1 / early v5 | fixed `App-Name` | per-user anonymized (HMAC-derived) only | name also randomized in Phase 7.0w-AR |
| Phase 7.0w-AR onward | randomized via rMat derivation | randomized via rMat derivation | (current) |

The `vault-id` tag was also added in plaintext by the server until v4.0, removed in v4.1, and the vault-id concept itself was abolished in Phase 7.0w-AR.

The reasons for these removals and the detection methods are detailed in `docs/security-baseline.md` on the `arpass` repository side (the public portion is not included in `arpass-spec`).
