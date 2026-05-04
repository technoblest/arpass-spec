# Arweave Transaction Tag Specification

> 🌐 日本語版: [docs/arweave-tags.md](../arweave-tags.md)

Transactions written to Arweave by Arpass carry tags (key/value pairs). This document defines the tags applied and their respective anonymization policies.

In v4.1 (2026-04) and v5 (2026-04), the design evolved to **remove all ID-related information from plaintext tags**. This document describes the latest state as of v5. For differences from past formats (v3 and earlier), see the last section.

---

## Design goals

1. **Make it possible to find one's own vault transactions via GraphQL** — must be searchable by information only the user has (HMAC derived from Recovery Secret)
2. **Prevent third parties from identifying "which tx is from Arpass" at a glance via scanning** — no common identifier like `App-Name = "Arpass"`
3. **Do not expose vault contents (version, crypto algorithm, owner attributes, etc.) in tags** — write only inside the encrypted envelope blob
4. **Never expose vault-id on Arweave** (an invariant introduced in v4.1, further strengthened in v5)

---

## Applied tags (v5)

| Tag name | Value | Origin |
|---|---|---|
| `App-Name` | per-user anonymized value (see below) | Computed by client and included in the request |
| `Content-Type` | `application/octet-stream` | Fixed (v5: outer encryption hides JSON structure) |
| `Unix-Time` | epoch seconds | Server adds the write timestamp |

**Tags removed in v5**:

- `vault-id` — Plaintext tag emission stopped in v4.1 (removed from `tags` in `functions/api/write.js`)
- `Arpass-Phase` — Removed in v5 to prevent operational-information leakage (internal operations are managed only within KV)
- Arbitrary `Arpass-*` tags — No information that would make Arpass identifiable on Arweave is added

---

## Per-user anonymization of `App-Name`

Arweave's GraphQL has tag-based filtering, so using a fixed value like `App-Name = "Arpass"` would let an attacker get "the list of transactions for all Arpass users" with one query. To prevent this, `App-Name` uses **a value anonymized per user**.

```
appNameTag = base64url-truncate(
  HMAC-SHA256(
    key = recoveryMaterial,
    message = "arpass-app-name-tag-v1"
  ),
  16 chars  // base64url, ~96 bit
)
```

- The same Recovery Secret always derives the same `appNameTag`
- A different user's Recovery yields a different `appNameTag`
- Since it's HMAC, third parties without the Recovery cannot predict the value

→ **Only devices that know the same Recovery can discover each other's tx**. At the same time, enumerating all transactions of the entire service is difficult.

---

## Meaning of Content-Type (v5 change)

Up through v4.1 we used `application/json`, but in v5 changed to **`application/octet-stream`**.

Reason: in v5 we further encrypt the envelope JSON via the [outer AES-GCM layer](./envelope-v5.md), so the bytes on Arweave appear as completely random. Claiming `application/json` would give attackers a hint of "should be JSON → analyze the structure to identify Arpass", so we switched to `octet-stream` to correctly match the actual content.

In Arweave explorers like ViewBlock, it will be displayed as "unknown binary data" (also matching our intent).

---

## Information not exposed

Tags that are **intentionally not added**:

| Item | Reason |
|---|---|
| envelope version (`v: 5`) | To anonymize the format, written only in the inner (after outer-decryption) JSON |
| crypto algorithm names | Same as above |
| Device count, user attributes | Never leaked externally |
| User identifiers (email, name, etc.) | Even the server doesn't have them, so naturally not exposed |
| `vault-id` | Removed from plaintext tags in v4.1, prohibition continued in v5 |
| Operational info like `Arpass-Phase` | Operational implementation details not exposed externally |
| `publicKey` / `H(publicKey)` | The key in server KV, but not exposed on Arweave |

---

## Server-side tag handling

When the server receives a write request (`/api/write`), in addition to the tags sent by the client, it **always adds**:

- `Content-Type` — fixed at `application/octet-stream`
- `Unix-Time` — from server time

In the `tags` sent by the client, **only `App-Name`** carries meaning. The server forwards it as-is, without overwriting.

**An important change in v5**: client authentication is via `X-Public-Key` header + ECDSA signature, and the server derives the KV key `H(publicKey)` from the authenticated publicKey for balance management. It never receives `vault-id` and never adds it to Arweave tags.

---

## Legacy values (history)

For compatibility, past formats had the following values:

| Version | App-Name | Removal |
|---|---|---|
| v3 and earlier | Fixed `"Arpass-Vault"` | Migrated to per-user anonymization in v4.0 |
| v4.0 | Both per-user anonymized and legacy value searchable | `LEGACY_APP_NAME = "Arpass-Vault"` fallback completely removed in v4.1 |
| v4.1 / v5 | Per-user anonymized only | (current) |

The `vault-id` tag was also added in plaintext by the server up through v4.0, but was removed in v4.1.

The reasons for these removals and detection methods are detailed in `docs/security-baseline.md` on the `arpass` repository side (the public portion is not included in `arpass-spec`).
