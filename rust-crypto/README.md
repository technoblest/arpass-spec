<!--
====================================================================
⚠️ AUTO-GENERATED MIRROR — DO NOT PR HERE

This file is automatically synced from the private arpass repo on every
release. Direct edits to this file will be overwritten.

Source: technoblest/arpass / rust-crypto/README.md
Mirror generator: scripts/generate-arpass-spec-mirror.mjs
====================================================================
-->

# arpass-crypto (Rust + WASM)

**Status**: Stage 2 (2026-06) — opaque-handle crypto core. 鍵は Rust 側の不透明ハンドル (`MekKey` / `K1Key` / `BekKey` / `OuterKey` / `RMatKey` / `EmpPrivKey` / `SigningKey`) としてのみ存在し、 AES-GCM wrap/unwrap・HKDF 派生・ECDSA 署名・ECIES unwrap を各ハンドルのメソッドで実行する。 JS 側 (vault-crypto.js / vault-client.js) の鍵関連 `crypto.subtle` はゼロ (SHA-256 digest のみ)。 envelope の高レベル orchestration は引き続き JS。

## What this is

Rust + WASM implementations of the cryptographic primitives used by Arpass:

| Primitive | Crate | Replaces |
|---|---|---|
| Argon2id | `argon2` 0.5 | `@noble/hashes/argon2` |
| SHA-256 | `sha2` 0.10 | `@noble/hashes/sha2` |
| HKDF-SHA256 | `hkdf` 0.12 | `@noble/hashes/hkdf` |
| ECDH P-256 | `p256` 0.13 | `@noble/curves/p256` |
| AES-256-GCM | `aes-gcm` 0.10 | `crypto.subtle` (WebCrypto) |
| random bytes | `getrandom` 0.2 | `crypto.getRandomValues` |

All from the RustCrypto org (= audited, industry-standard).

## Building (= CI only)

This crate is built by `.github/workflows/build-rust-crypto.yml` on every
push to `feat/rust-crypto`, `staging`, and `main`. The output WASM binary
+ JS glue is committed to `web/lib/rust-crypto/`.

### Local build (= if you have Rust + wasm-pack installed)

```sh
cd rust-crypto
cargo install wasm-pack    # one-time
wasm-pack build --target web --out-dir ../web/lib/rust-crypto --release
```

### Native tests

```sh
cd rust-crypto
cargo test
```

## Backward-compatibility (CRITICAL)

All outputs MUST be bit-identical to the previous noble-based implementations.
See `src/lib.rs` for per-primitive backward-compat notes.

Existing vault data on Arweave (= pre-Phase 7.4Z) must continue to decrypt
without re-encryption.

## Scope (Stage 2)

- **Primitives** (Argon2id / SHA-256 / HKDF / ECDH / AES-GCM) — pure functions, fuzz target を維持。
- **Opaque handles** — 鍵 struct を Rust 側で保持し、 JS には Box pointer (`JsValue`) のみ渡す。
  暗号 op はハンドルのメソッド経由。 raw 鍵バイト列が JS heap に出ない。 `Drop` trait で確定的 zeroize。
- vault-crypto.js / vault-client.js は WASM をロードしハンドル経由で全鍵操作を実行 (Rust 必須、 CryptoKey fallback なし)。
- envelope v7 の高レベル orchestration は JS のまま。
- mobile FFI/JNI bindings は未実装 (= 現状 web のみ、 同一 Rust core を将来 FFI で流用予定)。

## Future stages (= not implemented)

- iOS FFI / Android JNI bindings using same Rust core

## License

AGPL-3.0-or-later. リポジトリルートの [`LICENSE`](../LICENSE) を参照 (= AGPL-3.0 全文)。
