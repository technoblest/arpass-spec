<!--
====================================================================
⚠️ AUTO-GENERATED MIRROR — DO NOT PR HERE

This file is automatically synced from the private arpass repo on every
release. Direct edits to this file will be overwritten.

Source: technoblest/arpass / docs/rust-crypto-stage1.md
Mirror generator: scripts/generate-arpass-spec-mirror.mjs
====================================================================
-->

# Rust crypto core — Stage 1 (= primitives only)

**Status**: ✅ **Stage 1 完成** (2026-06-04) — Argon2id + HKDF + SHA-256 を Rust + WASM 化、 staging で実機検証 OK。 残り: user flow 全検証 → main マージ。
**Branch**: `feat/rust-crypto`
**Rollback tag**: `staging-pre-rust-2026-06-04` → `dae3c3b`

## What this is

User had asked (= 2026-06-04 session) to make staging a "Rust version".
We agreed on Stage 1 scope: replace the 5 crypto primitives with Rust + WASM,
keep envelope orchestration in JS.

Stage 1 does NOT:
- Replace envelope v7 logic (= vault-crypto.js high-level flows stay in JS)
- Replace vault-client.js
- Add mobile FFI/JNI bindings

It DOES:
- Replace `@noble/hashes/argon2` (= Argon2id KDF) with `argon2` crate
- Replace `@noble/hashes/sha2` with `sha2` crate
- Replace `@noble/hashes/hkdf` with `hkdf` crate
- Replace `@noble/curves/p256` (= ECDH) with `p256` crate
- Replace `crypto.subtle` AES-GCM with `aes-gcm` crate

## Why this might matter

| Benefit | Real impact |
|---|---|
| Audit-aligned crypto primitives | RustCrypto org maintenance + security history |
| Type-safe primitive boundaries | Rust compile-time checks for length/format mismatches |
| Speed (= 4 of 5 primitives were pure-JS via noble) | Argon2id especially: 1-3 sec → 0.1-0.5 sec |
| Mobile preparation | Same Rust core compiles to FFI/JNI later (= Stage 4) |
| Audit-aligned crypto primitives | RustCrypto org maintenance + security history |

| Drawback | Mitigation |
|---|---|
| ~150-300 KB WASM bundle added | gzipped + lazy-load on vault unlock |
| AES-GCM via WASM 5-15% slower than WebCrypto native | Negligible at envelope size |
| Build complexity | CI handles it (build-rust-crypto.yml) |

## Current files

```
rust-crypto/
├── Cargo.toml                 # crate manifest
├── src/lib.rs                 # 5 primitives + tests
├── README.md                  # build/usage docs
└── .gitignore

.github/workflows/
└── build-rust-crypto.yml      # CI: cargo test + wasm-pack build + commit

web/lib/rust-crypto/           # 🆕 (= CI-generated, not in source)
└── arpass_crypto.{wasm,js}    # built artifact, committed back

docs/
└── rust-crypto-stage1.md      # THIS FILE
```

## Backward compatibility (= MUST)

Stage 1 changes the implementation but NOT the on-wire format.

For every primitive, the same inputs must produce bit-identical outputs.
Otherwise, any existing vault data on Arweave (= pre-Phase 7.4Z) becomes
undecryptable.

The Rust unit tests in `rust-crypto/src/lib.rs` include known answer vectors
(= RFC 5869 HKDF test case 1, SHA-256 "abc", etc.). When wiring into
vault-crypto.js, add JS-side parity tests that compare Rust and noble
outputs for the same inputs.

## Stage 1 sub-tasks (= tracked in TaskList)

- [x] #349 Rollback tag (= `staging-pre-rust-2026-06-04` at dae3c3b)
- [x] #350 Create `feat/rust-crypto` branch from staging
- [x] #351 Scaffold (= Cargo.toml + src/lib.rs + CI workflow + this doc)
- [x] #352 Argon2id wiring (= derivePMat → rust.argon2id_derive、 noble fallback)
- [~] #353 AES-GCM wiring → **deferred** (= 意図的、 non-extractable CryptoKey 設計を保護)
- [x] #354 HKDF/SHA-256 wiring (= hkdfBytes → rust.hkdf_sha256、 同期 dispatch)
- [ ] #355 End-to-end user flow verification on staging (= 後セッション)
- [x] #356 Merge to staging branch → staging.arpass.io deploy ✅
- [x] #361 CSP wasm-unsafe-eval 追加
- [x] #363 ES module identity 罠 修正 (= vault-crypto.js 9 occurrences absolute path 統一)
- [x] #367 Cloudflare Pages staging に build command 'npm install' 設定

## Rollback procedure

If Stage 1 introduces a regression and we need to revert:

```sh
# Revert staging branch to pre-Rust state
git checkout staging
git reset --hard staging-pre-rust-2026-06-04
git push origin staging --force-with-lease

# (Optional) Delete the WASM artifact directory
rm -rf web/lib/rust-crypto/
git add web/lib/rust-crypto/
git commit -m "Revert: remove Rust crypto WASM artifacts"
git push origin staging
```

main is never touched until staging proves stable.

## 後続: Stage 2 + Stage G

Stage 1 完成後の次の Stage は **opaque handle migration** (= raw bytes 撲滅)。

- Stage 2a (= ECDH P-256 Rust 移行)、 Stage 2b (= AES-GCM dispatcher)、 Stage 2c (= OuterKey / MekKey / BekKey / K1Key / RMatKey handle 設計)
- Stage G4-G11 (= Personal mode primary path 全 Rust handle 経由)

詳細は [rust-crypto-opaque-handle.md](./rust-crypto-opaque-handle.md) を参照。

## Next session

Stage 1 wiring 完成 (= #352 / #354 / #363 / #367 すべて済)。 次の選択肢:

1. **#355 user flow 全検証** — vault 作成 / unlock / file 保存 / device 追加 / changePassword の完全 walk-through on staging
2. **staging → main マージ** — 本番反映 (= wrangler.toml 本番値復元含む)
3. **Stage 2 検討** — envelope orchestration を Rust 化 (= vault-crypto.js / vault-client.js の高 level logic)、 mobile FFI/JNI 準備、 3-6 ヶ月 単位の投資判断

Stage 2 を始める前に user 実機検証を全 flow で行い、 backward-compat 担保を確認すべき。 main マージは検証 OK 後。

## License

AGPL-3.0-or-later. arpass-spec public mirror updated when Stage 1
reaches main.
