# Rust opaque handle migration — Stage 2a / 2c / G4-G11

最終更新: 2026-06-06
ステータス: **Personal mode primary path 完了**
担当: Yamaki / Technoblest
関連: [rust-crypto-stage1.md](./rust-crypto-stage1.md) (= Argon2id / HKDF / SHA-256 / ECDH 純関数)、 [implementation-status.md](./implementation-status.md) §「Rust 化 Phase 1 完成」
公開ミラー: [`technoblest/arpass-spec`](https://github.com/technoblest/arpass-spec) `docs/rust-crypto-opaque-handle.md`

---

## 目的 (= なぜ opaque handle?)

Stage 1 (= 2026-06-04) で Argon2id / HKDF / SHA-256 / ECDH を Rust + WASM に純関数化した。 ただし純関数 path は **入出力が raw bytes**。 派生鍵 (= MEK / K1 / K2 / BEK / outer key / rMat) は JS の `Uint8Array` として heap に置かれ、 OSS 公開や fuzzing 対象としての品質を担保するには raw bytes 露出を撲滅する必要がある。

業界標準 (= Signal libsignal、 1Password sequoia、 ChromeOS keystore) は **opaque handle pattern**:

- Rust 側で鍵 struct を保持し JS には Box pointer (= `JsValue`) のみ渡す
- 暗号 op (= AES-GCM encrypt/decrypt、 HKDF、 wrap/unwrap) は handle method 経由で実行
- JS は raw bytes を直接見ない、 触らない

これにより:

1. JS heap dump / DevTools memory snapshot から鍵が露見しない
2. WASM linear memory には raw 32 bytes が一時的に存在するが、 Rust の Drop trait で zeroize される
3. `--features fuzzing` で純関数 fuzz の対象は維持しつつ、 production code path は handle 経由

## アーキテクチャ

### Rust 側 (rust-crypto/src/lib.rs)

5 つの opaque handle 型 + factory + method:

| 型 | 主要 method | 用途 |
|---|---|---|
| `MekKey` | `aes_gcm_encrypt`, `aes_gcm_decrypt`, `hkdf_derive_mek`, `wrap_bek`, `unwrap_bek`, `wrap_k1`, `unwrap_k1` | Personal vault の MEK |
| `K1Key` | (= Business mode の K1 wrap chain 用、 G phase では未配線) | Business mode |
| `BekKey` | `aes_gcm_encrypt`, `aes_gcm_decrypt`, `BekKey::generate()` | record (= file) BEK と chunk CEK |
| `OuterKey` | `aes_gcm_encrypt`, `aes_gcm_decrypt`, `wrap_mek`, `unwrap_mek` | envelope outer (= unlock/save path) |
| `RMatKey` | `derive_outer_key`, `hkdf_*` | Recovery 経路 (= rMat → outer key 派生) |

全 handle は:

- `Box<[u8; 32]>` を内部に持つ (= raw key bytes)
- `Drop` impl で `zeroize::Zeroize` 実行
- JS 側に渡るのは `JsValue` (= WASM heap pointer)
- `extractable: false` 相当 (= raw bytes export method を提供しない)

### JS 側 (web/lib/vault-crypto.js)

#### dispatcher pattern

`crypto.subtle.encrypt` / `decrypt` を直接呼ばず、 dispatcher 関数経由:

```javascript
async function aesGcmEncrypt(key, iv, aad, plaintext) {
  // duck-type: MekKey / K1Key / BekKey / OuterKey handle?
  if (key && typeof key.aes_gcm_encrypt === "function") {
    return key.aes_gcm_encrypt(iv, aad, plaintext);
  }
  // Uint8Array raw key?
  if (key instanceof Uint8Array) {
    const cryptoKey = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
    return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, cryptoKey, plaintext));
  }
  // CryptoKey?
  return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, key, plaintext));
}
```

これにより既存 caller は変更不要、 引数の type で自動分岐。

#### polymorphic deriveKEK (= Stage G9 核心)

`deriveKEK` は 14 caller (= addCredential, changePassword, changeRecovery_caseA/B, business mode 全 path) から呼ばれる中核 helper。 polymorphic 化により一括 Rust 経路化:

```javascript
export async function deriveKEK(material1, material2, saltKey) {
  const raw = hkdfBytes(material1, material2, saltKey, 32, "kek-derive");
  try {
    const handle = await importMekRawAsHandle(raw);
    if (handle) {
      raw.fill(0);
      return handle;  // ← MekKey handle (= Rust path 優先)
    }
  } catch (_) { /* fallback */ }
  return crypto.subtle.importKey("raw", raw, ...);  // ← CryptoKey fallback
}
```

`raw.fill(0)` は WASM 移送後の JS 側 buffer を即座に zeroize する明示。

## Stage 別 表

| Stage | 完成日 | 内容 |
|---|---|---|
| **2a** | 2026-06-05 | ECDH P-256 を noble から Rust (`p256_keypair_generate`, `p256_ecdh`) に |
| **2b-pre** | 2026-06-05 | `p256_keypair_from_seed` Rust 関数 + `_signingKeyFromSeed` wiring |
| **2b** | 2026-06-05 | AES-GCM dispatcher 追加 (= CryptoKey + raw bytes 両対応) |
| **2c outer** | 2026-06-05 | `wrapEnvelopeOuter` / `unwrapEnvelopeOuter` / `fetchEnvelope` / `writeEnvelope` を OuterKey handle に。 全 unlock-AB / AC / BC + save が handle 経由 |
| **2c Recovery** | 2026-06-05 | `encryptRecoveryWithMek` / `decryptRecoveryWithMek` dispatcher 化 |
| **G1-G3** | 2026-06-06 | session に MEK / K1 / BEK handle field cleanup 足場 + 並列 populate (= 退避) |
| **G4** | 2026-06-06 | `addCredential` (= file 添付) の BEK 生成 + wrap を Rust handle 化 (Personal mode) |
| **G5** | 2026-06-06 | `fetchRecord` (= file 復号) も同じ handle path 化 |
| **G6** | 2026-06-06 | `chunk` (= LSM-tree archival、 CEK) も Rust handle 化 |
| **G7** | 2026-06-06 | `encryptVault` / `decryptVault` の body AES-GCM を MekKey handle に |
| **G8** | 2026-06-06 | `encryptVault` の wrap A/B/C + `decryptVault` の AB/AC/BC unwrap を KEK handle に |
| **G9** | 2026-06-06 | `deriveKEK` 自体を polymorphic 化 (= handle 優先、 CryptoKey fallback)。 14 caller 一括 Rust 経路 |
| **G10** | 2026-06-06 | `deriveRecoveryProtectKey` が MekKey handle 受付 (= Recovery 経路の Rust path 開通) |
| **G11** | 2026-06-06 | `encryptRecoveryWithMek` / `decryptRecoveryWithMek` 内部で raw mek → handle 変換、 caller 透過化 |

## Rust handle 経由 まとめ (= 2026-06-06 時点)

| 操作 | path | 備考 |
|---|---|---|
| Argon2id (Master KDF) | ✅ Rust (Stage 1) | 純関数 |
| HKDF / SHA-256 / ECDH | ✅ Rust (Stage 1/2a) | 純関数 |
| Outer envelope wrap/unwrap | ✅ Rust handle (Stage 2c) | OuterKey |
| **vault body encrypt/decrypt** | ✅ Rust handle (G7) | MekKey |
| **MEK wrap A/B/C + unwrap** | ✅ Rust handle (G8/G9) | KEK derived MekKey |
| **KEK derive** | ✅ Rust handle 優先 (G9) | polymorphic、 14 callers |
| **Recovery K_recovery 派生 + encrypt/decrypt** | ✅ Rust handle (G10/G11) | MekKey path |
| **BEK (record file)** | ✅ Rust handle (G4/G5) | Personal mode のみ |
| **CEK (chunk)** | ✅ Rust handle (G6) | Personal mode のみ |

## 残作業 (= Phase 2 候補)

| 部位 | 状態 | 投資判断 |
|---|---|---|
| Business mode BEK / CEK | CryptoKey path (= K1→K2→MEK chain の Rust 化 要設計) | mobile native 着手時に再検討 |
| `_session.mek` raw bytes | encryptVault / decryptVault 内 transient (= 数命令の生存期間) | 完全撲滅には外部 API 変更必要 |
| `_session.mekKey` CryptoKey | session 保持 legacy field | session を MekKey handle 中心に再設計可能だが scope 巨大 |
| signing key 派生 | `deriveSigningKey(mek)` → CryptoKey | Rust `p256_keypair_from_seed` 経路は既に存在、 wiring のみ |
| Business mode K1 wrap chain | 全 CryptoKey | per-version cache 設計が必要 |

## backward compat 担保

- ciphertext format **完全同一** (= AES-256-GCM 同 algorithm、 同 key bytes、 同 IV、 同 AAD)
- rust-crypto 未ロード時は **CryptoKey path に自動 fallback** (= regression なし)
- 既存 envelope を新 path で復号可能、 新 envelope を旧 path で復号可能
- 業務 mode は (G9 の deriveKEK polymorphic 化を除き) 既存 CryptoKey path 完全維持
- KDF params / HKDF salt / envelope schema は全て不変

## 検証 (= サービスイン後の特殊事情)

サービスイン (2026-06-02) 後の variant のため backward-compat 必須:

- Personal vault 作成 → unlock → file 保存 → file 復号 → changePassword → Recovery export/import の全 walk-through 実機 OK
- Business mode (= K1 chain は CryptoKey 維持) の signup / unlock / write / read 全 path 動作確認 OK
- staging-first 厳守、 main マージ前に user 実機確認

## 関連 commit (= main 反映済)

| commit | 内容 |
|---|---|
| `2c11f77` | Stage G5: fetchRecord Rust handle 化 |
| `aa133c9` | Stage G6: chunk CEK Rust handle 化 |
| `ab7a8de` | Stage G7: vault body encrypt/decrypt |
| `8975455` | Stage G8: KEK derive + wrap A/B/C |
| `a8be7d1` | Stage G9: deriveKEK polymorphic (= 全 14 callers 一括移行) |
| `6cb2e83` | Stage G10: deriveRecoveryProtectKey handle 受付 |
| `4f4ccc6` | Stage G11: encryptRecoveryWithMek 内部 Rust 化 |
| `ea403f2` | hotfix: migrateAccount URL `/api/migrate` → `/api/vault/migrate` (= pre-existing bug、 Stage G11 検証時発覚) |
| `169c267` | staging→main マージ |
| `72d583d` | doc sync: implementation-status.md |

## 教訓

### Stage G4 v1 (= dual-emit) の revert

最初の Stage G4 attempt は `generateBlobKeyWithHandle` で **CryptoKey と handle を並列 populate** する dual-emit 設計だった。 これは Rust crypto module の load を阻害し unlock 不能 regression を引き起こした。

User からの critical feedback:

> 「すでに CryptoKey と同等の機能を用意済みのはずです。 全て置き換えるだけでは？」

これに従い Stage G4 v2 は **`BekKey::generate()` を直接呼ぶ完全置換** に再設計。 一発で成功。

**教訓: 並列 populate より完全置換が opaque handle migration の正解 path**。 dual-emit は state 同期 cost と module load order 問題を生む。

### migrate URL bug の副次的発見

Stage G11 検証作業中、 user が Recovery Case B (= 機種変更後の Recovery 再発行) を試した際に 405 エラー。 client `/api/migrate` vs server `/api/vault/migrate` の不一致。 「前から bug だった」 が試したことがなかったため未発覚。

**教訓: Recovery Case B のような低頻度 path は CI smoke test に含めるか、 staging 検証 checklist に明記**。

## License

AGPL-3.0-or-later. arpass-spec public mirror は main 反映後に同期。
