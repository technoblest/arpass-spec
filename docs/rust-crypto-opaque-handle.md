<!--
====================================================================
⚠️ AUTO-GENERATED MIRROR — DO NOT PR HERE

This file is automatically synced from the private arpass repo on every
release. Direct edits to this file will be overwritten.

Source: technoblest/arpass / docs/rust-crypto-opaque-handle.md
Mirror generator: scripts/generate-arpass-spec-mirror.mjs
====================================================================
-->

# Rust opaque handle migration — Stage 2a / 2c / G4-G11

最終更新: 2026-06-19
ステータス: **全モード CryptoKey 全廃・opaque handle 一本化 完了 (2026-06-19)** — 詳細は末尾「Phase 2-最終」節
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

---

## Phase 2 完成 (= H1 + H2 + H3 + H4 + H5、 2026-06-07 朝 JST)

### 達成

Phase 1 (= Stage G4-G11) で Personal mode primary path を Rust handle 化した後、 Phase 2 で **opaque handle pattern を完成**:

| Phase | 内容 | 完成 commit |
|---|---|---|
| **H1** | signing key (= ECDSA P-256) を Rust SigningKey handle 経由化 | `136c10e` + `11ce392` |
| **H2-prep** | vault-client.js の raw subtle.encrypt/decrypt 2 箇所を dispatcher 経由化 | `6f8cd76` |
| **H2-a** | wrapKey / unwrapKey に MekKey handle 検出 path 追加 | `77f1964` |
| **H2-b** | encryptVault / decryptVault が mekKey を MekKey handle で返却 | `a90c2b4` |
| **H3** | `_session.mek` raw bytes 完全撲滅 (= Phase 7.3-A.10 で済確認) | (既完了) |
| **H4** | deriveBusinessMekKeyV2 が MekKey handle 返却 (Business mode 完成) | `acaeef1` |
| **H5** | dispatcher fallback の保持判断 | (設計判断) |
| Final | staging → main マージ | `8408ef4` |

### 全 secret material が opaque handle 化された

| 鍵 | type | 経路 |
|---|---|---|
| outer key (envelope wrap) | `OuterKey` | Stage 2c |
| MEK (vault body) | `MekKey` | Stage G7 + H2-b + H4 |
| K1 (Business key) | `K1Key` | Stage G3 (populate)、 H4 (consumption) |
| BEK (record file) | `BekKey` | Stage G4-G5 |
| CEK (chunk) | `BekKey` | Stage G6 |
| rMat (Recovery base) | `RMatKey` | Stage 2c Stage D2 |
| Signing key (ECDSA) | `SigningKey` | **H1 (新規)** |

### dispatcher / polymorphic 化 一覧 (= 2026-06-07 確定状態)

| 関数 | 場所 | handle path | CryptoKey path |
|---|---|---|---|
| `aesGcmEncrypt` | vault-crypto.js | ✅ Rust | ✅ subtle.encrypt |
| `aesGcmDecrypt` | vault-crypto.js | ✅ Rust | ✅ subtle.decrypt |
| `aesGcmEncryptRaw` | vault-client.js (= H2-prep 新規) | ✅ | ✅ |
| `aesGcmDecryptRaw` | vault-client.js | ✅ (= 今日午前 hotfix) | ✅ |
| `wrapKey` | vault-crypto.js | ✅ H2-a 新規 | ✅ |
| `unwrapKey` | vault-crypto.js | ✅ H2-a 新規 | ✅ |
| `signRequest` | vault-crypto.js | ✅ H1 新規 | ✅ |
| `deriveKEK` | vault-crypto.js | ✅ Stage G9 | ✅ |

### 重要な regression と教訓 (= 2026-06-06 / 2026-06-07 で経験)

1. **Stage G9 deriveKEK polymorphic 化で `aesGcmDecryptRaw` が取り残された** (= 社員 unlock 全滅、 hotfix `7e9205f`)
2. **H2-prep の saveVault 置換漏れ** (= H2-b で mekKey handle 化したら即死、 hotfix `1ddee5c`)

両方とも 「raw 直叩き helper が dispatcher 経由化漏れ」 が原因。 memory `[[polymorphic-dispatcher-consistency]]` に記録。

### dispatcher fallback を残す方針 (= H5 設計判断)

| シナリオ | fallback なし | fallback あり |
|---|---|---|
| 古 browser (WASM 未対応) | 全機能停止 | CryptoKey path で動作 |
| CSP issue で WASM block | エラー | 同上 |
| WASM artifact 破損 | エラー | 同上 |
| network 失敗で WASM 取得不可 | エラー | 同上 |

**結論**: fallback は OSS 公開後も保持。 「常に Rust handle 優先、 WASM 不可時のみ CryptoKey で互換性確保」 と説明できる。

### 元の browser 版 (= CryptoKey のみ) との比較

| 観点 | CryptoKey 版 | Phase 2 完成版 |
|---|---|---|
| JS から raw 取得 | ❌ 不可 (= extractable false) | ❌ 不可 (= API なし) |
| JS heap snapshot | 鍵は browser 領域 | 鍵は WASM linear memory |
| **明示 zeroize** | GC 任せ | ✅ Drop trait で確定的 |
| **mobile native 流用** | ❌ browser 専用 | ✅ Rust crate を FFI で |
| **OSS 監査** | 「browser を信用」 | ✅ 単一 Rust crate を fuzz / verify |
| **side-channel 耐性** | browser 依存 | RustCrypto は constant-time 設計 |

## Phase 2-H4-full (= K2 raw 露出ゼロ、 2026-06-07 main 反映)

### 達成

Phase 2 完成宣言 (= 上節) では Business mode の `deriveBusinessMekKeyV2` が MekKey handle を返却するようになったが、 K2 raw bytes は依然 deriveBits 経由で JS heap に transient に出現していた。 H4-full で **K2 を MekKey opaque handle として並列保持**、 `K1Key.derive_business_mek_v2` で HKDF を WASM 内 完結。

| Stage | 内容 | 反映 commit |
|---|---|---|
| **F1** | Rust: `K1Key.derive_business_mek_v2(k2: MekKey, info)` 追加 | `04318a0` |
| **F2** | Rust: ECIES K1 unwrap で K1Key handle 直接生成 (= 当初設計、 後で F6 で reshape) | 同上 |
| **F3** | Rust: `MekKey.hkdf_derive_bytes`, `MekKey.derive_signing_key` 追加 | `f1206a0` |
| **F4** | JS: `_session.k2Handle` を MekKey opaque handle として並列 populate、 lockSession で free | `084d3a9` |
| **F5** | JS: `deriveBusinessMekKeyV2` polymorphic (= K2 handle 入力で K1Key.derive_business_mek_v2 経由) | `0f4730a` |
| **F6 Rust** | Rust: `ecies_unwrap_to_k1key_with_emp_priv` standalone 関数 (emp_priv を引数化、 SigningKey 経由ではない正確な ECIES) | `22e1c7c` |
| **F6 JS** | JS: tryTransitionFromPending + refreshFromServerLatest で `_session.k2Handle ?? _session.k2HkdfKey` 優先 | `66aa6c7` |
| **hotfix** | Rust: hkdf_sha256 引数の u32/usize 整合 (= cargo test 失敗修正) | `497013b` |
| Final | staging → main マージ | `e4df742` |

### invariant

- K2 raw bytes は importK2AsKeys 内で MekKey handle 化 + zeroize、 JS heap に永続的に存在しない
- K1 raw bytes は eciesUnwrapForRecipient 直後の数 μs のみ存在 (= K1Key handle に即 import)
- mekKey 派生は K1Key.derive_business_mek_v2(K2 handle, info) で HKDF を WASM 内で完結

### sub-key 派生 (= mekHkdfKey, signing key, recovery protect) の状態

**main 反映済**: mekHkdfKey は CryptoKey HKDF base のまま。 deriveSigningKeyFromHkdf も CryptoKey 入力前提。 sub-key 派生時に一瞬 raw bytes が deriveBits 経由で JS heap に出現する。

**F7 (= 試みて revert)**: mekHkdfKey も MekKey handle にして sub-key 派生も Rust 内 完結を狙ったが、 admin signing key の pkHash が変わってしまう副作用が発覚し staging から即 revert (`ac2a476`)。 詳細は memory `[[f7-signing-key-trap]]`。 再着手は Rust/JS bit-equivalence test を CI に組み込んだ後。


## Phase 2-H4-full F7 完成 (= mekHkdfKey も MekKey handle 化、 2026-06-07 main 反映)

### 達成

H4-full では mekHkdfKey が CryptoKey HKDF base のまま残っており、 sub-key 派生 (signing key + recovery protect) で deriveBits 経由の transient raw bytes が JS heap に出現していた。 F7 で **mekHkdfKey も MekKey opaque handle 化**、 sub-key 派生も WASM 完結。

### F7 retry 段階移行 (= 前回 regression 教訓)

最初の F7 (1 commit に F7-A/B/C 全部) で staging に push したところ、 admin signing key の pkHash が変わって "Caller has no company" regression。 即 revert。 root cause 完全特定できず。

その教訓を踏まえて **段階移行** で retry 成功:

| Stage | 内容 | 反映 commit |
|---|---|---|
| **bit-equiv test** | Rust test: `test_mek_derive_signing_key_equivalent_to_explicit_hkdf_path` + `test_business_signing_chain_bit_equivalent` で F7 path と F6 path が bit-identical な signing pubkey を生成することを CI 担保 | `8289065` |
| **F7-A/B dormant** | JS: deriveBusinessMekHkdfKeyV2 / deriveSigningKeyFromHkdf に MekKey handle 入力受付 path 追加。 caller は依然 CryptoKey を渡すので **発火しない** (= 0 behavior 変更) | `ab30f7e` (main) |
| **F7-C step 1** | JS: refreshFromServerLatest の newMekHkdfKey を k2Handle 経由化。 K1 rotation path のみ発火 | `a840864` (main) |
| **F7-C step 2** | JS: tryTransitionFromPending の realMekHkdfKey も k2Handle 経由化。 K1 pending member transition path も発火 | `8c3135b` (main) |

各 step で staging に push、 5 mode (Personal / Business 社員 / Business admin / hwkey / signup transition) で検証 OK 後に main マージ。

### 最終 invariant (= F7 完成後)

- mekHkdfKey は MekKey opaque handle として session に保持 (= transition / refresh 経由)
- signing key 派生は `MekKey.derive_signing_key(salt, info)` で WASM 完結 (= 48-byte seed が JS heap に出現しない)
- Recovery protect 派生は `MekKey.hkdf_derive_mek(salt, info)` で WASM 完結
- lockSession で mekHkdfKey も `.free()` (= MekKey handle の場合)

### 教訓: 段階移行の効用

- dormant 受付 (受付 path 追加だが発火しない) と actual behavior change を別 commit / 別 stage に分離
- 1 caller ずつ実発火に切替、 各 stage で staging 検証
- bit-equivalence test を CI に組み込んで数学的等価性を担保
- 「1 commit で全部やる」 は temporary 速いが、 regression debug が地獄になる

cf memory `[[f7-signing-key-trap]]`。

### 残る課題: K1 raw window (= 数 μs)

K1 raw bytes は eciesUnwrapForRecipient → K1Key handle import の数 μs window で JS heap に存在。 これを消すには Rust 側で ECIES 全工程を完結する必要 (= EmpPrivKey opaque handle + ecies_unwrap_to_k1key methodization)。 別 phase で着手。

## Phase 2-F8 (= K1 raw window 消去への足場、 2026-06-07 main 反映)

### 達成 (step 1+2+3a まで)

F7 完成で mekHkdfKey も MekKey handle 化したが、 K1 raw bytes は依然 ECIES unwrap 直後の数 μs window で JS heap に出現。 F8 は **ECIES decrypt 全工程を Rust 内で完結**して、 K1 raw が JS heap に一度も出現しない設計。

| Stage | 内容 | 反映 commit |
|---|---|---|
| **step 1 Rust** | `EmpPrivKey` opaque handle (= 32-byte ECDH scalar)、 `ecies_unwrap_to_k1key` method | `699b11f` |
| **step 1b Rust** | `EmpPrivKey::from_pkcs8` (= PKCS8 DER parser、 JS 側 ASN.1 不要)、 p256 features に pkcs8 追加 | `7647c8a` |
| **step 1 test** | `test_emppriv_handle_ecies_unwrap_bit_equivalent_to_standalone` で handle method と standalone 関数の出力が bit-identical なことを CI 担保 | `699b11f` |
| **step 2 JS** | `unwrapEmpPrivAsHandleWithK2Key` + `eciesUnwrapToK1Handle` (dormant 受付 helper) | `56708b2` |
| **step 3a JS** | session.empPrivHandle 並列 populate、 lockSession で free、 4 propagate site + refresh path | `dc075cb` |

### 各 step の dormant 範囲

- **step 1+2 dormant**: Rust handle + JS helpers のみ、 caller 未変更。 0 behavior 変更。
- **step 3a dormant**: session に empPrivHandle が populate されるが、 ECIES decrypt caller は依然 CryptoKey 経由。 0 behavior 変更。

### 残作業 (step 3b、 step 4)

**step 3b**: tryTransitionFromPending / refreshFromServerLatest の ECIES decrypt site で empPrivHandle 経由化:

```javascript
// 既存 (= K1 raw window 存在):
const k1Raw = await eciesUnwrapForRecipient(empPrivKey, encK1);
const k1 = new Uint8Array(k1Raw);
// ... importK1RawAsHandle で k1Handle populate ...
k1.fill(0);

// F8 step 3b 後 (= K1 raw window 消去):
const newK1Handle = await eciesUnwrapToK1Handle(_session.empPrivHandle, encK1);
// K1 raw bytes は WASM 内のみ、 JS heap に一切出現しない
```

**step 4**: HKDF 派生 (= deriveBusinessMekKeyV2) も k1Handle 経由化 (= 既に F5 で polymorphic 済、 caller が k1 raw を渡すのを止めれば完成)。

### Bit-equivalence 担保

新 Rust 関数追加時は必ず bit-equivalence test を追加。 既存 JS path との出力一致を CI で保証することで、 polymorphic 化での silent behavior change を防止 (= F7 retry の教訓を適用)。


---

## Phase 2-最終 (= CryptoKey 全廃 / 鍵関連 crypto.subtle ゼロ、 2026-06-19 staging 反映)

### 達成

F8 step 3b / step 4 を含む全残作業を完了し、 **鍵を扱う `crypto.subtle.*` をコードレベルで完全撤去**した。 ブラウザ WebCrypto 経由の鍵操作は一切残っていない。 Rust opaque handle が唯一の鍵経路であり、 WASM 未ロード時の CryptoKey fallback も撤去した (= Rust 必須化)。

検証コマンドと結果 (2026-06-19, staging `025c43c`):

```
$ grep -rn "crypto.subtle.(importKey|exportKey|deriveBits|deriveKey|wrapKey|unwrapKey|generateKey|sign|verify|encrypt|decrypt)" web/lib/*.js
（rust-crypto グルー内のコメント2件を除き 0 件）
$ grep -rn "crypto.subtle.digest" web/lib/*.js   → 7 件（SHA-256 のみ、 鍵ではないため保持）
$ grep -rn "instanceof CryptoKey" web/lib/*.js    → 0 件
```

残る `crypto.subtle.digest`（SHA-256）はファイル改ざん検知のハッシュであり鍵ではないため意図的に保持。

### batch 一覧 (= 各 batch がロールバック単位)

| batch | 内容 |
|---|---|
| **batch3** | `aesGcmEncrypt` / `aesGcmDecrypt` ディスパッチャ + PRF wrap 鍵から CryptoKey 経路を撤去 (handle / Uint8Array のみ受付、 それ以外は throw) |
| **batch4** | records の BEK / chunk CEK と添付 migrate を `BekKey` opaque handle に一本化。 `wrapKey` / `unwrapKey` / `generateBlobKey` / `encryptBlob` / `decryptBlob` / `rewrapKey` を撤去 |
| **batch5** | `decryptVault` / `decryptVaultHwkey` の raw 経路 body 復号と rotation 本体暗号化を `MekKey` handle 化 (`crypto.subtle.importKey` 撤去)。 `forceRawMek`（mutation / 災害復旧）の raw mek 自体は handle で扱い継続 |
| **batch6+7** | business unlock (`decryptVaultAuto`) の raw-K2 経路撤去 → K2 handle 必須化。 `saveVault` / 本体復号 / `_getMekKeyForVersion` / `_getRealMekForVersion` を handle 必須化。 → `vault-client.js` の鍵 crypto.subtle ゼロ |
| **batch8** | `wrapEmpPrivWithK2` / `unwrapEmpPrivWithK2` / `eciesUnwrapForRecipient` と ECIES の `recipientPubkey instanceof CryptoKey` 分岐を撤去 |

### 「dispatcher fallback を残す方針 (H5)」の撤回

上記 §「dispatcher fallback を残す方針」では OSS 公開後も CryptoKey fallback を保持する判断だったが、 **本 Phase でこの方針を撤回**した。 理由:

- 本サービスは既存ユーザ不在（後方互換不要）かつ Rust WASM は CI が常時ビルド・配信するため、 実運用で WASM 不在経路に落ちる状況が想定されない。
- fallback コードは「死んだ防御コード」として残り、 監査面では鍵が CryptoKey にも流れうるという誤読を招く。
- → Rust 必須化（WASM 不在時は明示 throw）の方が、 「鍵は Rust handle のみ」という不変条件を**コードで証明**できる。

### F8 step 3b / step 4 の完了

| 旧 残作業 | 完了状態 |
|---|---|
| step 3b: ECIES decrypt site の empPrivHandle 経由化 | ✅ `eciesUnwrapToK1Handle(empPrivHandle, encK1)` が唯一経路。 raw `eciesUnwrapForRecipient` は撤去 |
| step 4: HKDF 派生 (deriveBusinessMekKeyV2) の k1Handle 経由化 | ✅ caller は K1Key handle のみ渡す。 K1 raw window 消滅 |

### node 回帰テスト (= Rust WASM をロードして実行)

```
scripts/test-envelope-v7.mjs     → 56 passed   (personal / hwkey / records / outer / recovery)
scripts/test-business-crypto.mjs → 21 passed   (business AB/AC/BC round-trip / ECIES / deriveKEK)
```

### 最終不変条件

- 全鍵（MEK / K1 / K2 / BEK / CEK / outer key / rMat / emp_priv / signing key）は `MekKey` / `K1Key` / `BekKey` / `OuterKey` / `RMatKey` / `EmpPrivKey` / `SigningKey` のいずれかの opaque handle としてのみ存在。
- raw 鍵バイト列が JS heap に出るのは `forceRawMek`（端末追加・パスワード変更・K1 rotation・災害復旧）の mutation 経路に限定され、 これも即 handle 化 + `fill(0)`。
- ブラウザ WebCrypto による鍵操作（importKey / exportKey / deriveBits / wrapKey / sign / encrypt …）はソースコード上ゼロ。 `crypto.subtle.digest`（SHA-256）のみ保持。
