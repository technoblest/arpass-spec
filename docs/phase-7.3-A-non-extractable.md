<!--
====================================================================
⚠️ AUTO-GENERATED MIRROR — DO NOT PR HERE

This file is automatically synced from the private arpass repo on every
release. Direct edits to this file will be overwritten.

Source: technoblest/arpass / docs/phase-7.3-A-non-extractable.md
Mirror generator: scripts/generate-arpass-spec-mirror.mjs
====================================================================
-->

# Phase 7.3-A — Non-Extractable Crypto for Personal mode + Business mode

**Status:** **完了・後継方式に発展 (2026-06-19)** — 当初 design draft (2026-05-16)
**Goal:** ブラウザ拡張機能 / XSS / 改竄 npm dep からの **JS-readable な鍵漏洩を構造的に防ぐ**
**Out of scope:** OS root権限 / メモリダンプ / 改造ブラウザ (= 原理的限界、 DRM L1 と同じ)

> **現状更新 (2026-06-19)**: 本 Phase が掲げた「non-extractable `CryptoKey` で raw 鍵を JS から隠す」目標は達成し、 さらに**より強い後継方式 = Rust/WASM opaque handle に全面移行**した。 non-extractable CryptoKey は raw bytes こそ隠せるが鍵オブジェクト自体は JS に存在する。 後継方式では鍵は WASM linear memory のみに存在し、 JS には不透明ハンドルだけが渡る (Drop trait で確定的 zeroize / Rust crate を単体で fuzz・監査可能)。 最終的に **`CryptoKey` 自体をコードから全廃**し、 鍵を扱う `crypto.subtle.*` はゼロ (SHA-256 digest のみ保持)。 移行の詳細は [rust-crypto-opaque-handle.md](rust-crypto-opaque-handle.md) を参照。 以下の本文は当時の設計記録として保持する。

---

## 0. 動機

Phase 7.2-B (α) で Business mode の forward security は実現したが、 Personal mode の最大の脅威は **悪意ある browser extension / XSS / supply chain attack**:

LastPass 2022 流出: 平文 master password がメモリ常駐 → 拡張機能がリーク。
1Password: 同様の懸念で 2024 にメモリ衛生 disclaimer 追加。

これらは `_session.mek` のような **raw 32 byte の AES 鍵を JS から `localStorage.setItem` / `console.log` / `JSON.stringify` で抜き取れる**から起きる。

WebCrypto の `non-extractable CryptoKey` は raw bytes を JS の世界から隠せる (= C++ heap のみに存在)。 拡張機能 / 一般 JS code からは抜き出せない。

これを Personal mode + Business mode (= 既に α で session 持ち) の両方に展開する。

## 1. 攻撃モデル

| 攻撃 | 現状 (raw mek) | Phase 7.3-A 後 (non-ext mekKey) |
|---|---|---|
| 悪意ある拡張機能が `_session.mek` を読む | ◯ 抜ける | ✗ 防げる |
| XSS で `_session.mek` を fetch して送信 | ◯ 抜ける | ✗ 防げる |
| 侵害 npm dep が秘密鍵 export | ◯ 抜ける | ✗ 防げる |
| 'console.log(_session)' を user に騙して実行 | ◯ 抜ける | ✗ 防げる (= raw 表示されない) |
| OS root + memory dump | ◯ 抜ける | △ 抜ける (= C++ heap には raw 残る) |
| 改造ブラウザ (= V8 直接 patch) | ◯ 抜ける | △ 抜ける |

つまり「OS 権限を持たない攻撃者」 のほぼ全てに対して防御強化。

## 2. 設計の核

### 2.1 session 構造変更

**旧:**
```js
_session = {
  mek: Uint8Array(32),   // raw, JS-readable
  signingState: { signingPrivateKey: CryptoKey, ... },
  ...
}
```

**新:**
```js
_session = {
  mekKey: CryptoKey,         // non-extractable AES-GCM-256、 raw 取り出し不可
  mekKeyForHkdf: CryptoKey,  // non-extractable HKDF base、 sub-key 派生用
  signingState: { ... },     // 既存通り、 ECDSA private は non-extractable に
  businessK2: Uint8Array(32) | null,  // 残置 (= Business mode の K2 wrap source)
  ...
  // mek (= raw) は削除
}
```

`mekKey` と `mekKeyForHkdf` は **同じ raw bytes** から派生されるが、 用途別に CryptoKey object として分離 (= AES-GCM 専用 / HKDF 専用)。

### 2.2 unlock 時の派生 chain

```
unlock 入力 (raw bytes):
  password → derivePMat (raw 32B 一時)
  prfOutput (raw 32B)
  recoveryMaterial (raw 32B)
        ↓ wrap A/B/C unwrap (raw 32B 一時)
  K2 (raw 32B 一時)
        ↓ + K1 (Business mode: raw 32B 一時、 server経由)
  combined (raw 64B 一時)
        ↓ subtle.importKey("raw", combined, "HKDF", false, ["deriveKey"])
  mekHkdfBase (non-extractable)
        ↓ subtle.deriveKey(HKDF salt/info, ..., {AES-GCM,256}, false, ["encrypt","decrypt"])
  mekKey (non-extractable AES-GCM)

  ※ combined raw を fill(0) で zeroize
  ※ 派生時に signing key 用 sub-key も同時派生:
    subtle.deriveBits(HKDF "signing-key", mekHkdfBase, 32B) → raw 32B 一時
    → noble curves で ECDSA scalar 計算
    → subtle.importKey("jwk", ..., "ECDSA", false, ["sign"]) → non-extractable signing key
    → raw 32B fill(0)
```

これで unlock 終了時、 session には CryptoKey object のみが残り、 raw bytes は全て `fill(0)` 済。

### 2.3 セキュアな intermediate 扱い

- password 文字列: JS の `String` は immutable で zeroize 不可。 受け取り次第即 `TextEncoder().encode()` で `Uint8Array` 化、 派生後に `fill(0)`。 password 入力 field も `.value = ""` でクリア。
- prfOutput: 既に `Uint8Array`、 派生後 `fill(0)`。
- recoveryMaterial: 派生後 `fill(0)`。 ただし session.recoveryMaterial に保管するケース (= addCredential 等で必要) は保持選択。

### 2.4 saveVault / refreshFromServerLatest / 他消費者

`session.mekKey` を直接 `subtle.encrypt/decrypt` の鍵として渡す。
`raw → importKey` の 1 ステップが不要になる (= 速度的にも改善)。

Business mode の per-save K1 rotation:
```
1. server から K1 fetch (raw 一時)
2. K1 || K2 raw combine (一時)
3. importKey("raw", combined, "HKDF") → HKDF base (non-ext)
4. deriveKey AES-GCM → 新 mekKey (non-ext)
5. envelope.c 再暗号化に使用
6. session.mekKey = 新 mekKey で置換
7. combined + K1 raw を fill(0)
```

### 2.5 影響を受ける API

| 既存関数 | 変更内容 |
|---|---|
| `encryptVault` / `encryptVaultBusiness` | 戻り値の `mek` を `mekKey` (CryptoKey) に変更、 raw は zeroize |
| `decryptVault` / `decryptVaultBusiness` | 同上 |
| `addCredential` / `changePassword` / `changeRecovery_caseA` | `secretToWrap` を非 extractable で受け取れるよう調整 (raw か CryptoKey か) |
| `saveVault` | `_session.mekKey` を直接使う |
| `_decryptBodyWithSessionMek` | 同上 |
| `wrapKey` / `unwrapKey` (= blob keys for Records) | 入力 mek を CryptoKey 化 |
| `encryptRecoveryWithMek` / `decryptRecoveryWithMek` | 同上 |
| `deriveSigningKey` | unlock 時に 1 度だけ raw で呼び、 結果を non-extractable JWK import |

### 2.6 互換性

既存 envelope format は **変更なし** (= raw 暗号文の構造は同じ)。 実装変更のみ。

migrations 不要。 既存 user は次回 unlock 時に新 chain で session を組む。

---

## 3. 実装フェーズ

| Phase | 内容 | リスク |
|---|---|---|
| 7.3-A.0 | 設計仕様書 (本書) | 低 |
| 7.3-A.1 | zeroize 規律強化 (= 既存 raw bytes に `.fill(0)` を追加) | 低 |
| 7.3-A.2 | encryptVault / decryptVault に mekKey を return (= mek raw と並行 emit) | 中 |
| 7.3-A.3 | session.mekKey 追加、 saveVault / _decryptBodyWithSessionMek が mekKey を使う | 中 |
| 7.3-A.4 | signing key を non-extractable JWK import に変更 | 中 |
| 7.3-A.5 | Business mode K1 unwrap 後の HKDF を deriveKey ベースに | 高 |
| 7.3-A.6 | session.mek (raw) を完全削除、 全消費者を mekKey ベースに | 高 |
| 7.3-A.7 | encryptedRecovery / blob keys (Records) も mekKey ベース | 中 |
| 7.3-A.8 | smoke test 全 unlock + saveVault + Records | 高 |

各 phase は前のフェーズの上に乗る。 ファシリテーション順序通り (= リスク低い → 高い)。

---

## 4. テスト計画 (= 7.3-A.8)

### 4.1 機能テスト

1. 新規 createVault (Personal mode) → unlock → entry 追加 → saveVault → reload → unlock OK
2. createVault Business mode → 同上
3. unlock 後 `console.log(_session)` で `mekKey` が CryptoKey object として出ること (= raw bytes ではない)
4. `await crypto.subtle.exportKey("raw", _session.mekKey)` が `InvalidAccessError` でエラーすること (= extractable=false 確認)
5. changePassword / addCredential / Recovery 再発行が動作
6. Records (= 電子書類 chunk write/read) が動作

### 4.2 拡張機能シミュレーション

7. (試験用) `Object.entries(_session)` で構造を確認。 raw mek が無いこと。
8. `JSON.stringify(_session)` で CryptoKey が `{}` (= 空 object) として出る (= raw bytes 露出しない)。

---

## 5. 既知の限界

### 5.1 OS-level メモリダンプ

C++ heap の BoringSSL に raw bytes は依然として存在する。 OS root を持つ攻撃者は依然として抜ける。 これは Widevine DRM L1/L3 階層と同じ。

### 5.2 unlock 中の極短間 raw 露出

Argon2id 出力 (pMat)、 HKDF derive 結果は raw bytes として一瞬 JS に出てから importKey で CryptoKey 化。 この window は ~1ms。 攻撃者が exactly そのタイミングで メモリスキャンできれば取れるが、 現実的には困難。

### 5.3 plaintext 表示中のセキュアドライブ内容

entry を画面に表示している間、 password text は DOM にある。 `extension が DOM 読む` 攻撃は依然成立。 これは Phase 7.3-A の対象外 (= 別 phase で「画面 mask / on-demand reveal」 等別途検討)。

---

## 6. 訴求面

「Arpass は browser extension 由来の鍵漏洩を構造的に防ぎます」 という claim が立てられる。 LastPass 2022 流出のような事件への明確な回答。

competitive advantage:
- 1Password: extension 経由で master password を抜ける構造あり (= 拡張機能本体が信用前提)
- LastPass: 同上 + 2022 流出で plaintext master password が memory にあったと判明
- Bitwarden: 比較的良い、 ただし non-extractable は完全実装ではない

Arpass: WebCrypto non-extractable + zeroize 規律で **構造的に**抜けない。

---

## 7. 変更履歴

- 2026-05-16: 初版作成。 user 推奨 (yamaki) で Phase 7.2-B (α) クローズ後の優先タスクとして着手。


## Phase 7.3-A.9: OSS 公開対応 — raw bytes 残量と運用境界

OSS 公開を前提とした memory residue の最小化を完了。 残る raw 32B field は以下:

### Personal mode session 残量

| field | 用途 | 残量理由 | 撲滅方法 (= 将来の改良) |
|---|---|---|---|
| `_session.mek` | changePassword / changeRecovery / addCredential / records migration | WebCrypto で非 extractable AES-GCM key の re-wrap 不可 | 「操作時 Master 再入力で transient derive」 への refactor (= Phase 7.3-A.10) |

### Business mode (= member) session

| field | 用途 | 撲滅状態 |
|---|---|---|
| `_session.mek` | (business では使わない) | ✅ null 強制 (Phase 7.3-A.7) |
| `_session.businessK2` | K1 rotation 時の HKDF IKM | ⚠ raw のまま (= K1+K2 concat 構造上必要) |
| `_session.k1` | (admin が ECIES wrap、 member は無し) | ✅ admin も null (Phase 7.3-A.7e、 transient decode pattern) |

### Common

| field | 撲滅状態 |
|---|---|
| `_session.outerKeyBytes` | ✅ null (Phase 7.3-A.9 part 1) |
| `_session.recoveryMaterial` | ✅ null (Phase 7.3-A.9 part 2、 rMatHkdfKey で代替) |
| `_session.recoverySecret` (= 文字列) | ⚠ 保持 (Recovery 表示 / 機種追加 で必要)、 lock 時に削除 |

### CryptoKey 化済 (= 非 extractable)

- `_session.mekKey` (AES-GCM)
- `_session.mekHkdfKey` (HKDF base)
- `_session.rMatHkdfKey` (HKDF base)
- `_session.outerKey` (AES-GCM)
- `_session.signingState.signingPrivateKey` (ECDSA)
- `_session.empPrivKey` (ECDH P-256)

### Lock 時の hygiene

`clearSession` で全 raw field を `fill(0)` で消去 (= 防御)。 unlock 中も、 上記
の raw 保持は **「ユーザが unlock 状態で操作中」 という限定 window** に bounded。
1Password / Bitwarden 等の業界標準と同等。

### OSS 公開時の脅威モデル

- ✅ source disclosure: API 構造を知られても WebCrypto の非 extractable 保証で raw 抜き取り不可
- ⚠ XSS / browser exploit (= 同一 origin で任意 JS 実行可): session 内の Uint8Array raw は読まれ得る → 残る Personal mode の `_session.mek` がリスク
- 緩和策: 自動 lock (= timer 5 分 idle、 tab close)、 CSP (= self-only script-src 適用済)
