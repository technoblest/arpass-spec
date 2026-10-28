<!--
====================================================================
⚠️ AUTO-GENERATED MIRROR — DO NOT PR HERE

This file is automatically synced from the private arpass repo on every
release. Direct edits to this file will be overwritten.

Source: technoblest/arpass / docs/totp-spec.md
Mirror generator: scripts/generate-arpass-spec-mirror.mjs
====================================================================
-->

# TOTP（2段階認証コード）— 保存形式と実装仕様

最終更新: 2026-10-28
ステータス: **本番公開（2026-10-28）。Phase 1〜3 と本番公開まで完了**
担当: Yamaki / Technoblest
関連: [rust-crypto-opaque-handle.md](./rust-crypto-opaque-handle.md)（鍵の opaque handle 方式）、
[web-stage2-raw-mek-elimination-plan.md](./web-stage2-raw-mek-elimination-plan.md)（生 MEK の JS heap 露出撲滅）、
[envelope-v7-spec.md](./envelope-v7-spec.md)（vault 本体の暗号形式）

---

## 1. 目的

PC 中心で使う人が、スマホの認証アプリを取り出さずに Web 上で 2 段階認証コードを出せるようにする。
各サービスの TOTP 秘密キーを Arpass のエントリに保存し、ドライブ画面に 6 桁（または 8 桁）のコードを表示する。

## 2. 守ること・守れないこと

### 守ること

1. **秘密キーは保存後に画面・コピー・書き出しで一切出さない。** 表示・コピーできるのはコードだけ。
2. **秘密キーは JS heap に置かない。** 保存時は Rust の opaque handle（`TotpKey`）に渡して包み（wrap）、
   ほどく（unwrap）のもコード計算も Rust の中で行う。JS に戻るのはコード文字列だけ。
3. **運営・サーバー・Arweave からは見えない。** vault 本体と同じく端末内で暗号化した形でしか外に出ない。
4. **既存の受け渡し経路に乗らない。** 自動入力（iOS AutoFill / Android AutofillService / 拡張機能ブリッジ）は
   決まった項目（`id`, `site`, `url`, `user`, `pw`）しか渡さない。`totp` はこの固定項目に入れない。
5. **取り出せるのは緊急復旧ツールだけ。** 運営が消えても他の認証アプリへ移せるように、
   `arpass-emergency-restore.html` と `tools/recover-yubikey.py` は otpauth:// URI と QR で秘密キーを出せる。

### 守れないこと（割り切り）

- **登録の瞬間は JS を通る。** QR の読み取り結果や貼り付けた文字列は JS の文字列として一度存在する。
  JS の文字列は消去できないので、変数の寿命を最短にして Rust に渡す。
- **パスワードと同じ金庫に入る。** 金庫そのもの（2-of-3 のうち 2 要素）を破られると、パスワードと
  2 段階目の鍵を同時に失う。重要なサービスは別の認証アプリを併用するようヘルプで案内する。
- **端末の時計に依存する。** 時計が大きくずれているとコードが合わない。

## 3. エントリの保存形式

エントリ（`vault.entries[]`）に任意項目 `totp` を追加する。既存項目は変えない。

```jsonc
{
  "id": "e_…",
  "site": "GitHub", "url": "…", "user": "…", "pw": "…", "notes": "…",
  "createdAt": "…", "updatedAt": "…",
  "totp": {
    "v": 1,                      // この項目の形式バージョン
    "issuer": "GitHub",          // 表示用（秘密ではない）。無ければ ""
    "account": "alice@example.com", // 表示用（秘密ではない）。無ければ ""
    "algorithm": "SHA1",         // "SHA1" | "SHA256" | "SHA512"
    "digits": 6,                 // 6 | 7 | 8
    "period": 30,                // 秒。10〜300
    "wrapped": {
      "iv": "<base64url 12 bytes>",
      "ct": "<base64url AES-256-GCM 暗号文 + tag>"
    },
    "k1Version": null,           // Business のみ。包んだ時点の K1 版（records の BEK と同じ扱い）
    "createdAt": "…"
  }
}
```

- 平文の秘密キー（Base32 文字列もバイト列も）は **どの項目にも入れない**。
- `issuer` / `account` / `algorithm` / `digits` / `period` は秘密ではないので平文（vault 本体の暗号化のみ）で持つ。

### 3.1 包む鍵

```
totpWrapKey = HKDF-SHA256(ikm = MEK, salt = "arpass/totp/v1", info = "totp-wrap", L = 32)
```

- Personal: `MEK` は現行の vault MEK。Business: 現行の real MEK（= HKDF(K1, K2)）で、`k1Version` を記録する。
- `totpWrapKey` は Rust の中だけで派生し、JS には出さない。

### 3.2 暗号化

```
iv  = 乱数 12 bytes
aad = UTF-8("arpass/totp/v1|" + entry.id)
ct  = AES-256-GCM(totpWrapKey, iv, aad, secretBytes)
```

- `secretBytes` は Base32 をデコードした生のバイト列（Rust の `TotpKey` が保持）。
- AAD にエントリ ID を入れるので、包んだ秘密キーを別エントリへ付け替えると unwrap に失敗する。

### 3.3 鍵が変わるとき

| 出来事 | 対応 |
|---|---|
| Personal: Recovery 再発行 Case B（MEK 一新） | `changeRecovery_caseB` の中で `rewrapVaultSecretsForNewMek` が、全エントリの `totp.wrapped` とファイルの鍵（BEK / CEK）を旧 MEK で unwrap → 新 MEK で wrap し直す（Rust handle 間で完結、`scripts/test-caseb-rewrap.mjs`）。**2026-10-27 staging で実装** |
| Business: K1 ローテーション | 移行バナー（`migrateAllRecordsToCurrentK1`）が `rewrapBusinessSecretsToCurrentK1` で、ファイルの鍵（BEK / CEK）と一緒に現行と違う `k1Version` の `totp.wrapped` を旧 real MEK で unwrap → 現行 real MEK で wrap し、`k1Version` を更新（`scripts/test-k1-rewrap.mjs`）。**2026-10-28 staging で実装** |
| パスワード変更・Recovery 再発行 Case A | MEK は変わらないので不要 |

> **2026-10-27 判明・対応:** Case B はファイルの鍵も包み直しておらず（ほかに、直後の保存が版の競合になる、
> この端末でもパスワード＋Passkey で開けなくなる、保存用の鍵が旧 MEK のまま、の 3 件）、本番では Case B を一時停止した
> （main dbeb8006）。staging で 4 件とも修正し、TOTP の包み直しも同じ処理に載せた（2026-10-28 本番で Case B 再開）。
> **2026-10-28:** K1 ローテーションの移行（`countRecordsNeedingK1Migration` / `migrateAllRecordsToCurrentK1`）は
> `vault.records`（schema v3 ではオブジェクト）を配列として反復して例外になっており、添付の移行も動いていなかった。
> vault 全体を走査する方式に直し、TOTP も対象に加えた。

## 4. Rust API（Phase 2 で `rust-crypto/src/lib.rs` に追加予定）

| 追加 | 内容 |
|---|---|
| 依存 | `hmac = "0.12"`, `sha1 = "0.10"`（`sha2` は既存） |
| `TotpKey` | `Box<[u8]>` を保持。`Drop` で zeroize。**生バイトを返すメソッドは作らない** |
| `TotpKey::from_base32(s)` | 登録時。Base32（大文字・パディング無し）をデコードして handle を返す |
| `MekKey::wrap_totp(&TotpKey, entry_id, iv) -> Vec<u8>` | 3.1 の派生 + 3.2 の暗号化 |
| `MekKey::unwrap_totp(ct, iv, entry_id) -> TotpKey` | 逆。AAD 不一致は Err |
| `TotpKey::code(unix_secs, period, digits, algorithm) -> String` | RFC 6238。ゼロ埋めした桁数ぶんの文字列 |

緊急復旧ツールの個人経路は WASM 無しでも動く pure JS（`emergency-recover-purejs.js`）なので、
3.1 / 3.2 の unwrap を Web Crypto（HKDF + AES-GCM）でも実装し、Rust と同じ結果になることをテストで確認する。

## 5. otpauth の読み取り規則（Phase 1 で `web/lib/totp.js` に実装）

入力は QR の読み取り結果、または貼り付けた文字列。

| 入力 | 扱い |
|---|---|
| `otpauth://totp/<label>?secret=…&issuer=…&algorithm=…&digits=…&period=…` | 受け付ける |
| `otpauth://hotp/…` | 拒否（回数ベースは対象外） |
| `otpauth-migration://…`（Google 認証システムの一括エクスポート） | 拒否（各サービスの QR を個別に読んでもらう） |
| その他の URI・文字列 | Base32 の秘密キーとして解釈を試みる |

- **label:** パーセントデコードし、`発行元:アカウント` の形なら分ける。`issuer` パラメータがあればそちらを優先。
- **secret:** 空白・`-` を除き、大文字にし、末尾の `=` を除く。文字は `A-Z2-7` のみ。
  長さは 16〜128 文字（16 文字 = 80 bit。Google 認証システムの手入力の下限に合わせる）。
  Base32 として成り立たない長さ（8 で割った余りが 1・3・6）は拒否。**デコードはしない**（Rust の `from_base32` が行う）。
- **algorithm:** 省略時 `SHA1`。`SHA1` / `SHA256` / `SHA512`（大文字小文字は問わない）のみ。
- **digits:** 省略時 6。6・7・8 のみ。
- **period:** 省略時 30。10〜300 の整数のみ。

## 6. 画面の規則

- **登録:** 編集画面の「2段階認証コード」欄で、QR を読む（カメラ・画像）か、URI / 秘密キーを貼り付ける。
  貼り付け欄は `type="password"`。読み取り結果は発行元・アカウント・方式だけを表示し、秘密キーは表示しない。
- **表示:** 詳細画面と一覧に、コードと残り秒数、コードのコピーボタン。秘密キーの表示・コピーのボタンは作らない。
- **編集:** 既存の `totp` はそのまま保持（エントリ更新は spread なので自動的に残る）。削除と再登録はできる。
- **ロック時:** 保持している `TotpKey` handle をすべて `free()` する。

## 7. 規則を守る仕組み（`scripts/lint-security.sh` の (28)〜(31)、2026-10-28）

1. (28) エントリに平文の秘密キーを入れるコードが無いこと（`totp.secret` などへの代入の禁止）
2. (29) `TotpKey` の公開メソッドは `from_base32` と `code` だけ（生バイトを返すメソッド・getter が無いこと、Rust 側）
3. (30) 拡張機能ブリッジ・iOS / Android 自動入力の受け渡し・アプリの CSV 書き出しに `totp` が含まれないこと
4. (31) otpauth の QR（`qr.js` の `generateOtpauthQrSvg`）を作るのは緊急復旧ツールだけ（検査 (5) の Recovery 専用ルールの例外）

## 8. テスト

- **RFC 6238 付録 B のテストベクタ**（8 桁、period 30）。シードは ASCII で
  SHA1 = `12345678901234567890`（20 bytes）、SHA256 = `12345678901234567890123456789012`（32 bytes）、
  SHA512 = `1234567890123456789012345678901234567890123456789012345678901234`（64 bytes）。
  （RFC 本文はシード長を 20 bytes と書いているが、付録の参照実装と下表はこのシードでの値。）

  | Unix 時刻 | SHA1 | SHA256 | SHA512 |
  |---|---|---|---|
  | 59 | 94287082 | 46119246 | 90693936 |
  | 1111111109 | 07081804 | 68084774 | 25091201 |
  | 1111111111 | 14050471 | 67062674 | 99943326 |
  | 1234567890 | 89005924 | 91819424 | 93441116 |
  | 2000000000 | 69279037 | 90698825 | 38618901 |
  | 20000000000 | 65353130 | 77737706 | 47863826 |

- wrap → unwrap の往復、AAD（エントリ ID）違いでの失敗、pure JS 実装と Rust 実装の一致。
- otpauth の読み取り: `scripts/test-totp-parse.mjs`（`npm run test:totp`）。
- 緊急復旧ツールの pure-JS 経路: `scripts/test-emergency-purejs.mjs`（`npm run test:emergency-purejs`）。本体（WASM）で包んだ秘密キーを
  pure-JS で取り出し、Rust の既知の値（`WRAP_KAT_HEX`）と RFC 6238 の値で照合。`tools/recover-*.py --selftest` も同じ既知の値で照合。
- K1 ローテーション後の包み直し: `scripts/test-k1-rewrap.mjs`（`npm run test:k1-rewrap`）。

## 9. 段階

| 段階 | 内容 | 状態 |
|---|---|---|
| Phase 1 | この仕様書、otpauth の読み取り（`web/lib/totp.js`）、編集画面の登録欄、16 言語の文言 | 完了（staging 42be0bc5） |
| Phase 2a | Rust（`rust-crypto/src/totp.rs`: `TotpKey` / `MekKey::wrap_totp` / `unwrap_totp` / `code`）、`vault-crypto.js` / `vault-client.js` 末尾の TOTP ヘルパ、保存（`entry.totp`）、登録済み表示と取り外し、詳細画面のコード表示（残り秒数・コピー）。**staging でのみ有効** | staging で実装 |
| Phase 2b | 鍵ローテーション対応（Personal の Recovery 再発行 Case B、Business の K1 ローテーション）、一覧へのコード表示（残り秒数・コピー） | staging で実装（2026-10-28） |
| Phase 3 | 緊急復旧ツール（otpauth URI / QR、一括書き出し。business も pure-JS で復号）・`tools/recover-personal.py` / `recover-yubikey.py`（`totp.txt`）、lint の検査 (28)〜(31)、ヘルプ（16 言語、`isTotpUiEnabled` のときだけ表示）、公開仕様ミラーへの本書と `totp.rs` の追加 | staging で実装（2026-10-28） |
| 本番公開 | `isTotpUiEnabled()` を本番でも true にする、`app.totp.staging_notice` の表示をやめる（文言も削除）、ヘルプの節を常時表示にする | 完了（2026-10-28、八巻さんの指示） |

TOTP の画面（登録欄・詳細画面と一覧のコード）とヘルプの節は `isTotpUiEnabled()`（`web/lib/totp.js`）が true のときだけ
表示・保存する。2026-10-28 の本番公開で常に true になった（それまでは staging / localhost / `localStorage["arpass.feature.totp"]`
のときだけ）。止めるときはこの関数で false を返す。

> **Business の K1 ローテーション後:** 古い K1 がサーバから削除されるまでは読める。移行バナーの一括包み直し
> （`migrateAllRecordsToCurrentK1`）で TOTP も現行 K1 に移る（2026-10-28）。
