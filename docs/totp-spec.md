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

最終更新: 2026-11-05
ステータス: **本番公開（2026-10-28）。Phase 1〜3 と本番公開まで完了。本人確認つきの QR 書き出し（§6）は staging（2026-11-05）**
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

1. **秘密キーは、本人確認なしには画面・コピー・書き出しで出さない。** ふだん表示・コピーできるのはコードだけ。
   出すのは、詳細画面の「ほかの認証アプリへ移す（QR）」で本人確認（Passkey・YubiKey）をしたときだけ（§6）。
   2026-11-05 に「一切出さない」から変更（八巻さん判断: 緊急復旧ツールは運営終了時向けで、YubiKey だけの
   ドライブを開けず、全パスワードを平文で一覧表示するため、ふだんの移行には使えない）。
2. **秘密キーは JS heap に置かない。** 保存時は Rust の opaque handle（`TotpKey`）に渡して包み（wrap）、
   ほどく（unwrap）のもコード計算も Rust の中で行う。JS に戻るのはコード文字列だけ。
   例外は 1. の書き出しで、`TotpKey.export_base32()` の Base32 文字列が表示のあいだだけ JS と DOM にある。
3. **運営・サーバー・Arweave からは見えない。** vault 本体と同じく端末内で暗号化した形でしか外に出ない。
4. **既存の受け渡し経路に乗らない。** 自動入力（iOS AutoFill / Android AutofillService / 拡張機能ブリッジ）は
   決まった項目（`id`, `site`, `url`, `user`, `pw`）しか渡さない。`totp` はこの固定項目に入れない。
5. **取り出せるのは、本人確認つきの QR 表示（§6）と緊急復旧ツールだけ。** 運営が消えても他の認証アプリへ
   移せるように、`arpass-emergency-restore.html` と `tools/recover-yubikey.py` は otpauth:// URI と QR で秘密キーを出せる。

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
| `otpauth-migration://…`（Google 認証システムの一括エクスポート） | エントリの登録欄では受けず、一括取り込みの画面へ回す（§5.1）。2026-11-03 までは拒否していた |
| その他の URI・文字列 | Base32 の秘密キーとして解釈を試みる |

- **label:** パーセントデコードし、`発行元:アカウント` の形なら分ける。`issuer` パラメータがあればそちらを優先。
- **secret:** 空白・`-` を除き、大文字にし、末尾の `=` を除く。文字は `A-Z2-7` のみ。
  長さは 16〜128 文字（16 文字 = 80 bit。Google 認証システムの手入力の下限に合わせる）。
  Base32 として成り立たない長さ（8 で割った余りが 1・3・6）は拒否。**デコードはしない**（Rust の `from_base32` が行う）。
- **algorithm:** 省略時 `SHA1`。`SHA1` / `SHA256` / `SHA512`（大文字小文字は問わない）のみ。
- **digits:** 省略時 6。6・7・8 のみ。
- **period:** 省略時 30。10〜300 の整数のみ。

### 5.1 Google 認証システムの一括エクスポート（2026-11-03 追加）

Google 認証システムの「コードを移行」→「コードをエクスポート」が出す QR（`otpauth-migration://offline?data=<base64>`）を
`parseMigrationInput`（`web/lib/totp.js`）で解く。中身は protobuf の `MigrationPayload`。

- **秘密キー:** 生バイトで入っているので、Base32 に**エンコード**して §5 と同じ検査（16〜128 文字）にかける。
  以降はエントリの登録と同じく `wrapTotpSecretForEntry` で Rust に渡す。バイト列は保持しない。
- **name:** `発行元:アカウント` の形なら分ける（`issuer` が空か、前半が `issuer` と同じとき）。
- **algorithm:** 0・1 = SHA1、2 = SHA256、3 = SHA512。4（MD5）は取り込めない。
- **digits:** 0・1 = 6 桁、2 = 8 桁。
- **type:** 1（HOTP）は取り込めない。0・2 は TOTP として扱う。
- **period:** 持たない（Google 認証システムは 30 秒固定）。
- **複数枚:** アカウントが多いと QR が分かれる。`batch_id`（同じ書き出しで共通）・`batch_index`・`batch_size` で
  何枚目まで読んだかを数え、残りがあれば画面で知らせる。同じ QR を読み直しても重複して足さない。
- 取り込めない項目（HOTP・MD5・短すぎる秘密キーなど）は一覧に理由付きで出し、秘密キーは残さない。
- Microsoft Authenticator と Authy には書き出し機能が無いので対象外。
- テスト: `scripts/test-totp-parse.mjs`（protobuf を組み立てて読む）。

### 5.2 ほかのパスワード管理アプリの CSV（2026-11-03 追加）

エントリ追加画面の「ほかのパスワード管理アプリから CSV で取り込む」（`web/lib/csv-import.js`）は、パスワードと一緒に
2段階認証の列も取り込む。列は Apple のパスワード・1Password の `OTPAuth`（otpauth:// の URI）、Bitwarden の
`login_totp`（保存したままの値。URI か秘密キー）、LastPass の `totp`（秘密キー）。

- 列の値は §5 の `parseTotpInput` でそのまま読む。読めない値（HOTP・`steam://` など）は、その行の2段階認証だけを
  取り込まず（理由を一覧に出す）、パスワードは取り込む。
- 秘密キーだけの値は発行元・アカウントを持たないので、表示用にサイト名・ユーザ名で補う。
- 取り込みは新しいエントリだけ。エントリ ID を先に決めて `wrapTotpSecretForEntry(秘密キー, エントリ ID)` で 1 件ずつ包み、
  全件を組み立ててからドライブへ 1 回で書き込む。CSV から読んだ値（パスワード・秘密キー）は取り込み画面を閉じるか
  取り込み終わった時点で捨てる。CSV 自体はサーバーに送らない。
- テスト: `scripts/test-csv-import.mjs`（CSV の読み取りと各社の形式の判定）。

### 5.3 iOS の「パスワード」アプリから直接（Credential Exchange、2026-11-03 追加）

iOS 26 以降の「パスワード」→「データをほかのアプリに書き出す」→ Arpass（FIDO CXP/CXF、`ASCredentialImportManager`）。
CSV のファイルを作らずに、§5.2 と同じ取り込み画面に出す。

- iOS アプリ（arpass-ios の `App/CredentialExchangeImport.swift`）が受け取り、1 件ずつ `{ site, url, user, pw, notes, otp }` にする。
  2段階認証は CXF の TOTP（秘密キーはバイト列）を Base32 に戻して otpauth:// の URI にし、web は §5.2 と同じく
  `parseTotpInput` → `wrapTotpSecretForEntry` で包む。パスキーは保存先が無いので移さず、件数だけを渡して画面に出す。
- 受け渡しは `window.__arpassCxImport` と `arpass-cx-import` イベント。web は受け取ったらすぐ window から消し、
  ロック中なら解錠まで持つ（`_pendingCxImport`）。iOS 側もパスワードをディスク・UserDefaults・ログに書かない。

## 6. 画面の規則

- **登録:** 編集画面の「2段階認証コード」欄で、QR を読む（カメラ・画像）か、URI / 秘密キーを貼り付ける。
- **一括取り込み（§5.1）:** 登録欄の「Google 認証システムからまとめて取り込む」、または登録欄で一括エクスポートの QR を
  読んだときに開く。読み取った項目ごとに、取り込み先を「新しいエントリ」か、発行元の名前が合う既存エントリ
  （2段階認証がまだ無いもの。ユーザ名がアカウントと一致するものを既定に）から選ぶ。同じ発行元・アカウントが
  登録済みなら既定で外す。取り込みは 1 件ずつ包み、ドライブへの書き込みは 1 回にまとめる。
  貼り付け欄は `type="password"`。読み取り結果は発行元・アカウント・方式だけを表示し、秘密キーは表示しない。
- **表示:** 詳細画面と一覧に、コードと残り秒数、コードのコピーボタン。秘密キーをそのまま表示・コピーするボタンは作らない。
- **ほかの認証アプリへ移す（2026-11-05）:** 詳細画面の「ほかの認証アプリへ移す（QR）」から。
  1. 本人確認: 「Recovery を表示」と同じく Passkey 認証（`authenticateWithPasskey`、前回の Passkey を名指し）。
     YubiKey モードは解錠と同じ `hwkeyAuthenticateForUnlock`（iOS アプリはネイティブ）でタッチを求める。
  2. `exportTotpSecretForEntry`（vault-client）が Rust でほどいて `TotpKey.export_base32()` を呼び、すぐ `free()` する。
  3. `openTotpExport`（app-main）が otpauth:// URI（`buildOtpauthUri`、緊急復旧ツールと同じ形）の QR と、
     4 文字ずつ区切ったセットアップキー、キーのコピーボタンを出す。閉じる・2 分たつ・ロック（再読み込み）で DOM から消す。
  - 移してもエントリの `totp` はそのまま（Arpass のコードも使い続けられる）。
- **編集:** 既存の `totp` はそのまま保持（エントリ更新は spread なので自動的に残る）。削除と再登録はできる。
- **ロック時:** 保持している `TotpKey` handle をすべて `free()` する。

## 7. 規則を守る仕組み（`scripts/lint-security.sh` の (28)〜(31)、2026-10-28）

1. (28) エントリに平文の秘密キーを入れるコードが無いこと（`totp.secret` などへの代入の禁止）
2. (29) `TotpKey` の公開メソッドは `from_base32` と `code`、それに `export_base32`（§6 の書き出し用）だけ
   （ほかに生バイトや秘密キーを返すメソッド・getter が無いこと、Rust 側。2026-11-05 に `export_base32` を追加）
3. (30) 拡張機能ブリッジ・iOS / Android 自動入力の受け渡し・アプリの CSV 書き出しに `totp` が含まれないこと
4. (31) otpauth の QR（`qr.js` の `generateOtpauthQrSvg`）と `exportTotpSecretForEntry` を使うのは、緊急復旧ツールと
   app-main の `openTotpExport` の中だけ（検査 (5) の Recovery 専用ルールの例外。2026-11-05 に `openTotpExport` を追加）

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
| QR 書き出し | 本人確認つきで、ほかの認証アプリへ移す QR とセットアップキーを出す（§6）。`TotpKey.export_base32`、lint (29) / (31)、ヘルプ（16 言語） | staging で実装（2026-11-05、八巻さんの指示） |

TOTP の画面（登録欄・詳細画面と一覧のコード）とヘルプの節は `isTotpUiEnabled()`（`web/lib/totp.js`）が true のときだけ
表示・保存する。2026-10-28 の本番公開で常に true になった（それまでは staging / localhost / `localStorage["arpass.feature.totp"]`
のときだけ）。止めるときはこの関数で false を返す。

> **Business の K1 ローテーション後:** 古い K1 がサーバから削除されるまでは読める。移行バナーの一括包み直し
> （`migrateAllRecordsToCurrentK1`）で TOTP も現行 K1 に移る（2026-10-28）。
