<!--
====================================================================
⚠️ AUTO-GENERATED MIRROR — DO NOT PR HERE

This file is automatically synced from the private arpass repo on every
release. Direct edits to this file will be overwritten.

Source: technoblest/arpass / docs/crypto-2of3.md
Mirror generator: scripts/generate-arpass-spec-mirror.mjs
====================================================================
-->

# Arpass 暗号設計 v6 — anti-fingerprint + Recovery in セキュアドライブ

最終更新: 2026-06-06
ステータス: **公開後** (= サービスイン 2026-06-02、 backward-compat 厳守)。**2026-05 に envelope v7 増分1・増分2 を追加 — 下記「v7 への更新」を参照**
暗号 op 実装: **Rust + WASM opaque handle** に移行済 — [rust-crypto-stage1.md](./rust-crypto-stage1.md) / [rust-crypto-opaque-handle.md](./rust-crypto-opaque-handle.md) を参照
担当: Yamaki / Technoblest
前バージョン: v5 (本ドキュメントの §2〜13、参考のため保存)、[v4.1](#v41-からの差分一覧) (Passkey 必須 + at-rest 鍵保護)
公開ミラー: [`technoblest/arpass-spec`](https://github.com/technoblest/arpass-spec) `docs/crypto-2of3.md`（envelope 形式は `docs/envelope-v7-spec.md`）。 main への push で `mirror-to-spec` ワークフローが自動同期。

---

## v7 への更新 (2026-05、envelope v7 増分1・増分2)

本ドキュメントは **v6 仕様**を記述します。2026-05 に **envelope v7（増分1・増分2）** を実装しました。v7 は v6 の暗号骨格（2-of-3、外側 AES-GCM、publicKey 識別、anti-fingerprint タグ）を**そのまま維持**し、次の点のみを変える非破壊的な拡張です（増分2 の YubiKey 専用モードは別系統の hwkey envelope を追加）。

- **outer 鍵 (32 byte) と vault 所在 (appNameTag) を Passkey の WebAuthn `user.id` に格納する。** これにより新端末でも「Master + Passkey」だけで解錠でき、Recovery 入力も端末ごとの localStorage 依存も不要になります（v6 までは新端末の解錠に Recovery が必須でした — §8.1 参照）。
- outer 鍵は **Master パスワード由来鍵で AES-256-CTR ラップして** user.id に持ちます（v7 ハードニング 2026-05-24）。WebAuthn の順序制約（`user.id` は credential 作成の *前* に確定する入力値であり、PRF はその credential を作った *後* にしか得られない＝鶏と卵）のため、その credential 自身の PRF で user.id を暗号化することは不可能です。代わりに、credential 作成順序と独立な Master を使ってラップします。ラップ鍵 = `Argon2id(Master, salt=appNameTag.value, m=64MiB, t=3, p=4)`、AES-CTR は非膨張なので user.id は 57 byte を維持。これにより user.id が将来想定外の場所へ漏れても、Master を知らない者には暗号文でしかありません。user.id 自体も Passkey ハードウェアでゲートされ（物理キー＋タッチ＋UV）、Arweave 公開オブジェクトには一切載らないため、§0.2 の anti-fingerprint は 100% 無傷です。
- Arweave オブジェクトの構造・書き込みパターン・タグ匿名化（§0.2）・outer 鍵の HKDF 派生（§0.1）は **v6 と完全に同一**。outer 鍵は v6 と同じ `HKDF(rMat)` で、envelope 形式そのものは変わりません。
- **outer 鍵は localStorage に一切保存しません**（2026-05-24）。解錠のたびに user.id から復元するため、ブラウザプロファイル窃取・拡張機能・XSS でも localStorage から秘密は取れません（§0.1 の v6 では localStorage に保存していましたが v7 で撤去）。端末追加で作るパスキーも v7 user.id を焼きます。
- **Master を変更すると新しい Passkey を作成します。** `user.id` は credential 作成後に変更できないため、Master 変更時は新 Master でラップした user.id を持つ Passkey を新規作成し、envelope の全 Master+Passkey wrap を作り直します（旧 Passkey の wrap は破棄）。これにより旧 Master はどの端末でも即無効になります。共有パスキーなら新 Passkey は自動同期され、他端末は次回それを選ぶだけです（詳細は `envelope-v7-spec.md` §14）。
- personal / business / admin 全モードが対象。Master 最低長 8 文字を撤廃（空のみ不可）。
- **YubiKey 専用モード（増分2、2026-05-25 実装完了・staging 検証済）。** オプションで Master も Recovery も持たず、登録した YubiKey（≥2 本）のみで 1-of-N 解錠する vault を作れます。MEK は各 YubiKey の WebAuthn PRF で個別に wrap し（inner envelope の `k[]`）、outer 鍵と vault 所在は YubiKey ごとの「keyslot blob」（その鍵の PRF で暗号化し padding で本体と同サイズ帯に難読化した独立 Arweave オブジェクト）が運びます。user.id には keyslot の所在タグのみを焼き、秘密を一切持ちません。任意の端末で解錠でき、別端末への YubiKey 追加にも対応します。詳細は `envelope-v7-spec.md` §5〜§11。

**v7 の完全な仕様は [`envelope-v7-spec.md`](./envelope-v7-spec.md) を参照してください。** 上位の設計メモは [`yubikey-outer-key-redesign.md`](./yubikey-outer-key-redesign.md)。以降の本文（§0「v5 → v6 サマリー」〜）は引き続き **v6 の参照仕様**として有効で、v7 はそこに上記の user.id 機構を加えたものです。サービス未公開のため v6→v7 のデータマイグレーションは実装せず、v7 を全新規 vault の形式とします。

---

## 0. v5 → v6 サマリー (Phase 7.0w-AH / 7.0w-AR 〜 7.0w-AU)

v5 で導入した 2-of-3 + 外側暗号化 + publicKey 識別という骨格は維持しつつ、以下 3 つの大改修を行いました。本ドキュメントの後半 (§2〜) は v5 時点の記述を残してありますが、**最新の実装は v6 仕様です**。

### 0.1 vault-id 概念の完全廃止 — outer key を rMat から直接派生 (Phase 7.0w-AR)

```
旧 (v5):  rMat → vault-id (16 byte) → outer_key (32 byte AES-GCM)
新 (v6):  rMat → outer_key (32 byte AES-GCM)
                outer_key = HKDF-SHA256(rMat, salt="arpass-outer-v6", info="envelope-wrap", L=32)
```

- 16 byte の中間鍵 (vault-id) を削除。UI からも `vault-id` の 8 文字表示を除去。
- localStorage では `vaultId` フィールドを廃し、代わりに `outerKey` (32 byte b64u) を保存。
  - Path AB (Master + Passkey) unlock 経路でも outer 復号に必要なため。
  - 攻撃面積は v5 と同等 (localStorage を読める攻撃者は元から outer key を取れる)。
- Passkey の WebAuthn `user.id` は appNameTag.value (= rMat 派生 22 文字) を流用。

### 0.2 Arweave タグの完全 anti-fingerprint 化 (Phase 7.0w-AR)

v5 までは Arweave に書き込む各 tx に固定 tag name `App-Name: <rMat 派生 b64u 16 文字>` を付けていました。これだと外部観測者が GraphQL で `tags.name == "App-Name"` を条件に **全 Arpass tx を一発で抽出可能**。v6 では tag name 自体もランダム化:

```
旧 (v5):  { "App-Name": <16 文字 b64u rMat派生 value> }
新 (v6):  { <11 文字 b64u rMat派生 name>: <22 文字 b64u rMat派生 value> }
   name  = HKDF(rMat, "arpass-app-tag-name-v6",  "app-tag-name::<tier>",   L=8)  → b64u 11 chars
   value = HKDF(rMat, "arpass-app-tag-value-v6", "app-tag-value::<tier>",  L=16) → b64u 22 chars
```

- tier qualifier (free/paid/private/corp::companyId) は v5 と同じく info 文字列に組み込まれます (= tier ごとに完全に別 tag)。
- これで外部観測者は「どの Arweave tx 群が Arpass のものか」を tx tag 名から識別する経路を失います。
- 書込種別 (セキュアドライブ envelope vs records ファイル) は **Arweave tag ではなく `body.kind`** で server に伝達 (anti-fingerprint 維持しつつ会計分類は server 側でできる)。
- Records ファイル本体の tx も tag name/value 両方ランダム化 (固定 `Arpass-Rec-*` プレフィックスを廃止)。

サーバ側 `/api/write` は任意 b64url tag name を 4 個まで forward (SAFE_TAG_RE で sanitize)。

### 0.3 Recovery をセキュアドライブ内に encryptedRecovery として保存 (Phase 7.0w-AH / AP / AS)

v5 までは Recovery Secret は **signup 時に画面で 1 回見せて以降は紙にしか存在しない**。紙紛失 = Recovery 再発行 (Case A/B) で全 wrap を作り直すか、二度と再表示できないかの 2 択でした。

v6 ではセキュアドライブデータ内部に encryptedRecovery を inject:

```
vault.encryptedRecovery = AES-GCM(HKDF(MEK, "arpass-recovery-protect-v1"), iv, UTF8(recoveryString))
v=2 (Phase 7.0w-AP format marker、文字列ベース)
```

- unlock 後のセキュアドライブデータに encryptedRecovery が含まれている → MEK 既知 (= unlock 済) なら復号可能 → **再印刷可能**
- biometric ゲート: 設定画面の「Recovery を表示」ボタンは Passkey 認証 (PRF) を要求してから decryptRecoveryWithMek を呼ぶ
- 紙紛失したユーザーは別経路 (= 紙からの再入力) で Recovery をセキュアドライブに migrate 可能
- legacy セキュアドライブ (v=1 形式 = rMat ENC、再表示不可) → v=2 (文字列 ENC、再表示可能) の自動 migration

これにより:
- 紙紛失リスクが「再印刷で済む」レベルに下がる
- 機種追加で peer-to-peer QR ペアリング (Phase 7.0w-AH #100, 未実装) の素地ができる
- Deep Recovery Phase A (#102, 実装済) の "Recovery + 残存 Passkey" 経路で envelope 内の Recovery を取り出して機種追加に流用できる

### 0.4 Deep Recovery Phase A (#102, Phase 7.0w-AH)

Path BC (Passkey + Recovery) unlock を **credIdHash 非依存** に拡張:

- v5: `decryptVault({prfOutput, recoveryMaterial, credIdHash})` — credIdHash で envelope.w.c を filter
- v6: `decryptVault({prfOutput, recoveryMaterial})` — credIdHash を渡さず envelope.w.c の **全 wrap_kr を順次試行**

これにより以下のシナリオが救済可能:
- ローカル meta の credIdHash が壊れている / 古い
- 完全な fresh device で OS Keychain Passkey だけ生存 (新規 signup view に Deep Recovery 入口)
- 複数 Passkey を持つユーザーが picker で別 Passkey を選択 → retry で正解に到達

UI:
- 既存 unlock view の「🔑 マスターパスワードを忘れた → Passkey + Recovery で再設定」(Phase 5.3-J 由来)
- **新規** view-restore の details/summary に「🆘 マスターパスワードも忘れた場合 (Passkey は OS に残っている)」入口 (#102 follow-up)

失敗時は confirm dialog で別 Passkey 切替 retry を提案 (`forcePicker: true`)。

### 0.5 その他の小変更

- **changePasswordUI 後の編集バッジ通知** (Phase 7.0w-AT): writeEnvelope を直接呼ぶ change-password 系で save-debounce 経由ではないため saving → saved 遷移が出ない bug を、UI handler 側で `updateSaveStatusBadge` を手動叩いて補正。
- **createVault の in-memory セキュアドライブに encryptedRecovery を sync** (Phase 7.0w-AS): encryptVault は spread で別オブジェクトを作るので session.vault に reflect されない → signup 直後の「Recovery を表示」が paper modal に落ちる不整合を修正。
- **i18n 整合性** (Phase 7.0w-AU): 32 個の新キーを 14 言語に翻訳、全言語 1197/1197 (100%) 達成。

---

## 1. 設計目標

Arpass は B2C 向けのブラウザベース・パスワードマネージャで、保管データを Arweave 上に暗号化保存します。本仕様書はその暗号レイヤと鍵管理を規定します。v5 では v4.1 で確立した 2-of-3 構造を維持しつつ、以下の 3 点を新たに導入します。

**v5 で新たに到達する目標**:

1. **vault-id をサーバから完全に消す** — Cloudflare KV のキーが `H(publicKey)` になり、サーバは `vault-id` を一切受信・保管しない。Arpass 運用者が侵害されても vault-id は漏れない。
2. **Arweave 上の本体を「乱数バイト列」として書く** — エンベロープ JSON 構造を外側 AES-GCM 層で再暗号化し、JSON パターン・フィールド名・暗号文長などのフィンガープリントを Arweave スクレイパーから隠す。
3. **署名鍵を Arweave に一切保存しない** — ECDSA P-256 鍵ペアを MEK から決定論的に派生 (HKDF) し、エンベロープ本体に「秘密鍵」「公開鍵」のいずれも書かない。SNDL 攻撃 (Store Now Decrypt Later) の対象面積を縮小。

**v4.1 から維持する目標**:

- **2-of-3 復号** が唯一無二のセールスポイント。3 要素 (Master / Passkey / Recovery) の任意 2 要素でセキュアドライブを復号可能。3 要素のうち 2 つを失うと永久復旧不可
- **password 単独モードは存在しない** (弱パスワードのユーザーでも一定のセキュリティ床を保証)
- **サーバには秘密の情報を一切渡さない** (Cloudflare 側に Recovery / Master Password / 秘密鍵が漏れてもセキュアドライブは復号不可)
- **端末プロファイル盗難でも書き込み権限を奪えない** (localStorage 漏洩 → 任意リクエスト署名、を成立させない)
- **マスターパスワードを忘れても、Passkey + Recovery で復旧できる** (2-of-3 の保証)
- **Passkey が壊れても、Master + Recovery で identity を再生成できる** (緊急復旧経路)

---

## 2. 要素表記

| 略号 | 名称 | 保存場所 | 失える条件 |
|---|---|---|---|
| **A** | Master Password | ユーザの記憶のみ | 忘却 |
| **B** | Passkey + WebAuthn PRF | 端末の Secure Enclave | 端末紛失・故障・Passkey 削除 |
| **C** | Recovery Secret | 紙メモ・物理金庫 (Phase 4.95 で QR 化) | 紛失・焼失 |

任意 2 要素 (A+B / A+C / B+C) でセキュアドライブが復号可能。

---

## 3. 鍵階層

### 3.1 MEK (Master Encryption Key) は **ランダム**

v5 の中核は、MEK が**いずれの認証要素からも派生されない独立したランダム値**だという事実です。

```
セキュアドライブ作成時:
  MEK = crypto.getRandomValues(new Uint8Array(32))  ← 256-bit ランダム
```

3 要素は MEK を「派生」しているのではなく「unlock」している、という関係です。これにより：

- 1 要素のみ rotation する時 (例: Recovery 再発行) **MEK 不変** → 本体 c の再暗号化不要、サーバ側何もしない
- MEK 自体を rotation する時のみ (compromise 等) **本体再暗号化 + サーバ側 migration**

### 3.2 Recovery 起点の派生

```
Recovery Secret (C)
    │
    ├──[HKDF-SHA256 salt="arpass-vault-id-v5" info="vault-id"]──► vault-id (16 byte)
    │       │
    │       ├──[HKDF-SHA256 salt="arpass-outer-v5" info="envelope-wrap"]──► outer_key (32 byte)
    │       │       │
    │       │       └─► AES-256-GCM で envelope JSON を wrap (外側層)
    │       │
    │       └─► localStorage に保存 (検索とArweaveキャッシュキー用)
    │
    └──[HKDF-SHA256 salt="arpass-app-tag-v1" info="App-Name"]──► appNameTag (12 byte)
            │
            └─► Arweave タグ "App-Name" として公開 (HMAC of Recovery)
```

**重要**: `vault-id` はサーバには送信しません。Arweave タグにも出ません。**ユーザーのブラウザ + 紙の Recovery にしか存在しない値**です。

### 3.3 MEK 起点の派生 (v5 新規)

MEK が決定すると、署名鍵ペアもそこから決定論的に派生されます。

```
MEK (32 byte ランダム)
    │
    ├──[HKDF-SHA256 info="arpass-signing-key-v5"]──► 32 byte
    │       │
    │       └─► ECDSA P-256 秘密鍵 d (mod n で curve order に収める)
    │              │
    │              └─► 公開鍵 Q = d × G  (基準点の d 倍)
    │                     │
    │                     └─► API リクエストの X-Public-Key ヘッダに毎回付与
    │
    └─► AES-256-GCM で本体 c を暗号化 (セキュアドライブデータ本体)
```

**派生方式の重要な性質**:

- 同じ MEK → 必ず同じ (d, Q)
- 全端末が共通の鍵ペアを持つ (= 同一アカウント)
- Arweave に「秘密鍵」「公開鍵」のどちらも保存しない
- 端末復旧後も `HKDF(MEK)` で同じ Q が再現される → サーバ側の同じアカウントに復帰

### 3.4 各要素の wrap 鍵

```
A (Master) + C (Recovery)  ──HKDF──► AC_KEY  ──AES-GCM──► AC wrap (= w.a)
A (Master) + B (Passkey PRF)──HKDF──► AB_KEY ──AES-GCM──► AB wrap (= w.b[i])
B (Passkey PRF) + C (Recovery)──HKDF──► BC_KEY ──AES-GCM──► BC wrap (= w.c[i])
```

各 wrap は MEK を別々の 2 要素鍵で AES-GCM 暗号化したもの。任意の 2 要素を持っていれば、対応する wrap を復号して MEK を取り出せます。

---

## 4. v5 envelope 構造

### 4.1 内側 (decrypt 後の JSON)

```jsonc
{
  "v": 5,                                         // フォーマットバージョン (= 全アルゴリズムを暗黙規定)
  "s": "<base64url 16-byte salt>",                // Argon2id 用ソルト
  "i": "<base64url 12-byte ciphertext IV>",       // 本体 c の AES-GCM IV
  "c": "<base64url ciphertext (セキュアドライブ JSON、padded)>",   // 本体 (passwords + UI metadata)
  "w": {
    "a": { "i": "<wrap IV>", "c": "<wrap ciphertext>" },         // AC wrap (1 個)
    "b": [                                                          // AB wraps (Passkey 数分)
      { "h": "<credIdHash>", "i": "<wrap IV>", "c": "<wrap ciphertext>" },
      ...
    ],
    "c": [                                                          // BC wraps (Passkey 数分)
      { "h": "<credIdHash>", "i": "<wrap IV>", "c": "<wrap ciphertext>" },
      ...
    ]
  }
}
```

### 4.2 v5 が暗黙規定するアルゴリズム

`v: 5` の値だけで以下を全部固定。エンベロープ内に algorithm フィールドを置かない (= Arweave スクレイパーの enumeration コスト上昇)。

| 用途 | アルゴリズム | パラメータ |
|---|---|---|
| KDF (Master → KEK) | Argon2id | m=64 MiB, t=3, p=4, dkLen=32, 16 byte salt (memory-hard) |
| 鍵派生 (HKDF) | HKDF-SHA256 | salt は purpose ごとに固定文字列 |
| 対称暗号 | AES-256-GCM | 96-bit IV、128-bit auth tag |
| 署名鍵 | ECDSA P-256 (secp256r1) | 派生は `HKDF(MEK)` の決定論派生 |
| 本体 padding | バケット + ジッタ | `[80, 160, 240] KiB` の最小収まるバケット + 0..8 KiB ジッタ。**最小 80 KiB raw → base64 1.33× → on-chain ~110 KiB**。Turbo 無料枠 (100 KiB = 102,400 B) を確実に超える (フリーライド回避 + size-based フィンガープリント耐性) かつコスト最小化 (¥0.33/write、Phase 6.7 で 120→80 KiB に圧縮し ¥0.47→¥0.33 へ 30% 削減)。実装は `web/lib/vault-crypto.js` の `padPlaintext` |

将来アルゴリズムを変える時は **`v` を上げる** (例: 次の量子耐性 KDF 移行 = v8)。 Argon2id は Phase 7.4 (2026-05-31) で v5 envelope 内で導入済。

### 4.3 各 wrap エントリの内訳

| フィールド | 型 | 意味 |
|---|---|---|
| `h` | base64url 文字列 | credIdHash = SHA-256(WebAuthn credential ID)。`w.b[]` と `w.c[]` でどの Passkey 用かを識別 |
| `i` | base64url 12 byte | この wrap 専用の AES-GCM IV |
| `c` | base64url 文字列 | AES-GCM(対応する KEK, MEK) の ciphertext + auth tag |

`w.a` は単一なので `h` フィールド不要 (Master + Recovery は端末非依存)。

### 4.4 v4 からの構造的な差分

| 項目 | v4 | v5 |
|---|---|---|
| `k` (KDF パラメータブロック) | あり (`{n, i, s}`) | **削除** (algorithm は `v` で暗黙規定、salt のみ top-level `s`) |
| `d` (devices メタ配列) | あり (端末名・追加日・deviceId が **平文**) | **削除** (UI 用メタは本体 `c` の中に入れる) |
| `deviceId` フィールド | 各 wrap に付与 | **削除** (credIdHash で十分) |
| 署名秘密鍵 (`encryptedPrivateKey`) | 本体 `c` の中に PRF 暗号化で同梱 | **保存しない** (HKDF(MEK) で派生) |
| 署名公開鍵 (`publicKeyJwk`) | 本体 `c` の中に同梱、サーバ KV に register | **本体に書かない** (HKDF(MEK) で派生、リクエスト都度送る) |
| Arweave Content-Type | `application/json` | **`application/octet-stream`** (外側暗号化済み) |
| Arweave 本体形式 | JSON (構造可視) | **AES-GCM 暗号化された乱数バイト列** |

---

## 5. 外側 AES-GCM 層 (v5 新規)

### 5.1 目的

エンベロープを **JSON のまま Arweave に書くと、構造的フィンガープリント** で Arpass のセキュアドライブと特定できてしまう (キー集合 `{v, s, i, c, w}` + サイズ on-chain ~110 KiB が一致する tx を全件抽出可能)。これを防ぐため、**vault-id から派生した鍵で本体ごと再暗号化**してから書き込みます。

### 5.2 仕組み

```
[書き込み]
  envelope = JSON.stringify({ v:5, s, i, c, w })
  outer_key = HKDF-SHA256(vault-id, salt="arpass-outer-v5", info="envelope-wrap")
  outer_iv  = randomBytes(12)
  outer_ct  = AES-256-GCM(outer_key, outer_iv, envelope)
  blob      = outer_iv || outer_ct                          // 12 + N + 16 byte
  ↓
  Arweave.write(blob)  with tags: App-Name (HKDF), Content-Type=octet-stream
```

```
[読み込み]
  blob      = Arweave.read(txid)
  outer_iv  = blob.slice(0, 12)
  outer_ct  = blob.slice(12)
  outer_key = HKDF-SHA256(vault-id, ...)                    // ユーザーが知っている vault-id
  envelope  = JSON.parse(AES-GCM-decrypt(outer_key, outer_iv, outer_ct))
  ↓
  通常の v5 復号フロー (wrap 選択 → MEK → 本体 c 復号)
```

### 5.3 セキュリティ的な位置付け

`outer_key = HKDF(vault-id)` は vault-id を知っている人 = ユーザー本人だけが導出可能。**vault-id はサーバ・Arweave のいずれにも露出しない**ので、外側層は実質的な機密性を提供します。

| 攻撃者 | vault-id を持つか | 外側復号可能か |
|---|---|---|
| 一般 Arweave スクレイパー | ❌ | ❌ → Arpass セキュアドライブと判別不能 |
| ar.io / ViewBlock 運用者 | ❌ | ❌ |
| Arpass 運用者 (Cloudflare) | ❌ (KV にも保存しない) | ❌ |
| ユーザー本人 | ✅ | ✅ |

### 5.4 何を防ぎ、何を防がないか

**防ぐ**:
- 全 Arweave tx を download して JSON parse + キー集合チェックで「Arpass セキュアドライブだ」と特定する攻撃
- `v: 5` や `pbkdf2-sha256` 等のリテラル文字列で grep する攻撃
- 暗号文サイズ分布 (on-chain ~110 KiB ± 6 KiB jitter) によるフィンガープリント (外側層が padding なしの場合は分布は同じだが、JSON 構造が見えない分敵対分析コストは上がる)

**防がない**:
- vault-id を別経路で入手した攻撃者 (例: 紙の Recovery を写真撮影) からの解読
- 内側エンベロープの 2-of-3 鍵管理が破綻した場合のセキュアドライブデータ漏洩

つまり外側層は **「Arpass の存在自体を Arweave 上で隠す」** ためのレイヤで、機密性の最終防衛線は依然として 2-of-3 wrap です。

---

## 6. サーバ側 KV と publicKey ベース識別

### 6.1 KV 構造

```
ARPASS_LEDGER (Cloudflare KV):
  Key:   "<H(publicKey) を base64url 16 文字>"
  Value: {
    "publicKey":   "<base64url EC P-256 raw public key 65 byte>",
    "credits":     <integer>,
    "totalSpent":  <integer>,
    "totalAdded":  <integer>,
    "registeredAt":<unix sec>,
    "lastSeenAt":  <unix sec>
  }
```

**KV value に publicKey 自体も保存** (v5 では任意だが推奨): 将来の運用機能 (audit log、暗号化通知、anomaly detection、共有セキュアドライブ、相続、SSO 等) を可能にするため。サーバ容量的には数十 byte の追加で実用上の負担なし。

### 6.2 リクエストヘッダの v5 仕様

すべての認証付き API は以下のヘッダで識別・認証されます。

| ヘッダ | 値 | 用途 |
|---|---|---|
| `X-Public-Key` | base64url EC P-256 raw publicKey | サーバはこれを SHA-256 して KV キーを引く |
| `X-Timestamp` | unix sec | リプレイ防止 (±5 分窓) |
| `X-Signature` | base64url ECDSA(d, "${ts}.${rawBody}") | publicKey で検証 |

**`X-Vault-Id` ヘッダは v5 で完全廃止**。

### 6.3 サーバ側の認証ロジック (簡略)

```javascript
const pk = req.headers.get("X-Public-Key");
const sig = req.headers.get("X-Signature");
const ts = req.headers.get("X-Timestamp");

// 1. timestamp 窓チェック (リプレイ防止)
if (Math.abs(now() - ts) > 300) return 401;

// 2. 署名検証 (publicKey が「主張」されたものを使う = client が嘘の pk を送っても、
//    対応する秘密鍵を持ってないので署名は通らない)
const valid = await verifyECDSAP256(pk, sig, `${ts}.${rawBody}`);
if (!valid) return 401;

// 3. KV ルックアップ
const kvKey = sha256(pk).toBase64url().slice(0, 22);   // 16 byte → 22 char
const entry = await env.KV.get(kvKey);
if (!entry) return 404;  // not registered

// 4. 業務処理 (debit/credit/...)
```

**`X-Public-Key` を「主張」として受けるが、署名検証に通らない限り嘘は無意味** という設計。 vault-id を介する必要は消えました。

---

## 7. 復号経路 (unlock 時)

### 7.1 Path AB: Master + Passkey (日常 unlock、最速)

```
1. ユーザー: Master Password 入力
2. ユーザー: WebAuthn navigator.credentials.get() (PRF extension)
   → credentialId, prfOutput 取得
3. クライアント:
   - localStorage から vault-id 取得
   - outer_key = HKDF(vault-id) で Arweave blob を取得・復号
   - envelope JSON parse
   - credIdHash = SHA-256(credentialId)
   - w.b[] から credIdHash 一致のエントリを探す
   - AB_KEY = HKDF(Argon2id(Master, s) + prfOutput)
   - 該当 w.b[i].c を AES-GCM 復号 → MEK
   - MEK で本体 c を復号 →セキュアドライブデータ
   - HKDF(MEK, "arpass-signing-key-v5") → (d, Q)
4. 以降の API リクエストは X-Public-Key=Q + ECDSA(d) 署名で認証
```

### 7.2 Path AC: Master + Recovery (端末紛失時の復旧)

```
1. ユーザー: Master Password + Recovery Secret 入力 (QR スキャンも可)
2. クライアント:
   - vault-id = HKDF(Recovery)
   - App-Name tag = HKDF(Recovery)
   - Arweave に App-Name で問い合わせ → 最新 tx 取得
   - outer_key = HKDF(vault-id) で blob 復号 → envelope
   - AC_KEY = HKDF(Argon2id(Master, s) + recoveryMaterial)
   - w.a 復号 → MEK
   - 本体 c 復号 →セキュアドライブ
   - HKDF(MEK) → (d, Q)  ← v4 と違って同じ Q が再現される
3. サーバ側: 同じ Q で X-Public-Key 認証 → 同じ KV エントリ → 同じ残高
4. 任意: この端末で新 Passkey 登録 → AB / BC wrap 追加 → envelope 再書き込み
```

### 7.3 Path BC: Passkey + Recovery (Master 忘却時の復旧)

```
1. ユーザー: 「Master Password を忘れた」をクリック
2. ユーザー: Recovery Secret 入力 + Passkey 認証
3. クライアント:
   - vault-id = HKDF(Recovery) → Arweave 取得 → 外側復号
   - BC_KEY = HKDF(prfOutput + recoveryMaterial)
   - w.c[] から credIdHash 一致のエントリ → 復号 → MEK
   - 本体 c 復号 →セキュアドライブデータアクセス可能 ✅
4. UI: 「新しい Master Password を設定」
5. 新 Master 入力 → クライアント:
   - 新 AC wrap = AES-GCM(HKDF(新Master + Recovery), MEK)
   - この端末の AB wrap を新 Master で再生成
   - 他端末の AB wrap は触らない (lazy 補完)
   - envelope 再書き込み
```

---

## 8. 端末追加と Recovery rotation

### 8.1 新端末追加 (常に Recovery 必須)

```
[新端末で]
1. Arpass を開く → 「すでにアカウントがある」
2. Master + Recovery 入力
3. クライアント (Path AC と同じ流れ):
   - vault-id 派生 → Arweave 取得 → 外側復号 → AC unlock → MEK
4. UI: 「この端末で Passkey を作成」
5. WebAuthn create → 新 PRF
6. 新 AB wrap (Master + 新 PRF) を w.b[] に追加
   新 BC wrap (新 PRF + Recovery) を w.c[] に追加
7. envelope 再書き込み (1 credit)
```

**設計判断**: クロスデバイスペアリング (QR + ECDH + signaling mailbox) は **採用しない**。新端末追加が稀なイベントであることと、Recovery が手元にある状態 = 機種変更の準備が整った状態である自然さを優先。Phase 4.95 で QR 化したことで紙の Recovery 入力も大幅に楽になっている。

### 8.2 Master 変更後の他端末 (lazy 補完)

```
[他端末で次回 unlock 時]
- ユーザー: 新 Master + Passkey
- AB wrap 復号失敗 (古い Master で wrap されている)
- 自動 fallback: 「Recovery を入力してください」
- 紙の Recovery 入力 (Path AC または BC)
- 復号成功 → MEK → 本体
- この端末の AB wrap を新 Master で再生成
- envelope 再書き込み
```

これは **手動の作業を強要しない設計**。普通に使っていてエラーが出たら Recovery を入れる、という自然なフロー。

### 8.3 Recovery 再発行 — ケース A (MEK 据え置き)

「紙を紛失したが盗まれた可能性は低い」場合。

```
1. 既存端末で unlock 済み
2. 新 Recovery 生成
3. AC wrap 再生成 = AES-GCM(HKDF(Master + 新 Recovery), MEK)  ← MEK 同じ
4. BC wraps を再生成 (この端末分)。他端末分は lazy 補完
5. 新 vault-id = HKDF(新 Recovery)
6. 新 App-Name tag、新 outer_key
7. envelope を新 vault-id で Arweave 書き込み (1 credit)
8. localStorage の vault-id を更新

→ MEK 不変、publicKey 不変 → サーバ KV は何もしない
注意: 古い envelope は Arweave に永久に残る。古い Recovery + Master を入手された
場合は過去セキュアドライブが読める (MEK 同じため)。
```

### 8.4 Recovery 再発行 — ケース B (MEK ごと一新)

「Recovery を盗まれた疑いがある」「定期 rotation」「過去と本気で縁を切る」場合。

```
1. 既存端末で unlock 済み
2. 新 MEK = randomBytes(32)
3. 新 Recovery 生成
4. 新 (d, Q) = HKDF(新MEK)  ← publicKey が変わる
5. 全 wrap を新 MEK + 新 Recovery で再生成
6. 本体 c を新 MEK で再暗号化
7. 新 vault-id で envelope を Arweave 書き込み
8. POST /api/migrate を旧鍵で署名:
   - body: { newPublicKey: Q' }
   - サーバ: 旧 KV[H(Q)].credits を新 KV[H(Q')] に移動、旧エントリは migratedTo マーク + credits=0
9. localStorage 更新

→ publicKey 変わる、サーバ KV migration 必要
→ 古い envelope の中身は古い MEK を持たない人には永久に読めない
```

---

## 9. サーバ API 一覧 (v5)

| Method | Path | 認証 | 用途 |
|---|---|---|---|
| `POST` | `/api/vault/register` | `X-Public-Key` (署名なし可) | 新規アカウント作成、ボーナス credit 付与 |
| `POST` | `/api/write` | ECDSA 署名 + publicKey | Arweave 書き込み + 1 credit 消費 |
| `POST` | `/api/checkout` | ECDSA 署名 + publicKey | Stripe Checkout Session 発行 |
| `POST` | `/api/webhook/stripe` | Stripe HMAC | 決済完了 → credit 加算 |
| `GET` | `/api/balance` | ECDSA 署名 + publicKey | 残高取得 (新設、URL に id を含めない) |
| `POST` | `/api/migrate` | 旧鍵で署名 | 新 publicKey へ残高移行 (ケース B rotation) |
| `POST` | `/api/admin/credit` | Bearer token | 運用者 manual credit |
| `POST` | `/api/admin/bundle-dropped` | Bearer token | bundler 失敗時の自動返金 |

**v5 で廃止された API**:
- `GET /api/vault/:vaultId` — vault-id を URL に含める設計を廃止。`/api/balance` で代替。

---

## 10. v4.1 からの差分一覧

| 項目 | v4.1 | v5 |
|---|---|---|
| **Envelope** |
| `k` (KDF block) | `{n, i, s}` 必須 | **削除** (`s` のみ top-level) |
| `d[]` (devices) | 配列、平文メタ | **削除** (本体 `c` 内に移動) |
| `deviceId` | 各 wrap + `d[]` で重複 | **削除** (credIdHash で識別) |
| `encryptedPrivateKey` | 本体 c に同梱 | **削除** (HKDF(MEK) 派生) |
| `publicKeyJwk` | 本体 c + サーバ KV | **削除** (HKDF(MEK) 派生) |
| **Arweave** |
| 本体形式 | JSON 平文 | **AES-GCM(HKDF(vault-id))** で外側暗号化 |
| Content-Type タグ | `application/json` | `application/octet-stream` |
| **サーバ** |
| KV キー | vault-id | `H(publicKey)` |
| KV value | `{credits, publicKey, ...}` | `{publicKey?, credits, ...}` (publicKey 任意保存) |
| クライアント送信 ID | `X-Vault-Id` | **`X-Public-Key`** (vault-id 完全廃止) |
| `/api/vault/:vaultId` | あり | **廃止** |
| `/api/balance` | なし | **新設** |
| `/api/migrate` | あり (vault-id ベース) | publicKey ベースに更新 |
| **vault-id** |
| サーバ受信 | あり (X-Vault-Id ヘッダ) | **なし** |
| サーバ KV 保存 | キーとして保存 | **なし** |
| Arweave タグ | (v4.1 で平文撤去済み) | (同じく無し) |
| クライアント所在 | localStorage + 派生計算 | **localStorage + 派生計算 (= 本人のみ)** |

---

## 11. セッション管理

### 11.1 セッション開始

unlock 成功時、メモリ上に以下を保持：

- MEK (32 byte) — 本体 c の復号に使用
- 派生 signingKey (d, Q) — API 署名に使用
- セキュアドライブデータ — UI 表示・編集

### 11.2 リクエスト署名

```javascript
const message = `${timestamp}.${rawBody}`;
const sig = await crypto.subtle.sign(
  { name: "ECDSA", hash: "SHA-256" },
  signingKey,    // d (秘密鍵)
  new TextEncoder().encode(message)
);

fetch("/api/write", {
  headers: {
    "X-Public-Key": base64url(rawPublicKey),
    "X-Timestamp": String(timestamp),
    "X-Signature": base64url(sig),
  },
  body: rawBody,
});
```

### 11.3 セッション終了 (lockSession)

メモリ上の MEK / signingKey / セキュアドライブを全て破棄。localStorage の vault-id は残す (次回 unlock のため)。

---

## 12. Recovery Secret のフォーマット

v4.1 から変更なし。`RS1-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` (8 グループ × 4 文字 = 32 文字 base32 + RS1 接頭辞 + 7 ハイフン = 43 文字、160-bit エントロピー)。

Phase 4.95 で QR 化と Emergency Kit 印刷をサポート (`web/lib/qr.js` 経由)。

---

## 13. セキュリティ前提

### 13.1 仮定する攻撃者と対策

| 攻撃者 | 取りうる行動 | v5 の対策 |
|---|---|---|
| Arweave 全件スクレイパー | tx 全件 download + 構造解析 | **外側 AES-GCM 層** で本体を乱数化 → JSON 構造 不可視 |
| ar.io / ViewBlock 運用者 | 同上 + index 業 | 同上、+ App-Name タグも HKDF 由来 opaque |
| Arpass 運用者 (Cloudflare 内部) | KV 全件読み取り | **vault-id がサーバに無い** → 既存セキュアドライブとの対応関係を把握不能 |
| ネットワーク傍受 (TLS 破られる仮定) | リクエスト/レスポンス読み取り | **vault-id 送信なし** + **publicKey は元々公開** |
| 端末プロファイル盗難 + Master 平文 | localStorage + メモリの吸出 | Passkey 生体認証要 + Master 必要 (現状 v4.1 と同じ) |
| 量子コンピュータ (将来) | ECDSA / AES に攻撃 | 将来 v8 で ML-DSA へ migrate (Argon2id は Phase 7.4 で導入済) |

### 13.2 防げない攻撃

- **3 要素のうち 2 つ以上を持つ攻撃者** (= 本人と等価) — 設計上不可。
- **ユーザーが自分で平文を別経路で漏らす** (例: PDF 化して Dropbox 同期) — Phase 4.95 で UI 上の禁止メッセージ + PDF lib 不採用で予防。
- **ブラウザ実装のバグ** (Web Crypto API の側面攻撃 等) — 範囲外、ブラウザベンダ責任。

---

## 14. 廃止された設計

### 14.1 ALG_PBKDF2_ONLY (v4.1 で廃止済み、v5 でも継続禁止)

password 単独 unlock モード。Passkey 必須化に伴い廃止。

### 14.2 平文 privateKeyJwk の localStorage 保存 (v4.1 で廃止済み)

v4.1 で encryptedPrivateKey に変更。v5 では更に **localStorage / 本体 c のいずれにも保存しない** に進化 (HKDF(MEK) 派生に移行)。

### 14.3 vault-id = HKDF(Recovery) を直接 publicKey として使う設計

v4 から続いていた「vault-id がほぼ公開鍵相当」という設計を v5 で完全分離。vault-id は **検索・外側暗号鍵の派生にのみ使う**、publicKey は **API 認証専用**、と役割を明確化。

### 14.4 deviceId フィールド (v5 で廃止)

各 wrap と `d[]` 配列で deviceId を管理していたが、credIdHash と 1:1 対応する死にフィールドだったため削除。

### 14.5 d[] (devices メタ配列、v5 で廃止)

端末名・追加日・deviceId を **平文で** Arweave に記録していたフィールド。第三者に「ユーザーが何の端末を持っているか」が見える状態だったため、本体 c (暗号化領域) に移動。

### 14.6 サーバ KV キーとしての vault-id (v5 で廃止)

`H(publicKey)` に置き換え。詳細は §6 と §10 の差分表参照。

### 14.7 X-Vault-Id リクエストヘッダ (v5 で廃止)

`X-Public-Key` に置き換え。

### 14.8 GET /api/vault/:vaultId (v5 で廃止)

URL に vault-id を含める設計を廃止。`/api/balance` (署名認証) で代替。

### 14.9 内側 envelope の `k.n` / `k.i` (v5 で廃止)

algorithm name と iteration count はバージョン番号 `v` で暗黙規定。フィールド削除によりサイズ縮小と enumeration 耐性向上。

---

## 15. 実装責任範囲

| ファイル | v5 で必要な変更 |
|---|---|
| `web/lib/vault-crypto.js` | `encryptVaultV5` / `decryptVaultV5` / `deriveSigningKeyV5` / 外側 AES-GCM API、d[] 廃止、k 廃止、HKDF salt 名変更 |
| `web/lib/vault-client.js` | createVault / load / save / restore / rotation 全パスを v5 に。X-Public-Key ヘッダ送信、ケース A / B rotation の選択 UI、署名鍵の都度派生 |
| `web/lib/client-auth.js` | API ヘッダ生成 (X-Vault-Id → X-Public-Key)、register/balance フロー |
| `functions/api/_lib/auth.js` | X-Public-Key を直接受けて検証、X-Vault-Id 経路撤去 |
| `functions/api/_lib/ledger.js` | KV キーを `H(publicKey)` に変更 |
| `functions/api/write.js` | Tag 生成、Content-Type を octet-stream に |
| `functions/api/vault/register.js` | publicKey ベース登録 |
| `functions/api/vault/migrate.js` | publicKey ベース migration |
| `functions/api/balance.js` | **新規** (vault-id を URL に含めない置き換え) |
| `functions/api/checkout.js` | Stripe metadata から vault-id を撤去、publicKey を埋め込む |
| `functions/api/webhook/stripe.js` | metadata から publicKey 取得 → KV[H(pk)] に credit 加算 |
| `web/app.html` | 「Master を忘れた」入口、ケース A / B rotation UI |
| `scripts/test-vault-crypto-v5.mjs` | **新規** v5 用 ラウンドトリップテスト |
| `scripts/lint-security.sh` | invariant 追加: vault-id がサーバ側コードに復活していない、X-Vault-Id 復活なし、k.n / k.i / d[] 復活なし |
| `docs/implementation-status.md` | Phase 5 反映 |
| `README.md` | Crypto v5 セクション追加 |
| `docs/security-baseline.md` | §6-10 (v5 不変条件) 追加 |
| `docs/technical-spec.docx` | 付録 v5 マップを追加 (tracked changes) |
| `business/implementation-roadmap.md` | Phase 5 反映 |

公開ミラー (arpass-spec):
| ファイル | 変更 |
|---|---|
| `docs/crypto-2of3.md` | 本ドキュメントを丸ごと自動ミラー（`mirror-to-spec` ワークフロー、 main push 時） |
| `docs/crypto-rationale.md` | v5 採用理由 (HKDF derivation、外側暗号化) を追記 |
| `docs/arweave-tags.md` | Content-Type 変更を反映 |
| `lib/*.js` | arpass repo からの最新 snapshot |

---

## 16. テスト要件

### 16.1 ラウンドトリップ

- 各 unlock 経路 (AB / AC / BC) で `encrypt → decrypt` が一致
- 外側 AES-GCM の wrap → unwrap 一致
- HKDF(MEK) 派生鍵の決定論性 (同じ MEK → 同じ Q が必ず返る)
- 複数 Passkey を持つ envelope で、任意の Passkey 選択で AB / BC unlock 可能

### 16.2 ローテーション

- ケース A: AC + BC re-wrap、MEK 不変、publicKey 不変
- ケース B: 全 wrap 再生成、MEK 新規、publicKey 新規、`/api/migrate` で残高引き継ぎ

### 16.3 セキュリティ不変条件 (CI)

- `X-Vault-Id` がサーバ側コードに復活していない
- vault-id が KV キーとして使われていない
- `k.n` / `k.i` / `d[]` が新規生成されていない
- 平文の `privateKeyJwk` / `publicKeyJwk` が envelope 本体に書かれていない
- 外側 AES-GCM 層を経由しない直書き Arweave write が無い

### 16.4 既存 v4 互換

サービス未公開のため**互換性ゼロ** (v5 のみ生成・読み込み)。v4 デコードコードは削除。

---

## 17. 移行計画

### 17.1 既存ユーザへの影響

- 公開前のため**ゼロ** (本番には v5 のみデプロイ)
- ステージング / 開発環境の v4 セキュアドライブは**作り直し** (互換性なし)

### 17.2 ロールアウト戦略

1. PR をブランチ単位でレビュー (spec → crypto → client → server → UI → docs)
2. 各 PR 個別に CI green を確認
3. 全 PR マージ後にステージング環境で E2E (新規登録 → write → recovery → migrate)
4. arpass-spec 同期 PR を出して公開
5. 本番デプロイ
6. ドメイン公開 (closed beta → public beta)

---

## 付録 A: 略号集

| 略号 | 意味 |
|---|---|
| A | Master Password |
| B | Passkey + WebAuthn PRF |
| C | Recovery Secret |
| MEK | Master Encryption Key (セキュアドライブ全体の対称鍵、ランダム 256-bit) |
| KEK | Key Encryption Key (各 wrap で MEK を包む鍵、HKDF 派生) |
| AC_KEY | A + C で派生する KEK |
| AB_KEY | A + B で派生する KEK |
| BC_KEY | B + C で派生する KEK |
| AC wrap | `w.a`、AC_KEY で MEK を AES-GCM 包んだもの |
| AB wrap | `w.b[i]`、AB_KEY で MEK を AES-GCM 包んだもの (Passkey ごとに 1 個) |
| BC wrap | `w.c[i]`、BC_KEY で MEK を AES-GCM 包んだもの (Passkey ごとに 1 個) |
| credIdHash | SHA-256(WebAuthn credentialId)、wrap 配列内のインデックス |
| outer_key | HKDF(vault-id, ...) で派生、外側 AES-GCM 層の鍵 |
| signingKey | HKDF(MEK, ...) で派生、ECDSA P-256 鍵ペア (d, Q) |
| SNDL | Store Now Decrypt Later (今暗号文を保存して将来解読する攻撃) |

---

## 付録 B: 関連ドキュメント

- [`docs/security-baseline.md`](security-baseline.md) — Tier 制セキュリティ運用方針、§6-10 で v5 不変条件
- [`docs/technical-spec.docx`](technical-spec.docx) — エンドユーザ向け技術仕様書 (付録に v5 マップ)
- [`README.md`](../README.md) — リポジトリ概要
- [`business/implementation-roadmap.md`](../business/implementation-roadmap.md) — フェーズロードマップ
- 公開ミラー: [`technoblest/arpass-spec`](https://github.com/technoblest/arpass-spec) — `docs/crypto-2of3.md`
