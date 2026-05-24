# Arpass Envelope 仕様書 — v7

> 🌐 English version: [en/envelope-v7.md](en/envelope-v7.md)

Arpass の v5 保存フォーマット。各端末がブラウザ上で組み立てて Arweave に書き込み、復号時に再構築する暗号化エンベロープの構造を定義します。

v4 から **3 つの大きな変更**があります:

1. **外側 AES-GCM 層** — エンベロープ JSON 全体をさらに暗号化してから Arweave に書く (Arweave スクレイパーから JSON 構造を隠蔽)
2. **署名鍵を保存しない** — ECDSA P-256 鍵ペアは MEK から決定論的に派生する (Arweave 上に「秘密鍵」「公開鍵」のいずれも書かない)
3. **vault-id がサーバに無い** — Cloudflare KV のキーは `H(publicKey)`、`X-Vault-Id` ヘッダ廃止 (Phase 7.0w-AR では vault-id 概念そのものを廃止)

それ以外 (2-of-3 鍵管理、PBKDF2-SHA256 600K、AES-256-GCM、HKDF-SHA256、Recovery Secret 形式) は v4.1 を継承します。

---

## 概要

`vault` (= ユーザの平文エントリのリスト) は次の手順で **エンベロープ** に変換され、外側暗号化されたうえで Arweave に保存されます。

```
平文 vault JSON
    │
    ├─► AES-256-GCM(MEK, iv) ──► 本体 ciphertext (パディングあり)
    │
    └─► MEK は 3 種の wrap で別ルートで保管:
         • wraps.pr   = AES-GCM(MEK, KEK(P, R))            1 個
         • wraps.pk[] = AES-GCM(MEK, KEK(P, K_device))     端末ごと
         • wraps.kr[] = AES-GCM(MEK, KEK(K_device, R))     端末ごと

エンベロープ JSON 完成後:
    │
    └─► AES-256-GCM(outer_key, outer_iv) ──► Arweave に書き込む blob
        (outer_key = HKDF(rMat) — Phase 7.0w-AR で vault-id を廃止)
```

**MEK** は vault 全体で共通の 32-byte 対称鍵で、端末ごとに新規生成されません。端末追加 (`addDevice`) はその端末用の wrap エントリを `wraps.pk[]` と `wraps.kr[]` に追加するだけで、MEK も `wraps.pr` も既存のまま継承されます。

> **Phase 7.0w-AR (2026-05) 更新**: 初期 v5 にあった `vault-id` という中間識別子 (Recovery から派生する 16 byte) は **概念ごと廃止**されました。外側 AES-GCM 層の鍵も Arweave 検索タグも、いまは Recovery 材料 `rMat` から直接派生します。「vault を一意に指す ID」が存在しないため、サーバ・Arweave・localStorage のどこにも vault を指す識別子が残りません。

クライアントが `rMat` (= Recovery Secret から HKDF で導出される 32 byte) を使う用途:

1. Arweave 検索のための匿名タグ (name/value 両方) の派生 — [arweave-tags.md](./arweave-tags.md) を参照
2. 外側 AES-GCM 層の鍵 `outer_key` 派生

API リクエストの認証は **publicKey** (MEK から派生) で行い、サーバ側 KV のキーは `H(publicKey)` です。`X-Vault-Id` ヘッダは存在しません。

---

## JSON 構造 (内側 — 復号後)

実際にネットワークを流れる本体は外側暗号化されているため不透明バイト列ですが、**外側を復号した後の内側 JSON** は以下の構造を持ちます。

```json
{
  "v": 5,
  "s": "<base64url 16-byte salt>",
  "i": "<base64url 12-byte ciphertext IV>",
  "c": "<base64url ciphertext (vault JSON、padded)>",
  "w": {
    "a": { "i": "<wrap IV>", "c": "<wrap ciphertext>" },
    "b": [
      { "h": "<credIdHash>", "i": "<wrap IV>", "c": "<wrap ciphertext>" },
      ...
    ],
    "c": [
      { "h": "<credIdHash>", "i": "<wrap IV>", "c": "<wrap ciphertext>" },
      ...
    ]
  }
}
```

| JSON | 内部名 | 内容 |
|---|---|---|
| `v` | `version` | 整数 `5` (フォーマットバージョン) |
| `s` | `salt` | base64url、16 byte (PBKDF2 用、vault ごとにランダム) |
| `i` | `iv` | base64url、12 byte (本体 ciphertext の AES-GCM IV) |
| `c` | `ciphertext` | base64url (本体 ciphertext、padded、AES-GCM 認証タグ込み) |
| `w` | `wraps` | wrap 群 |
| `w.a` | `wraps.pr` | Master+Recovery で MEK を取り出す唯一の wrap (1 個) |
| `w.b` | `wraps.pk` | 端末ごとの Master+Passkey wrap の配列 |
| `w.c` | `wraps.kr` | 端末ごとの Passkey+Recovery wrap の配列 |

各 wrap エントリ:

| JSON | 内部名 | 内容 |
|---|---|---|
| `h` | `credIdHash` | base64url、SHA-256(WebAuthn credential id) (端末識別、`w.a` には不要) |
| `i` | `iv` | base64url、12 byte (この wrap の AES-GCM IV) |
| `c` | `ciphertext` | base64url (MEK を KEK で AES-GCM 包んだもの、認証タグ込み) |

### v4 から削除されたフィールド

| 削除されたフィールド | 削除理由 |
|---|---|
| `k` (KDF パラメータブロック `{n, i, s}`) | algorithm name と iteration 数は `v` で暗黙規定。salt のみ top-level `s` に昇格 |
| `d` (devices メタ配列) | 端末名・追加日・deviceId が **平文で** Arweave 上に残っていたフィールド。本体 `c` (暗号化領域) の中に移動 |
| 各 wrap の `d` (deviceId) | credIdHash と 1:1 対応する死にフィールドだったため削除 |
| 各 wrap の `n`, `a` (name, addedAt) | 同上、本体 `c` 内に移動 |
| `migratedFromV3At`, `passwordChangedAt` | UI metadata 扱いとして本体 `c` 内に統合 |

---

## 外側暗号化層 (Arweave に書く blob)

エンベロープ JSON を完成させたあと、**さらにもう一段** AES-256-GCM で wrap してから Arweave に書きます。

### 鍵の派生

```
outer_key = HKDF-SHA256(
  ikm  = rMat,                           // 32 byte (Recovery Secret 由来)
  salt = "arpass-outer-v6",
  info = "envelope-wrap",
  L    = 32                              // 256-bit AES key
)
```

`rMat` (= Recovery Secret) を持つ人 (= ユーザー本人) だけが導出できる鍵です。Phase 7.0w-AR より前は `ikm = vault-id` / `salt = "arpass-outer-v5"` でしたが、vault-id 廃止に伴い `rMat` 直接派生 + ドメイン分離のため salt を `v6` に更新しました。

### 書き込み手順

```
envelopeJson = JSON.stringify({ v: 5, s, i, c, w })
outerIv      = randomBytes(12)
outerCt      = AES-256-GCM(outer_key, outerIv, envelopeJson)
blob         = outerIv || outerCt              // 12 + N + 16 byte
↓
Arweave に blob を書き込む (タグは下記)
```

### 読み込み手順

```
blob       = Arweave から取得
outerIv    = blob.slice(0, 12)
outerCt    = blob.slice(12)
envelopeJson = AES-256-GCM-decrypt(outer_key, outerIv, outerCt)
envelope   = JSON.parse(envelopeJson)
↓
通常の v5 復号フロー (wrap 選択 → MEK → 本体 c 復号)
```

### この層の目的

外側層は **「Arpass の存在自体を Arweave 上で隠す」** ための obfuscation 兼 機密性レイヤです。これがないと、Arweave 全件をスキャンする攻撃者は JSON parse + キー集合 `{v, s, i, c, w}` の一致で「これは Arpass の vault だ」と特定できてしまいます。

外側層を入れることで、Arweave に書かれる blob は完全な乱数バイト列に見え、JSON 構造・フィールド名・暗号アルゴリズム名・サイズ分布などのフィンガープリントが全て消えます。`rMat` を持つ本人だけが `outer_key` を導出して復号できるので、これは**機密性を提供する**層でもあります (`outer_key` がサーバ・Arweave のどこにも露出しないため、obfuscation 以上の意味を持つ)。

詳しい背景は [crypto-rationale.md §外側暗号化](./crypto-rationale.md) を参照。

---

## 鍵導出

### 1. パスワード材料 `pMat`

ユーザーが入力した Master Password から PBKDF2 で派生される 32 byte。

```
pMat = PBKDF2-HMAC-SHA256(
  password,
  salt = envelope.s,         // 16 byte、vault ごとにランダム
  iterations = 600_000,
  L = 32
)
```

### 2. Passkey 材料 `kMat`

WebAuthn PRF 拡張で得る端末固有の 32 byte。

```
kMat = HKDF-SHA256(
  ikm  = prfOutput,          // navigator.credentials.get() の PRF 出力 (32 byte)
  salt = "arpass-passkey-prf-v1",
  info = "passkey-material",
  L    = 32
)
```

### 3. Recovery 材料 `rMat`

Recovery Secret の文字列から HKDF で派生される 32 byte。

```
rMat = HKDF-SHA256(
  ikm  = utf8(recoverySecretString),     // RS1-XXXX-... 43 文字
  salt = "arpass-recovery-v1",
  info = "recovery-material",
  L    = 32
)
```

### 4. KEK 導出

3 種の wrap に対応する 3 つの KEK を、上記材料の組み合わせで導出。

```
KEK_pr = HKDF(ikm = pMat || rMat,    salt = "arpass-kek-pr-v1", info = "kek-pr", L = 32)
KEK_pk = HKDF(ikm = pMat || kMat,    salt = "arpass-kek-pk-v1", info = "kek-pk", L = 32)
KEK_kr = HKDF(ikm = kMat || rMat,    salt = "arpass-kek-kr-v1", info = "kek-kr", L = 32)
```

### 5. wrap

vault 共通の MEK を 3 通りに包む。

```
MEK = randomBytes(32)                  // vault 作成時に 1 回だけ生成、以降不変

wraps.pr   = { iv: rand12, ct: AES-GCM(KEK_pr, iv, MEK) }
wraps.pk[] = [ { h: credIdHash, iv: rand12, ct: AES-GCM(KEK_pk, iv, MEK) }, ... ]
wraps.kr[] = [ { h: credIdHash, iv: rand12, ct: AES-GCM(KEK_kr, iv, MEK) }, ... ]
```

### 6. 本体暗号化

```
plaintext  = JSON.stringify(vault)
padded     = padToBucket(plaintext)       // on-chain ~110 KiB ±6 KiB バケット (Phase 6.7)
iv         = randomBytes(12)
ciphertext = AES-256-GCM(MEK, iv, padded)
```

### 7. 署名鍵 (v5 新規 — Arweave に保存しない)

ECDSA P-256 鍵ペアを MEK から決定論的に派生する。**保存はしない**。

```
seed = HKDF-SHA256(
  ikm  = MEK,
  salt = "arpass-signing-key-v5",
  info = "p256-keypair",
  L    = 32
)

d = bytesToBigInt(seed) mod n            // P-256 curve order
Q = d × G                                // 公開鍵 (基準点 G の d 倍)
```

毎セッション開始時 (= unlock 後) に MEK から派生して使う。同じ MEK からは必ず同じ (d, Q) が出るので、端末復旧後も同じ identity が再現される。

---

## サイズパディング (Phase 5.2 改訂)

本体 `c` のサイズで vault のエントリ数を推定されないよう、**離散バケット + ジッタ**にパディングしてから AES-GCM 暗号化する。

```
buckets = [80 KiB, 160 KiB, 240 KiB]   // Phase 6.7: on-chain 110 KiB ターゲット
jitter  = 0..8 KiB のランダム加算
target  = 最も小さい bucket s.t. plaintext.length + 16 <= bucket
        + jitter
padded  = plaintext || 0x80 || 0x00 * (target - plaintext.length - 17)
```

復号時は末尾の `0x80` マーカーを後方探索して padding を取り除く (ジッタ加算分のゼロ埋めは scan が継続できるため復号に影響しない)。

外側暗号化が加わったため、Arweave 上の最終 blob サイズは `12 + (bucket + jitter) + 16` の範囲。

### バケット最小値が 80 KiB である理由 (Phase 6.7、旧 Phase 5.2 = 120 KiB)

最小バケット 80 KiB raw → on-chain 約 110 KiB は **4 つの目的を同時に達成する** ように設計されている。Phase 5.2 では 120 KiB raw だったが、on-chain 162.97 KiB / ¥0.47/write が過剰だったため、Phase 6.7 で実 upload 測定に基づき 80 KiB raw / on-chain 110 KiB / ¥0.33/write に最適化した。

| 目的 | v5.0 退化 [4 KiB, ...] | v5.2 復元 [120 KiB, ...] | v6.7 最適化 [80 KiB, ...] |
|---|---|---|
| (a) フィンガープリント耐性 | tx サイズで Arpass vault を一発抽出できた | on-chain ~163 KiB 固定で抽出耐性 ✓ | on-chain ~110 KiB ± 6 KiB jitter で揺らぎ + 抽出耐性 ✓ |
| (b) Turbo フリーライド回避 | 4 KiB write は Turbo 無料枠に収まり全 user が無料枠で書き続ける状態 = AUP 違反 | 全 write が有料 tier (¥0.47/write) | 全 write が有料 tier (¥0.33/write、無料枠 100 KiB を on-chain ~110 KiB で確実に超過) ✓ |
| (c) サイズ秘匿 | エントリ数の増減で bucket が頻繁に変わり外部に漏れた | bucket 変化が稀 ✓ | bucket [80, 160, 240] KiB の階層化 + jitter で同様 ✓ |
| (d) コスト最小化 (Phase 6.7 追加) | n/a | ¥0.47/write (過剰) | ¥0.33/write (Turbo 実測ベース最適化、Free tier 自社負担を ¥47→¥33 に圧縮) ✓ |

旧値 [4 KiB, 16 KiB, 64 KiB, 256 KiB, 1 MiB, 4 MiB] は v5 cutover 直後 (Phase 5.0〜5.1) に存在したが、(a) と (b) を同時に破る重大バグだった。Phase 5.2 で [120 KiB, ...] に復元。Phase 6.7 で実 upload 測定 (`scripts/measure-turbo-write-cost.mjs`) により Turbo 無料枠が on-chain 100 KiB と確定したため、[80 KiB, 160 KiB, 240 KiB] に最適化した。raw 80 KiB → base64 1.33× → on-chain 約 110 KiB で安全余裕 ~10 KiB を確保しつつ、コストを 30% 圧縮。

ジッタ (`PAD_JITTER_BYTES = 8 KiB`) は同一ユーザーの連続書き込みでも tx サイズが揺らぐので「サイズ X = Arpass」というフィンガープリントが成立しない追加防御。

---

## Phase 5.3 改訂: クライアント耐性とサーバ匿名化

v5 公開後に追加された 4 つの重要な改修。

### 5.3-A: 楽観的並行制御 (`expectedLatestTxId`)

複数端末で同時編集 → 後保存が古いデータで上書きするのを防ぐ。

```
1. unlock 時にサーバから latestTxId を取得して session に保存
2. saveVault: signedFetch("/api/save", { ..., expectedLatestTxId: session.latestTxId })
3. サーバ側: KV の現在の latestTxId と一致しなければ 409 version_conflict を返す
4. クライアント側: 409 を受けたら toast「他端末で更新されました。ロック解除し直してください」+ 編集を破棄せず保留
```

server-side `_safeOptLock(expected, current)` で照合。`expected === undefined` の場合は古いクライアントとみなして警告のみ (互換性)。

### 5.3-B: localStorage envelope cache (cache-first fetch)

bundling 中の Arweave gateway の 0〜2 分窓 (= Turbo CDN は受領済みだが arweave.net は 404) でユーザを 30 秒待たせない設計。

```
fetchEnvelope():
  1. localStorage から cache lookup (sync 同等で即時)
     a. hit → 即座に return + 裏で network probe を発火 (background fresh)
     b. cache の latestTxId とサーバの latestTxId を比較し、差異があれば update
  2. cache miss → network fetch (Turbo + arweave.net 並列、30s timeout)
```

cache key: `arpass.cache.envelope.<txid>`、value: 外側暗号化済み blob (= 平文 vault は localStorage に存在しない)。
クライアントが lock 状態に戻っても cache は残るので、次回 unlock 時に initial fetch が高速化。
**localStorage 内容も外側暗号化済みなので、ブラウザプロファイル盗難でも解読不能** (`rMat` 由来の `outer_key` を持たない攻撃者には)。

### 5.3-AA: ephemeral session token (Stripe metadata 匿名化)

旧設計: Stripe Checkout の `metadata` に `publicKeyHash` を直接渡していた → Stripe DB に persistent な Arpass 識別子が永続的に残るリスク。

新設計: 30 分有効の使い捨て token を Cloudflare KV に発行し、Stripe metadata には token のみを渡す。webhook 受信時に KV から resolve → consume (delete) する。

```
checkout.js (POST /api/checkout):
  sessionToken = randomBase64Url(32)  // 256-bit, 43 chars
  ARPASS_LEDGER.put(`checkout:${sessionToken}`, { publicKeyHash, pack, credits, createdAt },
                    { expirationTtl: 30 * 60 })  // KV 側自動削除
  form.append("metadata[sessionToken]", sessionToken)

webhook.js (POST /api/webhook/stripe):
  sessionToken = event.data.object.metadata.sessionToken
  data = ARPASS_LEDGER.get(`checkout:${sessionToken}`)
  ARPASS_LEDGER.delete(`checkout:${sessionToken}`)  // consume
  // クレジット加算
```

これで Stripe 側の DB に Arpass の persistent identifier が一切残らない。

### 5.3-J: Passkey hint + picker hybrid

複数 Passkey を同一 Relying Party に登録している場合、`allowCredentials = [{ id: hintId }]` だけだと「現在の hint が消えた」「ユーザーが別の Passkey を選びたい」ケースで詰む。

```
authenticateWithPasskey(hint, options = {}):
  if hint && !options.forcePicker:
    allowCredentials = [{ id: hint }]    // 1 クリック (auto-fill)
  else:
    allowCredentials = []                 // 全候補ピッカー
```

呼出側は: hint 経路で失敗 (NotAllowedError 等) → catch して `forcePicker: true` で再呼出。「別の Passkey で開錠する」UI ボタンも `forcePicker: true` で同じ関数を呼ぶ。

---

## 復号ロジック

### Path AB: Master + Passkey (日常 unlock)

```
1. rMat から outer_key = HKDF(rMat) を派生
2. Arweave から最新 blob 取得 → outer_key で復号 → envelope JSON
3. credIdHash = SHA-256(WebAuthn credential id)
4. wraps.pk[] から credIdHash 一致のエントリを探す
5. KEK_pk = HKDF(pMat || kMat)
6. AES-GCM-decrypt(KEK_pk, wrap.iv, wrap.ct) → MEK
7. AES-GCM-decrypt(MEK, envelope.i, envelope.c) → padded JSON
8. padding を取り除いて JSON.parse
9. signing key (d, Q) = HKDF(MEK)
```

### Path AC: Master + Recovery (端末紛失時の復旧)

```
1. Recovery Secret 入力 → rMat = HKDF(Recovery)
2. 匿名タグ (name/value) を rMat から派生 → 全 tier 分を一括計算
3. Arweave に匿名タグで問い合わせ → 最新 tx 取得
4. outer_key = HKDF(rMat) で blob 復号 → envelope JSON
5. KEK_pr = HKDF(pMat || rMat)
6. wraps.pr (1 個) を AES-GCM 復号 → MEK
7. 本体復号 → vault データ
8. signing key (d, Q) = HKDF(MEK)  ← v4 と違って、同じ Q が再現される
```

### Path BC: Passkey + Recovery (Master 忘却時の復旧)

```
1. Recovery Secret 入力 + Passkey 認証 (WebAuthn PRF)
2. rMat 派生 → 匿名タグで Arweave 取得 → outer_key = HKDF(rMat) で外側復号
3. KEK_kr = HKDF(kMat || rMat)
4. wraps.kr[] から credIdHash 一致のエントリ → 復号 → MEK
5. 本体復号 → 全データアクセス可能
6. UI: 「新しい Master Password を設定」
7. 新 Master を入力すると wrap_pr と wrap_pk (この端末分) が再生成される
```

---

## 端末追加 (`addDevice`)

新端末を追加するには **常に Recovery Secret が必要** です (v5 では QR ペアリングは採用しない)。

```
[新端末で Master + Recovery で unlock 済み (= MEK を持っている)]
1. 新 Passkey を WebAuthn で登録 → credentialId, prfOutput 取得
2. credIdHash = SHA-256(credentialId)
3. kMat = HKDF(prfOutput)
4. KEK_pk = HKDF(pMat || kMat) → wraps.pk に新エントリ追加
5. KEK_kr = HKDF(kMat || rMat) → wraps.kr に新エントリ追加
6. envelope を Arweave に書き直し (1 credit 消費)

→ MEK 不変、publicKey 不変 → サーバ KV は無関係
```

---

## パスワード変更 (`changePassword`)

Master Password を変更するには現在の Recovery が必要。

```
[現端末で Master + Recovery で unlock 済み]
1. 新 Master Password 入力
2. 新 pMat = PBKDF2(新 Master, envelope.s)
3. 新 KEK_pr = HKDF(新 pMat || rMat) → wraps.pr 再生成
4. 新 KEK_pk = HKDF(新 pMat || kMat) → この端末の wraps.pk[] エントリ再生成
5. 他端末の wraps.pk[] は触らない (lazy 補完)
6. envelope を Arweave に書き直し (1 credit)

→ MEK 不変、publicKey 不変 → サーバ KV は無関係
他端末は次回 unlock 時に古い wraps.pk 復号失敗 → Recovery で fallback unlock →
その時に自分の wraps.pk を新 Master で再生成 (lazy migration)
```

---

## Recovery 再発行

2 通りの選択肢があります。

### ケース A — MEK 据え置き

「紙を紛失したが盗まれた可能性は低い」場合の軽量 rotation。

```
1. 新 Recovery 生成
2. 新 rMat = HKDF(新 Recovery)
3. wraps.pr 再生成 (新 rMat 使用)
4. wraps.kr[] を再生成 (この端末分のみ、他は lazy)
5. 新 outer_key = HKDF(新 rMat)
6. 新 匿名タグ (name/value) を新 rMat から派生
7. envelope を新 outer_key で暗号化 + 新タグで Arweave に書き込み (1 credit)

→ MEK 不変、publicKey 不変 → サーバ KV 無関係
注意: 古い envelope は Arweave 上に永久に残る。古い Recovery + Master を入手された場合は過去 vault が読めてしまう (MEK 同じため)。
```

### ケース B — MEK ごと一新

「Recovery を盗まれた疑いがある」場合の本格 rotation。

```
1. 新 MEK = randomBytes(32)
2. 新 Recovery 生成
3. 新 (d, Q) = HKDF(新 MEK)  ← publicKey が変わる
4. 全 wrap を新 MEK + 新 Recovery で再生成
5. 本体 c を新 MEK で再暗号化
6. 新 rMat 由来の outer_key + 匿名タグで envelope を Arweave に書き込み
7. POST /api/migrate を旧鍵で署名 → サーバが旧 KV[H(Q)] の credits を新 KV[H(Q')] に移送
8. localStorage 更新

→ publicKey 変わる、サーバ KV migration 必要
→ 古い envelope の中身は古い MEK を持たない人には永久に読めない
```

---

## Phase 7.2: Business mode envelope (`m: "business"`)

Phase 7.2-B で、組織向けの **Business mode** 用 envelope バリアントを追加しました。バージョン番号は `v: 5` のまま、`m: "business"` フィールドの有無で Personal / Business を判別します。Personal mode envelope は一切変更しません。

### Business envelope の追加フィールド

```json
{
  "v": 5,
  "m": "business",
  "kdfV2": true,
  "cid": "<companyId>",
  "s": "...", "i": "...", "c": "...",
  "w": { "a": {...}, "b": [...], "c": [...] },
  "w_emp": { "i": "...", "c": "..." },
  "emp_pub": { ... },
  "k1Pending": true
}
```

| JSON | 内容 |
|---|---|
| `m` | `"business"` 固定 (このフィールドが無ければ Personal mode) |
| `kdfV2` | `true` — `real_MEK` を K2 ベースの HKDF で派生する方式 (Phase 7.3-A) |
| `cid` | companyId (会社識別子) |
| `w` | Personal mode と同じ 2-of-3 wrap 構造。ただし wrap される鍵は **MEK ではなく K2** |
| `w_emp` | 社員 ECDH 鍵ペアの秘密鍵を K2 で AES-GCM wrap したもの |
| `emp_pub` | 社員 ECDH 公開鍵 (JWK)。整合性確認用のキャッシュ (サーバが authoritative) |
| `k1Pending` | signup 直後で Admin から K1 がまだ配布されていない状態を示す (任意フィールド) |

### Personal mode との暗号上の差分

1. 本体 `c` の暗号鍵は単独の MEK ではなく `real_MEK = HKDF(K1 ‖ K2, salt="arpass-business-mek-v2", info="real-mek")`
2. `w.{a,b,c}` が wrap するのは K2 (会社共通の K1 ではなく、社員個別の鍵)
3. 会社共通の K1 は envelope には乗らず、サーバ KV に社員ごとの ECIES wrap (`enc_K1[i]`) として保管される
4. K1 配布まわりの設計根拠は [crypto-rationale.md の Phase 7.2 節](./crypto-rationale.md) を参照

> v1 設計では K1 を `envelope.ws` として Arweave 上に乗せていましたが、v2 で **K1 関連データを Arweave から完全に除去**し、サーバ KV のみで lifecycle 管理する方式に変更しました。`envelope.ws` / `envelope.kv` フィールドは廃止済みです。

### Business mode の unlock 順序

```
1. Arweave から vault envelope を取得 (公開 read、認証不要)
2. w.{a|b|c} を 2-of-3 factor KEK で開く → K2
3. signing key = HKDF(K2, "arpass-signing-v2")
   emp_priv = AES-GCM-decrypt(K2, w_emp)
   ← ここまで K1 不要、K2 のみで完結
4. signing key で署名して GET /api/corp/unwrap-k1 → enc_K1[i] 取得
5. emp_priv で ECIES 復号 → K1
6. real_MEK = HKDF(K1 ‖ K2) (非 extractable CryptoKey)
7. 本体 c を real_MEK で復号
```

`k1Pending: true` の envelope は K1 = 全ゼロ 32 byte (sentinel) で本体が暗号化されており、後で Admin が実 K1 を配布したタイミングで実 K1 による再暗号化が行われます。

---

## Phase 7.3: 非 extractable CryptoKey 化 (envelope フォーマット不変)

Phase 7.3-A は **envelope フォーマットを一切変更しません**。Arweave に書かれる v5 / business envelope の暗号文構造はそのままです。

変更されるのは **クライアント実装が鍵をどう保持するか**だけです。従来は `MEK` などを raw な `Uint8Array(32)` で session に保持していましたが、Phase 7.3-A 以降は非 extractable な `CryptoKey` (= JS から生バイト列を取り出せない鍵オブジェクト) として保持します。詳細と防御範囲は [crypto-rationale.md の Phase 7.3 節](./crypto-rationale.md) を参照。

マイグレーションは不要で、既存ユーザは次回 unlock 時に自動的に新しい派生 chain で session を構築します。

---

## Phase 7.4: envelope v7 — Passkey が outer 鍵を運ぶ (新端末解錠)

Phase 7.4 は **envelope の JSON フォーマットを一切変更しません** (`v: 5` のまま、Personal / Business とも同一)。Arweave に書かれる暗号文構造・サイズパディング・匿名タグはすべて Phase 7.0w-AR と同一です。変わるのは **outer 鍵をどこから入手するか**だけです。

### 動機

v6 まで、新しい端末で既存 vault を開くには outer 鍵 (`HKDF(rMat)`) が必要でしたが、これは端末の localStorage にしか無いため、新端末は必ず Recovery Secret の入力を要しました。Recovery Secret の現実的な保管 (印刷) が難しい利用者が多いため、「鍵 (Passkey / YubiKey) と Master だけで、どの端末でも開ける」状態を目指します。

### 仕組み — outer 鍵を WebAuthn user.id に格納

Passkey の WebAuthn `user.id` (userHandle、認証器が保持・同期/携行する最大 64 byte 領域) に、次の 57 byte ペイロードを格納します。

```
[1 byte version=7][8 byte appNameTag.name][16 byte appNameTag.value][32 byte outer_key (Master ラップ済)]
```

- `outer_key` は v6 と同一の `HKDF(rMat)`。ただし user.id 内では Master でラップして格納します (下記)。
- `appNameTag` は Arweave 検索用の匿名タグ (name/value) — [arweave-tags.md](./arweave-tags.md) を参照。

新端末では WebAuthn の `get()` を 1 回行うだけで userHandle と PRF が同時に得られます。userHandle から outer 鍵と appNameTag を取り出し → Arweave から vault を取得 → 外側 AES-GCM を復号 → 通常の 2-of-3 unlock。**localStorage も Recovery 入力も不要**です。

### outer 鍵は Master でラップして user.id に持つ

`user.id` は credential を作成する *前* に確定する入力値で、PRF はその credential を作成した *後* にしか得られません。したがって「その credential 自身の PRF で user.id を暗号化する」ことは原理的に不可能です (鶏と卵)。よって PRF は使えません。代わりに **outer 鍵を Master パスワード由来鍵で AES-256-CTR ラップして user.id に持ちます** (v7 ハードニング 2026-05-24)。Master は credential 作成順序と独立なので順序制約に抵触しません。ラップ鍵 = `PBKDF2-SHA256(Master, salt=appNameTag.value, 600k)`、AES-CTR は非膨張なので user.id は 57 byte を維持します。誤 Master の検出は独自タグを持たず下流の外側 AES-GCM 層に委譲します (誤 Master → 誤 outer 鍵 → envelope 復号がそこで失敗)。この設計は安全です:

- `user.id` は Passkey ハードウェアでゲートされ、読み出しに物理鍵 + タッチ + UV を要します。マルウェアも Arweave スクレイパーも読めません。さらに outer 鍵は Master でラップ済なので、仮に user.id が将来想定外の場所 (パスキー export 規格・OS 変更・フォレンジック等) へ漏れても、Master を知らない者には暗号文でしかありません。
- Arweave 公開オブジェクトは v6 と完全に同一で、outer 鍵は公開側に一切載りません → anti-fingerprint は無傷。
- outer 鍵は難読化層 (外側 AES-GCM) の鍵であり、vault 本体の機密性鍵ではありません。本体は MEK + 2-of-3 要素で守られます。露出しうるのは「あなたの物理 Passkey を持つ者」だけで、その者は既に要素 B を握っています。
- appNameTag (vault の所在) は秘密ではなく Arweave 上の匿名タグそのものなので、user.id 内では平文で持ちます (ラップ対象は outer 鍵 32 byte のみ)。

### 適用範囲

Personal / Business / Admin の全モードが対象です。同期パスキー (iCloud Keychain / Google Password Manager) と YubiKey 等のセキュリティキーの双方で動作します。あわせて Master の最低長 8 文字を撤廃しました (空のみ不可)。サービス未公開のため v6 → v7 のデータ移行は実装せず、v7 を全新規 vault の形式とします。完全な実装仕様はサービス本体リポジトリの `docs/envelope-v7-spec.md` に対応します。

---

## 互換性

- v4 / v4.1 envelope と **互換性なし** (Arpass は公開前のため、移行ユーザーは存在しない)
- 読み込み時は `envelope.v` をチェックし、`v: 5` 以外は明示的に reject する

---

## 関連

- [crypto-rationale.md](./crypto-rationale.md) — アルゴリズム選定の根拠と v5 で新たに追加した設計の理由
- [arweave-tags.md](./arweave-tags.md) — Arweave トランザクションタグの仕様
