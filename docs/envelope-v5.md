# Envelope v5 仕様書

Arpass の v5 保存フォーマット。各端末がブラウザ上で組み立てて Arweave に書き込み、復号時に再構築する暗号化エンベロープの構造を定義します。

v4 から **3 つの大きな変更**があります:

1. **外側 AES-GCM 層** — エンベロープ JSON 全体をさらに暗号化してから Arweave に書く (Arweave スクレイパーから JSON 構造を隠蔽)
2. **署名鍵を保存しない** — ECDSA P-256 鍵ペアは MEK から決定論的に派生する (Arweave 上に「秘密鍵」「公開鍵」のいずれも書かない)
3. **vault-id がサーバに無い** — Cloudflare KV のキーは `H(publicKey)`、`X-Vault-Id` ヘッダ廃止

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
        (outer_key = HKDF(vault-id))
```

**MEK** は vault 全体で共通の 32-byte 対称鍵で、端末ごとに新規生成されません。端末追加 (`addDevice`) はその端末用の wrap エントリを `wraps.pk[]` と `wraps.kr[]` に追加するだけで、MEK も `wraps.pr` も既存のまま継承されます。

**vault-id** は Recovery Secret から HKDF で導出される 16 byte の値で、**サーバには一切送信せず、Arweave のタグにも含めません**。クライアントは vault-id を以下の 3 つの目的にのみ使います:

1. Arweave 検索のための `App-Name` タグ計算
2. 外側 AES-GCM 層の鍵 `outer_key` 派生
3. localStorage に保存して次回のキャッシュキーに使う

API リクエストの認証は **publicKey** (MEK から派生) で行い、サーバ側 KV のキーは `H(publicKey)` です。

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
  ikm  = vault-id,                       // 16 byte
  salt = "arpass-outer-v5",
  info = "envelope-wrap",
  L    = 32                              // 256-bit AES key
)
```

`vault-id` を知っている人 (= ユーザー本人) だけが導出できる鍵です。

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

外側層を入れることで、Arweave に書かれる blob は完全な乱数バイト列に見え、JSON 構造・フィールド名・暗号アルゴリズム名・サイズ分布などのフィンガープリントが全て消えます。`vault-id` を知る人だけが復号できるので、これは**機密性を提供する**層でもあります (vault-id がサーバ・Arweave のどこにも露出しないため、obfuscation 以上の意味を持つ)。

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
padded     = padToBucket(plaintext)       // ~110 KiB ±5 KiB バケット
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
buckets = [120 KiB, 240 KiB, 480 KiB, 960 KiB, 4 MiB]
jitter  = 0..8 KiB のランダム加算
target  = 最も小さい bucket s.t. plaintext.length + 16 <= bucket
        + jitter
padded  = plaintext || 0x80 || 0x00 * (target - plaintext.length - 17)
```

復号時は末尾の `0x80` マーカーを後方探索して padding を取り除く (ジッタ加算分のゼロ埋めは scan が継続できるため復号に影響しない)。

外側暗号化が加わったため、Arweave 上の最終 blob サイズは `12 + (bucket + jitter) + 16` の範囲。

### バケット最小値が 120 KiB である理由 (Phase 5.2)

最小バケット 120 KiB は **3 つの目的を同時に達成する** ように設計されている。

| 目的 | 旧値 [4 KiB, ...] | 新値 [120 KiB, ...] |
|---|---|---|
| (a) フィンガープリント耐性 | tx サイズで Arpass vault を一発抽出できた | 全 write が 120 KiB 以上で他の Arweave トラフィックと区別不能 |
| (b) Turbo フリーライド回避 | 4 KiB write は Turbo 無料枠 (107520 B / 105 KiB) に収まり、Arpass 全 user が無料枠で書き続ける状態 = AUP 違反リスク | 全 write が無料枠を確実に超え Turbo の有料 tier に入る |
| (c) サイズ秘匿 | エントリ数の増減で bucket が頻繁に変わり外部に漏れた | bucket 変化が稀なので「エントリ数増減」が外から判別不能 |

旧値 [4 KiB, 16 KiB, 64 KiB, 256 KiB, 1 MiB, 4 MiB] は v5 cutover 直後 (Phase 5.0〜5.1) に存在したが、(a) と (b) を同時に破る重大バグだった。Phase 5.2 で全面改訂。

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
**localStorage 内容も外側暗号化済みなので、ブラウザプロファイル盗難でも解読不能** (vault-id を持たない攻撃者には)。

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
1. localStorage から vault-id を取得
2. outer_key = HKDF(vault-id)
3. Arweave から最新 blob 取得 → outer_key で復号 → envelope JSON
4. credIdHash = SHA-256(WebAuthn credential id)
5. wraps.pk[] から credIdHash 一致のエントリを探す
6. KEK_pk = HKDF(pMat || kMat)
7. AES-GCM-decrypt(KEK_pk, wrap.iv, wrap.ct) → MEK
8. AES-GCM-decrypt(MEK, envelope.i, envelope.c) → padded JSON
9. padding を取り除いて JSON.parse
10. signing key (d, Q) = HKDF(MEK)
```

### Path AC: Master + Recovery (端末紛失時の復旧)

```
1. Recovery Secret 入力
2. vault-id = HKDF(Recovery, "arpass-vault-id-v5")
3. App-Name tag = HKDF(Recovery, "arpass-app-tag-v1")
4. Arweave に App-Name タグで問い合わせ → 最新 tx 取得
5. outer_key = HKDF(vault-id) で blob 復号 → envelope JSON
6. KEK_pr = HKDF(pMat || rMat)
7. wraps.pr (1 個) を AES-GCM 復号 → MEK
8. 本体復号 → vault データ
9. signing key (d, Q) = HKDF(MEK)  ← v4 と違って、同じ Q が再現される
```

### Path BC: Passkey + Recovery (Master 忘却時の復旧)

```
1. Recovery Secret 入力 + Passkey 認証 (WebAuthn PRF)
2. vault-id 派生 → Arweave 取得 → 外側復号
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
5. 新 vault-id = HKDF(新 Recovery)
6. 新 outer_key = HKDF(新 vault-id)
7. envelope を新 vault-id で Arweave に書き込み (1 credit)
8. localStorage の vault-id を更新

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
6. 新 vault-id で envelope を Arweave に書き込み
7. POST /api/migrate を旧鍵で署名 → サーバが旧 KV[H(Q)] の credits を新 KV[H(Q')] に移送
8. localStorage 更新

→ publicKey 変わる、サーバ KV migration 必要
→ 古い envelope の中身は古い MEK を持たない人には永久に読めない
```

---

## 互換性

- v4 / v4.1 envelope と **互換性なし** (Arpass は公開前のため、移行ユーザーは存在しない)
- 読み込み時は `envelope.v` をチェックし、`v: 5` 以外は明示的に reject する

---

## 関連

- [crypto-rationale.md](./crypto-rationale.md) — アルゴリズム選定の根拠と v5 で新たに追加した設計の理由
- [arweave-tags.md](./arweave-tags.md) — Arweave トランザクションタグの仕様
