# Arweave トランザクションタグ仕様

> 🌐 English version: [en/arweave-tags.md](en/arweave-tags.md)

Arpass が Arweave に書き込むトランザクションには tag (name/value pair) が付与されます。本ドキュメントは付与するタグの種類と、それぞれの匿名化ポリシーを定義します。

Phase 7.0w-AR (2026-05) で **タグの匿名化が完成段階**に到達しました。それまでは `App-Name` という固定的なタグ名を残し、値のみを per-user 匿名化していましたが、現行設計では **タグの name と value の両方をユーザごとにランダム化**します。Arweave 上には認識可能な文字列が一切残りません。本ドキュメントは現行 (Phase 7.x) の最新状態を記述します。過去フォーマットとの差分は最後の節を参照してください。

---

## 設計目標

1. **GraphQL で自分の vault のトランザクションを検索可能にする** — 自分しか持っていない情報 (Recovery Secret 由来の鍵材料) で逆引きできる必要がある
2. **第三者がスキャンしても「どれが Arpass の tx か」を一目で識別できないようにする** — `App-Name = "Arpass"` のような共通識別子はもちろん、`App-Name` というタグ名そのものも付けない
3. **vault の中身 (バージョン、暗号アルゴリズム、所有者属性等) を tag に出さない** — 暗号化された envelope blob 内にのみ書く
4. **vault-id を一切 Arweave に露出しない** (Phase 7.0w-AR では vault-id 概念自体を廃止)
5. **書き込み種別 (vault 本体 / 添付 record) を tag から推測させない** — 種別はサーバへ HTTP body で伝え、Arweave tag には出さない

---

## 付与されるタグ (現行)

| Tag name | 値 | 由来 |
|---|---|---|
| `<匿名タグ name>` | `<匿名タグ value>` | クライアントが計算してリクエストに含める (name/value 両方 rMat 派生) |
| `Content-Type` | `application/octet-stream` | サーバが固定付与 (外側暗号化により JSON 構造を隠す) |
| `Unix-Time` | エポック秒 | サーバが書き込み時刻を付与 |

意味を持つのは **匿名タグ 1 個のみ**で、その name も value も `"App-Name"` のような認識可能な文字列ではありません。`Content-Type` と `Unix-Time` は Arweave 規格上の汎用タグで、Arpass 固有の情報を持ちません。

サーバ側は安全側で、クライアントが送る tag を厳しく制限します: tag name は ASCII 英数と `-_` のみ、name + value 合計 64 文字以下、最大 4 tag。`Content-Type` / `Unix-Time` をクライアントが送っても無視されます。

---

## 匿名タグの name / value 両方をランダム化

### なぜ name もランダム化するのか

Arweave の GraphQL は tag name でも tag value でもフィルタできます。たとえ value を per-user 匿名化しても、tag **name** が `App-Name` のような固定文字列のままだと、攻撃者は `tags: [{ name: "App-Name" }]` でフィルタして「App-Name タグを持つ tx の集合」を 1 クエリで取得できてしまいます。これは Arpass 利用者全体のトラフィック量を観測する糸口になります。

Phase 7.0w-AR では tag **name 自体も rMat から派生**することで、この糸口を塞ぎました。Arweave 上のどのタグ名にも `arpass` / `vault` といった認識可能な文字列が現れません。

### 派生

匿名タグは Recovery 材料 `rMat` (Recovery Secret から HKDF で導出される 32 byte) から、name と value を別々に派生します。

```
name  = base64url( HKDF-SHA256(
            ikm  = rMat,
            salt = "arpass-app-tag-name-v6",
            info = "app-tag-name" + tierSuffix,
            L    = 8 ) )                          // 8 byte → base64url 11 文字

value = base64url( HKDF-SHA256(
            ikm  = rMat,
            salt = "arpass-app-tag-value-v6",
            info = "app-tag-value" + tierSuffix,
            L    = 16 ) )                         // 16 byte → base64url 22 文字
```

- name は 8 byte (base64url 11 文字)、value は 16 byte (base64url 22 文字)。どちらも固定の接頭辞を持たず、見た目は完全な乱数文字列
- 同じ Recovery Secret からは常に同じ name / value が導出される (端末復旧・複数端末で同じ tx を発見できる)
- 別ユーザの Recovery では別の name / value になる
- HKDF なので Recovery を持たない第三者は値を予測不能

→ **同じ Recovery を知る端末同士でのみ、お互いの tx を発見可能**。同時に、サービス全体のトランザクションを横断的に列挙することは tag name レベルでも不可能。

### tier ごとのタグ分離 (`tierSuffix`)

`info` ラベルの末尾に `tierSuffix` を付けることで、同一ユーザでも所属 tier ごとに別のタグになります:

| tier | `tierSuffix` |
|---|---|
| legacy (tier 指定なし) | (空文字列) |
| free | `::free` |
| paid | `::paid` |
| private | `::private` |
| corp (Business mode) | `::corp::<companyId>` |

新端末で初開錠する際は所属 tier が不明なため、クライアントは全 tier 分のタグ (legacy / free / paid / private、判明していれば corp) を一括計算し、それらを 1 回の GraphQL クエリで並列検索して最新 tx を採用します。

---

## Content-Type の意味

`Content-Type` は `application/octet-stream` 固定です。Arpass は envelope JSON を[外側 AES-GCM 層](./envelope-v5.md)でさらに暗号化してから書き込むため、Arweave 上の bytes は完全な乱数バイト列に見えます。`application/json` を主張すると attacker に「JSON のはず → 構造解析して Arpass と特定」のヒントを与えてしまうため、内容実体に正しく合わせて `octet-stream` にしています。

ViewBlock 等の Arweave エクスプローラでは「未知のバイナリデータ」として表示されます (これも意図通り)。

---

## 出さない情報

意図的に **付与しない** タグ:

| 項目 | 理由 |
|---|---|
| `App-Name` というタグ名 | 固定文字列タグ名は GraphQL での横断列挙の糸口になる。Phase 7.0w-AR で name 自体をランダム化 |
| envelope バージョン (`v: 5`) | フォーマットを匿名化するため、内部 (外側復号後の) JSON にのみ書く |
| 暗号アルゴリズム名 | 同上 |
| 書き込み種別 (vault 本体 / record) | tag からは推測不能。サーバへは HTTP body の `kind` フィールドで伝える |
| 端末数・ユーザ属性 | 一切外部に漏らさない |
| ユーザ識別子 (メール、名前等) | サーバすら持たないので当然出さない |
| `vault-id` | Phase 7.0w-AR で概念ごと廃止 |
| `Arpass-Phase` 等の運用情報 | 運用実装の詳細を外部に出さない |
| `publicKey` / `H(publicKey)` | サーバ KV のキーであるが、Arweave には出さない |

---

## サーバ側のタグ取り扱い

書き込みリクエスト (`/api/write`) を受けたサーバは、クライアントが送ったタグに加えて以下を **必ず付与** します:

- `Content-Type` — `application/octet-stream` 固定
- `Unix-Time` — サーバ時刻から

クライアントが送る `tags` には **匿名タグ 1 個のみ**が意味を持ちます。サーバはそれをそのまま転送し、上書きはしません。書き込み種別はタグではなく HTTP body の `kind` フィールドで受け取ります (anti-fingerprint 維持のため)。

クライアントの認証は `X-Public-Key` ヘッダ + ECDSA 署名で行い、サーバは認証された publicKey から KV キー `H(publicKey)` を導出して残高管理します。`vault-id` を一切受信せず、Arweave タグにも追加しません。

---

## レガシー値 (履歴)

互換性のため過去のフォーマットでは以下が存在しました:

| バージョン | タグ name | タグ value | 撤去時期 |
|---|---|---|---|
| v3 以前 | `App-Name` 固定 | `"Arpass-Vault"` 固定 | v4.0 で value を per-user 匿名化 |
| v4.0 | `App-Name` 固定 | per-user 匿名化 + レガシー値の両方検索 | v4.1 でレガシー値フォールバック削除 |
| v4.1 / v5 初期 | `App-Name` 固定 | per-user 匿名化 (HMAC 由来) のみ | Phase 7.0w-AR で name もランダム化 |
| Phase 7.0w-AR 以降 | rMat 派生でランダム化 | rMat 派生でランダム化 | (現行) |

`vault-id` タグも v4.0 まではサーバが平文で付与していましたが、v4.1 で削除され、Phase 7.0w-AR で vault-id 概念そのものが廃止されました。

これらの撤去理由と検出方法は `arpass` レポジトリ側 `docs/security-baseline.md` に詳細あり (公開部分は `arpass-spec` には載せていません)。
