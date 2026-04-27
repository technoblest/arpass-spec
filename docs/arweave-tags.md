# Arweave トランザクションタグ仕様

Arpass が Arweave に書き込むトランザクションには、tag (key/value pair) が付与されます。本ドキュメントは、付与するタグの種類と、それぞれの匿名化ポリシーを定義します。

---

## 設計目標

1. **GraphQL で自分の vault のトランザクションを検索可能にする** — `vault-id` で逆引きできる必要がある
2. **第三者がスキャンしても「どれが Arpass の tx か」を一目で識別できないようにする** — `App-Name = "Arpass"` のような共通識別子は付けない
3. **vault の中身（バージョン、暗号アルゴリズム、所有者属性等）を tag に出さない** — 暗号化された envelope JSON 内部にのみ書く

---

## 付与されるタグ

| Tag name | 値 | 由来 |
|---|---|---|
| `App-Name` | per-user 匿名化値（後述） | クライアントが計算してリクエストに含める |
| `vault-id` | base64url、公開鍵 SHA-256 ハッシュ | identity から派生 |
| `Content-Type` | `application/json` | 固定 |
| `Unix-Time` | エポック秒 | サーバが書き込み時刻を付与 |

---

## `App-Name` の per-user 匿名化

Arweave の GraphQL は tag-based filter を持つため、`App-Name = "Arpass"` のような固定値を使うと、攻撃者が「Arpass 利用者全員のトランザクション一覧」を1クエリで取得できてしまいます。これを防ぐため、`App-Name` は **ユーザごとに異なる匿名化された値** を使います。

```
appNameTag = base64url-truncate(
  HMAC-SHA256(
    key = recoveryMaterial,
    message = "arpass-app-name-tag-v1"
  ),
  16 chars  // base64url、~96 bit
)
```

- 同じ Recovery Secret からは常に同じ `appNameTag` が導出される
- 別ユーザの Recovery では別の `appNameTag` になる
- HMAC なので Recovery を持たない第三者は値を予測不能

→ **同じ Recovery を知る端末同士でのみ、お互いの tx を発見可能**。同時に、サービス全体のトランザクションを横断的に列挙することは困難。

---

## レガシー値

互換性のため、過去のフォーマットでは固定値 `"Arpass-Vault"` を `App-Name` に使っていました。GraphQL で過去 tx を検索する際は、両方の候補値を tag フィルタの値配列に含めます:

```graphql
transactions(
  tags: [
    { name: "App-Name",
      values: ["Arpass-Vault", "<per-user-anonymized-tag>"] },
    { name: "vault-id",
      values: ["<vaultId>"] }
  ]
)
```

これにより、レガシー envelope と新形式の envelope の両方が見つかります。

---

## 出さない情報

意図的に **付与しない** タグ:

| 項目 | 理由 |
|---|---|
| envelope バージョン (`v: 4`) | フォーマットを匿名化するため、内部 JSON にのみ |
| 暗号アルゴリズム名 | 同上 |
| 端末数・ユーザ属性 | 一切外部に漏らさない |
| ユーザ識別子（メール、名前等） | サーバすら持たないので当然出さない |
| Phase 識別子（"Phase-A"等の運用情報） | 運用実装の詳細を外部に出さない |

---

## サーバ側の追加タグについて

書き込みリクエスト (`/api/write`) を受けたサーバは、クライアントが送ったタグに加えて以下を **必ず付与** します:

- `vault-id` — リクエストヘッダの `X-Vault-Id` から（クライアントが偽れない）
- `Content-Type` — body から
- `Unix-Time` — サーバ時刻から

クライアントが送る body の `tags` は **`App-Name` のみ** が意味を持ちます。サーバはここを上書き可能にせず、クライアントから受けた `App-Name` をそのまま転送する設計です（クライアント側で `appNameTag` を計算するため）。
