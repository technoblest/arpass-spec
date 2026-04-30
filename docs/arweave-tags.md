# Arweave トランザクションタグ仕様

Arpass が Arweave に書き込むトランザクションには tag (key/value pair) が付与されます。本ドキュメントは付与するタグの種類と、それぞれの匿名化ポリシーを定義します。

v4.1 (2026-04) と v5 (2026-04) で **平文タグから ID 系情報を全て撤去** する設計に進化しました。本ドキュメントは v5 時点の最新状態を記述します。過去フォーマット (v3 以前) との差分は最後の節を参照してください。

---

## 設計目標

1. **GraphQL で自分の vault のトランザクションを検索可能にする** — 自分しか持っていない情報 (Recovery Secret 由来の HMAC) で逆引きできる必要がある
2. **第三者がスキャンしても「どれが Arpass の tx か」を一目で識別できないようにする** — `App-Name = "Arpass"` のような共通識別子は付けない
3. **vault の中身 (バージョン、暗号アルゴリズム、所有者属性等) を tag に出さない** — 暗号化された envelope blob 内にのみ書く
4. **vault-id を一切 Arweave に露出しない** (v4.1 で導入された不変条件、v5 で更に厳格化)

---

## 付与されるタグ (v5)

| Tag name | 値 | 由来 |
|---|---|---|
| `App-Name` | per-user 匿名化値 (後述) | クライアントが計算してリクエストに含める |
| `Content-Type` | `application/octet-stream` | 固定 (v5: 外側暗号化により JSON 構造を隠す) |
| `Unix-Time` | エポック秒 | サーバが書き込み時刻を付与 |

**v5 で削除されたタグ**:

- `vault-id` — v4.1 で平文タグ送出を停止 (`functions/api/write.js` の `tags` から撤去)
- `Arpass-Phase` — 運用情報の漏洩を防ぐため v5 で削除 (内部運用は KV 内でのみ管理)
- `Arpass-*` 系の任意タグ — Arpass の存在を Arweave 上で識別可能にする情報は一切付けない

---

## `App-Name` の per-user 匿名化

Arweave の GraphQL は tag-based filter を持つため、`App-Name = "Arpass"` のような固定値を使うと、攻撃者が「Arpass 利用者全員のトランザクション一覧」を 1 クエリで取得できてしまいます。これを防ぐため、`App-Name` は **ユーザごとに異なる匿名化された値** を使います。

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

## Content-Type の意味 (v5 の変更点)

v4.1 までは `application/json` を付けていましたが、v5 では **`application/octet-stream`** に変更しました。

理由: v5 では envelope JSON を [外側 AES-GCM 層](./envelope-v5.md) でさらに暗号化してから書き込むため、Arweave 上の bytes は完全な乱数バイト列に見えます。`application/json` を主張すると attacker に "JSON のはず → 構造解析して Arpass と特定" のヒントを与えてしまうため、内容実体に正しく合わせて `octet-stream` に切り替えています。

ViewBlock 等の Arweave エクスプローラでは「未知のバイナリデータ」として表示されるようになります (これも当方の意図通り)。

---

## 出さない情報

意図的に **付与しない** タグ:

| 項目 | 理由 |
|---|---|
| envelope バージョン (`v: 5`) | フォーマットを匿名化するため、内部 (外側復号後の) JSON にのみ書く |
| 暗号アルゴリズム名 | 同上 |
| 端末数・ユーザ属性 | 一切外部に漏らさない |
| ユーザ識別子 (メール、名前等) | サーバすら持たないので当然出さない |
| `vault-id` | v4.1 で平文タグから撤去、v5 でも継続禁止 |
| `Arpass-Phase` 等の運用情報 | 運用実装の詳細を外部に出さない |
| `publicKey` / `H(publicKey)` | サーバ KV のキーであるが、Arweave には出さない |

---

## サーバ側のタグ取り扱い

書き込みリクエスト (`/api/write`) を受けたサーバは、クライアントが送ったタグに加えて以下を **必ず付与** します:

- `Content-Type` — `application/octet-stream` 固定
- `Unix-Time` — サーバ時刻から

クライアントが送る `tags` には **`App-Name` のみ** が意味を持ちます。サーバはそれをそのまま転送し、上書きはしません。

**v5 で重要な変更**: クライアントの認証は `X-Public-Key` ヘッダ + ECDSA 署名で行い、サーバは認証された publicKey から KV キー `H(publicKey)` を導出して残高管理します。`vault-id` を一切受信せず、Arweave タグにも追加しません。

---

## レガシー値 (履歴)

互換性のため過去のフォーマットでは以下の値が存在しました:

| バージョン | App-Name | 撤去時期 |
|---|---|---|
| v3 以前 | `"Arpass-Vault"` 固定 | v4.0 で per-user 匿名化に移行 |
| v4.0 | per-user 匿名化 + レガシー値の両方検索 | v4.1 で `LEGACY_APP_NAME = "Arpass-Vault"` のフォールバック完全削除 |
| v4.1 / v5 | per-user 匿名化のみ | (現行) |

`vault-id` タグも v4.0 まではサーバが平文で付与していましたが、v4.1 で削除されました。

これらの撤去理由と検出方法は `arpass` レポジトリ側 `docs/security-baseline.md` に詳細あり (公開部分は `arpass-spec` には載せていません)。
