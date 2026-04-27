# arpass-spec

**Arpass のクライアント側暗号コードと仕様書 — 公開部分。**

このリポジトリは [Arpass](https://arpass.io)（Technoblest 株式会社が運営する、Arweave 永続ストレージを使ったゼロ知識パスワード管理サービス）の信頼性を第三者が独立に検証できるようにするためのものです。

「**運営側はあなたのパスワードを見られません**」という主張がコードレベルで本当か、どなたでも確認できます。

---

## このリポジトリに何があるか

| 場所 | 内容 |
|---|---|
| [`lib/vault-crypto.js`](lib/vault-crypto.js) | すべての暗号処理（鍵導出、暗号化、復号、Passkey 連携、Recovery 派生） |
| [`lib/vault-client.js`](lib/vault-client.js) | envelope の構築、保存、ロード、多端末同期、Recovery 再発行 |
| [`lib/client-auth.js`](lib/client-auth.js) | Ed25519 署名による API 認証、Arweave からのデータ取得 |
| [`docs/envelope-v4.md`](docs/envelope-v4.md) | エンベロープ JSON 構造の仕様 |
| [`docs/arweave-tags.md`](docs/arweave-tags.md) | Arweave トランザクションタグの意味と匿名化方針 |
| [`docs/crypto-rationale.md`](docs/crypto-rationale.md) | 採用したアルゴリズムの選定理由 |

これらだけで「Arpass がブラウザ上で何を暗号化しサーバーに何を送っているか」が完全に追跡可能です。

---

## このリポジトリに **無いもの**（意図的に）

- **サーバー側コード** (`/api/*` の Cloudflare Pages Functions) — Arpass のサーバーは設計上、暗号化されたエンベロープ（不透明な ciphertext）と匿名 ID しか扱いません。サーバーが平文を見られないことは **クライアント側のコードを読めば検証可能** で、サーバーの実装を公開する必要はありません。Stripe Webhook、KV Ledger 等の運用ロジックは非公開です。
- **マーケティングページ・UI 全体** (`web/*.html`) — 営業資産であり、技術検証には不要です。
- **秘密鍵・運用設定** — Turbo wallet、Stripe シークレット、その他のシークレットは当然非公開です。

---

## 信頼モデルの要旨

Arpass は **「2 of 3 復旧方式」**の鍵管理を採用しています。

```
3 つの要素のうち、いずれか 2 つが揃うと vault を復号できる:

  P  Master password    （ユーザの記憶）
  K  Passkey PRF        （端末の生体認証）
  R  Recovery Secret    （紙等で保管）

3 種類の "wrap":

  wraps.pr   = AES-GCM(k_vault, KEK(P, R))    1 個 / vault
  wraps.pk[] = AES-GCM(k_vault, KEK(P, K))    端末ごとに 1 個
  wraps.kr[] = AES-GCM(k_vault, KEK(K, R))    端末ごとに 1 個

すべての wrap を unwrap した結果は同一の k_vault。
本体ciphertext = AES-256-GCM(vault_json, k_vault, iv) で 1 個。
```

サーバーが見られるのは:
- 不透明な ciphertext (k_vault なしには復号不能)
- wraps の暗号文（KEK 無しには unwrap 不能）
- 匿名のドライブ ID（公開鍵のハッシュ）
- 残高情報（クレジット数）

→ **k_vault の一切は端末の中だけ** に存在し、サーバーには到達しません。詳細は [`docs/envelope-v4.md`](docs/envelope-v4.md)。

---

## 採用アルゴリズム

| 用途 | アルゴリズム | パラメータ |
|---|---|---|
| パスワード鍵導出 | PBKDF2-SHA256 | 600,000 iterations |
| KEK 導出 | HKDF-SHA256 | 32-byte info label per wrap |
| 対称暗号 | AES-256-GCM | 12-byte IV, 16-byte tag |
| 端末認証 | WebAuthn PRF 拡張 | 32-byte PRF output |
| API 署名 | ECDSA P-256 (SHA-256) | per-vault keypair |
| Recovery 文字列 | base32, 192 bit エントロピー | 8 グループ × 4 文字 |

すべて **ブラウザ標準の Web Crypto API** で実装。外部暗号ライブラリには依存しません。

選定理由は [`docs/crypto-rationale.md`](docs/crypto-rationale.md) を参照。

---

## ライセンス

[GNU Affero General Public License v3.0](LICENSE) 。

派生サービスを公開運用する場合、当該派生サーバーのソースコードもユーザに公開する必要があります（AGPL の network use 条項）。

非商用・私的検証・監査用途は AGPL の通常条件で自由に利用できます。

---

## 連絡先

- Issue: このリポジトリの GitHub Issues
- 商用ライセンス・問い合わせ: [support@arpass.io](mailto:support@arpass.io)
- サービス本体: [arpass.io](https://arpass.io)
- 運営: [Technoblest 株式会社](https://technoblest.com)
