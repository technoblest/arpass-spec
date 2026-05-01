# arpass-spec

**Arpass のクライアント側暗号コードと仕様書 — 公開部分。**

このリポジトリは [Arpass](https://arpass.io)（Technoblest 株式会社が運営する、Arweave 永続ストレージを使ったゼロ知識パスワード管理サービス）の信頼性を第三者が独立に検証できるようにするためのものです。

「**運営側はあなたのパスワードを見られません**」という主張がコードレベルで本当か、どなたでも確認できます。

---

## このリポジトリに何があるか

| 場所 | 内容 |
|---|---|
| [`lib/vault-crypto.js`](lib/vault-crypto.js) | すべての暗号処理（v5 envelope の生成・復号、KEK 導出、外側 AES-GCM、HKDF(MEK) からの ECDSA 鍵派生、Recovery Secret 文字列フォーマット 等） |
| [`lib/vault-client.js`](lib/vault-client.js) | ハイレベル vault 操作 (createVault / 3 unlock パス / saveVault / addCredential / changePassword / Recovery rotation Case A & B / Stripe Checkout) |
| [`lib/client-auth.js`](lib/client-auth.js) | API 認証 (X-Public-Key + ECDSA 署名)、Arweave からのデータ取得 (Turbo + arweave.net 並列、外側 AES-GCM 復号)、tx status (GraphQL + L1 status) |
| [`lib/vendor/noble-curves-and-hashes.mjs`](lib/vendor/noble-curves-and-hashes.mjs) | @noble/curves v2 + @noble/hashes v2 の必要部分を esbuild で 1 ファイル化 (~70 KB)。p256 / sha256 / hkdf / hmac / mod を提供。MIT (Paul Miller)。Web Crypto API は ECDSA P-256 鍵を seed bytes から決定論派生できないため必要 |
| [`lib/vendor/LICENSE-noble`](lib/vendor/LICENSE-noble) | @noble ライセンス全文 |
| [`docs/envelope-v5.md`](docs/envelope-v5.md) | **現行** v5 エンベロープ JSON 構造 + 外側暗号化の仕様 |
| [`docs/envelope-v4.md`](docs/envelope-v4.md) | (履歴) v4 エンベロープ仕様 — Arweave 上に過去 v4 が残っているため参照可能 |
| [`docs/arweave-tags.md`](docs/arweave-tags.md) | Arweave トランザクションタグの意味と匿名化方針 (v4.1 / v5 反映) |
| [`docs/crypto-rationale.md`](docs/crypto-rationale.md) | 採用したアルゴリズムの選定理由 (v5 追加分含む) |

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
  R  Recovery Secret    （紙等で保管。Phase 4.95 で QR 化対応）

3 種類の "wrap":

  wraps.pr   = AES-GCM(MEK, KEK(P, R))    1 個 / vault
  wraps.pk[] = AES-GCM(MEK, KEK(P, K))    端末ごとに 1 個
  wraps.kr[] = AES-GCM(MEK, KEK(K, R))    端末ごとに 1 個

すべての wrap を unwrap した結果は同一の MEK (Master Encryption Key)。
本体 ciphertext = AES-256-GCM(MEK, iv, vault_json) で 1 個。

v5 では更に、上記エンベロープ全体を AES-256-GCM(HKDF(vault-id), iv) で
外側からもう一度暗号化して Arweave に書き込む (Arweave 上の bytes は
完全な乱数バイト列に見える)。
```

サーバー (Cloudflare KV) が見られるのは v5 以降:
- ユーザーの公開鍵 (ECDSA P-256、元々公開可能な値)
- 残高情報（クレジット数）
- 書き込み回数等の運用統計

サーバーには **存在しない** もの:
- vault-id (v5 でサーバ側完全撤去 — Cloudflare 運用者を侵害しても出ない)
- ciphertext / 暗号化された envelope (Arweave に直接書き、サーバは中継しない)
- Master password / Passkey PRF / Recovery Secret のいずれの素材も

→ **MEK の一切は端末の中だけ** に存在し、サーバーには到達しません。
詳細は [`docs/envelope-v5.md`](docs/envelope-v5.md)。

---

## 採用アルゴリズム

| 用途 | アルゴリズム | パラメータ |
|---|---|---|
| パスワード鍵導出 | PBKDF2-SHA256 | 600,000 iterations |
| KEK 導出 | HKDF-SHA256 | 32-byte info label per wrap |
| 対称暗号 | AES-256-GCM | 12-byte IV, 16-byte tag |
| 端末認証 | WebAuthn PRF 拡張 | 32-byte PRF output |
| API 署名 | ECDSA P-256 (SHA-256) | per-vault keypair |
| Recovery 文字列 | base32, 160 bit エントロピー | 8 グループ × 4 文字 (RS1- 接頭辞付き、Phase 4.95 で QR 化) |
| 署名鍵 (v5) | ECDSA P-256, HKDF(MEK) で決定論派生 | Arweave に保存しない、毎セッション再導出 |
| 外側暗号化 (v5) | AES-256-GCM, HKDF(vault-id) | Arweave 上で JSON 構造を隠す |

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
