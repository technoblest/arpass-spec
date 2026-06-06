# Arpass — 実装状況サマリー

**最終更新**: 2026-06-02 (Phase 7.5 シリーズ — hwkey UX 大規模強化 + Android 救済 + サービスイン直後の bug 撲滅) / 2026-05-25 (Phase 7.4 — envelope v7 + Argon2id) / Phase 7.2 — IP 許可リスト + ZK 監査ログ / Phase 7.3 — 非抽出可能鍵への全面移行
**対象読者**: オペレータ、エンジニア、投資家、採用候補者

技術スペック（`technical-spec.docx`）は長期ビジョンを示す。本ドキュメントは **2026-04-29 時点で実際に動いているもの**と、**その先の優先順位**を簡潔にまとめる。

v4.1 リリース (2026-04-29) で確定した方針:
- **Passkey + WebAuthn PRF を必須化** (`ALG_PBKDF2_ONLY` の生成経路を完全削除)
- **秘密鍵を at-rest で AES-256-GCM 暗号化** (端末プロファイル盗難 → 書き込み権限奪取を防止)
- **メタデータ匿名化の徹底** (`vault-id` 平文タグの送出停止 / `LEGACY_APP_NAME` fallback の廃止)
- GraphQL polling 双方向化 (永久 bundling 表示の修正)
詳細は `docs/crypto-2of3.md` (v4.1 仕様書) と `docs/security-baseline.md` §6 (各バグの background と回帰防止)。

---

## 一言まとめ

**v4.1 リリース完了**: 2-of-3 envelope (v4) に **Passkey 必須化 + 秘密鍵 at-rest 暗号化** を加え、実装上の匿名性破壊バグ (vault-id 平文タグ・LEGACY_APP_NAME fallback) と UI バグ (永久 bundling 表示) を修正。Cloudflare Pages + Functions + KV の最小構成で、エンドユーザが PC + スマホで Arpass を本格利用可能。

- サービスウォレット保有型アーキテクチャ（ユーザーは crypto 知識不要）
- **ゼロ知識 2-of-3 暗号化**（Master × Passkey PRF × Recovery Secret）+ **v4.1 で Passkey 必須**
- **秘密鍵の at-rest 保護** (Passkey PRF で AES-256-GCM 暗号化、ブラウザプロファイル盗難で書き込み権限奪取不可)
- **複数端末対応**（端末ごとの Passkey wrap、端末一覧・追加・削除・名前変更）
- ECDSA P-256 による API 署名認証（**Recovery Secret から決定論導出**）
- per-vault 残高台帳（Cloudflare KV）
- Stripe Checkout でのプリペイド購入（¥300 / ¥1,000 / ¥3,000 / ¥10,000）
- Android TWA（Bubblewrap）— Play Console Internal Testing に公開済
- Privacy Policy（日英二言語）
- 自社 bundler + AR.IO Gateway（コード完成、VPS デプロイは任意）
- クライアント暗号のユニットテスト: `test-vault-crypto-v2.mjs` (96 assertions) + `test-identity-protection.mjs` (26 assertions、v4.1 新規)

---

## 実装構成

### デプロイ構造

    arpass.io (Cloudflare Pages)
      ├── web/             静的フロント（landing, app, lab, pricing, privacy, manifest）
      └── functions/api/   サーバレス API（write, セキュアドライブ, checkout, webhook, admin）
           ├── _lib/        bundler adapter / ledger / auth / pricing
           └── ...

    Cloudflare KV: ARPASS_LEDGER  (vault-id → {credits, publicKey, ...})

    deploy/
      ├── arpass-bundler/   自社 ANS-104 bundler（Docker、VPS）※任意
      ├── ar-io-gateway/    自社 AR.IO Gateway（Docker、VPS）※任意
      └── arpass-android/   Android TWA（Bubblewrap）→ Play Console

    arweave mainnet:       service-wallet (0.3 AR, 書き込み原資)

### セキュアドライブ暗号化構造（v3 envelope、多端末対応）

    K_vault = random 256-bit —セキュアドライブ JSON を AES-256-GCM で暗号化
    wraps.pr           = AES-GCM(K_vault, HKDF(password ‖ recovery))
    wraps.pk  [device] = AES-GCM(K_vault, HKDF(password ‖ prf_device))
    wraps.kr  [device] = AES-GCM(K_vault, HKDF(prf_device ‖ recovery))

- Password + Passkey / Password + Recovery / Passkey + Recovery のどれでも unlock 可
- 端末追加時は `pk[]` と `kr[]` に新エントリを append
- 端末削除は配列から filter で除外
- Password/Recovery 変更は他端末の pk/kr を invalidate（他端末は次回 P+R で再認可）

### ECDSA 認証 identity

    Recovery Secret
      ↓ HKDF → 32 byte seed
      ↓ P-256 scalar reduction, × G
      ↓ canonical JWK → SHA-256 → 先頭32文字
    セキュアドライブ ID

- 別端末で同じ Recovery Secret を入れるだけで同じセキュアドライブ ID に到達
- 秘密鍵は毎回決定論的に再生成。サーバは単一の公開鍵で全端末の署名を検証

### Identity at-rest 保護 (v4.1, 2026-04-29)

ECDSA 秘密鍵を localStorage に **平文 JSON で保存しない**。Passkey PRF 由来の AES-256-GCM 鍵で暗号化:

    identityProtectKey = HKDF-SHA256(prfOutput, info="identity-key-protect-v1", 32B)
    encryptedPrivateKey = AES-256-GCM(privateKeyJwk, identityProtectKey)

    localStorage["arpass_client_v1"] = {
      vaultId, publicKeyJwk,
      encryptedPrivateKey: { iv, ct, alg: "id-protect-v1" },  ← 平文 JWK は持たない
      passkeyCredentialId, version: "v4.1"
    }

セッション中はメモリにのみ展開、`lockSession()` / `pagehide` で消去。**ブラウザプロファイル盗難 → 書き込み権限奪取が成立しなくなった**。
v4.0 の平文 identity を持つ既存ユーザは、初回 unlock 時に自動マイグレーション。

### 書き込みフロー

                Browser ──sign(ECDSA)──►  /api/write  ──verify──►  debit 1 credit (KV)  ──►  bundler.uploadToArweave()  ──►  Arweave mainnet
                                                                                                   │
                                                                                              成功: 返却 txid
                                                                                              失敗: refund 1 credit (KV)

### 決済フロー

                Browser ──►  /api/checkout  ──►  Stripe Checkout Session ──redirect──►  Stripe 決済
                                                                                                  │
                                                                                                  ▼
                Stripe Webhook  ──POST──►  /api/webhook/stripe  ──verify HMAC──►  addCredits(セキュアドライブ)  ──►  KV 更新

### Bundler 依存関係（任意段階）

    Phase                BUNDLER_BACKEND    Bundler 必要？    書き込みコスト/回
    MVP（現状）          direct              不要               ¥0.43
    1,000 DAU 以降        self-gateway       ✅ VPS 1 台         ¥0.01 前後
    10,000 DAU 以降       self-gateway       ✅ + 複数インスタンス   ¥0.005

---

## 実装済み API

| Method | Path | 認証 | 概要 |
|---|---|---|---|
| GET    | /api/status             | — | サービスウォレット残高、backend、bundler URL |
| POST   | /api/vault/register     | — | 新規セキュアドライブ登録（3 credits ボーナス付与） |
| GET    | /api/vault/:vaultId     | — | セキュアドライブ残高・総消費・総追加 |
| POST   | /api/write              | ECDSA 署名必須 | 書き込み（debit 1 credit） |
| POST   | /api/checkout           | — | Stripe Checkout Session 発行 |
| POST   | /api/webhook/stripe     | Stripe-Signature HMAC | 決済成功で credit 付与 |
| POST   | /api/admin/credit       | Bearer | 運用者が手動 credit 付与 |
| POST   | /api/admin/bundle-dropped | Bearer | Bundler からの自動返金 callback |
| GET    | /api/hello              | — | ランタイム診断 |
| GET    | /api/probe              | — | arweave-js 統合診断 |

---

## Phase 進捗

| Phase | 内容 | 状態 |
|---|---|---|
| 0 | プロトタイプ検証 | ✅ 完了 |
| 1 | Service-side Arweave 書き込み | ✅ 完了 |
| 2 | Balance Ledger (Cloudflare KV) | ✅ 完了 |
| 3 | ECDSA 署名認証 | ✅ 完了 |
| 4 | Stripe Checkout 決済 | ✅ 完了 |
| 4.6 | 自社 bundler + AR.IO Gateway 準備 | ✅ コード完成 |
| 4.7 | 自動返金 + read fallback + rate limit | ✅ 完了 |
| 4.8 | エンドユーザセキュアドライブ UI + クライアント暗号化 | ✅ 完了 |
| 4.9 | Passkey (WebAuthn + PRF) 二要素、tx 状態表示、envelope ローカルキャッシュ | ✅ 完了 |
| **Crypto v2** | **2-of-3 リカバリー**（Master × Passkey × Recovery Secret）+ 代替 unlock 経路 + パスワード変更 + Recovery 再発行 | ✅ 完了 |
| **Crypto v3** | **複数端末同時使用**（端末ごとの Passkey wrap、端末一覧・追加・削除・名前変更）+ Recovery Secret からの決定論 identity 導出 | ✅ 完了 |
| **Crypto v4** | **Envelope パディング（on-chain ~110 KiB + 6 KiB jitter）**（サイズ秘匿）+ **per-user 匿名化 App-Name タグ**（GraphQL 一括列挙の防止）| ✅ 完了。ただし Phase 5.0 cutover 時に padding が `[4 KiB, 16 KiB, …]` バケットに退化していたバグを Phase 5.2 で修正、Phase 6.7 で `PAD_BUCKETS = [80 KiB, 160 KiB, 240 KiB] + 0..8 KiB jitter` に再設計しコスト最小化（¥0.47→¥0.33/write）|
| **Crypto v4.1** | **Passkey + WebAuthn PRF 必須化** (`ALG_PBKDF2_ONLY` 生成停止) + **秘密鍵 at-rest 暗号化** (Passkey PRF wrapping) + 対応端末要件の明示 | ✅ 完了 (2026-04-29) |
| **メタデータ匿名化バグ修正** | (1) 永久 bundling 表示の polling バグ (両 GW 並列化) (2) サーバ側 vault-id 平文タグの送出停止 (3) `LEGACY_APP_NAME` fallback の完全削除 | ✅ 完了 (2026-04-29) |
| **Recovery 再発行 = identity migration** | 旧 identity 署名で新 vault-id へクレジット移送（POST /api/vault/migrate）、新 envelope を新 vault-id・新 anonymized タグで Arweave に書き込み、localStorage を新 identity に切替 | ✅ 完了 |
| **Phase 4.95: Recovery Kit (QR + 印刷専用)** | Recovery 表示時に **QR (SVG) を自動生成**、4 つの Recovery 入力欄に **📷 QR スキャン**ボタン追加 (BarcodeDetector 優先 / jsQR fallback)、印刷用 Emergency Kit レイアウト ( @media print + hidden div、A4 1 枚) を実装。**PDF 生成ライブラリは不採用** (Downloads / iCloud 残留リスク回避)。`web/lib/qr.js` + vendored `qrcode-generator` (MIT) + `jsQR` (Apache-2.0)。Permissions-Policy で `camera=(self)` 解放、CSP に `media-src blob:` `img-src blob:` 追加 | ✅ 完了 (2026-04-30) |
| **Phase 5.0: v5 envelope + 外側暗号化 + publicKey 識別** | (1) envelope JSON 全体を **AES-GCM(HKDF(vault-id))** で外側暗号化し Arweave に octet-stream として書く (JSON 構造を完全に隠蔽)、(2) サーバ KV キーを `H(publicKey)` に変更、`X-Vault-Id` ヘッダを完全廃止 (Cloudflare 運用者を侵害しても vault-id が出ない)、(3) ECDSA P-256 署名鍵を **HKDF(MEK) で決定論派生** し Arweave に一切保存しない (SNDL 攻撃対象面積縮小)、(4) `/api/balance` 新設、`GET /api/vault/:vaultId` 廃止、(5) v2/v3/v4 関連コード (旧 vault-crypto/vault-client/client-auth/auth/ledger 計 7,900 行) を **完全削除**。全ファイル名から `-v5` サフィックス除去、関数名から `V5` サフィックス除去 (常に v5 のみのため)。`@noble/curves` を esbuild で 35KB ESM バンドル化して vendor。test:crypto 46/46、test:client 13/13、lint:security 8/8 invariants intact。公開ミラー `arpass-spec` も同期更新済み。 | ✅ 完了 (2026-04-30) |
| **Phase 5.2: envelope padding 修復** | v5.0 cutover 時に `PAD_BUCKETS = [4 KiB, 16 KiB, ...]` に退化していたため、(a) tx サイズが 5,912 B 固定で size-based フィンガープリントが成立、(b) Turbo 無料枠 (107,520 B) に永続的に収まり sponsored 扱い (AUP 違反リスク + 「我々は支払う」プライバシー訴求の崩壊) が発生していた重大バグを修正。`PAD_BUCKETS = [120 KiB, 240 KiB, 480 KiB, 960 KiB, 4 MiB] + 0..8 KiB jitter` に復元、テスト 51/51 (うち 3 件が padding invariant: 無料枠超過 / ジッタ / バケット昇格)、`scripts/lint-security.sh` に `PAD_BUCKETS[0] >= 110 KiB` invariant 追加。 | ✅ 完了 (2026-05-01) |
| **Phase 6.7: envelope on-chain サイズ最小化** | Phase 5.2 で復元した `PAD_BUCKETS[0] = 120 KiB` (raw) は **on-chain 162.97 KiB / ¥0.47/write** で過剰だった。実 upload 測定 (`scripts/measure-turbo-write-cost.mjs`) で **Turbo 無料枠は on-chain 100 KiB** と確定したため、PAD_BUCKETS[0] を **80 KiB raw → on-chain ~110 KiB** に再設計し、無料枠超え (free ride 防止) と fingerprint 防止 (jitter) を維持しつつ **¥0.33/write** へコスト 30% 圧縮。lint invariant (9) を「raw ≥ 110 KiB」から「raw ≥ 78 KiB → on-chain ≥ 約 104 KiB > 100 KiB」に変更、`PAD_BUCKETS = [80, 160, 240] KiB`、テスト 51/51 通過、`VAULT_SIZE_WARN_BYTES` を 60 KiB / `VAULT_SIZE_BLOCK_BYTES` を 230 KiB に再調整。事業計画 (¥0.001/write 想定) と運用設計 (free ride 防止には paid tier 必須) の二本立てを両立、Free signup bonus (3 writes/user) の自社負担も ¥1.4→¥1.0 に圧縮 (元来 ¥1 程度なので影響軽微)。`FREE_BONUS_CREDITS = 100` は付与回数ではなく Free/Paid 分類の境界値 (累計クレジットがこれを超えたら Paid 扱いに移行) であって混同しない。 | ✅ 完了 (2026-05-06) |
| **Stripe Test Mode** | API key + Webhook 設定、テスト決済（4242...）動作確認済 | ✅ 完了 |
| **Packaging** | Android TWA（Play Console Internal Testing）、PWA manifest、Digital Asset Links、Privacy Policy | ✅ 完了 |
| Turbo backend | adapter スタブのみ。Phase A では direct mainnet で paid model を満たす設計に決定 | ⏸ 後続検討 |
| **Phase 5.3: localStorage cache + 楽観ロック完成** | (a) 保存済 envelope を localStorage に短期 cache → 「保存直後の Turbo bundling 待ち窓 (0-2 分)」での unlock 失敗を解消、Turbo gateway が配信開始したら即破棄して長期残留させない。(b) 既存の server-side `version_conflict` (write.js) を client から発火させる — `expectedLatestTxId` を saveVault が送信するようにし、複数端末同時編集による lost-update を 409 で阻止 + UI 警告。(c) cache 抽象層 `web/lib/local-cache.js` を作って Phase 6 で IndexedDB に置換可能にしておく。 | ⏸ 進行中 (2026-05-01) |
| **Phase 6.8: USD-balance accounting + tier-aware billing** | writeCount 固定モデル → balance USD micro モデルへ移行。Stripe charge 額をそのまま USD で残高に加算、書込ごとに `AR_PER_WRITE × AR/USD × tier × GROSSUP_RATIO` で減算。tier 1/2/3 で margin 維持、AR 価格変動に追従。 | ✅ 完了 (2026-05-07) |
| **Phase 7.0a-r: Records 機能 (経理書類保管)** | (1) Records v3 schema (active/chunks/corrections/tombstones/recordHistory)、(2) 3-tier KEK 暗号化 (BEK / MEK)、(3) 任意ファイル形式対応 (PDF/画像/Word/Excel/text、最大 1 MB)、(4) 検索/フィルタ (日付/金額/取引先/タイトル、日本語正規化)、(5) 訂正/削除 + append-only audit history (電子帳簿保存法対応)、(6) chunks overflow + IndexedDB cache、(7) records.csv エクスポート (UTF-8 BOM)、(8) PDF OCR (PDF.js + 1 page → image)、(9) BYO-key OCR (OpenAI gpt-4o vision、画像直送)、(10) iPhone 写真自動圧縮 (Canvas multi-pass)。 | ✅ 完了 (2026-05-09) |
| **Phase 7.0s: Turbo 実費ベース課金 (reserve + reconcile)** | 旧 estimate 即時 deduct → 新 2-phase: estimate で balance 確保 → upload → 実 winston cost で reconcile (差分 refund / 追加 deduct)。100 KiB 未満 sponsored は 0 円課金 (誠実 pass-through)、margin は維持。セキュアドライブ表示 perWriteUsd は直近セキュアドライブ書込みの実費 × grossup。 | ✅ 完了 (2026-05-10) |
| **Phase 7.0u-w: ドキュメント / マーケコピー整合** | landing page hero pivot (パスワード+ファイル両軸)、Records FAQ 5 問追加、HELP に Records 専用セクション (5 サブ)、pricing.html に Records note、100 KiB 無料 disclosure、原価率 ('× 6.06') を公開コピーから削除 + lint 回帰防止 rule 追加。 | ✅ 完了 (2026-05-10) |
| **Phase 7.0w-L: 英語 UI "Records" → "Files" 統一** | 英語版アプリのタブ・ボタン・モーダル・トースト等を Records / record → Files / file に統一 (~20 keys)。14 言語側で混在していた btn_add / modal_title (zh-CN 「文档」、de 「Beleg」、ko 「문서」等) を file 系に統一。CSV ダウンロードファイル名を `arpass-records-` → `arpass-files-` に変更 (pre-launch safe rename)。`security.crypto_records_desc` の "Records 索引" / "Records index" 等を 15 言語で files 系に。内部識別子 (`app.records.*` key / `addRecord()` 関数 / IDB store / KV "the KV record") は維持。 | ✅ 完了 (2026-05-11) |
| **Phase 7.0w-M: signup bonus 説明強化 + pricing.html 容量目安テーブル** | signup bonus は \$0.05 (パスワード約 3 回分) を据え置き、`app.create.hint_signup_bonus` に「100 KiB 未満は無料、それより大きいファイルも残高があれば最後の 1 回は必ず書ける」旨を 16 言語で追加。pricing.html に新セクション `pricing.records_size_guide_html` 追加: 容量帯別の料金目安 (< 100 KiB / 100-500 KiB / 500 KiB-1 MB) + AR 価格変動と残高 floor の透明性。`docs/pricing-revision-runbook.md` を Phase 6.8 → Phase 7.0 に更新、Records 容量別コスト表 + 平均 800 KiB 超 abuse alert を追記。 | ✅ 完了 (2026-05-11) |
| **Phase 7.1: Business mode 安定化 + 完全 lockout 救済** | 実機検証で出たエッジケース対応 (credentialId 先行 patchMeta、business signup で Recovery 非表示、KV キャッシュ遅延ガード、空 profile 防御) + 全端末紛失社員の唯一の救済路 (admin 発行 8 文字機種追加コード) + 招待コードと機種追加コードの入口統一 + ZK 監査ログの土台整備 + 15 言語同期。 | ✅ 完了 (2026-05-15) |
| **Phase 7.2: IP 許可リスト + ZK 監査ログ + Business mode K1 配布刷新** | (A/D) 法人管理者がオフィス IP 範囲 (CIDR、IPv4 /24・IPv6 /64 上限) に会社セキュアドライブ利用を制限 + 登録法人 IP からの個人モードアクセス遮断、(E) 管理者セキュアドライブ内に格納するゼロ知識暗号化監査ログ、(B) Business mode K1 配布を v1 (server keypair ECIES) → α → 最終 v2 (per-employee enc_K1) に刷新しサーバが単独で K1 を復号できない構造を確立。 | ✅ 完了 (2026-05-17) |
| **Phase 7.3: 非抽出可能鍵への全面移行** | コードベース全体で MEK / K1 / K2 / Recovery 材料 / 署名鍵の raw バイト列を非抽出可能 WebCrypto CryptoKey に置換。raw 鍵材料が JS ヒープに常駐しないようにし、ブラウザ拡張 / XSS / サプライチェーン攻撃からの鍵漏洩を構造的に防止。OSS 公開準備の一環。 | ✅ 完了 (2026-05-19) |
| **Phase 7.4: envelope v7 — YubiKey 対応 / Passkey が outer 鍵を運ぶ** | 増分1: outer 鍵 (32 byte) と vault 所在 (appNameTag) を Passkey の WebAuthn `user.id` に格納し、新端末でも「Master + Passkey」だけで解錠可能にした (Recovery 入力・端末ごとの localStorage 依存を解消)。WebAuthn の順序制約 (user.id は credential 作成前に確定するため、その credential 自身の PRF では暗号化できない) のため、outer 鍵は Master パスワード由来鍵で AES-256-CTR ラップして user.id に格納する (v7 ハードニング、PBKDF2(Master, salt=appNameTag.value, 600k)、非膨張で 57 byte 維持)。user.id は Passkey ハードウェアでゲートされ Arweave 公開オブジェクトには一切載らず、さらに Master ラップにより将来 user.id が漏れても Master 無しでは復号不能。anti-fingerprint は無傷。Arweave オブジェクト構造・書き込みパターンは v6 と同一。personal / business / admin 全モード対応 (business も多端末利用が多く、IP 許可リスト + K1 退社制御でアクセス管理は担保されるため対象に含めた)。Master 最低長 8 文字を撤廃 (空のみ不可)。同期パスキー (iCloud Keychain / Google Password Manager) と YubiKey の両方で 実機クロスデバイス検証済 (Mac / iPhone / Android)。`createPasskey` が create 時に PRF を返さないセキュリティキー (YubiKey 等) で常に失敗していた既存バグも修正 (create 後に get() を 1 回行い PRF 取得)。仕様書 `docs/envelope-v7-spec.md`、上位メモ `docs/yubikey-outer-key-redesign.md`。サービス未公開のため v6→v7 マイグレーションは不要。さらにハードニングとして outer 鍵を Master でラップして user.id に格納し (AES-256-CTR、PBKDF2(Master, appNameTag.value, 600k)、非膨張で 57 byte 維持)、localStorage からは outer 鍵を完全撤去 (解錠のたびに user.id から復元、端末追加パスキーも v7 user.id 化)。 Master 変更時は user.id が不変な制約に対処するため、新 Master でラップした user.id を持つ Passkey を新規作成し envelope の全 Master+Passkey wrap を作り直す (Option A、旧 Master は即全端末無効、`envelope-v7-spec.md` §14)。lint invariant (26) で functions/ への userHandle 出現を恒久禁止。増分2 (YubiKey 専用モード) も完了 (2026-05-25、staging 検証済): Master / Recovery を一切持たず登録 YubiKey ≥2 本のみで 1-of-N 解錠する hwkey envelope (`m:"hwkey"`、`k[]` は per-YubiKey の PRF MEK wrap)。outer 鍵と vault 所在は YubiKey ごとの「keyslot blob」(その鍵の PRF で暗号化し padding で本体と同サイズ帯に難読化した独立 Arweave オブジェクト) が運び、user.id は keyslot の所在タグのみで秘密ゼロ。任意端末での解錠 (`unlockWithHwkeyAuthed` / `hwkeyAuthenticateForUnlock` — 登録済み端末は specific get でパスキー一覧を出さず YubiKey 直行)、別端末への YubiKey 追加 (`addHwkeyDevice`)、作成直後の Arweave 伝播遅延に対するバックオフ再試行 (~60s) に対応。WebAuthn PRF が UV (PIN) の有無で値が変わる問題に対し hwkey の全 WebAuthn を `userVerification:"discouraged"` に統一し PRF を UV 非依存に固定。Mac Safari は WebAuthn 実装が他ブラウザと非互換で PRF が一致せず hwkey ドライブを他環境と共有できないため、ブロックせず注意喚起のみとした (Mac Chrome/Edge・Windows・iPhone・Android は相互運用可)。test-envelope-v7.mjs 56/56 PASS。 増分3 (2026-05-31): Master KDF を PBKDF2-SHA256 600k iter から Argon2id (m=64MiB, t=3, p=4, dkLen=32) に移行 — memory-hard KDF で GPU/ASIC 並列攻撃耐性を 1000x 程度向上、Recovery Secret 漏洩 + 弱い Master の組み合わせ攻撃を実用上無効化。`@noble/hashes/argon2` を vendor bundle に追加 (~34KB)。test 109/109 PASS。 | ✅ 増分1・2・3 完了 (2026-05-31) |
| 5 | Durable Objects / 第三者監査 / Import/Export / Browser 拡張 | 未着手 (Argon2id は Phase 7.4 で完了) |

---

## 認証・暗号まわりの現状（2026-04-30、Phase 5.0 完了時点）

**2-of-3 リカバリー + 複数端末 + 外側暗号化 + publicKey ベース認証が完全実装**。

| 領域 | 現状 (v5) | 長期目標 (Phase 6+) |
|---|---|---|
| ブラウザ鍵ペア | ECDSA P-256、**MEK から HKDF 決定論派生** (Arweave に保存しない、端末復旧後も同一 PK 再生成) | 同じ (将来 ML-DSA への量子耐性移行) |
| ユーザ認証 | **Passkey (WebAuthn + PRF) を必須**、PRF 不可ブラウザはサインアップでブロック | 同じ |
| サーバ認証 | `X-Public-Key` + `X-Signature` (旧 `X-Vault-Id` ヘッダ廃止)。サーバ KV キー = `H(publicKey)` | 同じ |
| 秘密鍵保存 | **Arweave に一切書かない** (HKDF(MEK) で都度派生)。localStorage にも置かない。MEK は session memory のみ、lockSession で `fill(0)` で破壊 | 同じ |
| セキュアドライブ暗号化 | AES-256-GCM + HKDF + **Argon2id (64 MiB, t=3, p=4)** + **2-of-3 wrap (v5 envelope)** + **外側 AES-GCM(HKDF(rMat)) 層** | — (Argon2id 移行完了 Phase 7.4) |
| リカバリー | **2-of-3** (Master × Passkey × Recovery Secret)、いずれか 1 つ喪失で復旧可能 | 同じ |
| Emergency Kit | Recovery Secret の **印刷用ページ + QR コード** (Phase 4.95) | **PDF 化は採用しない** (Downloads/iCloud 流出リスク) |
| 複数端末 | ✅ 端末ごとの AB / BC wrap (`w.b[]` `w.c[]`)、credIdHash で識別 | UI の登録端末リスト整理 (Phase 5.1) |
| 復旧端末サポート | Passkey + PRF 対応ブラウザ必須 (iOS 17+ Safari / Android 13+ Chrome / macOS 14+ / Windows 11+ Chrome・Edge) | 同じ |
| メタデータ匿名化 | App-Name タグは per-user HMAC、`vault-id` タグ廃止、`Content-Type=octet-stream` 固定 (外側暗号化済み)、`LEGACY_APP_NAME` fallback 完全削除 | 同じ |
| Recovery 再発行 | **Case A** (MEK 据え置き、軽量、サーバ無関係) と **Case B** (MEK 一新 + `/api/migrate` で残高移送) | UI から Case 選択 (Phase 5.1) |
| Master 忘却復旧 | UI 入口 「🔑 Master を忘れた → Passkey + Recovery で再設定」、unlock 直後に新 Master prompt が出て自動 changePasswordUI() | 同じ |

### 日常使用に必要な端末性能

- **日常使用**: Passkey + PRF 対応ブラウザ（iOS 17+ Safari、Android 13+ Chrome、macOS 14+ Safari、最近の Windows Chrome/Edge）
- **緊急アクセス**（紙の Recovery Secret + Master password）: Passkey 不要。手入力または将来的に QR スキャン
- **復旧端末**: 初回は Passkey + PRF 対応端末で Passkey 再登録 → その後日常使いへ

### Recovery Secret の現状

- セキュアドライブ作成時に画面に RS1-XXXX-XXXX-…-XXXX 形式の Recovery Secret を **ワンタイム表示** + **scannable QR (SVG)** (Phase 4.95)
- 「🖨 紙に印刷 (推奨)」ボタンが primary、`@media print` で同一ページ内 hidden div を A4 1 枚 Emergency Kit レイアウトに切替
- **PDF 生成ライブラリは採用しない** (Phase 4.95 で確定方針) — Downloads / iCloud 残留・Spotlight インデックス・マルウェア収穫対象になるため、紙への印刷を強推奨。ブラウザ印刷ダイアログの「PDF として保存」は OS 経由でユーザー自己責任
- 4 つの Recovery 入力欄に「📷 QR スキャン」ボタン (BarcodeDetector → jsQR fallback)
- Settings モーダルからいつでも再発行可能 (Case A: MEK 据え置き軽量版がデフォルト、Case B: MEK 一新本格版は将来 UI 選択肢化)

### パスワード変更・端末管理時の副作用 (UX 明示)

v5 では「**lazy 補完**」設計が標準。他端末の wrap は触れないが、次回 unlock で自然に追従する：

- **Master Password 変更**: 現端末の AB wrap と AC wrap が再生成。他端末の AB wrap は古い Master のまま → 他端末は次回 unlock で AB 失敗 → 「Recovery を入力」プロンプト → BC または AC で復活 → そのセッション中に自端末 AB wrap を新 Master で再生成 (lazy 自然解消、ユーザー操作は Recovery 入力 1 回だけ)
- **Recovery Secret 再発行 Case A**: AC + 現端末 BC を再生成、MEK 据え置き → サーバ KV 無関係、publicKey 不変
- **Recovery Secret 再発行 Case B**: 全 wrap 再生成 + 本体再暗号化 + 新 publicKey 派生 → サーバ `/api/migrate` で残高移送
- **端末追加 (機種変更)**: 常に Recovery 必須 (QR ペアリングは採用しない)。新端末で Master + Recovery 入力 → AC unlock → Passkey 作成 → AB + BC wrap 追加 → envelope 再書き込み

---

## 本格実装（technical-spec.docx）との差分

| 項目 | 当初計画 | MVP 実装（2026-04-24） | 差分を埋める必要性 |
|---|---|---|---|
| 暗号ライブラリ | Argon2id + AES-GCM | Web Crypto API + @noble/hashes/argon2 (vendored) | 低 — Phase 7.4 で Argon2id 採用済 |
| リカバリー | 2-of-3（Master × Passkey × Recovery Secret） | ✅ **実装済** | — |
| WebAuthn Passkey 認証 | 必須 | ✅ **実装済** | — |
| WebAuthn PRF | あり | ✅ **実装済** | — |
| Envelope 構造 | 3 envelope 同時暗号化 | ✅ **実装済**（v2 の wrap 3 種 + v3 の端末配列）| — |
| 複数端末対応 | あり | ✅ **実装済** | — |
| Emergency Kit | QR + PDF | テキスト表示 + 印刷ボタンのみ | 中 — QR + PDF 化は UX 改善 |
| データ形式 | 差分更新 (Delta Encoding) | 丸ごと上書き | 低 — 10 KiB 未満なら無害 |
| UI 多言語 | 5 言語（en, ja, ko, zh, es） | 日本語のみ（Privacy Policy は日英） | 中 |
| サードパーティ監査 | 契約前提 | 未契約 | **最高**（GA 前必須） |

---

## 運用ハンドオフ時の必須タスク

CTO 採用後、最初の 2 週間でやること:

1. **Cloudflare Pages 設定の確認**
   - `BUNDLER_BACKEND=direct` で稼働しているか（本番移行時は `self-gateway` or `turbo` 推奨）
   - KV binding `ARPASS_LEDGER` が有効か
   - Secret が 4〜5 種全て登録済みか（ARWEAVE_JWK, ARPASS_ADMIN_TOKEN, STRIPE_*, 任意で ARPASS_BUNDLER_CALLBACK_TOKEN）
2. **Cloudflare Access bypass の確認**
   - `/manifest.webmanifest` / `/icon-*.png` / `/.well-known/*` / `/privacy.html` が 200 で返るか（Bubblewrap と Play 審査が依存）
   - 本番公開時は `/app.html` `/lib/*` `/api/*` も bypass
3. **service-wallet.json のバックアップ 2 箇所確認**（iCloud / Dropbox / USB など）
4. **Android TWA keystore のバックアップ 2 箇所確認**（`deploy/arpass-android/android.keystore`）— Play Store 更新が永久不能になるリスクの単一点
5. **Stripe Live Mode への移行**（Test Mode から切替、本番 API キー再登録）
6. **監視**: `/api/status` を外形監視（Uptime Robot など）、サービスウォレット残高アラート
7. **Phase 5 着手準備**: 第三者セキュリティ監査、Import/Export、ブラウザ拡張、ポスト量子鍵交換の調査 (Argon2id 移行は Phase 7.4 で完了)
8. **テスト自動化**: `test-vault-crypto-v2.mjs` (96 assertions) と `test-identity-protection.mjs` (26 assertions、v4.1) を CI で回す
9. **回帰防止 grep tests** (security-baseline §6-1, §6-6, §6-7 参照): `ALG_PBKDF2_ONLY` 復活防止、平文 privateKeyJwk 保存防止、`LEGACY_APP_NAME` 復活防止 を CI に追加

---

## テスト状況

    node scripts/test-vault-crypto-v2.mjs        → 96 passed, 0 failed
    node scripts/test-identity-protection.mjs    → 26 passed, 0 failed (v4.1 新規)

`test-vault-crypto-v2.mjs` のカバー範囲:
- 2-of-3 ラウンドトリップ（全 3 つの factor pair）
- 要素不足 / 誤 factor の reject
- 再暗号化 (reEncrypt) の wrap 不変性
- rewrap / change password / change Passkey / change Recovery の wrap 更新ルール
- P-256 identity の決定論性と WebCrypto 互換性
- セキュアドライブ ID 導出の決定論性
- v3 複数端末：端末追加・削除・名前変更
- v2 → v3 マイグレーション

`test-identity-protection.mjs` のカバー範囲 (v4.1):
- `wrapPrivateKeyWithPRF` / `unwrapPrivateKeyWithPRF` のラウンドトリップ
- 復号した秘密鍵で ECDSA 署名 → 元の公開鍵で検証成功 (E2E)
- wrong PRF / tampered ct / tampered iv / tampered GCM tag の確実な拒絶
- alg-mismatch / null 入力の reject
- 確率的暗号化 (同じ key+PRF で 2 回 wrap → 別 ct、復号は同じ平文)
- PRF 入力 validation (32B 未満、非 Uint8Array、d なし JWK)
- 20 ランダム key × 20 ランダム PRF のソーク

---

## 2026-04-29 オペレーション修正サマリー

v4.1 リリースの一環で、実機テストで発見された 3 件のバグを同時修正:

| バグ | 影響 | 修正コミット |
|---|---|---|
| **#1 GraphQL polling の永久 bundling** | UI ヘッダのバッジが「📦 Turbo 配信中」のまま遷移しない (実際は L1 確定済) | `e02eb85` (両 GW 並列化) |
| **#2 vault-id 平文タグ ★★★★★** | サーバ側 `write.js` が全 write に平文 vault-id タグを付与 → 第三者が GraphQL でユーザの全 tx を追跡可能 | `e02eb85` (タグ削除 + GraphQL 検索条件からも撤去) |
| **#3 LEGACY_APP_NAME fallback ★★★★** | meta 不正状態で `Arpass-Vault` 共通タグが付与される silent 経路 | `1b7a127` (throw 化、検索条件からも撤去) |

詳細経緯と回帰防止項目は `docs/security-baseline.md` §6-6 (vault-id 平文タグ) と §6-7 (LEGACY_APP_NAME) を参照。

⚠️ **Arweave は immutable**: 修正以前に書き込まれた envelope は永久に `vault-id` 平文タグを保持。GA 前にユーザへの開示が必要 (現時点ではまだ生産ユーザは存在しないので影響範囲は開発時の試験 envelope のみ)。

---

## 参考ファイル

- [README.md](../README.md) — 運用手順
- [business/implementation-roadmap.md](../business/implementation-roadmap.md) — 長期ロードマップ
- [docs/technical-spec.docx](technical-spec.docx) — 詳細仕様（長期ビジョン）
- [docs/privacy-policy-and-tos.docx](privacy-policy-and-tos.docx) — 法務版プライバシーポリシー / 利用規約
- [deploy/README.md](../deploy/README.md) — 自社 bundler / Gateway 設計
- [deploy/arpass-android/README.md](../deploy/arpass-android/README.md) — Android TWA ビルド手順
- [web/privacy.html](../web/privacy.html) — 一般公開のプライバシーポリシー（2-of-3 を正確に反映）

---

## Phase 6.3 (2026-05-05): 法人 Corporate Wallet 共有 — 実装完了

**概要**: Mega Pack ¥15,000 購入者は招待コード `ARPASS-XXXX-XXXX` を介して最大 50 名の従業員と Arweave wallet を共有できる。従業員のセキュアドライブ内容は引き続き完全に独立 (Master + Passkey + Recovery)、共有されるのは「書込み課金 wallet」のみ。

**実装ファイル**:
- `functions/_lib/corp.js` (234行) — KV スキーマ + 全業務ロジック
- `functions/api/corp/info.js` (GET) — 自分の所属情報、admin なら member 一覧と code
- `functions/api/corp/join.js` (POST) — invite code で参加
- `functions/api/corp/leave.js` (POST) — 離脱 (admin 不可)
- `functions/api/corp/admin/rotate.js` (POST) — code 再生成 (古いの即無効)
- `functions/api/corp/admin/remove.js` (POST) — admin が member を除外
- `functions/_lib/wallet-pool.js` 修正 — `pickJwkForUser` に corp 経由 routing
- `functions/api/webhook/stripe.js` 修正 — Mega 購入時に `createCompany` 自動発火
- `web/lib/vault-client.js` — `corpInfoUI/corpJoinUI/corpLeaveUI/corpRotateUI/corpRemoveMemberUI`
- `web/app.html` + `web/lib/app-main.js` — Settings に「🏢 法人 / Corporate」セクション
- `web/i18n/{ja,en}.json` — 26 keys 追加
- `scripts/test-corp.mjs` — 12 アサーションで全業務ロジック検証 (in-memory KV mock)

**KV スキーマ**:
```
corp:<companyId>           → company record
corpCode:<code>            → companyId
corpMember:<H(pk)>         → companyId
corpRoster:<companyId>     → [H(pk), ...]
```

**設計判断**:
- 招待コード形式: `ARPASS-XXXX-XXXX` (Crockford Base32, ~60 bit entropy, 30日 TTL)
- Quota: デフォルト最大 50 名 / 1 会社
- Mitigation: code 再生成 (admin)、member 除外 (admin)、admin による会社 disable
- データ漏洩対策: 構造的にゼロ — 各 member の Master+Passkey が必要、wallet 共有は課金のみ
- Code 漏洩時の最大被害: ¥15,000 の credit 使い切りのみ

**Test Result**: 12 / 12 pass (`scripts/test-corp.mjs`)
**Lint Security**: 全 11 invariant pass (`scripts/lint-security.sh`)

**残課題 (Phase 6.4 候補)**:
- Admin による会社解約フロー (現在は disable まで実装、解約・credit 払い戻しは未着手)
- Multi-org (1 user が複数会社に所属) — 現状は 1 user = 1 company に制限
- Shared セキュアドライブ (Level 2 — 同じパスワードを複数人で見る) — Phase 7+
- SCIM / SSO (Level 3 — Enterprise plan) — Phase 8+


---

## Phase 6.5 (2026-05-05): Free wallet 分離 — 実装完了

**問題**: Phase 6.4 の App-Name tier qualifier だけでは「Free user による Standard pool wallet address の踏破」は防げない。Free user 大量作成 (Coupon Collector ≈ 120 signups) で全 30 wallet address 露見 → Paid user の tx を観察可能。

**解決**: Free user 全員で 1 wallet (`ARWEAVE_FREE_WALLET`) を共有、Standard pool 30 wallet とは完全分離。

**実装ファイル**:
- `functions/_lib/wallet-pool.js` 修正 — `loadFreeWallet`, `isFreeUser`, `pickJwkForUser` に Free 分岐追加
- `scripts/generate-free-wallet.mjs`, `topup-free-wallet.mjs`, `check-free-wallet-balance.mjs` 新規
- `scripts/lint-security.sh` invariant (15) 追加
- `scripts/test-wallet-routing.mjs` — routing decision tree 9/9 pass
- `docs/wallet-pool-runbook-phase6.5.md` 新規 — 運用ランブック
- `.gitignore` に `free-wallet.json` 追加

**Wallet 体系の最終形**:

| Pool | 個数 | 用途 | コスト | env var |
|---|---|---|---|---|
| Free wallet | 1 | Free user 全員で共有 | $4 | `ARWEAVE_FREE_WALLET` |
| Standard pool | 30 | Paid user (KV 永続割当) | $120 | `ARWEAVE_JWK_POOL` |
| Private warm pool | 10 | Mega/法人 (1:1 専有) | $40 | `ARWEAVE_PRIVATE_WARM_POOL` |
| **合計** | **41 wallet** | | **$164 (約 ¥24,600)** | |

**Routing 優先度**:
1. Corp member → admin の Private wallet
2. Mega user → 自分の Private wallet
3. Paid user (totalCredits > 100) → Standard pool 30 (KV 永続割当)
4. Free user → ARWEAVE_FREE_WALLET (単一)
5. ARWEAVE_FREE_WALLET 未設定時の fallback → Standard pool (warning ログ)

**判定閾値**: `totalCredits > FREE_BONUS_CREDITS (= 100)` で Paid 認定。最小 Pack (Starter ¥300 = +100 credits) で確実に閾値超過。

**Lint security**: 15/15 invariant pass。

## Phase 6.8 (2026-05-07): USD-balance accounting (writeCount 廃止) — 実装完了

### 背景

Phase 6.7 まで: 書き込み残高は KV 上の `credits` 整数 (= 残り write 回数)。
Pack 購入時に固定回数 (Standard ¥1,000 = 500 writes 等) が確定する。

問題: AR トークン市場価格が変動すると、Arpass 自社の仕入コストは AR 価格に
連動して動くのに対し、ユーザに約束した書き込み回数は固定。AR 高騰時には
margin が痩せ、最悪赤字になる。AR 暴落時には機会損失（高すぎる売価で売り続ける）。

### 解決策

**「ユーザ残高は USD で管理する」+「書き込み消費は当日の AR/USD レートに連動」**
の二本立てで、仕入:売価比率 ≈ 1:6.06 を構造的に固定する。

| 項目 | Phase 6.7 (旧) | Phase 6.8 (新) |
|---|---|---|
| 残高単位 | `credits` 整数 (writes) | `balanceUsdMicro` 整数 (USD × 10⁶) |
| Pack 単価 | 「¥1,000 で 500 writes」固定 | 「¥1,000 で $6.60 残高」固定 |
| 1 write 消費 | `credits -= 1` | `balanceUsdMicro -= 当日 AR price × AR_PER_WRITE × 6.06` |
| 残り回数表示 | KV の credits そのまま | `Math.ceil(balance / 当日 consume)` で client 計算 |
| UI 表示 | 「💳 100」 | 「💳 100 回 (¥1.85/回)」※ USD 残高は非表示 |
| Pack 容量変化 | AR 価格に関わらず固定 | 「本日のレートで約 N 回」daily 変動 |

### 主要変更

- **新規**: `functions/_lib/ar-price.js` — CoinGecko API + KV 5min cache + stale-while-revalidate fallback + emergency $7 fallback
- **新規**: `functions/api/ar-price.js` — 公開 endpoint (60s public cache)
- **書き換え**: `functions/_lib/ledger.js` — `credits` → `balanceUsdMicro`、`debitOne` → `consumeForWrite`、`addCredits` → `addUsdCredit`、`deductCredits` → `deductUsdCredit`
- **Pack 価格表**: `functions/_lib/pricing.js` — `credits: 100` → `depositUsdMicro: 1_980_000` (= $1.98)
- **Stripe webhook**: USD micro deposit に置換、refund/dispute も USD ベースで比例計算
- **Client UI**: `web/lib/app-main.js` の header pill が「💳 N 回 (¥X/回)」、in-app pack modal が「本日のレートで約 N 回」を各 Pack に表示
- **Pricing page**: `web/pricing.html` (via `web/lib/pricing-main.js`) が `/api/ar-price` を fetch して daily で「本日 N 回」を更新
- **Disclaimer**: TOS Article 3 に AR 連動の旨を明記、`web/i18n/{16 langs}.json` に `pricing.disclaimer_ar_linked` を追加
- **Daily monitor**: `scripts/monitor-ar-price.mjs` + `.github/workflows/ar-price-monitor.yml` で日次 spot を `data/ar-price-history.json` に記録、$7 を 7 日継続で GitHub Issue 自動起票、$15 で Mega 販売停止 alert
- **Runbook**: `docs/pricing-revision-runbook.md` に手動価格改定の判断基準を整理
- **Lint invariants**: 21 (consume must call getArPriceUsd) / 22 (GROSSUP_RATIO ≥ 5) / 23 (UI must not display USD balance) を `scripts/lint-security.sh` に追加
- **テスト**: `scripts/test-usd-balance-roundtrip.mjs` で AR 価格 → cost → consume → estimateWrites の math を検証 (13 / 13 通過)

### Yamaki 確認事項 (設計上の選択)

- 「未開業のためレガシー credits は廃止可、クリーン実装で」(完全置換)
- 残り回数は **`Math.ceil` で繰り上げ表示** (端数は切り上げ)
- **UI 上に USD 残高は表示しない** (本日のコスト ¥X/回 + 残り N 回 のみ)

### 環境変数 (Cloudflare Pages secrets)

- `ARPASS_GROSSUP_RATIO` (任意, 既定 6.06): 仕入:売価倍率
- `ARPASS_SIGNUP_BONUS_USD_MICRO` (任意, 既定 50_000 = $0.05): 新規登録時のボーナス USD micro

### 影響範囲

API レスポンスが大きく変わったため、Phase 6.7 以前の client は動作しなくなる
(後方互換なし)。**未開業のため既存ユーザー保護は不要** という前提に基づく。


## Phase 6.8.6 (2026-05-07): Mega Pack の bonus を Heavy と統一 (+100% → +50%)

### 背景

Phase 6.8.1 で導入した bonus 構造で、Mega は +100% (¥30,000 相当) としていた。
ユーザ (yamaki) 指摘: 「割引率が高くて高機能はおかしい。実質 corporate 版なので
機能で勝負すべき」。

### 変更

Mega の depositUsdMicro を 194_800_000 → 146_100_000 に変更（¥30,000 相当 → ¥22,500 相当）。
Bonus は Heavy と同じ +50% に統一。Private wallet + Corp 50 slots は従来通り。

| Pack | 売価 | Old (Phase 6.8.1) | New (Phase 6.8.6) |
|---|---|---|---|
| Mega | ¥15,000 | ¥30,000 相当 (+100%) | ¥22,500 相当 (+50%) |

### 経済性

| 項目 | Old | New | 差分 |
|---|---|---|---|
| Self-cost (¥) | 4,950 | 3,713 | -1,237 |
| 1 Pack 利益 | ¥9,510 | ¥10,747 | +¥1,238 |
| Margin | 63.4% | 71.6% | +8.2 pt |
| Writes (AR=$3.82) | 12,857 | 9,643 | -25% |

Margin が全 Pack で揃う (Standard/Heavy/Mega 71.6%、お試し 79.9%)。
Mega の write 回数は減るが、50 slot で割っても 1 slot 192 回で十分実用的。


## Phase 6.8.7 (2026-05-07): Mega を Business/Family 枠に再 positioning（bonus 廃止）

### 背景

Phase 6.8.6 で Mega の bonus を +100% → +50% に下げたが、Yamaki 氏より：
「Mega は実質 Business/Family（複数名で wallet 共有）。利用率を考えると
50 人で年 200 writes 程度しか使わないので、bonus を付ける必要がない。
機能で訴求すべき」との指摘。

50 名 × 年 4 回 × 5 年 = 1,000 writes が典型利用パターン。
Mega の本来容量（bonus 0%, AR=$3.82）は 6,429 writes ≈ 約 30 年分。
bonus を付けても KV に消費されない USD 残高が積み上がるだけで、
ユーザにも Arpass にも実利益がない。

### 変更

| Pack | Phase 6.8.6 | Phase 6.8.7 |
|---|---|---|
| Mega depositUsdMicro | 146,100,000 (+50%) | **97,400,000 (0%)** |
| Mega bonusJpyEquivalent | 22,500 | 15,000 (= 売価) |
| LP 訴求軸 | 「+50% お得」 | **「法人/家族 50 名で共有・約 30 年分の容量」** |
| LP badge | 🔒 Private Mode | **👥 Business / Family** |

### 経済性

| 項目 | Phase 6.8.6 | Phase 6.8.7 | 差分 |
|---|---|---|---|
| Self-cost (¥, 100% util) | 3,712.7 | 2,475.3 | -1,237.4 |
| 1 Pack 利益 (100% util) | ¥10,747 | ¥11,985 | +¥1,238 |
| Margin (100% util) | 71.6% | **79.9%** | +8.3 pt |
| Writes 容量 (AR=$3.82) | 9,643 | 6,429 | -33% |

実消費は 1,000 writes/5 年程度のため実 margin は 93%+ で変わらない。
理論容量 6,429 writes でも 50 名 × 年 4 回換算で約 30 年分、
50 名 × 年 12 回換算でも 11 年分 → 「使い切れない大容量」枠。

### 整理

Pack 構造：
- お試し (¥300)         : bonus 0%, 個人入門, margin 79.9%
- Standard (¥1,000)     : bonus +50%, 個人標準, margin 71.6%
- Heavy (¥5,000)        : bonus +50%, 個人ヘビー, margin 71.6%
- **Mega (¥15,000)**    : **bonus 0%, Business/Family 機能 SKU**, margin **79.9%**

個人向け (Standard/Heavy) は「+50% お得」で量訴求、
法人向け (Mega) は「専用 wallet + 50 名共有 + 大容量」で機能訴求。
役割が明確に分離。


## Phase 6.8.7 (2026-05-07): Mega を Business/Family 枠に再 positioning (bonus 廃止)

### 背景
Phase 6.8.6 で Mega bonus を +50% に下げたが、Yamaki 氏より「Mega は実質
Business/Family (複数名 wallet 共有)。利用率を考えると bonus 不要、機能で
訴求すべき」との指摘。50 名 × 年 4 回 × 5 年 = 1,000 writes が典型利用で、
bonus 0% でも 6,429 writes 容量 ≈ 30 年分。

### 変更
| Pack | Phase 6.8.6 | Phase 6.8.7 |
|---|---|---|
| Mega depositUsdMicro | 146,100,000 (+50%) | **97,400,000 (0%)** |
| 訴求軸 | 「+50% お得」 | 「専用 wallet + 50 名共有 + 約 30 年容量」 |

利益: ¥10,747 → ¥11,985 (+¥1,238)、margin: 71.6% → 79.9%。

## Phase 6.8.8 (2026-05-07): badge に Private + Business/Family 併記
LP badge を「🔒 Private · 👥 Business / Family」に変更。Private mode (技術
差別化) と Business/Family (use case) の両方を visibility 確保。

## Phase 6.8.9 (2026-05-07): Mega → Business/Family にリネーム + badge 簡素化

displayName と LP 全表記を「Mega」→「Business / Family」に統一。
Badge を「🔒 Private」だけに簡素化（重複解消）。Stripe SKU key (`mega-10000`)
は維持（後方互換）。

## Phase 6.8.10 (2026-05-07): 「最大 50 名」 + ストレージ表示を 80 KiB 基準に

(1) ja.json の lp.pricing.pack_mega_credits に「最大」prefix 追加。他 15 言語は
   既に "up to / hasta / 최대" 等で「最大」相当が含まれていた。
(2) アプリヘッダ「ドライブ容量 0/230 KB」が誤解を生んでいた。230 KB は
   server reject hard cap で、実用上の閾値は PAD_BUCKETS[0] = 80 KiB
   (これを超えると Tier 2/3 に昇格、書き込み 2-3 倍コスト)。表示を 80 KiB
   基準に変更し、超過時に視覚的 tier 警告 (Tier 2 オレンジ / Tier 3 赤 / 230 KB ブロック)。

## Phase 6.8.11 (2026-05-07): tier-aware consume (セキュアドライブ size に応じた消費)

### 背景
consumeForWrite がセキュアドライブ size を見ず固定 1× で消費していた。Tier 2 (80-160 KiB)
で margin 半減、Tier 3 (160-230 KiB) で margin 1/3 に痩せる bug。

### 修正
- `functions/_lib/ar-price.js`: `tierMultiplier(ciphertextBytes)` + `PAD_BUCKETS_BYTES` export
- `functions/_lib/ledger.js`: `consumeForWrite(env, pkHash, ciphertextBytes)` シグネチャ拡張
- `functions/api/write.js`: `dataBytes.byteLength` を渡す
- 倍率: 1.0 (≤80 KiB) / 2.0 (≤160 KiB) / 3.0 (≤240 KiB)
- lint invariant 24 追加 (consumeForWrite must accept ciphertextBytes)

## Phase 6.8.12 (2026-05-07): 「匿名のドライブ ID」表記を正確化

LP FAQ・特商法・利用規約で「匿名のドライブ ID と残高の 2 項目」と書いていたが、
実態は「公開鍵ハッシュ + USD 残高 + 書き込み履歴のメタデータ」。16 言語で正確化。

## Phase 6.8.13 (2026-05-07): アプリ Arpass icon → arpass.io 新タブで開く

ヘッダの Arpass ロゴを `<a href="https://arpass.io" target="_blank" rel="noopener">`
にラップ。重要なお知らせを LP に載せる前提の導線確保。16 言語に title key。

## Phase 6.8.14 (2026-05-07): FAQ q15 + security.html を honest + crypto-normalized に

LP FAQ a15 と security.html の wallet 戦略セクションが (1) Free/Paid wallet
共有を曖昧に表現、(2) Mega → Business/Family rename 未反映、(3) 「30+ アカウント
必要」など misleading な claim があった。3 段構造で書き直し:
- 「Bitcoin・Ethereum など他のブロックチェーンと共通の前提」で normalize
- Free/Paid pool は wallet 共有を honest に（k-anonymity として positive framing）
- Business/Family は専用 wallet を強調

## Phase 6.8.15 (2026-05-07): 「確認中…」i18n + 非日本語版 ¥ → $ 一括変換

- tx-detail-refresh ボタンの「確認中…」が hard-coded 日本語 → i18n_t 化 + 16 言語
- 15 非日本語版で残っていた ¥ 表記を $ に変換 (¥154/USD)
  - ¥2 → ~$0.02、¥300 → $2、¥1,500 → $10、¥7,500 → $50 (round)、¥15,000 → $100
  - lp.description / pricing.* / faq / security.wallet_* / corp.admin_lead 等

## Phase 6.8.16 (2026-05-07): 公開ドキュメントの整合性チェック

tokushoho.html / app.html corp section / pricing-revision-runbook の Mega →
Business/Family rebrand と固定回数 → USD-balance 表記への修正。

## Phase 7.0a-r (2026-04-30〜2026-05-09): Records 機能 (経理書類保管) 実装

### 背景
パスワード以外のもの（領収書・請求書・契約書・健康診断書類等）も Arweave に
永続保存したい需要に応えるため、Records (= ファイル保管) 機能を新規開発。
電子帳簿保存法 (日本) の真実性・検索性要件を念頭に置き、訂正・削除を
append-only audit history として保持する設計。

### 主要実装
- **v3 schema** (web/lib/vault-client.js): `active` / `chunks` / `corrections` /
  `tombstones` / `recordHistory` の 5 サブツリーで構成。chunks overflow 時は
  古い entries を LSM-tree 風に独立 chunk 化 (Arweave 上の 1 record file)
- **3-tier KEK 暗号化** (web/lib/vault-crypto.js):
  MEK → CHK_KEK (chunks-key encryption key) → BEK (body encryption key, per file)
  BEK は MEK で wrap、index と本体を別 tx として保管 (Records index vs file body)
- **任意ファイル形式** (PDF / 画像 / Word / Excel / テキスト等、最大 1 MB)
- **検索/フィルタ** (web/lib/app-main.js): 日付・金額・取引先・タイトル
  日本語 NFKC + ひらがな⇄カタカナ正規化
- **訂正/削除** (vault-client.js): 元 record は immutable、訂正は corrections
  に追加、削除は tombstone マーク、audit history で完全追跡
- **chunks overflow + IDB cache** (web/lib/idb-cache.js): Turbo 配信前の
  bridge として ciphertext を IndexedDB に 7 day TTL で永続キャッシュ
- **records.csv エクスポート**: UTF-8 BOM + 全 metadata カラム
- **PDF OCR** (web/lib/pdf-to-image.js): PDF.js で 1 ページ目を Canvas → PNG
  → gpt-4o-mini Vision API に直送 (BYO key)
- **iPhone 写真自動圧縮** (web/lib/image-compress.js): Canvas multi-pass で
  HEIC 含む大型写真を 200-500 KB JPEG に。OCR 精度を維持しつつ
  Turbo 課金を抑制

### 課金
Records も Turbo 実費 × 6.06 grossup で課金 (Phase 7.0s)。100 KiB 未満は
Turbo Free Tier 還元で完全無料。reserve → reconcile パターンで実費差分を
即時 refund (over-deduction なし)。

## Phase 7.0u-w (2026-05-10): ドキュメント / マーケコピー整合

### 背景
Records 機能リリース後、LP / HELP / pricing / FAQ にファイル保管機能の説明を
追加。Hero メッセージを「パスワード管理」単独から「パスワード + ファイル両軸」
に pivot し、領収書 OCR を wedge feature として打ち出し。

### 主要変更
- **index.html Hero**: "Arpass — パスワードもファイルも、永久に暗号化保存"
- **lp.faq**: a16-a20 として Records / OCR / 100 KiB 無料 / iPhone / 削除に
  関する 5 問追加 + 16 言語翻訳
- **help.html**: Records 専用セクション 5 サブ (Adding / OCR / Searching / 
  Correcting / CSV) + 16 言語
- **pricing.html**: `pricing.records_note` で「クレジットでできること」を
  Records に拡張、100 KiB 未満無料の透明性 disclosure
- **公開コピーから "× 6.06" を完全削除** (原価率露出を回避)
  + `scripts/lint-security.sh` に invariant 25 (公開 .html / web/lib に
  '6.06' / 'grossup' を含まない) を追加 lint 回帰防止
- **i18n カバレッジ**: 14 言語を 100% (1,160/1,160 keys) に到達。i18n-translate.mjs
  に Claude API + salvage fallback パイプラインを実装、JSON parse 堅牢化

## Phase 7.0w-L (2026-05-11): 英語 UI "Records" → "Files" 統一

### 背景
英語版アプリ内タブが「📄 Records」、LP / HELP / Hero では「Passwords + Files」
と混在していた。エンドユーザが LP →サインアップ → アプリ画面と進むと、
英語版だけ "Files" と "Records" の term shift が発生し UX を損ねていた。
14 言語側も `btn_add` だけ「文档」「Beleg」「문서」など別語を使っており
内部不整合があった。

### 主要変更
- **en.json**: `app.records.*` の表示文 ~20 keys を Records/record → Files/file に
  (tab / btn_add / heading / modal_title / toast / archive / csv 等)
- **14 言語**: `btn_add` / `modal_title` の混在 (zh-CN「文档」、de「Beleg」、
  ko「문서」、es/pt-BR/ru/fr/it/id/vi/ar/tr の generic「追加」、hi「दस्तावेज़」等)
  を file 系に統一
- **15 言語の `lp.faq.a20`**: 「Arpass の Records 機能 / Records feature」を
  各言語の「ファイル保管機能 / file storage feature」相当に
- **`security.crypto_records_desc` × 全 15 言語**: 「Records 索引/index/dizini」を
  「files 索引」に
- **CSV ファイル名**: `arpass-records-YYYY-MM-DD.csv` → `arpass-files-YYYY-MM-DD.csv`
  (pre-launch safe rename、`web/lib/app-main.js` + 16 言語の help.records_csv_step_html)
- **HTML default 文言** (i18n 読み込み前): `app.html` / `index.html` / `pricing.html`
  の visible テキストを修正

### 保持したもの
- 内部識別子 (`app.records.*` key、`addRecord()` 関数、IDB store 名、KV 内部用語
  "the KV record" 等) は技術用語として維持
- JS / HTML 内のコメント (`// Phase 7.0... Records` 等の履歴的記述)
- generic な英語複合語 (`medical records`, `Patient record access`)
- verb 形 (`Change recorded`, `we record SHA-256 hashes`, `is recorded`)

## Phase 7.0w-M (2026-05-11): signup bonus 説明強化 + pricing.html 容量目安テーブル

### signup bonus
$0.05 (= パスワード約 3 回分) を据え置き、説明文を強化:
- `app.create.hint_signup_bonus` × 16 言語に追加文: 「100 KiB 未満は無料、
  それより大きいファイルも残高が少しでもあれば最後の 1 回は必ず書き込めるので、
  まずはお試しください」
- 「残高 +1 floor」は Phase 6.8.29 で導入済みの仕様 — estimateWrites が
  「残り 0 回」と算出しても、残高 > 0 なら最後の 1 回は server で許可

### pricing.html: 容量別の料金目安テーブル
新 i18n key `pricing.records_size_guide_html` × 16 言語:
- &lt; 100 KiB: ¥0 (無料) — 圧縮レシート / 設定メモ等
- 100 KiB - 500 KiB: ~¥5 - ¥10 — 標準的な領収書画像
- 500 KiB - 1 MB: ~¥10 - ¥20 — 高解像度 PDF / 写真

JA は ¥ 表記、他 15 言語は $ 表記 (locale-currency split)。AR 価格変動で
前後する旨と残高 floor の透明性を末尾に明記。

### pricing-revision-runbook.md を Phase 7.0 に更新
- タイトル Phase 6.8 → Phase 7.0
- 基本設計に Signup bonus / MAX_DATA_BYTES (1.5 MiB) を追加
- 新セクション「ファイル保管機能の容量別コスト目安」
- 100 KiB 未満無料の根拠 (ArDrive Turbo Free Tier) + Free Tier 停止時の対応
- 残高使い切り保護 (Phase 6.8.29 floor) の説明
- AR > $15 緊急時に Records 上限を 500 KiB に下げる選択肢
- 平均 file size > 800 KiB が継続したら abuse alert (記録)
- BYO-key OCR で Arpass 側 OCR コスト 0 円の運用方針

---

## Phase 7.0w-AH (2026-05-11 〜 2026-05-13): Recovery in セキュアドライブ + Deep Recovery + anti-fingerprint 強化

### 7.0w-AH (#97/#98/#99): Recovery をセキュアドライブ内に encryptedRecovery として保存

セキュアドライブ schema v3 → v4 で `encryptedRecovery` field を導入。signup 時に 1 回だけ画面で見せた Recovery Secret を、AES-GCM(HKDF(MEK, "arpass-recovery-protect-v1")) で暗号化してセキュアドライブデータに inject。unlock 後 (= MEK 既知) であれば再復号して再印刷可能に。biometric ゲート (Passkey PRF) を表示時に再要求。Phase 7.0w-AP で format を rMat ENC (v=1, 一方向) → UTF8 string ENC (v=2, 再表示可能) に変更。既存ユーザは初回 unlock 時に v3→v4 自動 migration。

### 7.0w-AR (#121): vault-id 廃止 + Arweave タグ完全 anonymization

**vault-id 概念を完全削除**:
- 旧 `rMat → vault-id (16 byte) → outer_key` → 新 `rMat → outer_key (32 byte)` 直接派生
- localStorage は `vaultId` → `outerKey` (32-byte b64u) に置換
- UI header の vault-id 8 文字表示を削除

**Arweave タグの完全 anti-fingerprint**:
- 旧固定 tag name `App-Name: <value>` → 新形式 `<random name>: <random value>`
  - name: HKDF(rMat, salt="arpass-app-tag-name-v6", info="app-tag-name::<tier>", 8 bytes) → 11 文字 b64u
  - value: HKDF(rMat, salt="arpass-app-tag-value-v6", info="app-tag-value::<tier>", 16 bytes) → 22 文字 b64u
- 書込種別 (vault/record) は Arweave tag ではなく body.kind で server に伝達
- Record files の tag name/value 両方ランダム化 (`Arpass-Rec-*` プレフィックス廃止)

サーバ /api/write は任意 b64url tag name を 4 個まで forward (SAFE_TAG_RE で sanitize)。

### Deep Recovery Phase A (#102)

Path BC (Passkey + Recovery) unlock を **credIdHash 非依存** に拡張:
- `decryptVault({prfOutput, recoveryMaterial})` (credIdHash 省略) → envelope.w.c の全 wrap_kr を順次試行
- ローカル meta が古い / 完全 fresh device / 複数 Passkey を picker 経由で選択 — どのシナリオでも救済可能
- UI: 既存 unlock view の「Master を忘れた」ボタンに加え、view-restore に新規 details/summary 入口
  「🆘 マスターパスワードも忘れた場合 (Passkey は OS に残っている)」を追加
- 失敗時は confirm dialog で別 Passkey 切替 retry (`forcePicker: true`)

### 7.0w-AS / AT: 軽微 hot-fix

- **AS**: createVault が encryptVault 経由で envelope に encryptedRecovery を inject するが、in-memory セキュアドライブには spread の副作用がないため、session.vault.encryptedRecovery が undefined になる不整合を修正
- **AT**: changePasswordUI は writeEnvelope を直接呼ぶので save-debounce 経由ではない → 編集バッジが saving → saved に遷移しない bug を UI handler 側で updateSaveStatusBadge を手動叩いて補正 (3 か所: unlock-pk-rs / restore-deep-recovery / sec-pw)

### 7.0w-AU: i18n 整合性

Phase 7.0w-AH 〜 AR で en/ja に追加した 32 個の新キーを残り 13 言語 (ar, de, es, fr, hi, id, it, ko, pt-BR, ru, tr, vi, zh-CN, zh-TW) に翻訳して反映。i18n-check 結果: 全 14 言語 1197/1197 (100%) ✓ + placeholder count parity OK + 0 errors / 0 warnings。

### 検証

- `scripts/test-vault-crypto.mjs`: 51/51 passed
- `scripts/test-app-name-tier.mjs`: 7/7 passed
- `scripts/lint-security.sh`: 全 25 invariants intact
- `scripts/i18n-check.mjs`: 14 言語 100% カバレッジ + placeholder parity

### 残タスク (Phase 7.0w-AH umbrella)

- #100 機種追加 — peer-to-peer QR ペアリング (未着手、low priority — Deep Recovery + 再印刷で大部分の利用シナリオを既に救済)
- #101 Password 変更後の他デバイス再ペアリング誘導 (#100 と同じ UI で復旧、low priority)

---

## Phase 7.0w-AW (2026-05-13): email alias 整備 + Cowork sandbox author 切替

公開 repo の中で yamaki@technoblest.com / privacy@technoblest.com の生 email
露出を、Cloudflare Email Routing で稼働中の役割別 alias に置換 (privacy@ /
security@ / admin@ / support@arpass.io)。alias 経由なら yamaki@technoblest.com
への spam 急増時に alias ごとに disable できる。

Cowork sandbox の git author email も `admin@arpass.io` に切替 (本コミットが
切替後の初回 push、commit author が `admin@arpass.io` で記録されることを確認)。

Mac 側の `~/git/arpass*` の `git config user.email` も `admin@arpass.io` に
変えると、今後の Mac push でも生 email 流入が止まる。

---

## Phase 7.0w-AX (2026-05-13): GitHub noreply email 移行

git commit author email を GitHub の noreply 形式 (`<id>+<username>@users.noreply.github.com`)
に切替。これにより:

- 実 email (yamaki@technoblest.com / admin@arpass.io) が commit metadata に
  一切記録されなくなる
- GitHub プロフィール (https://github.com/yamaki) への紐付けが復活
  (avatar 表示 + contribution graph に counted)
- 「Block command line pushes that expose my email」設定で、誤って実 email で
  push しようとした場合は GitHub が reject (= 事故防止セーフティネット)

Mac 側 (`git config --global user.email ...`) と Cowork sandbox 側の両方を
切替済。本コミットが切替後の初回 push 動作確認 — GitHub commit 一覧で
avatar 付き Yamaki プロフィールが紐付けば成功。

---

## Phase 7.1 シリーズ (2026-05-14 〜 2026-05-15): Business mode 安定化 + 完全 lockout 救済

Yamaki さんの実機検証で発生した複数のエッジケースに対応する一連のホットフィックスと、 全端末紛失した社員の救済路新設。

### Phase 7.1-AA (2026-05-14): addCredentialOnThisDevice の credentialId 先行 patchMeta

`addCredentialOnThisDevice` の通常パス (deferSave なし) で `saveVault` が 409 を投げると、 OS には Passkey が作られているのにアプリ側 `vault_meta` から credIdHash/credentialId が消える「使えない端末」 状態に陥っていた。 createPasskey 完了直後に先行 patchMeta、 saveVault 後は latestTxId のみ追加 patch する 2 段階方式に修正。 deferSave path と同じ pattern。

### Phase 7.1-AB (2026-05-14): business signup で Recovery を社員に絶対表示しない

社員 signup 直後、 _businessJoinAndDeposit で admin に Recovery を送った後にも、 通常 signup と同じく `rs-box` / `rs-qr` に Recovery 文字列を出していたバグ。 社員には Recovery を見せず admin が一元管理する設計に違反。 `_inviteCode` 検出時は rs-box への描画と recoveryShow view 遷移を完全 skip し、 直接セキュアドライブ view 移行する。

### Phase 7.1-AC (2026-05-14): 完全 lockout 救済 — admin 発行の機種追加コード

社員が全端末紛失した時の唯一の救済路。 admin が `/api/corp/admin/device-add-code/create` で 8 文字 b64u-safe コード (64⁸ ≈ 2.8×10¹⁴, TTL 300s, single-use) を発行。 新端末が `/api/corp/device-add/redeem` (unauthenticated) でコードを引き換え。 IP rate limit 10/min。 autoApprove フラグで admin の追加操作不要モード切替可能。 admin の `_adminApprove` が `decryptEmployeeRecoveryUI` → ECIES (newDevicePubKey) → relay 送信、 新端末は ephemeral signing state で inbox poll → eciesDecrypt → unlockWithPasswordAndRecovery → Passkey 登録。

### Phase 7.1-AD (2026-05-15): 空 vault_meta profile 防御 + 自動 prune

`_migrateLegacyIfNeeded` が legacy `arpass_vault_meta_v5` の値が `{}` (空) でも profile を作ってしまい、 picker に「使えない default profile」 が居座る問題を修正。 加えて `_routeOnStartup` / `_startBusinessJoinFlow` 冒頭で空 profile を自動 prune。 picker render では空 profile を赤枠 + 「空 (使用不可)」 badge 表示し、 クリック時は confirm → delete に分岐。

### Phase 7.1-AE (2026-05-15): 招待コードと機種追加コードの入口統一

社員向け UI を 1 ボタン化。 同じ prompt でコードを受け、 client が format で自動分岐:
- `ARPASS-XXXX-XXXX` (BASE32, ハイフン区切り) → 新規 signup
- 8 文字 b64u-safe → 機種追加 redeem

`_inviteCode` を const → let に変更 (= 後から代入可能、 これが書けていなかったため当初 silent TypeError で create view 遷移しないバグあり)。 `_startBusinessJoinFlow` 全体を try/catch でラップし silent failure 可視化。 admin 招待 UI も「URL 生成 + 表示」 → 「コード発行 + コード表示」 に変更 (= phishing リスク軽減)。

### Phase 7.1-AF (2026-05-15): signup view 会社員モード明示

招待コード入力後の create view を business mode 専用 UI に切替:
- 黄→琥珀グラデーション banner「🏢 会社員モードで登録」
- heading「🏢 会社員として登録」 (個人モード「Arpass を始める」 を置換)
- 個人/admin 向け hint (existing-user-hint、 signup_bonus) を hide
- create-btn label「会社のセキュアドライブを作成」
- 「Recovery は admin に自動送信」 + 「admin が一度アプリを開いている必要」 を 12px hint で明記

### Phase 7.1-AG (2026-05-15): 機種追加を専用 view + 進捗 UI に

`window.prompt` 連発を廃止し、 `view-device-add-redeem` section 新設。 form mode (code / device name / master pw の 3 input) → submit → progress mode (大きな spinner + 10:00 count-down + status text + cancel) の 2 段構成。 polling は 5s 周期 10 分、 タイムアウトで form に戻る、 cancel で picker に戻る、 unlock 失敗時も form に戻る。 admin 承認待ちの間「ハングしたのか」 が一目で分かる UX。

### Phase 7.1-AH (2026-05-15): deposit 取り込み後の slot 同期 race 修正

社員 signup 直後、 admin tab に新規社員が一瞬「離脱済 (Recovery のみ保管)」 と誤表示され、 画面切替後にようやく「✅ Recovery 取り込み済」 になる問題。 `_processRecoveryDeposits` は vault.employees に追加後 cached `state._corpInfo` で再描画していたため、 server-side slot.usedByPkHash が新 pkHash に更新されていても client は古い slot 一覧を見ていた。 修正: deposit 取り込み完了後に `corpInfoUI()` 再 fetch して fresh な slot 情報で再描画。

### Phase 7.1-AI (2026-05-15): refreshFromServerLatest を KV キャッシュ遅延から守る

admin が触っていないのに 409 conflict modal が出る問題。 Cloudflare KV の eventual consistency で saveVault 成功直後に `/api/balance.latestVaultTxId` が古い値を返すケースに対応。 旧版は serverTxId !== oldTxId だと「別端末更新」と誤判定し fetchEnvelope で古い envelope を取得、 session.latestTxId を巻き戻していた。 次の saveVault が expected=古い tx で fire → 409。

修正: `_session.recentlyWrittenTxIds` (Set, FIFO bound 100) を導入。 saveVault 系 5 箇所の writeResult.txid 成功時に記録。 `refreshFromServerLatest` で serverTxId が recentlyWrittenTxIds に含まれていたら「server が自分の過去書込を返した = キャッシュ遅延」と判定し、 session を巻き戻さず `{ refreshed: false, staleCacheDetected: true }` を返す。

### i18n (2026-05-15): 15 言語フル同期

Phase 7.1-AA〜AI で追加された 145 keys を ja/en に投入後、 残り 13 言語 (zh-CN, zh-TW, ko, de, es, pt-BR, fr, it, ru, id, vi, hi, ar, tr) にも翻訳追加。 各言語 1346〜1348 keys に。 `scripts/i18n-translate.mjs` の自動翻訳 pipeline 不使用 (sandbox に ANTHROPIC_API_KEY 無し)、 Claude による手動翻訳でカバー。

### 学び / 今後への教訓

- Cloudflare KV の eventual consistency は単一 session でも 409 を引き起こす可能性がある → 自分の書込 TX を session 内でキャッシュして防御
- `addCredentialOnThisDevice` 系の状態遷移は OS Passkey 登録と Arweave 書込で分離可能 → 失敗時のリカバリ動線を分けやすくする
- 招待 URL より「コードのみ伝達」 が phishing 耐性高い (URL 偽装攻撃を防げる)
- 完全 lockout 救済は admin による帯域外コード発行 + ephemeral key 経由 ECIES が必要、 device-request 単独では不可


---

## Phase 7.2 シリーズ (2026-05-15 〜 2026-05-17): IP 許可リスト + ZK 監査ログ + Business mode K1 配布刷新

Business mode の運用堅牢化を進める 3 本立てのフェーズ。法人ネットワーク境界での接続制限、ゼロ知識を保った監査ログ、そして Business mode の中核である会社共通鍵 K1 の配布方式の全面刷新。

### Phase 7.2-A / 7.2-D (2026-05-15): IP 許可リスト

法人管理者が、自社オフィスの IP 範囲からのアクセスのみに会社セキュアドライブの利用を制限できる機能。管理者は CIDR 表記で許可レンジを登録する。登録できるレンジ幅には上限を設けており、IPv4 は /24 (256 アドレス)、IPv6 は /64 まで。過度に広いレンジ (例 /8) の登録による実質的な無効化を防ぐ。許可リストは会社レコードに紐づけて Cloudflare KV に保存し、各 API リクエストの処理冒頭で `CF-Connecting-IP` ヘッダのクライアント IP を照合、許可レンジ外は拒否する。

Phase 7.2-D は逆方向の保護: 法人として登録された IP レンジからの**個人モード (Personal mode) アクセスをブロック**する。「会社のネットワークから個人セキュアドライブを開く」行為を抑止し、業務環境と私的データの分離を担保する。IP 許可リストはネットワーク境界での補助的な防御層であり、ゼロ知識暗号 (at-rest 防御) を置き換えるものではない。

### Phase 7.2-E (2026-05-16): ゼロ知識暗号化監査ログ

Business mode の管理者操作・社員操作の監査証跡を、ゼロ知識を維持したまま記録する。社員加入・K1 配布・退社処理・K1 ローテーション等の主要イベントを監査ログのエントリとして push し、**管理者セキュアドライブの中に暗号化して格納**する。ログ本体は管理者セキュアドライブの鍵で暗号化されるため、サーバ運営者はログの平文を読めない。会社の管理者だけが unlock 後に閲覧できる。Phase 7.1 で整備した ZK 監査ログの土台の上に構築。

### Phase 7.2-B (2026-05-17): Business mode K1 配布の刷新 (v1 → α → v2)

本フェーズの中核。Business mode では社員セキュアドライブの実暗号鍵 `real_MEK` を「会社共通の wrap 鍵 K1」と「社員個別の wrap 鍵 K2」の 2 材料から HKDF で導出する。この K1 を各社員へ安全に配布する方式を全面刷新した。

- **v1 (envelope.ws 案)**: K1 を会社公開鍵で ECIES 暗号化して Arweave 上に乗せ、対応する会社秘密鍵をサーバが `CORP_KEK_MASTER_SECRET` で wrap して永続保管していた。しかし「サーバが会社秘密鍵を保持 = 構造的にサーバが単独で K1 を復号可能」というゼロ知識違反を抱えていた。会社秘密鍵紛失で全セキュアドライブ永久ロック、漏洩で過去全 wrap 露呈、サーバ鍵ローテーションには全 wrap 再暗号化が必要、という致命的欠陥もあった。中間段階の「α」リファクタを経て v2 に到達。
- **v2 (per-employee enc_K1、最終形)**: K1 を社員ごとに別々に wrap し、サーバは社員の公開鍵だけを預かり、配布操作はすべて管理者が能動的に実行する。各社員は signup 時に ECDH P-256 鍵ペア (emp_keypair) をランダム生成し、秘密鍵を K2 で暗号化してセキュアドライブ内 (`w_emp`) に保存。公開鍵をサーバに登録する。管理者は配布のたびに ephemeral ECDH 鍵ペアを新規生成し、社員公開鍵との ECDH 共有秘密から AES-GCM 鍵を導出して K1 を ECIES 暗号化。生成された `enc_K1[i]` (ephemeral 公開鍵・iv・暗号文) はサーバ KV に `CORP_KEK` で at-rest 暗号化して保存。社員は unlock 時に自分用の enc_K1 を取得し、セキュアドライブ内の emp 秘密鍵で復号して K1 を得る。

v2 の核心は「K1 を社員ごとに別 wrap」「サーバは公開鍵だけを預かる」「管理者のローテーション操作で完結」の 3 点。サーバプロセスは単独で K1 を復号する経路を一切持たず、`CORP_KEK_MASTER_SECRET` をすべて入手しても KV の at-rest 層を剥がせるだけで内側の ECIES wrap は剥がせない。API 署名鍵 (ECDSA P-256) は K1 ではなく K2 から HKDF 派生するため、「K1 取得 API を呼ぶには署名鍵が必要、署名鍵派生に K1 が必要」という鶏卵問題を回避し、K1 ローテーションの影響を受けず監査ログの連続性が保たれる。emp_keypair はランダム生成 + セキュアドライブ内保存 (Recovery からの決定論的派生は不採用) のため、Recovery 変更で鍵ペアが変わらず管理者への再 wrap 依頼が不要、機種追加もセキュアドライブを開けば秘密鍵が得られる。

退社処理ではサーバ側の会員チェック拒否に加え、当該社員の enc_K1 配布レコードを物理削除する。退社社員が enc_K1 をキャッシュしていても退社時点の K1 のみであり、K1 値ローテーション (旧 enc_K1 は 14 日 deprecated 期間後に削除) で永久無効化できる。会社秘密鍵を保管する旧エンドポイント (server-pubkey / derive-dek / upload-keypair 等) はすべて削除し、register-pubkey / unwrap-k1 / rotate-k1 等の新 API に置換。サービス未公開のため v1 / α 環境のデータは破棄して v2 へ移行した。詳細は `docs/phase-7.2-B-server-wrap.md` (v2)。

---

## Phase 7.3 シリーズ (2026-05-16 〜 2026-05-19): 非抽出可能鍵への全面移行

### Phase 7.3-A (2026-05-19): non-extractable CryptoKey 化

パスワードマネージャに対する最大級の脅威は悪意あるブラウザ拡張機能・XSS・改竄された npm 依存 (サプライチェーン攻撃) であり、これらはセッション内に raw な 32 byte の AES 鍵 (例 `_session.mek`) が `Uint8Array` として置かれていると `localStorage.setItem` / `console.log` / `JSON.stringify` で容易に抜き取れることに起因する (2022 年の LastPass 流出は平文マスターパスワードのメモリ常駐が問題視された)。

Phase 7.3-A はコードベース全体で **MEK / K1 / K2 / Recovery 材料 / 署名鍵の raw バイト列を、非抽出可能 (`extractable: false`) の WebCrypto `CryptoKey` オブジェクトに置換**した。非抽出可能 CryptoKey は raw バイト列を JS の世界から隠し C++ ヒープ (BoringSSL) のみに存在させるため、拡張機能や一般 JS コードからは raw を取り出せず `subtle.encrypt` / `decrypt` / `deriveKey` 経由でのみ使える。OS 権限を持たない攻撃者のほぼすべてに対して鍵の raw 抜き取りを構造的に防げる (OS root メモリダンプ・改造ブラウザは原理的限界として対象外、Widevine DRM L1/L3 と同じ)。

主な実装:
- セッションは `_session.mek` (raw) を廃止し、AES-GCM 専用の `mekKey` と HKDF 派生用の `mekHkdfKey` を同一 raw バイト列から用途別に分離して保持。
- unlock 時の派生チェーンで、Argon2id 出力 / Passkey PRF 出力 / Recovery 材料 / 各 wrap unwrap 結果といった中間 raw バイト列は CryptoKey へ取り込んだ直後に `fill(0)` で zeroize。unlock 終了時のセッションには CryptoKey オブジェクトのみが残る。
- 署名鍵 (ECDSA P-256) は unlock 時に 1 度だけ raw で派生し、結果を非抽出可能 JWK としてインポート。Business mode の社員 ECDH 秘密鍵 (`empPrivKey`) も非抽出可能 CryptoKey 化。
- 既存 envelope フォーマットは変更なし (実装変更のみ、データ移行不要)。既存ユーザは次回 unlock 時に新派生チェーンでセッションを組み直す。`saveVault` / body 復号は `session.mekKey` を直接渡すため raw → importKey の 1 ステップが不要になり速度面でも改善。

CryptoKey 化済 (非抽出可能): `mekKey` (AES-GCM)、`mekHkdfKey` / `rMatHkdfKey` (HKDF base)、`outerKey` (AES-GCM)、署名秘密鍵 (ECDSA)、`empPrivKey` (ECDH P-256)。撲滅しきれず raw のまま残る field も明示管理: Personal mode の `_session.mek` (changePassword / changeRecovery / addCredential / Records マイグレーションで必要、非抽出可能 AES-GCM 鍵の再 wrap が WebCrypto 上不可能なため)、Business mode の `businessK2` (K1 ローテーション時の HKDF 入力鍵材料として構造上必要)。これら raw 保持は「ユーザが unlock 状態で操作中」という限定 window に bounded され、1Password / Bitwarden 等の業界標準と同等。緩和策は 5 分アイドル自動ロック・タブクローズ時の `clearSession` による全 raw field `fill(0)` 消去・self-only `script-src` の CSP。

本フェーズはオープンソース公開を一部の動機としている。「Arpass はブラウザ拡張機能由来の鍵漏洩を構造的に防ぐ」という訴求が成り立ち、LastPass 2022 流出のような事案への明確な回答となる。詳細は `docs/phase-7.3-A-non-extractable.md`。


---

## サービスイン前 修正シリーズ (2026-05-22): unlock 信頼性・cross-talk 解消・admin UX

サービスイン直前の staging 検証で表面化した、unlock の信頼性と admin 業務フローに関わる一連の不具合を修正した。中核の cross-talk / 409 は「v2.6 で複数化したインデックス (App-Name タグ / pkHash / `account.latestVaultTxId` / `vaultSlots`) が食い違う」ことに起因する同根の問題群である。

### 緊急復旧 (emergency export) を K1 export に刷新 + 社員向けオフライン復元ツール

Business セキュアドライブは `real_MEK = HKDF(K1, K2)` で暗号化され、Arpass サービスが停止すると K1 配布 endpoint が死に社員は会社セキュアドライブを復号できなくなる。この「運営非依存での復旧」を保証するため、(1) 管理者画面の緊急 export を、廃止済み v1 の「サーバ秘密鍵」ではなく現行の K1 (current + 全 history) を JSON 出力するよう刷新し、(2) 社員側オフライン復元ツール `web/arpass-emergency-restore.html` を新規追加した。復元ツールは Master + Recovery factor と管理者から受領した K1 JSON を入力に、セキュアドライブ envelope を公開 Arweave から直接取得 (GraphQL + arweave.net、`/api/*` 不経由) して復号し、読み取り専用で表示・CSV/JSON エクスポートする。K1 単体ではどのセキュアドライブも開けず (各社員の 2-of-3 factor が別途必要)、ゼロ知識性は維持される。

### unlock エラー表示 — Master 違いと Passkey 違いの区別

従来、unlock 失敗時は crypto factor の不一致を一律 `passkey_wrong_for_vault` として扱い「別の Passkey で再試行」と誘導していた。しかし実際には Master パスワードの打ち間違いも同じ経路に落ち、ユーザは「Passkey の問題 = ロックアウト」と誤解しやすかった (体感上の「頻繁なロックアウト」の主因)。envelope の wrap には各 Passkey の credIdHash が記録されているため、`_extractK2FromBusinessEnvelope` が「提示された credIdHash に一致する wrap が存在したか」を `passkeyWrapPresent` フラグで報告するようにし、「一致 wrap は在るが復号失敗」= Master 違い (`master_wrong`)、「一致 wrap 無し」= Passkey 違い、と区別。UI は前者で「Master パスワードが違います。Passkey は登録済みです」と明示する。

### unlock の最新 txid 解決を pkHash 方式へ — cross-talk の構造的解消

unlock 時、client は「どの Arweave txid がセキュアドライブの最新か」をサーバに問い合わせる。従来の `?app=<App-Name タグ>` 方式は、App-Name タグが tier (free/paid/corp) ごとに別文字列へ派生する (anti-fingerprint 設計) ため、書き込み時と問い合わせ時で tier がドリフトすると一致 slot が見つからず、サーバが `account.latestVaultTxId` (問い合わせタグと無関係な「そのアカウントが最後に書いた何か」) にフォールバックして別セキュアドライブの envelope を返す cross-talk が発生していた。

修正として unlock の `resolveLatestTxIdForUnlock` を `?pk=<pkHash>` 方式へ変更した。pkHash は署名鍵 (`HKDF(MEK)` / `HKDF(K2)`) のハッシュで、tier 非依存・セキュアドライブ固有・不変であり、`?pk=` は当該アカウントの `vaultSlots` を直接返すためタグ照合もフォールバックも経由しない。あわせてサーバ `functions/api/vault/latest.js` の `?app=` パスから危険な `latestVaultTxId` フォールバックを廃止し、一致 slot が無ければ `not_found` を返す。client はその場合 Arweave GraphQL (App-Name タグ直検索) で解決する — Arweave のタグは各 tx に焼き込まれた不変の事実なので cross-talk しない。結果として「server fast-path = pkHash 安定キー」「server 非依存 fallback = App-Name タグ GraphQL」の 2 層構成が確立し、後者は運営撤退後の復旧経路も兼ねる。

### 退社処理 — 確認メッセージの v2 設計への訂正

退社処理の確認ダイアログが v1 設計の名残で「社員は自分の Master+Recovery で過去セキュアドライブを個人記録として使える」と記載していた。v2 では会社セキュアドライブは `real_MEK = HKDF(K1, K2)` で暗号化され K1 はサーバ管理のため、退社処理で slot binding を取り消すと退社者は K1 を得られず会社セキュアドライブを復号も書き込みもできない。メッセージを「退社者は会社セキュアドライブを利用できなくなる」「Arweave 上の暗号文は物理的に消せないが K1 無しでは解読不能な暗号データとして残るだけ」と正確に訂正。在職中に画面で見た情報の手元コピーは退社処理では取り消せない (どのシステムでも同じ) 旨も明示した。退社処理は「slot 取消 (サーバ、即時) → admin セキュアドライブ保存」の順で実行されるため、後段の保存が失敗しても K1 アクセス遮断は完了している。

### 購入後の管理メニュー自動表示

Business/Family (`mega-10000`) 購入時、Stripe webhook は「クレジット加算 → `createCompany` (管理者昇格)」の順で処理する。client の残高ポーリングはクレジット増加を検知した瞬間に停止し corp 情報を 1 回だけ確認していたため、管理者昇格がクレジット反映より遅れて届くと取りこぼし、再ロックするまで管理メニューが現れなかった。ポーリングを「クレジット反映」と「管理者昇格検知」の独立 2 目標に再構成し、Business/Family 購入時は管理者を検知するまで継続するよう修正。検知時は `applyVaultModeUI` を再適用し再ロック時と同一の UI 状態にする。

### 招待社員名の配線 + 社員名変更 UI

招待コード発行 UI の「社員名」入力欄 (`admin-invite-display`) がハンドラから一切参照されず入力値が捨てられていた。発行後に `_setSlotLabel` で管理者セキュアドライブの `corpSlots[slotId]` へ社員名を保存するよう配線し、社員一覧 (`_renderAdminEmployeesList`) は表示名に slot ラベルを最優先で使うようにした。さらに社員一覧の各行に「名前」ボタンを追加し一覧から直接社員名を変更可能にした (従来は別セクションの slot 表にしか rename UI が無かった)。slot ラベルは管理者セキュアドライブ内 (`corpSlots`) に保存され、社員名をサーバに平文で置かない ZK 設計を保つ。

### 文言整理: 「廃業」→「緊急復旧用」

緊急 export 関連の UI 文言から「廃業」表現を撤去し、「緊急復旧用」「Arpass のサービスが利用できなくなった場合」という中立的な表現に統一した (16 言語)。

### 退社処理などで発生する spurious 409 の修正

退社処理時などに、同時編集が無いにもかかわらず「サーバの内容と差分があります」(楽観ロック 409) が発生することがあった。原因は、unlock が `?pk=` で `vaultSlots` の txid から envelope を読み込む一方、保存時の楽観ロック (`write.js`) が `account.latestVaultTxId` とだけ照合していたこと。両フィールドは本来すべてのセキュアドライブ書き込みで同期されるべきだが、`setVaultSlot` が tier 申告条件 (corp 会員未確認など) でスキップされると `latestVaultTxId` のみが進み乖離する。その乖離があると、client が送る `expectedLatestTxId` (= unlock 時に読み込んだ slot の txid) が `latestVaultTxId` と一致せず spurious 409 となっていた。

修正として、楽観ロックの一致判定を「`expectedLatestTxId` が `account.latestVaultTxId` または いずれかの `vaultSlot.txid` のどれかに一致すれば許可」へ変更した。client が実際に読み込み得たいずれかの版と一致すれば「見た版からサーバが進んでいない」とみなす。他端末による実際の書き込みは `recordWrite` (`latestVaultTxId`) と `setVaultSlot` (`slot.txid`) を共に進めるため、真の競合では `expectedLatestTxId` がいずれにも一致せず 409 となり、競合検知能力は維持される。これにより cross-talk (unlock 読み取り側) と spurious 409 (保存書き込み側) という、v2.6 多重インデックス乖離に起因する 2 症状はいずれも解消した。

---

## Phase 7.5 シリーズ (2026-06-02): hwkey UX 大規模強化 + サービスイン直後の bug 撲滅

サービスイン (2026-06-02) 翌日。 hwkey (YubiKey 専用) mode の運用観察で見えた多数の問題を 1 日で集中的に修正したマラソン Phase。 サブシリーズ A 〜 C に分けると hwkey 解錠の速度・信頼性向上 (N〜P) → SW 自動更新基盤 (Q+V+W) → Android Chrome 救済 (Y+Z 系) → コード形式の品質改善 (ZA〜ZC) という流れ。

### Phase 7.5N (2026-06-02): hwkey keyslot を server KV に索引化

hwkey unlock は YubiKey の PRF から導出した anonymized tag で Arweave 上の keyslot blob を発見する必要があり、 従来は公開 GraphQL のみに依存していた。 公開 GraphQL の indexing lag (= upload 受領後 GraphQL 反映まで数分〜数十分) により、 vault 作成直後の unlock が `hwkey_keyslot_not_found` で頻発。

修正として、 `kind=keyslot` を新設し write.js が `KV[ks:<tagName>:<tagValue>] = txid` を記録、 新 `/api/keyslot/latest` endpoint を介して即時取得できるようにした。 通常 vault の `vlatest:<appName> → pkHash` 索引と同じ思想を hwkey にも適用。 GraphQL fallback は維持 (= 旧 keyslot や KV 障害時の救済)。 ZK 影響なし (= tag は元々 Arweave 公開、 pkHash は server 既知)。

「サーバ完全非依存」 を理由に索引化を避けていた初期設計を撤回した。 索引は単なるキャッシュであり、 GraphQL fallback さえあれば 「廃業しても YubiKey で解錠」 性質は失われない。 同じ判断を Phase 7.2-B 当時 vault に対して `vlatest:` 索引で適用していたのを hwkey にも適用しただけ。

### Phase 7.5O (2026-06-02): blob 取得を upload.ardrive.io + retry 短縮で高速化

hwkey unlock は keyslot blob + envelope blob の 2 回の Arweave fetch が必要で、 fresh write (= Turbo CDN 未伝播) では各 retry の初動 3 秒が体感を支配していた。 `/api/arweave/<txid>` proxy に `upload.ardrive.io/raw/<txid>` を 3 番目の並列 candidate として追加 (= Turbo bundler の hot storage を直接引くため upload 直後でも即返)。 `_retryArweaveFetch` の初動 retry を 3000ms → 1000ms に短縮。 体感 6〜15s → 2〜6s。

### Phase 7.5P (2026-06-02): hwkey unlock の段階別 progress + i18n 16言語

「YubiKey を確認中…」 が unlock 全工程 (WebAuthn + KV lookup + blob fetch ×2 + 復号) を被覆していて、 どこが遅いか切り分けられなかった。 6 段階の phase キーに分け、 phase key prefix で i18n 自動解決する仕組みに変更。 16 言語 全部一括追加。 console には `[hwkey-unlock] +<ms> — <label>` と `phase took XXms` の計測ログ。

### Phase 7.5Q + 7.5V + 7.5W (2026-06-02): SW 自動更新の基盤完成

`pwa-install.js` の `_showUpdateBanner` は Phase 7.5L で実装済だったが、 「sw.js のバイト列が前回と異なるとき」 にしか `updatefound` が発火しない仕様。 sw.js は滅多に変えないため、 通常 deploy ではバナーが永遠に出ない盲点を、 BUILD_ID 機構で恒久解消。

  - 7.5Q: sw.js に `const BUILD_ID = "DEV"` placeholder + `CACHE = "arpass-shell-" + BUILD_ID`。 `inject-cache-bust.mjs` に全 JS hash 集約 → SHA-256 先頭 12 文字を BUILD_ID に書き込む処理を追加
  - 7.5V: `build-hashes.yml` workflow の "Commit if changed" ステップが HTML + build-hashes しか commit に含めず、 sw.js + web/lib/ が永久に push されなかった bug 発見。 commit 対象に追加
  - 7.5W: 7.5N の `functions/api/keyslot/latest.js` コメントに 「passkey userHandle」 と書いたため lint:security #26 (= server から userHandle 関与禁止) 違反で Actions が失敗していた。 7.5V を効かせる前提として lint pass させる必要があり、 コメント文言を 「user.id から導出した (client-side のみ)」 に書換

3 つが揃って初めて 「deploy → bot push → sw.js BUILD_ID 変化 → SW updatefound → banner 表示」 のループが動く。 既存ユーザーは banner クリックで自動更新、 cache 手動クリア不要。

### Phase 7.5R 〜 7.5T (2026-06-02): hints / Android 警告の試行と撤回

Android Chrome の picker bug 救済のため WebAuthn L3 `hints: ["security-key"]` を `hwkeyAuthenticate` に渡す試み (7.5R) と、 Android 検知時の事前警告 toast (7.5S) を実装したが、 user 報告で hints が Android の挙動をさらに不安定化させていることが判明し 7.5T で revert。 hints は 「未対応ブラウザは無視するだけ」 と期待していたが、 部分実装ブラウザの方が多様な挙動を引き起こす実装差が激しい WebAuthn L3 機能の典型例。

### Phase 7.5U → 7.5X (2026-06-02): createPasskey UV split の試行と撤回

hwkey の createPasskey が PIN 設定済 YubiKey + Android Chrome で "Unknown error" を出す問題に対し、 create() の UV を `discouraged` → `preferred` に split して create() を成功させる試み (7.5U)。 ただし PIN-set YubiKey で hmac-secret PRF は UV 状態に依存する仕様のため、 create-time UV=true → 後の get() UV=discouraged で PRF mismatch を起こす可能性 (= 同端末 unlock も壊した可能性) があり、 7.5X で UV=discouraged 一貫に revert。 7.5U の error 診断 catch (= `KEY_STORE_FULL` / `Unknown error` 検出 → 詳細日本語エラーに変換) のみ残した。

### Phase 7.5Y (2026-06-02): Android picker mode で 2-tap unlock (NotReadableError 回避)

decisive な user 報告: Android Chrome で hwkey unlock 時 `NotReadableError: An unknown error occurred while talking to the credential manager` が picker get で発火。 Android Chrome CredentialManager は `allowCredentials=[]` + PRF 拡張 + USB-C YubiKey の組合せで NotReadableError を返す既知バグ (= CTAP2 の `authenticatorCredentialManagement` コマンド未実装)。

修正として `hwkeyAuthenticateForUnlock` に `_isAndroidChrome()` 検知を追加。 Android + picker mode 限定で 2-tap に分割: Tap 1 = `skipPrfExtension: true` で PRF 無しの picker get → credentialId + userHandle を discoverable で発見、 Tap 2 = 発見した credentialId で specific get + PRF → 解錠。 `authenticateWithPasskey` に `skipPrfExtension` option を共通追加。 Mac Chrome / iPhone Safari / 同端末 (= meta に credentialId あり) Android は全て 1-tap 維持。 後に 7.5ZA で「同 device の Android Chrome は discoverable list そのものも返さない」 ことが console log で判明し、 2-tap でも picker 経路は機能しなかったが、 7.5Z の AP1 コード方式が picker 完全回避路を提供することで結果的に user 救済された。

### Phase 7.5Z (2026-06-02): 端末追加コード (AP1 形式) — Android 救済 + 全 platform 高速セットアップ

Android Chrome の picker bug は CTAP2 仕様レベルの実装欠落で Chrome 側修正待ち (= 132+ で対応予定としつつ実際は 2026 時点も未修正)。 web 側で構造的に回避する仕組みとして 「端末追加コード」 を実装。 既存解錠端末で表示される `AP1.<credentialId>.<keyslotTag.name>.<keyslotTag.value>` 形式のコードを、 新端末に貼り付け / QR 読取で渡す → 新端末の `meta.credentialId` を populate → unlock 時 `specific get` (= `allowCredentials=[{id}]`) で picker をスキップして解錠成功。

  - `encodeDeviceAddCode` / `decodeDeviceAddCode` (`vault-client.js`)
  - `generateDeviceAddQrSvg` (`qr.js`) を Recovery 用 `generateQrSvg` と別関数化 (= lint:security #5 回避)
  - 設定画面 (`sec-hwkey-devices`) に 「📲 別端末で開くコードを表示」 ボタン → text + QR + コピーボタン
  - 作成画面下に 「📲 端末追加コード (AP1....) で開く」 リンク → 入力欄展開 → ペースト or QR scan → meta 保存 → 即解錠 flow
  - app.html / app-main.js handler / qr.js function / vault-client.js encode-decode / i18n 16言語

ZK 影響なし: credentialId は元々 WebAuthn 公開、 keyslotTag は元々 Arweave 公開。 PRF / 暗号鍵 / Recovery は一切含まない。 漏洩しても vault は守られる (= YubiKey 物理タッチが必須なため第三者は使えない)。

副次効果: picker get + 物理タッチ を全 platform で省略できるため、 単一 YubiKey で iPhone → Mac → Win → 別 Android と多端末展開する場合のセットアップ時間が大幅短縮。 当初 「Android 救済」 目的で設計したが、 全 platform で価値ある UX 改善になった。

### Phase 7.5Z-2 (2026-06-02): QR camera scan 対応

入力側で paste より camera scan が user 体験的に望ましい。 既存の `scanQrFromCamera` (BarcodeDetector + jsQR fallback、 Recovery 用に実装済) を流用し、 「📷」 ボタン → カメラ起動 → QR スキャン → AP1. prefix 検証 → input 流し込み → toast 通知。 i18n 16言語追加。 同時に `app.hwkey_devadd.guide` の文字列でダブルクォート を escape し忘れ JSON 構文を壊した hotfix も含む (= ja / en で全 key が raw 表示される regression を即座に修正)。

### Phase 7.5ZA (2026-06-02): iPhone NFC 2nd tap 回復 (object literal placement)

decisive な user 報告: 「さっきまで動いていた iPhone NFC の 2nd tap が認識しなくなった」。 7.5Y で `authenticateWithPasskey` 内の `_getPk` から `extensions` を object literal の外に取り出し、 条件付き代入する refactor をしたところ regression。 JS object としては functionally identical だが、 iOS Safari の WebAuthn `publicKey` 引数取扱いに何らかの property placement sensitivity があった可能性 (= 仕様外の挙動)。

修正として spread (`..._prfExt`) を使い literal 内で条件分岐する形に戻したところ user の iPhone NFC が即時復活。 通常時の `_getPk` オブジェクト構造は 7.5Y 以前と bit-identical。 WebAuthn 周辺は 「functional equivalent な refactor」 でも壊れることがある、 という非常に貴重な発見をメモリに記録。

### Phase 7.5ZB (2026-06-02): AP1 コード separator を「-」 → 「.」 へ (b64u hyphen 衝突)

user 報告: iPhone で表示した AP1- コードを Android で読むと 「形式が違う」 エラー。 Mac Chrome 表示のものは OK。 原因は b64u alphabet (`A-Za-z0-9-_`) に `-` が含まれるため、 credentialId / tagName / tagValue いずれかに偶然 `-` が混入すると `split("-")` が想定外の要素数を返し decode 失敗。 確率的 flaky bug (= 同じ vault でも credential によって出たり出なかったり)。

separator を ドット (`.`) に変更。 ドット は b64u 外文字なので確実に分離可能。 旧 AP1- 形式は flaky で意味がなかったので backward compat なし。 端末追加コードは ephemeral (= 生成して 1 回貼り付けたら破棄) なため、 既に表示中のコードが切れても影響ゼロ。

### Phase 7.5ZC (2026-06-02): 端末追加コード i18n を platform 中立化

user 指摘: 「既存端末 (iPhone/Mac) の設定で表示した AP1-...」 と書いていたが、 実際は Android や Win も含めて任意の組合せで動作する。 文言を 「既存の解錠済み端末で表示した AP1.... コード」 + 「任意の端末→任意の端末で動作」 に一般化。 16 言語 全部更新。

### 学び / 今後への教訓

  - WebAuthn `publicKey` 引数の **`extensions` field は object literal の中に置く**。 後付け代入は iOS Safari NFC で謎の regression を引き起こす ([[arpass-webauthn-extensions-placement]] にメモリ化)
  - i18n JSON を sed/replace で書き換えた後は **必ず `json.load()` で validate** してから commit する。 ダブルクォート escape 忘れで JSON 構文壊し → 全 key が raw 表示 という最悪 regression を 1 回引き起こした
  - WebAuthn L3 `hints` / authenticatorAttachment 系の新機能は **「未対応ブラウザは無視するだけ」 を信じない**。 部分実装ブラウザの挙動の方が破壊的なことがある
  - GitHub Actions の workflow が user 環境を作っているケース (= 例: BUILD_ID 注入) では、 **lint failure で workflow 全体が止まる** ことに気付きにくい。 lint pass を deploy 健全性の前提条件として扱う
  - separator に使う文字は **input space に含まれない文字を選ぶ**。 b64u 内で `.` `:` `;` ` ` などが安全 (= 7.5ZB の教訓)
  - 機種名を i18n string に書き込むのは UX バイアスを生む。 platform 中立な表現にする (= 7.5ZC の教訓)

---

## Phase 7.5ZD 〜 7.5ZY (2026-06-02 〜 2026-06-03): サービスイン後の大規模整備

サービスイン (2026-06-02) 当日と翌日にかけて、 SEO 整備、 LP 動的価格化、 Recovery UX 改革、 module identity 罠の解消、 CI 強化等を一気に進めた phase 群。 計 22 phase、 1 セッションで完走。

### Phase 7.5ZD: Turnstile language を arpass UI 言語に同期
Cloudflare Turnstile が日本語のまま英語 UI に出ていた regression を、 `language: i18n_getLang().toLowerCase()` で同期。

### Phase 7.5ZE: ファイル保存の insufficient_credits メッセージ修正
「balance 0 ≤ 0 (USD micro)」 という raw server エラーが UI に出ていた。 `e.code === "insufficient_credits"` ハンドリングを records modal の 2 箇所 (= records-modal-save / records-edit-save) で追加、 i18n 化された CTA HTML 表示に置換。

### Phase 7.5ZF: グローバル SEO 基盤
robots.txt + sitemap.xml (101 URL) + OpenGraph + Twitter Card + hreflang + JSON-LD 構造化データ (Organization + WebSite + SoftwareApplication) を index.html / help.html / guide hub / pricing.html / security.html に整備。 海外検索エンジンへの導入準備完了。

### Phase 7.5ZG: AP1 端末追加コード節 14 言語自然翻訳
7.5Z で追加した 7 keys を ja/en 以外の 14 言語に手動翻訳 (= zh-CN, zh-TW, ko, es, pt-BR, de, fr, it, ru, id, vi, hi, ar, tr)。 各言語の自然な技術文体を意識した翻訳。

### Phase 7.5ZH: LP + help.html を 16 言語に静的化
`scripts/render-static-html.mjs` を新規作成し、 cheerio で `data-i18n` 系 attribute 全種を処理して per-language 静的 HTML を生成。 `/en/index.html` `/zh-CN/help.html` 等 30 ファイル生成、 sitemap.xml 130 URL に拡張。 OG card 1200x630 PNG を Python で生成、 internal linking 強化 (LP/help ⇔ guide)、 hero img alt の i18n 化、 `<main>` landmark 追加。

### Phase 7.5ZH hotfix: package-lock.json 復旧
cheerio devDep install が timeout で interrupt され、 package-lock.json が 0 byte で commit されていた。 Cloudflare Pages の `npm ci` が EUSAGE で fail、 ZH 以降の deploy が一切走っていない状態。 pre-ZH 状態 (= 56f805a の 12258 行) から checkout で復旧、 cheerio を devDependencies から削除 (= build script はローカル専用化)。

### Phase 7.5ZI: URL prefix を localStorage より優先
i18n.js の `_resolveInitialLang()` で URL prefix (= /en/, /tr/ 等) を localStorage より優先するよう変更。 `_buildLangPrefixedUrl()` + `_isOnLangPrefixedPage()` helper を追加、 picker 切替時の URL ナビゲーション機能も実装。

### Phase 7.5ZJ: LCP 6.3s + CLS 0.428 改善
hero image (arpass-image.png) を 403K → 66K PNG / 58K WebP に圧縮 (= palette 256色 + WebP)、 `<picture>` + `<source>` で WebP 優先、 全 img に width/height 明示、 `<link rel="preload">` + `preconnect` 追加、 `<main>` landmark 追加。 Lighthouse Performance 58 → 96、 CLS 0.428 → 0.014。

### Phase 7.5ZK: Accessibility 93 → 100
heading 階層 h2 → h4 skip を h3 に正常化 (HOW IT WORKS + Footer)、 footer-brand / footer-tag の purple #5B21B6 (= 2.04:1 ❌) を sky-700 #0369A1 (= 5.93:1 ✅) に変更。 a11y 93 → 100。

### Phase 7.5ZL: section-kicker contrast 修正
section-kicker の var(--teal) #0EA5E9 が 2.77:1 で WCAG AA fail。 sky-700 #0369A1 (= 5.93:1) に変更。 10 箇所一括更新。

### Phase 7.5ZM: LP 動的価格化 — /api/ar-price 連動
LP の 「¥2/回」 「¥1000 で 500 回」 「10 年以上」 等の固定値を AR トークン市場価格連動の動的計算に。 `web/lib/lp-pricing.js` 新規 (= /api/ar-price fetch + 60 秒 cache + 6 種類 placeholder substitution)、 16 言語 i18n に `{perWrite}` 等の placeholder 化 (144 strings update)。 LP の 8 element に `data-lp-price` マーカー追加、 build-time placeholder default 値も render-static-html に組込み。

### Phase 7.5ZN: per-write 表示の 3 ページ統一
App ヘッダの per-write 表示が tier 2/3 反映で ¥3.39 だったのに対し、 LP / pricing.html は baseline ¥2 を表示。 App を `perWriteUsdBase` (= server が既に返している tier 1 baseline) 表示に変更、 JPY/USD レートも 154 → 150 に 3 ページ統一。

### Phase 7.5ZO: AR_PER_WRITE 0.000654 → 0.00114 再校正
user 実観測 (= 108 KiB tier 1 で actual ¥3.39) から逆算した値に校正。 旧定数は under-reservation で reconcile 時の差分が user 残高または Arpass 肩代わりに流出。 表示値も実態に近づき、 LP/pricing/App で揃う。 課金への影響は無し (= 実 billing は Turbo winston ベース)。

### Phase 7.5ZP: LP perWrite を floor 表示
formatPrice の round (3.50 → 4) で 「¥3〜」 が誤って 「¥4〜」 と表示される問題。 `fmtFloor()` 追加で perWrite のみ Math.floor を使い、 marketing の 「from price」 として誠実に。

### Phase 7.5ZQ: 英語表示の ¥ 残存除去
why-card 3 つ目のアイコン `<span class="why-icon">¥</span>` を 💰 emoji に、 twitter:description / og:description / JSON-LD 内の 「¥0/month + ¥2 per save」 を 「Free to start, pay a few cents」 に置換。 6 箇所の ¥ 残存完全除去。

### Phase 7.5ZR: picker URL redirect を root → /xx/ に拡張
Phase 7.5ZI の `_isOnLangPrefixedPage()` ガードで root → /xx/ への redirect が抜けていた bug を、 STATIC_RENDERED set (= /index.html, /help.html, /) チェックに変更して root も redirect 対象に。

### Phase 7.5ZS: lp-pricing.js の i18n.js import を absolute path に
LP の perWrite が EN mode でも ¥ 表示される真因。 lp-pricing.js が `import "./i18n.js"` (相対 path、 inject-cache-bust 対象外) を使っていたため、 index-main.js の `import "/lib/i18n.js?v=XXX"` とは別モジュール instance に解決され、 lp-pricing 側の `_lang` が "ja" デフォルトのまま。 `/lib/i18n.js` 絶対 path に変更で同一インスタンス共有。

### Phase 7.5ZT: lp-pricing の言語検出を DOM 直読
ZS で改善されたが、 module identity 罠の再発リスクを構造的に排除するため、 lp-pricing は `getLang()` / `onLangChange()` を使わず `document.documentElement.lang` を直読、 `MutationObserver` で属性変更を監視する設計に変更。 i18n.js の module state に一切依存しない。

### Phase 7.5ZU: QR scanner 画像ファイル読取り
`scanQrFromImage(file)` を qr.js に追加 (= BarcodeDetector + jsQR fallback)。 QR scan overlay に 「🖼 画像から読む」 ボタン追加、 既存の camera scan callsite (× 2) を `scanQrCombined(video, opts)` (= Promise.race) で camera + file 両方受付に refactor。 mobile user が camera 使えない / Photo に保存した QR から復元 が可能に。

### Phase 7.5ZV: Recovery 保存方法 picker UI + Photo 画像保存
「📵 写真撮影禁止」 の硬直方針による user 離脱を防ぐため、 4 段階 picker (BEST/GREAT/OK/AVOID) で現実的な best 選択肢を提示する設計に転換。 「📸 画像で保存」 ボタン で 800x1000 PNG (= RS1 + QR + 注意フッタ) を生成、 `navigator.share({files})` で OS 共有シート起動。 user は iCloud Photos 等に保存可能 (= ADP / E2E ON 前提)。

### Phase 7.5ZW: GROSSUP/AR_PER_WRITE を client 側から撤去 (= lint:security #25 修正)
ZM で client lp-pricing.js に埋めた `GROSSUP = 6.06` `AR_PER_WRITE = 0.00114` がもろに business margin 倍率を public に露出 (= rule #25 違反)。 secrets を撤去、 server が /api/ar-price で完成形 consumePerWriteUsd を返す設計に統一、 fallback も formula 化せず固定値 `FALLBACK_CONSUME_PER_WRITE_USD = 0.024` を持つ。 GitHub Actions の regression-grep failure 解消。

### Phase 7.5ZX: pre-commit / pre-push hook で lint:security 自動化
ZW 再発防止。 `.githooks/pre-commit` (= web/lib/, functions/, scripts/ 変更時のみ) + `.githooks/pre-push` (= 常に) で lint:security 自動実行。 `scripts/install-git-hooks.sh` で 1 行 install、 `npm run install-hooks` で簡単。 緊急時 `--no-verify` で bypass 可。

### Phase 7.5ZY: 画像保存ボタンを PC でも動くように
Mac で 「Photo に画像で保存」 が share sheet を起動して Notes/Mail/LINE 等のみ表示 (= Photos 項目なし)、 PC user が困った報告を受け、 mobile/PC 判定の `_isMobileLike()` helper 追加。 mobile = share sheet、 PC = 直接 download に分岐。 label を 「📸 Photo に保存」 → 「📸 画像で保存」 に neutral 化、 16 言語 i18n も 80 string update。

### 学び (= memory に保存)

  - **ES module identity 罠**: `./foo.js` と `/lib/foo.js?v=XXX` は別モジュール扱い。 シングルトン状態を持つ module は import を統一する ([[arpass-es-module-identity-trap]])
  - **DOM driven design**: module 間 state 同期に不安があるなら、 DOM 属性を真実の source にする (= MutationObserver で監視)
  - **business secret leak 防止**: GROSSUP 等の margin 倍率は server-only。 client 側に formula を埋めると逆算される。 pre-push hook で防御
  - **「禁止」 より 「条件付き OK」**: 厳格な禁止文言 (= 写真撮影禁止) は user 離脱を生む。 現実的 best 選択肢を picker で提示する設計が UX 上正解 (= [[arpass-recovery-in-vault]] を更新)
  - **commit 前 branch check**: 連続作業で main に居ることに気づかず直 commit する事故が頻発、 commit 前は必ず `git branch --show-current` ([[feedback_branch_check_before_commit]])
  - **build script 専用 dep は npm に入れない**: lockfile 壊しと Cloudflare Pages build 失敗の罠 (= ZH hotfix)

---

## Stage 1 Rust 化 (2026-06-04) — Argon2id + HKDF + SHA-256 を Rust + WASM に

Yamaki 判断 「まだ 1 本も売れてない今が大規模 refactor の絶好機」 を受け、 crypto primitives を Rust + WASM へ段階的に移行。 Stage 1 は **noble pure-JS の primitive を置換**、 envelope orchestration は JS のまま。 1 セッションで scaffold〜staging 検証 まで完走。

### scope (= 実施)

- ✅ **Argon2id** (= Master KDF、 主要 速度改善源): noble pure-JS 1-3 秒 → Rust + WASM 0.1-0.5 秒
- ✅ **HKDF-SHA256** (= 兄弟鍵派生): Rust crate `hkdf`、 derivePMat 以外の hkdfBytes() callsite 全部経由
- ✅ **SHA-256**: HKDF 内部経由 (= sha2 crate)
- 🟡 **AES-GCM**: WebCrypto 維持 (= 意図的、 non-extractable CryptoKey 設計を保護するため)
- ⏳ **ECDH P-256**: 後回し (= shared secret format conversion 必要、 caller 改修まで含むので別 task)

### アーキテクチャ

```
rust-crypto/
├── Cargo.toml              # RustCrypto crates (argon2 / aes-gcm / sha2 / hkdf / p256)
├── src/lib.rs              # 5 primitive + 5 KAT (= SHA-256 RFC, HKDF RFC 5869, etc.)
└── (wasm-pack build で出力)
    web/lib/rust-crypto/
    ├── arpass_crypto.js    # wasm-bindgen JS glue
    └── arpass_crypto_bg.wasm  # 124 KB binary

.github/workflows/
└── build-rust-crypto.yml   # CI: cargo test + wasm-pack build + commit back

web/lib/vault-crypto.js
├── _getRustCrypto()        # lazy load WASM module、 module init で fire-and-forget preload
├── derivePMat()            # Rust 優先 / noble fallback
└── hkdfBytes()             # Rust 優先 / noble fallback (同期)
```

### Backward-compatibility (= 維持)

- 既存 vault data on Arweave (= pre-Stage 1) を壊さない
- 同じ input で noble と bit-identical output を生成 (= Rust crate も noble も RFC 準拠)
- Argon2id params (= Phase 7.4): m=65536, t=3, p=4, tagLen=32 不変
- envelope.kdfParams 不変、 migration 無し
- Rust 失敗時 noble fallback で envelope 復号は必ず動く

### CI 構築の罠 5 件 (= 苦戦して memory に保存)

1. **wasm-opt = false 必須** (= bulk memory ops、 wasm-pack 同梱の wasm-opt が古い)
2. **JsError は native cargo test で panic** (= wasm-bindgen-test 環境で error path 検証する設計)
3. **p256 0.13 API** (= ToEncodedPoint trait import 必須、 from_slice / from_sec1_bytes 推奨)
4. **YAML literal block + multi-line commit msg は別 `-m` に分割** (= GitHub Actions workflow を壊さない)
5. **wasm-bindgen の auto-commit が untracked file を取りこぼす** (= git add は --cached check の前に)

詳細は memory [[feedback-rust-wasm-pack-gotchas]] / [[feedback-yaml-workflow-multiline-commit]] へ。

### 副次的に発覚 + 修正した 4 件

1. **CSP `'wasm-unsafe-eval'` 必要** — WebAssembly.instantiate を許可、 古い CSP では block される
2. **Cloudflare Bot Fight Mode の JSD inline script が CSP 衝突** — JS Detections を Off で解消 (= origin / staging 共通設定)
3. **build-hashes-monitor で robots.txt が毎時 false-positive mismatch** — Cloudflare AI bot 拒否機能が edge で改変、 monitor 側に SKIP_PATHS 追加
4. **ES module identity 罠の 2 件目** — vault-crypto.js への 9 occurrences の相対 path import (= vault-client.js / client-auth.js) が `_rustCrypto` singleton を分裂させていた、 absolute path に統一

### 実機検証 結果 (= staging.arpass.io)

console:
```
✅ vault-crypto.js?v=4fd25ef2:50 [arpass] Rust crypto core loaded (Stage 1: Argon2id)
   ← 1 回だけ表示、 cache-bust 付き
```

体感: vault unlock の Argon2id phase が 数倍高速化 (= user 確認)。

### rollback 手順 (= 不要だったが念のため)

```sh
git checkout staging
git reset --hard staging-pre-rust-2026-06-04  # tag at commit dae3c3b
git push origin staging --force-with-lease
```

### 関連 commit (= 主要のみ)

- `6bc5001` Stage 1 scaffold
- `52ad43a` **Argon2id wiring** (= derivePMat → Rust)
- `8f39959` **HKDF/SHA-256 wiring** (= hkdfBytes → Rust)
- `70db0da` **ES module identity 罠修正** (= 9 occurrences 統一)
- `f032434` CSP wasm-unsafe-eval 追加
- `30f41b7` build-hashes-monitor の robots.txt skip

### 残作業 (= 後セッション)

- ⏳ user flow 全検証 (= vault 作成 / file 保存 / device 追加 / changePassword)
- ⏳ staging → main マージ (= 本番反映)
- ⏳ Stage 2 検討 (= envelope orchestration を Rust 化、 mobile FFI/JNI 準備、 3-6 ヶ月 単位の投資判断)

---

## Phase 7.2-F (2026-06-06): 「読み出しも社内のみ」 toggle + 当日 hotfix 一式

### 背景

- Phase 7.2-A で会社 admin が IP allowlist を設定し **write** を社内 IP に gate する機能は完成済。
- ただし **read** (= 社員 unlock = K1 fetch) は IP gate 対象外で、 退職者の持ち帰り PC や WFH 社員が allowlist 外から復号可能だった。
- 銀行・医療・防衛等の DLP 厳格 enterprise 向けに、 「読み出しも社内 IP のみ」 を強制する opt-in toggle が必要。

### 設計

- 既存 IP allowlist (= `company.ipAllowlist`) と admin UI を再利用。
- 新フィールド `company.restrictReadToAllowlist` (= boolean) を追加。 default = false (= 既存環境への影響ゼロ)。
- gate の実装位置は `/api/corp/fetch-enc-k1` (= 社員が自分用 enc_K1 blob を fetch する endpoint)。 K1 を出さなければ復号不能なので、 ここで gate すれば arweave.net 直叩きでも復号できない。
- admin は exempt (= write 側 Phase 7.2-A hotfix と同じ思想)。 admin の IP 変動 (= 出張 / WFH / IPv6 prefix rotation) で操作不能になるのを防ぐ。

### server 実装

- `functions/_lib/corp.js` の `setIpPolicy` が `restrictReadToAllowlist` フィールドを受付、 KV に保存。
- `functions/api/corp/admin/set-ip-policy.js` が client からの値を `setIpPolicy` に pass-through、 response に最新 status を返却。
- `functions/api/corp/info.js` が admin info で `restrictReadToAllowlist` を返却 (= UI checkbox の初期表示に使用)。
- `functions/api/corp/fetch-enc-k1.js` で gate 実装:

```javascript
const company = await getCompanyForUser(auth.publicKeyHash, env);
if (company?.restrictReadToAllowlist === true &&
    company.adminPkHash !== auth.publicKeyHash &&  // admin exempt
    Array.isArray(company.ipAllowlist) &&
    company.ipAllowlist.length > 0) {
  const clientIp = getClientIp(request);
  if (!clientIp || !ipInAnyCidr(clientIp, company.ipAllowlist)) {
    return json({ ok: false, code: "ip_gate_read", error: "...", allowlistConfigured: ... }, 403);
  }
}
```

### client 実装

- `web/lib/vault-client.js` の `corpAdminSetIpPolicyUI` が `restrictReadToAllowlist` を body に追加。
- `web/app.html` の network policy セクションに **赤色** checkbox を追加 (= 強い警告 visual)。
- `web/lib/app-main.js` の save / load / reset handler に `restrictReadToAllowlist` 取得・送信・復元・clear を実装。
- audit log push の details にも `restrictReadToAllowlist` を含める。
- 新 i18n key 2 件 × 16 言語: `app.admin.netpolicy_restrict_read_label`, `app.admin.netpolicy_restrict_read_hint`。

### 検証 (= staging.arpass.io、 2026-06-06 user 実機)

1. ✅ admin が checkbox ON で save → KV に persist (= reload しても残る)
2. ✅ 社員 (= 非 admin) が allowlist 外 IP で unlock 試行 → 403 `ip_gate_read`
3. ✅ admin は同じ IP でも素通り (= exempt)
4. ✅ allowlist 空 (= `[]`) なら toggle ON でも effect なし (= default 動作)

### 制約事項 (= 設計判断として残す)

- 一度 K1 を fetch して session memory に持っている社員は、 lock するまでそのまま使える (= 「lock → 社外 → unlock」 で初めて gate 効く)。
- K1 rotation を行うと全社員 fetch 必要なので、 admin が「持ち帰り社員を即座に締め出したい」 ときは rotate-k1 を打てば次回 unlock 不可 (= 即時 enforcement の救済路)。

### 関連 commit

- `04bd7b9` **Phase 7.2-F 実装** (server + client + i18n 16 言語)
- `03cd761` admin exempt 追加 (= read gate にも write 側と同じ思想を適用)
- `506f179` save handler hotfix (= patch script silent fail で送信漏れていた一行を修正)

---

## 2026-06-06 当日 hotfix 一式 (= 業務モード復活 + UX 整理 + bug 撲滅)

### Critical fixes

1. **`_extractK2FromBusinessEnvelope` の kdfParams 渡し忘れ** (`5ce537f`) — Phase 7.4.1 strict 化以降、 業務モード unlock が `derivePMat: kdfParams required` で常時 throw する regression。 envelope.kdfParams を引数に追加して fix。
2. **derivePMat fallback の削除** (`af5e1fe`) — 上記 hotfix の一時 fallback (= CURRENT_KDF_PARAMS に fallback) を user 指示で revert、 strict throw 維持。 真因を silent に隠さないため。
3. **`/api/write` の inviteCode atomic 化** (`6f616ce`) — 業務モード signup 時、 IP allowlist が有効だと社員が vault 作成不能だった (= 未 member 状態で IP gate にかかる)。 inviteCode を /api/write に渡し server 側で member 登録 → IP gate という atomic 処理に。
4. **auto-prune 撤回** (`edb3abe`) — `_pruneEmptyProfiles()` が false positive で 「使える vault」 を起動時に削除する事例 発生。 起動時 auto 呼出を削除、 picker の赤バッジ + 手動削除 UI で代替 (= Phase 7.1-AD で既存)。
5. **picker-new-btn の即時 createProfile を delay** (`514f35f`) — 「+ 新しいドライブを追加」 click 時に profile entry を作っていたため、 create view でリロード / 戻ると 空 husk が増殖。 createProfile を create-btn click 時 (= 実際の signup 開始時) に delay、 失敗時 deleteProfile で rollback (`5ee82ec`)。

### UX 改善

1. **「すでにドライブをお持ちですか?」 を 1 ボタン化** (`4398e8a`) — heading `<p>` + button の 2 要素を 1 つの button に統合、 user が見出しテキストをクリックしても反応しない紛らわしさを解消。
2. **戻る link 追加** (`514f35f`) — create view 上部に 「← ドライブ一覧に戻る」 link、 1+ profile 時のみ表示。
3. **ボタン `<br>` 改行** (`51d6b17`) — 1 ボタン化後の文字列が横に長すぎたため `data-i18n-html` + `<br>` で 2 行に。

### IP allowlist UI 改善

- **IPv6 /128 警告追加** (`5ee82ec`) — admin UI の help text + placeholder を更新、 IPv4 推奨 /32 / IPv6 推奨 /64 を明示、 IPv6 で /128 単独 を使うと OS の Privacy Extensions で動かないことを警告。 16 言語反映。

### 関連事象 (= memory 化)

- Mac の git working dir (= `/Users/yamaki/.../arpass/`) が古い main (= Phase 7.0w-S2) で stale だった、 sandbox `/tmp/work/arpass/` の staging branch で作業継続。 → [[arpass-mac-git-auth]] memory 通り、 Mac 側で直接 commit していないため害なし。

---

## Rust 化 Phase 1 完成 (= Stage G4-G11、 2026-06-06)

### 背景

Stage 1 (= Argon2id / HKDF / SHA-256 / ECDH の純関数 Rust 移行) と Stage 2c outer key 全 path migration 完了後、 残された目標は 「**Personal mode の全主要 crypto operation を Rust 経由にする**」 = **「raw bytes JS heap 露出ゼロ化」**。

memory `[[arpass-rust-opaque-handle]]` Stage G で記録した難所 (= mekHkdfKey CryptoKey non-extractable、 K1→K2→MEK chain) を回避しつつ、 Personal mode の primary path のみ Rust 化することで pragmatic な完成を目指した。

### Stage G4-G11 内容

| Stage | 内容 | 影響 |
|---|---|---|
| **G4** | `addRecord` (= ファイル添付) の BEK 生成 + wrap を Rust handle 化 | Personal mode の record write |
| **G5** | `fetchRecord` (= ファイル復号) も同じ Rust handle 化 | Personal mode の record read |
| **G6** | `chunk` (= LSM-tree archival、 CEK) も Rust handle 化 | Personal mode の chunk seal/load |
| **G7** | `encryptVault` / `decryptVault` の **body AES-GCM** を MekKey handle に | Personal mode の vault 本体 encrypt/decrypt |
| **G8** | `encryptVault` の **wrap A/B/C** と `decryptVault` の **AB/AC/BC unwrap** を KEK handle に | Personal mode の MEK wrap/unwrap 全 3 path |
| **G9** | **`deriveKEK` 自体を polymorphic 化** (= handle 優先、 CryptoKey fallback) | 全 14 callers (= addCredential、 changePassword、 changeRecovery_caseA/B、 業務 mode 系含む) が一括 Rust 経路に |
| **G10** | `deriveRecoveryProtectKey` が MekKey handle を受付 (= Recovery 経路の Rust path 開通) | encryptedRecovery 経路 |
| **G11** | `encryptRecoveryWithMek` / `decryptRecoveryWithMek` 内部で raw mek → handle 変換、 Rust 経路を発動 | encryptedRecovery の caller は無変更で透過化 |

### Rust handle 経由のものまとめ (= 2026-06-06 時点)

| 操作 | path |
|---|---|
| Argon2id (Master KDF) | ✅ Rust (Stage 1) |
| HKDF / SHA-256 / ECDH | ✅ Rust (Stage 1/2a) |
| Outer envelope wrap/unwrap (= 全 unlock/save) | ✅ Rust handle (Stage 2c outer key) |
| **vault body encrypt/decrypt** | ✅ Rust handle (G7) |
| **MEK wrap A/B/C + unwrap** | ✅ Rust handle (G8/G9) |
| **KEK derive** | ✅ Rust handle 優先 (G9、 全 14 callers) |
| **Recovery K_recovery 派生 + encrypt/decrypt** | ✅ Rust handle (G10/G11) |
| BEK (record file) | ✅ Rust handle (G4/G5、 Personal only) |
| CEK (chunk) | ✅ Rust handle (G6、 Personal only) |

### 残作業 (= Phase 2 候補)

| 部位 | 状態 | 投資判断 |
|---|---|---|
| Business mode BEK/CEK | CryptoKey path (= K1→K2→MEK chain の Rust 化 要設計) | mobile native 着手時に再検討 |
| `_session.mek` raw bytes | encryptVault/decryptVault 内 transient (= 数命令の生存期間、 caller 経由で session に渡る前に消える設計を模索) | 完全撲滅には外部 API 変更必要 |
| `_session.mekKey` CryptoKey | session 保持 legacy field (= 互換性のため残置) | session を MekKey handle 中心に再設計可能だが scope 巨大 |
| signing key 派生 | `deriveSigningKey(mek)` → CryptoKey | Rust `p256_keypair_from_seed` 経路は既に存在、 wiring のみ |
| Business mode K1 wrap chain | 全 CryptoKey | 業務 mode K1Key handle の per-version cache 設計が必要 |

### backward compat

- ciphertext format **完全同一** (= AES-256-GCM 同 algorithm、 同 key bytes)
- rust-crypto 未ロード時は **CryptoKey path に自動 fallback** (= regression なし)
- 既存 envelope を新 path で復号可能、 新 envelope を旧 path で復号可能
- 業務 mode は (G9 の deriveKEK polymorphic 化を除き) 既存 CryptoKey path 完全維持

### 関連 commit (= main 反映済)

- `2c11f77` Stage G5: fetchRecord Rust handle 化
- `aa133c9` Stage G6: chunk CEK Rust handle 化
- `ab7a8de` Stage G7: vault body encrypt/decrypt
- `8975455` Stage G8: KEK derive + wrap A/B/C
- `a8be7d1` Stage G9: deriveKEK polymorphic (= 全 14 callers 一括移行)
- `6cb2e83` Stage G10: deriveRecoveryProtectKey handle 受付
- `4f4ccc6` Stage G11: encryptRecoveryWithMek 内部 Rust 化
- `ea403f2` hotfix: migrateAccount URL `/api/migrate` → `/api/vault/migrate` (= pre-existing bug、 Stage G11 検証時発覚)

### 関連事象

- **Stage G4 v1 (= dual-emit) は revert 済**: 前回 dual-emit (= CryptoKey + handle 並列) の attempt は unlock 不能 regression を起こして revert。 Stage G4 v2 (= 完全置換) で再着手し成功。 教訓: 「並列 populate より完全 置換」 が opaque handle migration の正解 path。
- **migrate URL bug は Recovery Case B 試行で発覚**: user 報告で 「Recovery Case B 機能を試したことがなかった」 → 試行で 405 露呈。 Stage G11 検証作業 内で副次的に bug fix した形。
