<!--
====================================================================
⚠️ AUTO-GENERATED MIRROR — DO NOT PR HERE

This file is automatically synced from the private arpass repo on every
release. Direct edits to this file will be overwritten.

Source: technoblest/arpass / docs/security-baseline.md
Mirror generator: scripts/generate-arpass-spec-mirror.mjs
====================================================================
-->

# Arpass — 公開前セキュリティ必須チェックリスト

最終更新: 2026-04-28
担当: Yamaki / Technoblest
ステータス: **GA 公開ブロッカー**（全項目クリア前は公開不可）
対象実装: v4.1 (Passkey 必須 + 秘密鍵 at-rest 暗号化, see docs/crypto-2of3.md)

---

## 0. このドキュメントの位置づけ

Arpass の暗号設計（`docs/crypto-2of3.md`）はすでに 2-of-3 で堅牢ですが、**攻撃者は最も弱いところを狙います**。AES-256 を破るより、GitHub アカウントを phishing するほうが何桁も楽です。

このリストは「暗号の議論を意味あるものにする土台」です。ここを通さず公開すると、`vault-crypto.js` がいかに正しく書かれていても、アカウント乗っ取り 1 件ですべてのユーザーの password が攻撃者に流れ得ます。

各項目は**公開前完了必須**。完了印（`[x]`）を埋めながら進めてください。

---

## 1. 認証・アカウント保護（2FA）

最も投資対効果が高い。30 分で全部終わる。

### 1-1. 関係アカウントすべてに 2FA を強制

- [ ] **GitHub**（Technoblest org）: Settings → Authentication security → Require two-factor authentication for everyone in your organization を **ON**
- [ ] **Cloudflare**（arpass-web Pages + KV + DNS 管理アカウント）: My Profile → Authentication → 2FA を ON、できれば FIDO2 セキュリティキー（YubiKey 等）
- [ ] **Stripe**（決済）: Profile → Two-step authentication → ON
- [ ] **ドメインレジストラ**（arpass.io / arpass.net 管理画面）: TOTP 必須、可能なら FIDO2
- [ ] **メールアカウント**（上記すべてのリセットメール先）: FIDO2 を強く推奨。**ここがルート権限**
- [ ] **NPM**（もし将来公開パッケージを出すなら）: 2FA を auth + publish 両方で ON

### 1-2. バックアップコード・予備認証手段の管理

- [ ] 各サービスのバックアップ用 TOTP コードを**紙に印刷して金庫**に保管（クラウドに置かない）
- [ ] FIDO2 キーは**最低 2 本**用意（紛失保険として 1 本は別物理場所に保管）
- [ ] 緊急用の予備管理者アカウントを設定（CTO 採用後）

### 1-3. パスワード強度

- [ ] 全アカウントで**ユニークかつ 20 文字以上のランダムパスワード**を使用
- [ ] パスワードマネージャー（1Password 等、または将来は Arpass 自身）で管理
- [ ] 同一パスワードの使い回しゼロ

---

## 2. ソースコード保護（GitHub）

### 2-1. Branch Protection（main ブランチ）

GitHub → Repository → Settings → Branches → Add rule で `main` に対して:

- [ ] Require a pull request before merging
- [ ] Require approvals: 最低 1（CTO 採用後は 2 推奨）
- [ ] Dismiss stale pull request approvals when new commits are pushed
- [ ] Require status checks to pass before merging
  - [ ] CI（テスト + lint）の green を必須に
  - [ ] `scripts/test-crypto-2of3.mjs` を CI で必ず走らせる
- [ ] Require branches to be up to date before merging
- [ ] Require conversation resolution before merging
- [ ] Require signed commits（GPG または SSH 署名）
- [ ] Do not allow bypassing the above settings（管理者も例外なし）
- [ ] Allow force pushes: **OFF**
- [ ] Allow deletions: **OFF**

### 2-2. Secret Scanning と Push Protection

- [ ] GitHub → Settings → Code security and analysis
  - [ ] **Secret scanning** を ON
  - [ ] **Push protection** を ON（うっかり push を即座にブロック）
  - [ ] **Dependabot alerts** を ON
  - [ ] **Dependabot security updates** を ON

### 2-3. アクセス権限の最小化

- [ ] Repository の Collaborator は本当に必要な人のみ
- [ ] Org owner は最小（八巻さん + CTO の 2 人想定）
- [ ] 外部 contractor は Outside Collaborator として PR ベースで参加させる（Member 化しない）
- [ ] 退職・契約終了時の access 削除手順を `docs/offboarding.md` に文書化

### 2-4. コミット署名

- [ ] 八巻さん本人の GPG または SSH commit signing キーを GitHub に登録
- [ ] CTO 採用後、その人にも同様に設定させる
- [ ] CI/Bot コミットは専用の signing key を使う

---

## 3. デプロイ・インフラ保護

### 3-1. Cloudflare Pages 設定

- [ ] Cloudflare アカウントで **API Token** をプロジェクト単位に最小権限で発行（root API Key を CI で使わない）
- [ ] Pages プロジェクト `arpass-web` の deploy hook URL を**シークレットスキャン対象**に
- [ ] Production deployment の Preview URL を本番ドメインから完全分離（CSP で `*.pages.dev` を許可しない）
- [ ] **Cloudflare Access** で `/api/admin/*` エンドポイントへのアクセスを IP ホワイトリスト or Zero Trust で保護

### 3-2. HTTP セキュリティヘッダ

`functions/_middleware.js`（または `_headers` ファイル）で全レスポンスに以下を付与:

- [ ] `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`（HSTS）
- [ ] `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' https://arweave.net https://*.arweave.net; frame-ancestors 'none'; form-action 'self'; base-uri 'self'`
- [ ] `X-Frame-Options: DENY`（クリックジャック防御）
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `Referrer-Policy: strict-origin-when-cross-origin`
- [ ] `Permissions-Policy: geolocation=(), microphone=(), camera=(), usb=()`（不要 API を全部切る）
- [ ] `Cross-Origin-Opener-Policy: same-origin`
- [ ] `Cross-Origin-Embedder-Policy: require-corp`（可能なら）

検証: https://securityheaders.com/?q=https://arpass.io で **A 以上**を確認

### 3-3. 同一オリジンポリシーの徹底

- [ ] すべての JS は `arpass.io` から配信（外部 CDN を使わない）
- [ ] `/web/` 内の `<script src="...">` は全て相対パス（`/lib/...`）
- [ ] WebAuthn の RP ID は `arpass.io` で固定

### 3-4. 配信ファイルのハッシュ公開（簡易 reproducible build）

- [ ] CI で各リリース時に主要ファイルの SHA-256 を計算:
  ```
  shasum -a 256 web/lib/vault-crypto.js \
                web/lib/vault-client.js \
                web/lib/client-auth.js \
                web/app.html > release-hashes.txt
  ```
- [ ] `release-hashes.txt` を GitHub Releases に添付
- [ ] 第三者検証スクリプト `scripts/verify-deploy.sh` を提供:
  ```sh
  for f in web/lib/vault-crypto.js web/lib/vault-client.js web/app.html; do
    expected=$(grep " $f$" release-hashes.txt | awk '{print $1}')
    actual=$(curl -s "https://arpass.io/${f#web/}" | shasum -a 256 | awk '{print $1}')
    [ "$expected" = "$actual" ] && echo "OK $f" || echo "MISMATCH $f"
  done
  ```

---

## 4. シークレット管理

### 4-1. リポジトリにシークレットを置かない

- [ ] `.env`, `*.key`, `service-wallet.json` 系は `.gitignore` に登録済みであることを確認
- [ ] 過去のコミット履歴に**誤って push したシークレットがないか** GitHub Secret Scanning の結果を確認
- [ ] 誤 push が発覚したら、該当 secret を**全部 rotate**してから git history を `git filter-repo` で除去
- [ ] Cloudflare Pages の secret は `wrangler pages secret put` でのみ設定（`wrangler.toml` に書かない）

### 4-2. シークレットの rotation 計画

| Secret | 場所 | 推奨 rotation 頻度 |
|---|---|---|
| `STRIPE_SECRET_KEY` | Cloudflare Pages | 90 日（または異常検知時） |
| `STRIPE_WEBHOOK_SECRET` | Cloudflare Pages | 90 日 |
| `ARWEAVE_JWK`（service wallet） | Cloudflare Pages | 紛失疑いあり時のみ（残高移し替えコストが高いため） |
| `ARPASS_ADMIN_TOKEN` | Cloudflare Pages | 30 日、または管理者交代時 |
| `ARPASS_BUNDLER_CALLBACK_TOKEN` | Cloudflare Pages | 90 日 |
| Cloudflare API Token | CI | 90 日 |

- [ ] `docs/secret-rotation.md` に rotation 手順を記載（誰が、いつ、どう新値を投入するか）
- [ ] カレンダーに 90 日後の rotation reminder を登録

### 4-3. service wallet（Arweave）の保護

- [ ] `service-wallet.json` のオフラインバックアップ最低 **3 箇所**（自宅金庫 / 銀行貸金庫 / 信頼できる第三者）
- [ ] 暗号化された USB メモリで保管、各バックアップごとに別パスフレーズ
- [ ] 残高は常時最小化（必要分だけ補充、大量保有しない）
- [ ] バックアップの存在確認を**四半期ごと**に実施

---

## 5. 監視・検知

### 5-1. 外形監視

- [ ] Uptime Robot 等で `/api/status` を 1 分間隔で監視、ダウン時は SMS / メール通知
- [ ] arpass.io トップページの監視
- [ ] `vault-crypto.js` のハッシュを定期的に取得して期待値と比較するスクリプト（10 分ごと、CI または GitHub Actions cron）

### 5-2. Cloudflare 側の監視

- [ ] Workers & Pages → Analytics で異常な request volume を週次レビュー
- [ ] Functions の error rate アラート（5 分間で 1% 超過時通知）
- [ ] WAF（Web Application Firewall）の Bot Fight Mode 有効化
- [ ] Rate limiting を `/api/checkout` と `/api/write` に設定（IP あたり 10 req/min 等）

### 5-3. Stripe 側の監視

- [ ] Stripe → Notifications で以下を有効:
  - [ ] 想定外金額のチャージ（10,001 円以上 = 異常）
  - [ ] 高頻度の決済失敗
  - [ ] Webhook 配信失敗
- [ ] Radar standard rules を有効、CVC mismatch ブロック

### 5-4. Service wallet の監視

- [ ] `service-wallet` の AR 残高アラート（残量 < 0.1 AR で通知）
- [ ] Arweave 上で service wallet からの**想定外の送信**を監視（攻撃者が wallet を奪取した場合の検知）

---

## 6. 暗号レイヤの公開前最終チェック

### 6-1. 実装の整合性

- [ ] `node scripts/test-crypto-2of3.mjs` が**全件 pass**することを CI で常時確認
- [ ] `node scripts/test-identity-protection.mjs` が**全件 pass** (v4.1)
- [ ] `docs/crypto-2of3.md` の仕様と実装の差分が無いか目視確認
- [ ] `web/index.html` の暗号アルゴリズム記述（FAQ 部分）が実装と一致
- [ ] **PBKDF2_ONLY 復活防止 grep test** (CI で実行):
      `grep -rn 'ALG_PBKDF2_ONLY' web/lib/ functions/ scripts/ | grep -v '\(legacy\|decrypt\|comment\)'`
      が空であること。新規 ALG_PBKDF2_ONLY envelope の生成経路が混入していないか継続的に検出
- [ ] **平文 privateKeyJwk 保存防止 grep test** (CI で実行):
      `grep -rn 'privateKeyJwk:' web/lib/client-auth.js | grep -v 'encryptedPrivateKey\|legacy\|comment'`
      が「常に encryptedPrivateKey を経由する」設計を維持していること
- [ ] **registerNewPasskey:false 経路の不在確認**:
      `grep -rn 'registerNewPasskey: false' web/` が空 (= サインアップ時の Passkey 拒否経路が完全に閉じている)

### 6-2. ライブテスト

- [ ] テスト用セキュアドライブで path AB（password + Passkey）の登録・解錠
- [ ] テスト用セキュアドライブで path AC（password + Recovery）の復旧
- [ ] テスト用セキュアドライブで path BC（Passkey + Recovery）の復旧
- [ ] localStorage の inspect で **arpass_client_v1 に encryptedPrivateKey が入っていて、平文 privateKeyJwk フィールドが存在しないこと**を確認 (v4.1)
- [ ] localStorage の inspect で **identity.version === "v4.1"** が記録されていることを確認
- [ ] DevTools Network で**平文パスワード / Recovery Secret / 平文 private JWK が送信されていない**ことを確認
- [ ] DevTools Memory で**Recovery Secret が確認画面後に消えている**ことを heap snapshot で確認
- [ ] DevTools Memory で **lockSession() / lockIdentitySession() 後に in-memory privateKey が GC 対象になる**ことを確認

### 6-3. PRF 非対応環境のブロック確認

- [ ] PRF 非対応ブラウザ（Firefox / Tor / 古い Android 等）で `app.html` を開き、
      **サインアップフォームの作成ボタン・入力欄が両方 disabled** になることを確認
- [ ] サインアップ画面の警告ボックス (#passkey-unavailable) に
      対応端末リスト (iOS17+/Android13+/macOS14+/Win11+) が表示される
- [ ] 万一 dev tools で disable を外して登録を試みても、createVault() が
      throw して半端な Passkey 登録が残らないことを確認
- [ ] エラーメッセージがユーザーに分かりやすいこと

### 6-4. Identity at-rest 保護の検証 (v4.1 新規)

秘密鍵が localStorage で平文ではなく Passkey PRF で保護されていることを確認:

- [ ] 新規サインアップ後、`localStorage.getItem("arpass_client_v1")` の中身に
      **`privateKeyJwk` キーが存在しない**こと、`encryptedPrivateKey` が存在することを確認
- [ ] `encryptedPrivateKey.alg === "id-protect-v1"` が記録されている
- [ ] ブラウザを closed → 開き直して unlock → 同じセキュアドライブが開けることを確認
      (Passkey PRF で encrypted private key が unwrap できる)
- [ ] `lockIdentitySession()` を明示的に呼んだ後、`signedFetch()` がエラーになり、
      再度 Passkey 認証で unlock すると復活することを確認
- [ ] 既存ユーザの v4.0 形式 identity（平文 privateKeyJwk）が unlock 時に
      自動的に v4.1 形式へ migrate されることを確認 (`migratedAt` タイムスタンプが付く)
- [ ] v4.1 移行後、平文 `privateKeyJwk` フィールドが完全消滅していることを確認

### 6-5. ALG_PBKDF2_ONLY envelope 生成停止の確認

- [ ] `encryptVault(セキュアドライブ, password, {})` を prfOutput なしで呼ぶと throw すること
- [ ] 既存の v1 ALG_PBKDF2_ONLY envelope が **読める** こと（legacy decrypt の互換性）
- [ ] 既存の v1 envelope を unlock 後 saveVault しようとすると、v4 へ移行される
      または明確なメッセージで再登録を促されることを確認

### 6-6. vault-id 平文タグの除去 (★★★★★ 公開ブロッカー)

**背景**: v4.1 (2026-04-29) より前は、サーバ側 `functions/api/write.js` が全 Arweave write のタグに `"vault-id": <平文 vault-id>` を強制付与していた。第三者が GraphQL で `tags: { name: "vault-id", value: "<対象 vault-id>" }` を検索すると、そのユーザの**書き込み tx 全件・タイミング・頻度・累計回数**を完全に追跡可能だった。`App-Name` を HMAC で匿名化していた意味が完全に消えていた。

**対応 (この PR で実施済み)**:

- [x] `functions/api/write.js`: `"vault-id": vaultId` 行を削除 (2026-04-29)
- [x] `web/lib/vault-client.js`: GraphQL クエリの検索条件から `VAULT_ID_TAG` を撤去、`APP_NAME_TAG` (HMAC of recovery material, per-user anonymized) 単独で検索する形に変更
- [x] `VAULT_ID_TAG` 定数自体は legacy reference のため deprecated コメント付きで残す (古い envelope に付いているタグを今後 audit する場合の参照名として)

**残課題 — Arweave は immutable のため過去データは削除不可**:

- [ ] **データ漏洩の事実認識と公表**: Arweave 上に既に書き込まれた envelope は永久に `vault-id` 平文タグを持ち続ける。これらは v4.1 リリース以降も誰でも GraphQL で取得可能。GA 公開前にユーザーへ「修正以前の書き込み履歴は GraphQL で観察可能」と明示する必要がある (プライバシーポリシー / リリースノート)
- [ ] **影響範囲の試算**: 修正以前に書き込まれた envelope 数 (= 既存ユーザの書き込み回数 × ユーザ数) を Arweave GraphQL で集計し、影響規模を把握
- [ ] **ユーザーへの推奨**: 既存ユーザーには「セキュリティ上、新しい Recovery Secret に migrate することで vault-id を変更できる (旧 vault-id への過去履歴は残るが、新 vault-id 以降は匿名化される)」と案内
- [ ] **回帰防止 grep test** (CI):
      `grep -rn '"vault-id":\|VAULT_ID_TAG' functions/ web/lib/ | grep -v 'deprecated\|legacy\|comment'`
      が空であること

**Why ★★★★★ (公開ブロッカー判定の根拠)**:

ランディングページの謳い文句:
- 「**No Vault Access**」
- 「**ゼロ知識設計**」
- 「**運営は中身を一切見られません**」

これらは「暗号文の中身は読めない」という限定的な主張だが、**書き込みパターン (timing, frequency, count) という重要なメタデータが世界中から観察可能**な状態は、業界標準のプライバシー期待を裏切る。GA 公開時点でこの状態が残っていると、セキュリティ監査やプレス報道で重大な指摘を受ける。

### 6-7. LEGACY_APP_NAME ('Arpass-Vault') 経路の完全削除 (★★★★ 公開ブロッカー)

**背景**: v4.1 (2026-04-29) より前は、`web/lib/vault-client.js` の `currentAppNameTag()` が以下の挙動だった:

```javascript
function currentAppNameTag() {
  return readMeta()?.appNameTag ?? LEGACY_APP_NAME;  // "Arpass-Vault"
}
```

`readMeta()?.appNameTag` が読めない条件下 (meta 破損、初期化前 write、新規端末で createVault 完了前など) では `"Arpass-Vault"` が App-Name タグに使われ、その書き込みが**全 Arpass ユーザ共通のグローバルタグ**で Arweave に記録される。さらに読み取り検索もこの legacy タグを OR 条件に含めていた:

```javascript
const tagValues = new Set([LEGACY_APP_NAME]);  // "Arpass-Vault"
```

**問題**:

1. **匿名性の崩壊**: バグ2 (vault-id 平文タグ) と同じ系統の問題。第三者が `tags: { name: "App-Name", value: "Arpass-Vault" }` で全 Arpass ユーザの fallback 書き込みを enumerate 可能
2. **検索性能の悪化**: 共通タグでの結果セット肥大
3. **発動経路が静かで気づきにくい**: meta が消える/壊れる/書き込み前の race など、UI には何も警告を出さずに global tag に切り替わる

**対応 (この PR で実施済み)**:

- [x] `LEGACY_APP_NAME` 定数定義を削除
- [x] `currentAppNameTag()` を「meta が無ければ throw」に変更 (silent fallback を完全廃止)
- [x] GraphQL 検索クエリ 2 箇所から `LEGACY_APP_NAME` を含む `tagValues` 初期化を撤去 (per-user HMAC 単独検索)
- [x] 関連 docstring / コメントを v4.1 方針に更新

**Arpass-Vault envelope の存在**:

未リリースのため、本タグで Arweave に記録された envelope は**生産環境では一切存在しない**。よって legacy 互換のための段階的削除は不要 (即削除で問題なし)。

**回帰防止 grep test** (CI):

```
grep -rn 'LEGACY_APP_NAME\|"Arpass-Vault"' web/lib/ functions/ \
  | grep -v 'docstring\|comment\|removed in'
```

が空であること。

**Why ★★★★ (公開ブロッカー判定)**:

バグ2 と同じ「匿名性破壊」系の問題で、修正が**書き込み停止 + 検索クエリ整合**の小さな範囲で完結するため公開ブロッカー級。リリース後に同じ系統のバグを残しておくのは整合性的に望ましくない。バグ2 (★★★★★) より一段下なのは、発動条件が限定的 (meta 不正状態) のため。

---

### 6-8. Recovery Kit (QR / 印刷) の取り扱い (Phase 4.95, 2026-04-30)

**目的**: Recovery Secret の紙保管 UX を破綻させないため、QR 生成と QR スキャンを導入。同時にユーザーが「PDF として保存」してしまう導線を**意図的に作らない**。

**実装方針**:

- **QR ペイロードは Recovery 文字列のみ**。日付・アカウント名等のメタデータは紙の周囲に印刷するが、QR には入れない (写真撮影 + QR スキャナアプリで用途を曝さないため)
- **PDF 生成ライブラリは採用しない** (jsPDF 等)。理由:
  - PDF は Downloads に残り、iCloud Drive / Google Drive で勝手に同期される
  - Spotlight 等の OS 検索インデックス対象、削除しても復元可能
  - マルウェアの収穫対象になるフォルダに置かれる
- 印刷は `window.print()` + `@media print` + 同一ページ内 hidden div 方式。**新規タブを開かない** (タブ履歴・セッション復元の痕跡を残さない)
- 印刷後に DOM の Recovery 部分を `setTimeout` で即座にクリア (RAM 滞留最小化)
- カメラフレームは **getImageData → 即破棄**、ストリームは読み取り完了 / キャンセル時に確実に `track.stop()` する
- カメラ permission は `Permissions-Policy: camera=(self)` でアプリ自身のみ。サードパーティ iframe からは利用不能

**回帰防止 grep test** (CI 候補):

```
# PDF ライブラリの偶発的導入を検知
grep -rn 'jspdf\|pdfmake\|html2pdf\|pdf-lib' web/ scripts/   | grep -v 'security-baseline\.md\|README\.md\|qrcode-generator'
# (空であること)

# QR ペイロードに余計な情報を入れていないか
grep -rn 'generateQrSvg\(' web/   | grep -v 'recoverySecret\|RS1'
# (Recovery 以外の用途で呼んでいる箇所が無いことを確認)
```

**Why ★★★** (運用ブロッカー):

PDF 経由のデジタル流出は事故報告で頻出する経路。導入時点で塞いでおくのが最小コスト。後から「PDF ボタンを外しましょう」と言うのは、既にそれを使っているユーザーへの UX 後退になる。

---

### 6-9. ゲートウェイ問い合わせの並列化と timeout (2026-04-30)

**症状**:
Recovery 復元時に Arweave からエンベロープが取れず、ユーザー体感で 10〜30 秒の無音時間が発生することがあった (本番遭遇)。

**根本原因**:
`vault-client.js` の `findLatestVaultTx` が GraphQL 検索を **逐次** (Turbo → Arweave) かつ **タイムアウト無し**で実装されていた。Turbo の GraphQL がスタールするとブラウザの fetch デフォルト (~30s) まで待ってから Arweave fallback、という挙動になっていた。同 `probeDataReachable` も同形 (sequential `for` ループ + タイムアウト無し)。

これは 2026-04-29 のバグ #1 修正 (`queryTxStatusGraphQL` の並列化) と同じ形の問題が、別の関数で残っていたもの。

**修正** (`web/lib/vault-client.js`):
- `findLatestVaultTx`: `Promise.all([Turbo, Arweave])` で並列化、各 5s timeout (`AbortController`)、Turbo 結果優先。
- `probeDataReachable`: 並列 race、各 4s timeout、最初に成功した gateway を返す。

**回帰防止**:
両 gateway を扱うコードパスは「並列 + 個別 timeout」が invariant。新規実装時にこれを守る。検出 grep:

```
# Sequential gateway pattern (TURBO → ARWEAVE) of concern
grep -nE 'queryGateway\(TURBO_GATEWAY\)' web/lib/ \
  | grep -v 'Promise\.all'
```

(`Promise.all` を介さない逐次 await が無いか確認)

**Why ★★★** (運用ブロッカー):
ユーザー体感の致命的な詰まりを起こす一方、データ自体は失われない。次のアップデートで確実に塞ぐ価値があるが、機密性破壊ではないので公開ブロッカーまでではない。

---

### 6-8. Phase 7.0w-AR (2026-05-11): vault-id 廃止 + Arweave タグ完全 anonymization

**背景**: v5 envelope では Arweave write の `App-Name` タグに rMat 派生の HMAC 値を入れることで「ユーザ間 cross-correlation」は防いでいたが、**タグ名 (= 固定文字列 "App-Name")** は全 Arpass write 共通だった。第三者が GraphQL で `tags.name == "App-Name"` を条件にすれば、(値は user 単位で異なるとはいえ) **全 Arpass tx の集合を一発で抽出可能**で、Arweave 上の Arpass トラフィック総量や時系列観測ができてしまう状態だった。さらに UI header に vault-id の先頭 8 文字を表示する弱さもあった (= 公開された情報が暗号鍵の派生に絡んでいないか、設計レビューで疑義)。

**対策** (Phase 7.0w-AR で適用):

1. **vault-id 概念を完全削除** — 旧 `rMat → vault-id (16 byte) → outer_key` の中間鍵を廃し、`outer_key = HKDF-SHA256(rMat, salt="arpass-outer-v6", info="envelope-wrap", L=32)` で直接派生。localStorage は `vaultId` を捨てて `outerKey` (32 byte b64u) に置換。UI 表示も削除。
2. **Arweave タグの name / value 両方を rMat 派生のランダム値に**:
   - name = HKDF(rMat, salt="arpass-app-tag-name-v6", info="app-tag-name::<tier>", L=8) → 11 文字 b64u
   - value = HKDF(rMat, salt="arpass-app-tag-value-v6", info="app-tag-value::<tier>", L=16) → 22 文字 b64u
3. **書込種別 (セキュアドライブ envelope vs record file) は body.kind で server に伝達** — Arweave tag には現れないので、server 側課金分類 (isVaultWrite) は維持しつつ tx tag からは判別不可能に。
4. **Record file の tag name も per-write random** — 旧固定 `Arpass-Rec-*` プレフィックスを廃止し、name/value 両方 8 byte / 16 byte ランダム化。
5. **/api/write が任意 b64url タグ名を 4 個まで forward** — `SAFE_TAG_RE = /^[A-Za-z0-9_-]+$/`, 各 32 文字以内, 予約名 (Content-Type / Unix-Time) は上書き禁止。

**残るリーク経路**:
- on-chain envelope の **サイズ分布** (80/160/240 KiB バケット + 8 KiB jitter) — Arweave 全 tx を nightly enumerate して「サイズ分布が Arpass バケットに一致する tx 群」を Arpass 候補集合として抽出する経路は依然として存在 (ただし誤検知率は高く、個別 user は識別不能)。
- 通信タイミング (Cloudflare ↔ Turbo gateway) — TLS で保護されているが、Cloudflare 内部の侵害があった場合は IP + 時刻が漏れる。

**確認方法**:

```bash
# vault-id / vaultId 識別子の server 側残骸検出
grep -rE '\bvaultId\b' functions/_lib/ functions/api/ | grep -vE '//|^\*'
# (空であること)

# 固定 "App-Name" tag を Arweave に書いていないか
grep -rn '"App-Name"\|'''App-Name'''' web/lib/client-auth.js | grep -v 'comment\|legacy'
# (writeRecordFile の randomTagName 経路と、writeEnvelope の appNameTag.name 経路だけが残るべき)
```

本ドキュメントは `mirror-to-spec` ワークフローにより main への push で **arpass-spec** (公開ミラー) の `docs/security-baseline.md` へ自動同期される（手動同期は不要）。

---

## 6.5 ユーザー側のセキュリティ運用ガイド (公開ドキュメント源泉)

2-of-3 設計上、Master 単独漏洩は無害。脅威は **factor の組み合わせ漏洩**。
ユーザーへの教育文言の source of truth はここ:

### 推奨

- マスターパスワードは Arpass 専用 (他サービスとの使い回し禁止)
- Recovery Secret は紙印刷、物理保管 (金庫等)
- Recovery Secret はマスターパスワードと **別の場所** に保管
- 複数の信頼端末を持つ (Passkey 喪失時の救済路)

### 非推奨 (= 規約上は禁止条項相当)

- Recovery Secret の写真撮影・スクリーンショット (iCloud/Google Photos 自動同期で流出)
- Recovery Secret をクラウドストレージ (Dropbox 等) に平文保存
- マスターパスワードをブラウザ autofill / Keychain に保存
- マスターパスワードを Slack / メール / SMS で他人に送信
- Recovery Secret 紙とマスターパスワードのメモを同じ場所に保管

### 適さない用途 (規約上の disclaimer 対象)

- 国家機密・軍事関連認証情報
- 大規模金融機関の管理者権限 (一般個人銀行ログインは想定範囲)
- 医療機関の患者記録アクセス権 (HIPAA 領域)
- 暗号通貨ウォレットの seed phrase (専用 HW ウォレット推奨)

### app/help/terms との整合

- web/app.html: Master 使い回し検出時の confirm モーダル + Recovery 表示画面の警告強化
- web/help.html: §「🛡️ セキュリティ運用ガイド」
- web/terms.html: 第 5 条 (利用者の責任) + 第 7 条 (想定外用途)
- docs/privacy-policy-and-tos.docx: 該当条項に反映

### 漏洩疑い時の対応指針

| 漏洩疑い | 推奨アクション |
|---|---|
| Master のみ | 設定 → マスターパスワード変更 |
| Recovery のみ | 設定 → セキュリティ事故対応 → Recovery 再発行 (Case A) |
| 両方 / 端末ごと盗難 | 設定 → セキュリティ事故対応 → Recovery 再発行 (Case B、MEK 一新) |

---

## 7. ドキュメント・透明性

### 7-1. SECURITY.md

リポジトリルートに `SECURITY.md` を作成し、以下を記載:

- [ ] 報告窓口（security@arpass.io or HackerOne 等）
- [ ] 暗号資産系を除く脆弱性報酬制度の有無と金額レンジ
- [ ] 報告から修正までの SLA（例: 重大度 High は 7 日以内）
- [ ] PGP 公開鍵（暗号化された脆弱性報告を受け取る用）
- [ ] サポート対象のブラウザ・プラットフォーム
- [ ] サポート対象の Arpass バージョン

### 7-2. プライバシーポリシーと整合

- [ ] `Arpass_プライバシーポリシー_利用規約.docx` を読み返し、新実装（vault-id が Recovery 由来、署名鍵 envelope 内、localStorage は vault-id のみ）と矛盾しないか確認
- [ ] 「データを保存しないもの」一覧に **Recovery Secret** を明記（最重要）
- [ ] 「データを永久に削除できない」旨を明記（Arweave の本質的性質）

### 7-3. インシデント対応 Runbook

`docs/incident-response.md` を作成し、以下のシナリオごとに対応手順を:

- [ ] **シナリオ A**: GitHub アカウント乗っ取り疑い → repo lock、secret 全 rotate、commit 履歴監査
- [ ] **シナリオ B**: Cloudflare アカウント乗っ取り疑い → API Token 全 revoke、Pages secret 全 rotate、deployment 履歴確認
- [ ] **シナリオ C**: `vault-crypto.js` の改竄が検知 → 即時 rollback、ユーザー全員に通知、原因調査
- [ ] **シナリオ D**: service wallet からの不審な送信 → 残高即時退避（新 wallet へ）、bundler 停止
- [ ] **シナリオ E**: Stripe webhook secret 漏洩疑い → secret rotation、過去の credit 不正付与監査
- [ ] **シナリオ F**: 法執行機関からのデータ開示要求 → 弁護士確認、保有データ（vault-id・publicKey・残高のみ）の説明、ユーザー通知の検討

各シナリオに「気づき方」「初動 30 分」「24 時間内」「事後対応」を記載

---

## 8. 外部評価 — 段階別 Tier 制 (2026-04-29 改訂)

**方針変更の背景**: 「第三者監査契約 = GA 公開前必須」という旧方針は、初期スタートアップにとっては過剰要求 ($30k-80k のコスト、数ヶ月のリードタイム)。代わりに、**段階的に外部評価の水準を引き上げる Tier 制** に再構成。

ランディング FAQ で「監査済み」と書けるのは Tier 2 完了後 (虚偽広告リスク)。Tier 1 完了時点では「**Best effort security with full transparency, automated tooling, and bug bounty**」と表現する (1Password / Bitwarden の旧方針と同じ立ち位置)。

### Tier 1: 自動ツール + Bug Bounty + Transparency (★★★★★ GA 公開前必須、$0)

人間監査の代わりに、**自動ツールによる継続的検証 + 透明性 + Bug Bounty** で Best effort を担保する。全部 \$0 で公開当日までに揃えられる。

- [x] **GitHub Dependabot** 有効化 (`.github/dependabot.yml`) — 依存関係の脆弱性を週次自動検知 + PR 自動作成
- [x] **Semgrep** workflow 追加 (`.github/workflows/semgrep.yml`) — オープンソース静的解析、`p/security-audit` + `p/owasp-top-ten` ルールセットで JS/TS の脆弱性検出 (XSS/SSRF/insecure crypto/hardcoded secrets/path traversal 等)。private repo + Team plan で追加コストなし。 (CodeQL の代替: Code Scanning は GitHub Advanced Security が別課金 +$30/user/月 のため Semgrep に置き換え)
- [x] **回帰防止 grep test** (`scripts/lint-security.sh` + `.github/workflows/regression-grep.yml`) — v4.1 invariant の自動検査
- [x] **HTTP セキュリティヘッダ A+** (`web/_headers`) — SSL Labs / Mozilla Observatory / SecurityHeaders.com で A+ を狙う構成
- [x] **`SECURITY.md`** — 報告窓口、SLA、スコープ、Safe harbor、PGP 鍵を明記
- [ ] **HackerOne Bug Bounty プログラム** — 無料プランで開始 (重大バグ発見時のみ報奨金 \$100-5,000、典型予算 ~\$5k/年)
- [ ] **`arpass-spec` リポジトリで暗号コード公開** (既に AGPL-3.0 で公開済 — `https://github.com/technoblest/arpass-spec`)
- [ ] **ランディングに評価バッジ表示** — SSL Labs A+, Mozilla Observatory A+, Snyk 0 vulnerabilities, GitHub Actions 緑
- [ ] **Snyk free tier 連携** (オプション) — npm 依存関係の高度なスキャン

完了後の状態: 「業界標準の Best effort + 透明性」を満たす。1Password が監査済みになる以前 (~2018 年頃) のセキュリティ姿勢と同等以上。

### Tier 2: 独立暗号コンサル軽量監査 (★★★ 数千ユーザ達成後、\$5k-\$15k)

ユーザ規模が拡大して bug bounty だけではカバーしきれなくなったタイミングで、**独立した暗号エンジニア** (元 Cure53 / NCC Group メンバー、日本の暗号研究者等) に**スポット監査**を依頼。

- [ ] 独立コンサルタントの選定 (Twitter / LinkedIn / Crypto Coding Standard コミュニティ等で評判確認)
- [ ] 見積取得 (1-2 週間の暗号レイヤレビューで \$5k-\$15k 想定)
- [ ] 監査対象の明確化 (`vault-crypto.js`, `vault-client.js`, `auth.js` の 3 ファイル + `docs/crypto-2of3.md` 仕様書)
- [ ] レポート受領 → 指摘修正 → 再レビュー
- [ ] レポートの公開 (NDA で許可される範囲) または summary を `arpass-spec` に追加

完了後の状態: 「**独立した第三者の目を通している**」と公にアピール可能。ランディング FAQ に「外部レビュー実施済み」と記載可能。

### Tier 3: 中規模専門会社による正式監査 (★★ 数万ユーザ / 法人展開時、\$30k-\$50k)

法人ユーザ獲得や規模拡大により正式な監査レポートが信頼性のシグナルとして必要になったタイミングで、**中規模の専門監査会社**に依頼。

- [ ] 監査会社選定 (Cure53、Aleph Research、Doyensec 等)
- [ ] 見積取得 (\$30k-\$80k、内容は暗号 + クライアント JS + サーバ Functions の総合)
- [ ] 監査スコープの確定 (vault-crypto / vault-client / auth / write / register / migrate + envelope format)
- [ ] レポート受領 → 指摘修正 → 再レビュー → CVE coordination (該当時)
- [ ] **公開レポート** を `arpass.io/audits/` に掲載 (Bitwarden 方式 — 信頼性の最大化)

完了後の状態: 「**監査済み**」と FAQ / ランディング / 営業資料で大胆に主張可能。SOC 2 等の compliance 取得も視野。

### Tier 4 (任意): 大手 + SOC 2 / ISO 27001 (エンタープライズ展開時、\$50k-\$200k+)

エンタープライズ・自治体・金融機関への提供時に求められる正式な compliance 取得段階。

- [ ] Trail of Bits / NCC Group / Doyensec 等の大手による包括監査
- [ ] SOC 2 Type 2 取得 (運用面の監査、年次更新が必要)
- [ ] ISO 27001 取得 (情報セキュリティマネジメント)
- [ ] 場合により ISO 27701 (プライバシー) や FedRAMP 等の業界別認証

ここまで来るのは数年単位の話。現時点では言及だけで十分。

---

## 9. 公開当日の最終確認

公開ボタンを押す直前に以下を**もう一度**:

- [ ] `npx wrangler pages secret list --project-name arpass-web` で 4 種の secret が揃っている
- [ ] Stripe Live mode 切替済み・実カードで小額テスト購入完了（手順書: `docs/stripe-go-live.md`）
- [ ] arpass.io トップページが 200 を返す
- [ ] `securityheaders.com` で A 以上
- [ ] テストアカウントで全 3 path（AB/AC/BC）の動作確認
- [ ] 監視（Uptime Robot 等）が active
- [ ] 緊急時連絡先がチームに共有済み
- [ ] `docs/incident-response.md` のリンクをブックマーク

---

## チェックリスト要約（重みづけ）

| カテゴリ | 項目数 | 公開前完了必須 | 重要度 |
|---|---|---|---|
| 1. 2FA | 8 | 全部 | ★★★★★ |
| 2. GitHub 保護 | 12 | 全部 | ★★★★★ |
| 3. デプロイ・HTTP ヘッダ | 12 | 全部 | ★★★★★ |
| 4. シークレット管理 | 9 | 全部 | ★★★★ |
| 5. 監視・検知 | 11 | 全部 | ★★★★ |
| 6. 暗号レイヤ最終確認 | 11 | 全部 | ★★★★★ |
| 7. ドキュメント | 14 | 全部 | ★★★ |
| 8. 第三者監査 | 4 | GA 後 OK | ★★★ |
| 9. 公開当日チェック | 8 | 必須 | ★★★★★ |

**合計 89 項目**。1〜2 日で大部分は片付きますが、**Branch Protection や 2FA の設定**は今すぐ着手して数時間以内に完了できます。逆に**インシデント対応 Runbook**などは丁寧に書くと半日かかるので、優先順位を考えて進めてください。

完了したら `[x]` でチェックを入れて、最終更新日を更新してください。
