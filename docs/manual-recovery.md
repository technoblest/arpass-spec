<!--
====================================================================
⚠️ AUTO-GENERATED MIRROR — DO NOT PR HERE

This file is automatically synced from the private arpass repo on every
release. Direct edits to this file will be overwritten.

Source: technoblest/arpass / docs/manual-recovery.md
Mirror generator: scripts/generate-arpass-spec-mirror.mjs
====================================================================
-->

# Manual Recovery — Arpass サービス停止時の自力復旧手順

## このドキュメントの目的

「**Arpass を運営している会社 (Technoblest) が消滅した**」「Cloudflare に
ban された」「サービスが永久停止した」など、最悪の事態が起きても、
ユーザーが自力でセキュアドライブデータを復号できるよう、技術的な復旧手順を残しておく。

Arpass は **ゼロ知識設計 + AGPL-3.0 OSS + 公開仕様 (arpass-spec)** で
構築されているため、運営側の存在に依存せず復号可能。

## 必要なもの

ユーザーが手元に持っている必要があるもの:

1. **マスターパスワード** (= 頭の中、書留)
2. **リカバリーシークレット** (= 紙、Recovery Kit に印刷したやつ。RS1-XXXX-XXXX-... 形式)
3. (任意) **セキュアドライブの Arweave tx ID** — 自分の最後の保存 tx (= localStorage に
   履歴あり、または直近の tx 詳細モーダルから記録)

これら 3 つのうち最低 **マスターパスワード + リカバリーシークレット** があれば
復号可能。tx ID は後で公開 GraphQL から検索可能 (App-Name タグ経由)。

## 復旧手順（ブラウザ緊急ツール）

Arpass が停止していても、公開ミラー同梱の **緊急復旧ツール
`arpass-emergency-restore.html`** で復号できます。このツールは
**公開 Arweave ゲートウェイを直接読み、Arpass サーバ (`/api/*`) を一切使いません**。
暗号は**公開ミラー同梱の Rust WASM 暗号コア**で実行します（成果物を同梱済みなので、
別途 Rust をビルドする必要はありません）。

### 最短ルート: GitHub Pages で開く（clone 不要）

公開ミラーが GitHub Pages で配信されている場合、ブラウザで次を開くだけで復号できます:

```
https://technoblest.github.io/arpass-spec/pages/arpass-emergency-restore.html
```

- 個人 vault は **マスターパスワード + リカバリーキー** だけ（K1 欄は空でOK）。
- 法人 vault は加えて管理者発行の K1 ファイルが必要。
- ツールが公開 Arweave からあなたの envelope を直接取得し、ブラウザ内で復号（サーバ不要。暗号は公開ミラー同梱の Rust WASM コアで実行）。

この URL が開けない場合（Pages 未稼働・GitHub 消失時）は、下の「clone + ローカル配信」で同じツールを動かせます。

---

### Step 1: 公開仕様を入手

```bash
git clone https://github.com/technoblest/arpass-spec.git
cd arpass-spec
```

（GitHub 自体が消えている場合は arpass-spec のフォーク、または Wayback Machine の
スナップショットからでも入手可能）

### Step 2: ローカルで配信する

緊急ツールは ES module で動くため `file://` では動きません。任意の静的サーバで配信します:

```bash
# 例: Python 標準ライブラリだけで OK
python3 -m http.server 8080
# または: npx serve -p 8080
```

### Step 3: ツールを開く

ブラウザで次を開く:

```
http://localhost:8080/arpass-emergency-restore.html
```

### Step 4: マスターパスワード + リカバリーで復号

画面に **マスターパスワード** と **リカバリーシークレット (RS1-...)** を入力すると、ツールが:

1. リカバリーから App-Name タグを導出し、**公開 Arweave の GraphQL** で自分の最新
   envelope tx を検索します（arweave.net / turbo-gateway.com）。
2. envelope を取得して **ブラウザ内で復号**します（Arpass サーバ不要。暗号は公開ミラー同梱の Rust WASM コアで実行。
   ビルド済み成果物を同梱しているため別途 Rust ビルドは不要）。
3. セキュアドライブを **読み取り専用で表示**し、**JSON / CSV でエクスポート**できます。

アカウント登録も、Arpass への接続も、Rust のビルドも不要です。

## YubiKey 専用 Vault の復旧（ネイティブ CLI）

**YubiKey 専用モード（Master も Recovery Secret も無い）**の Vault は、ブラウザ緊急ツールでは復旧できません。WebAuthn の資格情報は origin（arpass.io）に拘束され、別ドメインからは呼べないためです。

これ用に、**YubiKey に CTAP2 で直接アクセスするネイティブ CLI** を用意しています（`tools/recover-yubikey.py`）。CTAP2 プロトコルは rpId をパラメータで受け取るため、ブラウザの origin 判定を介さず同じ PRF を取り出せます＝arpass.io 消滅後も YubiKey で復旧可能。

```bash
cd tools
pip install -r requirements.txt
python3 recover-yubikey.py
# YubiKey を挿し、点滅したらタッチ
```

公開 Arweave からあなたの Vault を直接取得・復号し、パスワード一覧の表示・`vault.json` 出力・添付ファイル保存まで行います（Arpass サーバ非経由）。詳細は `tools/README-yubikey-recovery.md`。

## 暗号方式の要約 (検証用)

(詳細は arpass-spec/docs/crypto-2of3.md / arpass-spec/docs/envelope-v7-spec.md)

### 鍵階層

```
master password ─Argon2id(64MiB,t=3)─→ pMat ─┐
                                       ├HKDF─→ kek_pr ─AES-GCM→ AC wrap → MEK
recovery ─HKDF→ rMat ──────────────────┘

MEK ─AES-GCM→ envelope.c (暗号化されたセキュアドライブ JSON)
MEK ─HKDF→ vault-id, signing key (ECDSA P-256)
```

### 外側暗号化

```
envelope JSON ─JSON.stringify→ ─AES-GCM(HKDF(vault-id))→ outer-encrypted blob
                                                          ↓
                                                          Arweave に書き込み
```

vault-id を知らない攻撃者は外側 envelope を復号できない。
master + recovery を知らない攻撃者は MEK を取り出せない。

## 復旧の保証

| 保証されること | 保証されないこと |
|---|---|
| **Arweave 上に書かれたセキュアドライブは永久に存在** | サービス UI / 決済機能の継続性 |
| **公開仕様 (arpass-spec) でいつでも復号可能** | 新規アカウント登録 |
| **GitHub のミラーが残れば永続** | 過去の決済履歴の参照 |
| **リカバリー紙 + master が手元にあれば復号可能** | 紛失した認証要素は復活しない (2-of-3 で 2 個失うと不能) |

## 想定外シナリオへの対処

### Q1. Cloudflare に ban された

→セキュアドライブデータは Arweave 上にあり、本ドキュメントの手順で復号可能。
arweave.net を開いて直接 tx ID を取りに行ける。

### Q2. arweave.net が閉鎖された

→ Arweave は分散プロトコル。多数の代替 gateway が存在 (ar.io ネットワーク)。
ar-io.dev / g8way.io / arweave.dev 等いずれからでも tx ID で取得可能。

### Q3. Technoblest が破産した

→ arpass-spec は AGPL-3.0 で公開済。コミュニティフォークが続けば
新しい hosting で同じ仕様の web app が動く。
本ドキュメントの手順は会社の存在と関係なく実行可能。

### Q4. リカバリー紙を紛失した

→ Master + Passkey (端末に残っているなら) で開錠して、設定 →
リカバリー再発行 (Case A) で新規発行可能。

→ 全部失われた場合は **復旧不可能** (ゼロ知識設計の必然)。

### Q5. arpass-spec も GitHub から消えた

→ 過去の Wayback Machine スナップショットを探す。
仕様書は IPFS や Arweave に永続コミットしておく対策が望ましい
(運営側 future task)。

## このドキュメントの保管推奨

- 紙に印刷して安全な場所に保管 (リカバリー紙と同じ場所)
- USB メモリ等のオフラインメディアにコピー
- 信頼する家族 / 弁護士に預ける (Recovery Kit と一緒に)

## 連絡先 (運営継続中の場合)

- 通常の問い合わせ: support@arpass.io
- セキュリティ問題: SECURITY.md 参照
- 緊急事態: admin@arpass.io

(本ドキュメントは「運営が連絡取れない状態」を想定しているので、上記が
機能しなくても復旧できるよう書かれています)

---

**Last updated**: 2026-07-22 (ブラウザ緊急ツール arpass-emergency-restore.html 方式に更新。旧 CLI スクリプト手順は未実装のため差し替え)
**Maintained by**: Technoblest Inc.
**License**: This document is CC0 (Public Domain) — copy and redistribute freely
