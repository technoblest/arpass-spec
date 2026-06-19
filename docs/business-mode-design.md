<!--
====================================================================
⚠️ AUTO-GENERATED MIRROR — DO NOT PR HERE

This file is automatically synced from the private arpass repo on every
release. Direct edits to this file will be overwritten.

Source: technoblest/arpass / docs/business-mode-design.md
Mirror generator: scripts/generate-arpass-spec-mirror.mjs
====================================================================
-->

# Arpass Business mode 設計 — Phase 7.1

最終更新: 2026-05-13
ステータス: **設計フェーズ** (実装前、レビュー対象)
担当: Yamaki / Technoblest
関連: [crypto-2of3.md](crypto-2of3.md) (v6 暗号レイヤ) / `functions/_lib/corp.js` (Phase 6.3 corp tier 既存実装)

---

## 0. 一言まとめ

Personal mode で確立した 2-of-3 envelope + Recovery in セキュアドライブを **B2B 法人向けに拡張**する。違いは以下 3 点に集約される:

1. **Recovery は社員のセキュアドライブに持たず、admin のセキュアドライブに集約**
2. **Recovery が必要な操作 (機種追加 / Password 変更 / Deep Recovery) は admin 承認制**
3. **Admin は Passkey + Master で「会社用 meta セキュアドライブ」を持つ** (普通の user と仕組みは同じ、中身が違うだけ)

YubiKey 強制は **default OFF**、企業ポリシーで opt-in 可能な hardening として扱う (2026-05-13 reconsider 済)。

---

## 1. Actor

| Actor | 数 | 役割 |
| --- | --- | --- |
| **Admin** | 1〜数名 | 会社代表者 / IT 管理者。社員の Recovery を保管 / 承認権限を持つ |
| **社員 (Employee)** | N 名 | 日常業務で Arpass を使う一般ユーザ |
| **Server (Technoblest)** | — | Cloudflare Pages + KV + Workers。**payload 中継 + policy gate のみ**、復号能力なし |
| **Arweave** | — | 既存と同じ。envelope 永続保存 |

## 2. 信頼境界

- **Admin の Passkey + Master** = 会社全体の root of trust (会社 N 人の Recovery を unwrap できる)
- **社員の Passkey + Master** = 自分のセキュアドライブのみ unlock 可能 (= 他社員には影響しない)
- **Server** = 暗号化された payload を中継するが、復号能力はゼロ知識のまま維持

## 3. データ構造

### 3.1 社員のセキュアドライブ (Personal mode との差分)

```jsonc
{
  "v": 5,
  "mode": "business",         // Personal は省略 or "personal"
  "companyId": "abc12345",    // 帰属会社
  "entries": [...],

  // ❌ encryptedRecovery を持たない (Personal mode との唯一の構造的違い)
}
```

- 帰属会社 ID (`companyId`) がセキュアドライブに焼かれる
- `encryptedRecovery` 不在 = self-serve で Recovery 再印刷不可
- `mode === "business"` フラグが UI 表示の switch (Recovery 表示メニューを隠す等)

### 3.2 Admin のセキュアドライブ (新規)

Admin は普通のユーザと同じセキュアドライブを持つが、中身に「社員管理セクション」が含まれる:

```jsonc
{
  "v": 5,
  "mode": "admin",
  "companyId": "abc12345",
  "companyName": "Acme Corp",

  // Admin 自身の passwords / files (= 個人セキュアドライブと同じ shape)
  "entries": [...],
  "records": [...],

  // 新規: 社員管理セクション
  "employees": [
    {
      "userId": "emp_alice_a1b2",
      "displayName": "Alice",
      "email": "alice@acme.example",
      "addedAt": "2026-05-13T10:00:00Z",
      "status": "active",
      "publicKeyHash": "22-char-b64u",
      "encryptedRecovery": {
        "v": 2,
        "i": "b64u IV",
        "c": "b64u ciphertext"
      },
      "createdAtArweave": "tx-id"
    }
  ],

  "policy": {
    "requireAttestation": "none",
    "passwordMinLength": 12,
    "deviceAddRequiresApproval": true,
    "passwordChangeRequiresApproval": true,
    "auditLogToArweave": false
  },

  "additionalAdmins": [
    {
      "userId": "admin_bob_x9y0",
      "displayName": "Bob",
      "publicKeyHash": "...",
      "addedAt": "..."
    }
  ]
}
```

### 3.3 Server-side KV (新規 / 既存拡張)

```
# 既存 (Phase 6.3 corp tier):
pk:<H(adminPubKey)>       → { balance, plan: "corp", companyId, role: "admin", ... }
pk:<H(employeePubKey)>    → { balance: 0, plan: "corp", companyId, role: "employee", ... }
company:<companyId>       → { name, plan, ownerPkHash, slots, ... }
invite:<code>             → { companyId, role, used, expiresAt, ... } (使い捨て)

# 新規 (Phase 7.1):
relay:<toPkHash>:<id>     → { from, kind, payload (encrypted opaque), createdAt, ttl: 7days }
device-request:<reqId>    → { employeePkHash, newDevicePubKey,
                              kind, status, createdAt, expiresAt }
```

---

## 4. オペレーション一覧 (protocols)

### 4.1 会社 signup (Admin 1 人目)

```
Admin (web):
  1. /signup-corp フォームで「会社名」「自分の display name」「Master」入力
  2. createVault と同じく Recovery 生成 → Passkey 作成
  3. encryptVault するが mode="admin", companyId 新規発行
  4. employees[] は空、policy はデフォルト値、additionalAdmins[] は空
  5. /api/corp/create を叩く: {publicKey, signedRequest, companyName}
     → server: company:<companyId> + pk:<H(adminPubKey)> を作成

Admin:
  6. 通常通り writeEnvelope で admin セキュアドライブを Arweave に書き込み
  7. 画面に Recovery を 1 度表示 → **印刷必須** (admin の Recovery)
     ※ admin のセキュアドライブも business mode なので encryptedRecovery は **持たない**
     ※ admin が紙紛失 = admin の deep recovery シナリオ (§4.10) になる
```

### 4.2 社員 invite

```
Admin の admin console (= UI 上の「社員管理」タブ):
  1. 「社員を招待」ボタン → 招待 link 生成 request
  2. /api/corp/admin/slot-create を叩く: {role: "employee", displayName: "Alice"}
     (既存の Phase 6.3 corp invite を再利用)

Server:
  3. invite:<code> KV エントリ作成 (一回限り、24時間 expiry)
  4. response: invite URL `https://arpass.io/app.html?invite=<code>&corp=<companyId>`

Admin:
  5. URL を Alice にメールや Slack で送る (= server は invite delivery 自動化しない、admin 任せ)
```

### 4.3 社員 signup (招待経由)

```
社員 Alice の端末:
  1. 招待 URL を開く → 「Acme Corp に招待されました」 view
  2. Master Password を 2 度入力 (Personal mode と同じ)
  3. createVault を呼ぶが mode="business", companyId 指定
  4. Passkey 作成 → 通常通り
  5. encryptVault する **が encryptedRecovery を inject しない** (mode==="business" 時)
  6. /api/corp/join を叩く: {invite, publicKey, signedRequest}
     → server: pk:<H(alicePubKey)> = { companyId, role: "employee" } を作成、invite を used に
  7. writeEnvelope で alice セキュアドライブを Arweave に
  8. **Recovery を画面に 1 度だけ表示し、その場で admin に送信する必要あり**

社員 Alice → Admin への Recovery 送付フロー:
  9. Alice の端末で「Recovery を admin に送信」ボタン
 10. Admin の公開鍵 (invite URL に fingerprint 同梱 + Alice が手動確認 TOFU) を取得
 11. Alice の Recovery を admin の公開鍵で ECIES 暗号化
 12. /api/corp/relay で server に push: {from: alicePkHash, to: adminPkHash, kind: "recovery-deposit", payload}
 13. Alice 側で Recovery を破棄

Server:
 14. relay:<adminPkHash>:<id> エントリ作成

Admin (任意のタイミング、最大 7日):
 15. Admin の管理画面 inbox に「Alice からの recovery-deposit」が表示
 16. Admin が自分の Master + Passkey で admin セキュアドライブを unlock
 17. relay payload を ECIES で復号 → Alice の Recovery 取得
 18. encryptRecoveryWithMek(alice_recovery, admin_mek) で再暗号化
 19. admin vault.employees に Alice エントリ追加 (encryptedRecovery 含む)
 20. saveVault → admin セキュアドライブを Arweave に
 21. /api/corp/relay で「relay-consumed: <id>」を送って server から削除依頼
```

### 4.4 社員の日常 unlock (Personal mode と同じ)

```
社員 Alice の端末:
  1. Master + Passkey で Path AB unlock
  2. **Server へのアクセスは一切なし** (= mode="business" でも日常 unlock は同じ)
  3. UI は business mode 時に「Recovery を表示」「Recovery を再発行」を非表示にする
     (= settings.show_rs_btn 等を mode 判定で hide)
```

### 4.5 社員の機種追加 (admin 承認制)

```
Alice の新端末:
  1. 「📲 この端末を追加 (Business)」を選択
  2. Master Password を入力
  3. 新端末で ephemeral keypair 生成 (= ECDH 用)
  4. /api/corp/device-request を叩く:
     {employeePkHash, newDevicePubKey, kind: "device-add", signedByMasterChallenge}

Server:
  5. device-request:<reqId> KV エントリ作成 (24時間 expiry)
  6. admin の relay inbox に通知
  7. Alice 新端末側は polling で承認待機

Admin (任意のタイミング):
  8. 管理画面で「Alice から device-add request あり」を確認
  9. Admin の Master + Passkey で admin セキュアドライブを unlock
 10. admin vault.employees から Alice の encryptedRecovery を MEK で復号
 11. Alice の新端末公開鍵で Recovery を ECIES 暗号化
 12. /api/corp/admin/approve-device で server に push

Server:
 13. device-request status = approved
 14. relay:<alicePkHash>:<id> エントリ作成

Alice 新端末 (polling):
 15. relay 取得 → ECIES 復号で Recovery 取得
 16. Master + Recovery で Path AC unlock
 17. Passkey 作成 → addCredential で新端末用 wrap_pk / wrap_kr 追加
 18. saveVault で Arweave に
 19. Recovery を破棄 (in-memory のみ)
```

### 4.6 社員の Password 変更 (admin 承認制)

§4.5 と同じ flow。違い:
- `kind: "password-change"`
- admin 承認後、Alice が新 Master + Recovery で changePassword 実行
- 他の Alice の端末は古い Master で AB unlock 不可 → 各端末で機種追加 flow 再実行で復旧

### 4.7 社員の Deep Recovery (= 全機種紛失)

§4.5 と同じ flow。違い:
- `kind: "deep-recovery"`
- Alice はゼロから新規 setup 状態
- Master を忘れている場合は復旧不可 (= 設計の限界、明示)

### 4.8 Admin 自身の日常 unlock

Personal mode と完全に同じ。Master + Passkey で Path AB unlock 後、`mode==="admin"` で「管理画面」タブが表示される。

### 4.9 Admin 多人数化 (オプション)

```
1 人 admin だけだと bus factor = 1。複数 admin 追加:

Initial admin:
  1. Settings → 「Admin を追加」
  2. 新 admin の email を入力 → 招待 link (kind: "admin-invite")

新 admin (Bob):
  3. 招待 URL を開く → Master + Recovery (自分の) を生成して signup
  4. createVault で mode="admin", companyId 指定

Initial admin → Bob へのセキュアドライブ共有:
  5. **employees[] の各 encryptedRecovery を Bob の公開鍵で ECIES 再暗号化**
  6. relay で Bob に送信
  7. Bob が受信 → 自分の admin セキュアドライブに save
  8. additionalAdmins[] に追加

以降、any-1-admin で approve 可能
```

### 4.10 Admin の Deep Recovery

最も危険なシナリオ。設計選択肢:

| Option | 説明 | 推奨度 |
| --- | --- | --- |
| A. Multiple admin 必須 | 2 admin いれば片方が deep recovery 援助 | ★★★ |
| B. Admin Recovery 物理金庫 | signup 時に印刷必須、金庫保管 | ★★★ |
| C. オーナーが Master 絶対忘れない | 強い前提 | ★ |
| D. Technoblest による escrow | ゼロ知識崩壊、不採用 | ✗ |

Default 推奨: **A + B 両方** (= 2 admin、admin Recovery は物理金庫)

---

## 5. Server payload relay protocol

### 5.1 Endpoint

| Method | URL | 用途 | 認証 |
| --- | --- | --- | --- |
| POST | /api/corp/relay/send | encrypted payload を post | publicKey 署名 |
| GET | /api/corp/relay/inbox | 自分宛 relay 一覧取得 | publicKey 署名 |
| POST | /api/corp/relay/ack | 受信完了 ack → server 削除 | publicKey 署名 |
| POST | /api/corp/device-request/create | 機種追加 request 作成 | publicKey 署名 |
| GET | /api/corp/device-request/poll | request status polling | publicKey 署名 |
| GET | /api/corp/admin/inbox | admin 用 inbox | admin publicKey 署名 |
| POST | /api/corp/admin/approve | request 承認 + payload push | admin publicKey 署名 |

### 5.2 Payload format

```json
{
  "from": "22-char-b64u-pkHash",
  "to": "22-char-b64u-pkHash",
  "kind": "recovery-deposit | device-add | password-change | deep-recovery | recovery-grant",
  "payload": "<base64url, ECIES-encrypted opaque bytes>",
  "createdAt": "2026-05-13T10:00:00Z",
  "ttl": 604800
}
```

- server は `payload` を一切覗かない
- TTL 経過で自動 GC (Cloudflare KV TTL feature)

### 5.3 ECIES (Elliptic Curve Integrated Encryption Scheme)

```js
// 暗号化 (sender 側)
function eciesEncrypt(recipientPublicKey, plaintext) {
  const ephemeral = generateP256Keypair();
  const shared = ECDH(ephemeral.privateKey, recipientPublicKey);
  const kek = HKDF(shared, "arpass-ecies-v1", 32);
  const iv = randomBytes(12);
  const ct = AES_GCM_encrypt(kek, iv, plaintext);
  return { ephemeralPublicKey: ephemeral.publicKey, iv, ciphertext: ct };
}

// 復号 (recipient 側)
function eciesDecrypt(myPrivateKey, { ephemeralPublicKey, iv, ciphertext }) {
  const shared = ECDH(myPrivateKey, ephemeralPublicKey);
  const kek = HKDF(shared, "arpass-ecies-v1", 32);
  return AES_GCM_decrypt(kek, iv, ciphertext);
}
```

メモ:
- `myPrivateKey` = WebAuthn PRF derived key (= 既存の signingKey と同じ source)
- 既存の noble-curves vendor で P-256 ECDH をサポート済 → 追加依存ゼロ

---

## 6. UI 変更点

### 6.1 mode 判定 helper

```js
function isBusinessMode() { return session.vault?.mode === "business"; }
function isAdminMode()    { return session.vault?.mode === "admin"; }
```

### 6.2 mode === "business" 時に hide

- 設定画面の「🎟 Recovery を表示」ボタン
- 「機種追加 (peer-to-peer QR)」flow
- 「Recovery を再発行」ボタン
- 「Master を変更」(代わりに「変更リクエストを admin に送信」)
- Onboarding の Recovery 説明 (代わりに「会社 admin が Recovery を保管」と説明)

### 6.3 mode === "admin" 時に show

- 「管理画面」タブ (admin console)
  - employees 一覧
  - relay inbox (= 社員からの request 一覧)
  - 招待 link 生成
  - policy 設定
  - additionalAdmins 管理
- 「Admin 用 Recovery を再印刷」ボタン (initial signup 時のみ表示、または他 admin から QR ペアリング)

### 6.4 mode === "business" + 機種追加 flow

```
新端末 fresh signup view:
  - 既存「📲 この端末を追加 (Personal)」ボタン
  - 新規「🏢 会社の Arpass にこの端末を追加 (Business)」ボタン
    → 「Master + 会社の admin 承認」flow
```

### 6.5 mode === "business" + admin への request 経路

```
社員側で Recovery が必要な操作を選んだら:
  1. modal: 「この操作には admin の承認が必要です」
  2. 「admin にリクエストを送る」ボタン
  3. polling (5-30 秒 interval, max 30 分) で admin の承認を待つ
  4. Push notification (将来 mobile app で) または「再読み込み」ボタンで poll
```

---

## 7. Stripe plan との連動

| Plan | features |
| --- | --- |
| **Free** | Personal mode のみ |
| **Standard** ($N/m) | Personal mode のみ、容量上限 |
| **Corp** ($M/m × N seats) | Business mode 有効、admin console、relay TTL 7 日 |
| **Corp Pro** ($M/m × N seats, +20%) | + YubiKey attestation 強制、+ 監査ログ Arweave、+ multi-admin 3 人以上、+ custom invite |
| **Enterprise** (custom) | SLA、custom integrations、SAML SSO |

実装初期は Corp と Corp Pro の境界を曖昧にして、後で differentiate。

---

## 8. YubiKey optional hardening

`policy.requireAttestation` の値で switch:

| 値 | 動作 |
| --- | --- |
| `"none"` (default) | どの WebAuthn authenticator でも OK |
| `"platform"` | platform authenticator のみ (iCloud / Google / Windows Hello) |
| `"hardware"` | hardware-bound のみ (YubiKey 等) |

実装:
- Signup / addCredential 時に WebAuthn attestation を取得 (`attestation: "direct"`)
- server side で attestation 検証 (AAGUID チェック、Yubico root 等を bundle)
- policy が `"hardware"` で attestation が platform だった場合、server は invite / addCredential を 403 で拒否

---

## 9. 実装 phase 分割

| Phase | 内容 | LOC | depends on |
| --- | --- | --- | --- |
| **7.1-A** | 本設計 doc | 0 | — |
| **7.1-B** | セキュアドライブ schema 拡張 (mode / employees / policy) | ~50 | A |
| **7.1-C** | UI mode-switch (Recovery メニュー hide / admin console 雛形) | ~200 | B |
| **7.1-D** | ECIES helpers (vault-crypto.js に encryptForPubkey / decryptFromPubkey) | ~80 | B |
| **7.1-E** | Server relay endpoints (/api/corp/relay/*) | ~150 | D |
| **7.1-F** | Admin console UI (employees + invite + inbox) | ~300 | E, C |
| **7.1-G** | 社員 signup flow with Recovery deposit | ~150 | F |
| **7.1-H** | 社員機種追加 flow (request → approve → relay → unlock) | ~200 | G |
| **7.1-I** | 社員 Password 変更 flow | ~120 | H |
| **7.1-J** | Deep Recovery flow | ~100 | H |
| **7.1-K** | Multi-admin support | ~150 | F |
| **7.1-L** | Optional: WebAuthn attestation 検証 (server) | ~200 | E |
| **7.1-M** | i18n × 15 言語 | ~50 | A-K finalized |
| **7.1-N** | E2E test | ~300 | A-L 全て |
| **7.1-O** | docs / pitch-deck / technical-spec 更新 | ~100 | N |

合計概算: **~2150 LOC + 設計 / テスト時間**

MVP (Free company demo 用) は **A-J**。L / K / N は後段でも可。

---

## 10. オープン Issue

- [ ] Admin の公開鍵を社員が初回どう信頼するか (TOFU vs invite に fingerprint 埋め込み)
- [ ] Master Password 強度の server-side 検証 (= client で zxcvbn 計算してから signup 送信)
- [ ] Audit log Arweave 永続化のコスト (= per 操作 ¥X、 Corp Pro 付加価値)
- [ ] Admin 複数時の approve quorum (any-1 / 2-of-N / 設定可能)
- [ ] Server inbox: polling vs SSE (Cloudflare Workers の SSE 制約)
- [ ] Admin 退職時のセキュアドライブ引き継ぎ flow
- [ ] 社員退職時のセキュアドライブ扱い (encryptedRecovery 破棄、social engineering 防御)
- [ ] 監査要件 (改ざん不能ログ、誰がいつ確認したかの証明)

---

## 11. 次のアクション

設計 doc レビュー後:
1. Phase 7.1-B (セキュアドライブ schema 拡張) から実装開始
2. Phase 7.1-D (ECIES helpers) を並行で進める (web/lib/vault-crypto.js に追加)
3. Phase 7.1-C と 7.1-F の admin console UI は最後にまとめてやる
