<!--
====================================================================
⚠️ AUTO-GENERATED MIRROR — DO NOT PR HERE

This file is automatically synced from the private arpass repo on every
release. Direct edits to this file will be overwritten.

Source: technoblest/arpass / docs/phase-7.2-B-server-wrap.md
Mirror generator: scripts/generate-arpass-spec-mirror.mjs
====================================================================
-->

# Phase 7.2-B 設計書 v2 — Business mode K1 配布 (per-employee ECIES、ZK 維持)

最終更新: 2026-06-19 (handle 一本化追記) / 2026-05-17
ステータス: **実装完了** — 後述 ECIES/emp_priv 経路は Rust opaque handle 化済

> **現状更新 (2026-06-19)**: 本設計の K1 配布 (per-employee ECIES) は実装完了。 さらに当初 CryptoKey で扱っていた **emp_priv は `EmpPrivKey` opaque handle**、 **ECIES unwrap は `eciesUnwrapToK1Handle` → `K1Key` handle**、 **real_MEK は `K1Key.derive_business_mek_v2(K2 handle)` で WASM 内完結**に移行した。 社員の生 K1 / 生 K2 / emp_priv 秘密スカラが JS heap に出る経路は無い。 鍵を扱う `crypto.subtle.*` はコードレベルで全廃 (CryptoKey 版 `wrapEmpPrivWithK2` / `unwrapEmpPrivWithK2` / `eciesUnwrapForRecipient` は撤去)。 詳細は [rust-crypto-opaque-handle.md](rust-crypto-opaque-handle.md) §「Phase 2-最終」。

担当: Yamaki / Technoblest
関連: [crypto-2of3.md](crypto-2of3.md) (Personal mode の 2-of-3 設計)

---

## 0. v1 (envelope.ws 案) からの差分要約

v1 設計では K1 を `envelope.ws = ECIES(company_pubkey, K1)` として Arweave 上に乗せ、サーバが company privkey を CORP_KEK_MASTER_SECRET wrap で永続保管していました。これには次の致命的欠陥が判明:

| v1 の問題 | v2 での解決 |
|---|---|
| company privkey をサーバが永続保管 = 構造的に server が K1 を復号可能 (ZK 違反) | サーバは privkey を一切持たない |
| privkey 紛失 = 全セキュアドライブ永久ロック / privkey 漏洩 = 過去全 ws 露呈 | 永続秘密はサーバ側に CORP_KEK_MASTER_SECRET のみ。これは at-rest 防御層で、漏れても enc_K1 の内側 (ECIES) は剥がれない |
| Arweave 上に `ws` が permanent に残り、回収不能 | K1 関連データは Arweave に出さず、サーバ KV のみで管理 (運用上の lifecycle 制御が効く) |
| server keypair rotate = 全 ws を rewrap する必要 | server keypair は transport 専用に短命化、過去データに影響しない |

v2 の核心は **「K1 を社員ごとに別 wrap」「サーバは公開鍵だけ預かる」「Admin の rotation 操作で完結」** の 3 点に集約されます。

---

## 1. 設計目標

### 達成するもの

1. **Zero-knowledge 維持**: サーバプロセスが単独で K1 を復号できる経路を一切持たない。CORP_KEK_MASTER_SECRET を仮にすべて入手しても、ECIES wrap の内側は剥がせない。
2. **Admin 主権**: 会社オーナーが K1 のオーナー。社員加入承認・退社時無効化・rotation すべて Admin が能動的に実行する。
3. **退社後の遮断**: 退職社員は (a) サーバ access 不可 (member check で拒否)、(b) 端末に enc_K1 を保存していても新 K1 配布の対象外、の 2 重で遮断。
4. **機種追加の自然動作**: 社員が新端末で Recovery を入力すれば、同じ keypair が deterministic 派生され、サーバの enc_K1[i] をそのまま復号できる。サーバ側操作不要。
5. **Personal mode との共存**: Personal mode (K1 なし) は v5 設計 (crypto-2of3.md) を維持。Business mode のみ K1 層を追加。

### 達成しないもの (= 妥協点)

- **Admin オフライン中の即座加入**: 新規社員が join → サーバへ pubkey 登録 → ただし enc_K1 配布は Admin の次回ログイン待ち。Admin が 1 週間ログインしなければ 1 週間使えない。これは「Admin 主権」と引き換えのトレードオフ。
- **Admin のセキュアドライブ破壊からの会社復旧**: Admin が Master + Recovery を両方失うと、K1 平文へのアクセス経路が消える = 会社全体のセキュアドライブが永久復号不能になる。Emergency Export (Phase 7.2-B α で実装済) で別出力をオプトインで用意。

---

## 2. 用語

| 略号 | 名称 | 役割 | 保存場所 |
|---|---|---|---|
| **K1** | 会社共通 wrap 鍵 | 社員セキュアドライブの real_MEK の片方の材料 | Admin セキュアドライブに平文、各社員レコードに ECIES wrap |
| **K2** | 社員個別 wrap 鍵 | 社員セキュアドライブの real_MEK のもう片方の材料 | 各社員セキュアドライブの `w.a/b/c` (factor で開ける) |
| **real_MEK** | 実際のセキュアドライブ暗号化鍵 | body / records を AES-GCM で暗号化 | メモリ上のみ (CryptoKey) |
| **emp_keypair** | 社員 ECDH P-256 keypair (static) | K1 配布の受信側 | privkey は **セキュアドライブ内に K2 wrap で保存** (`w_emp` field)、pubkey はサーバ登録 + セキュアドライブ内 cache |
| **eph_keypair** | Admin が使う ephemeral ECDH keypair | K1 配布の送信側 | wrap 1 回ごとに新規生成、終了後破棄 |
| **enc_K1[i]** | 社員 i 用 K1 wrap blob | `{ eph_pub, iv, ciphertext }` | サーバ KV のみ |
| **signing keypair** | ECDSA P-256 | Arpass API リクエスト署名、監査ログ署名、ユーザー識別 (pkHash) | **K2 から HKDF 派生**、毎 unlock 再導出、メモリ上のみ |
| **CORP_KEK_MASTER_SECRET** | サーバ KV の at-rest 鍵 | enc_K1 を KV に書く際の rewrap 用 | Cloudflare Secret (env) |
| **company_id** | 会社識別子 | 16 文字 base32 | サーバ KV のみ |

鍵の関係式:
```
real_MEK         = HKDF(K1 ‖ K2, salt="arpass-business-mek-v2",  info="real-mek")
signing keypair  = HKDF(K2,        salt="arpass-signing-v2",      info="ecdsa-p256")  ← K1 非依存
emp_keypair      = generateKey(ECDH-P256) at signup, stored in w_emp = AES(K2, emp_priv)
pkHash           = SHA-256(signing_pubkey)
```

**重要**: signing key は K2 由来であり K1 を必要としない。これにより「K1 取得 API 呼ぶには signing key 要、signing key 派生に K1 要」の鶏卵問題を回避し、また K1 rotation の影響を受けない。

---

## 3. 鍵階層と暗号フロー

### 3.1 全体像

```
  ┌─────────────────────────────────────────────────────────────┐
  │  Admin セキュアドライブ (Arweave + 2-of-3 factor)                      │
  │  ├── K1 (平文、ランダム 32 byte)                              │
  │  ├── Admin's own real_MEK = HKDF(K1, K2_admin)               │
  │  │   └── body / records 暗号化                                │
  │  └── pendingEmployeePubkeys[] (= 未配布リスト)                │
  └─────────────────────────────────────────────────────────────┘
                          │
                          │ Admin が「配布」ボタン押下
                          │ (per-employee ephemeral ECDH wrap)
                          ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  サーバ KV (Cloudflare)                                       │
  │  corp:<cid>                  → 会社メタ (admin pkHash 等)     │
  │  corp:<cid>:member:<pkH>     → { emp_pubkey, status, ... }   │
  │  corpK1:<cid>:<pkH>          → AES(CORP_KEK, enc_K1[i])       │
  │  ※ server は K1 平文を一切保持しない                          │
  └─────────────────────────────────────────────────────────────┘
                          │
                          │ 社員 unlock 時
                          │ GET /api/corp/unwrap-k1 (member check)
                          ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  社員 client (unlock 順序)                                    │
  │                                                              │
  │  [1] Arweave からセキュアドライブ envelope fetch (認証不要、公開 read)  │
  │  [2] w.{a|b|c} を 2-of-3 factor KEK で開く → K2 取得           │
  │  [3] signing keypair = HKDF(K2, "arpass-signing-v2")          │
  │      emp_priv = AES-GCM-decrypt(K2, w_emp)                    │
  │      ↑ ここまで K1 不要、K2 のみで完結                         │
  │  [4] API 呼び出し可能 (signing key で署名)                     │
  │      GET /api/corp/unwrap-k1 → enc_K1[i] 取得                 │
  │      → emp_priv で ECIES_decrypt → K1                         │
  │  [5] real_MEK = HKDF(K1, K2)  ← non-extractable CryptoKey     │
  │  [6] body / records を real_MEK で復号                         │
  └─────────────────────────────────────────────────────────────┘
```

### 3.2 emp_keypair の生成とセキュアドライブ内保存

**設計判断**: emp_keypair は signup 時にランダム生成し、セキュアドライブ内に K2 wrap で保存する (案 ① 採用)。Recovery から deterministic 派生する案 (案 ②) は採用しない。理由:

- 標準 WebCrypto API でランダム生成できる (P-256 scalar の手動 deterministic 化は実装ミスリスクあり)
- **Recovery 変更時 (changeRecovery) に emp_keypair が変わらない** → Admin への再 wrap 依頼が不要
- **localStorage 一切不使用**を維持 (セキュアドライブは Arweave 上に暗号化保存)
- 機種追加でもセキュアドライブを fetch して開けば emp_priv が出るので問題なし

```js
// signup 時の生成
async function generateEmpKeypair() {
  return await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,                       // ← signup 時のみ extractable (wrap 保存のため)
    ["deriveKey"]
  );
  // 生成直後に emp_priv を raw export → AES(K2, emp_priv) → w_emp としてセキュアドライブへ
  // export 後 extractable=false 版を再 import して session に保持
}

// unlock 時の取得
async function unwrapEmpPrivFromVault(k2Key, w_emp) {
  const empPrivRaw = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64uDecode(w_emp.i) },
    k2Key,
    b64uDecode(w_emp.c)
  );
  return await crypto.subtle.importKey(
    "pkcs8", empPrivRaw,
    { name: "ECDH", namedCurve: "P-256" },
    false,                      // ← non-extractable で session 保持
    ["deriveKey"]
  );
}
```

### 3.2.1 signing keypair の派生 (K2 由来)

```js
// 2-of-3 unlock で K2 を取得した直後に呼ぶ
async function deriveSigningKeypair(k2Key) {
  const seed = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new TextEncoder().encode("arpass-signing-v2"),
      info: new TextEncoder().encode("ecdsa-p256-seed"),
    },
    k2Key, 256
  );
  // P-256 scalar として import → ECDSA keypair (= Phase 7.3-A.4 で non-extractable JWK 化)
  return await importP256SigningKeypair(seed);  // { privKey, pubKey }
}
```

K1 を必要としないので、K1 取得 API を呼ぶ前に署名鍵が用意できる。K1 rotation の影響を受けない (= 監査ログの連続性が保たれる)。Personal mode との互換性も維持 (Personal は K2 ≡ MEK)。

### 3.3 ECIES wrap (Admin → 社員 i)

```js
async function eciesWrap(empPubKey, k1RawBytes) {
  // ephemeral keypair (毎回新規)
  const eph = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false, ["deriveKey"]
  );

  // shared secret から AES-GCM key 派生
  const aesKey = await crypto.subtle.deriveKey(
    { name: "ECDH", public: empPubKey },
    eph.privateKey,
    { name: "AES-GCM", length: 256 },
    false, ["encrypt"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, aesKey, k1RawBytes
  );

  // ephemeral pubkey を export (受信側に同梱)
  const eph_pub_jwk = await crypto.subtle.exportKey("jwk", eph.publicKey);

  return { eph_pub: eph_pub_jwk, iv: b64u(iv), ct: b64u(ct) };
  // ※ eph.privateKey はこの関数を抜けたら GC で消える
}
```

### 3.4 ECIES unwrap (社員 i)

```js
async function eciesUnwrap(empPrivKey, encK1) {
  const ephPub = await crypto.subtle.importKey(
    "jwk", encK1.eph_pub,
    { name: "ECDH", namedCurve: "P-256" }, false, []
  );

  const aesKey = await crypto.subtle.deriveKey(
    { name: "ECDH", public: ephPub },
    empPrivKey,
    { name: "AES-GCM", length: 256 },
    false, ["decrypt"]
  );

  const k1Raw = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64uDecode(encK1.iv) },
    aesKey, b64uDecode(encK1.ct)
  );

  // すぐに K1 を CryptoKey 化、 raw は使い回さない
  return crypto.subtle.importKey(
    "raw", k1Raw, { name: "HKDF" }, false, ["deriveKey"]
  );
}
```

---

## 4. KV スキーマ

### 4.1 既存 (v1 から維持)

```
corp:<cid>                       → { companyId, adminPkHash, walletAddress,
                                       maxSlots, currentSlots, status,
                                       createdAt, updatedAt }
corpSlot:<cid>:<slotId>          → { code, status, usedByPkHash, ... }
corpCode:<code>                  → { companyId, slotId } (使い切り)
corpMember:<pkHash>              → { companyId, slotId } (現所属のみ)
```

### 4.2 新規 (v2 で追加)

```
corp:<cid>:member:<pkHash>       → {
                                     emp_pubkey: <JWK>,   // ECDH P-256 pub (社員ごとに違う、ランダム生成)
                                     joinedAt: <iso>,
                                     status: "active" | "pending_k1" | "revoked"
                                   }

corpK1:<cid>:<pkHash>            → AES_GCM(
                                     CORP_KEK_MASTER_SECRET,
                                     JSON.stringify({ eph_pub, iv, ct, k1Version }),
                                     iv = random
                                   )
                                   // 中身: ECIES(emp_pubkey, K1) blob
                                   // server は CORP_KEK 層は剥がせる
                                   // が、内側 ECIES は剥がせない

corp:<cid>:k1Version             → { current: <int>, deprecated: [<int>, ...],
                                     rotatedAt: <iso> }
                                   // K1 値 rotate で incr
                                   // deprecated は 14 日 (TTL) で削除
```

### 4.3 廃止 (v1 から削除)

```
corp:<cid>:keypair               → 削除  // company privkey 保管廃止
corp:<cid>:pubkey                → 削除  // server-side 単一 pubkey 廃止
```

---

## 5. 各操作のフロー

### 5.1 会社作成 (admin)

```
[admin client]
  1. Admin が "Business mode で開設" を選択
  2. Master + Recovery + Passkey で create セキュアドライブ (= Personal mode 同じ手順)
     → K2_admin が生成され w.a/b/c に保存
  3. K1 をランダム生成 (32 byte)
  4. Admin の emp_keypair をランダム生成 (= Admin 自身も Business mode 社員と同じ構造)
     emp_priv は w_emp_admin = AES(K2_admin, emp_priv) としてセキュアドライブに保存
  5. real_MEK = HKDF(K1, K2_admin) を派生
  6. body は real_MEK で暗号化
  7. K1 を Admin セキュアドライブの metadata field に書く (= K1 のオーナーは Admin)
  8. signing keypair = HKDF(K2_admin, "arpass-signing-v2") を派生
  9. envelope を Arweave に upload

[server]
  POST /api/corp/create
    → corp:<cid> を作成 (adminPkHash 記録)
    → corp:<cid>:k1Version = { current: 1, deprecated: [] }
    → corp:<cid>:member:<adminPkH> = { emp_pubkey: admin_emp_pub, status: "active" }
    → corpK1:<cid>:<adminPkH> = AES(CORP_KEK, ECIES(admin_emp_pub, K1))
       ※ Admin 自身も per-employee enc_K1 を持つ (= 統一 API、設計シンプル化)
```

注: Admin も「社員と同じ構造」で K1 を取得する。Admin 専用の特別経路は持たない。これにより API も flow も統一できる。Admin と通常社員の違いは「K1 平文をセキュアドライブの metadata に持っているか」「admin 操作 API へのアクセス権があるか」のみ。

### 5.2 社員参加 (社員 + admin)

```
[社員 client]
  1. 招待コード入力 → /api/corp/join (招待 code → slot bind)
  2. Master + Recovery + Passkey で新規セキュアドライブ作成 (Personal mode 同手順)
     → K2_emp が生成され w.a/b/c に保存
  3. emp_keypair をランダム生成 (WebCrypto generateKey, extractable=true 一時)
  4. emp_priv を export → AES(K2_emp, emp_priv) → w_emp として envelope に格納
     その後 emp_priv を non-extractable で再 import して session 保持
  5. signing keypair = HKDF(K2_emp, "arpass-signing-v2") を派生
  6. envelope を Arweave upload (signing key で API 署名済み)
  7. POST /api/corp/register-pubkey { pubkey: emp_pub_jwk }
      → server: corp:<cid>:member:<pkH> に保存、status: "pending_k1"
  8. GET /api/corp/unwrap-k1 を試みる
      → server: corpK1:<cid>:<pkH> 未設定 → 404 "pending_k1_distribution"
  9. UI に "Admin の承認待ち" を表示 (セキュアドライブは使えない状態)

[admin client, 次回ログイン時]
  1. renderAdminConsole で GET /api/corp/pending-employees
      → ["pkH1", "pkH2", ...] (= status: "pending_k1" のリスト)
  2. 各 pkH について:
      a. GET /api/corp/member-pubkey?pkH=<pkH> → emp_pub_jwk
      b. Admin セキュアドライブ metadata から K1 を取り出し
      c. enc_K1 = eciesWrap(emp_pub, K1)
         ※ eph_keypair は 1 件ごとに新規生成 (forward secrecy)
      d. POST /api/corp/upload-enc-k1 { pkHash: pkH, encK1, k1Version: 1 }
        → server: corpK1:<cid>:<pkH> = AES(CORP_KEK, enc_K1) 保存
        → status を "active" に変更
  3. 完了したら audit log に "k1_distributed" を push

[社員 client, 次回試行 or admin 配布完了後の自動再試行]
  1. Arweave から envelope fetch (公開 read)
  2. w.{a|b|c} を factor KEK で開く → K2
  3. signing keypair を K2 から派生 (= API 署名可能になる)
  4. w_emp を K2 で復号 → emp_priv (non-extractable CryptoKey)
  5. GET /api/corp/unwrap-k1 (signing key で API 署名)
      → server: CORP_KEK 剥がして { eph_pub, iv, ct, k1Version } を返す
  6. eciesUnwrap(emp_priv, enc_K1) → K1 CryptoKey
  7. real_MEK = HKDF(K1, K2)
  8. セキュアドライブ body 復号 → UI に credentials リスト表示
```

### 5.3 通常の unlock / save

unlock は §5.2 の最後のブロック (1〜8) と同じ。

save は body 暗号化のみ、K1 関連 fields に変更なし:

```
[社員 client, save]
  1. 既存 real_MEK で新 body を暗号化
  2. envelope を作り直し:
       { v, m, s, i, c=new_body_ct, w, w_emp, emp_pub, cid }
       ※ w / w_emp / emp_pub は再利用 (K2 由来、save では変えない)
  3. Arweave / Turbo に upload
  4. POST /api/vault/latest で vlatest 更新
```

K1 自体は envelope に乗らないので、save のたびに ECIES や K1 関連の crypto は走らない (= 高速)。

### 5.4 退社処理

```
[admin client]
  1. 該当社員の pkH を選択 → "退社" 確定
  2. DELETE /api/corp/member { pkHash, reason }
      → server:
         - corpMember:<pkH> を削除
         - corp:<cid>:member:<pkH> の status を "revoked" (記録は残す)
         - corpK1:<cid>:<pkH> を削除 ← K1 配布記録の物理削除
  3. audit log に "member_revoked" push
  4. (任意) IP allowlist から該当社員の IP を削除
  5. (深刻時) K1 値 rotate を実行 (= 5.5 参照)
```

退社後の元社員端末:
- 自分のセキュアドライブは手元の cache で読めるが、新規 save / fetch は server gate で拒否
- enc_K1 を端末に cache していても、それは 「退社時点の K1」だけ
- K1 値 rotate されたら永久に無効

### 5.5 K1 値 rotate (重量級)

実行条件:
- 元社員が K1 平文 + K2 cache を持って退社した疑い
- K1 漏洩疑い
- 定期的な強制 rotation ポリシー (例: 1 年に 1 回)

**変わらないもの**: emp_keypair (= 各社員の static keypair) はそのまま。signing keypair も K2 由来で K1 非依存なので不変。

```
[admin client]
  1. confirm dialog: "全社員に新 K1 を配布、14 日以内にログインしてもらう必要があります"
  2. 新 K1 (k1_new) をランダム生成
  3. Admin 自身の body / records を旧 K1 → 新 K1 で再暗号化:
       real_MEK_old = HKDF(K1_old, K2_admin)
       real_MEK_new = HKDF(K1_new, K2_admin)
       body_new = AES(real_MEK_new, AES_decrypt(real_MEK_old, body_old))
       records も同様
       ※ K2_admin、emp_keypair_admin、signing keypair はすべて不変
  4. 全社員 pubkey 一覧を fetch (corp:<cid>:member:* から)
  5. 各社員 i について:
       enc_K1_new[i] = eciesWrap(emp_pub_i, k1_new)  ← eph_keypair は毎回新規
  6. POST /api/corp/rotate-k1 {
       newVersion: <prev+1>,
       distributions: [{pkH, encK1_new}, ...],
       deprecatedTTLDays: 14
     }
      → server:
         - corp:<cid>:k1Version.current = newVersion
         - corp:<cid>:k1Version.deprecated.push(oldVersion)
         - corpK1:<cid>:<pkH> を全員分 upsert (新 version)
         - 旧 corpK1 は別 key (corpK1Deprecated:<cid>:<v>:<pkH>) に move + 14 日 TTL
  7. Admin 自身のセキュアドライブを新 body で save (Arweave に upload)
  8. audit log に "k1_rotated" push

[各社員, 次回ログイン時]
  1. GET /api/corp/unwrap-k1 → 新 enc_K1[i] が返る (k1Version: newVersion)
  2. ローカル env で前回の k1Version を localStorage hint に持っていて、不一致を検出
  3. 旧 K1 で body 復号する必要があるので:
     - 旧 envelope はローカル cache or Arweave 上に依然存在
     - 旧 enc_K1 を取得: GET /api/corp/unwrap-k1?version=<oldVersion>
       → server: deprecated 期間内なら corpK1Deprecated:<cid>:<v>:<pkH> を返す
  4. 旧 K1 + K2 で real_MEK_old → body 復号
  5. 新 K1 + K2 で real_MEK_new → body 再暗号化
  6. 新 body で save (envelope は変わらず、c フィールドだけ差し替え)
  7. 完了通知を audit log に push
```

14 日の deprecated 期間後:
- 全社員が完了していなければ警告 (admin tab に表示)
- 期限切れ社員の対応:
  - (a) admin が再度 grace period を延長 (= 旧 corpK1Deprecated の TTL を更新)
  - (b) 該当社員は admin に連絡 → admin が手動で「再加入扱い」(= 退社処理 + 招待コード再発行)
- 強制終了は admin の手動操作 (会社事情で残してもいい)

### 5.6 Server keypair rotate (transport 専用)

v2 では server keypair は K1 配布に直接関与しない (= K1 wrap は ephemeral)。
ただし `/api/corp/upload-enc-k1` などの transport で「より強い保護」が欲しい場合に
TLS の上に追加で server pubkey 暗号化を被せる選択肢を残す。これは optional な
"transport hardening" で、運用負荷を考えて Phase 7.2-C 以降で実装。

v2 本体では **transport は TLS のみ**、追加 envelope なし。

### 5.7 CORP_KEK rotate (server 内部)

```
[ops procedure]
  1. 新 CORP_KEK_MASTER_SECRET を生成し、Cloudflare secret として upload (--name CORP_KEK_MASTER_SECRET_NEW)
  2. /api/admin/migrate-corp-kek を叩く (内部 endpoint、admin 認証)
      → 各 corpK1:* を旧 CORP_KEK で復号 → 新 CORP_KEK で再 wrap → 上書き
      → 各 corpK1Deprecated:* も同様
  3. 完了したら旧 CORP_KEK_MASTER_SECRET を削除
  4. SECRET_NAME を MASTER_SECRET にリネーム (= 旧名に戻す)
```

社員側影響なし。Admin 側影響なし。

---

## 6. セキュリティ分析

### 6.1 脅威モデル

| 攻撃者 | できること | できないこと |
|---|---|---|
| Cloudflare 内部スタッフ | KV ダンプ、CORP_KEK にもアクセス可能なら corpK1 の外層を剥がせる | ECIES wrap の内側を剥がせない (emp_priv も Admin の K1 セキュアドライブも無いため) |
| サーバ侵害 (CORP_KEK 含む) | 全社の enc_K1[i] の外層を剥がして blob 取り出し | 同上 |
| 社員 i の端末侵害 (privkey + K2) | 社員 i のセキュアドライブを復号 | 他社員のセキュアドライブは別 keypair / 別 K1 wrap で復号不能 (※同じ K1 を使うが、他社員のセキュアドライブ body は K2 が別なので) |
| 元社員 (退社後) | 退社時に cache した enc_K1[i] + セキュアドライブの w_emp から「退社時点の」 K1 を導出可能 | server が新規リクエストを拒否 (corpK1 削除済) + K1 rotate 後はその K1 が無効 |
| Admin 端末侵害 | K1 平文 + 全社員 pubkey 取得 → K1 distribute は可能 (= 既存機能の悪用) | 社員 K2 が無いので、社員セキュアドライブ body は復号不能 |
| 単一 ephemeral privkey 漏洩 | 該当 wrap 1 個分の K1 値だけ復号可能 | 過去・他 wrap への波及なし (forward secrecy) |

### 6.2 K1 の漏洩経路の網羅

K1 が攻撃者の手に渡る経路をすべて列挙:

1. **Admin セキュアドライブ侵害** → K1 平文取得可能 (Admin の 2-of-3 factor が必要)
2. **既存社員 i の端末侵害** → K2 + w_emp で emp_priv 取得 + enc_K1[i] cache から K1 復号可能
3. **ephemeral privkey 漏洩** → 該当 wrap 1 個分のみ
4. **サーバ単独侵害 (CORP_KEK 含む)** → 不可能 (内側 ECIES wrap が emp_priv 無しでは剥がせない)

各経路に対する対策:
- (1) Admin が Master + Recovery を別管理、Master Password は強強度、Passkey 推奨
- (2) Phase 7.3-A の non-extractable CryptoKey 防御 (= raw key が JS heap に出ない)、社員教育
- (3) 1 wrap 分だけなので影響範囲限定的 (forward secrecy)
- (4) 構造的に成立しない (= zero-knowledge の核心)

### 6.3 K2 単独漏洩への耐性

K2 が漏れても K1 が無ければセキュアドライブは復号不能:
- `real_MEK = HKDF(K1, K2)` で K1 が必須
- 退社社員が手元に K2 cache を持っていても、サーバ access が拒否されれば K1 は取れない
- → 「退社処理 + IP gate + member check」の 3 段ですべて守られる

---

## 7. v1 設計との API 互換性

### 7.1 削除する API

- `GET /api/corp/server-pubkey` — server 永続 pubkey 廃止
- `POST /api/corp/derive-dek` — server-side ECIES 廃止
- `POST /api/corp/admin/upload-keypair` — privkey upload 廃止
- `POST /api/corp/admin/rotate-kek` — 機能を `/rotate-k1` に統合

### 7.2 新規 API

- `POST /api/corp/register-pubkey` — 社員が emp_pubkey を upload
- `GET /api/corp/member-pubkey?pkH=<>` — Admin が社員 pubkey を取得
- `GET /api/corp/pending-employees` — Admin が未配布社員リストを取得
- `POST /api/corp/upload-enc-k1` — Admin が enc_K1 を upload
- `GET /api/corp/unwrap-k1` — 社員が自分用 enc_K1 を取得 (旧名のまま、実装変更)
- `POST /api/corp/rotate-k1` — Admin が K1 値 rotate を実行

### 7.3 変更する API

- `DELETE /api/corp/member` — 退社時に corpK1 削除も実行
- `POST /api/corp/join` — register-pubkey との 2 段 (招待コード使用 + pubkey 登録)

---

## 8. 実装の段階分割

| 段階 | 内容 | task # |
|---|---|---|
| v2.0 | 設計書 (本書) | #95 |
| v2.1 | server: 旧 endpoint 削除 + 新 KV スキーマ | #96 |
| v2.2 | client: emp_keypair 派生 + 新 unwrap path | #97 |
| v2.3 | admin UI: 未配布リスト + 配布フロー | #98 |
| v2.4 | records BEK を real_MEK wrap に戻す | #99 |
| v2.5 | rotation (K1 値 / CORP_KEK) | #100 |
| v2.6 | i18n キー追加 | (新規 task) |
| v2.7 | E2E 検証 + 既存 α データの migration plan | (Task #57 と統合) |

---

## 9. 移行戦略 (α → v2)

サービス未公開のため α 環境のデータは破棄して構わない:

1. Cloudflare KV を全 prefix scan で削除 (`corp:*`, `corpK1:*`, `corpMember:*` 等)
2. Admin の Arweave 上セキュアドライブは再構築 (新 K1 をランダム生成)
3. テスト社員アカウントは新規招待からやり直し
4. CORP_KEK_MASTER_SECRET は維持 (新 KV エントリの at-rest 防御に再利用)
5. server keypair 関連 secret (もしあれば) は削除

公開後 (= 実ユーザーが居る状態) で同種の refactor が必要になった時の手順は **別 task で migration plan を策定**する。

---

## 10. 開発時 checklist

### emp_keypair / ephemeral keypair

- [ ] eph_keypair が wrap 操作のたびに `crypto.subtle.generateKey` 呼ばれている (= cache されてない)
- [ ] eph_keypair 生成時に `extractable: false` 指定 (privkey が JS 側に raw で出ない)
- [ ] emp_keypair は signup 時にランダム生成 (= Recovery 由来 deterministic 派生はしない)
- [ ] emp_priv は w_emp = AES(K2, emp_priv) としてセキュアドライブに保存される
- [ ] unlock 時に emp_priv を non-extractable で再 import している

### signing keypair

- [ ] signing keypair は K2 由来 HKDF で派生 (= K1 非依存)
- [ ] localStorage に signing privkey が一切書かれていない
- [ ] Phase 7.3-A.4 で non-extractable JWK import に切替

### KV / server

- [ ] enc_K1 blob に `k1Version` フィールドが含まれる
- [ ] server endpoint がすべて IP allowlist + member check を通過する
- [ ] corpK1 の TTL / cleanup ロジックが deprecated period 14 日に従う
- [ ] audit log が 主要操作 (配布 / 退社 / rotation) ですべて push される
- [ ] CORP_KEK_MASTER_SECRET 未設定時に server が起動失敗する (fail-closed)
- [ ] company privkey / server keypair の server-side 永続保管 endpoint がすべて削除されている

### rotation

- [ ] Admin 自身のセキュアドライブが新 K1 で再暗号化された後にのみ rotate を完了とみなす
- [ ] K1 rotation で emp_keypair / signing keypair が **変更されない** ことを確認
- [ ] deprecated 期間中の `?version=<old>` クエリで旧 enc_K1 が取れる
- [ ] 14 日経過後に corpK1Deprecated が自動削除される TTL 設定がある

---

## 11. 用語集 (再掲)

- **ECDH (Elliptic Curve Diffie-Hellman)**: 2 つの楕円曲線鍵ペアから共通秘密値を計算する鍵共有プロトコル。一方の privkey と他方の pubkey で同じ値を導出できる。
- **ECIES (Elliptic Curve Integrated Encryption Scheme)**: ECDH で共通秘密を作り、それを鍵に AES-GCM で暗号化する hybrid 方式。
- **ephemeral keypair**: 1 回の暗号化のために新規生成し、使用後即廃棄する keypair。forward secrecy を提供。
- **static keypair**: 長期間使い回す keypair。受信側 (社員) はこれ。
- **forward secrecy**: 将来 long-term key が漏洩しても過去の通信が解読されない性質。ephemeral key の使い回し禁止で達成。
- **HKDF (HMAC-based Key Derivation Function)**: 任意長の入力鍵材料から指定長の暗号鍵を派生する標準関数。
- **non-extractable key (CryptoKey)**: WebCrypto API で `extractable: false` で生成した key。JavaScript 側に生バイトが取り出せず、`subtle.encrypt/decrypt/deriveKey` 経由でのみ使える。XSS / extension 攻撃への防御。
- **at-rest 暗号化**: 保存状態のデータを暗号化すること。CORP_KEK はサーバ KV の at-rest 防御層。
- **zero-knowledge (ZK)**: サーバが平文データを構造的に取得できないこと。Arpass の根幹原則。

---

End of phase-7.2-B-server-wrap.md v2
