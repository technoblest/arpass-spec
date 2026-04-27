# 暗号アルゴリズム選定理由

Arpass で採用したアルゴリズムと、なぜそれを選んだかの記録。

## 全体方針

すべての暗号処理は **ブラウザ標準の Web Crypto API** で実装されます。外部暗号ライブラリ（libsodium 等）には依存しません。理由:

- ブラウザ実装は一般に各ベンダー（Apple / Google / Mozilla）の暗号チームが維持しており、定数時間性・耐サイドチャネル性の検証も継続的
- 外部ライブラリを混ぜると、バージョン管理・脆弱性パッチ追従・ビルド再現性が複雑化
- Web Crypto は 2026 年時点のすべての主要モダンブラウザでサポート

---

## パスワード鍵導出: PBKDF2-SHA256（600,000 iterations）

### なぜ PBKDF2

- **Web Crypto 標準** — 全ブラウザがネイティブ実装
- 確立された規格（NIST SP 800-132）
- 監査・検証が容易

### なぜ Argon2id ではないか

Argon2id（メモリハードな KDF）の方が GPU/ASIC 攻撃に対する耐性が高いとされ、現代のパスワードマネージャ（Bitwarden 等）でも採用が増えています。Arpass で Argon2id を採用しなかった理由:

1. **Web Crypto に組み込まれていない** — ブラウザ実装ではなく WASM 経由の外部ライブラリ（libsodium 等）が必要
2. 外部ライブラリ依存はサプライチェーンリスクとビルド複雑性を増す
3. **2-of-3 設計のおかげで、パスワード単独は Vault 復号の十分条件にならない** — Argon2id の追加防御の必要性が比較的低い
4. 600,000 iteration の PBKDF2-SHA256 は、最新の OWASP 推奨値（2023 年改訂で 600,000）に準拠

### iteration 数

OWASP の 2023 年最新推奨値 (600,000) を採用。これは現代のハイエンド CPU で約 0.5〜1 秒の計算コストとなります。

---

## KEK 合成: HKDF-SHA256

### なぜ HKDF

- 単一の鍵から複数の派生鍵を作るための標準（RFC 5869）
- Web Crypto 標準
- info ラベルで派生先を区別できる → 同じ材料の組み合わせから異なる KEK が無関係に派生できる

### info ラベルで wrap 種別を区別

各 wrap 種別に固有のラベルを付与:

| wrap 種別 | info ラベル |
|---|---|
| Password+Recovery | `arpass-wrap-pr-v1` |
| Password+Passkey | `arpass-wrap-pk-v1` |
| Passkey+Recovery | `arpass-wrap-kr-v1` |

これにより、たとえば pk と kr で同じ Passkey 因子を使っていても、両者の KEK は暗号学的に無関係になります。

---

## 対称暗号: AES-256-GCM

### なぜ AES-GCM

- **Web Crypto 標準**、すべての主要ブラウザがハードウェアアクセラレーション対応（Intel AES-NI、ARM Crypto Extensions）
- 認証付き暗号（AEAD）— ciphertext の改竄を検出
- NIST 標準

### なぜ XChaCha20-Poly1305 ではないか

XChaCha20-Poly1305 は IV が長く（24 byte）、誕生日攻撃の上限が高いため、IV をランダム生成する設計には理論上有利です。しかし:

- **Web Crypto に組み込まれていない**（2026 年時点）
- AES-GCM の 12-byte ランダム IV でも、同じ鍵での 2^32 メッセージまで衝突確率を 2^-32 以下に保てる — 通常の vault 利用ペースでは数億年の余裕

→ 標準実装が利用可能で、実用上のセキュリティ余裕も十分な AES-GCM を採用。

---

## サイズパディング: 離散バケット

### なぜパディングが必要か

Arweave 上の transaction サイズは公開情報です。暗号化された ciphertext のサイズ＝平文サイズと相関するため、**「どのユーザがどれだけパスワードを溜めているか」が公開ストレージから推測可能** になります。

### バケット方式

```
バケット境界（KiB）：32, 64, 128, 256, 512, 1024 ...
平文サイズ → 一つ上のバケットまで PKCS#7 風パディングで埋める
```

ほとんどのユーザの vault はサイズ的に同じバケット（128 KiB 程度）に収まるため、tx サイズだけでは vault のエントリ数を推測できなくなります。

---

## 識別子: ECDSA P-256 + SHA-256

### vaultId

```
vaultId = base64url(SHA-256(canonical_jwk_public_key))
```

vault id は **Recovery Secret から決定論的に派生したキーペアの公開鍵のハッシュ**。Recovery Secret を持つ者なら、新しい端末でも同じ vault id を導出可能。

### API 認証

各リクエストは ECDSA P-256（SHA-256）署名で本人確認:

```
X-Signature = base64url(ECDSA(privKey, "<unix_time>.<raw_body>"))
```

タイムスタンプ ±5 分以内、署名検証成功で認証通過。サーバは公開鍵だけを KV に保管しており、秘密鍵は端末から外に出ません。

---

## Recovery Secret: 192-bit エントロピー

```
Recovery 文字列の例: RS1-ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-4567

  - 接頭辞 "RS1-" (バージョン識別)
  - 8 グループ × 4 文字 = 32 文字 base32
  - 文字セット: ABCDEFGHIJKLMNPQRSTUVWXYZ23456789 (混同しやすい O, 0, 1, I を除外)
  - エントロピー: log2(32^32) ≈ 160 bit
```

総当たり攻撃に対する強度: 2^160 ≈ 1.5 × 10^48 通り。物理的に達成不能。

---

## 端末認証: WebAuthn PRF 拡張

### PRF とは

WebAuthn の Pseudo-Random Function 拡張は、認証器（iCloud Keychain、Google Password Manager、Windows Hello、YubiKey 等）が credential ID + RP-supplied salt から決定論的に 32-byte の出力を生成する機能です。

```
PRF_output = authenticator.PRF(credential_id, salt = "arpass-passkey-prf-v1")
```

これにより:
- 認証器の中の秘密鍵（外に出ない）に依存する材料を派生できる
- Passkey が同期される iCloud / Google アカウント間で同じ PRF が得られる
- 認証器を物理的に持っている者だけが PRF にアクセスできる

### PRF をなぜ使うか

通常の Passkey 認証は「公開鍵で署名検証」しかできず、暗号鍵を引き出すことはできません。PRF は Passkey から「鍵材料」を取り出す唯一の標準的な方法であり、Arpass の 2-of-3 設計の "K 因子" を実装するために必須です。

### PRF 非対応認証器への対応

PRF 拡張未対応の認証器（古い Android 等）では `prf.enabled` が false で返ります。この場合、Passkey 経由の wrap (`wraps.pk`、`wraps.kr`) は作成できず、ユーザは Password+Recovery (P+R) だけで vault にアクセスする形になります。
