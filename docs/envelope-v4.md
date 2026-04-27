# Envelope v4 仕様書

Arpass の現在の保存フォーマット (`v: 4`) の正確な仕様。各端末がブラウザ上で組み立てて Arweave に書き込み、復号時に再構築する暗号化エンベロープの構造を定義します。

## 概要

`vault` (= ユーザの平文エントリのリスト) は次の手順で **エンベロープ** に変換され、Arweave に保存されます。

```
平文 vault JSON
    │
    ├─► AES-256-GCM(k_vault, iv) ──► 本体 ciphertext (パディングあり)
    │
    └─► k_vault は 3 種の wrap で別ルートで保管:
         • wraps.pr   = AES-GCM(k_vault, KEK(P, R))            1個
         • wraps.pk[] = AES-GCM(k_vault, KEK(P, K_device))     端末ごと
         • wraps.kr[] = AES-GCM(k_vault, KEK(K_device, R))     端末ごと
```

**k_vault** は vault 全体で共通の 32-byte 対称鍵で、**端末ごとに新規生成されません**。端末追加 (`addDevice`) はその端末用の wrap エントリを `wraps.pk[]` と `wraps.kr[]` に追加するだけで、k_vault も `wraps.pr` も既存のまま継承されます。

---

## JSON 構造

実際にネットワークを流れるエンベロープの JSON 形は、Arweave 上のフォレンジック分析を困難にするため **不透明なフィールド名** で書かれています。下表に内部名と JSON 上の単文字キーを併記します。

```json
{
  "v": 4,
  "k": {
    "n": "PBKDF2",
    "i": 600000,
    "s": "<base64url 16-byte salt>"
  },
  "i": "<base64url 12-byte ciphertext IV>",
  "c": "<base64url ciphertext (vault JSON、padded)>",
  "w": {
    "a": { "h": "<credIdHash>", "i": "<wrap IV>", "c": "<wrap ciphertext>" },
    "b": [
      {
        "d": "<deviceId>",
        "h": "<credIdHash>",
        "n": "<device name>",
        "a": "<addedAt ISO8601>",
        "i": "<wrap IV>",
        "c": "<wrap ciphertext>"
      },
      ...
    ],
    "c": [ {同形}, ... ]
  },
  "d": [
    { "d": "<deviceId>", "n": "<device name>", "a": "<addedAt>" },
    ...
  ],
  "migratedFromV3At": "<optional ISO8601>",
  "passwordChangedAt": "<optional ISO8601>"
}
```

| JSON | 内部名 | 内容 |
|---|---|---|
| `v` | `v` | 整数 `4`（現在のフォーマットバージョン） |
| `k` | `kdf` | KDF パラメータブロック |
| `k.n` | `kdf.name` | 文字列 `"PBKDF2"` |
| `k.i` | `kdf.iterations` | 整数（現在 600,000） |
| `k.s` | `kdf.salt` | base64url、16 byte |
| `i` | `iv` | base64url、12 byte（本体 ciphertext の IV） |
| `c` | `ciphertext` | base64url（本体 ciphertext、padded、AES-GCM 認証タグ込み） |
| `w` | `wraps` | wrap 群 |
| `w.a` | `wraps.pr` | Password+Recovery で k_vault を取り出す唯一の wrap |
| `w.b` | `wraps.pk` | 端末ごとの Password+Passkey wrap の配列 |
| `w.c` | `wraps.kr` | 端末ごとの Passkey+Recovery wrap の配列 |
| `d` | `devices` | 端末メタ情報の配列（表示用、復号には使わない） |

各 wrap エントリ:

| JSON | 内部名 | 内容 |
|---|---|---|
| `d` | `deviceId` | 文字列、端末固有のランダム ID |
| `h` | `credIdHash` | base64url、SHA-256(Passkey credentialId) |
| `n` | `name` | 端末表示名（例: "iPhone 15", "オフィス Mac"） |
| `a` | `addedAt` | ISO8601 タイムスタンプ |
| `i` | `iv` | base64url、12 byte（この wrap 個別の IV） |
| `c` | `ct` | base64url（k_vault を KEK で AES-GCM 暗号化したもの） |

---

## 鍵導出

### 1. パスワード材料 `pMat`

```
pMat = PBKDF2-SHA256(password, salt, iterations) → 32 bytes
```

### 2. Passkey 材料 `kMat`

```
kMat = WebAuthn PRF 拡張の出力 → 32 bytes
```

PRF salt は固定の文字列 `"arpass-passkey-prf-v1"` を WebAuthn の `prf.eval.first` に渡して取得します。PRF は端末の認証器に紐付くため、端末ごとに異なる値になります。

### 3. Recovery 材料 `rMat`

```
rMat = HKDF-SHA256(recovery_bytes, info="arpass-recovery-material-v1") → 32 bytes

recovery_bytes = base32-decode(recovery_string_normalized)
```

Recovery 文字列の例: `RS1-ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-4567`（24 base32 文字 = 120 bit エントロピー）

### 4. KEK 導出

```
KEK_pr = HKDF-SHA256(pMat || rMat,        salt, info="arpass-wrap-pr-v1") → 32 bytes
KEK_pk = HKDF-SHA256(pMat || kMat_device, salt, info="arpass-wrap-pk-v1") → 32 bytes
KEK_kr = HKDF-SHA256(kMat_device || rMat, salt, info="arpass-wrap-kr-v1") → 32 bytes
```

`info` ラベルが各 wrap 種別を区別。同じ材料の組み合わせから派生した KEK が、異なるラベルでは互いに無関係になることを保証します。

### 5. wrap

```
wrap = AES-256-GCM(k_vault, KEK_*, random_iv_12byte) → 12-byte iv + 48-byte ciphertext
```

48 byte = 32-byte k_vault + 16-byte GCM authentication tag。

### 6. 本体暗号化

```
padded = pad(JSON.stringify(vault))  // 詳細は次節
ciphertext = AES-256-GCM(padded, k_vault, random_iv_12byte) → padded.length + 16 bytes
```

---

## サイズパディング

vault のエントリ数によって ciphertext のサイズが変動すると、攻撃者が Arweave 上の tx サイズだけで「このユーザは多くのパスワードを持っている / 持っていない」を推測できてしまいます。これを防ぐため、ciphertext は **離散的なサイズバケット** にパディングされます。

```
バケット境界（KiB）：32, 64, 128, 256, 512, 1024 ...
平文サイズ → 一つ上のバケットまで PKCS#7 風パディングで埋める
```

これにより、異なるユーザの vault サイズが同じバケット内なら識別不能になります。

---

## 復号ロジック

復号は提供された因子の組み合わせで分岐します：

```
factors:
  P 提供 + R 提供                  → wraps.pr を unwrap
  P 提供 + K 提供（この端末）       → wraps.pk[] のうち credIdHash 一致するものを unwrap
  K 提供 + R 提供                  → wraps.kr[] のうち credIdHash 一致するものを unwrap
```

すべて結果は **同じ k_vault** で、続く本体 AES-GCM 復号で `padded` を取り出し、PKCS#7 パディングを除去して JSON.parse で vault に戻します。

---

## 端末追加 (`addDevice`)

```
入力: 既存 envelope（base）, k_vault（base から復号済）, 因子 P・R, 新端末の K_new・credentialId

new_KEK_pk = HKDF(P_mat || K_new, salt, "arpass-wrap-pk-v1")
new_KEK_kr = HKDF(K_new || R_mat, salt, "arpass-wrap-kr-v1")

new_wrap_pk = AES-GCM(k_vault, new_KEK_pk, random_iv)
new_wrap_kr = AES-GCM(k_vault, new_KEK_kr, random_iv)

出力 envelope:
  wraps.pr        → base.wraps.pr のまま
  wraps.pk[]      → base.wraps.pk[] + new_wrap_pk
  wraps.kr[]      → base.wraps.kr[] + new_wrap_kr
  devices[]       → base.devices[] + 新端末メタ
  ciphertext, iv  → base のまま (本体は変えない)
```

→ k_vault は変わらず、他端末の wrap は **手付かず**で保持されます。

---

## パスワード変更 (`changePassword`)

```
入力: 既存 envelope, k_vault, 新 password, この端末の K, R

pMat_new   = PBKDF2(new_password, salt, iter)
KEK_pr_new = HKDF(pMat_new || rMat, salt, "arpass-wrap-pr-v1")
KEK_pk_new = HKDF(pMat_new || kMat_this, salt, "arpass-wrap-pk-v1")

出力 envelope:
  wraps.pr        → AES-GCM(k_vault, KEK_pr_new) で再 wrap
  wraps.pk[]      → 自端末分のみ KEK_pk_new で更新、他端末分は ⚠ 削除
  wraps.kr[]      → そのまま (recovery 材料が変わってないので KEK_kr は不変)
```

⚠ **他端末の `wraps.pk` が削除されるのは仕様**です。理由：他端末の K 因子（その端末の Passkey PRF 出力）は、この端末からは取得できないため、新パスワードと組み合わせた KEK_pk を再生成不能だからです。

他端末は P+R 経路（`wraps.pr` で復号可能）と K+R 経路（`wraps.kr` で復号可能）でアクセスできるため、データへのアクセスは失われませんが、各端末で「機種変更などで既存のドライブを復元」フローを再度踏むことで `wraps.pk` を補充できます。

---

## Recovery 再発行 (`reissueRecoverySecret`)

新しい Recovery を生成するということは、新しい identity（vaultId は公開鍵のハッシュ）に **vault 全体を移行** することを意味します。

```
1. 新 Recovery 生成 → 新 identity 派生 → 新 vaultId
2. /api/vault/migrate を旧 identity の署名で呼び、サーバ KV のクレジットを新 vaultId に転送
3. localStorage の identity を新 keypair に切替
4. この端末で新 Passkey を登録
5. 全因子（新 P、新 K、新 R）で v4 envelope を新規 encryptVault → 新 vaultId に書き込み
6. 結果: 新 envelope は **この端末の wrap のみ**を含む
```

他端末は以下のように移行する必要があります:
- 新 Recovery を取得する（直接コピーするか、信頼できるチャネル経由で受け渡し）
- 「機種変更などで既存のドライブを復元」フローで P + 新 R を入力 → addDevice で自端末を追加

---

## 互換性

- **v1**: 単一端末、AES-GCM のみ（読込のみサポート、書込は v3 以降に移行）
- **v2**: 単一端末、2-of-3 (P/K/R) wrap 構造の初版
- **v3**: 多端末対応 (wraps.pk[] と wraps.kr[] が配列に)
- **v4**: パディング追加、不透明フィールド名、`alg` フィールド削除（v=4 のみで algorithm 一意決定）

旧バージョンのエンベロープは復号のみサポートされ、保存（書き込み）時は最新バージョンに自動マイグレーションされます。
