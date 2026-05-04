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

## バケット最小値 120 KiB の選定根拠 (Phase 5.2)

旧バケット値 `[4 KiB, 16 KiB, ...]` は v5 cutover 直後 (Phase 5.0〜5.1) に存在したが、以下 2 つの問題を同時に抱えていた重大バグだった。

### 問題 1: Turbo フリーライド + AUP 違反リスク

ardrive の Turbo bundling service は **107520 B (105 KiB) 以下の write は無料** で受領する。Arpass の 4 KiB バケットは全 write がこの無料枠に収まり、結果として:

- ardrive 側に料金が一切落ちない (= service abuse の可能性)
- Arpass 全 user が同じ free tier に集中 → 利用規約違反のリスク
- Turbo CDN がレート制限を強化した場合 Arpass user 全員が一斉に書き込み不可になる構造的脆弱性

新値 [120 KiB, ...] により全 write が確実に有料 tier に入り、上記すべて解消。

### 問題 2: サイズベースフィンガープリント

bucket = 4 KiB の write は Arweave 全トラフィックの中で「異常に小さい (= Arpass)」と即座に識別できた。例えば Arweave indexer が data_size = 4096〜4112 のトランザクションをフィルタすれば Arpass envelope を全件抽出可能。

新値 [120 KiB, ...] により Arpass write が他の Arweave トラフィック (画像、PDF、ZIP 等) と data_size 分布で混ざり、size-based extraction が困難になる。

### ジッタ追加 (Phase 5.2)

`PAD_JITTER_BYTES = 8 KiB` のランダム加算で、同一 user の連続書き込みでも tx サイズが揺らぐ。これにより「サイズ X = Arpass」というフィンガープリントが成立しない。

復号時の影響: `unpadPlaintext` は末尾から `0x80` 終端マーカーを後方探索する方式なので、加算分のゼロ埋め長が変動しても復号は成立する。

---

## Phase 5.3 改修の暗号設計上の意義

### 楽観的並行制御 (`expectedLatestTxId`)

複数端末同時編集の race condition で「後保存が古い vault で上書き」してデータ喪失するのを防ぐ。これは **暗号方式そのものは変えない** が、サーバが知っている `latestTxId` を client が send する仕組みを追加することで、**「既知の状態に対する CAS (compare-and-swap)」**を実現している。

サーバ側 `_safeOptLock(expected, current)` は constant-time 比較ではない (タイミング攻撃で漏れる情報は txid の長さのみ = 65 文字固定なので無問題)。

### localStorage envelope cache

cache に保存される blob は **既に外側 AES-GCM で暗号化済み**なので、ブラウザプロファイル盗難でも attacker に vault 内容は漏れない (vault-id を知らないため)。これが「localStorage に書いていいか」の判定根拠。

`vault-id` 自体は Recovery Secret から HKDF 派生されるので localStorage には絶対書かない。

### Ephemeral session token (Stripe metadata 匿名化)

256-bit ランダム base64url が token なので brute force 不可能 (entropy = 256 bit)。Cloudflare KV の `expirationTtl` で 30 分後自動削除。webhook 受信時に手動 `DELETE` で early consume。

これは暗号アルゴリズムの選定ではなく **「外部サービスの DB に persistent identifier を残さない」** というアーキテクチャ判断。Stripe DB が侵害されても Arpass の publicKeyHash が漏れない構造。

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

---

# v5 で追加された設計判断

v5 (2026-04) では既存の暗号プリミティブ選定はそのまま維持しつつ、**運用面・流出経路に関する 3 つの新設計**を追加しました。それぞれの採用理由を以下に記述します。

## 外側 AES-GCM 層

### なぜ追加したか

v4.1 までの envelope は JSON のまま Arweave に書かれていたため、第三者が以下の攻撃で「これは Arpass の vault だ」と特定可能でした:

```
1. Arweave 全件を download
2. 各 body を JSON.parse
3. キー集合が {v, k, i, c, w, d} と一致 → Arpass v4 envelope
4. キー集合が {v, s, i, c, w}    と一致 → Arpass v5 envelope (※外側無しの場合)
5. サイズが ~110 KiB → 確度 +
```

これは**機密性の侵害ではなく、サービス利用の事実が漏れる**問題です。誰がいつどれくらい Arpass を使っているか、ユーザー数の推移、競合分析、政治的圧力下でのターゲティング等に悪用可能です。

### 採用方針

エンベロープ JSON 全体をさらに `AES-256-GCM(HKDF(vault-id), iv)` で暗号化してから Arweave に書き込む。これにより:

- Arweave 上の bytes は完全な乱数バイト列に見える
- JSON 構造・フィールド名・暗号アルゴリズム名・サイズ分布などのフィンガープリントが消える
- `vault-id` を知らない第三者は復号もできない (vault-id はサーバ・Arweave のどこにも露出しない)

### なぜ HKDF(vault-id) か

外側鍵は本来 Arpass の脅威モデル上は「秘密」である必要はなく、obfuscation 用途として `vault-id` を流用するのが最も簡単です。重要な性質:

- **クライアント本人だけが導出できる** (vault-id がサーバ・Arweave のどこにも無い)
- 端末復旧時も Recovery Secret から vault-id が再導出できるので外側鍵も再生成可能
- 複数端末で同じ vault に書き込んでも、同じ vault-id → 同じ outer_key で読める

### なぜ別の独立した「外側秘密鍵」を作らなかったか

理論的には MEK とは別の独立した「outer secret」を生成してさらに wrap で 3 通りに包む選択肢もあります。しかしこれだと:

- wrap が二重構造になり実装複雑化
- 端末追加時に「outer secret の wrap」も追加する必要がある
- Recovery 再発行でも「outer secret の rotation」を考えないといけない

Arpass の脅威モデルでは「Arpass の存在を Arweave 上で隠す」ことが目的なので、**vault-id を流用**するシンプル設計で十分と判断しました。

## 署名鍵を MEK から決定論派生

### なぜ決定論派生か

v4.1 では署名鍵 (ECDSA P-256 private key) を本体 ciphertext の中に同梱して保存していました。これは以下の問題を持ちます:

- **SNDL (Store Now Decrypt Later) リスク**: Arweave は永久に消えないので、将来 PBKDF2 / AES-GCM が破られた瞬間に過去の署名鍵が全部抽出される
- **量子耐性の問題**: 量子コンピュータで ECDSA P-256 が破られた場合、過去の署名から秘密鍵が逆算可能になる
- **「鍵の保存場所」が一つ増えるとそれだけ攻撃面が増える**

v5 では `HKDF(MEK, "arpass-signing-key-v5")` で署名鍵を都度派生する方式に変えました。MEK は元々本体 c の暗号化に使う鍵なので、追加の保管場所は発生しません。

### 同じ MEK → 同じ Q が必須

派生方式が機能するには「MEK が同じなら出てくる (d, Q) も毎回必ず同じ」という決定論性が必要です。HKDF の出力は input が同じなら常に同じなので OK。これにより:

- 別端末でユーザーが Recovery + Master で復元 → 同じ MEK → 同じ Q
- サーバ側の KV キー `H(Q)` も同じ → 同じアカウントの残高にアクセス可能

「アカウント連続性」がユーザーの何の操作もなしに自動的に保証されます。

### Web Crypto API では point multiplication ができない

ECDSA 鍵を「seed bytes から作る」ことは Web Crypto API の標準では直接サポートされていません。`generateKey({name: "ECDSA"})` は内部 RNG で乱数を作るだけで、外部から seed を与えられません。

このため v5 実装では `@noble/curves/p256` (TypeScript 製、~30 KB、独立監査済み) を使って `Q = d × G` の point multiplication を行い、結果を JWK 形式で `crypto.subtle.importKey` に渡す方式を取ります。`@noble/curves` は Bitwarden、Nostr 等で広く採用されている品質の高いライブラリです。

## サーバ KV を publicKey ベースに

### なぜ vault-id をサーバから消すか

v4.1 までは Cloudflare KV のキーが `vault-id` で、クライアントは `X-Vault-Id` ヘッダで vault-id を毎リクエスト送っていました。これは以下のリスクを持ちます:

- **Cloudflare 運用者を侵害された場合に vault-id が漏れる** (KV 全件読み取り、ログ収集)
- **vault-id が Arweave の検索キーにもなっている** ので、漏れた vault-id から「誰が、いつ、何を書いたか」を Arweave 上で逆引きできてしまう

v5 では:

- KV キーを `H(publicKey)` に変更
- クライアントは `X-Public-Key` (publicKey そのもの) + `X-Signature` (ECDSA 署名) を送る
- サーバは publicKey で署名検証 → `H(publicKey)` で KV ルックアップ
- vault-id を一切受信・保存しない

### publicKey は元々公開なので問題ない

publicKey は本来「公開して問題ない値」(公開鍵暗号の前提) です。これがサーバ側に保存されても流出しても、Arweave 検索の手がかりにはなりません (Arweave 側は別の HMAC 由来の `App-Name` で識別される)。

つまり v5 設計は **「Cloudflare が知るべき情報」と「Arweave が見られる情報」を完全に分離**します:

| データ | Cloudflare KV | Arweave |
|---|---|---|
| publicKey | ✅ (識別子として) | ❌ |
| vault-id | ❌ | ❌ (タグにも本体にも無い) |
| App-Name タグ | ❌ | ✅ (HKDF(Recovery)) |
| 暗号化された vault | ❌ | ✅ (外側暗号化済 blob) |

どの 1 か所が侵害されても他の系を識別できない、という直交性を達成しています。

### なぜ「サーバが publicKey を保存する」のはセキュリティ的に許容されるか

publicKey は元来公開可能な値であり、攻撃者が知っても暗号学的に得るものは無いから (= 対応する秘密鍵が無いと署名できない)。一方で publicKey 経由のサービス機能 (audit log、暗号化通知、匿名統計、anomaly detection 等) を将来導入する余地が残ります。

「publicKey はサーバに保存する」 vs 「毎リクエスト送るので保存不要」のどちらでも機能しますが、運用機能の拡張余地のため v5 では KV value 内に publicKey を保存することを推奨しています (任意)。
