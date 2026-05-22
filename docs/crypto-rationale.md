# 暗号アルゴリズム選定理由

> 🌐 English version: [en/crypto-rationale.md](en/crypto-rationale.md)

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

## バケット最小値 80 KiB の選定根拠 (Phase 6.7、旧 Phase 5.2 = 120 KiB)

旧バケット値 `[4 KiB, 16 KiB, ...]` は v5 cutover 直後 (Phase 5.0〜5.1) に存在したが、以下 2 つの問題を同時に抱えていた重大バグだった。Phase 5.2 で `[120 KiB, ...]` に修正、Phase 6.7 で `[80 KiB, 160 KiB, 240 KiB]` に最適化。

### 問題 1: Turbo フリーライド + AUP 違反リスク

ardrive の Turbo bundling service は **on-chain 100 KiB (102,400 B) 以下の write は無料** で受領する (Phase 6.7 で実 upload 測定により確定: `scripts/measure-turbo-write-cost.mjs`)。Arpass の 4 KiB バケットは全 write がこの無料枠に収まり、結果として:

- ardrive 側に料金が一切落ちない (= service abuse の可能性)
- Arpass 全 user が同じ free tier に集中 → 利用規約違反のリスク
- Turbo CDN がレート制限を強化した場合 Arpass user 全員が一斉に書き込み不可になる構造的脆弱性

Phase 5.2 の [120 KiB raw, ...] (= on-chain 162.97 KiB / ¥0.47/write) でこの問題を解決し、Phase 6.7 の [80 KiB raw, ...] (= on-chain ~110 KiB / ¥0.33/write) でコスト最小化しつつ無料枠超過を維持した。

### 問題 2: サイズベースフィンガープリント

bucket = 4 KiB の write は Arweave 全トラフィックの中で「異常に小さい (= Arpass)」と即座に識別できた。例えば Arweave indexer が data_size = 4096〜4112 のトランザクションをフィルタすれば Arpass envelope を全件抽出可能。

新値 [80 KiB, ...] により Arpass write が他の Arweave トラフィック (画像、PDF、ZIP 等) と data_size 分布で混ざり、size-based extraction が困難になる。on-chain ~110 KiB ± 6 KiB jitter のレンジに分布。

### Phase 6.7 のコスト最適化

Phase 5.2 で raw 120 KiB → on-chain 162.97 KiB / ¥0.47/write は abuse 防止には十分だったが、コストとして過剰だった。Phase 6.7 で実 upload 測定 (`scripts/measure-turbo-write-cost.mjs`) を行い:

| Raw bucket | On-chain | Cost/write | 用途 |
|---|---|---|---|
| 80 KiB (Phase 6.7) | ~110 KiB | ¥0.33 | 通常ユーザー (大半) |
| 160 KiB (Phase 6.7) | ~217 KiB | ¥0.40 | エントリ多めユーザー |
| 240 KiB (Phase 6.7) | ~325 KiB | ¥0.50 | 大量エントリユーザー (上限) |

事業計画 (Free tier 100 writes/user 自社負担) のコストが Phase 5.2 の ¥47/user → Phase 6.7 で ¥33/user に圧縮 (30% 削減)、$5 wallet で約 2,272 writes 可能 (旧 ~1,600 writes)。

### ジッタ追加 (Phase 5.2 〜 維持)

`PAD_JITTER_BYTES = 8 KiB` のランダム加算で、同一 user の連続書き込みでも tx サイズが揺らぐ。これにより「サイズ X = Arpass」というフィンガープリントが成立しない。Phase 6.7 でも同じ jitter を維持。

復号時の影響: `unpadPlaintext` は末尾から `0x80` 終端マーカーを後方探索する方式なので、加算分のゼロ埋め長が変動しても復号は成立する。

---

## Phase 5.3 改修の暗号設計上の意義

### 楽観的並行制御 (`expectedLatestTxId`)

複数端末同時編集の race condition で「後保存が古い vault で上書き」してデータ喪失するのを防ぐ。これは **暗号方式そのものは変えない** が、サーバが知っている `latestTxId` を client が send する仕組みを追加することで、**「既知の状態に対する CAS (compare-and-swap)」**を実現している。

サーバ側 `_safeOptLock(expected, current)` は constant-time 比較ではない (タイミング攻撃で漏れる情報は txid の長さのみ = 65 文字固定なので無問題)。

### localStorage envelope cache

cache に保存される blob は **既に外側 AES-GCM で暗号化済み**なので、ブラウザプロファイル盗難でも attacker に vault 内容は漏れない (外側鍵 `outer_key` を導出できないため)。これが「localStorage に書いていいか」の判定根拠。

`outer_key` は Recovery Secret 由来の `rMat` から HKDF 派生されるので、鍵そのものは localStorage には絶対書かない。

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

エンベロープ JSON 全体をさらに `AES-256-GCM(outer_key, iv)` で暗号化してから Arweave に書き込む。これにより:

- Arweave 上の bytes は完全な乱数バイト列に見える
- JSON 構造・フィールド名・暗号アルゴリズム名・サイズ分布などのフィンガープリントが消える
- `outer_key` を導出できない第三者は復号もできない

### なぜ Recovery 材料から直接派生するか

> **Phase 7.0w-AR (2026-05) 更新**: 初期の v5 では外側鍵を `HKDF(vault-id)` で派生していましたが、Phase 7.0w-AR で **vault-id 概念そのものを廃止**し、外側鍵を Recovery 材料 `rMat` から直接派生する方式に変更しました。

```
outer_key = HKDF-SHA256(
  ikm  = rMat,                    // Recovery Secret から派生した 32 byte
  salt = "arpass-outer-v6",
  info = "envelope-wrap",
  L    = 32 )
```

外側鍵は本来 Arpass の脅威モデル上は「秘密」である必要はなく、obfuscation 用途です。重要な性質:

- **クライアント本人だけが導出できる** (`rMat` は Recovery Secret を持つ本人しか持たない)
- 端末復旧時も Recovery Secret から `rMat` → `outer_key` が再導出できる
- 複数端末で同じ vault に書き込んでも、同じ Recovery → 同じ `outer_key` で読める
- vault-id という中間識別子を一切持たないので、サーバ・Arweave・localStorage のどこにも「vault を指す ID」が残らない

### なぜ vault-id を廃止したか

初期 v5 の `vault-id` は Recovery から派生する 16 byte の中間識別子で、Arweave タグ計算・外側鍵派生・localStorage キャッシュキーの 3 用途に使われていました。しかし「vault を一意に指す ID」が存在すること自体が、localStorage 盗難時や実装ミス時の漏洩面でした。Phase 7.0w-AR では外側鍵も Arweave タグも `rMat` から直接派生する設計に統一し、vault-id を完全に削除しました。

### なぜ別の独立した「外側秘密鍵」を作らなかったか

理論的には MEK とは別の独立した「outer secret」を生成してさらに wrap で 3 通りに包む選択肢もあります。しかしこれだと:

- wrap が二重構造になり実装複雑化
- 端末追加時に「outer secret の wrap」も追加する必要がある
- Recovery 再発行でも「outer secret の rotation」を考えないといけない

Arpass の脅威モデルでは「Arpass の存在を Arweave 上で隠す」ことが目的なので、**`rMat` を流用**するシンプル設計で十分と判断しました。

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
| 匿名タグ (name/value) | ❌ | ✅ (HKDF(rMat)、Phase 7.0w-AR で name もランダム化) |
| 暗号化された vault | ❌ | ✅ (外側暗号化済 blob) |

どの 1 か所が侵害されても他の系を識別できない、という直交性を達成しています。

### なぜ「サーバが publicKey を保存する」のはセキュリティ的に許容されるか

publicKey は元来公開可能な値であり、攻撃者が知っても暗号学的に得るものは無いから (= 対応する秘密鍵が無いと署名できない)。一方で publicKey 経由のサービス機能 (audit log、暗号化通知、匿名統計、anomaly detection 等) を将来導入する余地が残ります。

「publicKey はサーバに保存する」 vs 「毎リクエスト送るので保存不要」のどちらでも機能しますが、運用機能の拡張余地のため v5 では KV value 内に publicKey を保存することを推奨しています (任意)。

---

## Phase 6.2: Wallet pool による privacy 強化

### 問題: 単一 service-wallet による Arweave トラフィックの紐付け

v5 cutover (Phase 5.0) 以降も、Arweave への書き込みは **すべて単一の service-wallet が署名** していた。これにより:

- Arweave GraphQL `transactions(owners: [<service-wallet-address>])` で **全 Arpass writes が enumerable**
- Arpass のトラフィック総量・成長率・時間帯パターンが外部観察者に可視
- App-Name タグ (per-vault HKDF 由来) と組み合わせると **per-vault 活動量** も推測可能

これは v5 の「内容と identity は完全保護」という設計意図に対し、**「メタデータレベルでは Arpass 識別が trivial」** という抜け道を残していた。

### 解決策: 30-wallet pool + KV 永続割当

**Phase 6.1**: Arpass 運用が 30 個の独立した Arweave wallet を保有。各 wallet は独立に Stripe 経由で Turbo Credits を pre-fund。

**Phase 6.2 (重要修正)**: Per-write のランダム選択ではなく、**ユーザ単位で 1 wallet を永続割当**。Cloudflare KV に `userStandardWallet:<H(publicKey)> → wallet record` を保存。同じユーザは常に同じ wallet で署名する。

#### なぜ「ランダム選択」ではダメだったか

ランダム選択 (初期実装) では、1 ユーザが多数の write を行うと **Coupon Collector の問題** により高い確率で全 30 wallet を踏破できる。期待値:

- N=30 wallet → ~120 writes で全列挙
- N=100 wallet → ~520 writes
- N=1,000 wallet → ~7,500 writes

つまり Arpass を 1〜2 週間使っただけのユーザが、自分のクライアントから観察できる App-Name パターン経由で全 wallet を逆引きできてしまう。

#### KV 永続割当による mitigation

各ユーザは publicKey hash で識別され、初回 write 時に pool 内 1 個の wallet にランダム割当 → KV に保存。以降同ユーザは常に同 wallet で署名する。

これにより:

- 1 ユーザが Arweave 上で観察できるのは **割り当てられた 1 wallet のみ**
- 全 30 wallet を列挙するには **30+ 個の独立アカウント** が必要 (30+ 枚のカード or 30+ 個の free signup)
- 経済的・法執行追跡的に mass surveillance の閾値を大幅に引き上げる

### Private Mode (Mega ¥15,000+ 専用)

最高 tier の Mega プラン購入者には、**専用 wallet (他ユーザと一切非共有)** を warm pool から割り当て。Stripe webhook (`checkout.session.completed`) で `pricing.js` の `isPrivateMode: true` を持つ pack を検出し、`assignPrivateWallet()` を発火。

Private Mode user の保証:

- wallet address は KV (`userPrivateWallet:<H(pk)>`) にのみ保管 → 当該 user の publicKey でしか lookup 不可
- **本人以外、Arweave GraphQL で当該ユーザの書き込みを enumerate することは原理的に不可能**
- = 「pseudonymity at scale」を超えて「provable unlinkability for paid premium users」を達成

### 経済学的 privacy mechanism

これは pure 暗号学的 anonymity とは異なる、**経済 + 法的リスクを使った privacy 設計** である:

| 攻撃者タイプ | コスト | 法的リスク |
|---|---|---|
| 外部 passive observer (block-explorer scrape) | 0 | 0 | → 防御 ✅ |
| 学術研究者 (passive Arweave 解析) | 計算コスト中 | 0 | → 大半防御 ✅ |
| 内部攻撃者 (Arpass user として enumerate) | 1 wallet しか観察できない | 0 | → 防御 ✅ |
| Mass surveillance (state actor 級) | 30+ 独立 paid account = ¥150,000+ + card 履歴 | 個人特定可 (KYC 紐付け) | → 経済+法的に抑止 ⚠️ |
| Mega user の writes 特定 | 本人になる以外不可 | — | → 不可能 ✅ |

これにより **「Bitcoin pseudonym と同等以上の privacy を、UX を犠牲にせず、現実的な攻撃モデル下では絶対的に達成」** している。

### 設計上の限界 (透明性のため明記)

- Cloudflare KV / Arpass バックエンドが完全侵害された場合、wallet ↔ user の紐付け map が攻撃者に渡る (一般的な server-side compromise リスクと同等)
- 公開された tag pattern (App-Name 形式 + 107 KiB padding) を知る攻撃者が Arweave 全 transaction を nightly enumerate して **Arpass 全体トラフィック量** を推定することは可能 (ただし個別 user 識別は依然として不可)
- ArDrive Turbo に依存しているため、Turbo の bundle TX owner (Turbo wallet) は Arweave 上に常に Turbo として現れる (これは privacy 改善ではなく、bundling サービスの性質)

### コスト

- Phase 6.1: 30 standard pool wallets × USD $4 = **$120 (≈ ¥18,000)** 初期投資
- Phase 6.2: 10 private warm pool wallets × USD $4 = **$40 (≈ ¥6,000)** 初期投資
- 合計 **$160 ≈ ¥24,000** で privacy ★★★★ 達成
- スケール時: pool size を 100 → 1,000 と拡張、Phase 6.3 で AR/USDC 自動補充に移行

詳細な運用手順は [`docs/wallet-pool-runbook.md`](https://github.com/technoblest/arpass/blob/main/docs/wallet-pool-runbook.md) を参照。

---

# Phase 7.2: Business mode の暗号設計判断

Phase 7.2 では複数社員で共有する組織向けの **Business mode** を追加しました。Personal mode (1 ユーザ = 1 vault) の 2-of-3 鍵管理はそのまま維持しつつ、社員 vault に「会社共通の鍵層」を 1 段追加します。設計の核心は **「サーバを一切信用しないまま会社が鍵を統制する」** ことです。

## K1 を社員ごとに ECIES で別 wrap する

### 鍵階層

Business mode では vault の実暗号鍵 `real_MEK` を 2 つの材料から合成します:

```
real_MEK = HKDF( K1 ‖ K2, salt = "arpass-business-mek-v2", info = "real-mek" )
```

| 鍵 | 役割 | 保存場所 |
|---|---|---|
| **K1** | 会社共通 wrap 鍵 (ランダム 32 byte) | Admin vault に平文、各社員レコードに ECIES wrap |
| **K2** | 社員個別 wrap 鍵 (ランダム 32 byte) | 各社員 vault の `w.{a,b,c}` (2-of-3 factor で開く) |

K2 は Personal mode の MEK と同じく社員自身の 2-of-3 factor で開きます。K1 は会社が握り、社員ごとに **別々の wrap** で配布されます。

### なぜ社員ごとに別 wrap なのか

K1 をすべての社員に共通の 1 個の wrap blob で配ると、退社処理や鍵 rotation のたびに全社員分を作り直す必要があります。Phase 7.2-B では K1 を **社員ごとに ECIES (P-256 ECDH + HKDF + AES-GCM) で個別 wrap** します:

1. 各社員は signup 時に static な ECDH 鍵ペア `emp_keypair` を生成。秘密鍵は自分の vault 内に K2 wrap で保存 (`w_emp` フィールド)、公開鍵だけサーバに登録
2. Admin が「配布」操作をすると、社員ごとに使い捨ての ephemeral 鍵ペアを生成して `enc_K1[i] = ECIES(社員 i の公開鍵, K1)` を計算
3. `enc_K1[i]` はサーバ KV に保管され、社員が unlock 時に取得して自分の `emp_priv` で復号

ephemeral 鍵を毎回使い捨てにするため、1 つの wrap が漏れても他の wrap や過去の wrap には波及しません (forward secrecy)。

### なぜサーバを信用しなくてよいか (zero-knowledge)

旧 v1 設計では会社の秘密鍵をサーバが永続保管していたため、構造的にサーバが K1 を復号できてしまいました (zero-knowledge 違反)。Phase 7.2-B v2 では:

- サーバは社員の **公開鍵**と `enc_K1[i]` (ECIES wrap 済) しか持たない
- ECIES の内側を剥がすには社員の `emp_priv` (= vault 内、K2 wrap) か Admin の K1 vault が必要で、サーバはそのどちらも持たない
- サーバ KV の at-rest 防御として `CORP_KEK_MASTER_SECRET` で `enc_K1` をさらに rewrap するが、これが全部漏れても剥がれるのは外層だけで、内側の ECIES wrap は無傷

つまり **サーバプロセスが単独で K1 を復号できる経路が存在しません**。Cloudflare 内部スタッフや、サーバ + `CORP_KEK_MASTER_SECRET` を同時に侵害した攻撃者ですら、社員 vault の中身に到達できません。

### 署名鍵を K2 由来にした理由

Business mode の API 署名鍵 (ECDSA P-256) は K1 ではなく **K2 から派生**します (`HKDF(K2, "arpass-signing-v2")`)。理由は鶏卵問題の回避です: K1 を取得する API を呼ぶには署名鍵が要りますが、署名鍵の派生に K1 が必要だと、K1 取得前に署名できません。署名鍵を K2 由来にすることで、社員は K1 取得前に署名鍵を用意でき、また K1 rotation の影響を受けず監査ログの署名連続性が保たれます (Personal mode は K2 ≡ MEK なので互換)。

## IP allowlist (ネットワーク境界)

会社オーナーは自社の Business アカウントに **IP allowlist** (CIDR の配列) を設定できます。allowlist が空でなければ、社員の K1 取得などの corp API はその CIDR からのリクエストしか受け付けません。

- これは暗号的な保護ではなく **運用上のネットワーク境界**です。退社者が手元に K2 cache を残していても、社内ネットワーク外からは K1 を取得できません
- 暗号層 (社員ごと ECIES wrap) と独立した防御層で、「退社処理 + member check + IP gate」の 3 段で退社者を遮断します
- allowlist への CIDR 追加は、追加した CIDR が現在の Admin の IP を含まない場合は拒否されます (誤設定で Admin 自身が締め出される事故を防ぐ)

暗号設計の観点では、IP allowlist は zero-knowledge を一切損ないません (サーバはあくまで「リクエスト元 IP が許可範囲か」だけを判定し、鍵には触れません)。

## Zero-knowledge 監査ログ

Business mode には、誰がいつ何をしたかを記録する**監査ログ**があります。監査要件を満たしつつサーバ無知性を崩さないため、ログイベントは **ECIES で暗号化された opaque blob としてのみサーバを通過**します:

- 任意の社員/Admin が監査イベント (例: 「vault を開いた」「K1 を配布した」) を ECIES 暗号化してサーバに push する
- サーバはその blob を中身を知らないまま 30 日間だけ保管する (1 イベント 8 KiB 上限)
- Admin が後で pull して自分の鍵で復号し、ack することで自分の vault 内に永続化する

サーバは監査イベントの平文を一度も見ません。「改ざん不能な監査ログ」という企業要件と、「サーバは何も知らない」という Arpass の根本方針を両立させる設計です。

---

# Phase 7.3: 非 extractable CryptoKey 移行

## 動機

Personal mode の最大の脅威は、悪意ある **ブラウザ拡張機能 / XSS / 侵害された npm 依存** です。LastPass 2022 の流出では平文の master password がメモリに常駐しており、それが抜き取られました。

これらの攻撃が成立するのは、`_session.mek` のような **raw な 32 byte の鍵が JS から読める**からです。`localStorage.setItem` / `console.log` / `JSON.stringify` のどれでも抜き取れてしまいます。

## なぜ非 extractable CryptoKey か

WebCrypto の `CryptoKey` を `extractable: false` で作ると、その鍵 material は **JS の世界から完全に隠れ**ます (ブラウザの C++ heap にのみ存在)。`crypto.subtle.exportKey` を呼んでも `InvalidAccessError` で失敗し、`JSON.stringify` では空オブジェクト `{}` になります。鍵は使える (暗号化・復号・署名はできる) のに、生バイト列としては取り出せません。

Phase 7.3-A では、session に保持する鍵を raw `Uint8Array` から非 extractable `CryptoKey` に移行しました:

| 旧 (raw) | 新 (非 extractable CryptoKey) |
|---|---|
| `_session.mek: Uint8Array(32)` | `_session.mekKey` (AES-GCM) + `_session.mekHkdfKey` (HKDF base) |
| `signingPrivateKey` (extractable) | 非 extractable ECDSA private key |
| `_session.outerKeyBytes` | `_session.outerKey` (非 extractable AES-GCM) |
| `_session.recoveryMaterial` | `_session.rMatHkdfKey` (非 extractable HKDF base) |

unlock の派生 chain の途中では raw bytes が一瞬だけ JS に現れますが (PBKDF2 / HKDF の出力など)、`importKey` で CryptoKey 化した直後に `fill(0)` で zeroize します。unlock が終わった時点で、session には CryptoKey オブジェクトしか残りません。

## この防御で防げること / 防げないこと

| 攻撃 | raw mek 時代 | 非 extractable 後 |
|---|---|---|
| 悪意ある拡張機能が session の鍵を読む | 抜ける | **防げる** |
| XSS で鍵を fetch して外部送信 | 抜ける | **防げる** |
| 侵害された npm 依存が鍵を export | 抜ける | **防げる** |
| `console.log(_session)` をユーザに実行させる | 抜ける | **防げる** (raw が表示されない) |
| OS root 権限 + メモリダンプ | 抜ける | △ C++ heap には raw が残る |
| 改造ブラウザ (V8 直接 patch) | 抜ける | △ 防げない |

つまり **「OS 権限を持たない攻撃者」のほぼ全て**に対して防御が成立します。OS root やメモリダンプといった原理的限界 (Widevine DRM の L1/L3 階層と同じ構造) は対象外として明示しています。

## envelope フォーマットは不変

Phase 7.3-A は **実装上の鍵の扱い方を変えるだけ**で、Arweave に書かれる envelope の暗号文構造 (v5) は一切変わりません。マイグレーション不要で、既存ユーザは次回 unlock 時に自動的に新しい派生 chain で session を組みます。

## 残る限界 (透明性のため明記)

- unlock 中、鍵派生の中間 raw bytes が ~1ms 程度 JS に現れる window があります。攻撃者が正確にそのタイミングでメモリスキャンできれば取得し得ますが、現実的には困難です
- entry を画面表示している間、パスワード文字列は DOM 上にあります。「拡張機能が DOM を読む」攻撃は依然成立し、これは Phase 7.3-A の対象外です (別途、表示マスク / on-demand reveal で対処)
- Personal mode では `changePassword` / Recovery 再発行などで再 wrap が必要な操作のため、`_session.mek` 相当の raw を unlock 中だけ保持するケースが残ります。これは「ユーザが unlock 状態で操作中」という限定 window に bounded で、1Password / Bitwarden 等の業界標準と同等です。自動 lock (アイドル 5 分 / タブクローズ) と CSP (self-only script-src) で緩和します
