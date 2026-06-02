# Arpass envelope v7 — 詳細仕様（YubiKey 対応 / outer 鍵を Passkey が運ぶ）

最終更新: 2026-05-25（増分2 実装確定版に改訂）
ステータス: **増分1 本番反映済 / 増分2 実装完了・staging 検証済**
担当: Yamaki / Technoblest
上位メモ: [yubikey-outer-key-redesign.md](./yubikey-outer-key-redesign.md)
前形式: envelope v6（[crypto-2of3.md](./crypto-2of3.md)）

> 改訂メモ: 初版にあった「キースロット・オブジェクト（Arweave 上の別オブジェクト）」案は撤回。
> Arweave の伝播ラグと書き込みコスト（anti-fingerprint padding で各キースロットが本体並みの
> サイズになる）が割に合わない。代わりに **outer 鍵を Passkey の user.id に格納**する。
> Arweave オブジェクトは本体 1 個のまま、書き込みパターンも v6 と同じ。

---

## 0. 位置づけ

- **範囲**: personal / business / admin 全モードの envelope v7（増分1・増分2）。標準 2-of-3 と YubiKey 専用モード。
- business モードも v7 対象（2026-05-23 決定）: IP allowlist + K1 退社制御でアクセス管理は担保されるため端末追加を admin ゲートする必要は薄く、会社ユーザーこそ多端末利用が多い。encryptVaultBusiness の outer 鍵 / appNameTag 導出は encryptVault と同一なので v7 user.id 機構がそのまま転用できる。
- **移行**: サービス未公開＝実ユーザー不在のため v6→v7 マイグレーションは実装しない。v7 を全新規 vault の形式とする。

---

## 1. 目的

1. 「鍵（Passkey / YubiKey）＋ Master」で、新端末を含むどの端末でも解錠できる。新端末ごとの登録・localStorage 依存・Recovery 入力を不要にする。
2. outer 鍵を localStorage に生で置くのをやめる。
3. 2-of-3 の「端末を全部失っても Master+Recovery で復旧」を維持。
4. サーバ非依存性（運営撤退後も手元の鍵だけで復号）を保つ。
5. オプションで Master も Recovery も持たない「YubiKey モード」を選べる。

---

## 2. v6 → v7 変更サマリー

| | v6（現行） | v7 |
|---|---|---|
| outer 鍵の入手 | localStorage に生保存。新端末は Recovery 必須 | Passkey の `user.id` に格納（案A、§3） |
| Arweave オブジェクト数 | 本体 1 個 | 本体 1 個（変更なし） |
| 新端末での Master+Passkey 解錠 | 不可 | 可 |
| localStorage | outer 鍵の必須保管先 | **outer 鍵を一切保存しない**（毎回 user.id から復元） |
| モード | 2-of-3 のみ | 2-of-3 ＋ YubiKey モード（排他選択） |
| Master 最低長 | 8 文字 | 撤廃（短くても可。空は §10 参照） |
| Master 変更 | 現端末の AB wrap だけ再生成（他端末は lazy、旧 Master が残る） | 新 Passkey を作成し全 AB wrap を再構成（§14、旧 Master は即全端末無効） |

---

## 3. 中核アイデア（案A）

Passkey の `user.id`（WebAuthn userHandle、最大 64 byte、鍵が保持・同期/携行する）に、
**vault の所在（appNameTag）と outer 鍵（32 byte）** を載せる。

新端末では WebAuthn get 一回で userHandle と PRF が同時に取れる → userHandle から
outer 鍵を取り出して → vault を取得・外層復号できる。localStorage も
Recovery 入力も不要。

**outer 鍵を Master でラップして user.id に持つ（WebAuthn 順序制約への対処、v7 ハードニング 2026-05-24）**:
`user.id` は credential を作る *前* に確定する入力値であり、PRF はその credential を
作った *後* にしか得られない。したがって「ある credential の user.id を、その credential
自身の PRF で暗号化する」ことは原理的に不可能（鶏と卵）。よって PRF は使えない。
代わりに **outer 鍵を Master パスワード由来鍵で AES-256-CTR ラップして user.id に持つ**。
Master は credential 作成順序と独立なので順序制約に抵触しない。ラップ鍵 =
`Argon2id(Master, salt=appNameTag.value, m=64MiB, t=3, p=4)`、CTR カウンタは appNameTag から
決定論導出。AES-CTR は非膨張なので user.id は 57 byte を維持。誤 Master の検出は独自
タグを持たず下流の外側 AES-GCM 層に委譲する（誤 Master → 誤 outer 鍵 → envelope 復号
がそこで失敗）。この設計は安全である:

- user.id は Passkey ハードウェアでゲートされる（読み出しに物理キー＋タッチ＋UV が
  要る。マルウェアも Arweave スクレイパーも読めない）。さらに outer 鍵は Master で
  ラップ済なので、仮に user.id が将来想定外の場所（パスキー export 規格・OS 変更・
  フォレンジック等）へ漏れても、Master を知らない者には暗号文でしかない。
- Arweave 公開オブジェクトは v6 と完全に同一で、outer 鍵は公開側に一切載らない
  → anti-fingerprint は 100% 無傷。
- outer 鍵は難読化層の鍵であって金庫の機密性鍵ではない（金庫は MEK＋要素で守られる）。
  露出し得るのは「あなたの物理 Passkey を持つ者」だけで、その者は既に要素 B を握っている。
- appNameTag（vault の所在）は秘密ではなく Arweave 上の匿名タグそのものなので、
  user.id 内では平文で持つ（ラップ対象は outer 鍵 32 byte のみ）。

> **Master 変更時**: `user.id` は credential 作成後 *不変* なので、Master を変えると
> 既存 user.id 内のラップが解けなくなる。対処として Master 変更時に新 Master で
> ラップした user.id を持つ新しい Passkey を作成する（§14）。

---

## 4. user.id v7 レイアウト（57 byte）

```
[1B version=7] [8B appNameTag.name] [16B appNameTag.value] [32B outerKey（Master ラップ済）]  = 57 byte
```

- `outerKey` = 32 byte の AES-GCM 外層鍵を **Master 由来鍵で AES-256-CTR ラップ**して
  格納する（非膨張: 32→32 byte、IV/tag のオーバーヘッド無し、user.id は 57 byte 維持、
  64 byte 以内）。当初案の「16 byte seed → HKDF 展開」は不要と判明し撤回。
- **標準モード**: `outerKey = deriveOuterKeyBytes(rMat)` ── 既存 v6 の関数をそのまま使う。
  Recovery 経路（rMat から導出）と Passkey 経路（user.id から読む）が同一の 32 byte に到達。
  → **新たな鍵導出も envelope 形式変更も不要**。
- **YubiKey モード**: `outerKey` はランダム生成（rMat なし）。
- appNameTag.name / value は v6 と同様、両方とも独立に乱数派生（anti-fingerprint、crypto-2of3.md §0.2）。
- codec（`encodeUserIdV7` / `decodeUserIdV7` / `isUserIdV7`、Master-wrap 含む）を実装・検証済み（`scripts/test-envelope-v7.mjs` 23 項目 PASS）。

> **ロケーティング監査済（2026-05-23、§12-2）**: user.id が運ぶ appNameTag は
> **legacy（tier 非依存）** のもの。現行コードでも Arweave 書き込みタグは常に
> legacy tag（`deriveAppNameTag(rMat)` tier=null）で、tier 変更では移動しない
> （tier は `body.tier` で別途サーバ申告）。よって user.id の appNameTag は永続的に有効。

---

## 5. モード（vault 作成時に排他選択）

### 5.1 標準モード（2-of-3）

- 要素 A=Master / B=Passkey+PRF / C=Recovery。v6 と同じ 2-of-3。
- `outerKey` は rMat 由来（`deriveOuterKeyBytes(rMat)`）。Recovery 経路で新端末をブートストラップ可能。
- v7 追加点: 登録 Passkey の user.id に outer 鍵（Master でラップ済）を載せる → 新端末 Master+Passkey 解錠が可能。

### 5.2 YubiKey モード（1-of-N ハードウェア）

- Master 無し、Recovery 無し、rMat 無し。
- `outerKey` / `appNameTag` / `MEK` はランダム生成。
- 登録した任意の 1 本の YubiKey で解錠（1-of-N）。鍵は 2 本以上必須（§10）。
- **user.id に秘密を一切載せない**（標準モードの Master-wrap §3 は適用外）。
  代わりに各 YubiKey ごとに **keyslot blob**（その YubiKey の PRF で暗号化した
  独立 Arweave オブジェクト、§5.3）を作り、そこに `appNameTag` と `outerKey` を
  格納する。user.id は keyslot blob の所在タグ（25 byte、version=8、§5.4）だけを運ぶ。
- 設計根拠: hwkey は Master を持たないため「PRF で user.id を守る」ことができず
  （PRF は credential 作成後にしか得られない＝§3 と同じ鶏卵問題）、生の outer 鍵を
  user.id に置くと物理キー所持者以外への漏洩面が広がる。keyslot blob 方式なら
  user.id は秘密ゼロ、outer 鍵は PRF ゲートの暗号文としてのみ存在する。
- 安全装置は §10。

### 5.3 keyslot blob（増分2、hwkey 専用）

各 YubiKey は固有の **keyslot blob** を 1 つ持つ。これは vault 本体とは別の
独立した Arweave オブジェクトで、構造は次のとおり:

```
[12B IV] [AES-GCM( _keyslotKey(PRF), padPlaintext(JSON{ t:appNameTag, o:outerKey }) )]
```

- 暗号鍵 `_keyslotKey` = `HKDF(PRF, salt="arpass-keyslot-v7", info="keyslot-wrap", 32B)`。
  MEK wrap 用の鍵（info=`"mek-wrap"`）とはドメイン分離されている。
- 中身（`appNameTag` ＋ `outerKey` 32 byte）は **vault 生涯不変** なので keyslot blob は
  write-once（vault 本体の追記とは無関係）。
- 中身は `padPlaintext` で vault 本体と同じサイズ帯（~80 KiB+）まで膨らませる
  → Arweave 上では本体と区別のつかない乱数列に見える（anti-fingerprint 維持）。
- keyslot blob は user.id が運ぶランダムな所在タグ（§5.4 の keyslotTag）で
  `findLatestVaultTx` により GraphQL 発見される。タグ name/value とも乱数。
- codec は `encodeKeyslot` / `decodeKeyslot`、書き込み/取得は `writeKeyslot` /
  `fetchKeyslotBlob`。鍵追加時は新しい YubiKey 用に keyslot blob を 1 つ追記する（§8.2）。

### 5.4 hwkey の user.id レイアウト（25 byte、version=8）

```
[1B version=8] [8B keyslotTag.name] [16B keyslotTag.value]  = 25 byte
```

- 標準 v7 の user.id（57 byte、version=7、§4）とは **長さと version で区別** される。
- 焼くのは keyslot blob の所在タグ（§5.3）だけ。**outer 鍵も MEK も載らない**
  ＝ user.id が万一漏れても、そこから読めるのは「Arweave 上の匿名タグ」のみで、
  keyslot 本体はその YubiKey の PRF がなければ復号できない。
- codec は `encodeUserIdHwkey` / `decodeUserIdHwkey` / `isUserIdHwkey`。

---

## 6. inner envelope 構造（外層復号後）

### 6.1 標準モード
v6 の envelope をそのまま使う（`{ v:5, s, i, c, w:{a,b[],c[]} }`、構造変更なし）。MEK は w から 2 要素で復号。v7 性は user.id 側だけにあり envelope は不変。

### 6.2 YubiKey モード（増分2 as-built）
`{ v:5, m:"hwkey", i, c, k:[ {h,w}, ... ] }`
- `v:5` は `VAULT_FORMAT_V5`（標準モードと共通）、`m:"hwkey"` がモード判別子。
- `i` / `c` = 本体 AES-GCM の IV / 暗号文（MEK で暗号化、構造は標準と同形）。
- `k[i]` = `{ h: credIdHash, w: b64u(wrapMekForPrf(PRF_i, MEK)) }`
  - `h` = その YubiKey の credentialId の SHA-256（解錠時に k[] を絞り込む索引、秘密でない）。
  - `w` = `[IV][AES-GCM(HKDF(PRF_i, "arpass-mek-wrap-v7"/"mek-wrap"), MEK)]`。登録鍵ごとの MEK wrap。
- `s`（Argon2id salt）も `w`（標準モードの 2-of-3 wrap オブジェクト）も無い。
- 解錠は k[] を 1 本の YubiKey の PRF で順に試す 1-of-N（`decryptVaultHwkey`）。

---

## 7. 解錠フロー

### 7.1 標準モード — Master + Passkey（新端末・localStorage 空。今回直す摩擦）
1. WebAuthn get（discoverable）→ Passkey 選択 → `userHandle` ＋ `PRF`。
2. userHandle を parse → `appNameTag`、`outerKey`（生 32 byte）。
3. appNameTag で vault 取得 → outerKey で外層復号 → inner envelope。
4. `AB_KEY = HKDF(Argon2id(Master) ‖ PRF)` → `w.b[i]` 復号 → MEK。
5. MEK で本体 `c` 復号。**Recovery も localStorage も不要。**

### 7.2 標準モード — Master + Recovery（端末全喪失からの復旧）
1. Recovery 入力 → `rMat` → `outerKey = deriveOuterKeyBytes(rMat)`、`appNameTag = HKDF(rMat)`。
2. vault 取得・外層復号。
3. `AC_KEY = HKDF(Argon2id(Master) ‖ rMat)` → `w.a` 復号 → MEK。

### 7.3 YubiKey モード — 任意端末・YubiKey 1 本（増分2 as-built）
1. WebAuthn get → `userHandle`（hwkey 形式 user.id）＋ `credentialId` ＋ `PRF`。
   - 登録済み端末（localStorage meta に credentialId あり）は credentialId 名指しの
     specific get → ブラウザのパスキー一覧を出さず YubiKey に直行。
   - 新端末（meta なし）は discoverable get（picker）。`hwkeyAuthenticateForUnlock` が
     自動判定し、specific get 失敗時は picker に fallback する。
2. `decodeUserIdHwkey(userHandle)` → keyslot blob の所在タグ `keyslotTag`。
3. `findLatestVaultTx(keyslotTag)` で keyslot blob を GraphQL 発見 → 取得 →
   `decodeKeyslot(PRF, blob)` → `appNameTag` ＋ `outerKey`。
4. `appNameTag` で vault 本体を取得 → `outerKey` で外層復号 → inner envelope。
5. `decryptVaultHwkey(envelope, PRF, credIdHash)` → `k[]` を PRF で復号 → MEK → `c` 復号。
6. 作成直後は keyslot / 本体が Arweave 伝播待ちで一時的に 404/5xx になり得るため、
   「未反映」系エラーのみバックオフ再試行（~60s、`_retryArweaveFetch`）。それでも
   取得できなければ `hwkey_not_propagated`（「数分待って」案内）。
   Master も Recovery も localStorage も不要。

---

## 8. 鍵の登録・追加

解錠済み（outerKey / MEK / appNameTag 保持）であること。

### 8.1 標準モード
1. WebAuthn create（`residentKey:"required"`、`userVerification:"required"`）。
   user.id に §4 のレイアウト（version=7 ＋ appNameTag ＋ Master-wrap outerKey）を焼き込む。
2. inner に `w.b[j]`/`w.c[j]` 追加。
3. vault オブジェクトを書き直す（1 write、v6 の「Passkey 追加」と同じ）。

### 8.2 YubiKey モード（増分2、`addHwkeyDevice`）
別の端末に YubiKey を持っていって追加するケースも含む。解錠済みの hwkey vault に
YubiKey を 1 本足す:
1. 既存の登録済み YubiKey で認証 → その keyslot blob から `outerKey`/`appNameTag` を、
   `envelope.k[]` から raw MEK を取り出す（session の MEK は zeroize 済のため再取得）。
2. 新しい YubiKey を登録（`createPasskey`、resident 必須、`userVerification:"discouraged"` §10）。
   user.id に新しいランダム keyslotTag（version=8、§5.4）を焼く。
3. `addHwkey` で `envelope.k[]` に新鍵の PRF-wrap を追加し、新鍵専用の keyslot blob を
   `encodeKeyslot` で作って書き込む（write-once）。
4. `saveVault` で envelope を永続化。raw MEK / outerKey は `finally` で必ず zeroize。

> user.id は資格情報作成時に確定し後から変更不可。標準モードの outer 鍵、hwkey の
> keyslotTag はいずれも作成時に判っているので焼き込める。

---

## 9. 鍵の削除・無効化

- envelope から該当鍵の wrap（`w.b`/`w.c` または `k`）を外して vault を書き直す（ソフト削除）。
- Arweave 追記型ゆえ過去 envelope は残る。真の無効化には MEK のローテーション＋移行が必要（タスク #100）。加えて保存済みパスワードの変更も推奨。
- Master 変更（§14）は新 Passkey を作るため、旧 Passkey が OS / authenticator に蓄積する。WebAuthn に削除 API はないのでユーザーが手動削除する（旧 Passkey は AB 解錠に使えないので残っても解錠面の害はない）。

---

## 10. 安全装置（実装で強制する不変条件）

YubiKey モード:
1. **鍵 2 本以上必須**（`HWKEY_MIN_KEYS=2`）— 作成フローは 2 本登録完了まで vault 作成を
   完了させない。`removeHwkey` も 2 本未満になる削除を拒否する（Master/Recovery が
   無いぶん 1 本運用は全鍵喪失で復旧不能になり危険）。
2. **Recovery 扉を作らない** — Recovery 秘密を生成せず `w` も `encryptedRecovery` も作らない。
3. **discoverable 必須** — `residentKey:"required"`（新端末で userHandle を読むため）。
4. **UV 非依存（`userVerification:"discouraged"`、増分2 で確定）** — 当初は「UV 必須
   （`"required"`）」を予定したが、WebAuthn PRF は **UV（PIN 入力）の有無で出力値が
   変わる**。プラットフォーム間で UV の有無が食い違うと PRF が一致せず keyslot を
   復号できない（特に Mac Safari は `"required"` でも UV を省くことがある）。そこで
   hwkey の全 WebAuthn 呼び出し（create / get / follow-up get）を `"discouraged"` に
   統一し、PRF を常に「UV なし変種（タッチのみ）」に固定する。全プラットフォームで
   PRF が一致する。`createPasskey` は hwkey では create() が返す PRF（create ceremony の
   UV あり PRF）を捨て、必ず follow-up get（discouraged）の PRF を採用する。

> **Mac Safari の制約（増分2、アプリ側で修正不能）**: Mac の Safari は WebAuthn の
> 実装が他ブラウザと異なり、同じ YubiKey でも他ブラウザ（Mac Chrome/Edge、Windows、
> iPhone、Android）と PRF 値が一致しない。このため Mac Safari で作成・利用した hwkey
> ドライブは Mac Safari 専用になり、他環境と相互に開けない（逆も同様）。当初は Mac
> Safari を検出してブロックしたが、Safari 内で完結する利用は可能なため、ブロックは
> 撤廃し **「他ブラウザ/他端末と共有できない」旨の注意喚起（toast）にとどめる**
> （作成・解錠の実行は許可）。検出は `_isMacSafari()`（iPad は maxTouchPoints で除外）。

標準モード: Master 最低長ルールは撤廃。ただし **空 Master は標準モードでは不可**。空にすると w.a が「Recovery 単独で開く扉」に静かに変わるため。Master 無しが欲しい場合は YubiKey モードを使う（明示・安全装置付き）。

---

## 11. 増分（実装の段階分け）

### 増分 1 — 「どの端末でも・Recovery 入力なしで」（小・自己完結）
- outer 鍵（32 byte、Master ラップ済）を user.id に格納（案A、§3）。
- 解錠経路を userHandle に一本化。**localStorage には outer 鍵を一切保存しない**（2026-05-24、目的 #2 達成）。端末追加で作るパスキーも v7 user.id を焼く。
- Master 最低長 8 文字ルールを撤廃（短い Master を許容、空は不可のまま）。
- 標準モードのみ。YubiKey も Passkey として従来どおり使える。

### 増分 2 — YubiKey モード（「本当に YubiKey だけ」を安全に）— **実装完了（2026-05-25、staging 検証済）**
- `m:"hwkey"` envelope、`k[]` の per-YubiKey MEK wrap（§6.2）。
- keyslot blob 方式で outer 鍵 / appNameTag を運ぶ（§5.3）。user.id は所在タグのみ（§5.4）。
- 作成フロー（モード選択 UI、≥2 本、Recovery 非生成、`createHwkeyVault`）。
- 任意端末での解錠（§7.3、`unlockWithHwkeyAuthed` / `hwkeyAuthenticateForUnlock`）。
- 別端末での YubiKey 追加（§8.2、`addHwkeyDevice`）。
- WebAuthn を全て `userVerification:"discouraged"` に統一し PRF を UV 非依存に固定（§10）。
- Arweave 伝播遅延のバックオフ再試行（§7.3 step 6）。
- Mac Safari は PRF 非互換のため共有不可。ブロックせず注意喚起のみ（§10）。
- test-envelope-v7.mjs 56/56 PASS、lint:security clean、i18n:check 0 errors。

---

## 12. 未確定事項（実装で詰める）

1. ~~business モード（K1/K2）への適用~~ **増分1 で対応済（§0、createVault が全モードで v7 user.id を焼き込む。decryptVaultAuto は元々 business envelope を処理可）。**
2. ~~user.id に載せる所在情報の最小集合~~ **解決済（2026-05-23 ロケーティング監査）**:
   - vault の Arweave 書き込みタグは現行・v7 とも **legacy（tier 非依存）appNameTag** 固定。
     tier（free/paid/corp）は `body.tier` で別途サーバ申告し、タグは動かさない。
     → user.id は legacy appNameTag を持てばよく、tier 変更後も有効。
   - 新端末の vault 特定: userHandle → appNameTag → サーバ `?app=`（高速路）
     → GraphQL `findLatestVaultTx`（フォールバック、サーバ非依存）。
   - サーバ側: `vlatest:<appName>→pkHash` 索引は実コード上すでに TTL なしで恒久
     （write.js のコメントに「30 日 TTL」とあったが未実装の名残）。v7 はこの索引を
     `?app=` 高速路に使うため、deprecation しない旨を write.js コメントに明記済。
   - pkHash は MEK 由来で `createPasskey` 後にしか定まらず user.id に入れられない
     （鶏と卵）。`?pk=` は localStorage を持つ既知端末用の高速路として従来どおり。
3. HKDF info 文字列の最終確定、`v:7` フォーマットマーカー細部。
4. ~~固定 IV の安全性レビュー~~ **不要化（seed/PRF-wrap 撤回済。wrapMekForPrf はランダム IV）。**
5. YubiKey モードへの任意 Recovery（深いバックアップ）を後から足せる設計余地。

---

## 13. 実装ステップ（feature ブランチ `feat/envelope-v7`）

1. ~~`vault-crypto.js`: v7 鍵導出 ＋ user.id v7 codec ＋ MEK wrap の純関数 ＋ ラウンドトリップ検証~~ **完了（案A + Master-wrap、23 項目 PASS）。**
2. ~~増分1（サーバ）: `vlatest` 索引の恒久化~~ **完了（既に TTL なし。write.js に v7 依存を明記）。**
3. ~~増分1: `createVault` で user.id に v7 ペイロードを焼き込む~~ **完了（personal mode、`createPasskey` bytes 受付化）。**
4. ~~増分1: 解錠経路を userHandle 経由に + 新端末 UI 入口~~ **完了（Mac / iPhone 実機でクロスデバイス検証済 2026-05-23）。**
5. ~~増分1: Master 最低長ルール撤廃~~ **完了（8 文字 min を撤廃、空のみ不可）。**
6. ~~増分2: `m:"hwkey"` envelope ＋ `k[]` wrap、keyslot blob、createVault 分岐~~ **完了。**
7. ~~増分2: モード選択 UI、≥2 本の強制、解錠 §7.3、別端末 YubiKey 追加 §8.2~~ **完了（staging 検証済）。**
8. ~~`web/prf-test.html` / `prf-test.js` を削除~~ **完了（PRF 検証完了済）。**
9. ラウンドトリップ検証、staging 検証 → main。
10. ~~増分1（Option A）: Master 変更時に新 Passkey を作成し全 AB wrap を再構成（§14）~~ **完了（`changePassword` / `changePasswordUI` 改修、test-vault-crypto 53 項目 PASS）。**

各ステップ独立にレビュー・テスト可能な粒度。envelope 根幹ゆえステップごとにバイト一致のラウンドトリップ確認を必須とする。

---

## 14. Master 変更（user.id 不変への対処 — Option A）

`user.id` は credential 作成後 *不変* だが、outer 鍵はそこに Master でラップして
格納されている（§3）。したがって Master を変更すると、既存 user.id 内のラップは
旧 Master のままで新 Master では解けなくなる。`user.id` を後から書き換える API は
WebAuthn に存在しない。

**対処（Option A）**: Master 変更時に、新 Master でラップした user.id を持つ
**新しい Passkey を 1 つ作成する**。`changePasswordUI`（→ `changePassword`）の手順:

1. 現 Passkey で再認証して PRF を取得し、MEK（business は K2）を transient に復元。
2. `encodeUserIdV7(appNameTag, outerKey, newMaster)` で新 user.id を構築し、それを
   焼いた新しい Passkey を `createPasskey`（discoverable 必須）。
3. envelope の wrap を再構成:
   - `w.a`（AC = Master+Recovery）を新 Master で再生成。
   - `w.b`（AB = Master+Passkey）を **全削除**し、新 Passkey 用の 1 個だけにする。
   - `w.c`（BC = Passkey+Recovery）に新 Passkey 用エントリを追加（Master 無関係）。
     旧 Passkey の BC wrap は残す（Master 非依存に有効、各端末の救済路）。
4. envelope を書き戻し、localStorage meta と session を新 credential に更新。

**帰結**:
- 旧 Master はどの端末でも AB 解錠に使えない（全 `w.b` が破棄されたため）。これは
  「Master を変えても旧 Master が他端末で生き続ける」問題（v6 の lazy 補完）も同時に解消する。
- 共有（同期）Passkey の場合: 新 Passkey は各端末へ自動同期される。他端末は次回、
  新 Passkey を選び新 Master を入力するだけ（Recovery 不要）。
- 端末ごとに別 Passkey の場合: 他端末は旧 Passkey の AB wrap を失うので、次回
  `Master + Recovery`（AC）または `Passkey + Recovery`（BC）で開き直し、必要なら
  その端末で新 Passkey を登録（§8）する。
- 旧 Passkey は OS / authenticator に残る（WebAuthn に削除 API はない）。AB 解錠には
  使えないので、ユーザーが端末設定から手動削除する。

**解錠時の失敗の見分け（unlock-AB）**:
- *outer 失敗*（`unlock_outer_failed_v7`）: `decodeUserIdV7` が旧 Master ラップを
  別の Master で解こうとして誤った outer 鍵を返し、外層 AES-GCM 復号が失敗する。
  Master 取り違え、または「別端末で Master 変更後に古い Passkey を選んだ」。UI は
  新パスワード入力＋「別の Passkey で開錠する」（picker）を案内する。
- *inner 失敗*（`passkey_wrong_for_vault`）: 外層は解けたが `w.b` に該当 Passkey の
  wrap が無い。UI は同じく別 Passkey を案内する。


---

## 15. hwkey の運用改善 (Phase 7.5N+ / 2026-06-02 サービスイン直後)

サービスイン (2026-06-02) 翌日の集中改修で、 v7 hwkey モードの解錠経路に複数の運用改善が入った。 envelope 自体の構造 (= §6 / §10) は変更なし。 解錠時の補助インデックス、 別 device 追加経路、 ブラウザ実装差への defensive 対処 を追加した。

### 15.1 keyslot KV 索引 — `/api/keyslot/latest` (Phase 7.5N)

#### 問題
v7 hwkey の解錠時、 client は `keyslotTag` (= user.id v7 から復号した anonymized tag) で Arweave 上の keyslot blob を探す必要がある。 §3 / §7 では公開 GraphQL を経路として想定していたが、 サービスイン後の実運用で **公開 GraphQL の indexing lag (= upload 受領後反映まで数分〜数十分)** が user 体感を直撃。 vault 作成直後の unlock で `hwkey_keyslot_not_found` 頻発。

#### 設計変更
write.js に `kind: "keyslot"` を新設し、 client は `writeKeyslot()` でこの kind を指定して書き込む。 server は `KV[ks:<tagName>:<tagValue>] = txid` を記録。 client は新 endpoint `GET /api/keyslot/latest?name=<>&value=<>` でこの索引を引く。 索引にヒットすれば即時 (≈ 数十 ms)、 ヒットしなければ公開 GraphQL fallback (= 旧 keyslot や KV 障害時の救済)。

#### ZK 影響評価
- keyslotTag は元々 Arweave tag として **公開情報** (= 誰でも Arweave GraphQL で引ける)
- txid も公開情報
- 索引は単に 「server が既知の公開情報を高速 lookup できるようにする」 だけ
- PRF / outerKey / 暗号鍵 は索引に一切含まれない
- pkHash と異なり、 user が anonymous でも `?name=&value=` で引けるため認証不要

「サーバ完全非依存」 を理由に索引化を避けていた初期方針 ([[arpass-hwkey-keyslot-indexing]] 参照) を撤回。 索引はキャッシュであり、 GraphQL fallback さえあれば 「廃業しても YubiKey で解錠」 性質は失われない。 §3 の 「公開ガテートウェイで解錠」 という invariant は維持。

### 15.2 端末追加コード (AP1 形式) — picker bug 救済 + 多端末高速セットアップ (Phase 7.5Z / ZB)

#### 動機

§7 の 「別 device 解錠」 想定では、 新 device は WebAuthn `navigator.credentials.get()` を **discoverable mode (`allowCredentials=[]`)** で呼び、 YubiKey が自身に保存された discoverable credential を返す picker get に依存していた。 ところが Android Chrome の CredentialManager API は **外部 security key の discoverable credentials を列挙する CTAP2 コマンド (`authenticatorCredentialManagement`) を未実装** で、 picker get が `NotReadableError: An unknown error occurred while talking to the credential manager` で確定的に失敗する。 Chrome 132+ で対応予定とされつつ 2026 時点も未修正、 対応時期は不明。

Mac Chrome / iPhone Safari / Windows Chrome は picker get + PRF が正常動作するため、 hwkey vault を作って解錠まで一気通貫で動く。 Android Chrome のみがこの flow から外れる。

#### 設計
Android で picker get を **完全に回避する** ため、 「端末追加コード」 という新しい補助路を導入。

##### コード形式
```
AP1.<b64u credentialId>.<keyslotTag.name>.<keyslotTag.value>
```

- `AP1` prefix = Arpass Passkey 端末追加コード v1 (= 形式識別用)
- separator は `.` (= b64u alphabet 外文字)。 初期は `-` だったが b64u 内 hyphen と衝突して flaky だったため Phase 7.5ZB で変更
- credentialId は **WebAuthn の rawId** (= 各 credential 固有の不変識別子、 YubiKey 内で生成された CTAP credential id)
- keyslotTag は §6.5 の anonymized tag (`{name, value}` の b64u 短文字列)

##### 使い方
1. 既存解錠済み端末 (= localStorage `meta.credentialId` + `meta.appNameTag` が populate された端末) で 「📲 別端末で開くコードを表示」 ボタン → 文字列 + QR で表示
2. 新端末で 「📲 端末追加コード (AP1....) で開く」 リンク → ペースト or QR 読取
3. 新端末は `localStorage.meta` に `credentialId` + `appNameTag` (= keyslotTag に相当) を保存
4. unlock 時 `hwkeyAuthenticateForUnlock` は meta から `credentialId` を取得 → **specific get** (= `allowCredentials=[{id: credentialId, transports: ["usb","nfc","ble"]}]`) で呼ぶ
5. Android Chrome は specific get なら CTAP2 listing コマンド不要 → YubiKey に 「ID=X の credential で署名して」 と直接命令、 picker 経路を完全 bypass
6. PRF 取得 → keyslot 復号 → §7 の通常 unlock fl

#### ZK / セキュリティ評価
- **credentialId**: WebAuthn 仕様上、 各 RP が認証時に YubiKey から公開で受け取る値 (= rp と credentialId のペアは secret ではない)。 第三者が credentialId を入手しても、 物理的に YubiKey をタッチしない限り PRF は取れない
- **keyslotTag**: §6.5 の通り Arweave tag として元から完全公開
- **コードに含まれない**: PRF / outerKey / MEK / Recovery / Master / signing key
- 漏洩しても vault は守られる (= YubiKey 物理タッチが必須、 第三者がコードを持っていても使えない)
- ephemeral 想定 (= 1 回貼り付けて meta 保存したら破棄) なので長期保管しない方針

#### 副次効果 — 全 platform 高速セットアップ
Android 救済を目的に設計したが、 specific get は picker get より高速 (= タッチ 1 回減る、 UI 確認時間も短縮)。 単一 YubiKey で iPhone → Mac → Win → Android と多端末展開する場合、 各端末で picker tap + 待ち時間 を コード貼付 1 回で代替できる。 当初想定外の **全 platform 価値ある UX 改善** になった。

### 15.3 iPhone Safari の `extensions` placement sensitivity (Phase 7.5ZA)

#### 観察された regression
Phase 7.5Y で `authenticateWithPasskey` の `_getPk` (= `navigator.credentials.get` の publicKey 引数) から `extensions: { prf: ... }` を object literal の外に取り出し、 条件付きで後付け代入する refactor を実施。 JS object としては **functionally identical** (= 完成形の object property は同じ) のはずだが、 user 報告で iPhone Safari NFC YubiKey の 2nd tap (= PRF 取得用) が認識されなくなる regression が発生。

#### 仮説と対処
iOS Safari の WebAuthn 実装は `publicKey` 引数 object の property placement に何らかの sensitivity を持っている (= 仕様外の挙動)。 仕様上は許されないはずの挙動だが、 実装の一致を取るため spread (`..._prfExt`) を使い literal 内で条件分岐する形に戻したところ即時復活。

#### 教訓 (= envelope v7 実装ガイドへの追記)
- WebAuthn `publicKey` 引数 object は **必ず単一の object literal で構築する**
- 条件付き field は spread (`...(cond ? { extensions: {...} } : {})`) で literal 内に embed
- 「functional equivalent な refactor」 でも iOS Safari は壊れることがある → 触らないが吉
- [[arpass-webauthn-extensions-placement]] にメモリ化

### 15.4 Android picker mode 2-tap (Phase 7.5Y) — 暫定救済

§15.2 の AP1 端末追加コードが完成する前の暫定救済として、 `hwkeyAuthenticateForUnlock` に `_isAndroidChrome()` 検知 + 2-tap 分割を実装:

- Tap 1: `skipPrfExtension: true` で PRF 無しの picker get → credentialId + userHandle を発見
- Tap 2: 発見した credentialId で specific get + PRF → 解錠

ただし console log で 「Android Chrome は PRF を抜いても picker get 自体が `NotReadableError`」 と判明し、 2-tap でも picker 経路は機能しないことが分かった。 §15.2 の AP1 コード方式が picker を完全 bypass できる根本解になったため、 7.5Y の 2-tap 分岐は実質 dead code 化したが、 将来 Android Chrome が listing コマンドを実装したとき自動的に利用される無害な防御層として残置。

### 15.5 SW 自動更新の基盤 (Phase 7.5Q + V + W) — envelope に直接関係しない補足

envelope v7 自体には影響しないが、 hwkey UX を頻繁に改修する Phase 7.5 シリーズの体験を支えるため SW 自動更新バナーの仕組みも整備:

- `sw.js` に `BUILD_ID` placeholder + `CACHE = "arpass-shell-" + BUILD_ID`
- `inject-cache-bust.mjs` が全 JS hash 集約から BUILD_ID を計算 → sw.js に書き込む
- `build-hashes.yml` workflow が sw.js + web/lib/ も commit 対象に含めるよう修正 (= 旧設定は HTML のみで sw.js 変更が repo に push されない長期バグ)

deploy ごとに sw.js のバイト列が確実に変わり、 ブラウザの `updatefound` が発火 → `pwa-install.js` の 「🔄 新しいバージョンがあります」 バナー → 1 タップで自動 reload。 envelope v7 に間接的な利益は 「user に最新の hwkey 解錠 path / バグ修正が確実に届く」 こと。

