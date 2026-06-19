<!--
====================================================================
⚠️ AUTO-GENERATED MIRROR — DO NOT PR HERE

This file is automatically synced from the private arpass repo on every
release. Direct edits to this file will be overwritten.

Source: technoblest/arpass / docs/yubikey-outer-key-redesign.md
Mirror generator: scripts/generate-arpass-spec-mirror.mjs
====================================================================
-->

# Arpass 設計メモ — YubiKey 対応 と outer 鍵の到達経路見直し

最終更新: 2026-05-23
ステータス: **設計検討中（未実装・未確定）**
担当: Yamaki / Technoblest
関連: [crypto-2of3.md](./crypto-2of3.md), [staging-setup.md](./staging-setup.md), [envelope-v7-spec.md](./envelope-v7-spec.md)（詳細仕様）

> このメモは 2026-05-23 の設計会話で収束した内容の記録。実装前。
> ローンチ時期（サービスイン前にやるか、直後にやるか）は **未決**。
> 着手前に「§5 gating items」の検証（特に iOS Safari の PRF）が必須。

---

## 0. 背景・動機

現行の 2-of-3（Master / Passkey / Recovery）には、運用上 2 つの実害がある。

1. **Recovery の紙保管が非現実的。** 家庭にプリンタが無いユーザーが多く、実際にはスクリーンショット→クラウド保存になりがち。これは安全でないうえ、紛失もしやすい。「種類と置き場所の多様性」という 2-of-3 の設計意図が現実には崩れている。
2. **新端末の初回や Passkey 不調時に Recovery が頻繁に要る。** 機種変更・端末追加・（過去のバグ起因の）Passkey 失敗のたびに Recovery 入力が必要だった。

YubiKey（複数所持を前提）を要素として取り込めば、Master 忘れと紙 Recovery の問題を構造的に解消でき、「鍵を挿す＋Master」だけでどの端末でも使える状態に近づけられる。

---

## 1. 現状の整理（2026-05-23 時点のコード）

- 要素は A=Master / B=Passkey+PRF / C=Recovery。任意 2 要素で復号（envelope の `w.a` / `w.b[]` / `w.c[]`）。
- **MEK** はランダム値。3 要素は MEK を「unlock」する（派生ではない）。
- **outer 鍵** = `HKDF(rMat)` — Recovery 由来。envelope の最外層 AES-GCM を解く鍵で、3 経路すべての前提。
- outer 鍵は localStorage の `meta.outerKey` に **生（b64u）で保存**されている（`vault-client.js` `writeMeta`）。これは Master+Passkey 経路が rMat を持たず outer 鍵を導出できないための cache。
- `appNameTag`（住所）も rMat 由来で、Passkey の WebAuthn `user.id` にも入っているが、**現状アプリは読み戻していない（休眠）**。
- WebAuthn の `createPasskey` は `authenticatorAttachment` を制約していない → YubiKey（cross-platform 認証器）は今のコードでも登録可能。PRF 拡張も要求済み。
- 帰結: **localStorage が空の新端末は、Master+Passkey が両方正しくても outer 鍵を得られず解錠不可。新端末初回は構造的に Recovery 必須。**

---

## 2. 設計目標

1. 「鍵（Passkey / YubiKey）＋ Master」で、新端末を含むどの端末でも解錠できる。新端末ごとの登録作業・localStorage 依存・Recovery 入力を不要にする。
2. outer 鍵を localStorage に生で置くのをやめる。
3. 2-of-3 の「端末を全部失っても Master+Recovery で復旧」という命綱は維持する。
4. サーバ非依存性（運営撤退後も手元の鍵だけで復号）を保つ。
5. オプションとして、Recovery も Master も持たない「YubiKey-only モード」を選べるようにする。

---

## 3. 収束した設計

### 3.1 outer 鍵を「キースロット方式」にする

outer 鍵はひとつの値。それを **要素ごとに wrap** して複数経路から到達可能にする。

- `outer 鍵` を rMat 由来鍵で wrap（= Recovery 経路）。**この経路は 2-of-3 モードでは必ず残す**（端末喪失からの命綱）。
- 同じ `outer 鍵` を各 Passkey/YubiKey の PRF 由来鍵で wrap（= 鍵経路）。
- wrap 群は外層の **外側** に置く（outer 鍵が無いと外層を開けないため）。

> 重要原則: **outer 鍵は、有効なすべての解錠経路から到達できなければならない。**
> PRF 経路は「追加」であって「Recovery 経路の置き換え」ではない。
> （PRF だけから outer 鍵を導出する案は AC 経路を壊すため不可。)

### 3.2 PRF wrap + non-extractable CryptoKey

- 保管中（at-rest）: outer 鍵は **PRF 由来鍵で暗号化した暗号文**で持つ。生では置かない。これで保管場所（localStorage / user.id / Arweave）の安全性に依存しなくなる。
- 使用中（in-memory）: 復号後の鍵は **取り出し不可 CryptoKey**（`extractable:false`）で保持（Phase 7.3-A の規律を踏襲）。
- この 2 つは別レイヤー。両方適用する。

### 3.3 Passkey が解錠経路を「運ぶ」

localStorage は端末間を移動しないが、Passkey は移動する。

- **YubiKey**: 物理的に持ち歩く → どの端末（自分の iCloud にサインインしていない端末でも）でも挿せば使える。
- **同期プラットフォーム Passkey**（iCloud Keychain / Google）: クラウド同期で自分の他端末に自動伝播。ただし鍵材料がベンダーの E2E クラウドにも乗る。

PRF-wrap した outer 鍵を Passkey と一緒に運ばせる（`user.id`、または PRF から導出した住所の小オブジェクト）ことで、新端末でも localStorage / Recovery 無しに解錠できる。

### 3.4 YubiKey を要素 B として使う

- WebAuthn の `w.b[]` / `w.c[]` は配列 = **複数 Passkey 登録に対応済**。YubiKey を複数登録できる。
- 各 YubiKey は独立した PRF（hmac-secret）を持つ → それぞれ独立したキースロットになる。
- 注意: YubiKey 2 本はどちらも「要素 B」。2-of-3 では異なる種類の 2 要素が要るため、**YubiKey 2 本だけでは解錠できない**（B+B は不可）。常に B + (A または C)。
- 新しい鍵の登録には「解錠済みであること」が必要。予備・継承用も含め早めに登録する。

### 3.5 オプション: YubiKey-only モード

- Master も Recovery も持たない、1-of-N の YubiKey 専用モード。モードは**排他選択**（弱い扉を残さない）。
- 実態は「YubiKey + PIN」の have+know 2 要素。PRF は総当たり不可、PIN は約 8 回失敗で鍵がロック。
- 作成フローで **最低 2 本の登録を必須**にする（1 本のみ＝単一障害点を防ぐ）。
- 全鍵喪失 = 復旧不可（受け入れ済みのトレードオフ）。
- 二段構え案: 各 YubiKey が PRF から自分専用の住所＋outer を導出して小さな「ポインタ・オブジェクト」を持ち、その中に共通の内部秘密（rMat 相当）を入れる。本物の Vault はその内部秘密で配置・暗号化。

---

## 4. 鍵の削除・無効化

- 物理破棄だけでは無効化にならない。envelope からその鍵の wrap を外して書き直す（ソフト削除）。
- Arweave は追記型で過去 envelope は永久に残る。盗難・紛失で**真に**無効化するには MEK / 内部秘密のローテーション＋移行が必要（タスク #100）。さらに保存済みパスワード自体の変更も推奨。

---

## 5. 未解決点・gating items（着手前に潰す）

1. **PRF 実機検証 — 完了 (2026-05-23)。結果は全面的に良好。**
   `web/prf-test.html` ＋ 実機での Arpass 動作確認の結果:
   - **YubiKey（cross-platform / セキュリティキー）の PRF: Mac Chrome / Mac Safari / iPhone Safari / Android すべてで PASS。**
   - 端末内蔵（platform）passkey の PRF: Mac Chrome / Mac Safari / iPhone Safari で PASS。
     Android（Motorola）も、実機の Arpass が内蔵 passkey の指紋タップで解錠できており PRF は動作中。
   - 注記: prf-test の「端末内蔵」ボタンは `authenticatorAttachment:"platform"` を強制しており、
     Motorola で一度「PRF 非対応」と出たが、これはテスト artifact と判明（強制 attachment が
     Arpass 実フローと別の authenticator を選んだための false negative）。Arpass 本体は
     attachment を指定せず Google パスワードマネージャの PRF 対応 passkey を使うため実機で問題なし。
   - 結論: iOS Safari ＋セキュリティキーを含め PRF は全テスト環境で動作。最大の不確実性は解消。
2. envelope フォーマットのバージョニング（外層の外に wrap 群を置く新形式）。
3. business mode（K1/K2 階層）・records ファイル（BEK）との相互作用。
4. 単一障害点 UX — YubiKey-only モードは作成時 ≥2 本必須。
5. MEK / 内部秘密のローテーション実装（#100）— 鍵削除に必須。
6. `user.id`(64 byte) の容量 — 住所 16B + PRF-wrap 後 outer 鍵(~60B) は収まらない。住所は PRF 導出にする / wrap 済 blob は別オブジェクトに置く等、配置の詰めが必要。
7. ポインタ・オブジェクトのサイズ padding（anti-fingerprint。本体 envelope と同様 ≥110 KiB 帯に揃える）。
8. 「Passkey がうまくいかなかった」のがバグ起因なら、その調査・修正は本再設計と切り離して別途行う。

---

## 6. ローンチ時期の判断（未決）

- **サービスイン前にやる利点**: ユーザーがまだ居ない＝移行（マイグレーション）不要。後からだと既存 Vault の移行処理が要る。
- **リスク**: envelope / outer / 解錠の根幹に手を入れる＝最も危険な領域。バグは永久データ消失。（iOS PRF は §5-1 で検証済。残るのは実装リスク。）
- 方針: §5-1 の実機検証と本メモを先に固め、その結果を見てから「ローンチ延期して今フル実装」か「現行 2-of-3 でローンチ → 直後に再設計（versioned envelope ＋移行）」を決める。

---

## 7. 次のステップ

1. ~~`web/prf-test.html` を staging にデプロイ → 実機 PRF 検証~~ **完了 (2026-05-23)。**
2. ~~検証結果を本メモ §5-1 に追記~~ **完了。**
3. 結果をもとにローンチ時期を決定（§6）。PRF の最大未知数は解消済。
4. ~~envelope 新形式の詳細仕様を起こす~~ **完了 → [envelope-v7-spec.md](./envelope-v7-spec.md)（実装前・レビュー待ち）。**
5. `web/prf-test.html` / `web/prf-test.js` は検証用の一時ツール。main へはマージせず、不要になったら staging からも削除する。
