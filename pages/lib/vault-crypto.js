// ============================================================================
// web/lib/vault-crypto-v5.js
//
// Arpass v5 暗号モジュール — docs/crypto-2of3.md v5 仕様の参照実装。
//
// 本ファイルは v5 envelope に関連する暗号処理だけを完全自己完結で持つ。
// (v4 cutover 完了後の唯一の暗号モジュール。旧 v2/v3/v4 関数は
//  feat/phase-5-v5-cutover で削除済み。)
//
// 設計意図:
//   - v4 envelope は破壊的変更のため互換性なし (サービス未公開)
//   - 本モジュールは v5 のみ生成・読み込み
//   - 外側 AES-GCM 層は本モジュールが管理 (HKDF(rMat) で鍵派生、Phase 7.0w-AR)
//   - 署名鍵 (ECDSA P-256) は MEK から HKDF で決定論派生 — 本モジュールが
//     @noble/curves を vendor 経由で呼び、結果を Web Crypto API の
//     CryptoKey にインポートして以降の署名は subtle.sign で行う
//   - 全ての salt / info 文字列は本ファイル冒頭に集約
// ============================================================================

import { p256, sha256, hkdf, mod, argon2idAsync } from "./vendor/noble-curves-and-hashes.mjs";

// ---------------------------------------------------------------------------
// Phase 7.5ZZ-rust-stage1-a (= 2026-06-04): Rust + WASM crypto core の遅延ロード。
//
// Stage 1 では crypto primitives を Rust + RustCrypto に統一する。 段階的に
// noble pure-JS 呼び出しを Rust 経路に切り替える設計。 失敗時は noble に
// 自動 fallback するので、 WASM 未配備の環境 (= deploy 直後 / 古い browser) でも
// 既存挙動を維持する。
//
// 詳細: docs/rust-crypto-stage1.md
// ロールバック tag: staging-pre-rust-2026-06-04
// ---------------------------------------------------------------------------

let _rustCrypto = null;
let _rustCryptoLoading = null;
let _rustCryptoFailed = false;

async function _getRustCrypto() {
  if (_rustCryptoFailed) return null;
  if (_rustCrypto) return _rustCrypto;
  if (_rustCryptoLoading) return _rustCryptoLoading;
  _rustCryptoLoading = (async () => {
    try {
      const mod = await import("./rust-crypto/arpass_crypto.js?v=864a584e");
      // wasm-bindgen が emit する default export は init 関数。 呼ぶと
      // /lib/rust-crypto/arpass_crypto_bg.wasm を fetch + instantiate する。
      await mod.default();
      _rustCrypto = mod;
      // 1 回だけ console に出して動作確認しやすくする。
      console.log("[arpass] Rust crypto core loaded (Stage 1: Argon2id)");
      return mod;
    } catch (e) {
      if (!_rustCrypto) _rustCryptoFailed = true;  // 注入済み (setRustCryptoCore) なら clobber しない
      console.warn("[arpass] Rust crypto unavailable — using noble fallback:", e?.message || e);
      return _rustCrypto || null;
    }
  })();
  return _rustCryptoLoading;
}

/**
 * テスト/node 用: 外部で初期化した Rust crypto core module を注入する。
 *   本番ブラウザは _getRustCrypto の動的 import (= /lib/rust-crypto/arpass_crypto.js) で
 *   自動ロードするため不要。 node は絶対パス import + fetch ができないので、 wasm を
 *   バイトから initSync した module をここで差し込み、 本番と同じ Rust 経路をテストする。
 * @param {object|null} mod  wasm-bindgen module namespace (initSync 済) or null
 */
export function setRustCryptoCore(mod) {
  _rustCrypto = mod || null;
  _rustCryptoFailed = false;
  _rustCryptoLoading = mod ? Promise.resolve(mod) : null;
}

// Phase 7.5ZZ-rust-stage1-b (= 2026-06-04): module init で Rust crypto core を
// fire-and-forget preload。 unlock flow が走る頃には大抵 load 済になり、 同期
// 呼び出しの hkdfBytes() / sha256_hash() が Rust 経路を使える状態になる。
// 失敗時は noble fallback を維持する。
_getRustCrypto().catch(() => { /* swallow — fallback で処理済 */ });


// ---------------------------------------------------------------------------
// 定数 — v5 envelope のすべてのアルゴリズム規定はここに集約
// ---------------------------------------------------------------------------

export const VAULT_FORMAT_V5 = 5;

// Argon2id — Master Password から pMat を導出 (Phase 7.4: PBKDF2 から移行)
//
// OWASP 2023 推奨パラメータ:
//   - memorySize: 64 MiB (モバイル端末対応の最低ライン、推奨)
//   - iterations: 3
//   - parallelism: 4
//   - hashLength: 32 bytes
//
// PBKDF2-SHA256 600k iter からの移行理由:
//   - PBKDF2 は memory-hard でないため GPU/ASIC で大量並列攻撃が容易
//   - Argon2id は memory-hard で並列攻撃に強い (RTX 4090 で 1000x 程度遅くなる)
//   - Recovery Secret 漏洩 + 弱い Master の組み合わせ攻撃に対する耐性向上
const ARGON2_MEMORY_KIB = 64 * 1024;  // 64 MiB
const ARGON2_ITERATIONS = 3;
const ARGON2_PARALLELISM = 4;
const ARGON2_HASH_LEN = 32;
const SALT_LEN_BYTES = 16;

// Phase 7.4.1: KDF パラメータを envelope に埋め込み、将来 Argon2id を強化しても
// 旧 vault が解読できるようにする (forward-compat)。
//   - CURRENT_KDF_PARAMS: 新規 envelope を作るときの既定値。将来ここを上げると
//     新しい vault は強い KDF で守られるが、既存 vault は envelope.kdfParams に
//     記録された当時のパラメータで復号できる。
//   - USERID_KDF_PARAMS: user.id (WebAuthn userHandle) の outer 鍵ラップに使う
//     固定値。user.id は credential 作成後不変なので、ここは絶対に変えない値を
//     別に持つ。強化したい場合は USERID_V7_VERSION を 8 に上げる別経路で行う。
// validateKdfParams: downgrade attack (= envelope.kdfParams を弱いパラメータに
//   書き換える) を防ぐためのレンジ制約。 m: 32MiB-512MiB, t: 1-16, p: 1-16,
//   dkLen: 32 固定。
const CURRENT_KDF_PARAMS = Object.freeze({
  alg: "argon2id",
  m: ARGON2_MEMORY_KIB,
  t: ARGON2_ITERATIONS,
  p: ARGON2_PARALLELISM,
  dkLen: ARGON2_HASH_LEN,
});
const USERID_KDF_PARAMS = Object.freeze({
  alg: "argon2id",
  m: 64 * 1024,  // 固定 64 MiB
  t: 3,          // 固定
  p: 4,          // 固定
  dkLen: 32,     // 固定
});

/**
 * envelope.kdfParams のバリデーション。 downgrade attack を防ぐレンジ制約。
 * @param {object} p
 * @returns {object} validated params
 */
export function validateKdfParams(p) {
  if (!p || typeof p !== "object")
    throw new Error("kdfParams: object required");
  if (p.alg !== "argon2id")
    throw new Error(`kdfParams: unsupported alg ${p.alg} (expected argon2id)`);
  if (!Number.isInteger(p.m) || p.m < 32 * 1024 || p.m > 512 * 1024)
    throw new Error(`kdfParams: m out of range [32MiB, 512MiB] KiB, got ${p.m}`);
  if (!Number.isInteger(p.t) || p.t < 1 || p.t > 16)
    throw new Error(`kdfParams: t out of range [1, 16], got ${p.t}`);
  if (!Number.isInteger(p.p) || p.p < 1 || p.p > 16)
    throw new Error(`kdfParams: p out of range [1, 16], got ${p.p}`);
  if (!Number.isInteger(p.dkLen) || p.dkLen !== 32)
    throw new Error(`kdfParams: dkLen must be 32, got ${p.dkLen}`);
  return p;
}

/** @returns {object} 新規 envelope に書き込むべき kdfParams (mutable copy) */
export function getCurrentKdfParams() {
  return { ...CURRENT_KDF_PARAMS };
}

// AES-GCM
const AES_KEY_BITS = 256;
const AES_IV_LEN = 12;
const AES_TAG_LEN = 16;

// HKDF salt / info — 用途ごとに固定文字列。後方互換性が無くなるので変更厳禁。
const HKDF_SALTS = {
  recovery_material:  "arpass-recovery-v1",
  passkey_material:   "arpass-passkey-prf-v1",
  // Phase 7.0w-AR: vault-id 概念を廃止 → outer key を rMat から直接派生 (v6 ドメイン分離)
  app_tag_name:       "arpass-app-tag-name-v6",
  app_tag_value:      "arpass-app-tag-value-v6",
  outer_key:          "arpass-outer-v6",
  signing_key:        "arpass-signing-key-v5",
  kek_pr:             "arpass-kek-pr-v1",
  kek_pk:             "arpass-kek-pk-v1",
  kek_kr:             "arpass-kek-kr-v1",
  recovery_protect:   "arpass-recovery-protect-v1",
  // envelope v7 (docs/envelope-v7-spec.md): outer 鍵を Passkey の user.id が運ぶ
  mek_wrap_v7:            "arpass-mek-wrap-v7",
  keyslot_v7:             "arpass-keyslot-v7",
};

const HKDF_INFOS = {
  recovery_material:  "recovery-material",
  passkey_material:   "passkey-material",
  app_tag_name:       "app-tag-name",
  app_tag_value:      "app-tag-value",
  outer_key:          "envelope-wrap",
  signing_key:        "p256-keypair",
  kek_pr:             "kek-pr",
  kek_pk:             "kek-pk",
  kek_kr:             "kek-kr",
  recovery_protect:   "recovery-protect",
  // envelope v7
  mek_wrap_v7:            "mek-wrap",
  keyslot_v7:             "keyslot-wrap",
};

// Padding バケット (本体 c のサイズを統一するため、エントリ数の推測を防ぐ)。
//
// Phase 6.7 (2026-05-06): on-chain 110 KiB ターゲットに最適化。
//   raw 80 KiB → base64 1.33× → on-chain 約 106-117 KiB (jitter 込み)
//   平均コスト ~¥0.33/write。Turbo 無料枠 100 KiB を最小ケースでも超える。
//
// これにより以下を同時に達成する:
//   (a) フィンガープリント耐性: tx サイズで Arpass vault を一発抽出できない
//   (b) フリーライド回避: 全 write が Turbo の有料 tier に入り、AUP 違反リスクを排除
//   (c) サイズ秘匿: エントリ数の増減が外部に漏れない
//   (d) コスト最小化: 過去 120 KiB raw (¥0.47/write) → 80 KiB raw (¥0.33/write) で 30% 圧縮
//
// 履歴:
//   v5.0 cutover: `[4 KiB, 16 KiB, ...]` に退化 (a)(b) 破綻 — Phase 5.2 で修正
//   Phase 5.2:    `[120 KiB, ...]` に復元 (a)(b)(c) 達成、コスト ¥0.47/write
//   Phase 6.7:    `[80 KiB, ...]` に再設計 (a)(b)(c)(d) 達成、コスト ¥0.33/write
const PAD_BUCKETS = [80 * 1024, 160 * 1024, 240 * 1024];
// バケットに加算するランダムジッタ。同一ユーザーの連続書き込みでも tx サイズが
// 揺らぐので「サイズ X = Arpass」という size-based フィンガープリントが成立しない。
// raw 80 KiB + 0..8 KiB → on-chain 106-117 KiB の範囲で揺らぐ。
const PAD_JITTER_BYTES = 8 * 1024;  // 0..PAD_JITTER_BYTES の範囲で加算
const PAD_TERMINATOR = 0x80;

// ---------------------------------------------------------------------------
// base64url ヘルパー
// ---------------------------------------------------------------------------

const enc = new TextEncoder();
const dec = new TextDecoder();

export function b64uEncode(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64uDecode(str) {
  const pad = "===".slice(0, (4 - (str.length % 4)) % 4);
  const b64 = (str + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function concatBytes(...arrs) {
  let total = 0;
  for (const a of arrs) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

// ---------------------------------------------------------------------------
// HKDF / HMAC ベースの派生 (noble-hashes の hkdf を使う、Web Crypto より柔軟)
// ---------------------------------------------------------------------------

function hkdfBytes(ikm, salt, info, length) {
  // Phase 7.5ZZ-rust-stage1-b (= 2026-06-04): Rust + WASM (= RustCrypto hkdf)
  // を優先呼び出し。 module-level の _rustCrypto キャッシュが load 済なら
  // 同期 call、 未 load なら noble に fallback。 _getRustCrypto() は module
  // init 時に fire-and-forget で preload しているので、 unlock flow の頃には
  // 大抵 load 済になっている。
  if (_rustCrypto && typeof _rustCrypto.hkdf_sha256 === "function") {
    try {
      const ikmBytes = ikm instanceof Uint8Array ? ikm : new Uint8Array(ikm);
      const saltBytes = (typeof salt === "string") ? enc.encode(salt)
                       : (salt instanceof Uint8Array ? salt : new Uint8Array(salt));
      const infoBytes = (typeof info === "string") ? enc.encode(info)
                       : (info instanceof Uint8Array ? info : new Uint8Array(info));
      return _rustCrypto.hkdf_sha256(ikmBytes, saltBytes, infoBytes, length);
    } catch (e) {
      console.warn("[arpass] Rust HKDF failed, using noble:", e?.message || e);
    }
  }
  return hkdf(sha256, ikm, enc.encode(salt), enc.encode(info), length);
}

// ---------------------------------------------------------------------------
// 各認証要素の素材 (P/K/R) → 32 byte
// ---------------------------------------------------------------------------

/**
 * Master Password を Argon2id で 32-byte の pMat に伸ばす。
 * salt は envelope.s をそのまま使う (vault ごとにランダム)。
 *
 * Phase 7.4: PBKDF2-SHA256 600k iter から Argon2id に移行 (memory-hard KDF)。
 * Phase 7.4.1: 第3引数で envelope.kdfParams を渡せるように。省略時は
 *   CURRENT_KDF_PARAMS (= 新規 envelope 用の既定値)。
 * 既存 vault 互換性なし (pre-release のため legacy 不要)。
 *
 * @param {string} passwordString
 * @param {Uint8Array} saltBytes
 * @param {object} kdfParams  envelope.kdfParams or USERID_KDF_PARAMS (required, no fallback)
 *
 * Phase 7.4.1: kdfParams を必須化 (strict)。 旧 envelope (kdfParams 不在) は throw。
 *   サービスイン前なので dev 期 envelope を意図的に切る。 新規 envelope は
 *   encryptVault / encryptVaultBusiness / changePassword 経路で必ず kdfParams が
 *   埋まるので影響なし。 user.id outer wrap は USERID_KDF_PARAMS を明示的に渡す。
 */
export async function derivePMat(passwordString, saltBytes, kdfParams) {
  if (!kdfParams)
    throw new Error("derivePMat: kdfParams required (envelope.kdfParams missing — pre-launch dev envelope?)");
  const params = validateKdfParams(kdfParams);
  const pwBytes = enc.encode(passwordString);

  // Phase 7.5ZZ-rust-stage1-a: Rust + WASM (RustCrypto argon2) を優先。
  // 失敗時は @noble/hashes/argon2 に fallback。 同じ kdfParams で
  // bit-identical な出力が出ることが Argon2 spec 保証されている。
  const rust = await _getRustCrypto();
  if (rust && typeof rust.argon2id_derive === "function") {
    try {
      return rust.argon2id_derive(
        pwBytes, saltBytes,
        params.m, params.t, params.p, params.dkLen
      );
    } catch (e) {
      // 異常時は noble に fallback (= envelope を壊さない安全策)。
      console.warn("[arpass] Rust Argon2id failed, falling back to noble:", e?.message || e);
    }
  }

  // Fallback: @noble/hashes/argon2 (= async variant、 setTimeout で yield)
  const out = await argon2idAsync(pwBytes, saltBytes, {
    t: params.t,
    m: params.m,
    p: params.p,
    dkLen: params.dkLen,
  });
  return new Uint8Array(out);
}

/**
 * WebAuthn PRF 出力を HKDF で 32-byte の kMat に整形。
 */
export function deriveKMat(prfOutputBytes) {
  return hkdfBytes(prfOutputBytes, HKDF_SALTS.passkey_material, HKDF_INFOS.passkey_material, 32);
}

/**
 * Recovery Secret 文字列を HKDF で 32-byte の rMat に整形。
 */
/**
 * Secret Scanning 照合用: Recovery 文字列 (RS1-...) を正規化 → SHA-256 hex。
 *   server functions/_lib/recovery-hash.js recoveryHashHex と **バイト等価** であること。
 *   (deriveRMat と同じ正規化、 ただし HKDF せず生文字列の SHA-256)。
 * @param {string} recoveryString
 * @returns {Promise<string>} 64-char lowercase hex
 */
export async function recoveryStringToHashHex(recoveryString) {
  const normalized = (recoveryString || "")
    .replace(/[\u2010-\u2015\u2212\uFF0D\u2043\u2027]/g, "-")
    .replace(/\s+/g, "")
    .toUpperCase();
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(normalized)));
  return Array.from(digest).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function deriveRMat(recoveryString) {
  // 文字列は normalize して大文字化、空白除去 (parseRecoverySecret の前段相当)。
  //   修正(2026-06): 画像/印刷/フォント/OCR/コピペ経由で通常ハイフン(-) が
  //   各種 Unicode ダッシュ (— em-dash, – en-dash, − minus, － 全角, ‐ hyphen 等) に
  //   化けることがある。 recovery key は ASCII hyphen で生成される (generateRecoverySecret)
  //   ため、 入力側の各種ダッシュを ASCII '-' に正規化する。 canonical (ASCII '-') キーは
  //   不変なので既存 vault に影響なし。
  const normalized = (recoveryString || "")
    .replace(/[\u2010-\u2015\u2212\uFF0D\u2043\u2027]/g, "-")
    .replace(/\s+/g, "")
    .toUpperCase();
  return hkdfBytes(enc.encode(normalized), HKDF_SALTS.recovery_material, HKDF_INFOS.recovery_material, 32);
}

// ---------------------------------------------------------------------------
// Arweave タグ (rMat-derived name + value), outer_key の派生
// ---------------------------------------------------------------------------
//
// Phase 7.0w-AR (2026-05-11 cutover):
//   - vault-id 概念を完全廃止 (16 byte 中間鍵不要、UI 表示も削除)
//   - Outer AES-GCM 鍵は rMat から **直接** HKDF 派生 (salt "arpass-outer-v6")
//   - Arweave タグは name / value の両方を rMat 派生のランダム文字列に
//       → 旧固定 "App-Name" タグ名による fingerprint 攻撃を遮断
//       → 観測者は「Arpass を使っているか」「Arpass tx 群はどれか」を
//          グローバル GraphQL から特定できなくなる
//   - サービス未公開のため migration 不要 (既存テストデータは破棄)
//
//   tier qualifier の仕組み (Phase 6.4 の発展):
//     free/paid/private : "::free" / "::paid" / "::private"
//     corp::<companyId> : "::corp::<companyId>"
//   tier ごとに name と value が両方変わる。tier transition で観測者は再 harvest が必要。
//   Phase 7.4.1: legacy (tier 無し) 派生は廃止 — dev 期 envelope 救済不可。

/**
 * Arweave タグの name と value を rMat から両方派生 (両方ランダム化)。
 *
 * @param {Uint8Array} recoveryMaterial
 * @param {string|null} [tier=null] - "free" | "paid" | "private" | "corp::<companyId>" | null (bootstrap)
 * @returns {{ name: string, value: string }} 両方 base64url、name 11 文字、value 22 文字
 *
 * tier=null は vault 作成直後の bootstrap window 用 (= /api/balance で実 tier が
 *   分かる前の暫定値)。 refreshTierQualifier 後は free/paid/private/corp に移行する。
 */
export function deriveAppNameTag(recoveryMaterial, tier = null) {
  const tierSuffix = tier ? `::${tier}` : "";
  const nameInfo = `${HKDF_INFOS.app_tag_name}${tierSuffix}`;
  const valInfo  = `${HKDF_INFOS.app_tag_value}${tierSuffix}`;
  // name: 8 bytes → b64url 11 chars (no fixed prefix, full anonymization)
  const nameBytes = hkdfBytes(recoveryMaterial, HKDF_SALTS.app_tag_name, nameInfo, 8);
  // value: 16 bytes → b64url 22 chars
  const valBytes  = hkdfBytes(recoveryMaterial, HKDF_SALTS.app_tag_value, valInfo, 16);
  return { name: b64uEncode(nameBytes), value: b64uEncode(valBytes) };
}

/**
 * Phase 7.3-A.8 part 2d: rMatHkdfKey (= 非 extractable HKDF base CryptoKey) から
 *   appNameTag を派生する CryptoKey 版。 deriveAppNameTag と完全互換 (= 同じ bytes 出力)。
 *   _session.recoveryMaterial (raw) を介さずに動かすための足場。
 *
 * @param {CryptoKey} rMatHkdfKey
 * @param {string|null} [tier=null]
 * @returns {Promise<{name: string, value: string}>}
 */
export async function deriveAppNameTagFromHkdf(rmatHandle, tier = null) {
  // handle 化: RMatKey opaque handle.derive_bytes で HKDF (CryptoKey deriveBits 廃止)。
  //   bit-equiv: derive_bytes = hkdf_sha256(rMat, salt, info, len) = 旧 deriveBits / deriveAppNameTag(raw) と同一。
  if (!rmatHandle || typeof rmatHandle.derive_bytes !== "function")
    throw new Error("deriveAppNameTagFromHkdf: RMatKey opaque handle 必須");
  const tierSuffix = tier ? `::${tier}` : "";
  const nameInfo = `${HKDF_INFOS.app_tag_name}${tierSuffix}`;
  const valInfo  = `${HKDF_INFOS.app_tag_value}${tierSuffix}`;
  const nameBuf = rmatHandle.derive_bytes(enc.encode(HKDF_SALTS.app_tag_name), enc.encode(nameInfo), 8);
  const valBuf  = rmatHandle.derive_bytes(enc.encode(HKDF_SALTS.app_tag_value), enc.encode(valInfo), 16);
  return { name: b64uEncode(new Uint8Array(nameBuf)), value: b64uEncode(new Uint8Array(valBuf)) };
}

/**
 * 並列 vault 発見用に全 tier のタグを一括計算。
 * 新端末で初開錠する際、現所属 (free/paid/private/corp::<id>) が分からない時点でも
 * これら全てを GraphQL で並列検索 → 最新 tx を採用。
 *
 * @param {Uint8Array} recoveryMaterial
 * @param {string|null} [currentCompanyId=null] - 現所属 corp::<id> を含めるなら指定
 * @returns {{
 *   free: {name,value},
 *   paid: {name,value},
 *   private: {name,value},
 *   corp: {name,value}|null
 * }}
 *
 * Phase 7.4.1: legacy エントリ (= 旧 Phase 6.4 以前の tier 無し HKDF info) を削除。
 *   dev 期に作られた legacy tag を使う envelope はもう発見できないため復号不可。
 *   サービスイン前の意図的な break。
 */
export function deriveAllAppNameTags(recoveryMaterial, currentCompanyId = null) {
  return {
    free:    deriveAppNameTag(recoveryMaterial, "free"),
    paid:    deriveAppNameTag(recoveryMaterial, "paid"),
    private: deriveAppNameTag(recoveryMaterial, "private"),
    corp:    currentCompanyId ? deriveAppNameTag(recoveryMaterial, `corp::${currentCompanyId}`) : null,
  };
}

// ---------------------------------------------------------------------------
// ECIES (Elliptic Curve Integrated Encryption Scheme) — Phase 7.1
// ---------------------------------------------------------------------------
//
// 「相手の公開鍵で暗号化、相手の秘密鍵でしか復号できない」 1-shot 暗号。
// Business mode で社員 → admin への Recovery 送付、admin → 社員への
// Recovery 配信、両方向で使う。
//
// アルゴリズム: P-256 ECDH + HKDF-SHA256 + AES-GCM
//   1. sender: ephemeral P-256 keypair 生成 (= 1 度しか使わない使い捨て)
//   2. shared = ECDH(ephemeral.privateKey, recipient.publicKey)
//   3. kek = HKDF(shared, salt="arpass-ecies-v1", info="kek", L=32)
//   4. ct = AES-GCM(kek, iv, plaintext)
//   5. 送信: { ephemeralPublicKey, iv, ciphertext }
//   6. recipient: shared = ECDH(my.privateKey, ephemeral.publicKey) → 同じ kek
//
// 既存の noble-curves `p256.getSharedSecret` で ECDH をサポート済。

const ECIES_HKDF_SALT = "arpass-ecies-v1";
const ECIES_HKDF_INFO = "kek";

/**
 * ECIES encryption.
 *
 * @param {Uint8Array} recipientPublicKeyRaw  65-byte uncompressed P-256 pubKey (0x04 prefix)
 * @param {Uint8Array} plaintext              任意長の平文 bytes
 * @returns {Promise<{
 *   ephemeralPublicKey: Uint8Array(65),  // 65-byte uncompressed
 *   iv:                 Uint8Array(12),
 *   ciphertext:         Uint8Array       // = AES-GCM ciphertext + tag
 * }>}
 */
export async function eciesEncrypt(recipientPublicKeyRaw, plaintext) {
  if (!(recipientPublicKeyRaw instanceof Uint8Array) || recipientPublicKeyRaw.length !== 65 || recipientPublicKeyRaw[0] !== 0x04) {
    throw new Error("eciesEncrypt: recipientPublicKeyRaw must be 65-byte uncompressed P-256 pubKey (0x04 prefix)");
  }
  if (!(plaintext instanceof Uint8Array)) {
    throw new Error("eciesEncrypt: plaintext must be Uint8Array");
  }

  // 1. Ephemeral keypair — Stage 2a: Rust + WASM 優先、 noble fallback
  //   Rust 戻り値: 32 byte priv || 65 byte pub (= SEC1 uncompressed)
  let ephemeralPriv, ephemeralPublicKey;
  if (_rustCrypto && typeof _rustCrypto.p256_keypair_generate === "function") {
    try {
      const kp = _rustCrypto.p256_keypair_generate();
      ephemeralPriv = kp.slice(0, 32);
      ephemeralPublicKey = kp.slice(32);  // 65 byte (= 0x04 || X || Y)
    } catch (e) {
      console.warn("[arpass] Rust p256 keypair_generate failed, using noble:", e?.message || e);
      ephemeralPriv = null;
    }
  }
  if (!ephemeralPriv) {
    // Noble fallback: scalar gen + Point.BASE multiply
    const ephemeralPrivBn = (() => {
      const n = p256.Point.Fn.ORDER;
      let d;
      do {
        const b = crypto.getRandomValues(new Uint8Array(32));
        d = BigInt("0x" + Array.from(b).map(x => x.toString(16).padStart(2, "0")).join(""));
      } while (d === 0n || d >= n);
      return d;
    })();
    ephemeralPriv = new Uint8Array(32);
    let bn = ephemeralPrivBn;
    for (let i = 31; i >= 0; i--) {
      ephemeralPriv[i] = Number(bn & 0xffn);
      bn >>= 8n;
    }
    const ephemeralPubPoint = p256.Point.BASE.multiply(ephemeralPrivBn);
    ephemeralPublicKey = ephemeralPubPoint.toBytes(false);  // 65-byte uncompressed
  }

  // 2. ECDH shared secret — Stage 2a: Rust 優先、 noble fallback
  //   Rust 戻り値: 32 byte X-coord (= IKM 直接)、 slice 不要
  //   Noble 戻り値: 65 byte uncompressed point → .slice(1, 33) で X 取り出し
  let sharedX;
  if (_rustCrypto && typeof _rustCrypto.p256_ecdh === "function") {
    try {
      sharedX = _rustCrypto.p256_ecdh(ephemeralPriv, recipientPublicKeyRaw);
    } catch (e) {
      console.warn("[arpass] Rust p256 ECDH failed, using noble:", e?.message || e);
      sharedX = null;
    }
  }
  if (!sharedX) {
    const shared = p256.getSharedSecret(ephemeralPriv, recipientPublicKeyRaw, false);
    sharedX = shared.slice(1, 33);
  }

  // 3+4. #3 Part B: KEK を WASM 内で派生 (MekKey handle) → AES-GCM encrypt。
  //   raw KEK は JS heap に出ない (= _eciesAesKeyFromSharedX が derive_kek_handle 経由)。
  const kekKey = await _eciesAesKeyFromSharedX(sharedX, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const ct = await aesGcmEncrypt(kekKey, iv, plaintext);

  // 5. Zeroize ephemeral private key + sharedX。 KEK handle は free (CryptoKey は GC)。
  ephemeralPriv.fill(0);
  sharedX.fill(0);
  if (kekKey && typeof kekKey.free === "function") { try { kekKey.free(); } catch (_) {} }

  return { ephemeralPublicKey, iv, ciphertext: ct };
}

/**
 * ECIES decryption.
 *
 * @param {Uint8Array} myPrivateKeyRaw       32-byte P-256 private scalar
 * @param {object}     payload               { ephemeralPublicKey, iv, ciphertext }
 * @returns {Promise<Uint8Array>}            plaintext bytes
 */
export async function eciesDecrypt(myPrivateKeyRaw, payload) {
  const { ephemeralPublicKey, iv, ciphertext } = payload;
  if (!(myPrivateKeyRaw instanceof Uint8Array) || myPrivateKeyRaw.length !== 32) {
    throw new Error("eciesDecrypt: myPrivateKeyRaw must be 32-byte P-256 private scalar");
  }
  if (!(ephemeralPublicKey instanceof Uint8Array) || ephemeralPublicKey.length !== 65 || ephemeralPublicKey[0] !== 0x04) {
    throw new Error("eciesDecrypt: ephemeralPublicKey must be 65-byte uncompressed P-256 pubKey");
  }

  // 1. ECDH shared secret — Stage 2a: Rust 優先、 noble fallback
  let sharedX;
  if (_rustCrypto && typeof _rustCrypto.p256_ecdh === "function") {
    try {
      sharedX = _rustCrypto.p256_ecdh(myPrivateKeyRaw, ephemeralPublicKey);
    } catch (e) {
      console.warn("[arpass] Rust p256 ECDH failed, using noble:", e?.message || e);
      sharedX = null;
    }
  }
  if (!sharedX) {
    const shared = p256.getSharedSecret(myPrivateKeyRaw, ephemeralPublicKey, false);
    sharedX = shared.slice(1, 33);
  }

  // 2+3. #3 Part B: KEK を WASM 内で派生 (MekKey handle) → AES-GCM decrypt。
  //   raw KEK は JS heap に出ない。 HKDF は eciesEncrypt と同一スキームで既存暗号文と互換。
  const kekKey = await _eciesAesKeyFromSharedX(sharedX, ["decrypt"]);
  let pt;
  try {
    pt = await aesGcmDecrypt(kekKey, iv, ciphertext);
  } catch (e) {
    sharedX.fill(0);
    if (kekKey && typeof kekKey.free === "function") { try { kekKey.free(); } catch (_) {} }
    throw new Error("eciesDecrypt: AES-GCM decryption failed (wrong recipient key or tampered payload)");
  }

  sharedX.fill(0);
  if (kekKey && typeof kekKey.free === "function") { try { kekKey.free(); } catch (_) {} }
  return pt;
}

/**
 * 公開鍵 fingerprint (b64u(SHA-256(pubkey_raw))) を生成。
 * Business mode の invite URL に admin の fingerprint を埋めて、
 * 社員 signup 時の TOFU 攻撃を防ぐために使う。
 *
 * @param {Uint8Array} publicKeyRaw  65-byte uncompressed P-256 pubKey
 * @returns {Promise<string>}        b64u SHA-256 hash (~43 chars), short form 16 chars 推奨
 */
export async function publicKeyFingerprint(publicKeyRaw, length = 16) {
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", publicKeyRaw));
  return b64uEncode(hash).slice(0, length);
}

/**
 * 外側 AES-GCM 層の鍵 (32 byte) — rMat 直接派生 (Phase 7.0w-AR で vault-id 削除)。
 *
 * @param {Uint8Array} recoveryMaterial rMat (32 byte)
 * @returns {Uint8Array} 32-byte AES-GCM raw key bytes (caller responsibility to import)
 */
export function deriveOuterKeyBytes(recoveryMaterial) {
  return hkdfBytes(recoveryMaterial, HKDF_SALTS.outer_key, HKDF_INFOS.outer_key, 32);
}

/**
 * Stage 2c Stage D: rMat を Rust RMatKey opaque handle として import (= WASM 内に閉じ込め)。
 * raw bytes が JS heap に出ない経路で outer / mek / k1 等を派生可能になる。
 * Rust crypto core 未 load 時は null を返す (= caller は rMatHkdfKey CryptoKey 経路を使う)。
 *
 * @param {Uint8Array} rMatRaw 32 byte
 * @returns {Promise<object|null>} RMatKey handle or null
 */
export async function importRMatAsHandle(rMatRaw) {
  if (!(rMatRaw instanceof Uint8Array) || rMatRaw.length !== 32)
    throw new Error("rMatRaw must be 32 byte Uint8Array");
  const rc = await _getRustCrypto();
  if (!rc || typeof rc.RMatKey !== "function") return null;
  return new rc.RMatKey(rMatRaw);
}

/**
 * Stage 2c Stage D: RMatKey handle から OuterKey handle を WASM 内部派生 (= raw 露出ゼロ)。
 * WebCrypto deriveOuterKeyFromHkdf と構造的同等 (= 全 derive が native heap 内で完結)。
 *
 * @param {object} rmatHandle RMatKey handle
 * @returns {object} OuterKey handle
 */
export function deriveOuterKeyFromRMat(rmatHandle) {
  if (!rmatHandle || typeof rmatHandle.derive_outer_key !== "function")
    throw new Error("deriveOuterKeyFromRMat: invalid RMatKey handle");
  return rmatHandle.derive_outer_key(
    enc.encode(HKDF_SALTS.outer_key),
    enc.encode(HKDF_INFOS.outer_key),
  );
}

/**
 * Stage 2c Stage D3: outer key の raw 32 byte を Rust OuterKey opaque handle に変換。
 * AB unlock path (= user.id from Master-wrap) で直接 raw bytes を取得した時の wrap 用。
 * 呼出元は raw bytes を即 zeroize すべき。
 * Rust crypto core 未 load 時は null 返却 → caller は raw bytes を使う。
 *
 * @param {Uint8Array} outerKeyBytes 32 byte
 * @returns {Promise<object|null>} OuterKey handle or null
 */
export async function importOuterKeyAsHandle(outerKeyBytes) {
  if (!(outerKeyBytes instanceof Uint8Array) || outerKeyBytes.length !== 32)
    throw new Error("outerKeyBytes must be 32 byte Uint8Array");
  const rc = await _getRustCrypto();
  if (!rc || typeof rc.OuterKey !== "function") return null;
  return new rc.OuterKey(outerKeyBytes);
}

/**
 * Stage 2c Stage G2: MEK の raw 32 byte を Rust MekKey opaque handle に変換。
 * derivePersonalMekHkdfKey / deriveBusinessMekHkdfKey の呼出直前で raw mek
 * bytes が JS heap に一瞬存在するタイミングで、 並列 populate に使う。
 * 既存 mekHkdfKey CryptoKey 設計を維持しつつ MekKey handle を session に
 * 持たせることで、 後続 stage の consumer 移行で Rust path 利用可能になる。
 *
 * caller は raw bytes を即 zeroize すべき。
 * Rust crypto core 未 load 時は null 返却。
 *
 * @param {Uint8Array} mekRaw 32 byte
 * @returns {Promise<object|null>} MekKey handle or null
 */
export async function importMekRawAsHandle(mekRaw) {
  if (!(mekRaw instanceof Uint8Array) || mekRaw.length !== 32)
    throw new Error("mekRaw must be 32 byte Uint8Array");
  const rc = await _getRustCrypto();
  if (!rc || typeof rc.MekKey !== "function") return null;
  return new rc.MekKey(mekRaw);
}

/**
 * Stage 2c Stage G3: K1 の raw 32 byte を Rust K1Key opaque handle に変換。
 * business mode で K1 を ECIES unwrap した直後のタイミングで使用想定。
 * caller は raw bytes を即 zeroize すべき。
 *
 * @param {Uint8Array} k1Bytes 32 byte
 * @returns {Promise<object|null>} K1Key handle or null
 */
export async function importK1RawAsHandle(k1Bytes) {
  if (!(k1Bytes instanceof Uint8Array) || k1Bytes.length !== 32)
    throw new Error("k1Bytes must be 32 byte Uint8Array");
  const rc = await _getRustCrypto();
  if (!rc || typeof rc.K1Key !== "function") return null;
  return new rc.K1Key(k1Bytes);
}

/**
 * Stage 2c Stage G4: BEK の raw 32 byte を Rust BekKey opaque handle に変換。
 * file 添付の generate 直後のタイミングで使用想定。
 * caller は raw bytes を即 zeroize すべき。
 *
 * @param {Uint8Array} bekBytes 32 byte
 * @returns {Promise<object|null>} BekKey handle or null
 */
export async function importBekRawAsHandle(bekBytes) {
  if (!(bekBytes instanceof Uint8Array) || bekBytes.length !== 32)
    throw new Error("bekBytes must be 32 byte Uint8Array");
  const rc = await _getRustCrypto();
  if (!rc || typeof rc.BekKey !== "function") return null;
  return new rc.BekKey(bekBytes);
}

/** Stage 2c Stage G4 v2 (2026-06-06): Rust BekKey.generate() を直接呼ぶ。
 *  raw bytes は WASM 内で getrandom() 生成 → JS heap に一切露出しない。
 *  caller は handle を受け取り、 不要時に .free() を呼ぶ。
 *  rust-crypto 未ロード時は null。 */
export async function generateBekHandleViaRust() {
  const rc = await _getRustCrypto();
  if (!rc || typeof rc.BekKey?.generate !== "function") return null;
  return rc.BekKey.generate();
}

/** Stage G4 v2: BekKey handle で AES-GCM encrypt (= file 暗号化)。 */
export async function encryptWithBekHandle(bekHandle, iv, plaintext, aad = new Uint8Array(0)) {
  if (!bekHandle) throw new Error("encryptWithBekHandle: bekHandle required");
  return bekHandle.aes_gcm_encrypt(iv, plaintext, aad);
}

/** Stage G4 v2: BekKey handle で AES-GCM decrypt。 */
export async function decryptWithBekHandle(bekHandle, iv, ciphertext, aad = new Uint8Array(0)) {
  if (!bekHandle) throw new Error("decryptWithBekHandle: bekHandle required");
  return bekHandle.aes_gcm_decrypt(iv, ciphertext, aad);
}

/** Stage G4 v2: MekKey で BekKey handle を wrap (= envelope.records[].wrappedBEK)。
 *  返却: { wrapped: Uint8Array, iv: Uint8Array }。 */
export async function wrapBekWithMekHandle(mekHandle, bekHandle) {
  if (!mekHandle || !bekHandle) throw new Error("wrapBekWithMekHandle: handles required");
  const iv = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const wrapped = mekHandle.wrap_bek(bekHandle, iv);
  return { wrapped, iv };
}

/** Stage G4 v2: MekKey で wrapped BEK を unwrap して BekKey handle 返却。 */
export async function unwrapBekWithMekHandle(mekHandle, wrapped, iv) {
  if (!mekHandle) throw new Error("unwrapBekWithMekHandle: mekHandle required");
  return mekHandle.unwrap_bek(wrapped, iv);
}
// ---------------------------------------------------------------------------
// 外側 AES-GCM 層 — Arweave に書き込む blob の生成・復号
// ---------------------------------------------------------------------------

/**
 * envelope オブジェクトを JSON 化し、rMat 派生鍵で AES-GCM 暗号化して
 * 12+N+16 byte の blob を返す。これが Arweave に実際に書き込まれるバイト列。
 *
 * @param {object} envelopeObj
 * @param {Uint8Array} outerKeyBytes 32-byte raw AES-GCM key (deriveOuterKeyBytes(rMat) で取得)
 */
export async function wrapEnvelopeOuter(envelopeObj, outerKeyOrBytes) {
  // Stage 2c (= 2026-06-05): raw bytes path で Rust AES-GCM を使う。
  //   - outerKeyOrBytes が Uint8Array → 直接 aesGcmEncrypt (= dispatcher が
  //     Rust path 選択、 CryptoKey import 不要)
  //   - outerKeyOrBytes が CryptoKey → 既存通り WebCrypto path
  //   両 path とも同じ envelope blob format (= IV || ciphertext || tag) を生成、
  //   on-wire backward-compat 完全。
  const iv = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const json = JSON.stringify(envelopeObj);
  const ct = await aesGcmEncrypt(outerKeyOrBytes, iv, enc.encode(json));
  return concatBytes(iv, ct);
}

/**
 * Arweave から取った blob を解いて envelope オブジェクトに戻す。
 * blob: Uint8Array (12 byte IV + ciphertext + 16 byte auth tag)
 *
 * @param {Uint8Array} blob
 * @param {Uint8Array} outerKeyBytes 32-byte raw AES-GCM key
 */
export async function unwrapEnvelopeOuter(blob, outerKeyOrBytes) {
  if (blob.length < AES_IV_LEN + AES_TAG_LEN) {
    throw new Error(`Outer blob too short: ${blob.length} bytes`);
  }
  // Stage 2c: aesGcmDecrypt dispatcher 経由で Rust / WebCrypto 自動選択。
  const iv = blob.slice(0, AES_IV_LEN);
  const ct = blob.slice(AES_IV_LEN);
  let pt;
  try {
    pt = await aesGcmDecrypt(outerKeyOrBytes, iv, ct);
  } catch (e) {
    throw new Error("Outer envelope decryption failed (wrong outer key or corrupt blob)");
  }
  return JSON.parse(dec.decode(pt));
}

// ---------------------------------------------------------------------------
// KEK (各 wrap 用の鍵) と本体暗号化
// ---------------------------------------------------------------------------

export async function deriveKEK(material1, material2, saltKey) {
  // 増分2 deploy note: rust derive_kek_handle は CI(build-rust-crypto)で WASM 化される。
  //   WASM リビルドコミットは [skip ci] のため、 別 push で再デプロイ + ?v= 再付与が必要。
  // 増分2 (KEK の WASM 内派生): concat + HKDF-SHA256 を Rust 内で完結させ、 KEK を
  //   MekKey opaque handle として受け取る。 raw KEK は JS heap に一切出ない (= "B window" 除去)。
  //   bit-equivalence: rust derive_kek_handle = hkdf_sha256(material1||material2, salt, info, 32)
  //   は旧 hkdfBytes 経路と完全一致。 返却型 (MekKey handle) も従来 (importMekRawAsHandle) と同一。
  const rc = await _getRustCrypto();
  if (!rc || typeof rc.derive_kek_handle !== "function")
    throw new Error("deriveKEK: Rust crypto core (derive_kek_handle) 必須");
  return rc.derive_kek_handle(
    material1,
    material2,
    enc.encode(HKDF_SALTS[saltKey]),
    enc.encode(HKDF_INFOS[saltKey]),
  );
}

/** Stage 2c Stage G8 (2026-06-06): deriveKEK の Rust handle 版。
 *  HKDF 出力 raw 32 byte を即 MekKey handle に import + zeroize、 KEK を WASM 内に隠す。
 *  KEK は AES-256 鍵として MekKey handle で代用 (= type system 区別なし、 暗号操作は同 algorithm)。
 *  rust-crypto 未ロード時は null 返却で caller が CryptoKey path に fallback。 */
export async function deriveKEKHandle(material1, material2, saltKey) {
  // 増分2 + fallback 撤去: KEK を WASM 内で派生 (Rust 必須、 CryptoKey/raw 経路なし)。
  const rc = await _getRustCrypto();
  if (!rc || typeof rc.derive_kek_handle !== "function")
    throw new Error("deriveKEKHandle: Rust crypto core (derive_kek_handle) 必須");
  return rc.derive_kek_handle(
    material1,
    material2,
    enc.encode(HKDF_SALTS[saltKey]),
    enc.encode(HKDF_INFOS[saltKey]),
  );
}

// Stage 2b: AES-GCM dispatcher。 key の型で path 分岐:
//   - CryptoKey       → WebCrypto path (= 既存、 non-extractable 保護)
//   - Uint8Array (32B) → Rust + WASM path (= 新、 envelope orchestration が
//                        raw bytes を扱う場合に使う、 Stage 2c で活用)
//
// Stage 2c 以降の envelope orchestration を Rust に移すとき、 Rust 側は
// CryptoKey を扱えないので raw bytes を渡す必要があり、 このときに
// Rust path が effective になる。 既存 caller (= 全部 CryptoKey 経由) は
// 無修正で動作継続。
//
// AES-GCM AAD はオプション (= caller の用途次第)。
async function aesGcmEncrypt(key, iv, plaintext, aad) {
  // Stage 2c Stage C: Rust opaque handle path (= MekKey / K1Key / BekKey / OuterKey)
  // 全 4 type の handle が aes_gcm_encrypt method を持つ duck-type detection。
  // raw bytes が JS heap に出ない経路 (= 防御目標)。
  if (key && typeof key.aes_gcm_encrypt === "function") {
    const aadBytes = (aad instanceof Uint8Array) ? aad : new Uint8Array(0);
    return key.aes_gcm_encrypt(iv, plaintext, aadBytes);
  }
  if (key instanceof Uint8Array) {
    if (_rustCrypto && typeof _rustCrypto.aes256_gcm_encrypt === "function") {
      try {
        const aadBytes = (aad instanceof Uint8Array) ? aad : new Uint8Array(0);
        return _rustCrypto.aes256_gcm_encrypt(key, iv, plaintext, aadBytes);
      } catch (e) {
        console.warn("[arpass] Rust AES-GCM encrypt failed:", e?.message || e);
        throw e;  // raw bytes path で fallback 先が無いので throw
      }
    }
    throw new Error("aesGcmEncrypt: Uint8Array key requires Rust crypto core, but not loaded");
  }
  // CryptoKey 経路撤去: key は handle または 32-byte Uint8Array 必須。
  throw new Error("aesGcmEncrypt: key は opaque handle または Uint8Array 必須 (CryptoKey 廃止)");
}
async function aesGcmDecrypt(key, iv, ciphertext, aad) {
  // Stage 2c Stage C: Opaque handle path (= 同上の duck-type)
  if (key && typeof key.aes_gcm_decrypt === "function") {
    const aadBytes = (aad instanceof Uint8Array) ? aad : new Uint8Array(0);
    return key.aes_gcm_decrypt(iv, ciphertext, aadBytes);
  }
  if (key instanceof Uint8Array) {
    if (_rustCrypto && typeof _rustCrypto.aes256_gcm_decrypt === "function") {
      try {
        const aadBytes = (aad instanceof Uint8Array) ? aad : new Uint8Array(0);
        return _rustCrypto.aes256_gcm_decrypt(key, iv, ciphertext, aadBytes);
      } catch (e) {
        console.warn("[arpass] Rust AES-GCM decrypt failed:", e?.message || e);
        throw e;
      }
    }
    throw new Error("aesGcmDecrypt: Uint8Array key requires Rust crypto core, but not loaded");
  }
  // CryptoKey 経路撤去: key は handle または 32-byte Uint8Array 必須。
  throw new Error("aesGcmDecrypt: key は opaque handle または Uint8Array 必須 (CryptoKey 廃止)");
}

// ---------------------------------------------------------------------------
// Phase 7.0w-AH: encryptedRecovery (vault 内 Recovery 保管) helpers
// ---------------------------------------------------------------------------
//
// Recovery を vault データ内部に AES-GCM で暗号化して保管する。
// 暗号化キー K_recovery は MEK から HKDF で派生 (兄弟鍵)。
//
// 用途:
//   - 紙 Recovery 紛失時の再印刷 (ログイン後に取り出して表示)
//   - 機種追加の peer-to-peer ペアリング (既存デバイスから新デバイスへ転送)
//   - Deep recovery (Recovery + Passkey で過去 envelope を search する際)
//
// 暗号学的性質:
//   - K_vault (= MEK) が取れれば K_recovery も派生可能 (兄弟鍵)
//   - 真の追加防御層ではなく、コード規律 + biometric ゲートで遅延復号する設計
//   - 詳細な議論は memory: project_arpass_recovery_in_vault.md

async function deriveRecoveryProtectKey(mekOrHkdf) {
  // Phase 7.3-A.7b: mek が 非 extractable HKDF CryptoKey (= mekHkdfKey) でも対応。
  //   既存 encryptedRecovery と完全互換 (= 同じ HKDF chain で同じ bits を出すため)。
  // Stage 2c Stage G10 (2026-06-06): MekKey handle (= Rust opaque) も受付。
  //   hkdf_derive_mek で K_recovery handle を派生、 raw bytes WASM 内に隠蔽。
  //   返却は MekKey handle (= aes_gcm_encrypt/decrypt method 持ち、 dispatcher 透過)。
  if (mekOrHkdf && typeof mekOrHkdf.hkdf_derive_mek === "function") {
    return mekOrHkdf.hkdf_derive_mek(
      enc.encode(HKDF_SALTS.recovery_protect),
      enc.encode(HKDF_INFOS.recovery_protect)
    );
  }
  // fallback 撤去: MekKey opaque handle 必須 (CryptoKey/raw 経路廃止)。 caller は handle を渡す。
  throw new Error("deriveRecoveryProtectKey: MekKey opaque handle (hkdf_derive_mek) 必須");
}

/**
 * Phase 7.0w-AP: Recovery **文字列** ("RS1-XXXX-...") を MEK 由来の K_recovery で
 * AES-GCM 暗号化する。
 *
 * 旧版 (Phase 7.0w-AH) は rMat (HKDF 出力 32 bytes) を暗号化していたが、HKDF は
 * 一方向なので rMat → RS1-XXXX-... 文字列の復元不能 → 再表示不可だった。
 * 原文字列を UTF-8 で暗号化して再表示可能に。formatVersion v=2 を埋め込む。
 *
 * @param {string} recoveryString  "RS1-XXXX-XXXX-..." 形式の文字列
 * @param {Uint8Array} mek         32 byte の MEK
 * @returns {Promise<{ i: string, c: string, v: number }>}
 *          base64url 形式の IV / 暗号文 + formatVersion (常に 2)
 */
export async function encryptRecoveryWithMek(recoveryString, mek) {
  if (typeof recoveryString !== "string" || recoveryString.length < 4) {
    throw new Error("recoveryString must be a non-empty Recovery string");
  }
  // Stage 2c Stage G11 (2026-06-06): raw mek bytes は MekKey handle に即変換して
  //   Rust 経路で K_recovery 派生 + AES-GCM encrypt。 raw bytes JS heap 通過は
  //   importMekRawAsHandle の数行のみ。
  let _g11Handle = null;
  let mekArg = mek;
  if (mek instanceof Uint8Array) {
    try {
      _g11Handle = await importMekRawAsHandle(mek);
      if (_g11Handle) mekArg = _g11Handle;
    } catch (_) { /* fallback */ }
  }
  let key = null;
  try {
    key = await deriveRecoveryProtectKey(mekArg);
    const iv = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
    const ct = await aesGcmEncrypt(key, iv, enc.encode(recoveryString));
    return { i: b64uEncode(iv), c: b64uEncode(ct), v: 2 };
  } finally {
    if (key && typeof key.free === "function" && key !== _g11Handle) {
      try { key.free(); } catch (_) {}
    }
    if (_g11Handle && typeof _g11Handle.free === "function") {
      try { _g11Handle.free(); } catch (_) {}
    }
  }
}

/**
 * Phase 7.0w-AP: vault 内の encryptedRecovery (v=2 文字列形式) を MEK 由来の
 * K_recovery で復号して、原 Recovery 文字列 ("RS1-XXXX-...") を返す。
 *
 * v=1 (legacy rMat 形式) を見つけたら throw する (再表示不能、再 migration が必要)。
 *
 * @param {{ i: string, c: string, v?: number }} encryptedRecovery
 * @param {Uint8Array} mek
 * @returns {Promise<string>}  Recovery 原文字列
 */
export async function decryptRecoveryWithMek(encryptedRecovery, mek) {
  if (!encryptedRecovery?.i || !encryptedRecovery?.c) {
    throw new Error("encryptedRecovery must have { i, c }");
  }
  if (encryptedRecovery.v !== 2) {
    throw new Error("encryptedRecovery is in legacy v1 format (rMat) — cannot recover original string");
  }
  // Stage 2c Stage G11 (2026-06-06): raw mek bytes → MekKey handle 経路で Rust decrypt。
  let _g11Handle = null;
  let mekArg = mek;
  if (mek instanceof Uint8Array) {
    try {
      _g11Handle = await importMekRawAsHandle(mek);
      if (_g11Handle) mekArg = _g11Handle;
    } catch (_) { /* fallback */ }
  }
  let key = null;
  try {
    key = await deriveRecoveryProtectKey(mekArg);
    const iv = b64uDecode(encryptedRecovery.i);
    const ct = b64uDecode(encryptedRecovery.c);
    const plaintextBytes = await aesGcmDecrypt(key, iv, ct);
    return dec.decode(plaintextBytes);
  } finally {
    if (key && typeof key.free === "function" && key !== _g11Handle) {
      try { key.free(); } catch (_) {}
    }
    if (_g11Handle && typeof _g11Handle.free === "function") {
      try { _g11Handle.free(); } catch (_) {}
    }
  }
}

/**
 * vault オブジェクトに encryptedRecovery field を inject する。
 * encryptVault と changeRecovery_caseB から呼ばれる内部ヘルパー。
 *
 * @param {object} vault          vault データ
 * @param {string} recoveryString "RS1-XXXX-..." 文字列 (Phase 7.0w-AP)
 * @param {Uint8Array} mek        32 byte の MEK
 * @returns {Promise<object>}     encryptedRecovery field が追加された新 vault オブジェクト
 */
async function injectEncryptedRecovery(vault, recoveryString, mek) {
  const encryptedRecovery = await encryptRecoveryWithMek(recoveryString, mek);
  return { ...vault, encryptedRecovery };
}

// ---------------------------------------------------------------------------
// padding (サイズ秘匿) — v4 と互換のバケット方式 (本体 c のみ対象)
// ---------------------------------------------------------------------------

// --- 2026-07-12: Turbo Payment Service 障害時の緊急パディング ---
//   有料 (>100KiB) アップロードだけが落ちる障害 (Payment Service unreachable) の間、
//   sponsored 無料枠に収まる <100KiB のランダム長で書けるようにする。
//   ・emergency bucket 60KiB + jitter 0..6KiB → on-chain ~82-92KiB (無料枠 105KiB 内)
//   ・入り切らない大きな vault は通常バケットへ (障害中は失敗するが、データは縮めない)
//   ・読み側 (unpadPlaintext) は終端マーカー方式でサイズ非依存 = 互換問題なし
//   ・悪用面: 発動条件は「サーバが直近に upload_failed を記録」であり、攻撃者が
//     任意に sponsored 経路を選ぶことはできない
const EMERGENCY_PAD_BUCKET = 60 * 1024;
const EMERGENCY_PAD_JITTER = 6 * 1024;
let _emergencyPadUntil = 0;

export function enableEmergencyPad(ttlMs = 5 * 60 * 1000) {  // 2026-07-12: server 側 TTL (5分) に合わせる
  _emergencyPadUntil = Date.now() + ttlMs;
  try { console.warn("[pad] emergency (<100KiB sponsored) padding enabled for " + Math.round(ttlMs / 1000) + "s"); } catch (_) {}
}

export function isEmergencyPadActive() { return Date.now() < _emergencyPadUntil; }

export function padPlaintext(bytes) {
  const minRequired = bytes.length + 1;  // 0x80 マーカー分
  if (Date.now() < _emergencyPadUntil && EMERGENCY_PAD_BUCKET - AES_TAG_LEN >= minRequired) {
    const eJitter = crypto.getRandomValues(new Uint32Array(1))[0] % (EMERGENCY_PAD_JITTER + 1);
    const eTotal = EMERGENCY_PAD_BUCKET + eJitter - AES_TAG_LEN;
    const eOut = new Uint8Array(eTotal);
    eOut.set(bytes, 0);
    eOut[bytes.length] = PAD_TERMINATOR;
    return eOut;
  }
  let bucket = PAD_BUCKETS[PAD_BUCKETS.length - 1];
  for (const b of PAD_BUCKETS) {
    if (b - AES_TAG_LEN >= minRequired) { bucket = b; break; }
  }
  // Within-bucket jitter: 0..PAD_JITTER_BYTES の追加 padding をランダムに加算。
  // unpadPlaintext は末尾から 0x80 終端マーカーを後方探索する方式なので、
  // 加算分の長さが変動しても復号には影響しない (ゼロ埋めで scan が継続できる)。
  const jitter = crypto.getRandomValues(new Uint32Array(1))[0] % (PAD_JITTER_BYTES + 1);
  const totalBeforeTag = bucket + jitter - AES_TAG_LEN;
  const out = new Uint8Array(totalBeforeTag);
  out.set(bytes, 0);
  out[bytes.length] = PAD_TERMINATOR;
  // 残りはゼロ埋め (terminator scan が成立する条件)
  return out;
}

export function unpadPlaintext(padded) {
  // 末尾から 0x80 マーカーを後方探索 (0x00 を skip)
  for (let i = padded.length - 1; i >= 0; i--) {
    if (padded[i] === PAD_TERMINATOR) return padded.subarray(0, i);
    if (padded[i] !== 0) throw new Error("Padding terminator not found");
  }
  throw new Error("Padding terminator not found");
}

// ---------------------------------------------------------------------------
// 署名鍵の決定論派生 — HKDF(MEK) → ECDSA P-256 (d, Q)
// ---------------------------------------------------------------------------

/**
 * MEK から ECDSA P-256 鍵ペアを HKDF で決定論的に派生する。
 *
 * 戻り値:
 *   {
 *     d: bigint,                  // 秘密鍵スカラー (1 ≤ d < n)
 *     Q: { x: bigint, y: bigint }, // 公開鍵点
 *     privateKeyJwk: JsonWebKey,   // Web Crypto API への importKey 用
 *     publicKeyJwk:  JsonWebKey,   // 検証用
 *     publicKeyRaw:  Uint8Array(65), // 65 byte uncompressed (0x04 prefix)
 *   }
 *
 * 同じ MEK 入力からは必ず同じ (d, Q) が出る。これによりユーザーが端末復旧
 * 後も同じ identity (= サーバ KV の同じアカウント) に再到達できる。
 */
export function deriveSigningKey(mekBytes) {
  // HKDF で 48 byte (P-256 order の 256 bit + 余裕) を派生し、mod n に落とす
  // 余裕を取るのは "rejection" を避けて確実に [1, n-1] に収めるため
  const seed = hkdfBytes(mekBytes, HKDF_SALTS.signing_key, HKDF_INFOS.signing_key, 48);
  return _signingKeyFromSeed(seed);
}

/**
 * Phase 7.3-A: 非 extractable HKDF base CryptoKey (= k2HkdfKey / mekHkdfKey) から
 *   署名鍵を導出する。 deriveSigningKey(raw) と完全互換 (= 同一 seed なら同一鍵)。
 *   Phase 7.3-A 以降 raw な MEK/K2 を session に持たないため、 署名秘密 scalar が
 *   必要な操作 (例: 監査ログ event の ECIES 復号) はこの関数で transient に再導出する。
 * @param {CryptoKey} hkdfBaseKey MEK / K2 を HKDF base として import 済の CryptoKey
 * @returns {Promise<object>} deriveSigningKey と同じ shape
 */
export async function deriveSigningKeyFromHkdf(hkdfBaseKey) {
  // Phase 2-H4-full F7-B (retry): MekKey opaque handle 入力受付。
  //   MekKey.derive_signing_key で 48-byte seed → SigningKey handle を WASM 内で生成。
  //   bit-equivalence は Rust test test_mek_derive_signing_key_equivalent_to_explicit_hkdf_path
  //   で担保。 現状 caller は CryptoKey を渡すので、 この path は dormant。
  //   shape: {privateKeyRaw, publicKeyRaw, handle} (consumer は currentSigningPrivateKeyRaw
  //   のみで privateKeyRaw のみ参照)。
  if (hkdfBaseKey && typeof hkdfBaseKey.derive_signing_key === "function") {
    const handle = hkdfBaseKey.derive_signing_key(
      enc.encode(HKDF_SALTS.signing_key),
      enc.encode(HKDF_INFOS.signing_key)
    );
    const privateKeyRaw = new Uint8Array(handle.private_key_raw());
    const publicKeyRaw = new Uint8Array(handle.public_key_raw());
    return { privateKeyRaw, publicKeyRaw, handle };
  }
  // fallback 撤去: MekKey opaque handle 必須 (derive_signing_key)。
  throw new Error("deriveSigningKeyFromHkdf: MekKey opaque handle 必須 (Rust)");
}


/**
 * Phase 2-H1: Rust SigningKey opaque handle factory.
 *   Returns a SigningKey handle (= Rust opaque struct holding raw 32-byte
 *   private scalar + 65-byte public SEC1) when rust-crypto is loaded.
 *   Returns null on failure — caller falls back to CryptoKey path.
 *
 * @param {Uint8Array} seed  48-byte (or longer) seed (= HKDF output)
 * @returns {object|null}  SigningKey handle or null
 */
export function importSigningKeyHandleFromSeed(seed) {
  const rc = _rustCrypto;
  if (!rc || typeof rc.SigningKey !== "function") return null;
  try {
    return new rc.SigningKey(seed);
  } catch (e) {
    console.warn("[arpass] SigningKey handle factory failed:", e?.message || e);
    return null;
  }
}


/**
 * 48-byte seed → P-256 署名鍵オブジェクト。
 * deriveSigningKey と deriveSigningKeyFromHkdf の共通後段。
 */
function _signingKeyFromSeed(seed) {
  // Stage 2b-pre: Rust + WASM 優先 (= 同じ seed で同じ keypair を生成、
  //   noble の bigint mod n 計算と bit-identical)。 失敗時 noble fallback。
  let dBytes, xBytes, yBytes, d;
  if (_rustCrypto && typeof _rustCrypto.p256_keypair_from_seed === "function") {
    try {
      const kp = _rustCrypto.p256_keypair_from_seed(seed);
      dBytes = kp.slice(0, 32);
      // pub = 65 byte (= 0x04 || X || Y)
      xBytes = kp.slice(33, 65);
      yBytes = kp.slice(65, 97);
      // d as bigint (for legacy callers that may want it)
      d = 0n;
      for (const b of dBytes) d = (d << 8n) | BigInt(b);
    } catch (e) {
      console.warn("[arpass] Rust p256 keypair_from_seed failed, using noble:", e?.message || e);
      d = null;
    }
  }
  if (!d) {
    // Noble fallback: bigint mod n
    let dInt = 0n;
    for (const b of seed) dInt = (dInt << 8n) | BigInt(b);
    const n = p256.Point.Fn.ORDER;
    d = mod(dInt, n);
    if (d === 0n) d = 1n; // 極めて稀
    // 公開鍵 = d * G
    const Qpoint = p256.Point.BASE.multiply(d);
    const Qaffine = Qpoint.toAffine();
    xBytes = bigIntTo32Bytes(Qaffine.x);
    yBytes = bigIntTo32Bytes(Qaffine.y);
    dBytes = bigIntTo32Bytes(d);
  }
  // Construct Qaffine-equivalent object for return (legacy compatible)
  const Qaffine = { x: 0n, y: 0n };  // placeholder, actual values reconstructed from bytes
  for (const b of xBytes) Qaffine.x = (Qaffine.x << 8n) | BigInt(b);
  for (const b of yBytes) Qaffine.y = (Qaffine.y << 8n) | BigInt(b);

  const publicKeyJwk = {
    kty: "EC",
    crv: "P-256",
    x: b64uEncode(xBytes),
    y: b64uEncode(yBytes),
    ext: true,
  };
  const privateKeyJwk = {
    ...publicKeyJwk,
    d: b64uEncode(dBytes),
  };
  // Uncompressed publicKey: 0x04 || X || Y (= 65 byte)
  const publicKeyRaw = concatBytes(new Uint8Array([0x04]), xBytes, yBytes);
  // 32-byte big-endian private scalar (= for ECIES decrypt / ECDH operations, Phase 7.1)
  const privateKeyRaw = dBytes;

  // Phase 2-H1: Rust SigningKey opaque handle when available.
  //   Callers (= openSession, deriveSigningKeyFromHkdf consumers) can prefer
  //   `handle` over `privateKeyJwk` and let signRequest dispatch.
  let handle = null;
  try {
    handle = importSigningKeyHandleFromSeed(seed);
  } catch (_) { /* leave null, CryptoKey fallback via privateKeyJwk */ }

  return { d, Q: Qaffine, privateKeyJwk, publicKeyJwk, publicKeyRaw, privateKeyRaw, handle };
}

function bigIntTo32Bytes(n) {
  const out = new Uint8Array(32);
  let v = n;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/**
 * publicKey raw (65 byte uncompressed) → SHA-256 → base64url の先頭 22 文字。
 * これがサーバ側 KV のキー。
 */
export async function hashPublicKey(publicKeyRaw) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", publicKeyRaw));
  return b64uEncode(digest).slice(0, 22);  // 16 byte 相当
}

// ---------------------------------------------------------------------------
// credentialId (WebAuthn) → credIdHash (wrap 配列のインデックス)
// ---------------------------------------------------------------------------

/**
 * credentialId (Uint8Array, WebAuthn から取得した raw bytes) を SHA-256 して
 * base64url で 16 文字に。w.b[i].h と w.c[i].h に入る値。
 */
export async function credentialIdToHash(credentialIdBytes) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", credentialIdBytes));
  return b64uEncode(d).slice(0, 16);
}

// ---------------------------------------------------------------------------
// Vault 暗号化 — 内側 envelope 構築
// ---------------------------------------------------------------------------

/**
 * 新規 vault を v5 envelope に暗号化する。
 *
 * @param {object} vault             平文 vault データ (passwords, credentials, signingKey は含まない)
 * @param {string} password          Master Password
 * @param {Uint8Array} prfOutput     WebAuthn PRF output (32 byte)
 * @param {Uint8Array} recoveryMaterial  Recovery 文字列 → rMat
 * @param {string}     credIdHash    この端末の credIdHash (b64url 16 文字)
 * @param {string}     [recoverySecret]  Phase 7.0w-AP: 人間可読 Recovery 文字列
 *                                       渡された場合のみ vault に encryptedRecovery を inject
 *
 * @returns {Promise<{
 *   envelope: object,                // v5 内側 JSON
 *   mek: Uint8Array(32),             // 派生用に保持 (lockSession で破棄)
 *   outerKeyBytes: Uint8Array(32),   // 外側 AES-GCM 鍵 (rMat 直接派生、Phase 7.0w-AR)
 *   appNameTag: {name,value},        // Arweave タグ (name/value 両方 rMat 派生)
 *   signingKey: object,              // deriveSigningKey の戻り値
 * }>}
 */
export async function encryptVault(vault, password, prfOutput, recoveryMaterial, credIdHash, recoverySecret = null) {
  if (!password) throw new Error("password required");
  if (!(prfOutput instanceof Uint8Array) || prfOutput.length < 16)
    throw new Error("prfOutput required (Passkey + PRF mandatory in v5)");
  if (!(recoveryMaterial instanceof Uint8Array) || recoveryMaterial.length < 32)
    throw new Error("recoveryMaterial (32 byte) required");
  if (!credIdHash || typeof credIdHash !== "string")
    throw new Error("credIdHash required");

  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN_BYTES));
  const mek  = crypto.getRandomValues(new Uint8Array(32));
  const kdfParamsForEnvelope = getCurrentKdfParams();

  const pMat = await derivePMat(password, salt, kdfParamsForEnvelope);
  const kMat = deriveKMat(prfOutput);
  const rMat = recoveryMaterial.slice(0, 32);

  // KEK 3 種 — Stage 2c Stage G8 (2026-06-06): Rust handle 優先、 fallback で CryptoKey
  let kekPRHandle = null, kekPKHandle = null, kekKRHandle = null;
  try {
    kekPRHandle = await deriveKEKHandle(pMat, rMat, "kek_pr");
    kekPKHandle = await deriveKEKHandle(pMat, kMat, "kek_pk");
    kekKRHandle = await deriveKEKHandle(kMat, rMat, "kek_kr");
  } catch (_) { /* fallback */ }
  const kekPR = kekPRHandle ?? await deriveKEK(pMat, rMat, "kek_pr");
  const kekPK = kekPKHandle ?? await deriveKEK(pMat, kMat, "kek_pk");
  const kekKR = kekKRHandle ?? await deriveKEK(kMat, rMat, "kek_kr");

  // wrap 3 種 (= dispatcher が handle 利用可能なら Rust path、 CryptoKey なら WebCrypto path)
  const ivA = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const ivB = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const ivC = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const wrapA = await aesGcmEncrypt(kekPR, ivA, mek);
  const wrapB = await aesGcmEncrypt(kekPK, ivB, mek);
  const wrapC = await aesGcmEncrypt(kekKR, ivC, mek);
  // free handles (= WASM linear memory cleanup)
  [kekPRHandle, kekPKHandle, kekKRHandle].forEach(h => {
    if (h && typeof h.free === "function") { try { h.free(); } catch (_) {} }
  });

  // 本体暗号化 (vault JSON) — handle 化: MEK を MekKey opaque handle で扱う (CryptoKey 不使用)。
  const ivBody = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const mekHandle = await importMekRawAsHandle(mek);
  if (!mekHandle) throw new Error("encryptVault: Rust crypto core (MekKey) 必須");

  // encryptedRecovery を vault に inject (= recoveryProtect も MEK handle 由来)。
  const vaultWithRecovery = (typeof recoverySecret === "string" && recoverySecret.length > 0)
    ? await injectEncryptedRecovery(vault, recoverySecret, mekHandle)
    : vault;

  const padded = padPlaintext(enc.encode(JSON.stringify(vaultWithRecovery)));
  const bodyCt = await aesGcmEncrypt(mekHandle, ivBody, padded);  // handle 経由 (Rust AES-GCM)
  const _returnedMekKey = mekHandle;

  const envelope = {
    v: VAULT_FORMAT_V5,
    kdfParams: kdfParamsForEnvelope,  // Phase 7.4.1: KDF パラメータを envelope に固定 (派生時と一致)
    s: b64uEncode(salt),
    i: b64uEncode(ivBody),
    c: b64uEncode(bodyCt),
    w: {
      a: { i: b64uEncode(ivA), c: b64uEncode(wrapA) },
      b: [{ h: credIdHash, i: b64uEncode(ivB), c: b64uEncode(wrapB) }],
      c: [{ h: credIdHash, i: b64uEncode(ivC), c: b64uEncode(wrapC) }],
    },
  };

  const outerKeyBytes = deriveOuterKeyBytes(rMat);
  const appNameTag = deriveAppNameTag(rMat);
  const signingKey = deriveSigningKey(mek);  // {handle,...} (raw mek からだが handle を返す)
  // mekHkdfKey も MekKey opaque handle で (recoveryProtect 等の sub-key 派生用、 二重 free 回避に別 handle)。
  const mekHkdfHandle = await importMekRawAsHandle(mek);
  mek.fill(0);  // raw mek は全消費後に破棄
  return { envelope, mek: null, mekKey: _returnedMekKey, mekHkdfKey: mekHkdfHandle, outerKeyBytes, appNameTag, signingKey };
}

/**
 * v5 envelope を復号する。
 *
 * @param {object} envelope  v5 envelope (内側、外側復号後)
 * @param {object} factors   { password?, prfOutput?, recoveryMaterial?, credIdHash? }
 *                            少なくとも 2 要素が必要
 *
 * @returns {Promise<{
 *   vault: object,
 *   mek: Uint8Array(32),
 *   signingKey: object,
 *   path: "AB"|"AC"|"BC"
 * }>}
 */
export async function decryptVault(envelope, factors) {
  if (!envelope || envelope.v !== VAULT_FORMAT_V5) {
    throw new Error(`v5 envelope expected, got v=${envelope?.v}`);
  }
  const haveP = !!factors?.password;
  const haveK = factors?.prfOutput instanceof Uint8Array && factors.prfOutput.length >= 16;
  const haveR = factors?.recoveryMaterial instanceof Uint8Array && factors.recoveryMaterial.length >= 32;
  if ([haveP, haveK, haveR].filter(Boolean).length < 2) {
    throw new Error("Need at least 2 of {password, prfOutput, recoveryMaterial}");
  }

  const salt = b64uDecode(envelope.s);
  // Phase 7.4.1: 旧 envelope は kdfParams を持たないので CURRENT に fallback
  const pMat = haveP ? await derivePMat(factors.password, salt, envelope.kdfParams) : null;
  const kMat = haveK ? deriveKMat(factors.prfOutput) : null;
  const rMat = haveR ? factors.recoveryMaterial.slice(0, 32) : null;

  let mek = null;
  let mekHandle = null;   // Stage 2 Phase B: rust-crypto 時は生 mek を作らず MekKey handle 直取得
  let path = null;
  // forceRawMek: _deriveTransientMek 等 mutation 経路が raw mek を必要とする時に true。
  //   その場合は handle 産生をスキップし raw 経路 (生 mek 返却) を使う。
  const _wantRaw = !!factors?.forceRawMek;

  // Path AB: Master + Passkey (日常 unlock)
  if (haveP && haveK && envelope.w?.b?.length) {
    const credIdHash = factors.credIdHash;
    const candidates = credIdHash
      ? envelope.w.b.filter((w) => w.h === credIdHash)
      : envelope.w.b;
    for (const w of candidates) {
      let _kekHandleAB = null;
      try {
        try { _kekHandleAB = await deriveKEKHandle(pMat, kMat, "kek_pk"); } catch (_) {}
        const kek = _kekHandleAB ?? await deriveKEK(pMat, kMat, "kek_pk");
        if (!_wantRaw && kek && typeof kek.unwrap_mek === "function") {
          mekHandle = kek.unwrap_mek(b64uDecode(w.c), b64uDecode(w.i));  // handle、 生 mek 無し
        } else {
          mek = await aesGcmDecrypt(kek, b64uDecode(w.i), b64uDecode(w.c));  // raw
        }
        path = "AB";
        break;
      } catch { /* try next */ }
      finally { if (_kekHandleAB?.free) { try { _kekHandleAB.free(); } catch (_) {} } }
    }
  }
  // Path AC: Master + Recovery
  if (!mek && !mekHandle && haveP && haveR && envelope.w?.a) {
    let _kekHandleAC = null;
    try {
      try { _kekHandleAC = await deriveKEKHandle(pMat, rMat, "kek_pr"); } catch (_) {}
      const kek = _kekHandleAC ?? await deriveKEK(pMat, rMat, "kek_pr");
      if (!_wantRaw && kek && typeof kek.unwrap_mek === "function") {
        mekHandle = kek.unwrap_mek(b64uDecode(envelope.w.a.c), b64uDecode(envelope.w.a.i));
      } else {
        mek = await aesGcmDecrypt(kek, b64uDecode(envelope.w.a.i), b64uDecode(envelope.w.a.c));
      }
      path = "AC";
    } catch { /* try BC */ }
  }
  // Path BC: Passkey + Recovery (Master 忘却時)
  if (!mek && !mekHandle && haveK && haveR && envelope.w?.c?.length) {
    const credIdHash = factors.credIdHash;
    const candidates = credIdHash
      ? envelope.w.c.filter((w) => w.h === credIdHash)
      : envelope.w.c;
    for (const w of candidates) {
      let _kekHandleBC = null;
      try {
        try { _kekHandleBC = await deriveKEKHandle(kMat, rMat, "kek_kr"); } catch (_) {}
        const kek = _kekHandleBC ?? await deriveKEK(kMat, rMat, "kek_kr");
        if (!_wantRaw && kek && typeof kek.unwrap_mek === "function") {
          mekHandle = kek.unwrap_mek(b64uDecode(w.c), b64uDecode(w.i));
        } else {
          mek = await aesGcmDecrypt(kek, b64uDecode(w.i), b64uDecode(w.c));
        }
        path = "BC";
        break;
      } catch { /* try next */ }
      finally { if (_kekHandleBC?.free) { try { _kekHandleBC.free(); } catch (_) {} } }
    }
  }
  if (!mek && !mekHandle) throw new Error("Decryption failed: no wrap could be opened with the provided factors");

  // Stage 2 Phase B: handle 経路 = 生 mek を JS heap に出さない。 mek=null/mekHkdfKey=null、
  //   consumer は mekKey(handle) 経由。 signing は deriveSigningKeyFromHkdf(handle)。
  if (mekHandle) {
    const padded = await aesGcmDecrypt(mekHandle, b64uDecode(envelope.i), b64uDecode(envelope.c));
    const vault = JSON.parse(dec.decode(unpadPlaintext(padded)));
    const signingKey = await deriveSigningKeyFromHkdf(mekHandle);
    return { vault, mek: null, mekKey: mekHandle, mekHkdfKey: null, signingKey, path };
  }

  // raw 経路 (= forceRawMek mutation / 災害復旧): mek raw は caller が使用。 body 復号・
  //   返却 mekKey は Rust handle に統一 (CryptoKey importKey 廃止、 Rust 必須)。
  const _bodyHandle = await importMekRawAsHandle(mek);
  const padded = await aesGcmDecrypt(_bodyHandle, b64uDecode(envelope.i), b64uDecode(envelope.c));
  const json = unpadPlaintext(padded);
  const vault = JSON.parse(dec.decode(json));
  const signingKey = deriveSigningKey(mek);
  const mekHkdfKey = await importMekRawAsHandle(mek);
  return { vault, mek, mekKey: _bodyHandle, mekHkdfKey, signingKey, path };
}

// ---------------------------------------------------------------------------
// Mutation: 端末追加・パスワード変更・Recovery 再発行
// ---------------------------------------------------------------------------

/**
 * 既存 envelope に新端末の Passkey を追加 (AB / BC wrap を 2 個追加)。
 * 既存の MEK / publicKey は不変。
 *
 * @param {Uint8Array} secretToWrap  Personal mode: real MEK、 Business mode: K2
 *                                    (= envelope.w に wrap される 32 byte 素材)
 */
export async function addCredential(envelope, secretToWrap, password, recoveryMaterial, newPrfOutput, newCredIdHash) {
  const salt = b64uDecode(envelope.s);
  // Phase 7.4.1: 既存 envelope の kdfParams で派生 (Master を確認するため同じ KDF)
  const pMat = await derivePMat(password, salt, envelope.kdfParams);
  const kMat = deriveKMat(newPrfOutput);
  const rMat = recoveryMaterial.slice(0, 32);

  const kekPK = await deriveKEK(pMat, kMat, "kek_pk");
  const kekKR = await deriveKEK(kMat, rMat, "kek_kr");
  const ivB = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const ivC = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const wrapB = await aesGcmEncrypt(kekPK, ivB, secretToWrap);
  const wrapC = await aesGcmEncrypt(kekKR, ivC, secretToWrap);

  // 既存の同じ credIdHash があれば置き換え (1 端末 1 wrap、上書き安全)
  const newW = JSON.parse(JSON.stringify(envelope.w));
  newW.b = newW.b.filter((w) => w.h !== newCredIdHash);
  newW.c = newW.c.filter((w) => w.h !== newCredIdHash);
  newW.b.push({ h: newCredIdHash, i: b64uEncode(ivB), c: b64uEncode(wrapB) });
  newW.c.push({ h: newCredIdHash, i: b64uEncode(ivC), c: b64uEncode(wrapC) });
  return { ...envelope, w: newW };
}

/**
 * Master Password を変更する (envelope v7 / Option A — envelope-v7-spec.md §14)。
 * v7 では outer 鍵を Master でラップして user.id に格納する。user.id は credential
 *   作成後 *不変* なので、Master を変えるには「新しい Passkey」を作るしかない。
 *   よって本関数は呼び出し側 (changePasswordUI) が作った新 Passkey を受け取り:
 *     - AC wrap (Master+Recovery) を新 Master で再生成
 *     - 全 wraps.pk (AB) を破棄し、新 Passkey 用 1 個だけにする
 *       → 旧 Passkey の AB wrap は全消滅、旧 Master はどの端末でも AB 解錠不可
 *     - 新 Passkey 用の BC wrap (Passkey+Recovery) を追加 (Master 無関係)
 *   旧 Passkey の BC wrap は残す (Master 無関係に有効。各端末の救済路)。
 * @param {object} envelope
 * @param {Uint8Array} secretToWrap   Personal: MEK / Business: K2
 * @param {string} newCredIdHash      changePasswordUI が作った新 Passkey の credIdHash
 * @param {string} newPassword        新 Master
 * @param {Uint8Array} newPrfOutput   新 Passkey の PRF 出力
 * @param {Uint8Array} recoveryMaterial
 */
export async function changePassword(envelope, secretToWrap, newCredIdHash, newPassword, newPrfOutput, recoveryMaterial) {
  // Phase 7.2-B (α): secretToWrap は Personal: MEK / Business: K2
  const salt = b64uDecode(envelope.s);
  // Phase 7.4.1: 旧 envelope の kdfParams を維持 (新 envelope も同じ KDF で再 wrap)
  const newPMat = await derivePMat(newPassword, salt, envelope.kdfParams);
  const newKMat = deriveKMat(newPrfOutput);
  const rMat = recoveryMaterial.slice(0, 32);

  // AC wrap (Master+Recovery) を新 Master で再生成
  const kekPR = await deriveKEK(newPMat, rMat, "kek_pr");
  const ivA = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const wrapA = await aesGcmEncrypt(kekPR, ivA, secretToWrap);

  // AB wrap (Master+Passkey): 全 wraps.pk を破棄し新 Passkey 用 1 個だけにする
  const kekPK = await deriveKEK(newPMat, newKMat, "kek_pk");
  const ivB = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const wrapB = await aesGcmEncrypt(kekPK, ivB, secretToWrap);

  // BC wrap (Passkey+Recovery): 新 Passkey 用エントリを追加 (Master 無関係)
  const kekKR = await deriveKEK(newKMat, rMat, "kek_kr");
  const ivC = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const wrapC = await aesGcmEncrypt(kekKR, ivC, secretToWrap);

  const newW = JSON.parse(JSON.stringify(envelope.w));
  newW.a = { i: b64uEncode(ivA), c: b64uEncode(wrapA) };
  newW.b = [{ h: newCredIdHash, i: b64uEncode(ivB), c: b64uEncode(wrapB) }];
  newW.c = (newW.c || []).filter((w) => w.h !== newCredIdHash);
  newW.c.push({ h: newCredIdHash, i: b64uEncode(ivC), c: b64uEncode(wrapC) });

  return { ...envelope, w: newW };
}

/**
 * Recovery を再発行する (ケース A: MEK 据え置き)。
 * AC + 「現端末」の BC wrap を再生成。他端末の BC は lazy 補完。
 */
export async function changeRecovery_caseA(envelope, secretToWrap, password, currentCredIdHash, currentPrfOutput, newRecoveryMaterial) {
  // Phase 7.2-B (α): secretToWrap は Personal: MEK / Business: K2
  const salt = b64uDecode(envelope.s);
  // Phase 7.4.1: 既存 envelope の kdfParams で派生
  const pMat = await derivePMat(password, salt, envelope.kdfParams);
  const kMat = deriveKMat(currentPrfOutput);
  const newRMat = newRecoveryMaterial.slice(0, 32);

  // AC wrap 再生成
  const kekPR = await deriveKEK(pMat, newRMat, "kek_pr");
  const ivA = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const wrapA = await aesGcmEncrypt(kekPR, ivA, secretToWrap);

  // この端末の BC wrap 再生成
  const kekKR = await deriveKEK(kMat, newRMat, "kek_kr");
  const ivC = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const wrapC = await aesGcmEncrypt(kekKR, ivC, secretToWrap);

  const newW = JSON.parse(JSON.stringify(envelope.w));
  newW.a = { i: b64uEncode(ivA), c: b64uEncode(wrapA) };
  newW.c = newW.c.filter((w) => w.h !== currentCredIdHash);
  newW.c.push({ h: currentCredIdHash, i: b64uEncode(ivC), c: b64uEncode(wrapC) });

  // 新 outer-key, App-Name (caller がこれで envelope を新 outer-key 下に書く)
  const newOuterKeyBytes = deriveOuterKeyBytes(newRMat);
  const newAppNameTag = deriveAppNameTag(newRMat);

  return {
    envelope: { ...envelope, w: newW },
    newOuterKeyBytes,
    newAppNameTag,
  };
}

/**
 * Recovery を再発行する (ケース B: MEK ごと一新)。
 * 全 wrap 再生成、本体 c も再暗号化。新 publicKey が出るのでサーバ migration 必要。
 *
 * @returns {Promise<{ envelope, newMek, newVaultId, newAppNameTag, newSigningKey, oldSigningKey }>}
 *   newSigningKey で /api/migrate を呼んで oldSigningKey から新 KV エントリへ
 *   credit を移送する。Phase 7.0w-AR: newVaultId → newOuterKeyBytes に rename。
 */
export async function changeRecovery_caseB(envelope, oldMek, vault, password, currentCredIdHash, currentPrfOutput, newRecoveryMaterial, newRecoverySecret = null) {
  const oldSigningKey = deriveSigningKey(oldMek);
  const newRMat = newRecoveryMaterial.slice(0, 32);
  const newMek = crypto.getRandomValues(new Uint8Array(32));

  const salt = b64uDecode(envelope.s);  // salt は流用 (KDF はパスワードに依存、salt 同じで問題なし)
  // Phase 7.4.1: 既存 envelope の kdfParams で派生
  const pMat = await derivePMat(password, salt, envelope.kdfParams);
  const kMat = deriveKMat(currentPrfOutput);

  // 新 wrap 群
  const kekPR = await deriveKEK(pMat, newRMat, "kek_pr");
  const kekPK = await deriveKEK(pMat, kMat, "kek_pk");
  const kekKR = await deriveKEK(kMat, newRMat, "kek_kr");
  const ivA = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const ivB = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const ivC = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const wrapA = await aesGcmEncrypt(kekPR, ivA, newMek);
  const wrapB = await aesGcmEncrypt(kekPK, ivB, newMek);
  const wrapC = await aesGcmEncrypt(kekKR, ivC, newMek);

  // 新 MEK で本体再暗号化
  // Phase 7.0w-AH/AP: 新 Recovery + 新 MEK で encryptedRecovery も refresh。
  // 文字列が渡されていない場合は encryptedRecovery 抜きで再暗号化 (legacy 互換)。
  const vaultWithRecovery = (typeof newRecoverySecret === "string" && newRecoverySecret.length > 0)
    ? await injectEncryptedRecovery(vault, newRecoverySecret, newMek)
    : vault;
  const ivBody = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const mekKey = await importMekRawAsHandle(newMek);  // Rust handle (CryptoKey importKey 廃止)
  const padded = padPlaintext(enc.encode(JSON.stringify(vaultWithRecovery)));
  const bodyCt = await aesGcmEncrypt(mekKey, ivBody, padded);
  if (mekKey && typeof mekKey.free === "function") { try { mekKey.free(); } catch (_) {} }

  const newEnvelope = {
    v: VAULT_FORMAT_V5,
    // Phase 7.4.1: 旧 envelope の kdfParams を引き継ぐ (新 envelope も同じ KDF で
    // 派生したため)。 古い envelope が kdfParams を持たない場合は CURRENT を採用。
    kdfParams: envelope.kdfParams ? { ...envelope.kdfParams } : getCurrentKdfParams(),
    s: envelope.s,
    i: b64uEncode(ivBody),
    c: b64uEncode(bodyCt),
    w: {
      a: { i: b64uEncode(ivA), c: b64uEncode(wrapA) },
      b: [{ h: currentCredIdHash, i: b64uEncode(ivB), c: b64uEncode(wrapB) }],
      c: [{ h: currentCredIdHash, i: b64uEncode(ivC), c: b64uEncode(wrapC) }],
    },
  };

  return {
    envelope: newEnvelope,
    newMek,
    newOuterKeyBytes: deriveOuterKeyBytes(newRMat),
    newAppNameTag: deriveAppNameTag(newRMat),
    newSigningKey: deriveSigningKey(newMek),
    oldSigningKey,
  };
}

// ---------------------------------------------------------------------------
// 署名・検証 (API リクエスト用)
// ---------------------------------------------------------------------------

/**
 * リクエスト署名を生成する。
 * @param {CryptoKey} privateKey  importSigningKeyPair の戻り値
 * @param {string} message  通常 `${timestamp}.${rawBody}`
 * @returns {Promise<string>} base64url 署名 (raw IEEE P1363 形式、~64 byte)
 */
export async function signRequest(privateKey, message) {
  // Phase 2-H1: Rust SigningKey opaque handle path (= no CryptoKey, no subtle.sign).
  //   Detect duck-typed handle and prefer it.
  if (privateKey && typeof privateKey.ecdsa_sign === "function") {
    const sig = privateKey.ecdsa_sign(enc.encode(message));
    return b64uEncode(new Uint8Array(sig));
  }
  // fallback 撤去: 署名は Rust SigningKey opaque handle 必須 (subtle.sign 廃止)。
  throw new Error("signRequest: SigningKey opaque handle (ecdsa_sign) 必須");
}

/**
 * リクエスト署名を検証する (サーバ側でも使うが、ブラウザでは主に self-test 用)。
 */
// ---------------------------------------------------------------------------
// Phase 7.0b: 3-tier KEK helpers (BEK / CHK_KEK wrapping for Records feature)
// ---------------------------------------------------------------------------
//
// Records 機能 (電子書類保管) はファイル本体と sub-vault chunks を別 Arweave tx
// として保存する。再 unlock 時に MEK が同じであれば BEK / CHK_KEK の wrap も
// そのまま使えるが、Recovery 再発行 (Case B) で MEK が変わる場合に Arweave 上の
// 全 encrypted blob を再 write するのは非現実的 (records 数 × ¥6/write)。
//
// 解決策: 業界標準の 3-tier key wrapping (AWS KMS / Apple iCloud Keychain 採用):
//   レイヤ 1: MEK              ← 2-of-3 で derive (現状通り)
//   レイヤ 2: BEK / CHK_KEK    ← 各 blob / 各 chunk ごとに random
//   レイヤ 3: 実データ          ← BEK / CHK_KEK で encrypt、Arweave 保存
//
// MEK rotation 時:
//   各 wrappedBEK / wrappedCHK_KEK を decrypt → 新 MEK で re-wrap → main vault に保存
//   Arweave 上の暗号化済み blob は touch 不要 (BEK / CHK_KEK 自体は不変)
//
// API:
//   generateBlobKey()         → 32 byte random key (BEK or CHK_KEK)
//   wrapKey(mek, key)         → { wrapped, iv } (key を MEK で wrap)
//   unwrapKey(mek, wrapped, iv) → key bytes
//   rewrapKey(oldMek, newMek, oldWrapped, oldIv) → { wrapped, iv } (Case B 用)
//   encryptBlob(key, plaintext) → { ciphertext, iv }
//   decryptBlob(key, ciphertext, iv) → plaintext

// Phase 2-H2 最終 (2026-06): records BEK/CEK は BekKey opaque handle (wrap_bek/unwrap_bek)
// に一本化。旧 generateBlobKey/wrapKey/unwrapKey/rewrapKey/encryptBlob/decryptBlob
// (CryptoKey 経路) は撤去済み。

// ---------------------------------------------------------------------------
// Public-key utilities (server side / tests)
// ---------------------------------------------------------------------------

/**
 * publicKey raw (65 byte uncompressed) → JWK
 */
export function publicKeyRawToJwk(rawBytes) {
  if (rawBytes.length !== 65 || rawBytes[0] !== 0x04) {
    throw new Error("Expected 65-byte uncompressed P-256 publicKey (0x04 || X || Y)");
  }
  return {
    kty: "EC",
    crv: "P-256",
    x: b64uEncode(rawBytes.slice(1, 33)),
    y: b64uEncode(rawBytes.slice(33, 65)),
    ext: true,
  };
}

/**
 * JWK → 65-byte uncompressed raw.
 */
export function publicKeyJwkToRaw(jwk) {
  const x = b64uDecode(jwk.x);
  const y = b64uDecode(jwk.y);
  if (x.length !== 32 || y.length !== 32) throw new Error("Invalid JWK x/y length");
  return concatBytes(new Uint8Array([0x04]), x, y);
}


// ===========================================================================
// Utilities — Recovery Secret formatting, password generator, feature checks.
// (旧 vault-crypto.js から v5 cutover 時に保持。これらは v5 設計に直接関係
//  ないが UI/CLI から使われる convenience 関数。)
// ===========================================================================

// ----- Recovery Secret string format -----
// RS1-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX (160-bit entropy / 32 base32 chars)
// 内部の rMat 派生は deriveRMat が担当。本関数は文字列の発行と検証のみ。

export function generateRecoverySecret() {
  const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let s = "";
  for (const b of bytes) s += BASE32[b % 32];
  const groups = [];
  for (let i = 0; i < 8; i++) groups.push(s.slice(i * 4, (i + 1) * 4));
  return "RS1-" + groups.join("-");
}

export function parseRecoverySecret(s) {
  if (!s) return null;
  const cleaned = s.replace(/\s/g, "").toUpperCase();
  const m = cleaned.match(/^RS1-([A-Z2-7]{4}-){7}[A-Z2-7]{4}$/);
  if (!m) return null;
  return cleaned;
}

// ----- Password generator (UI 用) -----
const POOLS = {
  lower: "abcdefghijklmnopqrstuvwxyz",
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digit: "0123456789",
  symbol: "!@#$%^&*-_=+?.,:;",
};

export function generatePassword(options = {}) {
  const length = Math.max(8, Math.min(128, options.length ?? 20));
  const pools = [];
  if (options.lower !== false) pools.push(POOLS.lower);
  if (options.upper !== false) pools.push(POOLS.upper);
  if (options.digit !== false) pools.push(POOLS.digit);
  if (options.symbol !== false) pools.push(POOLS.symbol);
  if (pools.length === 0) pools.push(POOLS.lower + POOLS.upper + POOLS.digit);
  const combined = pools.join("");
  const out = [];
  for (const pool of pools) out.push(_pickOne(pool));
  for (let i = out.length; i < length; i++) out.push(_pickOne(combined));
  for (let i = out.length - 1; i > 0; i--) {
    const j = _randomInt(i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out.join("");
}

function _pickOne(alphabet) { return alphabet[_randomInt(alphabet.length)]; }

function _randomInt(max) {
  const limit = Math.floor(0xFFFFFFFF / max) * max;
  const buf = new Uint32Array(1);
  while (true) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % max;
  }
}

/** Heuristic password strength score 0-4. */
export function passwordStrength(pw) {
  if (!pw) return 0;
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 16) score++;
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^\w]/].filter((r) => r.test(pw)).length;
  if (classes >= 3) score++;
  if (classes === 4 && pw.length >= 12) score++;
  return Math.min(4, score);
}

// ----- Browser feature checks (UI gating) -----

export function isPasskeySupported() {
  return !!(
    typeof window !== "undefined" &&
    window.PublicKeyCredential &&
    navigator.credentials &&
    navigator.credentials.create
  );
}

export function isSecureContextOk() {
  if (typeof window === "undefined") return false;
  if (typeof window.isSecureContext === "boolean") return window.isSecureContext;
  const proto = window.location.protocol;
  const host = window.location.hostname;
  if (proto === "https:") return true;
  if (proto === "http:" && (host === "localhost" || host === "127.0.0.1" || host === "[::1]")) return true;
  return false;
}

/**
 * Pre-check: can this environment plausibly do WebAuthn + PRF?
 * Authoritative confirmation requires an actual ceremony.
 */
export function isPRFCapable() {
  if (typeof window === "undefined") return false;
  if (!window.PublicKeyCredential) return false;
  if (typeof navigator?.credentials?.create !== "function") return false;
  return true;
}

// ===========================================================================
// Phase 7.2-B: K1/K2 split + ECIES helpers (Business mode 用)
// ---------------------------------------------------------------------------
// 設計詳細: docs/phase-7.2-B-server-wrap.md
//
// Business mode では MEK を K1 (server gate) + K2 (client factor) の HKDF で派生する。
// 既存 encryptVault/decryptVault はここの helper を組み合わせる形で Phase 7.2-B.5/.6
// で改修する。
// ===========================================================================

const HKDF_SALT_MEK_BUSINESS = "arpass-mek-business-v1";
const HKDF_INFO_MEK_BUSINESS = "mek-business";
const HKDF_SALT_KEK_K1ADMIN  = "arpass-kek-k1admin-v1";
const HKDF_INFO_KEK_K1ADMIN  = "kek-k1admin";

/**
 * Phase 7.3-A.7d: Personal mode の raw mek (= random 32B) を 非 extractable HKDF base に
 *   import する helper。 一度 import すれば session.mekHkdfKey として保管され、 recoveryProtectKey
 *   など sub-key 派生に使える。 raw mek は import 後 (= signup/unlock 直後) に fill(0) で消去可能。
 *
 * @param {Uint8Array} mekRaw 32 byte
 * @returns {Promise<CryptoKey>} non-extractable HKDF base
 */
/**
 * Generate fresh K1 (32 byte random)。Business mode の write 開始時に呼ぶ。
 */
export function generateK1() {
  return crypto.getRandomValues(new Uint8Array(32));
}

// ===========================================================================
// ---------------------------------------------------------------------------
// Phase 7.2-B v2 helpers — WebCrypto ECDH ECIES + emp_keypair management
// ---------------------------------------------------------------------------
// v2 設計では admin が ephemeral keypair で per-employee に K1 を wrap し、
// 社員は vault 内 w_emp = AES(K2, PKCS8(emp_priv)) から自分の static keypair を
// 取り出して ECIES unwrap する。
//
// v1 の noble-curves ベース eciesEncrypt/eciesDecrypt (server-keypair 用) とは別系統。
// ---------------------------------------------------------------------------

/**
 * emp_keypair (ECDH P-256) を新規生成。signup 時に 1 回呼ぶ。
 * extractable=true で生成 (= w_emp に PKCS8 wrap するため)。
 * 戻り値: { privKey, pubKey, pubKeyJwk } — pubKeyJwk は server register-pubkey 用。
 */
export async function generateEmpKeypair() {
  // 非対称鍵 handle化 Phase2: emp keypair を Rust p256 で生成し、 privScalar (raw) +
  //   EmpPrivKey opaque handle + pubKeyJwk を返す。 CryptoKey は生成しない。
  //   privScalar は caller が wrap 後に即 fill(0) する。 Rust 未ロード時のみ WebCrypto fallback。
  const rc = await _getRustCrypto();
  if (rc && typeof rc.p256_keypair_generate === "function" && typeof rc.EmpPrivKey === "function") {
    const kp = rc.p256_keypair_generate();      // 32 priv || 65 pub (SEC1)
    const privScalar = kp.slice(0, 32);
    const pubSec1 = kp.slice(32);
    const pubKeyJwk = {
      kty: "EC", crv: "P-256",
      x: b64uEncode(pubSec1.slice(1, 33)),
      y: b64uEncode(pubSec1.slice(33, 65)),
    };
    const privHandle = new rc.EmpPrivKey(privScalar);
    return { privScalar, privHandle, pubKeyJwk, privKey: null, pubKey: null };
  }
  // fallback 撤去: Rust 必須 (emp keypair は EmpPrivKey handle のみ)。
  throw new Error("generateEmpKeypair: Rust crypto core (p256_keypair_generate / EmpPrivKey) 必須");
}


/**
 * 増分1 (K2 handle 一本化): K2 raw を MekKey opaque handle のみに import。
 *   CryptoKey (k2AesKey/k2HkdfKey) を一切作らない。 Rust crypto core 必須。
 *   raw K2 の fill(0) は caller 責務。
 * @param {Uint8Array} k2Raw 32 byte
 * @returns {Promise<object>} MekKey opaque handle
 */
export async function importK2AsHandle(k2Raw) {
  if (!(k2Raw instanceof Uint8Array) || k2Raw.length !== 32)
    throw new Error("k2Raw must be 32 byte Uint8Array");
  const rc = await _getRustCrypto();
  if (!rc || typeof rc.MekKey !== "function")
    throw new Error("importK2AsHandle: Rust crypto core (MekKey) 未ロード");
  return new rc.MekKey(k2Raw);
}

/**
 * Phase 7.3-A.9 part 3: K2 を HKDF base (= 非 extractable CryptoKey)、 K1 を salt として
 *   real_MEK (AES-GCM CryptoKey) を派生する v2 scheme。
 *
 * 旧 scheme (= deriveBusinessMekKey): IKM = K1||K2 concat、 salt = 固定。 これだと
 *   raw K2 を concat に持ち込む必要があり、 K2 を非 extractable にできなかった。
 *
 * 新 scheme: IKM = K2、 salt = K1 raw。 K1 は配布のため raw が transient に必要 (= 既に
 *   transient decode pattern)、 salt は HKDF の公開パラメータなので raw OK。 K2 は永続的に
 *   CryptoKey として session 保管できる。
 *
 * 注: 旧 scheme と output bytes が異なるため、 既存 business envelope は復号不可。
 *     service-in 前なので互換不要 (= 既存 corp slot を re-create 想定)。
 *
 * @param {Uint8Array} k1Bytes 32 byte (transient、 caller responsibility は fill(0))
 * @param {CryptoKey} k2HkdfKey 非 extractable HKDF base
 * @param {object} [opts] { usages = ["encrypt","decrypt","wrapKey","unwrapKey"] }
 * @returns {Promise<CryptoKey>} 非 extractable AES-GCM real_MEK
 */
export async function deriveBusinessMekKeyV2(k1Bytes, k2HkdfKey, opts = {}) {
  // Stage2 Business Phase B incr2: k1 を K1Key opaque handle でも受け付ける (= 生 K1 不在)。
  //   handle は caller (= decryptVaultAuto の eciesUnwrapToK1Handle) が所有 → ここでは free しない。
  const _k1IsHandle = k1Bytes && typeof k1Bytes.derive_business_mek_v2 === "function";
  if (!_k1IsHandle && (!(k1Bytes instanceof Uint8Array) || k1Bytes.length !== 32))
    throw new Error("k1 must be 32 byte Uint8Array or K1Key opaque handle");
  // Phase 2-H4-full F5: k2HkdfKey が MekKey opaque handle (= H4-full F4 経路) の場合
  //   K1Key.derive_business_mek_v2 を使用、 HKDF 全体を WASM 内で実行。
  //   返却は MekKey handle (= raw bytes JS heap 露出ゼロ)。
  if (k2HkdfKey && typeof k2HkdfKey.aes_gcm_encrypt === "function") {
    // incr2: k1 が既に K1Key handle なら直接使用 (= 生 K1 を materialize しない)。
    if (_k1IsHandle) {
      return k1Bytes.derive_business_mek_v2(
        k2HkdfKey,
        enc.encode(HKDF_INFO_MEK_BUSINESS + "-v2")
      );
    }
    const rc = await _getRustCrypto();
    if (rc && typeof rc.K1Key === "function") {
      const tmpK1Handle = new rc.K1Key(k1Bytes);
      try {
        const mekHandle = tmpK1Handle.derive_business_mek_v2(
          k2HkdfKey,
          enc.encode(HKDF_INFO_MEK_BUSINESS + "-v2")
        );
        return mekHandle;
      } finally {
        if (typeof tmpK1Handle.free === "function") {
          try { tmpK1Handle.free(); } catch (_) {}
        }
      }
    }
  }
  // fallback 撤去: K2 は MekKey opaque handle 必須 (CryptoKey K2 / raw 経路廃止、 Rust 必須)。
  throw new Error("deriveBusinessMekKeyV2: k2 は MekKey opaque handle 必須 (Rust)");
}

/**
 * Phase 7.3-A.9 part 3: sub-key 派生用の mekHkdfKey (= 非 extractable HKDF base) を
 *   K2HkdfKey + K1 salt から派生。 deriveBusinessMekKeyV2 と同じ chain で recoveryProtectKey
 *   などの sub-key 派生に使える。
 */
export async function deriveBusinessMekHkdfKeyV2(k1Bytes, k2HkdfKey) {
  // Stage2 Business Phase B incr2: k1 を K1Key opaque handle でも受け付ける (= 生 K1 不在)。
  const _k1IsHandle = k1Bytes && typeof k1Bytes.derive_business_mek_v2 === "function";
  if (!_k1IsHandle && (!(k1Bytes instanceof Uint8Array) || k1Bytes.length !== 32))
    throw new Error("k1 must be 32 byte Uint8Array or K1Key opaque handle");
  // Phase 2-H4-full F7-A (retry): MekKey opaque handle 入力受付。
  //   K1Key.derive_business_mek_v2 経由で MekKey handle を返却。
  //   bit-equivalence は Rust test test_business_signing_chain_bit_equivalent で担保。
  if (k2HkdfKey && typeof k2HkdfKey.aes_gcm_encrypt === "function") {
    // incr2: k1 が既に K1Key handle なら直接使用 (caller 所有 → free しない)。
    if (_k1IsHandle) {
      return k1Bytes.derive_business_mek_v2(
        k2HkdfKey,
        enc.encode(HKDF_INFO_MEK_BUSINESS + "-v2")
      );
    }
    const rc = await _getRustCrypto();
    if (rc && typeof rc.K1Key === "function") {
      const tmpK1Handle = new rc.K1Key(k1Bytes);
      try {
        return tmpK1Handle.derive_business_mek_v2(
          k2HkdfKey,
          enc.encode(HKDF_INFO_MEK_BUSINESS + "-v2")
        );
      } finally {
        if (typeof tmpK1Handle.free === "function") {
          try { tmpK1Handle.free(); } catch (_) {}
        }
      }
    }
  }
  // fallback 撤去: K2 は MekKey opaque handle 必須 (CryptoKey K2 経路廃止、 Rust 必須)。
  throw new Error("deriveBusinessMekHkdfKeyV2: k2 は MekKey opaque handle 必須 (Rust)");
}

/**
 * 増分1 (K2 handle 一本化): emp_priv を K2 MekKey opaque handle で wrap。
 *   handle.aes_gcm_encrypt 経由 (= 生 K2 を AES-GCM CryptoKey に import しない)。
 */
export async function wrapEmpPrivWithK2Handle(k2Handle, empPriv) {
  if (!k2Handle || typeof k2Handle.aes_gcm_encrypt !== "function")
    throw new Error("k2Handle must be MekKey opaque handle");
  // Phase2: raw 32-byte scalar をそのまま wrap (= 新形式)。 CryptoKey は pkcs8 export (legacy)。
  // fallback 撤去: raw 32-byte scalar 必須 (pkcs8 CryptoKey 経路廃止)。
  if (!(empPriv instanceof Uint8Array) || empPriv.length !== 32)
    throw new Error("wrapEmpPrivWithK2Handle: empPriv は 32-byte raw scalar 必須");
  const iv = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const ct = await aesGcmEncrypt(k2Handle, iv, empPriv);  // raw scalar は caller が fill
  return { i: b64uEncode(iv), c: b64uEncode(ct) };
}

/**
 * Stage2 Business Phase B: K2 を MekKey opaque handle (= k2Handle) のまま w_emp を
 *   unwrap し EmpPrivKey opaque handle を返す。 unwrapEmpPrivAsHandleWithK2Key の
 *   handle 入力版 (= raw K2 を AES-GCM CryptoKey に import せず、 handle.aes_gcm_decrypt で
 *   復号 = 生 K2 を JS heap に materialize しない)。
 *
 *   k2Handle は decryptVaultBusiness の handle 経路 (= kek.unwrap_mek) が産む MekKey。
 *   Rust 未対応環境では null を返す → caller は CryptoKey (raw) 経路で fallback。
 *
 * @param {object} k2Handle  MekKey opaque handle wrapping K2 bytes (aes_gcm_decrypt 持ち)
 * @param {{i:string,c:string}} w_emp
 * @returns {Promise<object|null>} EmpPrivKey handle or null
 */
export async function unwrapEmpPrivAsHandleWithK2Handle(k2Handle, w_emp) {
  if (!w_emp || !w_emp.i || !w_emp.c) throw new Error("w_emp must have { i, c }");
  if (!k2Handle || typeof k2Handle.aes_gcm_decrypt !== "function")
    throw new Error("k2Handle must be MekKey opaque handle");
  const rc = await _getRustCrypto();
  if (!rc || typeof rc.EmpPrivKey !== "function") return null;
  // aesGcmDecrypt(handle, iv, ct) は handle を duck-type 検出して handle.aes_gcm_decrypt(ct, iv) を呼ぶ。
  const dec0 = new Uint8Array(await aesGcmDecrypt(k2Handle, b64uDecode(w_emp.i), b64uDecode(w_emp.c)));
  try {
    // Phase2: 32-byte は raw scalar (新形式)、 それ以外は pkcs8 (legacy) として復元。
    return dec0.length === 32
      ? new rc.EmpPrivKey(dec0)
      : rc.EmpPrivKey.from_pkcs8(dec0);
  } finally {
    dec0.fill(0);
  }
}

/**
 * Phase 2-F8 step 2b: ECIES unwrap で K1Key opaque handle を直接返却 (= K1 raw window 消去)。
 *   empPrivHandle が EmpPrivKey opaque handle なら、 全工程 WASM 内で完結。
 *   eph_pub は JWK のまま受けて 65-byte SEC1 に変換。
 *
 * 注: 現状 dormant、 caller (= eciesUnwrapForRecipient consumer) は別 cycle で polymorphic 化。
 *
 * @param {object} empPrivHandle EmpPrivKey opaque handle
 * @param {{eph_pub:object,iv:string,ct:string}} encK1
 * @returns {Promise<object>} K1Key opaque handle
 */
export async function eciesUnwrapToK1Handle(empPrivHandle, encK1) {
  if (!encK1 || !encK1.eph_pub || !encK1.iv || !encK1.ct) {
    throw new Error("encK1 must have { eph_pub, iv, ct }");
  }
  if (!empPrivHandle || typeof empPrivHandle.ecies_unwrap_to_k1key !== "function") {
    throw new Error("empPrivHandle must be EmpPrivKey opaque handle");
  }
  // JWK → 65-byte SEC1 uncompressed (= 0x04 || X || Y)
  const xBytes = b64uDecode(encK1.eph_pub.x);
  const yBytes = b64uDecode(encK1.eph_pub.y);
  const ephPubSec1 = new Uint8Array(65);
  ephPubSec1[0] = 0x04;
  ephPubSec1.set(xBytes, 1);
  ephPubSec1.set(yBytes, 33);
  // ECIES KEK 派生用 salt/info (= existing constants in app-main / corp.js)
  // arpass-ecies-v1 + "kek" は server-side / client-side で同期されている。
  const enc = new TextEncoder();
  return empPrivHandle.ecies_unwrap_to_k1key(
    ephPubSec1,
    b64uDecode(encK1.iv),
    b64uDecode(encK1.ct),
    enc.encode("arpass-ecies-v1"),
    enc.encode("kek")
  );
}

/**
 * Phase 7.2-B v2 ECIES (WebCrypto): admin → 社員 emp_pubkey 宛て wrap。
 * ephemeral keypair は毎回新規生成 = forward secrecy。
 *
 * @param {JWK|CryptoKey} recipientPubkey
 * @param {Uint8Array} plaintext  (= K1 の 32 byte)
 * @returns {Promise<{eph_pub: JWK, iv: string, ct: string}>}
 */
// Stage2 ECIES 互換 fix: ECDH 共有秘密 X から HKDF(salt="arpass-ecies-v1", info="kek") で
//   AES-GCM kek を導出する共通ヘルパー。 旧 eciesWrap/Unwrap は WebCrypto deriveKey で生 ECDH 秘密を
//   そのまま AES 鍵にしていたため、 Rust handle 経路 (ecies_unwrap_to_k1key = HKDF) や
//   eciesEncrypt/Decrypt (HKDF) と非互換で、 handle 経路の enc_K1 unwrap が全て tag mismatch していた。
//   non-extractable CryptoKey でも deriveBits は可能なので raw scalar の JS 露出はない。
async function _eciesAesKeyFromSharedX(sharedX, usages) {
  // #3 Part B (ECIES KEK の WASM 内派生): sharedX から HKDF(salt="arpass-ecies-v1", info="kek")
  //   で AES-GCM KEK を WASM 内で導出し MekKey opaque handle として返す。 raw KEK は JS heap に
  //   出ない。 #2 の derive_kek_handle を再利用 (material2 を空にして IKM = sharedX)。
  //   bit-equivalence: HKDF-SHA256(sharedX, salt, info, 32) は旧 deriveBits 経路と完全一致、
  //   Rust ecies_unwrap_to_k1key の KEK 派生とも同一スキーム。
  const rc = await _getRustCrypto();
  if (!rc || typeof rc.derive_kek_handle !== "function")
    throw new Error("_eciesAesKeyFromSharedX: Rust crypto core (derive_kek_handle) 必須");
  return rc.derive_kek_handle(
    sharedX,
    new Uint8Array(0),
    enc.encode(ECIES_HKDF_SALT),
    enc.encode(ECIES_HKDF_INFO),
  );
}

export async function eciesWrapForRecipient(recipientPubkey, plaintext) {
  // 非対称鍵 handle 化 Phase 1: ephemeral keypair + ECDH を Rust p256 で実行 (CryptoKey 不使用)。
  //   ECDH 共有秘密 X は WebCrypto と Rust で同一のため、 既存の配布データ・unwrap 経路と互換。
  //   Rust 未ロード時のみ従来 WebCrypto 経路に fallback。
  if (_rustCrypto && typeof _rustCrypto.p256_keypair_generate === "function"
      && typeof _rustCrypto.p256_ecdh === "function") {
    // recipient pubkey → 65-byte SEC1 (0x04 || X || Y)
    let recipientSec1;
    if (recipientPubkey instanceof Uint8Array && recipientPubkey.length === 65 && recipientPubkey[0] === 0x04) {
      recipientSec1 = recipientPubkey;
    } else {
      const xb = b64uDecode(recipientPubkey.x);
      const yb = b64uDecode(recipientPubkey.y);
      recipientSec1 = new Uint8Array(65);
      recipientSec1[0] = 0x04;
      recipientSec1.set(xb, 1);
      recipientSec1.set(yb, 33);
    }
    const kp = _rustCrypto.p256_keypair_generate();   // 32 priv || 65 pub (SEC1)
    const ephPriv = kp.slice(0, 32);
    const ephPubSec1 = kp.slice(32);
    const sharedX = _rustCrypto.p256_ecdh(ephPriv, recipientSec1);  // 32-byte X 座標
    ephPriv.fill(0);
    const aesKey = await _eciesAesKeyFromSharedX(sharedX, ["encrypt"]);  // MekKey handle
    sharedX.fill(0);
    const iv = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
    const ct = await aesGcmEncrypt(aesKey, iv, plaintext);
    if (aesKey && typeof aesKey.free === "function") { try { aesKey.free(); } catch (_) {} }
    const eph_pub = {
      kty: "EC", crv: "P-256",
      x: b64uEncode(ephPubSec1.slice(1, 33)),
      y: b64uEncode(ephPubSec1.slice(33, 65)),
    };
    return { eph_pub, iv: b64uEncode(iv), ct: b64uEncode(ct) };
  }
  // fallback 撤去: Rust 必須 (ephemeral keypair + ECDH は Rust p256)。
  throw new Error("eciesWrapForRecipient: Rust crypto core (p256_keypair_generate / p256_ecdh) 必須");
}

// ---------------------------------------------------------------------------

// Phase 7.2-B: Business mode encryptVault / decryptVault
// ---------------------------------------------------------------------------
// 既存 encryptVault/decryptVault は触らず、Business mode 用に新規関数を追加。
// vault-client.js が mode に応じて dispatch する。
//
// 設計詳細: docs/phase-7.2-B-server-wrap.md §2-§4
// ===========================================================================

/**
 * Business mode 用 envelope 暗号化 (Phase 7.2-B α 案: Personal mode + ws field のみ)。
 *
 * Personal mode との差分:
 *   1. envelope.m = "business"
 *   2. envelope.cid = companyId
 *   3. envelope.kv = corpKeypair version
 *   4. envelope.ws = K1 を server ECDH 公開鍵で ECIES wrap
 *   5. body = HKDF(K1 || K2) で暗号化 (Personal は K2 のみで暗号化)
 *
 * Recovery は社員自身が持つ (= Personal mode 同様 encryptedRecovery を vault に inject)。
 * wsa (admin recovery wrap) は廃止 — Arpass 廃業時は admin vault に escrow されている
 * corpKeypair private key を使って社員が local unwrap する設計。
 *
 * @param {object} vault              平文 vault
 * @param {string} password           Master Password
 * @param {Uint8Array} prfOutput      WebAuthn PRF (32B)
 * @param {Uint8Array} recoveryMaterial  rMat (32B)
 * @param {string} credIdHash         credIdHash (b64u 16)
 * @param {object} bizCtx             { companyId, kekVersion, serverPublicKeyJwk }
 * @param {string|null} [recoverySecret=null]  encryptedRecovery を inject するなら渡す
 * @returns {Promise<{ envelope, mek, k2, outerKeyBytes, appNameTag, signingKey }>}
 */
export async function encryptVaultBusiness(vault, password, prfOutput, recoveryMaterial, credIdHash, bizCtx, recoverySecret = null) {
  // Phase 7.2-B v2: envelope.ws/wsa を廃止し、 emp_keypair を vault 内 w_emp に K2 wrap で保存。
  // K1 は admin が server の corpK1V2:<cid>:<pkH> に upload して配布される。
  if (!password) throw new Error("password required");
  if (!(prfOutput instanceof Uint8Array) || prfOutput.length < 16)
    throw new Error("prfOutput required");
  if (!(recoveryMaterial instanceof Uint8Array) || recoveryMaterial.length < 32)
    throw new Error("recoveryMaterial (32 byte) required");
  if (!credIdHash) throw new Error("credIdHash required");
  if (!bizCtx?.companyId) throw new Error("bizCtx.companyId required");
  // v2: kekVersion / serverPublicKeyJwk は不要 (= envelope.ws 廃止)

  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN_BYTES));
  // Phase 7.2-B v2.2: k1Pending mode 対応
  //   bizCtx.k1Pending=true → ZERO_K1 (32 byte 全部 0) で body 暗号化、 envelope に flag 立てる。
  //     admin が後で K1 配布 → member の transition で実 K1 で再暗号化 + flag 削除。
  //   bizCtx.k1Pending=false (or 未指定) → initialK1 を使う or ランダム生成。
  const isK1Pending = !!bizCtx.k1Pending;
  const k1 = isK1Pending
    ? new Uint8Array(32)  // ZERO_K1 sentinel
    : (bizCtx.initialK1 instanceof Uint8Array && bizCtx.initialK1.length === 32
        ? new Uint8Array(bizCtx.initialK1)
        : crypto.getRandomValues(new Uint8Array(32)));
  const k2 = crypto.getRandomValues(new Uint8Array(32));
  // 増分1 (K2 handle 一本化): K2 を MekKey opaque handle のみに import (CryptoKey 廃止)。
  //   raw K2 は wrap 用に末尾まで保持し fill(0)、 以後の wrap/derive は handle 経由のみ。
  const k2Handle = await importK2AsHandle(k2);
  // mekKey は V2 scheme で派生 (K2 handle base + K1 salt)
  const mekKey = await deriveBusinessMekKeyV2(k1, k2Handle, {
    usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
  });

  const kdfParamsForEnvelope = getCurrentKdfParams();
  const pMat = await derivePMat(password, salt, kdfParamsForEnvelope);
  const kMat = deriveKMat(prfOutput);
  const rMat = recoveryMaterial.slice(0, 32);

  // 既存 envelope と同じ wrap 構造 (K2 を wrap)
  const kekPR = await deriveKEK(pMat, rMat, "kek_pr");
  const kekPK = await deriveKEK(pMat, kMat, "kek_pk");
  const kekKR = await deriveKEK(kMat, rMat, "kek_kr");
  const ivA = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const ivB = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const ivC = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  // K2 raw を 3 つの KEK で wrap (= 既存 schema 維持。 K2 を unwrap 後は importK2AsKeys で CryptoKey 化)
  const wrapA = await aesGcmEncrypt(kekPR, ivA, k2);
  const wrapB = await aesGcmEncrypt(kekPK, ivB, k2);
  const wrapC = await aesGcmEncrypt(kekKR, ivC, k2);

  // v2: emp_keypair をランダム生成 → emp_priv を K2 で wrap (envelope.w_emp に格納)
  const empKeypair = await generateEmpKeypair();
  const w_emp = await wrapEmpPrivWithK2Handle(k2Handle, empKeypair.privScalar);
  if (empKeypair.privScalar instanceof Uint8Array) empKeypair.privScalar.fill(0);  // raw scalar 破棄

  // encryptedRecovery を vault に inject (= V2 では mekKey 経由)
  // Phase 7.3-A.9 part 3: realMek raw を使わない。 deriveRecoveryProtectKey は mekHkdfKey を accept。
  let vaultWithRecovery = vault;
  if (typeof recoverySecret === "string" && recoverySecret.length > 0) {
    // 修正(recovery K1非依存化): encryptedRecovery は K2 由来鍵で保護する。
    //   旧実装は mekHkdf(=HKDF(K1,K2)) を使っていたが、 signup は ZERO_K1、 その後 transition/
    //   rotation で K1 が変わると mek が変化し、 再表示が tag mismatch で不能になっていた。
    //   K2 は社員固有で K1 変化に影響されないため、 K2 で保護すれば常に再表示可能。
    const er = await encryptRecoveryWithMek(recoverySecret, k2Handle);
    vaultWithRecovery = { ...vault, encryptedRecovery: er };
  }

  // 本体暗号化 (real_MEK で = V2 scheme)
  const ivBody = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const padded = padPlaintext(enc.encode(JSON.stringify(vaultWithRecovery)));
  const bodyCt = await aesGcmEncrypt(mekKey, ivBody, padded);

  const envelope = {
    v: VAULT_FORMAT_V5,
    m: "business",
    kdfV2: true,                    // Phase 7.3-A.9 part 3: K2-based HKDF derivation
    kdfParams: kdfParamsForEnvelope,  // Phase 7.4.1: KDF パラメータを envelope に固定 (派生時と一致)
    cid: bizCtx.companyId,
    s: b64uEncode(salt),
    i: b64uEncode(ivBody),
    c: b64uEncode(bodyCt),
    w: {
      a: { i: b64uEncode(ivA), c: b64uEncode(wrapA) },
      b: [{ h: credIdHash, i: b64uEncode(ivB), c: b64uEncode(wrapB) }],
      c: [{ h: credIdHash, i: b64uEncode(ivC), c: b64uEncode(wrapC) }],
    },
    // === v2: K1 配布関連 ===
    w_emp,                          // AES(K2, PKCS8(emp_priv))
    emp_pub: empKeypair.pubKeyJwk,  // 整合性確認用 cache (server が authoritative)
    // 廃止: envelope.ws (= K1 を server で wrap)、 envelope.kv (= kekVersion)
  };
  // Phase 7.2-B v2.2: signup 直後の member は K1 未配布、 body は ZERO_K1 + K2 で暗号化
  if (isK1Pending) envelope.k1Pending = true;

  const signingKey = deriveSigningKey(k2);
  const outerKeyBytes = deriveOuterKeyBytes(rMat);
  const appNameTag = deriveAppNameTag(rMat, null);
  const k1Copy = new Uint8Array(k1);

  // memory hygiene — K2 raw は handle import 後 即破棄 (CryptoKey は作っていない)
  k1.fill(0);
  k2.fill(0);

  // mekHkdfKey も派生 (recoveryProtect 等の sub-key 派生用) — K2 handle 経由
  const mekHkdfKey = await deriveBusinessMekHkdfKeyV2(k1Copy, k2Handle);

  return {
    envelope, mek: null, mekKey, mekHkdfKey,  // Phase 7.3-A.9: raw mek 不在
    k1: k1Copy,                     // v2: caller が server に upload-enc-k1 で配布
    k2Handle,                        // 増分1: K2 は MekKey opaque handle のみ (CryptoKey 廃止)
    empKeypair,                     // v2: caller が register-pubkey で公開鍵登録
    outerKeyBytes, appNameTag, signingKey,
  };
}


/**
 * Business mode envelope の復号。
 * 通常運用: k1 は /api/corp/unwrap-k1 経由で取得した raw 32B
 * 緊急復旧 (admin): k1 は admin escrow keypair で復号 (Phase 7.2-B α 案、Arpass 廃業時の private key 配布 UI 経由)。
 *
 * caller が k1 を準備して渡す (= server fetch or admin escrow path は vault-client.js 側)。
 *
 * @param {object} envelope  business envelope (m === "business")
 * @param {object} factors   { password?, prfOutput?, recoveryMaterial?, credIdHash? }
 * @param {Uint8Array} k1Bytes  32B
 * @returns {Promise<{ vault, mek, signingKey, path }>}
 */
export async function decryptVaultBusiness(envelope, factors, k1Bytes) {
  // Phase 7.2-B v2: envelope.w_emp / emp_pub を読む。 envelope.ws/wsa は廃止。
  // caller が K1 を server (/api/corp/fetch-enc-k1) から取得 + emp_priv で ECIES unwrap して渡す。
  if (!envelope || envelope.v !== VAULT_FORMAT_V5 || envelope.m !== "business")
    throw new Error("business envelope expected");
  if (!envelope.w_emp || !envelope.cid)
    throw new Error("v2 business envelope must have w_emp and cid");
  // Phase 7.2-B v2.2: k1Pending mode の場合は k1 = ZERO_K1 で復号可能 (= 初回 signup placeholder)
  if (envelope.k1Pending) {
    if (k1Bytes == null) k1Bytes = new Uint8Array(32);  // ZERO_K1
  }
  // Stage2 Business Phase B incr2: k1 は raw 32 byte または K1Key opaque handle を許容。
  //   handle は decryptVaultAuto が eciesUnwrapToK1Handle で生成 (= 生 K1 不在)。
  //   deriveBusinessMekKeyV2 / deriveBusinessMekHkdfKeyV2 が handle を直接消費する。
  const _k1IsHandle = k1Bytes && typeof k1Bytes.derive_business_mek_v2 === "function";
  if (!_k1IsHandle && (!(k1Bytes instanceof Uint8Array) || k1Bytes.length !== 32))
    throw new Error("k1 (32 byte Uint8Array or K1Key handle) required");

  const haveP = !!factors?.password;
  const haveK = factors?.prfOutput instanceof Uint8Array && factors.prfOutput.length >= 16;
  const haveR = factors?.recoveryMaterial instanceof Uint8Array && factors.recoveryMaterial.length >= 32;
  if ([haveP, haveK, haveR].filter(Boolean).length < 2)
    throw new Error("Need at least 2 of {password, prfOutput, recoveryMaterial}");

  const salt = b64uDecode(envelope.s);
  // Phase 7.4.1: envelope.kdfParams を採用 (旧 envelope の場合は CURRENT)
  const pMat = haveP ? await derivePMat(factors.password, salt, envelope.kdfParams) : null;
  const kMat = haveK ? deriveKMat(factors.prfOutput) : null;
  const rMat = haveR ? factors.recoveryMaterial.slice(0, 32) : null;

  let k2 = null;
  let k2Handle = null;   // Stage2 Business Phase B: 生 K2 を materialize しない handle 経路
  let path = null;
  // Stage2 Business Phase B: 通常解錠は k2Handle 経由 (= kek.unwrap_mek)。 生 K2 を JS heap に
  //   出さない。 mutation (= K1 rotation / changePassword 等) は forceRawMek で raw 経路を選ぶ。
  const _wantRaw = !!factors?.forceRawMek;

  if (haveP && haveK && envelope.w?.b?.length) {
    const candidates = factors.credIdHash
      ? envelope.w.b.filter((w) => w.h === factors.credIdHash)
      : envelope.w.b;
    for (const w of candidates) {
      try {
        const kek = await deriveKEK(pMat, kMat, "kek_pk");
        if (!_wantRaw && kek && typeof kek.unwrap_mek === "function") {
          k2Handle = kek.unwrap_mek(b64uDecode(w.c), b64uDecode(w.i));
        } else {
          k2 = await aesGcmDecrypt(kek, b64uDecode(w.i), b64uDecode(w.c));
        }
        path = "AB";
        break;
      } catch { /* try next */ }
    }
  }
  if (!k2 && !k2Handle && haveP && haveR && envelope.w?.a) {
    try {
      const kek = await deriveKEK(pMat, rMat, "kek_pr");
      if (!_wantRaw && kek && typeof kek.unwrap_mek === "function") {
        k2Handle = kek.unwrap_mek(b64uDecode(envelope.w.a.c), b64uDecode(envelope.w.a.i));
      } else {
        k2 = await aesGcmDecrypt(kek, b64uDecode(envelope.w.a.i), b64uDecode(envelope.w.a.c));
      }
      path = "AC";
    } catch { /* try BC */ }
  }
  if (!k2 && !k2Handle && haveK && haveR && envelope.w?.c?.length) {
    const candidates = factors.credIdHash
      ? envelope.w.c.filter((w) => w.h === factors.credIdHash)
      : envelope.w.c;
    for (const w of candidates) {
      try {
        const kek = await deriveKEK(kMat, rMat, "kek_kr");
        if (!_wantRaw && kek && typeof kek.unwrap_mek === "function") {
          k2Handle = kek.unwrap_mek(b64uDecode(w.c), b64uDecode(w.i));
        } else {
          k2 = await aesGcmDecrypt(kek, b64uDecode(w.i), b64uDecode(w.c));
        }
        path = "BC";
        break;
      } catch { /* try next */ }
    }
  }
  if (!k2 && !k2Handle) throw new Error("Business decryption failed: no K2 wrap could be opened");

  // 増分1 (K2 handle 一本化): raw K2 で取り出した場合 (= forceRawMek / unwrap_mek 不可) も
  //   即 MekKey opaque handle に収束させる。 以後の downstream は handle 経路のみ。
  if (!k2Handle && k2) {
    k2Handle = await importK2AsHandle(k2);
    k2.fill(0);
    k2 = null;
  }

  // Phase 7.4.1: V1 (非 kdfV2) path を廃止。 kdfV2=true を必須化。
  //   dev 期に作られた kdfV2 不在 envelope は復号不可。 サービスイン前の意図的 break。
  if (envelope.kdfV2 !== true)
    throw new Error("Business decryption failed: envelope.kdfV2 must be true (V1 legacy path removed in Phase 7.4.1)");

  // === Stage2 Business Phase B: handle 経路 (= 生 K2 不在) ===
  //   k2Handle (= kek.unwrap_mek が産む MekKey) から MEK / sub-key / emp_priv / signing を
  //   全て WASM 内で導出。 raw K2 は JS heap に一切出ない。
  if (k2Handle) {
    const mekKey = await deriveBusinessMekKeyV2(k1Bytes, k2Handle, {
      usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
    });
    const mekHkdfKey = await deriveBusinessMekHkdfKeyV2(k1Bytes, k2Handle);
    let empPrivHandle = null;
    try {
      empPrivHandle = await unwrapEmpPrivAsHandleWithK2Handle(k2Handle, envelope.w_emp);
    } catch (e) {
      console.warn("[arpass Stage2 B-B] empPrivHandle (k2Handle) populate failed:", e?.message || e);
    }
    const padded = await aesGcmDecrypt(mekKey, b64uDecode(envelope.i), b64uDecode(envelope.c));
    const vault = JSON.parse(dec.decode(unpadPlaintext(padded)));
    // 署名 identity (= admin pk) は K2 由来。 k2Handle.derive_signing_key で同一 pk を WASM 内生成。
    //   bit-equivalence: Rust test test_mek_derive_signing_key_equivalent_to_explicit_hkdf_path。
    const signingKey = await deriveSigningKeyFromHkdf(k2Handle);
    return {
      vault,
      mek: null,
      mekKey, mekHkdfKey,
      k2Handle,                 // 増分1: K2 は handle のみ (k2AesKey/k2HkdfKey 廃止)
      empPrivKey: null, empPrivHandle,
      signingKey, path,
    };
  }

}




/**
 * Business mode の saveVault 用 (Phase 7.2-B α 案、 wsa 廃止):
 *   - K1 を per-save rotate (= forward security の要)
 *   - K2 は session 保持分を再利用
 *   - body / i / ws を更新、 w (= K2 wrap) は据置
 *   - wsa は存在しない (admin recovery は server private key escrow 経由)
 *
 * @param {object} prevEnvelope  直近の business envelope
 * @param {Uint8Array} k2        unlock 時に取得した K2 (32B、 session 保管分)
 * @param {object} vault         平文 vault (= 新しい状態)
 * @param {object} bizCtx        { companyId, kekVersion, serverPublicKeyJwk } current
 * @returns {Promise<{ envelope, mek }>}
 */
export async function saveVaultBusinessBody(prevEnvelope, k2, vault, bizCtx) {
  // Phase 7.2-B (α) 修正: K1 は envelope ライフタイム内 不変 (= per-save rotation 撤回)。
  //   K1 rotation は admin の意識的 rotate-kek 操作の時だけ。 通常 save は ws 不変。
  //   理由: per-save rotation すると wrappedBEK (= records BEK) が orphan 化、
  //         全社員がファイル取得不可になる UX 破壊。
  if (!prevEnvelope || prevEnvelope.m !== "business")
    throw new Error("prevEnvelope must be business envelope");
  if (!(k2 instanceof Uint8Array) || k2.length !== 32)
    throw new Error("k2 (32 byte) required");

  // 本体 body 再暗号化 (同じ K1 由来 real_MEK で。 ただし caller (vault-client) は
  // session.mek を持ってるが、 ここは vault-crypto layer なので K1 を再取得する
  // 必要は無い — caller が session.mek を渡してくれた前提で動くべき)。
  // → API 変更を最小化するため、 caller が session.mek を渡すように外側で対応。
  // この関数は呼び出し元から渡される ws/wsa を保持し、 body のみ更新する責務にする。
  throw new Error("saveVaultBusinessBody は per-save K1 rotation 用 の旧 API、 撤回済。 saveVault が body only 再暗号化を直接行う設計に変更。");
}

// ============================================================================
// envelope v7 — outer 鍵を Passkey の user.id が運ぶ (docs/envelope-v7-spec.md)
// ----------------------------------------------------------------------------
// outer 鍵 (32 byte) を WebAuthn user.id に格納する。新端末でも localStorage /
//   Recovery 無しに outer 鍵へ到達できる。
// 設計判断 (案A + Master-wrap, envelope-v7-spec.md §3-4 / §14): user.id をその
//   credential 自身の PRF で暗号化することは WebAuthn 順序制約 (user.id は
//   credential 作成 *前* に確定、PRF は作成 *後*) で不可能。代わりに outer 鍵を
//   Master パスワード由来鍵で AES-256-CTR ラップして user.id に格納する。
//   AES-CTR は非膨張なので user.id は 57 byte を維持。誤 Master の検出は独自
//   タグを持たず下流の外側 AES-GCM 層に委譲する (誤 Master → 誤 outer 鍵 →
//   envelope 復号がそこで失敗)。appNameTag は秘密ではない (Arweave 上の匿名
//   タグそのもの) ため平文で載せる。これにより user.id が将来想定外の場所
//   (パスキー export 規格・OS 変更・フォレンジック等) へ漏れても Master 無しでは
//   復号できない。
// user.id は credential 作成後 *不変* なのに Master は変更可能なので、Master
//   変更時は新 Master でラップした user.id を持つ「新しい Passkey」を作る
//   (changePassword + changePasswordUI)。これにより旧 Passkey の AB wrap は
//   全廃され、旧 Master はどの端末でも AB 解錠に使えなくなる。
// ============================================================================

export const VAULT_FORMAT_V7 = 7;
const USERID_V7_VERSION = 7;
const APPTAG_NAME_LEN = 8;    // appNameTag.name の raw byte 長 (b64u 11 文字)
const APPTAG_VALUE_LEN = 16;  // appNameTag.value の raw byte 長 (b64u 22 文字)
const V7_OUTER_KEY_LEN = 32;  // outer 鍵の byte 長
const USERID_V7_LEN = 1 + APPTAG_NAME_LEN + APPTAG_VALUE_LEN + V7_OUTER_KEY_LEN;  // 57

// userHandle v8 (2026-07-17, 追記③修正): user.id を Passkey ごとに一意化する。
//   v7 は user.id を (appNameTag + outerKey(rMat) + Master) から決定論生成していたため、
//   同一 Vault では全端末で user.id が同一 → iCloud/GPM の同期パスキーが (rpID,user.id)
//   衝突で「同一アカウント更新」とみなし、端末B登録が端末A のパスキーを置換・全同期端末へ
//   伝播して他端末のパスキーを消していた。v8 は末尾に per-credential のランダム nonce を
//   足して user.id を作成ごとに一意にし、衝突・置換を防ぐ。outer 鍵ペイロード(固定オフセット
//   [1..57))は v7 と同一レイアウトなので、decodeUserIdV7 は nonce を無視して両版を復号できる
//   (後方互換: 既存 v7 パスキーはそのまま解錠可)。
const USERID_V8_VERSION = 8;
const USERID_V8_NONCE_LEN = 4;   // 一意化 nonce (57+4=61 <= WebAuthn 64-byte 上限)
const USERID_V8_LEN = USERID_V7_LEN + USERID_V8_NONCE_LEN;  // 61

// user.id 内 outer 鍵ラップ用の AES-CTR カウンタ (appNameTag から決定論導出)。
//   ラップする平文 (outer 鍵) は 1 つの vault では常に同一なので、たとえ同じ
//   (鍵, カウンタ) でも同じ暗号文になるだけで keystream 再利用の問題は生じない。
//   Master 変更で作る新 Passkey は Master が変わる = ラップ鍵が変わる。
async function _userIdV7Counter(nameB, valB) {
  const h = await crypto.subtle.digest(
    "SHA-256", concatBytes(enc.encode("arpass-userid-v7-ctr"), nameB, valB)
  );
  return new Uint8Array(h).slice(0, 16);
}

// outer 鍵 (32B) を Master 由来鍵で AES-256-CTR ラップ / アンラップ (非膨張: 32B→32B)。
//   ラップ鍵 = Argon2id(Master, salt=appNameTag.value, m=64MiB, t=3, p=4)。
//   Phase 7.4.1: ここは USERID_KDF_PARAMS で固定。 user.id は credential 作成後
//   不変なので、CURRENT_KDF_PARAMS の将来変更があっても user.id outer wrap は
//   絶対に変えない。 強化したい場合は USERID_V7_VERSION を 8 に上げる。
async function _wrapOuterForUserId(outerKeyBytes, password, nameB, valB, mode) {
  const kekBytes = await derivePMat(password, valB, USERID_KDF_PARAMS);
  const counter  = await _userIdV7Counter(nameB, valB);
  // fallback 撤去: Rust AES-256-CTR を必須化 (user.id outer 鍵ラップの subtle/CryptoKey を除去)。
  //   CTR は対合なので mode 不問。 KAT (test_aes_ctr_webcrypto_vector) で WebCrypto と bit 互換。
  // 2026-06-29: 他の Rust 必須関数と同様に **ロード完了を await** する。これが無いと SW 更新直後の
  //   「WASM コールド(読み込み途中)」で _rustCrypto が null のまま throw し、解錠が落ちていた
  //   (iPhone 実機: アプリ再インストールでしか復旧しない事象の真因)。await すれば読み込みを待てる。
  const rc = await _getRustCrypto();
  if (!rc || typeof rc.aes256_ctr_apply !== "function") {
    kekBytes.fill(0);
    throw new Error("_wrapOuterForUserId: Rust crypto core (aes256_ctr_apply) 必須");
  }
  try {
    return new Uint8Array(rc.aes256_ctr_apply(kekBytes, counter, outerKeyBytes));
  } finally {
    kekBytes.fill(0);
  }
}

/**
 * envelope v7 の WebAuthn user.id (userHandle) ペイロードを構築 (案A + Master-wrap)。
 * レイアウト (57 byte): [1B version=7][8B name][16B value][32B outerKey(Master でラップ)]
 * outer 鍵は Master パスワード由来鍵で AES-256-CTR ラップして格納する。
 * @param {{name:string,value:string}} appNameTag  b64u (name 11 文字 / value 22 文字)
 * @param {Uint8Array} outerKeyBytes  32 byte (標準: deriveOuterKeyBytes(rMat) / YubiKey: 乱数)
 * @param {string} password  Master パスワード (outer 鍵ラップ鍵の導出元、空不可)
 * @returns {Promise<Uint8Array>} 57 byte (<=64)
 */
export async function encodeUserIdV7(appNameTag, outerKeyBytes, password) {
  const nameB = b64uDecode(appNameTag.name);
  const valB  = b64uDecode(appNameTag.value);
  if (nameB.length !== APPTAG_NAME_LEN)
    throw new Error(`encodeUserIdV7: name must decode to ${APPTAG_NAME_LEN} byte, got ${nameB.length}`);
  if (valB.length !== APPTAG_VALUE_LEN)
    throw new Error(`encodeUserIdV7: value must decode to ${APPTAG_VALUE_LEN} byte, got ${valB.length}`);
  if (!(outerKeyBytes instanceof Uint8Array) || outerKeyBytes.length !== V7_OUTER_KEY_LEN)
    throw new Error(`encodeUserIdV7: outerKeyBytes must be ${V7_OUTER_KEY_LEN}-byte Uint8Array`);
  if (typeof password !== "string" || password.length === 0)
    throw new Error("encodeUserIdV7: password (Master) required");
  const wrapped = await _wrapOuterForUserId(outerKeyBytes, password, nameB, valB, "encrypt");
  const out = concatBytes(new Uint8Array([USERID_V7_VERSION]), nameB, valB, wrapped);
  if (out.length > 64) throw new Error(`encodeUserIdV7: user.id ${out.length} byte exceeds WebAuthn 64-byte limit`);
  return out;
}

/**
 * encodeUserIdV7 の v8 版。末尾に per-credential のランダム nonce を付与し、user.id を
 *   作成ごとに一意にする (同期パスキーの (rpID,user.id) 衝突→置換を防止)。outer 鍵の
 *   ラップ部は v7 と同一 (固定オフセット) なので decodeUserIdV7 が両版を復号できる。
 * @param {{name:string,value:string}} appNameTag
 * @param {Uint8Array} outerKeyBytes 32 byte
 * @param {string} password  Master
 * @returns {Promise<Uint8Array>} 61 byte (<=64)
 */
export async function encodeUserIdV8(appNameTag, outerKeyBytes, password) {
  const nameB = b64uDecode(appNameTag.name);
  const valB  = b64uDecode(appNameTag.value);
  if (nameB.length !== APPTAG_NAME_LEN)
    throw new Error(`encodeUserIdV8: name must decode to ${APPTAG_NAME_LEN} byte, got ${nameB.length}`);
  if (valB.length !== APPTAG_VALUE_LEN)
    throw new Error(`encodeUserIdV8: value must decode to ${APPTAG_VALUE_LEN} byte, got ${valB.length}`);
  if (!(outerKeyBytes instanceof Uint8Array) || outerKeyBytes.length !== V7_OUTER_KEY_LEN)
    throw new Error(`encodeUserIdV8: outerKeyBytes must be ${V7_OUTER_KEY_LEN}-byte Uint8Array`);
  if (typeof password !== "string" || password.length === 0)
    throw new Error("encodeUserIdV8: password (Master) required");
  const wrapped = await _wrapOuterForUserId(outerKeyBytes, password, nameB, valB, "encrypt");
  const nonce = crypto.getRandomValues(new Uint8Array(USERID_V8_NONCE_LEN));
  const out = concatBytes(new Uint8Array([USERID_V8_VERSION]), nameB, valB, wrapped, nonce);
  if (out.length > 64) throw new Error(`encodeUserIdV8: user.id ${out.length} byte exceeds WebAuthn 64-byte limit`);
  return out;
}

/**
 * encodeUserIdV7 の逆。outer 鍵を Master でアンラップする。v7 形式でない
 *   (旧 string user.id 等) 場合は例外。
 * 誤 Master でも例外は出ず誤った outer 鍵が返る — 整合性は下流の外側 AES-GCM
 *   層が検出する (envelope 復号がそこで失敗する)。
 * @param {Uint8Array} userIdBytes
 * @param {string} password  Master パスワード (空不可)
 * @returns {Promise<{version:number, appNameTag:{name:string,value:string}, outerKey:Uint8Array}>}
 */
export async function decodeUserIdV7(userIdBytes, password) {
  if (!(userIdBytes instanceof Uint8Array))
    throw new Error("decodeUserIdV7: userIdBytes must be Uint8Array");
  // v7 (57 byte, version=7) と v8 (61 byte, version=8: 末尾 nonce 付き) の両対応。
  //   outer 鍵ラップ部は固定オフセットで同一なので nonce を無視して復号する。
  const _isV7 = userIdBytes.length === USERID_V7_LEN && userIdBytes[0] === USERID_V7_VERSION;
  const _isV8 = userIdBytes.length === USERID_V8_LEN && userIdBytes[0] === USERID_V8_VERSION;
  if (!_isV7 && !_isV8)
    throw new Error(`decodeUserIdV7: expected v7(${USERID_V7_LEN})/v8(${USERID_V8_LEN}) byte with matching version, got len=${userIdBytes.length} ver=${userIdBytes[0]}`);
  if (typeof password !== "string" || password.length === 0)
    throw new Error("decodeUserIdV7: password (Master) required");
  let off = 1;
  const nameB = userIdBytes.slice(off, off + APPTAG_NAME_LEN); off += APPTAG_NAME_LEN;
  const valB  = userIdBytes.slice(off, off + APPTAG_VALUE_LEN); off += APPTAG_VALUE_LEN;
  const wrapped = userIdBytes.slice(off, off + V7_OUTER_KEY_LEN);  // v8 の末尾 nonce は除外
  const outerKey = await _wrapOuterForUserId(wrapped, password, nameB, valB, "decrypt");
  return {
    version: _isV8 ? USERID_V8_VERSION : USERID_V7_VERSION,
    appNameTag: { name: b64uEncode(nameB), value: b64uEncode(valB) },
    outerKey,
  };
}

/**
 * userIdBytes が v7 形式か判定 (旧 string user.id と区別する。 unlock 経路用)。
 * @param {Uint8Array} userIdBytes
 * @returns {boolean}
 */
export function isUserIdV7(userIdBytes) {
  // v7-family 判定: v7(57,ver7) と v8(61,ver8) の両方を true とする (unlock 経路は
  //   decodeUserIdV7 が両版を復号するため、判定も両版を受理する)。
  if (!(userIdBytes instanceof Uint8Array)) return false;
  return (userIdBytes.length === USERID_V7_LEN && userIdBytes[0] === USERID_V7_VERSION)
      || (userIdBytes.length === USERID_V8_LEN && userIdBytes[0] === USERID_V8_VERSION);
}

/** v8 形式 (末尾 nonce 付き) か厳密判定。 */
export function isUserIdV8(userIdBytes) {
  return userIdBytes instanceof Uint8Array
    && userIdBytes.length === USERID_V8_LEN
    && userIdBytes[0] === USERID_V8_VERSION;
}

/**
 * YubiKey モード: MEK を Passkey の PRF 由来鍵で wrap (inner envelope の k[] エントリ)。
 * k[] は外層 AES-GCM の内側にあるため anti-fingerprint 上の懸念はない。
 * IV はランダム生成して ct と連結 (MEK rotation での IV 再利用も避けられる)。
 * @param {Uint8Array} prfOutput
 * @param {Uint8Array} mek  32 byte
 * @returns {Promise<Uint8Array>} 60 byte (12 iv + 32 ct + 16 tag)
 */
export async function wrapMekForPrf(prfOutput, mek) {
  if (!(prfOutput instanceof Uint8Array) || prfOutput.length < 16)
    throw new Error("wrapMekForPrf: prfOutput must be >=16-byte Uint8Array");
  // Phase A (dormant, Stage 2 raw-MEK elimination): mek が MekKey handle の場合は
  //   PRF→mek-wrap 鍵派生 + wrap を WASM 内で完結し、 生 mek を JS heap に出さない。
  //   現状 caller は raw を渡すので未発火 (= 0 behavior 変更)。bit-equiv は web crate
  //   の native test wrap_mek_for_prf_handle_equals_raw が担保。
  if (!(mek instanceof Uint8Array)) {
    const rc = await _getRustCrypto();
    if (!rc || typeof rc.MekKey !== "function")
      throw new Error("wrapMekForPrf: MekKey handle path requires rust-crypto");
    let prfH = null, wrapKey = null;
    try {
      prfH = new rc.MekKey(prfOutput.length === 32 ? prfOutput : prfOutput.slice(0, 32));
      wrapKey = prfH.hkdf_derive_mek(enc.encode(HKDF_SALTS.mek_wrap_v7), enc.encode(HKDF_INFOS.mek_wrap_v7));
      const iv = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
      const ct = wrapKey.wrap_mek(mek, iv);
      return concatBytes(iv, ct);
    } finally {
      if (prfH && typeof prfH.free === "function") { try { prfH.free(); } catch (_) {} }
      if (wrapKey && typeof wrapKey.free === "function") { try { wrapKey.free(); } catch (_) {} }
    }
  }
  if (mek.length !== 32)
    throw new Error("wrapMekForPrf: mek must be 32-byte Uint8Array");
  // handle 化: PRF 由来 wrap 鍵を MekKey handle に (CryptoKey 廃止)。 mek は raw 平文として渡す。
  const keyBytes = hkdfBytes(prfOutput, HKDF_SALTS.mek_wrap_v7, HKDF_INFOS.mek_wrap_v7, 32);
  const keyHandle = await importMekRawAsHandle(keyBytes);
  keyBytes.fill(0);
  if (!keyHandle) throw new Error("wrapMekForPrf: Rust crypto core (MekKey) 必須");
  const iv = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const ct = await aesGcmEncrypt(keyHandle, iv, mek);
  if (typeof keyHandle.free === "function") { try { keyHandle.free(); } catch (_) {} }
  return concatBytes(iv, ct);
}

/**
 * wrapMekForPrf の逆。
 * @param {Uint8Array} prfOutput
 * @param {Uint8Array} wrapped  60 byte
 * @returns {Promise<Uint8Array>} 32 byte MEK
 */
export async function unwrapMekForPrf(prfOutput, wrapped) {
  if (!(prfOutput instanceof Uint8Array) || prfOutput.length < 16)
    throw new Error("unwrapMekForPrf: prfOutput must be >=16-byte Uint8Array");
  if (!(wrapped instanceof Uint8Array) || wrapped.length !== AES_IV_LEN + 32 + AES_TAG_LEN)
    throw new Error(`unwrapMekForPrf: wrapped must be ${AES_IV_LEN + 32 + AES_TAG_LEN}-byte`);
  // handle 化: PRF 由来 wrap 鍵を MekKey handle に (CryptoKey 廃止)。
  const keyBytes = hkdfBytes(prfOutput, HKDF_SALTS.mek_wrap_v7, HKDF_INFOS.mek_wrap_v7, 32);
  const keyHandle = await importMekRawAsHandle(keyBytes);
  keyBytes.fill(0);
  if (!keyHandle) throw new Error("unwrapMekForPrf: Rust crypto core (MekKey) 必須");
  const iv = wrapped.slice(0, AES_IV_LEN);
  const ct = wrapped.slice(AES_IV_LEN);
  try {
    return await aesGcmDecrypt(keyHandle, iv, ct);
  } finally {
    if (typeof keyHandle.free === "function") { try { keyHandle.free(); } catch (_) {} }
  }
}


// ============================================================================
// envelope v7 増分2 — YubiKey 専用モード (mode:"hwkey")
// ----------------------------------------------------------------------------
// Master も Recovery も持たず、登録した複数本 (>=2) の YubiKey のみで 1-of-N 解錠
// する vault。MEK は各 YubiKey の PRF で個別に wrap して inner envelope の k[] に
// 並べる。outer 鍵は乱数で、各 YubiKey ごとの「keyslot blob」(PRF で暗号化し
// padPlaintext で難読化サイズに膨らませた独立 Arweave オブジェクト) が運ぶ。
// keyslot は {vault appNameTag, outer 鍵} を持ち、user.id は keyslot の所在を
// 指すランダムタグのみを焼く (秘密を user.id に置かない)。詳細は
// docs/envelope-v7-spec.md (増分2 / hwkey)。
// ============================================================================

export const HWKEY_MIN_KEYS = 2;  // YubiKey モードは 2 本以上必須 (安全装置)

/** hwkey モード用のランダム appNameTag (rMat が無いので乱数、構造は deriveAppNameTag と同形)。 */
export function randomAppNameTag() {
  return {
    name:  b64uEncode(crypto.getRandomValues(new Uint8Array(8))),
    value: b64uEncode(crypto.getRandomValues(new Uint8Array(16))),
  };
}

/**
 * YubiKey 専用モードの vault を暗号化する (inner envelope を返す。外層は caller)。
 * @param {object} vault
 * @param {Uint8Array[]} prfOutputs    登録する各 YubiKey の PRF 出力 (>=2)
 * @param {string[]} credIdHashes      対応する credIdHash (prfOutputs と同順・同数)
 * @returns {Promise<{envelope, mek, mekKey, mekHkdfKey, outerKeyBytes, appNameTag, signingKey}>}
 */
export async function encryptVaultHwkey(vault, prfOutputs, credIdHashes) {
  if (!Array.isArray(prfOutputs) || !Array.isArray(credIdHashes)
      || prfOutputs.length !== credIdHashes.length)
    throw new Error("encryptVaultHwkey: prfOutputs / credIdHashes は同数の配列が必要");
  if (prfOutputs.length < HWKEY_MIN_KEYS)
    throw new Error(`encryptVaultHwkey: YubiKey モードは ${HWKEY_MIN_KEYS} 本以上必要`);

  // handle 化: MEK を MekKey opaque handle として生成 (CryptoKey 不使用、 生 mek は即 fill)。
  const rc = await _getRustCrypto();
  if (!rc || typeof rc.MekKey !== "function")
    throw new Error("encryptVaultHwkey: Rust crypto core (MekKey) 必須");
  const mekRaw = crypto.getRandomValues(new Uint8Array(32));
  const mekHandle = new rc.MekKey(mekRaw);
  const mekHkdfHandle = new rc.MekKey(mekRaw);  // HKDF base 用に別 handle (同値、 二重 free 回避)
  mekRaw.fill(0);
  const ivBody = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const padded = padPlaintext(enc.encode(JSON.stringify(vault)));
  const bodyCt = await aesGcmEncrypt(mekHandle, ivBody, padded);  // handle 経由

  // k[]: 各 YubiKey の PRF で MEK(handle) を個別 wrap (wrapMekForPrf の handle 経路)
  const k = [];
  for (let i = 0; i < prfOutputs.length; i++) {
    k.push({ h: credIdHashes[i], w: b64uEncode(await wrapMekForPrf(prfOutputs[i], mekHandle)) });
  }

  const envelope = {
    v: VAULT_FORMAT_V5,
    m: "hwkey",
    i: b64uEncode(ivBody),
    c: b64uEncode(bodyCt),
    k,
  };

  const outerKeyBytes = crypto.getRandomValues(new Uint8Array(32));  // hwkey: outer 鍵は乱数
  const appNameTag = randomAppNameTag();
  const signingKey = await deriveSigningKeyFromHkdf(mekHandle);  // MEK handle 由来 (raw deriveSigningKey と bit-equiv)
  return { envelope, mek: null, mekKey: mekHandle, mekHkdfKey: mekHkdfHandle, outerKeyBytes, appNameTag, signingKey };
}

/**
 * hwkey envelope を 1 本の YubiKey で復号する (1-of-N)。
 * @param {object} envelope         m:"hwkey" envelope (外層復号後)
 * @param {Uint8Array} prfOutput    手元の YubiKey の PRF 出力
 * @param {string|null} [credIdHash=null]  分かっていれば k[] の絞り込みに使う
 * @returns {Promise<{vault, mek, mekKey, mekHkdfKey, signingKey, path:"K"}>}
 */
export async function decryptVaultHwkey(envelope, prfOutput, credIdHash = null) {
  if (!envelope || envelope.v !== VAULT_FORMAT_V5 || envelope.m !== "hwkey")
    throw new Error("decryptVaultHwkey: hwkey envelope が必要");
  if (!Array.isArray(envelope.k) || envelope.k.length === 0)
    throw new Error("decryptVaultHwkey: envelope.k が空");
  if (!(prfOutput instanceof Uint8Array) || prfOutput.length < 16)
    throw new Error("decryptVaultHwkey: prfOutput が必要");

  const candidates = credIdHash ? envelope.k.filter((e) => e.h === credIdHash) : envelope.k;

  // Stage 2 Phase B: rust-crypto があれば unwrap を WASM 内で行い、 生 MEK を JS heap に
  //   一度も出さない (PRF→mek-wrap 鍵 handle→unwrap_mek で MEK handle を直接得る)。
  //   bit-equiv は web crate test unwrap_mek_for_prf_handle_equals_raw が担保。
  const _rc = await _getRustCrypto();
  if (_rc && typeof _rc.MekKey === "function") {
    let prfH = null, wrapKey = null, mekHandle = null;
    try {
      prfH = new _rc.MekKey(prfOutput.length === 32 ? prfOutput : prfOutput.slice(0, 32));
      wrapKey = prfH.hkdf_derive_mek(enc.encode(HKDF_SALTS.mek_wrap_v7), enc.encode(HKDF_INFOS.mek_wrap_v7));
      for (const e of candidates) {
        const wrapped = b64uDecode(e.w);
        if (wrapped.length !== AES_IV_LEN + 32 + AES_TAG_LEN) continue;
        const iv = wrapped.slice(0, AES_IV_LEN);
        const ct = wrapped.slice(AES_IV_LEN);
        try { mekHandle = wrapKey.unwrap_mek(ct, iv); break; } catch { /* 次の k[] */ }
      }
    } finally {
      if (prfH && typeof prfH.free === "function") { try { prfH.free(); } catch (_) {} }
      if (wrapKey && typeof wrapKey.free === "function") { try { wrapKey.free(); } catch (_) {} }
    }
    if (mekHandle) {
      const padded = await aesGcmDecrypt(mekHandle, b64uDecode(envelope.i), b64uDecode(envelope.c));
      const vault = JSON.parse(dec.decode(unpadPlaintext(padded)));
      const signingKey = await deriveSigningKeyFromHkdf(mekHandle);
      // 生 mek を JS heap に出さない: mek=null、 mekKey=handle、 consumer は mekKey 経由。
      return { vault, mek: null, mekKey: mekHandle, mekHkdfKey: null, signingKey, path: "K" };
    }
    // 全 candidate で handle-unwrap 失敗 → 下の raw fallback で再試行 (診断/未ロード救済)。
  }

  // Fallback (rust-crypto 未ロード or 上記失敗): 従来の raw 経路。
  let mek = null;
  for (const e of candidates) {
    try {
      mek = await unwrapMekForPrf(prfOutput, b64uDecode(e.w));
      break;
    } catch { /* 次の k[] エントリを試す */ }
  }
  if (!mek) throw new Error("decryptVaultHwkey: この YubiKey で開ける k[] エントリがありません");

  const _hwBodyHandle = await importMekRawAsHandle(mek);  // Rust 必須 (CryptoKey importKey 廃止)
  const padded = await aesGcmDecrypt(_hwBodyHandle, b64uDecode(envelope.i), b64uDecode(envelope.c));
  const vault = JSON.parse(dec.decode(unpadPlaintext(padded)));
  const signingKey = deriveSigningKey(mek);
  const mekHkdfKey = await importMekRawAsHandle(mek);
  return { vault, mek, mekKey: _hwBodyHandle, mekHkdfKey, signingKey, path: "K" };
}

/** keyslot blob の暗号鍵 (YubiKey PRF 由来、mek_wrap とは別ドメイン)。 */
async function _keyslotKey(prfOutput, _mode) {
  // handle 化: PRF 由来 keyslot 鍵を MekKey opaque handle に (CryptoKey 不使用、 aesGcm 透過)。
  const kb = hkdfBytes(prfOutput, HKDF_SALTS.keyslot_v7, HKDF_INFOS.keyslot_v7, 32);
  const h = await importMekRawAsHandle(kb);
  kb.fill(0);
  if (!h) throw new Error("_keyslotKey: Rust crypto core (MekKey) 必須");
  return h;
}

/**
 * keyslot blob を作る (YubiKey ごとに 1 つ)。中身 {vault appNameTag, outer 鍵} を
 *   その YubiKey の PRF で暗号化し、padPlaintext で vault と同じサイズ帯まで
 *   膨らませる (Arweave 上で乱数列に見える)。中身は vault 生涯不変なので write-once。
 * @param {Uint8Array} prfOutput
 * @param {{name:string,value:string}} appNameTag
 * @param {Uint8Array} outerKeyBytes  32 byte
 * @returns {Promise<Uint8Array>}  [IV | AES-GCM(...)] — そのまま Arweave に書く
 */
export async function encodeKeyslot(prfOutput, appNameTag, outerKeyBytes) {
  if (!(prfOutput instanceof Uint8Array) || prfOutput.length < 16)
    throw new Error("encodeKeyslot: prfOutput が必要");
  if (!(outerKeyBytes instanceof Uint8Array) || outerKeyBytes.length !== 32)
    throw new Error("encodeKeyslot: outerKeyBytes は 32 byte");
  if (!appNameTag || typeof appNameTag.name !== "string" || typeof appNameTag.value !== "string")
    throw new Error("encodeKeyslot: appNameTag {name,value} が必要");
  const payload = JSON.stringify({ t: appNameTag, o: b64uEncode(outerKeyBytes) });
  const padded = padPlaintext(enc.encode(payload));
  const key = await _keyslotKey(prfOutput, "encrypt");
  const iv = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const ct = await aesGcmEncrypt(key, iv, padded);
  return concatBytes(iv, ct);
}

/**
 * encodeKeyslot の逆。その YubiKey の PRF でしか開けない。
 * @param {Uint8Array} prfOutput
 * @param {Uint8Array} blob
 * @returns {Promise<{appNameTag:{name:string,value:string}, outerKey:Uint8Array}>}
 */
export async function decodeKeyslot(prfOutput, blob) {
  if (!(prfOutput instanceof Uint8Array) || prfOutput.length < 16)
    throw new Error("decodeKeyslot: prfOutput が必要");
  if (!(blob instanceof Uint8Array) || blob.length <= AES_IV_LEN + AES_TAG_LEN)
    throw new Error("decodeKeyslot: blob が短すぎる");
  const key = await _keyslotKey(prfOutput, "decrypt");
  const iv = blob.slice(0, AES_IV_LEN);
  const ct = blob.slice(AES_IV_LEN);
  const padded = await aesGcmDecrypt(key, iv, ct);
  const payload = JSON.parse(dec.decode(unpadPlaintext(padded)));
  return { appNameTag: payload.t, outerKey: b64uDecode(payload.o) };
}

/**
 * hwkey envelope に YubiKey を 1 本追加する (k[] エントリ追加)。MEK は解錠済みの
 *   caller が渡す。新 YubiKey 用の keyslot blob は別途 encodeKeyslot で作る。
 */
export async function addHwkey(envelope, mek, prfOutputNew, credIdHashNew) {
  if (!envelope || envelope.m !== "hwkey")
    throw new Error("addHwkey: hwkey envelope が必要");
  // mek は raw 32B でも MekKey handle でも可 (wrapMekForPrf が両対応)。
  if (mek instanceof Uint8Array && mek.length !== 32)
    throw new Error("addHwkey: mek は 32 byte");
  const w = b64uEncode(await wrapMekForPrf(prfOutputNew, mek));
  const newK = (envelope.k || []).filter((e) => e.h !== credIdHashNew);
  newK.push({ h: credIdHashNew, w });
  return { ...envelope, k: newK };
}

/**
 * hwkey envelope から YubiKey を 1 本外す (k[] エントリ削除)。2 本未満になる削除は
 *   拒否する (安全装置 — 全鍵喪失で復旧不能になるため)。
 */
export function removeHwkey(envelope, credIdHash) {
  if (!envelope || envelope.m !== "hwkey")
    throw new Error("removeHwkey: hwkey envelope が必要");
  const newK = (envelope.k || []).filter((e) => e.h !== credIdHash);
  if (newK.length < HWKEY_MIN_KEYS)
    throw new Error(`removeHwkey: YubiKey モードは ${HWKEY_MIN_KEYS} 本以上を保つ必要があります`);
  return { ...envelope, k: newK };
}


// ----------------------------------------------------------------------------
// hwkey モードの user.id コーデック
//   レイアウト (25 byte): [1B version=8][8B keyslotTag.name][16B keyslotTag.value]
//   標準 v7 (57 byte、version=7、outer 鍵入り) と長さ・version で区別される。
//   hwkey の user.id は keyslot blob の所在タグだけを運び、秘密を一切含まない
//   (keyslot 自体が YubiKey の PRF で暗号化されているため)。
// ----------------------------------------------------------------------------
export const USERID_HWKEY_VERSION = 8;
const USERID_HWKEY_LEN = 1 + APPTAG_NAME_LEN + APPTAG_VALUE_LEN;  // 25

/**
 * hwkey モードの user.id (userHandle) を構築。keyslot blob の所在タグを焼く。
 * @param {{name:string,value:string}} keyslotTag  b64u (name 11 / value 22 文字)
 * @returns {Uint8Array} 25 byte
 */
export function encodeUserIdHwkey(keyslotTag) {
  if (!keyslotTag || typeof keyslotTag.name !== "string" || typeof keyslotTag.value !== "string")
    throw new Error("encodeUserIdHwkey: keyslotTag {name,value} が必要");
  const nameB = b64uDecode(keyslotTag.name);
  const valB  = b64uDecode(keyslotTag.value);
  if (nameB.length !== APPTAG_NAME_LEN)
    throw new Error(`encodeUserIdHwkey: name must decode to ${APPTAG_NAME_LEN} byte, got ${nameB.length}`);
  if (valB.length !== APPTAG_VALUE_LEN)
    throw new Error(`encodeUserIdHwkey: value must decode to ${APPTAG_VALUE_LEN} byte, got ${valB.length}`);
  return concatBytes(new Uint8Array([USERID_HWKEY_VERSION]), nameB, valB);
}

/**
 * encodeUserIdHwkey の逆。
 * @param {Uint8Array} userIdBytes
 * @returns {{version:number, keyslotTag:{name:string,value:string}}}
 */
export function decodeUserIdHwkey(userIdBytes) {
  if (!(userIdBytes instanceof Uint8Array))
    throw new Error("decodeUserIdHwkey: userIdBytes must be Uint8Array");
  if (userIdBytes.length !== USERID_HWKEY_LEN)
    throw new Error(`decodeUserIdHwkey: expected ${USERID_HWKEY_LEN} byte, got ${userIdBytes.length}`);
  if (userIdBytes[0] !== USERID_HWKEY_VERSION)
    throw new Error(`decodeUserIdHwkey: version ${userIdBytes[0]} (expected ${USERID_HWKEY_VERSION})`);
  const nameB = userIdBytes.slice(1, 1 + APPTAG_NAME_LEN);
  const valB  = userIdBytes.slice(1 + APPTAG_NAME_LEN, 1 + APPTAG_NAME_LEN + APPTAG_VALUE_LEN);
  return {
    version: USERID_HWKEY_VERSION,
    keyslotTag: { name: b64uEncode(nameB), value: b64uEncode(valB) },
  };
}

/** userIdBytes が hwkey 形式 (version=8、25 byte) か判定。 */
export function isUserIdHwkey(userIdBytes) {
  return userIdBytes instanceof Uint8Array
    && userIdBytes.length === USERID_HWKEY_LEN
    && userIdBytes[0] === USERID_HWKEY_VERSION;
}
