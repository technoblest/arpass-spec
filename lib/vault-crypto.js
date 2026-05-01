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
//   - 外側 AES-GCM 層は本モジュールが管理 (HKDF(vault-id) で鍵派生)
//   - 署名鍵 (ECDSA P-256) は MEK から HKDF で決定論派生 — 本モジュールが
//     @noble/curves を vendor 経由で呼び、結果を Web Crypto API の
//     CryptoKey にインポートして以降の署名は subtle.sign で行う
//   - 全ての salt / info 文字列は本ファイル冒頭に集約
// ============================================================================

import { p256, sha256, hkdf, mod } from "./vendor/noble-curves-and-hashes.mjs";

// ---------------------------------------------------------------------------
// 定数 — v5 envelope のすべてのアルゴリズム規定はここに集約
// ---------------------------------------------------------------------------

export const VAULT_FORMAT_V5 = 5;

// PBKDF2 — Master Password から pMat を導出
const PBKDF2_HASH = "SHA-256";
const PBKDF2_ITER = 600_000;
const SALT_LEN_BYTES = 16;

// AES-GCM
const AES_KEY_BITS = 256;
const AES_IV_LEN = 12;
const AES_TAG_LEN = 16;

// HKDF salt / info — 用途ごとに固定文字列。後方互換性が無くなるので変更厳禁。
const HKDF_SALTS = {
  recovery_material:  "arpass-recovery-v1",
  passkey_material:   "arpass-passkey-prf-v1",
  vault_id:           "arpass-vault-id-v5",
  app_name_tag:       "arpass-app-tag-v1",
  outer_key:          "arpass-outer-v5",
  signing_key:        "arpass-signing-key-v5",
  kek_pr:             "arpass-kek-pr-v1",
  kek_pk:             "arpass-kek-pk-v1",
  kek_kr:             "arpass-kek-kr-v1",
};

const HKDF_INFOS = {
  recovery_material:  "recovery-material",
  passkey_material:   "passkey-material",
  vault_id:           "vault-id",
  app_name_tag:       "App-Name",
  outer_key:          "envelope-wrap",
  signing_key:        "p256-keypair",
  kek_pr:             "kek-pr",
  kek_pk:             "kek-pk",
  kek_kr:             "kek-kr",
};

// Padding バケット (本体 c のサイズを統一するため、エントリ数の推測を防ぐ)
const PAD_BUCKETS = [4 * 1024, 16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024, 4 * 1024 * 1024];
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
  return hkdf(sha256, ikm, enc.encode(salt), enc.encode(info), length);
}

// ---------------------------------------------------------------------------
// 各認証要素の素材 (P/K/R) → 32 byte
// ---------------------------------------------------------------------------

/**
 * Master Password を PBKDF2 で 32-byte の pMat に伸ばす。
 * salt は envelope.s をそのまま使う (vault ごとにランダム)。
 */
export async function derivePMat(passwordString, saltBytes) {
  const km = await crypto.subtle.importKey(
    "raw",
    enc.encode(passwordString),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations: PBKDF2_ITER, hash: PBKDF2_HASH },
    km,
    32 * 8
  );
  return new Uint8Array(bits);
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
export function deriveRMat(recoveryString) {
  // 文字列は normalize して大文字化、空白除去 (parseRecoverySecret の前段相当)
  const normalized = (recoveryString || "").replace(/\s+/g, "").toUpperCase();
  return hkdfBytes(enc.encode(normalized), HKDF_SALTS.recovery_material, HKDF_INFOS.recovery_material, 32);
}

// ---------------------------------------------------------------------------
// vault-id, App-Name タグ, outer_key の派生
// ---------------------------------------------------------------------------

/**
 * vault-id (16 byte) — Recovery 由来。サーバ・Arweave のいずれにも露出しない。
 */
export function deriveVaultId(recoveryMaterial) {
  return hkdfBytes(recoveryMaterial, HKDF_SALTS.vault_id, HKDF_INFOS.vault_id, 16);
}

/**
 * Arweave タグ "App-Name" の値 — Recovery 由来の HMAC、12 byte → 16 文字 base64url。
 * 同じ Recovery の端末同士でのみ自分の vault tx を発見可能にする。
 */
export function deriveAppNameTag(recoveryMaterial) {
  const bytes = hkdfBytes(recoveryMaterial, HKDF_SALTS.app_name_tag, HKDF_INFOS.app_name_tag, 12);
  return b64uEncode(bytes);
}

/**
 * 外側 AES-GCM 層の鍵 (32 byte) — vault-id 由来。
 */
async function deriveOuterCryptoKey(vaultIdBytes) {
  const raw = hkdfBytes(vaultIdBytes, HKDF_SALTS.outer_key, HKDF_INFOS.outer_key, 32);
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

// ---------------------------------------------------------------------------
// 外側 AES-GCM 層 — Arweave に書き込む blob の生成・復号
// ---------------------------------------------------------------------------

/**
 * envelope オブジェクトを JSON 化し、vault-id 由来鍵で AES-GCM 暗号化して
 * 12+N+16 byte の blob を返す。これが Arweave に実際に書き込まれるバイト列。
 */
export async function wrapEnvelopeOuter(envelopeObj, vaultIdBytes) {
  const key = await deriveOuterCryptoKey(vaultIdBytes);
  const iv = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const json = JSON.stringify(envelopeObj);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(json))
  );
  return concatBytes(iv, ct);
}

/**
 * Arweave から取った blob を解いて envelope オブジェクトに戻す。
 * blob: Uint8Array (12 byte IV + ciphertext + 16 byte auth tag)
 */
export async function unwrapEnvelopeOuter(blob, vaultIdBytes) {
  if (blob.length < AES_IV_LEN + AES_TAG_LEN) {
    throw new Error(`Outer blob too short: ${blob.length} bytes`);
  }
  const key = await deriveOuterCryptoKey(vaultIdBytes);
  const iv = blob.slice(0, AES_IV_LEN);
  const ct = blob.slice(AES_IV_LEN);
  let pt;
  try {
    pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  } catch (e) {
    throw new Error("Outer envelope decryption failed (wrong vault-id or corrupt blob)");
  }
  return JSON.parse(dec.decode(pt));
}

// ---------------------------------------------------------------------------
// KEK (各 wrap 用の鍵) と本体暗号化
// ---------------------------------------------------------------------------

async function deriveKEK(material1, material2, saltKey) {
  const raw = hkdfBytes(
    concatBytes(material1, material2),
    HKDF_SALTS[saltKey],
    HKDF_INFOS[saltKey],
    32
  );
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function aesGcmEncrypt(key, iv, plaintext) {
  return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext));
}
async function aesGcmDecrypt(key, iv, ciphertext) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext));
}

// ---------------------------------------------------------------------------
// padding (サイズ秘匿) — v4 と互換のバケット方式 (本体 c のみ対象)
// ---------------------------------------------------------------------------

function padPlaintext(bytes) {
  const minRequired = bytes.length + 1;  // 0x80 マーカー分
  let bucket = PAD_BUCKETS[PAD_BUCKETS.length - 1];
  for (const b of PAD_BUCKETS) {
    if (b - AES_TAG_LEN >= minRequired) { bucket = b; break; }
  }
  const totalBeforeTag = bucket - AES_TAG_LEN;
  const out = new Uint8Array(totalBeforeTag);
  out.set(bytes, 0);
  out[bytes.length] = PAD_TERMINATOR;
  // 残りはゼロ埋め
  return out;
}

function unpadPlaintext(padded) {
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
  // Bytes → bigint, then mod n
  let dInt = 0n;
  for (const b of seed) dInt = (dInt << 8n) | BigInt(b);
  const n = p256.Point.Fn.ORDER;
  let d = mod(dInt, n);
  if (d === 0n) d = 1n; // 極めて稀
  // 公開鍵 = d * G
  const Qpoint = p256.Point.BASE.multiply(d);
  const Qaffine = Qpoint.toAffine();
  const xBytes = bigIntTo32Bytes(Qaffine.x);
  const yBytes = bigIntTo32Bytes(Qaffine.y);
  const dBytes = bigIntTo32Bytes(d);

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

  return { d, Q: Qaffine, privateKeyJwk, publicKeyJwk, publicKeyRaw };
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
 * 署名鍵を Web Crypto API の CryptoKey として importKey し、subtle.sign で使えるようにする。
 * @returns {Promise<{ privateKey: CryptoKey, publicKey: CryptoKey }>}
 */
export async function importSigningKeyPair(privateKeyJwk, publicKeyJwk) {
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    privateKeyJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    publicKeyJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );
  return { privateKey, publicKey };
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
 *
 * @returns {Promise<{
 *   envelope: object,         // v5 内側 JSON
 *   mek: Uint8Array(32),      // 派生用に保持 (lockSession で破棄)
 *   vaultId: Uint8Array(16),  // outer_key と App-Name の派生に使用
 *   appNameTag: string,       // Arweave タグ用
 *   signingKey: object,       // deriveSigningKey の戻り値
 * }>}
 */
export async function encryptVault(vault, password, prfOutput, recoveryMaterial, credIdHash) {
  if (!password) throw new Error("password required");
  if (!(prfOutput instanceof Uint8Array) || prfOutput.length < 16)
    throw new Error("prfOutput required (Passkey + PRF mandatory in v5)");
  if (!(recoveryMaterial instanceof Uint8Array) || recoveryMaterial.length < 32)
    throw new Error("recoveryMaterial (32 byte) required");
  if (!credIdHash || typeof credIdHash !== "string")
    throw new Error("credIdHash required");

  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN_BYTES));
  const mek  = crypto.getRandomValues(new Uint8Array(32));

  const pMat = await derivePMat(password, salt);
  const kMat = deriveKMat(prfOutput);
  const rMat = recoveryMaterial.slice(0, 32);

  // KEK 3 種
  const kekPR = await deriveKEK(pMat, rMat, "kek_pr");
  const kekPK = await deriveKEK(pMat, kMat, "kek_pk");
  const kekKR = await deriveKEK(kMat, rMat, "kek_kr");

  // wrap 3 種
  const ivA = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const ivB = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const ivC = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const wrapA = await aesGcmEncrypt(kekPR, ivA, mek);
  const wrapB = await aesGcmEncrypt(kekPK, ivB, mek);
  const wrapC = await aesGcmEncrypt(kekKR, ivC, mek);

  // 本体暗号化 (vault JSON)
  const ivBody = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const mekKey = await crypto.subtle.importKey("raw", mek, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  const padded = padPlaintext(enc.encode(JSON.stringify(vault)));
  const bodyCt = await aesGcmEncrypt(mekKey, ivBody, padded);

  const envelope = {
    v: VAULT_FORMAT_V5,
    s: b64uEncode(salt),
    i: b64uEncode(ivBody),
    c: b64uEncode(bodyCt),
    w: {
      a: { i: b64uEncode(ivA), c: b64uEncode(wrapA) },
      b: [{ h: credIdHash, i: b64uEncode(ivB), c: b64uEncode(wrapB) }],
      c: [{ h: credIdHash, i: b64uEncode(ivC), c: b64uEncode(wrapC) }],
    },
  };

  const vaultId = deriveVaultId(rMat);
  const appNameTag = deriveAppNameTag(rMat);
  const signingKey = deriveSigningKey(mek);

  return { envelope, mek, vaultId, appNameTag, signingKey };
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
  const pMat = haveP ? await derivePMat(factors.password, salt) : null;
  const kMat = haveK ? deriveKMat(factors.prfOutput) : null;
  const rMat = haveR ? factors.recoveryMaterial.slice(0, 32) : null;

  let mek = null;
  let path = null;

  // Path AB: Master + Passkey (日常 unlock)
  if (haveP && haveK && envelope.w?.b?.length) {
    const credIdHash = factors.credIdHash;
    const candidates = credIdHash
      ? envelope.w.b.filter((w) => w.h === credIdHash)
      : envelope.w.b;
    for (const w of candidates) {
      try {
        const kek = await deriveKEK(pMat, kMat, "kek_pk");
        mek = await aesGcmDecrypt(kek, b64uDecode(w.i), b64uDecode(w.c));
        path = "AB";
        break;
      } catch { /* try next */ }
    }
  }
  // Path AC: Master + Recovery
  if (!mek && haveP && haveR && envelope.w?.a) {
    try {
      const kek = await deriveKEK(pMat, rMat, "kek_pr");
      mek = await aesGcmDecrypt(kek, b64uDecode(envelope.w.a.i), b64uDecode(envelope.w.a.c));
      path = "AC";
    } catch { /* try BC */ }
  }
  // Path BC: Passkey + Recovery (Master 忘却時)
  if (!mek && haveK && haveR && envelope.w?.c?.length) {
    const credIdHash = factors.credIdHash;
    const candidates = credIdHash
      ? envelope.w.c.filter((w) => w.h === credIdHash)
      : envelope.w.c;
    for (const w of candidates) {
      try {
        const kek = await deriveKEK(kMat, rMat, "kek_kr");
        mek = await aesGcmDecrypt(kek, b64uDecode(w.i), b64uDecode(w.c));
        path = "BC";
        break;
      } catch { /* try next */ }
    }
  }
  if (!mek) throw new Error("Decryption failed: no wrap could be opened with the provided factors");

  // 本体復号
  const mekKey = await crypto.subtle.importKey("raw", mek, { name: "AES-GCM" }, false, ["decrypt"]);
  const padded = await aesGcmDecrypt(mekKey, b64uDecode(envelope.i), b64uDecode(envelope.c));
  const json = unpadPlaintext(padded);
  const vault = JSON.parse(dec.decode(json));

  const signingKey = deriveSigningKey(mek);
  return { vault, mek, signingKey, path };
}

// ---------------------------------------------------------------------------
// Mutation: 端末追加・パスワード変更・Recovery 再発行
// ---------------------------------------------------------------------------

/**
 * 既存 envelope に新端末の Passkey を追加 (AB / BC wrap を 2 個追加)。
 * 既存の MEK / publicKey は不変。
 */
export async function addCredential(envelope, mek, password, recoveryMaterial, newPrfOutput, newCredIdHash) {
  const salt = b64uDecode(envelope.s);
  const pMat = await derivePMat(password, salt);
  const kMat = deriveKMat(newPrfOutput);
  const rMat = recoveryMaterial.slice(0, 32);

  const kekPK = await deriveKEK(pMat, kMat, "kek_pk");
  const kekKR = await deriveKEK(kMat, rMat, "kek_kr");
  const ivB = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const ivC = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const wrapB = await aesGcmEncrypt(kekPK, ivB, mek);
  const wrapC = await aesGcmEncrypt(kekKR, ivC, mek);

  // 既存の同じ credIdHash があれば置き換え (1 端末 1 wrap、上書き安全)
  const newW = JSON.parse(JSON.stringify(envelope.w));
  newW.b = newW.b.filter((w) => w.h !== newCredIdHash);
  newW.c = newW.c.filter((w) => w.h !== newCredIdHash);
  newW.b.push({ h: newCredIdHash, i: b64uEncode(ivB), c: b64uEncode(wrapB) });
  newW.c.push({ h: newCredIdHash, i: b64uEncode(ivC), c: b64uEncode(wrapC) });
  return { ...envelope, w: newW };
}

/**
 * Master Password を変更する。
 * AC wrap と「現端末」の AB wrap を再生成。他端末の AB wrap は触らない (lazy 補完)。
 */
export async function changePassword(envelope, mek, currentCredIdHash, newPassword, currentPrfOutput, recoveryMaterial) {
  const salt = b64uDecode(envelope.s);
  const newPMat = await derivePMat(newPassword, salt);
  const kMat = deriveKMat(currentPrfOutput);
  const rMat = recoveryMaterial.slice(0, 32);

  // AC wrap 再生成
  const kekPR = await deriveKEK(newPMat, rMat, "kek_pr");
  const ivA = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const wrapA = await aesGcmEncrypt(kekPR, ivA, mek);

  // この端末の AB wrap 再生成
  const kekPK = await deriveKEK(newPMat, kMat, "kek_pk");
  const ivB = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const wrapB = await aesGcmEncrypt(kekPK, ivB, mek);

  const newW = JSON.parse(JSON.stringify(envelope.w));
  newW.a = { i: b64uEncode(ivA), c: b64uEncode(wrapA) };
  newW.b = newW.b.filter((w) => w.h !== currentCredIdHash);
  newW.b.push({ h: currentCredIdHash, i: b64uEncode(ivB), c: b64uEncode(wrapB) });
  // BC wrap は Master 無関係なので触らない (Recovery 不変)

  return { ...envelope, w: newW };
}

/**
 * Recovery を再発行する (ケース A: MEK 据え置き)。
 * AC + 「現端末」の BC wrap を再生成。他端末の BC は lazy 補完。
 */
export async function changeRecovery_caseA(envelope, mek, password, currentCredIdHash, currentPrfOutput, newRecoveryMaterial) {
  const salt = b64uDecode(envelope.s);
  const pMat = await derivePMat(password, salt);
  const kMat = deriveKMat(currentPrfOutput);
  const newRMat = newRecoveryMaterial.slice(0, 32);

  // AC wrap 再生成
  const kekPR = await deriveKEK(pMat, newRMat, "kek_pr");
  const ivA = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const wrapA = await aesGcmEncrypt(kekPR, ivA, mek);

  // この端末の BC wrap 再生成
  const kekKR = await deriveKEK(kMat, newRMat, "kek_kr");
  const ivC = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const wrapC = await aesGcmEncrypt(kekKR, ivC, mek);

  const newW = JSON.parse(JSON.stringify(envelope.w));
  newW.a = { i: b64uEncode(ivA), c: b64uEncode(wrapA) };
  newW.c = newW.c.filter((w) => w.h !== currentCredIdHash);
  newW.c.push({ h: currentCredIdHash, i: b64uEncode(ivC), c: b64uEncode(wrapC) });

  // 新 vault-id, App-Name (caller がこれで envelope を新 vault-id 下に書く)
  const newVaultId = deriveVaultId(newRMat);
  const newAppNameTag = deriveAppNameTag(newRMat);

  return {
    envelope: { ...envelope, w: newW },
    newVaultId,
    newAppNameTag,
  };
}

/**
 * Recovery を再発行する (ケース B: MEK ごと一新)。
 * 全 wrap 再生成、本体 c も再暗号化。新 publicKey が出るのでサーバ migration 必要。
 *
 * @returns {Promise<{ envelope, newMek, newVaultId, newAppNameTag, newSigningKey, oldSigningKey }>}
 *   newSigningKey で /api/migrate を呼んで oldSigningKey から新 KV エントリへ
 *   credit を移送する。
 */
export async function changeRecovery_caseB(envelope, oldMek, vault, password, currentCredIdHash, currentPrfOutput, newRecoveryMaterial) {
  const oldSigningKey = deriveSigningKey(oldMek);
  const newRMat = newRecoveryMaterial.slice(0, 32);
  const newMek = crypto.getRandomValues(new Uint8Array(32));

  const salt = b64uDecode(envelope.s);  // salt は流用 (PBKDF2 はパスワードに依存、salt 同じで問題なし)
  const pMat = await derivePMat(password, salt);
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
  const ivBody = crypto.getRandomValues(new Uint8Array(AES_IV_LEN));
  const mekKey = await crypto.subtle.importKey("raw", newMek, { name: "AES-GCM" }, false, ["encrypt"]);
  const padded = padPlaintext(enc.encode(JSON.stringify(vault)));
  const bodyCt = await aesGcmEncrypt(mekKey, ivBody, padded);

  const newEnvelope = {
    v: VAULT_FORMAT_V5,
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
    newVaultId: deriveVaultId(newRMat),
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
  const sig = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      privateKey,
      enc.encode(message)
    )
  );
  return b64uEncode(sig);
}

/**
 * リクエスト署名を検証する (サーバ側でも使うが、ブラウザでは主に self-test 用)。
 */
export async function verifyRequest(publicKey, message, sigB64u) {
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    b64uDecode(sigB64u),
    enc.encode(message)
  );
}

// ---------------------------------------------------------------------------
// Public-key utilities (server side / tests)
// ---------------------------------------------------------------------------

/**
 * publicKey を JWK で受け取り、ECDSA verify 用の CryptoKey を返す。
 */
export async function importPublicKeyJwk(publicKeyJwk) {
  return crypto.subtle.importKey(
    "jwk",
    publicKeyJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );
}

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
