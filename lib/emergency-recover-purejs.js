// ============================================================================
// emergency-recover-purejs.js — Pure-JS recovery crypto (NO Rust WASM)
// ----------------------------------------------------------------------------
// 緊急復旧ツール専用の自己完結復号モジュール。 本体 vault-crypto.js は Rust WASM
// opaque-handle 経路 (鍵を JS heap に出さない) だが、 復旧ツールは「バイナリ非依存・
// ブラウザ標準/公開 OSS だけで検証可能」 を優先し、 noble (HKDF-SHA256 / Argon2id)
// + WebCrypto (AES-GCM) だけで同じ結果を再現する。
//
// 互換: 個人 (Master + Recovery / Passkey) と business (K1 export + 2-of-3) の decrypt path、
//   records BEK、 2段階認証 (TOTP) の秘密キー。
//   salt/info・Argon2id パラメータ・wrap 構造は vault-crypto.js / rust-crypto と bit 一致。
//   HKDF は noble 同期版で本体と同一署名 (deriveRMat 等が sync)。
//   WebAuthn は範囲外 (ツールが本体の authenticateWithPasskey に委譲)。
// 2026-10-28: business も pure-JS に (旧: WASM の decryptBusinessVaultWithK1。 MEK を返さず
//   添付ファイルを復号できなかった)。 TOTP の秘密キーは docs/totp-spec.md §2-5 のとおり
//   このツールでだけ otpauth:// URI として取り出せる。
// ============================================================================
import { hkdf, sha256, argon2idAsync } from "/lib/vendor/noble-curves-and-hashes.mjs";

const enc = new TextEncoder();
const dec = new TextDecoder();
const AES_IV_LEN = 12;
const AES_TAG_LEN = 16;
const PAD_TERMINATOR = 0x80;
const VAULT_FORMAT_V5 = 5;

const S = {
  recovery_material: "arpass-recovery-v1",
  passkey_material:  "arpass-passkey-prf-v1",
  app_tag_name:      "arpass-app-tag-name-v6",
  app_tag_value:     "arpass-app-tag-value-v6",
  outer_key:         "arpass-outer-v6",
  kek_pr:            "arpass-kek-pr-v1",
  kek_pk:            "arpass-kek-pk-v1",
  kek_kr:            "arpass-kek-kr-v1",
};
const I = {
  recovery_material: "recovery-material",
  passkey_material:  "passkey-material",
  app_tag_name:      "app-tag-name",
  app_tag_value:     "app-tag-value",
  outer_key:         "envelope-wrap",
  kek_pr:            "kek-pr",
  kek_pk:            "kek-pk",
  kek_kr:            "kek-kr",
};
const CURRENT_KDF = { alg: "argon2id", m: 64 * 1024, t: 3, p: 4, dkLen: 32 };

// ---- base64url ----
export function b64uEncode(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function b64uDecode(str) {
  const s = String(str).replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4 ? "=".repeat(4 - (s.length % 4)) : "";
  const bin = atob(s + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---- primitives ----
// HKDF-SHA256 (noble, sync — 本体 hkdfBytes と bit 一致: hkdf(sha256, ikm, salt, info, len))
function hkdfBytes(ikm, saltStr, infoStr, len) {
  return hkdf(sha256, ikm, enc.encode(saltStr), enc.encode(infoStr), len);
}
// AES-256-GCM decrypt (WebCrypto, 全ブラウザ標準)
async function aesGcmDecrypt(keyBytes, iv, ct, aad = null) {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  const params = aad ? { name: "AES-GCM", iv, additionalData: aad } : { name: "AES-GCM", iv };
  const pt = await crypto.subtle.decrypt(params, key, ct);
  return new Uint8Array(pt);
}
function unpad(padded) {
  for (let i = padded.length - 1; i >= 0; i--) {
    if (padded[i] === PAD_TERMINATOR) return padded.subarray(0, i);
    if (padded[i] !== 0) throw new Error("Padding terminator not found");
  }
  throw new Error("Padding terminator not found");
}

// ---- derivations (sync, bit-compatible with vault-crypto.js) ----
export function deriveRMat(recoveryString) {
  const norm = (recoveryString || "")
    .replace(/[‐-―−－⁃‧]/g, "-")
    .replace(/\s+/g, "")
    .toUpperCase();
  return hkdfBytes(enc.encode(norm), S.recovery_material, I.recovery_material, 32);
}
export function deriveKMat(prfOutput) {
  return hkdfBytes(prfOutput, S.passkey_material, I.passkey_material, 32);
}
export function deriveOuterKeyBytes(rMat) {
  return hkdfBytes(rMat, S.outer_key, I.outer_key, 32);
}
export function deriveAppNameTag(rMat, tier = null) {
  const suf = tier ? `::${tier}` : "";
  const name = hkdfBytes(rMat, S.app_tag_name, I.app_tag_name + suf, 8);
  const value = hkdfBytes(rMat, S.app_tag_value, I.app_tag_value + suf, 16);
  return { name: b64uEncode(name), value: b64uEncode(value) };
}
export function deriveAllAppNameTags(rMat) {
  return {
    free:    deriveAppNameTag(rMat, "free"),
    paid:    deriveAppNameTag(rMat, "paid"),
    private: deriveAppNameTag(rMat, "private"),
  };
}
async function derivePMat(password, saltBytes, kdfParams) {
  const p = kdfParams || CURRENT_KDF;
  return argon2idAsync(enc.encode(password), saltBytes, { t: p.t, m: p.m, p: p.p, dkLen: p.dkLen || 32 });
}
function deriveKEK(m1, m2, saltKey) {
  const cat = new Uint8Array(m1.length + m2.length);
  cat.set(m1, 0); cat.set(m2, m1.length);
  return hkdfBytes(cat, S[saltKey], I[saltKey], 32);
}

// ---- outer envelope ----
export async function unwrapEnvelopeOuter(blob, outerKeyBytes) {
  if (blob.length < AES_IV_LEN + AES_TAG_LEN) throw new Error(`Outer blob too short: ${blob.length}`);
  const iv = blob.slice(0, AES_IV_LEN);
  const ct = blob.slice(AES_IV_LEN);
  let pt;
  try { pt = await aesGcmDecrypt(outerKeyBytes, iv, ct); }
  catch { throw new Error("Outer envelope decryption failed (wrong outer key or corrupt blob)"); }
  return JSON.parse(dec.decode(pt));
}

// ---- inner: 2-of-3 wrap (w.a / w.b / w.c) をほどく。 personal は MEK、 business は K2 が出る ----
async function unwrapFactorKey(envelope, factors) {
  const haveP = !!factors?.password;
  const haveR = factors?.recoveryMaterial instanceof Uint8Array && factors.recoveryMaterial.length >= 32;
  const haveK = factors?.prfOutput instanceof Uint8Array && factors.prfOutput.length >= 16;
  if ([haveP, haveK, haveR].filter(Boolean).length < 2) {
    throw new Error("Need at least 2 of {password, prfOutput, recoveryMaterial}");
  }
  const salt = b64uDecode(envelope.s);
  const pMat = haveP ? await derivePMat(factors.password, salt, envelope.kdfParams) : null;
  const kMat = haveK ? deriveKMat(factors.prfOutput) : null;
  const rMat = haveR ? factors.recoveryMaterial.slice(0, 32) : null;
  const credIdHash = factors.credIdHash;

  let mek = null;
  const tryUnwrap = async (kek, w) => { try { return await aesGcmDecrypt(kek, b64uDecode(w.i), b64uDecode(w.c)); } catch { return null; } };

  if (!mek && haveP && haveK && envelope.w?.b?.length) {          // AB: Master + Passkey
    const kek = deriveKEK(pMat, kMat, "kek_pk");
    const cands = credIdHash ? envelope.w.b.filter((w) => w.h === credIdHash) : envelope.w.b;
    for (const w of cands) { mek = await tryUnwrap(kek, w); if (mek) break; }
  }
  if (!mek && haveP && haveR && envelope.w?.a) {                  // AC: Master + Recovery
    const kek = deriveKEK(pMat, rMat, "kek_pr");
    mek = await tryUnwrap(kek, envelope.w.a);
  }
  if (!mek && haveK && haveR && envelope.w?.c?.length) {          // BC: Passkey + Recovery
    const kek = deriveKEK(kMat, rMat, "kek_kr");
    const cands = credIdHash ? envelope.w.c.filter((w) => w.h === credIdHash) : envelope.w.c;
    for (const w of cands) { mek = await tryUnwrap(kek, w); if (mek) break; }
  }
  if (!mek) throw new Error("Vault key unwrap failed (wrong factors, or a mode this tool does not support).");
  return mek;
}

// ---- inner: personal decryptVault (AB / AC / BC) ----
export async function decryptVault(envelope, factors) {
  if (!envelope || envelope.v !== VAULT_FORMAT_V5) throw new Error(`v5 envelope expected, got v=${envelope?.v}`);
  const mek = await unwrapFactorKey(envelope, factors);
  const padded = await aesGcmDecrypt(mek, b64uDecode(envelope.i), b64uDecode(envelope.c));
  const vault = JSON.parse(dec.decode(unpad(padded)));
  return { vault, mek };  // mek = raw 32B (records BEK / TOTP unwrap 用)
}

// ---- inner: business (K1 + K2) ----
// real_MEK = HKDF-SHA256(ikm = K2, salt = K1, info = "mek-business-v2")
//   (rust-crypto K1Key::derive_business_mek_v2 / vault-crypto.js HKDF_INFO_MEK_BUSINESS + "-v2")
export function deriveBusinessRealMek(k2, k1Bytes) {
  return hkdf(sha256, k2, k1Bytes, enc.encode("mek-business-v2"), 32);
}

/**
 * business vault を K1 export の候補 ({ bytes, version }[]) で順に試して復号する。
 * K2 は factor 由来で GCM 認証付きなので、 本体の tag 不一致は K1 不一致を意味する。
 * @returns {Promise<{ vault, mek, k2, k1Version }>}  mek = 本体を開いた real_MEK (raw 32B)
 */
export async function decryptVaultBusiness(envelope, factors, k1Candidates) {
  if (!envelope || envelope.v !== VAULT_FORMAT_V5 || envelope.m !== "business")
    throw new Error("business envelope expected");
  if (envelope.kdfV2 !== true)
    throw new Error("Business decryption failed: envelope.kdfV2 must be true");
  const k2 = await unwrapFactorKey(envelope, factors);
  for (const cand of k1Candidates || []) {
    const mek = deriveBusinessRealMek(k2, cand.bytes);
    let padded;
    try { padded = await aesGcmDecrypt(mek, b64uDecode(envelope.i), b64uDecode(envelope.c)); }
    catch { mek.fill(0); continue; }
    const vault = JSON.parse(dec.decode(unpad(padded)));
    return { vault, mek, k2, k1Version: cand.version };
  }
  k2.fill(0);
  throw new Error("Business decryption failed: no K1 in the export file opens this vault");
}

// ---- records (files): MEK/BEK は raw AES-256 鍵として直接使用 ----
export async function unwrapBek(mekBytes, wrappedBEK, wrapIv) {
  return aesGcmDecrypt(mekBytes, wrapIv, wrappedBEK);   // → 32B BEK
}
export async function decryptFileWithBek(bekBytes, dataIv, ciphertext) {
  return aesGcmDecrypt(bekBytes, dataIv, ciphertext);   // → 平文ファイル
}

// ---- 2段階認証 (TOTP) の秘密キー: docs/totp-spec.md §3.1 / §3.2 (rust-crypto/src/totp.rs と bit 一致) ----
//   totpWrapKey = HKDF-SHA256(ikm = MEK, salt = "arpass/totp/v1", info = "totp-wrap")
//   secret      = AES-256-GCM-decrypt(totpWrapKey, iv, aad = "arpass/totp/v1|" + entry.id, ct)
export async function unwrapTotpSecret(mekBytes, entryId, wrapped) {
  const wrapKey = hkdfBytes(mekBytes, "arpass/totp/v1", "totp-wrap", 32);
  try {
    return await aesGcmDecrypt(wrapKey, b64uDecode(wrapped.iv), b64uDecode(wrapped.ct),
      enc.encode("arpass/totp/v1|" + entryId));
  } finally {
    wrapKey.fill(0);
  }
}

// RFC 4648 Base32 (大文字・パディング無し。 認証アプリの otpauth が受け付ける形)
export function base32Encode(bytes) {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let out = "", bits = 0, value = 0;
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) { out += A[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += A[(value << (5 - bits)) & 31];
  return out;
}

/**
 * 他の認証アプリへ移すための otpauth:// URI (Key URI Format)。
 * issuer / account が空ならエントリのサイト名 / ユーザー名で補う。
 */
export function totpOtpauthUri(entry, secretBytes) {
  const t = entry?.totp || {};
  const issuer = String(t.issuer || entry?.site || "").trim();
  const account = String(t.account || entry?.user || "").trim() || issuer || "Arpass";
  const label = issuer
    ? encodeURIComponent(issuer) + ":" + encodeURIComponent(account)
    : encodeURIComponent(account);
  const q = [
    "secret=" + base32Encode(secretBytes),
    ...(issuer ? ["issuer=" + encodeURIComponent(issuer)] : []),
    "algorithm=" + (t.algorithm || "SHA1"),
    "digits=" + (t.digits || 6),
    "period=" + (t.period || 30),
  ];
  return "otpauth://totp/" + label + "?" + q.join("&");
}
