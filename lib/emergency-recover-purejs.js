// ============================================================================
// emergency-recover-purejs.js — Pure-JS recovery crypto (NO Rust WASM)
// ----------------------------------------------------------------------------
// 緊急復旧ツール専用の自己完結復号モジュール。 本体 vault-crypto.js は Rust WASM
// opaque-handle 経路 (鍵を JS heap に出さない) だが、 復旧ツールは「バイナリ非依存・
// ブラウザ標準/公開 OSS だけで検証可能」 を優先し、 noble (HKDF-SHA256 / Argon2id)
// + WebCrypto (AES-GCM) だけで同じ結果を再現する。
//
// 互換: 個人 (Master + Recovery / Passkey) の decrypt path + records BEK。
//   salt/info・Argon2id パラメータ・wrap 構造は vault-crypto.js と bit 一致。
//   HKDF は noble 同期版で本体と同一署名 (deriveRMat 等が sync)。
//   business K1 path と WebAuthn は範囲外 (ツールが WASM path に委譲)。
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
async function aesGcmDecrypt(keyBytes, iv, ct) {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
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

// ---- inner: personal decryptVault (AB / AC / BC) ----
export async function decryptVault(envelope, factors) {
  if (!envelope || envelope.v !== VAULT_FORMAT_V5) throw new Error(`v5 envelope expected, got v=${envelope?.v}`);
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
  try {
    console.log("[pure-js dbg] v=", envelope.v, "m=", envelope.m,
      "kdfParams=", JSON.stringify(envelope.kdfParams),
      "wKeys=", Object.keys(envelope.w || {}),
      "wa=", envelope.w?.a ? Object.keys(envelope.w.a) : null,
      "wbN=", envelope.w?.b?.length, "wcN=", envelope.w?.c?.length,
      "have P/K/R=", haveP, haveK, haveR,
      "pMatLen=", pMat?.length, "rMatLen=", rMat?.length, "saltLen=", salt.length,
      "iLen=", envelope.i ? b64uDecode(envelope.i).length : null,
      "cLen=", envelope.c ? b64uDecode(envelope.c).length : null);
  } catch (_) {}

  let mek = null;
  const tryUnwrap = async (kek, w, tag) => {
    try { return await aesGcmDecrypt(kek, b64uDecode(w.i), b64uDecode(w.c)); }
    catch (e) {
      try { console.log("[pure-js dbg] " + tag + " unwrap fail:", e?.name || e?.message,
        "kekLen=", kek.length, "wIvLen=", b64uDecode(w.i).length, "wCtLen=", b64uDecode(w.c).length); } catch (_) {}
      return null;
    }
  };

  if (!mek && haveP && haveK && envelope.w?.b?.length) {          // AB: Master + Passkey
    const kek = deriveKEK(pMat, kMat, "kek_pk");
    const cands = credIdHash ? envelope.w.b.filter((w) => w.h === credIdHash) : envelope.w.b;
    for (const w of cands) { mek = await tryUnwrap(kek, w); if (mek) break; }
  }
  if (!mek && haveP && haveR && envelope.w?.a) {                  // AC: Master + Recovery
    const kek = deriveKEK(pMat, rMat, "kek_pr");
    mek = await tryUnwrap(kek, envelope.w.a, "AC");
  }
  if (!mek && haveK && haveR && envelope.w?.c?.length) {          // BC: Passkey + Recovery
    const kek = deriveKEK(kMat, rMat, "kek_kr");
    const cands = credIdHash ? envelope.w.c.filter((w) => w.h === credIdHash) : envelope.w.c;
    for (const w of cands) { mek = await tryUnwrap(kek, w); if (mek) break; }
  }
  if (!mek) throw new Error("MEK unwrap failed (wrong factors, or a mode this tool does not support).");

  const padded = await aesGcmDecrypt(mek, b64uDecode(envelope.i), b64uDecode(envelope.c));
  const vault = JSON.parse(dec.decode(unpad(padded)));
  return { vault, mek };  // mek = raw 32B (records BEK unwrap 用)
}

// ---- records (files): MEK/BEK は raw AES-256 鍵として直接使用 ----
export async function unwrapBek(mekBytes, wrappedBEK, wrapIv) {
  return aesGcmDecrypt(mekBytes, wrapIv, wrappedBEK);   // → 32B BEK
}
export async function decryptFileWithBek(bekBytes, dataIv, ciphertext) {
  return aesGcmDecrypt(bekBytes, dataIv, ciphertext);   // → 平文ファイル
}
