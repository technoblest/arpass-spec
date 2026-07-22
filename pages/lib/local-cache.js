// ============================================================================
// web/lib/local-cache.js
//
// Phase 5.3 — Encrypted envelope blob の短期キャッシュ抽象層。
//
// 目的:
//   保存直後の Turbo bundling 待ち窓 (0〜2 分) を埋める。Turbo gateway が
//   配信を開始した時点で即破棄するため、長期残留しない。
//
// セキュリティ:
//   キャッシュする blob は **既に外側 AES-GCM 済み** (HKDF(vault-id) で暗号化
//   済) のため、localStorage に置いても追加情報露出はない。同じ blob は
//   Arweave 上にも publicly 存在する。詳細は docs/security-baseline.md §6-9。
//
// 容量設計:
//   - vault envelope は ~120-200 KB (base64url 含む)。1 件のみ保持。
//   - localStorage の typical 上限 5-10 MB / origin に対し余裕。
//
// Phase 6 への移行:
//   ファイル添付対応で IndexedDB に移行する際、本モジュールの API シグネチャ
//   を維持したまま実装だけ差し替えれば呼び出し側 (vault-client.js,
//   client-auth.js) は無修正。そのため意図的に async API にしてある。
// ============================================================================

import { activeEnvCacheKey, activeRecCacheKeyPrefix } from "./profiles.js?v=69cb395d";

// Phase 7.1-W: localStorage key を profile-aware に。
//   旧: const STORAGE_KEY = "arpass.envCache"
//   新: _envKey() = "arpass.envCache__<activeProfileId>"
// active profile が無いと null を返す → 全 set/get/delete が no-op になる (= safe fail)。
function _envKey() {
  return activeEnvCacheKey();
}

/**
 * @param {string} txid              対応する Arweave tx id
 * @param {Uint8Array} blob          outer-encrypted envelope バイト列
 * @returns {Promise<void>}
 */
export async function setEnvelopeCache(txid, blob) {
  if (!txid || !(blob instanceof Uint8Array)) {
    throw new TypeError("setEnvelopeCache: txid (string) と blob (Uint8Array) が必要");
  }
  const blob_b64u = _bytesToB64u(blob);
  const payload = JSON.stringify({
    txid,
    blob_b64u,
    savedAt: Date.now(),
  });
  try {
    const k = _envKey(); if (k) localStorage.setItem(k, payload);
  } catch (e) {
    // QuotaExceededError 等。cache は best-effort なので silently skip。
    console.warn("[local-cache] setEnvelopeCache failed (non-fatal):", e?.message ?? e);
  }
}

/**
 * @param {string} txid              対応する Arweave tx id
 * @returns {Promise<Uint8Array | null>}
 */
export async function getEnvelopeCache(txid) {
  if (!txid) return null;
  try {
    const k = _envKey(); if (!k) return null; const raw = localStorage.getItem(k);
    if (!raw) return null;
    const obj = JSON.parse(raw);
    if (obj?.txid !== txid) return null;
    return _b64uToBytes(obj.blob_b64u);
  } catch {
    return null;
  }
}

/**
 * @param {string} [txid]   指定すれば「その txid のとき」のみ削除、未指定なら無条件削除
 * @returns {Promise<void>}
 */
export async function deleteEnvelopeCache(txid) {
  try {
    if (typeof txid === "string") {
      const k = _envKey(); if (!k) return null; const raw = localStorage.getItem(k);
      if (!raw) return;
      try {
        const obj = JSON.parse(raw);
        if (obj?.txid !== txid) return;
      } catch { /* fall through */ }
    }
    const k = _envKey(); if (k) localStorage.removeItem(k);
  } catch {
    /* no-op */
  }
}

/**
 * 単に「現在キャッシュされている txid は何か」だけ取りたいとき。
 * UI 表示や outOfSync 判定に使える軽量版。
 * @returns {Promise<string | null>}
 */
export async function getCachedTxId() {
  try {
    const k = _envKey(); if (!k) return null; const raw = localStorage.getItem(k);
    if (!raw) return null;
    const obj = JSON.parse(raw);
    return obj?.txid ?? null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Phase 7.0e refine v9: Records ファイル本体の cache (Turbo 配信前 bridge)
// ---------------------------------------------------------------------------
//
// Vault envelope と同じく、書き込み直後の 0-2 分間 (Turbo 配信開始前) は
// gateway から GET できない。この窓を埋めるため、ciphertext を localStorage に
// 一時保存。
//
// 違い:
//   - Vault: 単一 slot (常に最新 1 個のみ)
//   - Records: 複数 entry (各 record が独立した txid を持つため、key 別に保存)
//
// セキュリティ:
//   ciphertext は BEK (random per-blob) で encrypt 済み。BEK 自体は MEK で wrap
//   されて vault に保存。localStorage 漏洩しても BEK なしで解読不能。
//
// 容量:
//   - 1 record max 1 MB plaintext → ~1 MB ciphertext → ~1.4 MB b64u
//   - localStorage 5-10 MB quota → 3-5 records 同時保持可能
//   - 超過時は setRecordFileCache が silently skip (best-effort)
//   - 10 分経過で自動 expire (Turbo 配信開始の十分後)

// Phase 7.1-W: record file cache prefix も profile-aware に
//   旧: "arpass.recCache.<txid>"
//   新: "arpass.recCache__<profileId>.<txid>"
function _recKey(txid) {
  const prefix = activeRecCacheKeyPrefix();
  if (!prefix) return null;
  return prefix + txid;
}
const RECORD_CACHE_KEY_PREFIX_LEGACY = "arpass.recCache.";  // 旧 prefix、cleanup 用

const RECORD_CACHE_MAX_AGE_MS = 10 * 60 * 1000;  // 10 分 (localStorage fallback の TTL)

// Phase 7.0i: IndexedDB に primary 移行。本モジュールは互換 API + localStorage fallback。
import { idbSetRecordFile, idbGetRecordFile, idbDeleteRecordFile, idbCleanupExpired } from "./idb-cache.js?v=ea255434";

// 起動時に IDB の expired cleanup を一度だけ実行 (best-effort)
let _idbCleanupRan = false;
function _runIdbCleanupOnce() {
  if (_idbCleanupRan) return;
  _idbCleanupRan = true;
  idbCleanupExpired().catch(() => {});
}

/**
 * Record ファイル ciphertext を保存 (IDB primary、localStorage fallback)。
 * Phase 7.0i:
 *   - IDB は 7-day TTL + binary native + 50-500MB quota で primary
 *   - IDB unavailable / quota over の時のみ localStorage 10-min TTL に fallback
 * @param {string} txid
 * @param {Uint8Array} ciphertext  BEK で暗号化済み bytes
 * @returns {Promise<void>}
 */
export async function setRecordFileCache(txid, ciphertext) {
  if (!txid || !(ciphertext instanceof Uint8Array)) return;
  _runIdbCleanupOnce();
  // 1) Primary: IndexedDB
  try {
    await idbSetRecordFile(txid, ciphertext);
    return;
  } catch (e) {
    console.warn("[local-cache] IDB unavailable, falling back to localStorage:", e?.message ?? e);
  }
  // 2) Fallback: localStorage (10 min TTL bridge for Turbo distribution)
  cleanupExpiredRecordCaches();
  const ct_b64u = _bytesToB64u(ciphertext);
  const payload = JSON.stringify({ ct_b64u, savedAt: Date.now() });
  try {
    const k = _recKey(txid); if (k) localStorage.setItem(k, payload);
  } catch (e) {
    console.warn("[local-cache] localStorage also failed (non-fatal):", e?.message ?? e);
  }
}

/**
 * Record ファイル cache を取得 (IDB → localStorage の順)。
 * @param {string} txid
 * @returns {Promise<Uint8Array | null>}
 */
export async function getRecordFileCache(txid) {
  if (!txid) return null;
  // 1) Primary: IndexedDB
  try {
    const b = await idbGetRecordFile(txid);
    if (b) return b;
  } catch { /* fallthrough */ }
  // 2) Fallback: localStorage (古いキャッシュとの互換)
  try {
    const k = _recKey(txid); if (!k) return null; const raw = localStorage.getItem(k);
    if (!raw) return null;
    const obj = JSON.parse(raw);
    if (!obj?.ct_b64u) return null;
    if (typeof obj.savedAt === "number" && Date.now() - obj.savedAt > RECORD_CACHE_MAX_AGE_MS) {
      try { const k = _recKey(txid); if (k) localStorage.removeItem(k); } catch {}
      return null;
    }
    return _b64uToBytes(obj.ct_b64u);
  } catch {
    return null;
  }
}

/**
 * Record ファイル cache を削除 (IDB + localStorage 両方)。
 * @param {string} txid
 */
export async function deleteRecordFileCache(txid) {
  if (!txid) return;
  idbDeleteRecordFile(txid).catch(() => {});
  try { const k = _recKey(txid); if (k) localStorage.removeItem(k); } catch {}
}

/** 期限切れ record cache を全削除 (quota 確保用、setRecordFileCache が呼ぶ)。 */
function cleanupExpiredRecordCaches() {
  try {
    const now = Date.now();
    const toRemove = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      // Phase 7.1-W: 全 profile の record cache + legacy prefix を cleanup 対象に
      const profPrefix = activeRecCacheKeyPrefix() || "";
      if (!k || (!k.startsWith(RECORD_CACHE_KEY_PREFIX_LEGACY) && !k.includes("arpass.recCache__"))) continue;
      try {
        const obj = JSON.parse(localStorage.getItem(k) ?? "");
        if (typeof obj?.savedAt === "number" && now - obj.savedAt > RECORD_CACHE_MAX_AGE_MS) {
          toRemove.push(k);
        }
      } catch {
        toRemove.push(k);  // 壊れた entry も削除
      }
    }
    for (const k of toRemove) {
      try { localStorage.removeItem(k); } catch {}
    }
  } catch { /* ignore */ }
}

// ---------------------------------------------------------------------------
// 内部ヘルパー (vault-crypto.js の b64u と独立に持つ — 循環依存回避)
// ---------------------------------------------------------------------------

function _bytesToB64u(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function _b64uToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4;
  if (pad === 2) s += "==";
  else if (pad === 3) s += "=";
  else if (pad === 1) throw new Error("invalid base64url length");
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
