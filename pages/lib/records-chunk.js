// ============================================================================
// web/lib/records-chunk.js — Records のアーカイブ (records.chunks) の暗号 (2026-11-19)
// ----------------------------------------------------------------------------
// 鍵はすべて Rust の handle (MekKey / BekKey) のまま扱い、 生の鍵を JS に出さない。 import は持たない
//   (vault-client.js とテストの両方から、 同じものを使えるように)。
//
// 形は 2 つある:
//   v3 (2026-11-19 まで): chunk の中身を CEK (BekKey) で暗号化し、 CEK を MEK で包んで
//       chunkRef.encryption.wrappedCEK に置く。 中の各記録のファイル鍵 (attachments[].encryption.wrappedBEK)
//       は、 封をしたときの MEK に包まれたまま (Arweave の上なので書き換えられない)。 Recovery の Case B で
//       MEK が変わると、 中のファイルが開けなくなる。
//   v4 (chunkRef.schemaVersion = 4): chunk ごとに「チャンク鍵」 (MekKey.generate()) を作る。
//       - 中身 (JSON) はチャンク鍵で暗号化する (AES-GCM、 AAD は空。 v3 と同じ形)。
//       - 中の各記録のファイル鍵は、 チャンク鍵で包み直す (印: encryption.wrappedBy = "chunk")。
//       - チャンク鍵は MEK で包み、 v3 と同じ欄 chunkRef.encryption.wrappedCEK に置く (業務は k1Version つき)。
//       Rust の wrap_mek と wrap_bek は、 どちらも「32 バイトの鍵を AES-GCM (AAD 空) で包む」だけで、 できる
//       バイト列が同じ。 だから Case B の包み直し (rewrapVaultSecretsForNewMek) と業務の K1 移行
//       (rewrapBusinessSecretsToCurrentK1) は、 何も変えずに v4 のチャンク鍵も包み直す。 本体の鍵だけ包み直せば
//       Arweave の上の chunk は開き続ける (vault-crypto.js の 3 層の設計どおり)。
//       この「混ぜても往復できる」ことは scripts/test-records-archive.mjs で押さえている。
// ============================================================================

export const CHUNK_SCHEMA_V4 = 4;
// 封をしてから、 Arweave で確定しないまま、 この日数を過ぎた chunk は落ちたものとみなす (items は active に残してある)。
export const CHUNK_PENDING_GIVE_UP_MS = 14 * 24 * 60 * 60 * 1000;

const EMPTY = new Uint8Array(0);

function _b64uEncode(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function _b64uDecode(str) {
  const pad = (4 - (str.length % 4)) % 4;
  const bin = atob(String(str).replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function _iv() { return crypto.getRandomValues(new Uint8Array(12)); }
function _free(h) { if (h && typeof h.free === "function") { try { h.free(); } catch (_) {} } }
function _err(code, message, cause) {
  const e = new Error(message || code);
  e.code = code;
  if (cause) e.cause = cause;
  return e;
}

export function chunkSchema(ref) { return ref?.schemaVersion === CHUNK_SCHEMA_V4 ? CHUNK_SCHEMA_V4 : 3; }
export function isPendingChunk(ref) { return ref?.pending === true; }
/** チャンク鍵 (v3 は CEK) を包んだものが無い (= 開けないと分かって外したもの)。 */
export function chunkKeyMissing(ref) { return typeof ref?.encryption?.wrappedCEK !== "string"; }

/**
 * v4 の封。 items は active の記録 (書き換えない。 写しを作る)。
 * @param {object} o
 * @param {Array}  o.items
 * @param {(k1Version: number|null) => Promise<object>} o.mekForVersion  ファイル鍵を包んでいる MEK (MekKey handle、 free しない)
 * @param {object} o.currentMek     チャンク鍵を包む今の MEK (MekKey handle、 free しない)
 * @param {() => Promise<object>} o.generateKey  新しいチャンク鍵 (MekKey handle) を作る
 * @param {number|null} [o.k1Version]  業務の今の K1 版 (個人は null)
 * @param {string} [o.sealedAt]
 * @returns {Promise<{ ciphertext: Uint8Array, encryption: object, items: Array, sealedAt: string }>}
 */
export async function sealChunkV4({ items, mekForVersion, currentMek, generateKey, k1Version = null, sealedAt = new Date().toISOString() }) {
  if (!currentMek || typeof currentMek.wrap_mek !== "function") throw new Error("sealChunkV4: current MekKey handle required");
  const ck = await generateKey();
  if (!ck || typeof ck.wrap_bek !== "function") throw new Error("sealChunkV4: chunk key (MekKey) required");
  try {
    const sealedItems = JSON.parse(JSON.stringify(items));
    for (const item of sealedItems) {
      delete item.archivedIn;
      for (const att of Array.isArray(item?.attachments) ? item.attachments : []) {
        const enc = att?.encryption;
        if (!enc?.wrappedBEK || !enc?.wrapIv) continue;
        const mek = await mekForVersion(enc.k1Version ?? null);
        const bek = mek.unwrap_bek(_b64uDecode(enc.wrappedBEK), _b64uDecode(enc.wrapIv));
        try {
          const wrapIv = _iv();
          const wrapped = ck.wrap_bek(bek, wrapIv);
          att.encryption = {
            algorithm: enc.algorithm || "AES-GCM-256",
            wrappedBEK: _b64uEncode(wrapped),
            wrapIv: _b64uEncode(wrapIv),
            dataIv: enc.dataIv,
            wrappedBy: "chunk",
          };
        } finally { _free(bek); }
      }
    }
    const plain = new TextEncoder().encode(JSON.stringify({ items: sealedItems, sealedAt, schemaVersion: CHUNK_SCHEMA_V4 }));
    const dataIv = _iv();
    const ciphertext = ck.aes_gcm_encrypt(dataIv, plain, EMPTY);
    const wrapIv = _iv();
    const wrappedCEK = currentMek.wrap_mek(ck, wrapIv);
    return {
      ciphertext,
      sealedAt,
      items: sealedItems,
      encryption: {
        algorithm: "AES-GCM-256",
        wrappedCEK: _b64uEncode(wrappedCEK),
        wrapIv: _b64uEncode(wrapIv),
        dataIv: _b64uEncode(dataIv),
        ...(k1Version != null ? { k1Version } : {}),
      },
    };
  } finally { _free(ck); }
}

/**
 * chunk の鍵を開く。 v4 は MekKey (チャンク鍵)、 v3 は BekKey (CEK)。 どちらも aes_gcm_decrypt を持つ。 呼び出し側が free する。
 * 失敗は code で返す:
 *   - chunk_key_unwrap_failed: 鍵はあるのにほどけない (この先も開けない)
 *   - chunk_key_version_unavailable: 業務で、 包んだ K1 の版がサーバーから消えている (管理者が配り直せば開ける)
 *   - key_fetch_failed: 鍵を取りに行けなかった (通信など。 少し待てば開けるかもしれない)
 */
export async function openChunkKey(ref, mekForVersion) {
  const enc = ref?.encryption || {};
  if (typeof enc.wrappedCEK !== "string" || typeof enc.wrapIv !== "string") throw _err("chunk_key_unwrap_failed", "chunk key is missing");
  const mek = await _mekOrThrow(mekForVersion, enc.k1Version ?? null);
  try {
    return chunkSchema(ref) === CHUNK_SCHEMA_V4
      ? mek.unwrap_mek(_b64uDecode(enc.wrappedCEK), _b64uDecode(enc.wrapIv))
      : mek.unwrap_bek(_b64uDecode(enc.wrappedCEK), _b64uDecode(enc.wrapIv));
  } catch (e) {
    throw _err("chunk_key_unwrap_failed", "chunk key could not be unwrapped: " + (e?.message || e), e);
  }
}

// 包んでいる鍵 (MEK / その版の real_MEK) を取る。 取れなかったわけを code で分ける。
async function _mekOrThrow(mekForVersion, k1Version) {
  try {
    const mek = await mekForVersion(k1Version);
    if (!mek) throw new Error("no key");
    return mek;
  } catch (e) {
    if (e?.code === "old_k1_unavailable" || e?.code === "chunk_key_version_unavailable") {
      const err = _err("chunk_key_version_unavailable", "K1 v" + k1Version + " is not available: " + (e?.message || e), e);
      err.k1Version = k1Version;
      throw err;
    }
    throw _err("key_fetch_failed", "key could not be fetched: " + (e?.message || e), e);
  }
}

/**
 * chunk の暗号文を開いて { items, sealedAt, schemaVersion } を返す。
 * 失敗は code で返す: chunk_key_unwrap_failed / chunk_key_version_unavailable / key_fetch_failed (openChunkKey) と
 *   chunk_decrypt_failed / chunk_malformed (暗号文が壊れている。 手元の写しなら取り直して確かめること: readChunkVerified)。
 */
export async function decryptChunk(ref, ciphertext, mekForVersion) {
  const key = await openChunkKey(ref, mekForVersion);
  let bytes;
  try {
    bytes = key.aes_gcm_decrypt(_b64uDecode(ref.encryption.dataIv), ciphertext, EMPTY);
  } catch (e) {
    throw _err("chunk_decrypt_failed", "chunk could not be decrypted: " + (e?.message || e), e);
  } finally { _free(key); }
  let json;
  try { json = JSON.parse(new TextDecoder().decode(bytes)); }
  catch (e) { throw _err("chunk_malformed", "chunk JSON malformed", e); }
  if (!Array.isArray(json?.items)) throw _err("chunk_malformed", "chunk JSON malformed (no items[])");
  return json;
}

/**
 * chunk を読んで開く。 手元の写し (キャッシュ) で復号できなければ、 ネットワークから取り直してもう一度試す
 *   (壊れた写しだけで「この先も開けない」と決めないため)。
 * @param {(ref: object, opts: {fresh: boolean}) => Promise<Uint8Array>} fetchCiphertext
 */
export async function readChunkVerified(ref, mekForVersion, fetchCiphertext) {
  const ct = await fetchCiphertext(ref, { fresh: false });
  try {
    return await decryptChunk(ref, ct, mekForVersion);
  } catch (e) {
    if (e?.code !== "chunk_decrypt_failed" && e?.code !== "chunk_malformed") throw e;
    const fresh = await fetchCiphertext(ref, { fresh: true });
    return decryptChunk(ref, fresh, mekForVersion);
  }
}

/**
 * アーカイブした記録のファイル鍵 (BekKey) をほどく。 呼び出し側が free する。
 *   wrappedBy "chunk" (v4) はチャンク鍵で、 そうでなければ (v3) 記録した版の MEK で。
 */
export async function unwrapArchivedBek(ref, att, mekForVersion) {
  const enc = att?.encryption || {};
  if (enc.wrappedBy === "chunk") {
    const ck = await openChunkKey(ref, mekForVersion);
    try { return ck.unwrap_bek(_b64uDecode(enc.wrappedBEK), _b64uDecode(enc.wrapIv)); }
    finally { _free(ck); }
  }
  const mek = await _mekOrThrow(mekForVersion, enc.k1Version ?? null);
  return mek.unwrap_bek(_b64uDecode(enc.wrappedBEK), _b64uDecode(enc.wrapIv));
}

/**
 * 記録の添付のファイル鍵が、 いまの鍵 (mekForVersion) で全部ほどけるか (v3 の chunk から active に戻してよいか)。
 * 包み直しの走査は 1 つでもほどけないと止まるので、 ほどけない記録は active に戻さない。
 *   false を返すのは unwrap_bek が失敗したとき (鍵が違う) だけ。 鍵を取りに行けなかったときは throw する
 *   (code key_fetch_failed = 一時的、 chunk_key_version_unavailable = 業務で K1 の版がサーバーに無い)。
 */
export async function attachmentsUnwrappable(item, mekForVersion) {
  for (const att of Array.isArray(item?.attachments) ? item.attachments : []) {
    const enc = att?.encryption;
    if (!enc) continue;
    if (enc.wrappedBy === "chunk") return false;   // v4 の中身は active に戻さない
    if (typeof enc.wrappedBEK !== "string" || typeof enc.wrapIv !== "string") continue;
    const mek = await _mekOrThrow(mekForVersion, enc.k1Version ?? null);
    let h = null;
    try {
      h = mek.unwrap_bek(_b64uDecode(enc.wrappedBEK), _b64uDecode(enc.wrapIv));
    } catch (_) {
      return false;
    } finally { _free(h); }
  }
  return true;
}

/**
 * chunk を読めなかったわけ:
 *   - "lost":        鍵がほどけない・(取り直しても) 復号できない・中身が壊れている。 この先も開けない
 *                    (進めても失うものは増えない)
 *   - "missing":     どのゲートウェイにも無い (404)。 その時点で無いというだけで、 あとで読めるようになるかもしれない
 *   - "k1_waiting":  業務で、 包んだ K1 の版がサーバーに無い (管理者が配り直せば開ける)
 *   - "transient":   通信の失敗・5xx・鍵を取りに行けなかった (少し待てば読めるかもしれない)
 * decrypt / malformed は、 取り直したあとの失敗だけを lost とみなすこと (readChunkVerified)。
 */
export function classifyChunkLoadError(err) {
  const code = err?.code || "";
  if (code === "chunk_key_unwrap_failed" || code === "chunk_decrypt_failed" || code === "chunk_malformed") return "lost";
  if (code === "chunk_key_version_unavailable") return "k1_waiting";
  if (code === "chunk_missing" || /not yet available/.test(String(err?.message || ""))) return "missing";
  return "transient";
}

/**
 * 鍵を包み直す前 (Recovery の Case B、 業務の K1 移行) のアーカイブの準備。 vault の写しを返す
 *   (元の vault は変えない。 包み直しが途中で止まっても手元は変わらない)。
 *   - どの chunk も、 チャンク鍵 (v3 は CEK) が今の鍵でほどけるかを確かめる。 ほどけない (lost) と包み直しの走査
 *     (rewrapVaultSecretsForNewMek) が止まるので、 markLostKeys のときは wrappedCEK を wrappedCEKUnopenable に
 *     移す (chunk の参照は残す)。 業務で K1 の版がサーバーに無いとき (k1_waiting) は k1Unavailable を付けて残す
 *     (移行のお知らせに数えない。 開けたら外す)。
 *   - v3 の chunk は中身を読み (手元の写しで開けなければネットワークから取り直す)、 今の鍵でファイル鍵が全部ほどける
 *     記録だけ active に戻す (ほかの記録と一緒に包み直される。 Arweave への書き込みはなし)。 全部戻せたら chunk の
 *     参照を外す。 ほどけない記録 (unwrap_bek の失敗) だけが残るときは legacyCheckedAt を付ける (次からは確かめない)。
 *   - v4 の chunk は鍵を確かめるだけ (チャンク鍵を包んだ wrappedCEK だけが、 走査で包み直される)。
 *   - 一時的な失敗 (通信・5xx・鍵を取りに行けない) があれば、 何も変えずに止める (code "archive_transient")。
 *   - 返す unreadable は、 lost (この先も開けない。 進めても失うものは増えない) と missing (404。 今は読めない。
 *     進めると、 あとで読めるようになっても中のファイルは開けなくなる) に分けて kind を付ける。
 *     404・通信の失敗・K1 の版が無いときは legacyCheckedAt を付けない (あとでもう一度確かめる)。
 * @param {object} vault
 * @param {object} o
 * @param {(k1Version: number|null) => Promise<object>} o.mekForVersion
 * @param {(chunkRef: object, opts: {fresh: boolean}) => Promise<Uint8Array>} o.fetchCiphertext
 * @param {boolean} [o.markLostKeys]
 * @param {number} [o.now]
 * @returns {Promise<{vault: object, moved: number, unreadable: Array, waiting: Array, changed: boolean}>}
 */
export async function prepareArchivesForKeyChange(vault, { mekForVersion, fetchCiphertext, markLostKeys = false, now = Date.now() } = {}) {
  const copy = JSON.parse(JSON.stringify(vault ?? {}));
  if (!copy.records || !Array.isArray(copy.records.chunks) || copy.records.chunks.length === 0) {
    return { vault: copy, moved: 0, unreadable: [], waiting: [], changed: false };
  }
  if (!Array.isArray(copy.records.active)) copy.records.active = [];
  if (!Array.isArray(copy.recordHistory)) copy.recordHistory = [];
  const mf = mekForVersion;
  const unreadable = [], transient = [], waiting = [];
  let moved = 0, changed = false;
  const at = new Date(now).toISOString();
  const activeIds = new Set(copy.records.active.map((r) => r?.id));
  const info = (ref, kind, reason, extra = {}) => ({
    id: ref.id, kind, reason, count: ref.count ?? null,
    dateFrom: ref.range?.dateFrom ?? null, dateTo: ref.range?.dateTo ?? null, ...extra,
  });
  const markWaiting = (ref, k1Version) => {
    waiting.push(info(ref, "k1_waiting", "chunk_key_version_unavailable", { k1Version }));
    if (!ref.k1Unavailable || ref.k1Unavailable.version !== k1Version) {
      ref.k1Unavailable = { version: k1Version ?? null, at };
      changed = true;
    }
  };
  for (const ref of [...copy.records.chunks]) {
    if (chunkKeyMissing(ref)) continue;   // 前に「開けない」と分かって鍵を外したもの
    // 1) チャンク鍵 (v3 は CEK) が今の鍵でほどけるか
    try {
      const k = await openChunkKey(ref, mf);
      _free(k);
      if (ref.k1Unavailable) { delete ref.k1Unavailable; changed = true; }
    } catch (e) {
      const kind = classifyChunkLoadError(e);
      if (kind === "lost") {
        unreadable.push(info(ref, "lost", "key"));
        if (markLostKeys) {
          ref.encryption.wrappedCEKUnopenable = ref.encryption.wrappedCEK;
          delete ref.encryption.wrappedCEK;
          ref.unopenable = "key";
          changed = true;
        }
      } else if (kind === "k1_waiting") {
        markWaiting(ref, e?.k1Version ?? ref.encryption?.k1Version ?? null);
      } else {
        transient.push(info(ref, "transient", e?.code || "network"));
      }
      continue;
    }
    if (chunkSchema(ref) === CHUNK_SCHEMA_V4) continue;
    if (ref.legacyCheckedAt) continue;   // 前に確かめた v3 (戻せない記録だけが残っている)
    // 2) v3: 中身を読む (手元の写しで開けなければ取り直す)
    let json;
    try {
      json = await readChunkVerified(ref, mf, fetchCiphertext);
    } catch (e) {
      const kind = classifyChunkLoadError(e);
      if (kind === "lost") {
        unreadable.push(info(ref, "lost", e?.code || "unreadable"));
        ref.legacyCheckedAt = at;   // 取り直しても開けない: 次からは確かめない
        changed = true;
      } else if (kind === "missing") {
        unreadable.push(info(ref, "missing", "chunk_missing"));
      } else if (kind === "k1_waiting") {
        markWaiting(ref, e?.k1Version ?? null);
      } else {
        transient.push(info(ref, "transient", e?.code || "network"));
      }
      continue;
    }
    // 3) 今の鍵でファイル鍵がほどける記録だけ active に戻す
    let kept = 0, movedHere = 0, waitingVersion = null, transientHere = null;
    const toMove = [];
    for (const item of json.items) {
      if (!item?.id || activeIds.has(item.id)) continue;
      let ok;
      try {
        ok = await attachmentsUnwrappable(item, mf);
      } catch (e) {
        const kind = classifyChunkLoadError(e);
        if (kind === "k1_waiting") { waitingVersion = e?.k1Version ?? waitingVersion; continue; }
        transientHere = e;
        break;
      }
      if (ok) toMove.push(item);
      else kept++;
    }
    if (transientHere) {
      transient.push(info(ref, "transient", transientHere?.code || "network"));
      continue;
    }
    for (const item of toMove) {
      const it = JSON.parse(JSON.stringify(item));
      delete it.archivedIn;
      copy.records.active.push(it);
      activeIds.add(it.id);
      movedHere++;
    }
    moved += movedHere;
    if (movedHere > 0 || kept > 0) changed = true;
    if (waitingVersion != null) {
      markWaiting(ref, waitingVersion);   // まだ戻せない記録がある: 確かめ済みにはしない
      if (movedHere > 0) copy.recordHistory.push({ id: ref.id, action: "chunk_partly_unsealed", at, count: movedHere, kept });
    } else if (kept === 0) {
      copy.records.chunks = copy.records.chunks.filter((x) => x.id !== ref.id);
      copy.recordHistory.push({ id: ref.id, action: "chunk_unsealed", at, count: movedHere });
      changed = true;
    } else {
      ref.legacyCheckedAt = at;
      copy.recordHistory.push({ id: ref.id, action: "chunk_partly_unsealed", at, count: movedHere, kept });
      changed = true;
    }
  }
  if (transient.length) {
    const e = new Error("archived records could not be loaded (temporary) — try again later");
    e.code = "archive_transient";
    e.archives = transient;
    throw e;
  }
  return { vault: copy, moved, unreadable, waiting, changed };
}

/** v3 の chunk で、 まだ鍵の包み直しの前の確かめをしていないものの数 (K1 の版を待っているものは数えない)。 */
export function legacyChunksNeedingCheck(vault) {
  return (vault?.records?.chunks ?? []).filter((c) =>
    chunkSchema(c) !== CHUNK_SCHEMA_V4 && !chunkKeyMissing(c) && !c.legacyCheckedAt && !c.k1Unavailable).length;
}

/** K1 の版がサーバーに無くて待っている chunk のうち、 チャンク鍵が古い版のままのもの (K1 移行のお知らせから引く)。 */
export function chunksWaitingForK1(vault, curVer) {
  return (vault?.records?.chunks ?? []).filter((c) =>
    c?.k1Unavailable && typeof c?.encryption?.wrappedCEK === "string" && typeof c?.encryption?.wrapIv === "string" &&
    c.encryption.k1Version != null && c.encryption.k1Version !== curVer).length;
}

/**
 * 記録の日付が、 chunk の range (封をしたときの日付から作る) の外に訂正されたとき、 range を広げる
 *   (日付で絞ったとき、 その chunk を読むように)。 変えたら true。
 */
export function widenChunkRange(ref, date) {
  if (!ref || typeof date !== "string" || !date) return false;
  if (!ref.range) { ref.range = { dateFrom: date, dateTo: date }; return true; }
  let changed = false;
  if (!ref.range.dateFrom || date < ref.range.dateFrom) { ref.range.dateFrom = date; changed = true; }
  if (!ref.range.dateTo || date > ref.range.dateTo) { ref.range.dateTo = date; changed = true; }
  return changed;
}
