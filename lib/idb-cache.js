// ============================================================================
// web/lib/idb-cache.js — Phase 7.0i (IndexedDB record file cache)
// ----------------------------------------------------------------------------
// Records ファイル本体 (BEK で暗号化済 ciphertext) のクライアント側永続キャッシュ。
// localStorage 比でメリット:
//   - 容量: localStorage 5-10MB → IndexedDB 50-500MB (browser/origin quota)
//   - binary native: base64 encoding 不要 → メモリ + 速度 効率化
//   - TTL 拡張: 10 分 → 7 日 (頻用 record の Arweave gateway 往復削減)
//
// セキュリティ:
//   - cache する ciphertext は AES-GCM で暗号化済 (BEK + dataIv)
//   - BEK は MEK で wrap、MEK は session memory のみ。lock 時に MEK 消去で
//     IDB 上の ciphertext は decrypt 不能に。
//   - 同じ ciphertext は Arweave 上に publicly 存在する。追加情報露出ゼロ。
//
// Fallback:
//   - IDB unavailable / quota over → local-cache.js が localStorage に fallback
//   - 7-day expire は best-effort、起動時に cleanup 走らせる
// ============================================================================

const DB_NAME = "arpass.recordsCache";
const DB_VERSION = 1;
const STORE_NAME = "files";
const TTL_MS = 7 * 24 * 60 * 60 * 1000;  // 7 days

let _dbPromise = null;

/** @returns {Promise<IDBDatabase>} */
function _openDb() {
  if (_dbPromise) return _dbPromise;
  if (typeof indexedDB === "undefined") {
    return Promise.reject(new Error("IndexedDB not available"));
  }
  _dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        const store = db.createObjectStore(STORE_NAME, { keyPath: "txid" });
        store.createIndex("savedAt", "savedAt", { unique: false });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error("IDB open failed"));
  });
  return _dbPromise;
}

/**
 * Records ファイル ciphertext を IDB に保存 (TTL 7 day)。
 * @param {string} txid
 * @param {Uint8Array} ciphertext
 * @returns {Promise<void>}
 */
export async function idbSetRecordFile(txid, ciphertext) {
  if (!txid || !(ciphertext instanceof Uint8Array)) return;
  try {
    const db = await _openDb();
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      const store = tx.objectStore(STORE_NAME);
      // Uint8Array をそのまま structured-clone 可能 (IDB native binary support)
      store.put({ txid, ciphertext, savedAt: Date.now() });
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error || new Error("IDB put failed"));
    });
  } catch (e) {
    // QuotaExceededError 等は best-effort skip (上位で localStorage fallback)
    console.warn("[idb-cache] set failed (non-fatal):", e?.message ?? e);
    throw e;  // 上位 (local-cache.js) が catch して localStorage fallback
  }
}

/**
 * Records ファイル ciphertext を IDB から取得。expire 済 / 不在なら null。
 * @param {string} txid
 * @returns {Promise<Uint8Array | null>}
 */
export async function idbGetRecordFile(txid) {
  if (!txid) return null;
  try {
    const db = await _openDb();
    const obj = await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const req = tx.objectStore(STORE_NAME).get(txid);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    if (!obj) return null;
    if (typeof obj.savedAt === "number" && Date.now() - obj.savedAt > TTL_MS) {
      idbDeleteRecordFile(txid).catch(() => {});
      return null;
    }
    if (obj.ciphertext instanceof Uint8Array) return obj.ciphertext;
    if (obj.ciphertext instanceof ArrayBuffer) return new Uint8Array(obj.ciphertext);
    return null;
  } catch (e) {
    console.warn("[idb-cache] get failed (non-fatal):", e?.message ?? e);
    return null;
  }
}

/**
 * 指定 txid の cache を削除。
 * @param {string} txid
 * @returns {Promise<void>}
 */
export async function idbDeleteRecordFile(txid) {
  if (!txid) return;
  try {
    const db = await _openDb();
    await new Promise((resolve) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      tx.objectStore(STORE_NAME).delete(txid);
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();  // best-effort
    });
  } catch { /* ignore */ }
}

/**
 * 期限切れ entries を一括 cleanup (起動時 or quota over 時に呼ぶ)。
 * @returns {Promise<number>} 削除した entry 数
 */
export async function idbCleanupExpired() {
  try {
    const db = await _openDb();
    const cutoff = Date.now() - TTL_MS;
    return await new Promise((resolve) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      const idx = tx.objectStore(STORE_NAME).index("savedAt");
      const range = IDBKeyRange.upperBound(cutoff, true);
      let removed = 0;
      idx.openCursor(range).onsuccess = (e) => {
        const cursor = e.target.result;
        if (cursor) {
          cursor.delete();
          removed++;
          cursor.continue();
        }
      };
      tx.oncomplete = () => resolve(removed);
      tx.onerror = () => resolve(removed);
    });
  } catch {
    return 0;
  }
}

/**
 * IndexedDB が利用可能か確認 (機能検出)。
 * @returns {Promise<boolean>}
 */
export async function idbIsAvailable() {
  if (typeof indexedDB === "undefined") return false;
  try {
    await _openDb();
    return true;
  } catch {
    return false;
  }
}
