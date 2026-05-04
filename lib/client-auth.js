// ============================================================================
// web/lib/client-auth-v5.js
//
// Arpass v5 用 identity / API 認証 / Arweave 読み書きレイヤ。
//
// docs/crypto-2of3.md v5 に従い、以下の方針で実装:
//   - vault-id をサーバには一切送らない (X-Vault-Id ヘッダ廃止)
//   - 認証は X-Public-Key + X-Signature + X-Timestamp の 3 ヘッダ
//   - 署名鍵は localStorage に永続化しない (vault-client-v5 が MEK から派生して
//     都度 importSigningKeyPair、本モジュールは渡された CryptoKey で署名)
//   - localStorage には軽量メタ (vault-id, App-Name タグ, credIdHash) のみ
//   - Arweave 読み書きは外側 AES-GCM 層を経由 (HKDF(vault-id) で wrap/unwrap)
// ============================================================================

import {
  signRequest,
  unwrapEnvelopeOuter,
  wrapEnvelopeOuter,
  b64uEncode,
  b64uDecode,
} from "./vault-crypto.js";

import {
  getEnvelopeCache,
  setEnvelopeCache,
  deleteEnvelopeCache,
} from "./local-cache.js";

// ---------------------------------------------------------------------------
// localStorage キー (v5)
// ---------------------------------------------------------------------------

// v5 では「identity」概念が消え、代わりに復号後派生の publicKey を使う。
// localStorage に永続化するのは vault-id (= Arweave 検索キー、外側暗号鍵の
// 種) と関連メタのみ。
const META_KEY = "arpass_vault_meta_v5";

const ARWEAVE_GATEWAY = "https://arweave.net";
const TURBO_GATEWAY = "https://turbo-gateway.com";
const FETCH_TIMEOUT_MS = 30000;  // Turbo gateway 経由は遅い時 ~3s、長めに余裕
const GRAPHQL_TIMEOUT_MS = 5000;

// ---------------------------------------------------------------------------
// Meta (localStorage)
// ---------------------------------------------------------------------------

/**
 * v5 メタ:
 *   {
 *     vaultId:     "<base64url 16-byte vault-id>",
 *     appNameTag:  "<16-char base64url, HKDF(Recovery)>",
 *     credIdHash:  "<16-char base64url, this device's Passkey>",
 *     credentialId:"<base64url WebAuthn raw credential id>",
 *     publicKeyHash: "<22-char H(publicKey)>",
 *     latestTxId:  "<arweave txid>"  // performance hint, NOT authoritative
 *   }
 * vault-id 含めて localStorage 内であり、HTTPS 越しサーバや Arweave に送らない。
 */
export function readMeta() {
  try { return JSON.parse(localStorage.getItem(META_KEY) || "null"); }
  catch { return null; }
}
export function writeMeta(meta) {
  localStorage.setItem(META_KEY, JSON.stringify(meta));
}
export function patchMeta(patch) {
  const cur = readMeta() || {};
  writeMeta({ ...cur, ...patch });
}
export function clearMeta() {
  localStorage.removeItem(META_KEY);
}

// ---------------------------------------------------------------------------
// API 認証ヘルパー (X-Public-Key + ECDSA 署名)
// ---------------------------------------------------------------------------

/**
 * 署名状態オブジェクト:
 *   {
 *     signingPrivateKey: CryptoKey (ECDSA P-256 sign)
 *     publicKeyRaw: Uint8Array(65, uncompressed)
 *   }
 *
 * これは vault-client-v5 が unlock 後に作って渡す。本モジュールは保持しない
 * (= lockSession 後にリーク経路ゼロ)。
 */

/**
 * 認証付き fetch。X-Public-Key, X-Timestamp, X-Signature を生成して付加する。
 *
 * @param {string} url
 * @param {string} method  GET / POST etc.
 * @param {object|null} bodyObject  JSON 本体 (なければ null)
 * @param {object} signingState  { signingPrivateKey, publicKeyRaw }
 * @returns {Promise<Response>}
 */
export async function signedFetch(url, method, bodyObject, signingState) {
  if (!signingState?.signingPrivateKey || !signingState?.publicKeyRaw) {
    throw new Error("signedFetch requires signingState with signingPrivateKey + publicKeyRaw");
  }
  const ts = Math.floor(Date.now() / 1000).toString();
  const rawBody = bodyObject == null ? "" : JSON.stringify(bodyObject);
  const message = `${ts}.${rawBody}`;
  const sigB64u = await signRequest(signingState.signingPrivateKey, message);
  const headers = {
    "X-Public-Key": b64uEncode(signingState.publicKeyRaw),
    "X-Timestamp": ts,
    "X-Signature": sigB64u,
  };
  if (bodyObject != null) headers["Content-Type"] = "application/json";
  return fetch(url, { method, headers, body: rawBody || undefined });
}

// ---------------------------------------------------------------------------
// サーバ API (publicKey ベース)
// ---------------------------------------------------------------------------

/**
 * /api/vault/register — 新規アカウント作成。署名は不要 (誰でも publicKey 申告
 * できるが、対応する秘密鍵を持っていないと以降の認証付き操作は通らない)。
 */
export async function registerVault(publicKeyRaw) {
  const r = await fetch("/api/vault/register", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Public-Key": b64uEncode(publicKeyRaw),
    },
    body: JSON.stringify({}),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) throw new Error(`register failed: ${j.error || r.status}`);
  return j;  // { ok, credits, alreadyRegistered? }
}

/**
 * /api/balance — 残高取得 (旧 GET /api/vault/:vaultId の置換)。
 */
export async function getBalance(signingState) {
  const r = await signedFetch("/api/balance", "GET", null, signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`balance fetch failed: ${j.error || r.status}`);
  return j;  // { credits, totalSpent, totalAdded, latestTxId, ... }
}

/**
 * /api/migrate — Case B Recovery 再発行用。旧鍵で署名 → 新 publicKey へ残高移送。
 *
 * @param {object} oldSigningState  旧 (d, Q) を Web Crypto に importKey した状態
 * @param {Uint8Array} newPublicKeyRaw  新 publicKey の uncompressed raw
 */
export async function migrateAccount(oldSigningState, newPublicKeyRaw) {
  const body = { newPublicKey: b64uEncode(newPublicKeyRaw) };
  const r = await signedFetch("/api/migrate", "POST", body, oldSigningState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) throw new Error(`migrate failed: ${j.error || r.status}`);
  return j;  // { ok, oldKvKey, newKvKey, credits, migratedAt }
}

// ---------------------------------------------------------------------------
// Arweave 読み書き (外側 AES-GCM 層経由)
// ---------------------------------------------------------------------------

/**
 * Arweave からエンベロープを取得 → 外側復号 → 内側 envelope JSON を返す。
 *
 * @param {string} txid
 * @param {Uint8Array} vaultId  16-byte
 * @param {object} [options]
 *   bundlerBase: ペンディング bundler の URL (任意 fallback)
 * @returns {Promise<{ envelope: object, source: "turbo"|"arweave"|"bundler-pending" }>}
 */
export async function fetchEnvelope(txid, vaultId, options = {}) {
  // Phase 5.3 (revised): **Cache-first with background network probe**.
  //
  // 旧実装は「network 先試行 → 失敗で cache fallback」だったが、bundling 中の
  // 0〜2 分窓では network が 30 秒 timeout するまで待たされる致命的 UX バグ
  // だった。順序を逆転:
  //
  //   1. cache lookup (sync 同等で即時)
  //      a. hit → 即座に return + 裏で network probe を発火 (Turbo 配信開始
  //         を検知したら cache 破棄して、次回 unlock で source-of-truth に
  //         戻れるようにする)
  //      b. miss → 通常の network fetch (待つしかない)
  //
  // ※ 並行端末更新の整合性は別レイヤー (server.latestTxId vs meta.latestTxId
  //    比較 = outOfSync 検知) で担保するので、本関数は「指定された txid を
  //    最速で出す」責務に集中する。
  const cached = await getEnvelopeCache(txid);
  if (cached) {
    // Background probe — fire-and-forget. 成功したら cache を捨てる。
    // 結果は今回の return には影響させない。
    readBlobWithFallback(txid, options)
      .then(() => { deleteEnvelopeCache(txid).catch(() => {}); })
      .catch(() => { /* まだ Turbo bundling 中。cache はそのまま */ });
    const envelope = await unwrapEnvelopeOuter(cached, vaultId);
    return { envelope, source: "local-cache" };
  }
  // cache miss — network を待つしかない
  const blob = await readBlobWithFallback(txid, options);
  const envelope = await unwrapEnvelopeOuter(new Uint8Array(blob.body), vaultId);
  return { envelope, source: blob.source };
}

/**
 * raw blob を Arweave (Turbo + arweave.net 並列) または bundler から取得。
 * 並列化 + 個別 timeout — 直近 hotfix 済みパターンを踏襲。
 */
async function readBlobWithFallback(txid, options = {}) {
  const candidates = [
    { name: "turbo", url: `${TURBO_GATEWAY}/${txid}` },
    { name: "arweave", url: `${ARWEAVE_GATEWAY}/${txid}` },
  ];

  const winner = await new Promise((resolve, reject) => {
    let pending = candidates.length;
    const errors = [];
    const settle = (msg) => {
      errors.push(msg);
      if (--pending === 0) reject(new Error(errors.join("; ")));
    };
    for (const { name, url } of candidates) {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
      fetch(url, { cache: "no-store", signal: ctrl.signal })
        .then(async (r) => {
          clearTimeout(timer);
          if (r.ok) {
            const buf = await r.arrayBuffer();
            resolve({
              source: name,
              body: buf,
              contentType: r.headers.get("content-type") ?? "application/octet-stream",
            });
          } else {
            settle(`${name}: HTTP ${r.status}`);
          }
        })
        .catch((e) => {
          clearTimeout(timer);
          settle(`${name}: ${e?.message ?? e}`);
        });
    }
  }).catch(() => null);

  if (winner) return winner;

  // Final fallback: pending bundler queue (if configured)
  if (options.bundlerBase) {
    const r = await fetch(`${options.bundlerBase}/items/${txid}`, { cache: "no-store" });
    if (r.ok) {
      return {
        source: "bundler-pending",
        body: await r.arrayBuffer(),
        contentType: r.headers.get("content-type") ?? "application/octet-stream",
      };
    }
  }

  throw new Error(`Item ${txid} not available on Turbo, arweave.net, or bundler.`);
}

/**
 * App-Name タグで Arweave GraphQL を検索し、最新の txid を返す。
 * Turbo + arweave.net 並列、各 5s timeout。
 *
 * @param {string} appNameTag  vault-client が deriveAppNameTag で派生した値
 * @returns {Promise<string|null>}
 */
export async function findLatestVaultTx(appNameTag) {
  const query = `
    query {
      transactions(
        tags: [{ name: "App-Name", values: ["${appNameTag}"] }]
        sort: HEIGHT_DESC
        first: 1
      ) {
        edges { node { id } }
      }
    }
  `;

  async function queryGateway(gateway) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), GRAPHQL_TIMEOUT_MS);
    try {
      const resp = await fetch(`${gateway}/graphql`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query }),
        signal: ctrl.signal,
      });
      clearTimeout(timer);
      if (!resp.ok) return null;
      const data = await resp.json();
      return data?.data?.transactions?.edges?.[0]?.node?.id ?? null;
    } catch (e) {
      clearTimeout(timer);
      return null;
    }
  }

  const [turboHit, arweaveHit] = await Promise.all([
    queryGateway(TURBO_GATEWAY),
    queryGateway(ARWEAVE_GATEWAY),
  ]);
  return turboHit ?? arweaveHit;
}

// ---------------------------------------------------------------------------
// Arweave 書き込み (サーバ API /api/write 経由)
// ---------------------------------------------------------------------------

/**
 * envelope を 外側 AES-GCM で wrap → /api/write に POST → Arweave に書き込み。
 * /api/write はサーバが Arweave bundler に submit する経路。本クライアントから
 * 直接 Arweave に書くことはない (credit 課金とサーバ側の認証が必要なため)。
 *
 * @param {object} envelope          v5 内側 envelope
 * @param {Uint8Array} vaultId       外側暗号化に使う vault-id
 * @param {string} appNameTag        Arweave タグ用
 * @param {object} signingState
 * @returns {Promise<object>}        サーバの { ok, txid, credits, ... }
 */
export async function writeEnvelope(envelope, vaultId, appNameTag, signingState, options = {}) {
  const blob = await wrapEnvelopeOuter(envelope, vaultId);
  const dataB64u = b64uEncode(blob);
  const body = {
    data: dataB64u,
    encoding: "base64url",                  // サーバが decode する目印
    contentType: "application/octet-stream", // Arweave タグ Content-Type
    tags: { "App-Name": appNameTag },        // クライアントが指定可能なのは App-Name のみ
  };
  // Phase 5.3 楽観ロック: client が知っている直前の latestTxId を server に送り、
  // server 側 KV と異なれば 409 version_conflict を返してもらう。複数端末同時編集
  // による lost-update を防ぐ。options.expectedLatestTxId === undefined のときは
  // 送信しない (= 楽観ロック非適用、初回 createVault 経路など)。
  if (options.expectedLatestTxId !== undefined) {
    body.expectedLatestTxId = options.expectedLatestTxId;
  }
  const r = await signedFetch("/api/write", "POST", body, signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) {
    // 409 version_conflict は呼び出し側で UX 処理が必要なので code を保持して投げる。
    const err = new Error(j.error || `write failed: HTTP ${r.status}`);
    err.code = j.code;
    err.status = r.status;
    err.expectedLatestTxId = j.expectedLatestTxId;
    err.actualLatestTxId = j.actualLatestTxId;
    throw err;
  }
  // Phase 5.3: 書き込み成功直後に local cache に保存。Turbo bundling 完了までの
  // ブリッジ目的。fetchEnvelope が成功した時点で deleteEnvelopeCache される。
  try {
    await setEnvelopeCache(j.txid, blob);
  } catch (e) {
    console.warn("[writeEnvelope] cache save failed (non-fatal):", e?.message ?? e);
  }
  return j;  // { ok, txid, credits, size_bytes, ... }
}

// ===========================================================================
// getTxStatus — Arweave トランザクションの状態を取得 (Phase 5.1 で v5 用に
// 本実装を復活)
//
// 旧 vault-client.js v4 の queryTxStatusGraphQL + queryTxStatus を統合した
// もの。client-auth.js (本モジュール) は API + Arweave I/O 担当層なので
// ここに置くのが妥当。
//
// フロー:
//   1. Turbo + arweave.net 両方の GraphQL を並列クエリ (5s timeout)
//      → block.height があれば 'confirmed'、bundledIn があれば 'bundling'
//   2. GraphQL に何もなければ /tx/{id}/status (L1) を arweave.net に問う
//      → 200 + parsed → confirmed、202 / "Pending" → pending、404 → not_found
//      → 429 → rate_limited (retryAfterSeconds 付き)
//   3. 404 の場合は probeDataReachable で Turbo / arweave に GET Range
//      bytes=0-0 して、データ自体は読めるなら 'bundling' (state without L1
//      yet)
// ===========================================================================

const _GRAPHQL_TIMEOUT_MS = 5000;
const _PROBE_TIMEOUT_MS = 4000;

async function _queryTxStatusGraphQL(txid) {
  // Arweave GraphQL schema:
  //   Block { id, timestamp, height, previous }     ← indep_hash は無い (block.id がそれ相当)
  //   Transaction.bundledIn { id }                   ← Turbo bundle 用拡張、両 gateway で OK
  // 旧コードは block { height timestamp indep_hash } で書いていたが、
  // indep_hash フィールドが存在しないため 400 Bad Request になっていた。
  const query = `
    query {
      transactions(ids: ["${txid}"]) {
        edges { node { id block { id height timestamp } bundledIn { id } } }
      }
    }
  `;
  async function askGw(gateway) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), _GRAPHQL_TIMEOUT_MS);
    try {
      const r = await fetch(`${gateway}/graphql`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query }),
        signal: ctrl.signal,
      });
      clearTimeout(timer);
      if (!r.ok) {
        // 400 は schema mismatch (= 私たちのコードのバグ) なので必ずログ。
        const body = await r.text().catch(() => "(no body)");
        console.warn(`[getTxStatus] ${gateway} returned ${r.status}: ${body.slice(0, 300)}`);
        return null;
      }
      const j = await r.json();
      const node = j?.data?.transactions?.edges?.[0]?.node;
      return node ?? null;
    } catch {
      clearTimeout(timer);
      return null;
    }
  }
  const [turbo, arw] = await Promise.all([askGw(TURBO_GATEWAY), askGw(ARWEAVE_GATEWAY)]);
  // block.height がある方を優先 (= 確定済み情報)。
  // Turbo は bundledIn を即座に返すが block 情報は遅れる傾向がある。
  if (arw?.block?.height) {
    return {
      state: "confirmed",
      blockHeight: arw.block.height,
      blockIndepHash: arw.block.id ?? null,
      confirmations: null,  // /tx/{id}/status で取れるが GraphQL では出ない
      via: "arweave-graphql",
    };
  }
  if (turbo?.block?.height) {
    return {
      state: "confirmed",
      blockHeight: turbo.block.height,
      blockIndepHash: turbo.block.id ?? null,
      confirmations: null,
      via: "turbo-graphql",
    };
  }
  if (turbo?.bundledIn?.id || arw?.bundledIn?.id) {
    return {
      state: "bundling",
      via: "https://turbo-gateway.com",
      bundleId: turbo?.bundledIn?.id ?? arw?.bundledIn?.id,
    };
  }
  return null;
}

const TURBO_UPLOAD_SERVICE = "https://upload.ardrive.io";

/**
 * Turbo upload service の "data item status" API を叩く。
 *
 *   GET https://upload.ardrive.io/v1/tx/{txid}/status
 *   → {
 *       status: "RECEIVED" | "PROCESSING" | "BUNDLED" | "CONFIRMED",
 *       bundleId: "..." (CONFIRMED + info=pending 以降),
 *       info: "new" | "pending" | "permanent"?,
 *       rawContentLength, payloadContentType, winc, ...
 *     }
 *
 * 観察 (実測 by Yamaki):
 *   - status は「Turbo が受領を確約したか」の意味 (= CONFIRMED は受領済の合意)
 *   - info で詳細 lifecycle:
 *       new       = 受領完了、bundle 未割当 (bundleId なし)
 *       pending   = bundle 化済み、L1 確定後も **永続的に pending のまま**
 *       permanent = 仕様上はあるかも、実用では observe されず
 *   - **真の "Arweave 確定" 判定は arweave.net gateway 200 が唯一の確実な signal**
 *   - Turbo info=permanent path はほぼ dead code (互換のため残置)
 *
 * @returns {Promise<{ accepted: bool, finalized: bool, bundleId?: string, info?: string, raw?: object } | null>}
 */
async function _queryTurboStatus(txid) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), _PROBE_TIMEOUT_MS);
  try {
    const r = await fetch(`${TURBO_UPLOAD_SERVICE}/v1/tx/${txid}/status`, {
      method: "GET",
      cache: "no-store",
      signal: ctrl.signal,
    });
    clearTimeout(timer);
    if (!r.ok) return null;
    const j = await r.json().catch(() => null);
    if (!j?.status) return null;
    // Turbo が受領を確約してる状態
    const accepted = j.status === "CONFIRMED" ||
                     ["RECEIVED", "PROCESSING", "BUNDLED"].includes(j.status);
    // info=permanent (or 同等) なら完全確定とみなす (gateway 200 と同等の真の最終確定)
    const finalized = j.status === "CONFIRMED" && (j.info === "permanent" || j.info === "finalized");
    return {
      accepted,
      finalized,
      bundleId: j.bundleId,
      info: j.info,
      raw: j,
    };
  } catch {
    clearTimeout(timer);
    return null;
  }
}

async function _probeDataReachable(txid) {
  // Phase 5.3-N: gateway 別に「200 が返ったか」を個別に追跡する。
  //   - arweave.net 200 → データは Arweave 本体に確定 (= ViewBlock 可)
  //   - turbo-gateway.com 200 のみ → Turbo の CDN cache だけ (= まだ転送中)
  //   - 両方 4xx/5xx → 不到達
  // 戻り値: { arweave: bool, turbo: bool }
  const cb = `?t=${Date.now()}`;
  const candidates = [
    { name: "turbo", base: TURBO_GATEWAY },
    { name: "arweave", base: ARWEAVE_GATEWAY },
  ];
  const result = { arweave: false, turbo: false };
  await Promise.all(candidates.map(({ name, base }) => new Promise((resolve) => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), _PROBE_TIMEOUT_MS);
    fetch(`${base}/${txid}${cb}`, {
      method: "GET",
      headers: { Range: "bytes=0-0" },
      cache: "no-store",
      redirect: "follow",
      signal: ctrl.signal,
    })
      .then((r) => {
        clearTimeout(timer);
        if (r.ok || r.status === 206) result[name] = true;
        resolve();
      })
      .catch(() => {
        clearTimeout(timer);
        resolve();
      });
  })));
  return result;
}

/**
 * Arweave 上の tx の状態を取得する。
 * 戻り値:
 *   { state: "confirmed", blockHeight, blockIndepHash, confirmations, via }
 *   { state: "bundling",  via, bundleId? }
 *   { state: "pending" }
 *   { state: "not_found" }
 *   { state: "rate_limited", retryAfterSeconds }
 *   { state: "error", message }
 */
export async function getTxStatus(txid, options = {}) {
  if (!txid || typeof txid !== "string") {
    return { state: "error", message: "invalid txid" };
  }
  // Phase 5.3-Y: { forceProbe: true } で「Turbo bundleId なし」段階でも
  // arweave.net + GraphQL を並列で叩く。手動「🔄 今すぐ再確認」用。
  // ポーリング (default) は最適化のため bundleId 出るまでスキップ。
  const forceProbe = !!options.forceProbe;
  try {
    // ★ Phase 5.3-N: 状態を 4 つにシンプル化 (delivered を廃止)。
    //
    //   judging principle:
    //     arweave.net 200 = データは Arweave 本体に確定保存済 (ViewBlock 可)
    //                     → "confirmed"
    //     turbo-gateway 200 のみ = Turbo CDN cache だけ、Arweave 未到達
    //                            → "bundling"
    //     GraphQL に block.height あり = 確定 (重複判定、意味は同じ)
    //                                  → "confirmed"
    //     全部失敗 → "not_found"

    // ★ Phase 5.3-T: Turbo upload service status を最優先 source に。
    //   - upload.ardrive.io/v1/tx/{id}/status が真の権威 (Turbo 自身の認識)
    //   - gateway probe は補助情報 (bundleId / arweave 確定の証拠としては有用)
    //
    // 判定優先順位:
    //   1) Turbo status === "CONFIRMED"      → "confirmed" (bundle が Arweave 確定済)
    //   2) Turbo status === RECEIVED/PROCESSING/BUNDLED → "bundling"
    //   3) Turbo status 404                 → 古い tx か直接書き込み → 4) へ
    //   4) gateway probe arweave.net 200    → "confirmed"
    //   5) gateway probe turbo-gateway 200  → "bundling"
    //   6) GraphQL bundling                 → "bundling"
    //   7) 何も無い                          → "not_found"
    // ★ Phase 5.3-Y: 2 段階 fetch — Turbo status だけ先に確認し、
    //   bundleId が出てから (= bundling phase 以降) に arweave.net + GraphQL を発火。
    //
    //   理由: Turbo 受領未配信 (bundleId なし) 段階では arweave.net も
    //         GraphQL も 100% 失敗 (まだ bundle 化されてない)。叩いても無駄。
    //         bundleId が出てから初めて Arweave 反映の可能性が出るので、その時に
    //         並列 probe する方が効率的 (poll 1 回あたりの request 数を 3→1 に削減)。
    //
    //   流れ:
    //     1) Turbo status だけ取得 (1 request)
    //     2a) Turbo unknown (404) → 古い tx or 直接書込 → 全 source で fallback
    //     2b) Turbo accepted + bundleId なし → not_found (確定)
    //     2c) Turbo accepted + bundleId 有  → arweave.net + GraphQL 並列 probe (3 requests)
    //     2d) Turbo finalized → confirmed (確定)

    const turbo = await _queryTurboStatus(txid).catch(() => null);

    // (a) Turbo finalized (info=permanent) → 即座に confirmed
    if (turbo?.finalized) {
      return {
        state: "confirmed",
        via: "turbo-status",
        bundleId: turbo.bundleId,
        info: turbo.info,
        rawTurbo: turbo.raw,
      };
    }

    // (b) Turbo が知らない (404) → 古い tx or Turbo 障害 → gateway/GraphQL で fallback
    if (!turbo?.accepted) {
      const [probe, gql] = await Promise.all([
        _probeDataReachable(txid).catch(() => ({ arweave: false, turbo: false })),
        _queryTxStatusGraphQL(txid).catch(() => null),
      ]);
      if (probe.arweave || gql?.state === "confirmed") {
        return {
          state: "confirmed",
          via: probe.arweave ? "https://arweave.net" : (gql?.via ?? "graphql"),
          blockHeight: gql?.blockHeight ?? null,
          blockIndepHash: gql?.blockIndepHash ?? null,
          confirmations: gql?.confirmations ?? null,
          bundleId: gql?.bundleId,
        };
      }
      if (probe.turbo || gql?.state === "bundling") {
        return {
          state: "bundling",
          via: probe.turbo ? "https://turbo-gateway.com" : (gql?.via ?? "graphql"),
          bundleId: gql?.bundleId,
        };
      }
      return { state: "not_found" };
    }

    // (c) Turbo accepted + bundleId なし → 通常は not_found 確定 (= 「Turbo 受領未配信」)
    //     arweave.net 叩いても 100% 404 なので発火しない (パフォーマンス最適化)。
    //     ただし forceProbe (= 手動再確認) なら念のため両方叩く。
    if (!turbo.bundleId) {
      if (forceProbe) {
        const [probe, gql] = await Promise.all([
          _probeDataReachable(txid).catch(() => ({ arweave: false, turbo: false })),
          _queryTxStatusGraphQL(txid).catch(() => null),
        ]);
        if (probe.arweave || gql?.state === "confirmed") {
          return {
            state: "confirmed",
            via: probe.arweave ? "https://arweave.net" : (gql?.via ?? "graphql"),
            bundleId: gql?.bundleId,
            info: turbo.info,
            blockHeight: gql?.blockHeight ?? null,
            blockIndepHash: gql?.blockIndepHash ?? null,
            confirmations: gql?.confirmations ?? null,
            rawTurbo: turbo.raw,
          };
        }
        if (probe.turbo || gql?.state === "bundling") {
          return {
            state: "bundling",
            via: probe.turbo ? "https://turbo-gateway.com" : (gql?.via ?? "graphql"),
            bundleId: gql?.bundleId,
            info: turbo.info,
            rawTurbo: turbo.raw,
          };
        }
      }
      return {
        state: "not_found",
        info: turbo.info,
        rawTurbo: turbo.raw,
        note: `Turbo 受領済み (info=${turbo.info ?? "?"})、bundle 化を待っています`,
      };
    }

    // (d) Turbo accepted + bundleId 有 → arweave.net + GraphQL 並列で確認
    const [probe, gql] = await Promise.all([
      _probeDataReachable(txid).catch(() => ({ arweave: false, turbo: false })),
      _queryTxStatusGraphQL(txid).catch(() => null),
    ]);

    // arweave.net 200 → confirmed
    if (probe.arweave || gql?.state === "confirmed") {
      return {
        state: "confirmed",
        via: probe.arweave ? "https://arweave.net" : (gql?.via ?? "graphql"),
        bundleId: turbo.bundleId,
        info: turbo.info,
        blockHeight: gql?.blockHeight ?? null,
        blockIndepHash: gql?.blockIndepHash ?? null,
        confirmations: gql?.confirmations ?? null,
        rawTurbo: turbo.raw,
      };
    }

    // arweave.net 未反映 → bundling (turbo-gateway で取れるはず)
    return {
      state: "bundling",
      via: probe.turbo ? "https://turbo-gateway.com" : "turbo-status",
      bundleId: turbo.bundleId,
      info: turbo.info,
      rawTurbo: turbo.raw,
      note: `bundle ${turbo.bundleId.slice(0, 8)}... に格納済み (Turbo 配信中)`,
    };
  } catch (e) {
    return { state: "error", message: e?.message ?? String(e) };
  }
}
