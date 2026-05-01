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

// ---------------------------------------------------------------------------
// localStorage キー (v5)
// ---------------------------------------------------------------------------

// v5 では「identity」概念が消え、代わりに復号後派生の publicKey を使う。
// localStorage に永続化するのは vault-id (= Arweave 検索キー、外側暗号鍵の
// 種) と関連メタのみ。
const META_KEY = "arpass_vault_meta_v5";

const ARWEAVE_GATEWAY = "https://arweave.net";
const TURBO_GATEWAY = "https://turbo-gateway.com";
const FETCH_TIMEOUT_MS = 8000;
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
export async function writeEnvelope(envelope, vaultId, appNameTag, signingState) {
  const blob = await wrapEnvelopeOuter(envelope, vaultId);
  const dataB64u = b64uEncode(blob);
  const body = {
    data: dataB64u,
    encoding: "base64url",                  // サーバが decode する目印
    contentType: "application/octet-stream", // Arweave タグ Content-Type
    tags: { "App-Name": appNameTag },        // クライアントが指定可能なのは App-Name のみ
  };
  const r = await signedFetch("/api/write", "POST", body, signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) throw new Error(`write failed: ${j.error || r.status}`);
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

async function _probeDataReachable(txid) {
  const candidates = [
    { name: "turbo", base: TURBO_GATEWAY },
    { name: "arweave", base: ARWEAVE_GATEWAY },
  ];
  return await new Promise((resolve) => {
    let pending = candidates.length;
    for (const { name, base } of candidates) {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), _PROBE_TIMEOUT_MS);
      fetch(`${base}/${txid}`, {
        method: "GET",
        headers: { Range: "bytes=0-0" },
        cache: "no-store",
        redirect: "follow",
        signal: ctrl.signal,
      })
        .then((r) => {
          clearTimeout(timer);
          if (r.ok || r.status === 206) resolve(base);
          else if (--pending === 0) resolve(null);
        })
        .catch(() => {
          clearTimeout(timer);
          if (--pending === 0) resolve(null);
        });
    }
  });
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
export async function getTxStatus(txid) {
  if (!txid || typeof txid !== "string") {
    return { state: "error", message: "invalid txid" };
  }
  try {
    // 1) GraphQL で確定 / bundling 情報を取りに行く
    const gql = await _queryTxStatusGraphQL(txid);
    if (gql) return gql;

    // 2) /tx/{id}/status (L1) — direct-mainnet write 経路をカバー
    const r = await fetch(`${ARWEAVE_GATEWAY}/tx/${txid}/status`, { cache: "no-store" });
    if (r.status === 404) {
      // L1 知らない → CDN reachability を probe
      const reachable = await _probeDataReachable(txid);
      if (reachable) return { state: "bundling", via: reachable };
      return { state: "not_found" };
    }
    if (r.status === 429) {
      const ra = r.headers.get("retry-after");
      const sec = ra ? Math.max(1, parseInt(ra, 10) || 60) : 60;
      return { state: "rate_limited", retryAfterSeconds: sec };
    }
    if (r.status === 200 || r.status === 202) {
      const text = (await r.text()).trim();
      if (text === "Pending" || text === "pending") return { state: "pending" };
      try {
        const body = JSON.parse(text);
        return {
          state: "confirmed",
          confirmations: body.number_of_confirmations ?? 0,
          blockHeight: body.block_height ?? null,
          blockIndepHash: body.block_indep_hash ?? null,
        };
      } catch {
        return { state: "pending" };
      }
    }
    return { state: "error", httpStatus: r.status };
  } catch (e) {
    return { state: "error", message: e?.message ?? String(e) };
  }
}
