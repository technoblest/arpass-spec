// ============================================================================
// web/lib/client-auth-v5.js
//
// Arpass v5 用 identity / API 認証 / Arweave 読み書きレイヤ。
//
// docs/crypto-2of3.md v5 に従い、以下の方針で実装:
//   - Outer key / 外側 AES-GCM 鍵をサーバには一切送らない
//   - 認証は X-Public-Key + X-Signature + X-Timestamp の 3 ヘッダ
//   - 署名鍵は localStorage に永続化しない (vault-client-v5 が MEK から派生して
//     都度 importSigningKeyPair、本モジュールは渡された CryptoKey で署名)
//   - localStorage には軽量メタ (outerKey, App-Name タグ name+value, credIdHash) のみ
//   - Arweave 読み書きは外側 AES-GCM 層を経由 (HKDF(rMat) で wrap/unwrap、Phase 7.0w-AR)
// ============================================================================

import {
  signRequest,
  unwrapEnvelopeOuter,
  wrapEnvelopeOuter,
  b64uEncode,
  b64uDecode,
} from "/lib/vault-crypto.js?v=11331c7d";

import {
  getEnvelopeCache,
  setEnvelopeCache,
  deleteEnvelopeCache,
} from "./local-cache.js";

// ---------------------------------------------------------------------------
// localStorage キー (v5)
// ---------------------------------------------------------------------------

// v5 では「identity」概念が消え、代わりに復号後派生の publicKey を使う。
// localStorage に永続化するのは outerKey (外側 AES-GCM 鍵、rMat 直接派生、Phase 7.0w-AR) と App-Name タグ
// 種) と関連メタのみ。
//
// Phase 7.1-W: META_KEY は profile-aware に置換。
// 各 profile (個人 / 会社 / 別会社) ごとに独立 localStorage namespace を持つ:
//   arpass_vault_meta_v5__<profileId>
// 個別 profile が active な時のみ readMeta/writeMeta が動く。
// no active profile (picker 表示中) では readMeta() は null を返す。
import { activeMetaKey } from "/lib/profiles.js?v=5ef6de24";

const ARWEAVE_GATEWAY = "https://arweave.net";
const TURBO_GATEWAY = "https://turbo-gateway.com";
const FETCH_TIMEOUT_MS = 30000;  // Turbo gateway 経由は遅い時 ~3s、長めに余裕
const GRAPHQL_TIMEOUT_MS = 5000;

// ---------------------------------------------------------------------------
// Meta (localStorage)
// ---------------------------------------------------------------------------

/**
 * localStorage メタ (envelope v7 / 2026-05-24 で outerKey を撤去):
 *   {
 *     appNameTag:  { name: "<11 chars>", value: "<22 chars>" },  // 両方 rMat 派生、秘密ではない
 *     currentAppNameTag: { name, value } | null,
 *     credIdHash:  "<16-char base64url, this device's Passkey>",
 *     credentialId:"<base64url WebAuthn raw credential id>",
 *     publicKeyHash: "<22-char H(publicKey)>",
 *     latestTxId:  "<arweave txid>"  // performance hint, NOT authoritative
 *   }
 * outer 鍵 (秘密) は localStorage に保存しない。Passkey の WebAuthn user.id に
 *   Master でラップして格納し、解錠時に user.id から取り出す (envelope-v7-spec.md)。
 *   meta に残るのは vault 所在タグと UX/性能ヒントのみで、秘密値は含まない。
 */
export function readMeta() {
  const k = activeMetaKey();
  if (!k) return null;  // no active profile
  try { return JSON.parse(localStorage.getItem(k) || "null"); }
  catch { return null; }
}
export function writeMeta(meta) {
  const k = activeMetaKey();
  if (!k) throw new Error("[client-auth] writeMeta called without active profile");
  localStorage.setItem(k, JSON.stringify(meta));
}
export function patchMeta(patch) {
  const cur = readMeta() || {};
  writeMeta({ ...cur, ...patch });
}
export function clearMeta() {
  const k = activeMetaKey();
  if (k) localStorage.removeItem(k);
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
 *
 * Phase 6.7-3: 第 2 引数で Cloudflare Turnstile token を渡せる。production で
 * TURNSTILE_SECRET_KEY が設定されていれば server 側で検証され、無効なら 403。
 * dev/staging で env 未設定の場合は server 側で skip される。
 */
export async function registerVault(publicKeyRaw, captchaToken = null) {
  const body = captchaToken ? { "cf-turnstile-response": captchaToken } : {};
  const r = await fetch("/api/vault/register", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Public-Key": b64uEncode(publicKeyRaw),
    },
    body: JSON.stringify(body),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) {
    if (j?.code === "captcha_failed") {
      throw new Error("Captcha verification failed. Please refresh and try again.");
    }
    throw new Error(`register failed: ${j.error || r.status}`);
  }
  return j;  // { ok, credits, alreadyRegistered?, captchaSkipped? }
}

/**
 * /api/balance — 残高取得 (旧 GET /api/vault/:userId の置換)。
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
  const r = await signedFetch("/api/vault/migrate", "POST", body, oldSigningState);
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
 * @param {Uint8Array} outerKeyBytes  32-byte raw AES-GCM key (deriveOuterKeyBytes(rMat))
 * @param {object} [options]
 *   bundlerBase: ペンディング bundler の URL (任意 fallback)
 * @returns {Promise<{ envelope: object, source: "turbo"|"arweave"|"bundler-pending" }>}
 */
export async function fetchEnvelope(txid, outerKeyBytes, options = {}) {
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
    const envelope = await unwrapEnvelopeOuter(cached, outerKeyBytes);
    return { envelope, source: "local-cache" };
  }
  // cache miss — network を待つしかない
  const blob = await readBlobWithFallback(txid, options);
  const envelope = await unwrapEnvelopeOuter(new Uint8Array(blob.body), outerKeyBytes);
  return { envelope, source: blob.source };
}

/**
 * raw blob を Arweave (Turbo + arweave.net 並列) または bundler から取得。
 * 並列化 + 個別 timeout — 直近 hotfix 済みパターンを踏襲。
 */
async function readBlobWithFallback(txid, options = {}) {
  // Phase 7.2-B v2.6 hotfix: /api/arweave/<txid> を最優先 (= same-origin server proxy、
  //   CORS 問題なし、 server-side で Turbo + arweave.net 並列 fetch)。
  //   外部 gateway 直叩きは fallback として残す (= proxy 障害時の保険)。
  // Phase 7.5h: turbo-gateway 直叩きを削除 (常に CORS で失敗していたため noise だけ)。
  //   /api/arweave proxy が server-side で Turbo + arweave.net を並列叩きするので
  //   同じデータが取れる。 arweave.net 直叩きは CORS OK で確定後 tx の保険。
  const candidates = [
    { name: "proxy", url: `/api/arweave/${txid}` },
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
 * Phase 7.0w-AR: タグは {name, value} オブジェクト (両方 rMat 派生のランダム文字列)。
 *
 * @param {{name: string, value: string}} appNameTag
 * @returns {Promise<string|null>}
 */
/**
 * Phase 7.2-B (α): server 権威の latest vault txid を取得 (認証不要)。
 * @param {string} appNameTagValue  appNameTag の value (= b64u 22 chars)
 * @returns {Promise<{ txid: string, pkHash: string }|null>}
 */
export async function fetchServerVaultLatest(appNameTagValue) {
  if (!appNameTagValue) return null;
  try {
    const r = await fetch(`/api/vault/latest?app=${encodeURIComponent(appNameTagValue)}`);
    if (!r.ok) return null;
    const j = await r.json();
    if (!j.ok || !j.txid) return null;
    return { txid: j.txid, pkHash: j.pkHash };
  } catch { return null; }
}

/**
 * Phase 7.2-B v2.6: pkHash 直 lookup で account.vaultSlots を取得。
 * unlock 時 (= 未認証) に Recovery → rMat → 派生 pkHash を使って 1 回問合せで
 * tier ごとの appName + txid を全て取得する。
 *
 * @param {string} pkHash - b64u pkHash (= SHA256(signingPubkey) を 22 chars に丸めたもの)
 * @returns {Promise<{ free, paid, corp, priority }|null>}
 */
export async function fetchServerVaultSlots(pkHash) {
  if (!pkHash) return null;
  try {
    const r = await fetch(`/api/vault/latest?pk=${encodeURIComponent(pkHash)}`);
    if (!r.ok) return null;
    const j = await r.json();
    if (!j.ok || !j.slots) return null;
    return {
      free: j.slots.free || null,
      paid: j.slots.paid || null,
      corp: j.slots.corp || null,
      priority: j.priority || null,
    };
  } catch { return null; }
}

export async function findLatestVaultTx(appNameTag) {
  if (!appNameTag?.name || !appNameTag?.value) return null;
  // GraphQL の tag name は識別子用文字種制限がない (Arweave 規格)。安全のため b64url 文字 + - _ のみ許容。
  const safeName = String(appNameTag.name).replace(/[^A-Za-z0-9_-]/g, "");
  const safeVal = String(appNameTag.value).replace(/[^A-Za-z0-9_-]/g, "");
  if (!safeName || !safeVal) return null;
  const query = `
    query {
      transactions(
        tags: [{ name: "${safeName}", values: ["${safeVal}"] }]
        sort: HEIGHT_DESC
        first: 1
      ) {
        edges { node { id } }
      }
    }
  `;

  // Phase 7.5k: /api/arweave-graphql proxy を経由 (= server-side で Turbo + arweave 並列)。
  //   client から turbo-gateway 直叩きは CORS で失敗するため。 これにより hwkey 作成
  //   直後 (Turbo bundling 中) の keyslot blob 検索も成功する。
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), GRAPHQL_TIMEOUT_MS);
  try {
    const resp = await fetch(`/api/arweave-graphql`, {
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


/**
 * Phase 6.4: 複数 App-Name で並列検索し、最新 (block height 最大) の tx を返す。
 * Tier 移行 (free→paid→private→corp::id) や legacy 後方互換のため。
 *
 * Phase 7.0w-AR: 各 tag は {name,value}。同 rMat の tier 違いでも tag name 自体が
 *   異なるので、GraphQL は **複数 tag 条件の OR** ではなく **個別 query を並列発火**
 *   して結果をマージする (Arweave GraphQL は単一 query 内で異なる tag name 並列を
 *   サポートするが、サポート粒度の差を避けるため per-tag 並列で確実に揃える)。
 *
 * @param {{name:string,value:string}[]} appNameTags
 * @returns {Promise<{ txid: string, appName: {name,value}, height: number } | null>}
 */
export async function findLatestVaultTxAcrossTiers(appNameTags) {
  // 正規化: name と value が揃った tag のみ採用、重複 (name+value) 排除
  const seen = new Set();
  const tags = [];
  for (const t of appNameTags || []) {
    if (!t?.name || !t?.value) continue;
    const k = `${t.name}\x00${t.value}`;
    if (seen.has(k)) continue;
    seen.add(k);
    tags.push({ name: String(t.name), value: String(t.value) });
  }
  if (tags.length === 0) return null;

  // 各 tag は b64url 文字種限定 (rMat 派生の HKDF 出力なので保証されているが防御的に sanitize)
  function safe(x) { return String(x).replace(/[^A-Za-z0-9_-]/g, ""); }

  function queryFor(tag) {
    return `
      query {
        transactions(
          tags: [{ name: "${safe(tag.name)}", values: ["${safe(tag.value)}"] }]
          sort: HEIGHT_DESC
          first: 5
        ) {
          edges {
            node {
              id
              tags { name value }
              block { height }
            }
          }
        }
      }
    `;
  }

  async function queryViaProxy(tag) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), GRAPHQL_TIMEOUT_MS);
    try {
      const resp = await fetch(`/api/arweave-graphql`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: queryFor(tag) }),
        signal: ctrl.signal,
      });
      clearTimeout(timer);
      if (!resp.ok) return [];
      const data = await resp.json();
      return (data?.data?.transactions?.edges ?? []).map(e => ({ node: e.node, tag }));
    } catch {
      clearTimeout(timer);
      return [];
    }
  }

  // Phase 7.5k: /api/arweave-graphql proxy 経由で並列発火 (= server side で Turbo +
  //   arweave 並列、 bundling 中の tx も発見可能)。
  const jobs = [];
  for (const tag of tags) {
    jobs.push(queryViaProxy(tag));
  }
  const results = (await Promise.all(jobs)).flat();
  if (results.length === 0) return null;

  // Phase 7.2-B (α): 全候補を sorted list で返す。 caller (unlock 経路) は順番に試して
  //   fetchable + outer 復号成功なものを採用する。 phantom tx (= unfetchable / 中身古い)
  //   をスキップして次の candidate に進める。
  const allCandidates = [];
  const seenTxIds = new Set();
  for (const { node, tag } of results) {
    const hit = node.tags?.find(t => t.name === tag.name && t.value === tag.value);
    if (!hit) continue;
    if (seenTxIds.has(node.id)) continue;
    seenTxIds.add(node.id);
    const h = node.block?.height ?? Number.MAX_SAFE_INTEGER;
    allCandidates.push({ txid: node.id, appName: tag, height: h });
  }
  // height DESC でソート (unfinalized = MAX_SAFE_INTEGER は先頭)
  allCandidates.sort((a, b) => b.height - a.height);
  if (allCandidates.length === 0) return null;
  // 後方互換のため、 top 候補を {txid, appName, height} で返す + candidates も付与
  return { ...allCandidates[0], candidates: allCandidates };
}

// ---------------------------------------------------------------------------
// Arweave 書き込み (サーバ API /api/write 経由)
// ---------------------------------------------------------------------------

/**
 * envelope を 外側 AES-GCM で wrap → /api/write に POST → Arweave に書き込み。
 * /api/write はサーバが Arweave bundler に submit する経路。本クライアントから
 * 直接 Arweave に書くことはない (credit 課金とサーバ側の認証が必要なため)。
 *
 * @param {object} envelope               v5 内側 envelope
 * @param {Uint8Array} outerKeyBytes      外側 AES-GCM 鍵 (32 byte, rMat 直接派生)
 * @param {{name:string,value:string}} appNameTag  Arweave タグ (両方 rMat 派生)
 * @param {object} signingState
 * @returns {Promise<object>}             サーバの { ok, txid, credits, ... }
 */
export async function writeEnvelope(envelope, outerKeyBytes, appNameTag, signingState, options = {}) {
  if (!appNameTag?.name || !appNameTag?.value) {
    throw new Error("writeEnvelope: appNameTag must be {name, value}");
  }
  const blob = await wrapEnvelopeOuter(envelope, outerKeyBytes);
  const dataB64u = b64uEncode(blob);
  const body = {
    data: dataB64u,
    encoding: "base64url",                  // サーバが decode する目印
    contentType: "application/octet-stream", // Arweave タグ Content-Type
    // Phase 7.0w-AR: tag name もランダム化 (固定 "App-Name" 廃止)
    tags: { [appNameTag.name]: appNameTag.value },
    kind: "vault",                          // server-only 分類 (Arweave には乗らない)
  };
  // Phase 7.2-B v2.6: tier 申告 (= account.vaultSlots を正しい slot に更新するため)。
  //   server は嘘を弾く (corp 申告で会社員でなければ slot 更新せず log のみ)。
  //   options.tier 未指定なら server 側で free 扱いになる (= 無料層 default)。
  if (typeof options.tier === "string") {
    body.tier = options.tier;
  }
  // Phase 7.2-B/D hotfix (2026-06-05): initial corp signup の atomic 化。
  //   createVault 経路で _inviteCode あれば server に渡す。 server 側で
  //   未 member の場合は joinViaCode で先に MEMBER_KEY 登録、 通常 gate
  //   に合流。 詳細は functions/api/write.js の Phase 7.2-B/D hotfix コメント。
  if (typeof options.inviteCode === "string" && options.inviteCode) {
    body.inviteCode = options.inviteCode;
  }
  // Phase 5.3 楽観ロック: client が知っている直前の latestTxId を server に送り、
  // server 側 KV と異なれば 409 version_conflict を返してもらう。複数端末同時編集
  // による lost-update を防ぐ。options.expectedLatestTxId === undefined のときは
  // 送信しない (= 楽観ロック非適用、初回 createVault 経路など)。
  if (options.expectedLatestTxId !== undefined) {
    body.expectedLatestTxId = options.expectedLatestTxId;
  }
  if (options.forceOverwrite === true) {
    body.forceOverwrite = true;  // Phase 7.1-N.3: server-side optimistic lock を bypass
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
// Phase 7.0e: writeRecordFile — Records (電子書類) のファイル本体を Arweave に書く
//
// vault envelope と異なり「outer wrap」なし。BEK 暗号化済みの ciphertext を
// そのまま Arweave に保存する。tag は識別用に Arpass-Rec-* を使う。
//
// 呼び出し側 (vault-client.js addRecord) は:
//   1. file → BEK encrypt → ciphertext
//   2. wrapKey(MEK, BEK) → wrappedBEK (vault に保存する)
//   3. writeRecordFile(ciphertext, signingState) → txid
//   4. vault.records.active に push (txId + wrappedBEK)
//
// 戻り値: { ok, txid, credits, size_bytes, ... } (writeEnvelope と同じ shape)
// ===========================================================================
export async function writeRecordFile(ciphertext, signingState) {
  const dataB64u = b64uEncode(ciphertext);
  // Phase 7.0e + 7.0w-AR: tag は name / value 両方 random 化。
  // vault envelope の deriveAppNameTag (rMat 派生) とは独立 — record file は単発 immutable で
  // GraphQL discovery 不要 (vault に txid を直接保存)。観測者から「Arpass の record file」と
  // 識別される手がかりを完全に消すため、tag name も per-write random にする。
  const randomTagName  = b64uEncode(crypto.getRandomValues(new Uint8Array(8)));
  const randomTagValue = b64uEncode(crypto.getRandomValues(new Uint8Array(16)));
  const body = {
    data: dataB64u,
    encoding: "base64url",
    contentType: "application/octet-stream",
    tags: { [randomTagName]: randomTagValue },
    kind: "record",  // server-only 分類 (Arweave tag には現れない)
  };
  const r = await signedFetch("/api/write", "POST", body, signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) {
    const err = new Error(j.error || `record file write failed: HTTP ${r.status}`);
    err.code = j.code;
    err.status = r.status;
    throw err;
  }
  return j;
}

/**
 * Phase 7.0e: Arweave 上の record file を取得 (BEK 復号は vault-client 側で行う)。
 * 単純に txid → encrypted ciphertext bytes を返す。
 */
/**
 * Phase 7.0e: Records ファイル本体を gateway から取得 (encrypted ciphertext のまま)。
 *
 * 重要な設計:
 *   - ローカルキャッシュは持たない (server / 別端末から同じ txid で取得可能)
 *   - Turbo gateway を **優先** (受領直後から配信可能、Arweave L1 確定前から read OK)
 *   - arweave.net は L1 確定後の fallback (Turbo 障害時 / 古い tx)
 *
 * Turbo の value prop:
 *   - 受領 = 即時配信可能 (= 書き込み直後に detail modal で preview できる理由)
 *   - bundle = Arweave L1 への決定論的コミット (5-30 分後)
 *   この 2 段階により「書き込み即読める + 永続性保証」を両立。
 */
export async function fetchRecordFileBytes(txid) {
  // Phase 7.5h: /api/arweave proxy 経由で取得 (= server-side で Turbo + arweave +
  //   upload-ardrive を並列叩く)。 turbo-gateway.com 直叩きは CORS で失敗。
  //   arweave.net 直叩きは Turbo 期間中の tx を取れない。 proxy が良いとこ取り。
  //
  //   error message 改善 (2026-06-05): proxy が 404 を返す = 3 gateway 全部 404 を
  //   既に試行済 (= turbo + arweave + upload-ardrive) なので、 arweave.net 直叩き
  //   fallback は redundant。 proxy 200 失敗 + non-404 (= proxy 落ち or 5xx) の時
  //   のみ arweave.net 直叩き保険を試す。
  //
  //   Turbo hot storage 期待と実態の drift については memory:
  //   project_arpass_turbo_hot_storage_drift.md 参照。
  const proxyUrl = `/api/arweave/${encodeURIComponent(txid)}`;
  try {
    const r = await fetch(proxyUrl, { method: "GET" });
    if (r.ok) {
      const buf = await r.arrayBuffer();
      return new Uint8Array(buf);
    }
    if (r.status === 404) {
      // proxy が全 gateway 404 を確認済 (= turbo + arweave + upload-ardrive)
      throw new Error(`record file not yet available on any Arweave gateway (Turbo + arweave.net + upload.ardrive.io tried via proxy); tx=${txid}`);
    }
    // 5xx / その他 → proxy 自体の問題、 保険で arweave.net 直叩き
    console.warn(`[fetchRecordFileBytes] proxy returned ${r.status}, falling back to arweave.net direct`);
  } catch (e) {
    if (e?.message?.includes("not yet available")) throw e;
    console.warn(`[fetchRecordFileBytes] proxy unreachable (${e?.message ?? e}), falling back to arweave.net direct`);
  }
  // 保険: proxy 落ち時 のみ arweave.net 直叩き
  const fallbackUrl = `${ARWEAVE_GATEWAY}/${encodeURIComponent(txid)}`;
  const r2 = await fetch(fallbackUrl, { method: "GET" });
  if (r2.ok) {
    const buf = await r2.arrayBuffer();
    return new Uint8Array(buf);
  }
  throw new Error(`record file fetch failed (proxy + arweave.net direct both failed); arweave.net status=${r2.status}; tx=${txid}`);
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
  async function askProxy() {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), _GRAPHQL_TIMEOUT_MS);
    try {
      const r = await fetch(`/api/arweave-graphql`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query }),
        signal: ctrl.signal,
      });
      clearTimeout(timer);
      if (!r.ok) {
        const body = await r.text().catch(() => "(no body)");
        console.warn(`[getTxStatus] proxy returned ${r.status}: ${body.slice(0, 300)}`);
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
  // Phase 7.5k: /api/arweave-graphql proxy 経由 (= server-side Turbo + arweave 並列)
  const turbo = null;  // legacy 互換 (下流の if 分岐は skip される)
  const arw = await askProxy();
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
  // Phase 7.5h: turbo branch は CORS により null 固定なので dead code 削除。
  //   arw.bundledIn.id があれば bundling 中と判定 (= Turbo bundle ID は arweave.net
  //   GraphQL でも返るので情報は失われない)。
  if (arw?.bundledIn?.id) {
    return {
      state: "bundling",
      via: "arweave-graphql",
      bundleId: arw.bundledIn.id,
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
  // Phase 7.5h: turbo 直叩き削除 (CORS で常に失敗)。 proxy 経由で Turbo + arweave を
  //   server-side 並列実行するので、 turbo の到達は proxy 200 で代理判定する。
  const candidates = [
    { name: "proxy", base: "/api/arweave" },
    { name: "arweave", base: ARWEAVE_GATEWAY },
  ];
  const result = { arweave: false, proxy: false };
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
          via: probe.proxy ? "/api/arweave (Turbo+arweave proxy)" : (gql?.via ?? "graphql"),
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
            via: probe.proxy ? "/api/arweave (Turbo+arweave proxy)" : (gql?.via ?? "graphql"),
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
      via: probe.proxy ? "/api/arweave (Turbo+arweave proxy)" : "turbo-status",
      bundleId: turbo.bundleId,
      info: turbo.info,
      rawTurbo: turbo.raw,
      note: `bundle ${turbo.bundleId.slice(0, 8)}... に格納済み (Turbo 配信中)`,
    };
  } catch (e) {
    return { state: "error", message: e?.message ?? String(e) };
  }
}


// ===========================================================================
// envelope v7 増分2 — hwkey モードの keyslot blob 入出力
//   keyslot blob (encodeKeyslot 済 = 既に暗号化) を Arweave に書く / 読む。
//   外層 wrap なし、指定タグ (= user.id に焼く所在タグ)。write-once なので
//   GraphQL (findLatestVaultTx) で発見する。kind:"record" で書くため vault の
//   tier slot は更新されない。
// ===========================================================================

/**
 * keyslot blob を Arweave に書く。
 * @param {Uint8Array} keyslotBlob   encodeKeyslot の出力
 * @param {{name:string,value:string}} keyslotTag  この keyslot の所在タグ
 * @param {object} signingState
 * @returns {Promise<{ok:boolean, txid:string}>}
 */
export async function writeKeyslot(keyslotBlob, keyslotTag, signingState) {
  if (!keyslotTag?.name || !keyslotTag?.value)
    throw new Error("writeKeyslot: keyslotTag must be {name, value}");
  const body = {
    data: b64uEncode(keyslotBlob),
    encoding: "base64url",
    contentType: "application/octet-stream",
    tags: { [keyslotTag.name]: keyslotTag.value },
    // Phase 7.5N: server に keyslot として識別させ KV 索引 (ks:<name>:<value>) に記録させる
    kind: "keyslot",
  };
  const r = await signedFetch("/api/write", "POST", body, signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) {
    const err = new Error(j.error || `keyslot write failed: HTTP ${r.status}`);
    err.code = j.code;
    err.status = r.status;
    throw err;
  }
  return j;  // { ok, txid, ... }
}

/**
 * keyslot blob を txid から取得 (生バイト、外層 wrap 無し)。
 * @param {string} txid
 * @returns {Promise<Uint8Array>}
 */
export async function fetchKeyslotBlob(txid) {
  const blob = await readBlobWithFallback(txid);
  return new Uint8Array(blob.body);
}

/**
 * keyslot tag → txid を server KV から即時取得 (= Phase 7.5N 索引)。
 *
 * 通常モードの /api/vault/latest?pk= と同じ目的: 公開 GraphQL の indexing
 * lag を回避し、 作成直後の unlock を即時化する。 我々の KV に書込時に
 * 索引した値を引くだけ (= 同期遅延ゼロ)。
 *
 * 索引が無い場合は null を返す。 caller は GraphQL fallback すること
 * (= 古い keyslot や、 KV から消失した場合の救済路)。
 *
 * @param {{name:string,value:string}} keyslotTag
 * @returns {Promise<string|null>} txid or null
 */
export async function lookupKeyslotTxid(keyslotTag) {
  if (!keyslotTag?.name || !keyslotTag?.value) return null;
  try {
    const qs = new URLSearchParams({
      name: keyslotTag.name,
      value: keyslotTag.value,
    });
    const r = await fetch(`/api/keyslot/latest?${qs.toString()}`, {
      method: "GET",
      headers: { "Accept": "application/json" },
    });
    if (r.status === 404) return null;
    if (!r.ok) return null;
    const j = await r.json().catch(() => null);
    if (j?.ok && typeof j.txid === "string" && j.txid.length > 0) {
      return j.txid;
    }
    return null;
  } catch {
    return null;
  }
}
