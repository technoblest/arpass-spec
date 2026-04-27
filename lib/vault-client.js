// ============================================================================
// Arpass — Vault loader / saver
// ----------------------------------------------------------------------------
// Bridges the authenticated API (client-auth.js) with the encryption layer
// (vault-crypto.js), and knows how to find the latest vault version on
// Arweave via GraphQL tag-search.
//
//   loadLatestVault(password) →  { vault, latestTxId } | throws
//   saveVault(vault, password)  →  { txid, vault }
//   createVault(password)       →  { vault, txid } // first-ever save
// ============================================================================

import {
  hasClientIdentity,
  readClientIdentity,
  generateKeypairAndRegister,
  restoreIdentityFromRecovery,
  signedFetch,
  readWithFallback,
} from "./client-auth.js";
import {
  encryptVault,
  decryptVault,
  b64uDecode,
  authenticateWithPasskey,
  registerPasskey,
  isPasskeySupported,
  isSecureContextOk,
  // v2 (2-of-3) additions:
  generateRecoverySecret,
  recoverySecretToMaterial,
  encryptVaultV2,
  decryptVaultV2,
  reEncryptVaultV2,
  rewrapVaultV2,
  changePasswordV2,
  changePasskeyV2,
  changeRecoveryV2,
  deriveIdentityKeypair,
  deriveVaultIdFromPublicJwk,
  VAULT_FORMAT_V2,
  ALG_2OF3_V1,
  // v3 (multi-device) additions:
  encryptVaultV3,
  decryptVaultV3,
  reEncryptVaultV3,
  addDeviceV3,
  removeDeviceV3,
  renameDeviceV3,
  changePasswordV3,
  changeRecoveryV3,
  migrateV2ToV3,
  generateDeviceId,
  defaultDeviceName,
  VAULT_FORMAT_V3,
  ALG_2OF3_V2,
  // v4 (padded + tag-anonymized) additions:
  encryptVaultV4,
  decryptVaultV4,
  reEncryptVaultV4,
  migrateV3ToV4,
  addDeviceV4,
  removeDeviceV4,
  renameDeviceV4,
  changePasswordV4,
  deriveAppNameTag,
  VAULT_FORMAT_V4,
} from "./vault-crypto.js";

// Module-level in-memory cache of the current session's K_vault (v2). Held
// between a successful unlock and the user locking / closing the tab, so that
// subsequent saves can rotate only the outer ciphertext without re-prompting
// every factor.
let _currentKVault = null;
let _currentEnvelope = null; // the envelope we unlocked from, for wrap re-use on save

/**
 * Build an Error from a non-OK /api/write JSON response, carrying through
 * the server's `code` and (when present) `credits` fields so the UI can
 * branch on 402 / insufficient_credits without parsing the message.
 */
function writeError(result, fallbackMessage = "write failed") {
  const err = new Error(result?.error ?? fallbackMessage);
  if (result?.code) err.code = result.code;
  if (result && "credits" in result) err.credits = result.credits;
  return err;
}

const ARWEAVE_GATEWAY = "https://arweave.net";

// Turbo's own gateway indexes data-items as soon as they're submitted —
// without waiting for the bundle to confirm on Arweave L1. arweave.net's
// GraphQL lags 5-15 minutes behind, which would make multi-device "I just
// saved on my phone, why doesn't my laptop see it?" miserable.
//
// Strategy in findLatestVaultTx: query Turbo first; fall back to arweave.net
// if Turbo doesn't know about the tx (e.g., it was posted via direct
// mainnet, not via Turbo, or Turbo's index is temporarily unavailable).
const TURBO_GATEWAY = "https://turbo-gateway.com";

const VAULT_ID_TAG = "vault-id";
const APP_NAME_TAG = "App-Name";
// Legacy default, used for v1/v2/v3 envelopes and as a fallback when this
// device doesn't yet know the user's per-user anonymized tag value (e.g. a
// fresh install on a device that hasn't run Recovery-based restoration).
const LEGACY_APP_NAME = "Arpass-Vault";

/**
 * Returns the App-Name tag value this device should use when querying
 * Arweave / writing new envelopes. Per-user anonymized values are derived
 * from the Recovery Secret material and cached in localStorage meta the
 * moment they're first known. Returns the legacy "Arpass-Vault" string for
 * users who have not yet upgraded to a v4 + per-user tag envelope.
 */
function currentAppNameTag() {
  return readMeta()?.appNameTag ?? LEGACY_APP_NAME;
}

// Cache: vault salt + latest tx id + passkey credentialId, so we don't have
// to GraphQL on every load or re-register the Passkey on every login.
const CACHE_KEY = "arpass_vault_meta_v1";

// How many recent envelopes the picker fetches when resolving "latest".
// Trade-off: GraphQL HEIGHT_DESC is unreliable for pending Turbo bundles
// (multiple block.height=null entries return in arbitrary order), so we
// can't trust just the top hit. Empirically there are rarely more than
// 1–2 truly concurrent pending writes per vault — 3 is a safe margin
// without the latency cost of fetching 10.
const PICKER_LIMIT = 3;

function readMeta() {
  try { return JSON.parse(localStorage.getItem(CACHE_KEY) ?? "null"); }
  catch { return null; }
}
function writeMeta(patch) {
  const current = readMeta() ?? {};
  // Scrub legacy envelope-cache fields. Earlier versions stored the entire
  // decrypted envelope in localStorage to bridge arweave.net's propagation
  // window; that's no longer needed (we go to Turbo gateway directly on
  // every load) and the lingering data caused stale-state bugs after
  // a buggy restore-from-Recovery wrote an empty addDevice envelope.
  delete current.cachedEnvelope;
  delete current.savedAt;
  localStorage.setItem(CACHE_KEY, JSON.stringify({ ...current, ...patch }));
}

/** Returns the Passkey credentialId stored locally, or null. */
export function getPasskeyCredentialId() {
  return readMeta()?.passkeyCredentialId ?? null;
}

/**
 * Stable per-device identifier. Generated once on first use and persisted in
 * localStorage so multiple saves on this device reference the same wrap entry.
 */
export function currentDeviceId() {
  const m = readMeta();
  if (m?.deviceId) return m.deviceId;
  const id = generateDeviceId();
  writeMeta({ deviceId: id });
  return id;
}

/** Human-readable device name for this device. Auto-generated if unset. */
export function currentDeviceName() {
  const m = readMeta();
  if (m?.deviceName) return m.deviceName;
  const n = defaultDeviceName();
  writeMeta({ deviceName: n });
  return n;
}

export function setCurrentDeviceName(name) {
  writeMeta({ deviceName: name });
}

/** Returns whether this device remembers a Passkey that supports PRF. */
export function hasPasskey() {
  return !!getPasskeyCredentialId();
}

/** Returns the vault's algorithm-in-use, or null if unknown yet. */
export function getVaultAlg() {
  return readMeta()?.alg ?? null;
}

/** Remember Passkey info after successful registration. */
export function storePasskey({ credentialId, prfEnabled }) {
  writeMeta({
    passkeyCredentialId: credentialId,
    passkeyPrfEnabled: !!prfEnabled,
    passkeyRegisteredAt: new Date().toISOString(),
  });
}

/** Forget the Passkey on this device. Does not remove it from the authenticator. */
export function forgetPasskey() {
  const current = readMeta() ?? {};
  delete current.passkeyCredentialId;
  delete current.passkeyPrfEnabled;
  delete current.passkeyRegisteredAt;
  localStorage.setItem(CACHE_KEY, JSON.stringify(current));
}

/** Store the most recent Recovery Secret (only during registration; cleared after user confirms). */
export function cacheRecoverySecret(rs) {
  writeMeta({ pendingRecoverySecret: rs });
}
export function readCachedRecoverySecret() {
  return readMeta()?.pendingRecoverySecret ?? null;
}
export function clearCachedRecoverySecret() {
  const m = readMeta() ?? {};
  delete m.pendingRecoverySecret;
  localStorage.setItem(CACHE_KEY, JSON.stringify(m));
}

export {
  registerPasskey, authenticateWithPasskey, isPasskeySupported, isSecureContextOk,
  generateRecoverySecret, recoverySecretToMaterial,
};

/** Clear the in-memory K_vault (e.g. when the user locks the vault). */
export function lockSession() {
  _currentKVault = null;
  _currentEnvelope = null;
}

/**
 * Check whether a vault identity exists in the browser (not whether a vault
 * has been written yet).
 */
export function hasVaultIdentity() {
  return hasClientIdentity();
}

/**
 * Create the API identity if it doesn't exist. Returns {vaultId, credits}.
 * This only creates the signing keypair; it does NOT write an empty vault
 * (that happens on first save).
 */
export async function ensureIdentity() {
  if (hasClientIdentity()) {
    return readClientIdentity();
  }
  const res = await generateKeypairAndRegister();
  return {
    vaultId: res.vaultId,
    credits: res.credits,
    createdAt: new Date().toISOString(),
  };
}

/**
 * Query Arweave for the latest vault tx belonging to this vault-id. Returns
 * the tx id string, or null if none exists yet.
 *
 * Two-tier query strategy for multi-device freshness:
 *   1. Turbo's gateway — indexes data-items as soon as they're submitted
 *      (before Arweave L1 confirmation). 95% of recent writes are findable
 *      here within seconds.
 *   2. arweave.net — slower (5-15 min indexing) but covers writes posted via
 *      direct mainnet (BUNDLER_BACKEND=direct), not just Turbo, AND covers
 *      writes that have already confirmed on L1 even if Turbo cached them
 *      out.
 *
 * Searches under BOTH the per-user anonymized App-Name tag (if known) and
 * the legacy "Arpass-Vault" tag, so users mid-migration can still find
 * pre-anonymization envelopes.
 */
async function findLatestVaultTx(vaultId, options = {}) {
  // Build the union of App-Name tag values to search under:
  //   • "Arpass-Vault" (legacy, pre-Phase-A envelopes)
  //   • this device's known per-user anonymized tag (from meta), if any
  //   • any tag values the caller explicitly provides — used by recovery
  //     flows that derive the tag from the Recovery Secret before the
  //     device's meta has been populated. Without this, a brand-new device
  //     restoring from Recovery would search ONLY under "Arpass-Vault" and
  //     miss every v4 envelope (which is written under the anonymized tag),
  //     surfacing as "この vault には Arweave 上のエンベロープがまだありません".
  const tagValues = new Set([LEGACY_APP_NAME]);
  const meta = readMeta();
  if (meta?.appNameTag) tagValues.add(meta.appNameTag);
  if (Array.isArray(options.extraTagValues)) {
    for (const t of options.extraTagValues) if (t) tagValues.add(t);
  }

  const tagValuesJson = JSON.stringify([...tagValues]);
  const query = `
    query {
      transactions(
        tags: [
          { name: "${APP_NAME_TAG}", values: ${tagValuesJson} }
          { name: "${VAULT_ID_TAG}",  values: ["${vaultId}"] }
        ]
        sort: HEIGHT_DESC
        first: 1
      ) {
        edges { node { id } }
      }
    }
  `;

  async function queryGateway(gateway) {
    try {
      const resp = await fetch(`${gateway}/graphql`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query }),
      });
      if (!resp.ok) return null;
      const data = await resp.json();
      return data?.data?.transactions?.edges?.[0]?.node?.id ?? null;
    } catch {
      return null;
    }
  }

  // Try Turbo first for sub-minute multi-device freshness.
  const turboHit = await queryGateway(TURBO_GATEWAY);
  if (turboHit) return turboHit;

  // Fall back to canonical Arweave gateway (covers direct-mainnet writes).
  return queryGateway(ARWEAVE_GATEWAY);
}

/**
 * Fetch an Arweave data item as JSON, using the bundler fallback for
 * writes that haven't landed on-chain yet.
 */
async function fetchVaultJson(txid, bundlerBase) {
  const result = await readWithFallback(txid, {
    gateway: ARWEAVE_GATEWAY,
    bundlerBase: bundlerBase ?? null,
  });
  return _envelopeFromJson(result.body);
}

// =====================================================================
// Opaque envelope serialization
// ---------------------------------------------------------------------
// To frustrate bulk fingerprinting on Arweave, the on-disk JSON form of
// v4 envelopes uses opaque single-letter keys instead of the descriptive
// internal names. The internal code (vault-crypto.js) keeps using the
// readable names — translation happens only at the JSON I/O boundary.
//
// internal name → opaque key:
//   wraps   → w
//   pr      → a       (password + recovery wrap)
//   pk      → b       (password + passkey wraps array)
//   kr      → c       (passkey + recovery wraps array)
//   devices → d
//
// Other distinctive fields like `kdf`, `iv`, `ciphertext`, `deviceId`,
// `credIdHash`, `name`, `addedAt` are common across crypto schemes and
// don't add useful fingerprint signal — left as-is for debuggability.
//
// Backward compat: _envelopeFromJson accepts either the new opaque form
// or the legacy named form, so existing envelopes already on Arweave
// (with `wraps`/`pr`/`pk`/`kr`/`devices`) keep working.
// =====================================================================

// Internal name → opaque key mapping (deep, all envelope fields).
//   kdf          → k
//   iv (top)     → i
//   ciphertext   → c
//   wraps        → w
//   pr / pk / kr → a / b / c
//   devices      → d
//   ・wrap entry: { iv, ct, deviceId?, credIdHash?, name?, addedAt? }
//                  →   { i, c, d?,        h?,          n?,    a? }
//   ・device entry: { deviceId, name, addedAt }  →  { d, n, a }
//   ・kdf:          { name, iterations, salt }   →  { n, i, s }

function _opaqueWrap(wrap) {
  if (!wrap) return undefined;
  return {
    d: wrap.deviceId,    // optional (only on pk/kr entries, omitted on pr)
    h: wrap.credIdHash,
    n: wrap.name,         // optional (only on pk entries)
    a: wrap.addedAt,      // optional (only on pk entries)
    i: wrap.iv,
    c: wrap.ct,
  };
}
function _namedWrap(o) {
  if (!o) return undefined;
  return {
    deviceId: o.d,
    credIdHash: o.h,
    name: o.n,
    addedAt: o.a,
    iv: o.i,
    ct: o.c,
  };
}

function _envelopeToJson(envelope) {
  // Only v4 envelopes get the opaque transform — legacy v1/v2/v3 stay
  // as-is (they aren't being created any more anyway).
  if (envelope?.v !== VAULT_FORMAT_V4 || !envelope.wraps) {
    return JSON.stringify(envelope);
  }
  const opaque = {
    v: envelope.v,
    k: envelope.kdf ? {
      n: envelope.kdf.name,
      i: envelope.kdf.iterations,
      s: envelope.kdf.salt,
    } : undefined,
    i: envelope.iv,
    c: envelope.ciphertext,
    w: {
      a: _opaqueWrap(envelope.wraps.pr),
      b: (envelope.wraps.pk ?? []).map(_opaqueWrap),
      c: (envelope.wraps.kr ?? []).map(_opaqueWrap),
    },
    d: (envelope.devices ?? []).map((d) => ({
      d: d.deviceId,
      n: d.name,
      a: d.addedAt,
    })),
    // Pass-through informational timestamps (not security-relevant).
    migratedFromV3At: envelope.migratedFromV3At,
    passwordChangedAt: envelope.passwordChangedAt,
  };
  return JSON.stringify(opaque);
}

function _envelopeFromJson(body) {
  const o = JSON.parse(body);
  // Legacy named form (with `wraps`/`devices`) passes through unchanged.
  // Detect opaque form by presence of `w` key on a v=4 envelope.
  if (o?.v !== VAULT_FORMAT_V4 || !o.w) {
    return o;
  }
  return {
    v: o.v,
    kdf: o.k ? {
      name: o.k.n,
      iterations: o.k.i,
      salt: o.k.s,
    } : undefined,
    iv: o.i,
    ciphertext: o.c,
    wraps: {
      pr: _namedWrap(o.w.a),
      pk: (o.w.b ?? []).map(_namedWrap),
      kr: (o.w.c ?? []).map(_namedWrap),
    },
    devices: (o.d ?? []).map((d) => ({
      deviceId: d.d,
      name: d.n,
      addedAt: d.a,
    })),
    migratedFromV3At: o.migratedFromV3At,
    passwordChangedAt: o.passwordChangedAt,
  };
}

/**
 * Load the latest vault from Arweave and decrypt it.
 *
 * Strategy: ALWAYS go to network. Turbo gateway serves data items
 * immediately on write and indexes them in GraphQL within seconds, so
 * the local envelope cache that earlier versions kept (to bridge
 * arweave.net's 3–15 minute propagation window) is no longer useful —
 * and was actively harmful when it pinned a buggy older snapshot
 * (e.g. an empty addDevice envelope from a pre-fix restore-from-Recovery).
 *
 * The picker decrypts the top 10 GraphQL candidates with one Passkey
 * authentication and picks the highest in-vault `updatedAt`. Cost on
 * each unlock: one GraphQL query + ~300ms × N decrypts (typically 2-5
 * candidates for active vaults).
 *
 * @param {string} password  the Master password
 * @param {object} [options] reserved for legacy bundlerBase wiring
 * @returns {{vault, latestTxId, alg}}
 */
export async function loadLatestVault(password, options = {}) {
  const tLoadStart = performance.now();
  const identity = readClientIdentity();
  if (!identity) throw new Error("No identity — call ensureIdentity() first");

  const cache = readMeta();
  const credId = cache?.passkeyCredentialId;
  if (!credId) {
    throw new Error(
      "この端末には Passkey が登録されていません。別端末追加フローで Recovery Secret を使ってこの端末を登録してください。",
    );
  }

  // === Step 1 — get the authoritative latest txid ===
  //
  // The server records `vault.latestTxId` on every successful /api/write
  // (see ledger.recordWrite). This is the SINGLE SOURCE OF TRUTH for
  // "what's the latest envelope on this vault." We no longer compare
  // GraphQL results vs localStorage vs server — only the server's view
  // matters.
  //
  // Run in parallel with Passkey ceremony so the user's biometric prompt
  // overlaps the network round-trip.
  const tPasskeyStart = performance.now();
  const prfPromise = authenticateWithPasskey(credId).then(
    (prfOutput) => {
      console.log(`[load] Passkey: ${(performance.now() - tPasskeyStart).toFixed(0)}ms`);
      return prfOutput;
    },
    (e) => {
      console.warn(`[load] Passkey FAILED after ${(performance.now() - tPasskeyStart).toFixed(0)}ms:`, e?.message ?? e);
      throw e;
    },
  );

  const tHintStart = performance.now();
  let serverHint;
  try {
    const r = await fetch(`/api/vault/${identity.vaultId}`, { cache: "no-store" });
    const j = r.ok ? await r.json() : null;
    serverHint = j?.latestTxId ?? null;
    console.log(`[load] Server hint: ${(performance.now() - tHintStart).toFixed(0)}ms (latestTxId=${serverHint ?? "none"})`);
  } catch (e) {
    // Server is down — can't determine latest. Fail safe.
    console.warn(`[load] Server hint FAILED:`, e?.message);
    throw new Error(
      "サーバーに接続できません。ネットワーク状態を確認して再試行してください。",
    );
  }

  // === Step 2 — handle "no envelope yet" ===
  if (!serverHint) {
    // Server has no latestTxId. Either:
    //   (a) brand-new vault (no writes yet) → return empty vault
    //   (b) legacy vault from before recordWrite was added → bootstrap via GraphQL
    const legacyTxId = await findLatestVaultTx(identity.vaultId, {
      extraTagValues: cache?.appNameTag ? [cache.appNameTag] : [],
    }).catch(() => null);
    if (!legacyTxId) {
      console.log(`[load] TOTAL (empty): ${(performance.now() - tLoadStart).toFixed(0)}ms`);
      return { vault: emptyVault(), latestTxId: null, alg: null };
    }
    return await _loadAndDecrypt(legacyTxId, password, prfPromise, credId, cache, tLoadStart, options);
  }

  // === Step 3 — fetch + decrypt the authoritative latest ===
  return await _loadAndDecrypt(serverHint, password, prfPromise, credId, cache, tLoadStart, options);
}

/**
 * Internal helper: fetch a specific txid, decrypt it, and update meta.
 * Throws clear errors for fetch failure / wrap missing / Passkey failure
 * so the UI can route the user appropriately.
 */
async function _loadAndDecrypt(txid, password, prfPromise, credId, cache, tLoadStart, options) {
  const tFetchStart = performance.now();
  let envelope;
  try {
    envelope = await fetchVaultJson(txid, options?.bundlerBase);
    console.log(`[load] Fetch: ${(performance.now() - tFetchStart).toFixed(0)}ms (tx=${txid})`);
  } catch (e) {
    console.log(`[load] TOTAL (fetch failed): ${(performance.now() - tLoadStart).toFixed(0)}ms`);
    throw new Error(
      `最新エンベロープ (${txid.slice(0, 8)}…) を取得できません: ${e?.message ?? String(e)}\n` +
      "Turbo / Arweave gateway が一時的に不調です。少し時間をおいて再試行してください。" +
      "古いデータを表示・編集すると別端末の更新を消してしまうため、ロック解除を中止します。",
    );
  }

  let prfOutput;
  try {
    prfOutput = await prfPromise;
  } catch (e) {
    console.log(`[load] TOTAL (passkey failed): ${(performance.now() - tLoadStart).toFixed(0)}ms`);
    throw new Error(
      "Passkey 認証ができませんでした。以下を確認してください:\n" +
      "・iOS: 設定 → Apple ID → iCloud → 「パスワードとキーチェーン」が ON\n" +
      "・Android: Google パスワードマネージャーが有効\n" +
      "・ダメなら「機種変更などで既存のドライブを復元」から Recovery で再登録",
    );
  }

  const tDecryptStart = performance.now();
  let res;
  try {
    if (envelope.v === VAULT_FORMAT_V4) {
      res = await decryptVaultV4(envelope, { password, prfOutput }, { credentialId: credId });
    } else if (envelope.v === VAULT_FORMAT_V3) {
      res = await decryptVaultV3(envelope, { password, prfOutput }, { credentialId: credId });
    } else if (envelope.v === VAULT_FORMAT_V2) {
      res = await decryptVaultV2(envelope, { password, prfOutput });
    } else {
      // Legacy v1
      const vault = await decryptVault(envelope, password, prfOutput);
      _currentKVault = null;
      _currentEnvelope = envelope;
      writeMeta({ salt: envelope.salt, iterations: envelope.iterations, alg: envelope.alg, latestTxId: txid });
      console.log(`[load] TOTAL (v1): ${(performance.now() - tLoadStart).toFixed(0)}ms`);
      return { vault, latestTxId: txid, alg: envelope.alg };
    }
  } catch (e) {
    console.log(`[load] TOTAL (decrypt failed): ${(performance.now() - tLoadStart).toFixed(0)}ms`);
    throw new Error(
      "最新エンベロープの復号に失敗しました。原因として考えられるもの:\n" +
      "・マスターパスワードの入力ミス\n" +
      "・別端末で Recovery 再発行 / changePassword されてこの端末の wrap が外された\n" +
      "→ パスワードを再確認するか「機種変更などで既存のドライブを復元」から Recovery で再登録してください。\n" +
      `(内部: ${e?.message ?? String(e)})`,
    );
  }
  console.log(`[load] Decrypt: ${(performance.now() - tDecryptStart).toFixed(0)}ms`);

  _currentKVault = res.kVault;
  _currentEnvelope = envelope;
  writeMeta({
    salt: envelope.kdf.salt,
    iterations: envelope.kdf.iterations,
    alg: envelope.alg,
    latestTxId: txid,
  });
  console.log(`[load] TOTAL: ${(performance.now() - tLoadStart).toFixed(0)}ms`);
  return { vault: res.vault, latestTxId: txid, alg: envelope.alg };
}

/**
 * Alternate unlock: Master password + Recovery Secret (for when the device
 * Passkey is gone — e.g. new phone, lost phone, factory reset).
 *
 * After a successful unlock, the caller should immediately prompt the user
 * to register a NEW Passkey on this device and call `rewrapWithNewPasskey()`
 * so daily unlocks resume using the cheap Password+Passkey path.
 */
export async function unlockWithPasswordAndRecovery(password, recoveryString) {
  const identity = readClientIdentity();
  if (!identity) throw new Error("No identity — call ensureIdentity() first");
  // Derive the per-user App-Name tag from Recovery first, so the GraphQL
  // search can find v4 envelopes even when this device's meta doesn't
  // yet have the tag cached (e.g. fresh install on a known vault).
  const recoveryMaterial = await recoverySecretToMaterial(recoveryString);
  const appNameTag = await deriveAppNameTag(recoveryMaterial);
  // Pick the latest decryptable envelope by vault.updatedAt — same
  // rationale as restoreVaultOnNewDevice: GraphQL HEIGHT_DESC is
  // unreliable for pending bundles.
  // Shared PBKDF2 cache across all 10 picker candidates (see loadLatestVault).
  const passwordMaterialCache = {};
  const tryDecrypt = async (env) => {
    if (env?.v === VAULT_FORMAT_V4) return decryptVaultV4(env, { password, recoveryMaterial, passwordMaterialCache });
    if (env?.v === VAULT_FORMAT_V3) return decryptVaultV3(env, { password, recoveryMaterial, passwordMaterialCache });
    if (env?.v === VAULT_FORMAT_V2) return decryptVaultV2(env, { password, recoveryMaterial });
    throw new Error(
      "この vault はまだ v1 フォーマットです。Recovery Secret による復旧は v2 以降のみ対応しています。",
    );
  };
  // Server hint: catches just-written envelopes that GraphQL hasn't indexed.
  const serverHint = await _fetchServerLatestTxId(identity.vaultId);
  const best = await _pickLatestDecryptableEnvelope(identity.vaultId, tryDecrypt, {
    extraTagValues: [appNameTag],
    limit: PICKER_LIMIT,
    pinnedTxIds: serverHint ? [serverHint] : [],
  });
  if (!best) {
    throw new Error(
      "この vault に対応する暗号化エンベロープが見つからない、または復号に失敗しました。" +
        "リカバリーシークレットとマスターパスワードが正しいかご確認ください。",
    );
  }
  _currentKVault = best.dec.kVault;
  _currentEnvelope = best.envelope;
  return { vault: best.dec.vault, wrapUsed: best.dec.wrapUsed };
}

/** Internal helper: ask the server for vault.latestTxId (returns null on any failure). */
async function _fetchServerLatestTxId(vaultId) {
  return fetch(`/api/vault/${vaultId}`, { cache: "no-store" })
    .then((r) => (r.ok ? r.json() : null))
    .then((j) => j?.latestTxId ?? null)
    .catch(() => null);
}

/**
 * Alternate unlock: Passkey PRF + Recovery Secret (for when the Master
 * password is forgotten — rare, but a real recovery channel).
 */
export async function unlockWithPasskeyAndRecovery(recoveryString) {
  const identity = readClientIdentity();
  if (!identity) throw new Error("No identity");
  const cache = readMeta();
  const credId = cache?.passkeyCredentialId;
  if (!credId) throw new Error("この端末には Passkey が登録されていません");
  // Derive App-Name tag from Recovery first so the GraphQL search includes
  // the per-user anonymized value (see unlockWithPasswordAndRecovery for
  // the full rationale).
  const recoveryMaterial = await recoverySecretToMaterial(recoveryString);
  const appNameTag = await deriveAppNameTag(recoveryMaterial);
  const prfOutput = await authenticateWithPasskey(credId);
  const tryDecrypt = async (env) => {
    if (env?.v === VAULT_FORMAT_V4) return decryptVaultV4(env, { prfOutput, recoveryMaterial }, { credentialId: credId });
    if (env?.v === VAULT_FORMAT_V3) return decryptVaultV3(env, { prfOutput, recoveryMaterial }, { credentialId: credId });
    if (env?.v === VAULT_FORMAT_V2) return decryptVaultV2(env, { prfOutput, recoveryMaterial });
    throw new Error("v1 vault は Passkey+Recovery 経路に対応していません");
  };
  const serverHint = await _fetchServerLatestTxId(identity.vaultId);
  const best = await _pickLatestDecryptableEnvelope(identity.vaultId, tryDecrypt, {
    extraTagValues: [appNameTag],
    limit: PICKER_LIMIT,
    pinnedTxIds: serverHint ? [serverHint] : [],
  });
  if (!best) {
    throw new Error(
      "この vault に対応する暗号化エンベロープが見つからない、または復号に失敗しました。" +
        "リカバリーシークレットが正しいかご確認ください。",
    );
  }
  _currentKVault = best.dec.kVault;
  _currentEnvelope = best.envelope;
  return { vault: best.dec.vault, wrapUsed: best.dec.wrapUsed };
}

async function _fetchLatestEnvelopeFor(vaultId, options = {}) {
  // `options.extraTagValues` lets recovery flows pass the App-Name tag
  // they just derived from the Recovery Secret, so a fresh device can
  // find v4 envelopes that were written under the per-user anonymized
  // tag (which this device's localStorage doesn't yet know about).
  const latestTxId = await findLatestVaultTx(vaultId, {
    extraTagValues: options.extraTagValues,
  });
  if (!latestTxId) throw new Error("この vault には Arweave 上のエンベロープがまだありません");
  return await fetchVaultJson(latestTxId, null);
}

/**
 * Fetch the N most recent candidate tx ids for this vault from GraphQL.
 *
 * Used by recovery / restore flows that can't afford to take the gateway's
 * "first hit" at face value: GraphQL `sort: HEIGHT_DESC` is unreliable
 * when txs are still pending (block_height = null) — different gateways
 * order them differently, and Turbo has occasionally returned the
 * earliest unconfirmed tx in the bundle as "first" rather than the
 * latest. The recovery code pulls top N here, decrypts each candidate,
 * then picks the one with the highest decrypted `vault.updatedAt`. That
 * field is set by the client on every save, so it's the most
 * authoritative ordering we have access to.
 */
async function findRecentVaultTxs(vaultId, options = {}) {
  const tagValues = new Set([LEGACY_APP_NAME]);
  const meta = readMeta();
  if (meta?.appNameTag) tagValues.add(meta.appNameTag);
  if (Array.isArray(options.extraTagValues)) {
    for (const t of options.extraTagValues) if (t) tagValues.add(t);
  }

  const tagValuesJson = JSON.stringify([...tagValues]);
  const limit = Math.max(1, Math.min(50, options.limit ?? 10));
  const query = `
    query {
      transactions(
        tags: [
          { name: "${APP_NAME_TAG}", values: ${tagValuesJson} }
          { name: "${VAULT_ID_TAG}",  values: ["${vaultId}"] }
        ]
        sort: HEIGHT_DESC
        first: ${limit}
      ) {
        edges { node { id block { height timestamp } } }
      }
    }
  `;

  async function queryGateway(gateway) {
    // 5s timeout per gateway. Was unbounded — observed 10s+ hangs when one
    // gateway was unhealthy, blocking the entire unlock. Better to skip a
    // slow gateway than make the user wait 30 seconds.
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 5000);
    try {
      const resp = await fetch(`${gateway}/graphql`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query }),
        signal: ctrl.signal,
      });
      if (!resp.ok) return [];
      const data = await resp.json();
      return data?.data?.transactions?.edges?.map((e) => e.node) ?? [];
    } catch {
      return [];
    } finally {
      clearTimeout(timer);
    }
  }

  // Union the two gateways' result sets, dedup by id. Turbo sees fresh
  // pending bundles; arweave.net has the canonical confirmed view.
  // Parallelized — was sequential, costing ~1s extra per unlock.
  const [turboHits, arweaveHits] = await Promise.all([
    queryGateway(TURBO_GATEWAY),
    queryGateway(ARWEAVE_GATEWAY),
  ]);
  const seen = new Set();
  const out = [];
  for (const node of [...turboHits, ...arweaveHits]) {
    if (!node?.id || seen.has(node.id)) continue;
    seen.add(node.id);
    out.push(node);
  }
  return out;
}

/**
 * Find the most-recently-updated envelope for a vault by decrypting the
 * top N GraphQL candidates with the supplied factors and picking the
 * highest `vault.updatedAt`. Returns { envelope, dec, txid } or null if
 * no candidate decrypts successfully.
 *
 * `tryDecrypt(envelope)` should return either a decrypt result like
 * `{ vault, kVault, ... }` or throw. Caller chooses what factors to try.
 */
async function _pickLatestDecryptableEnvelope(vaultId, tryDecrypt, options = {}) {
  const tStart = performance.now();
  const candidates = await findRecentVaultTxs(vaultId, {
    extraTagValues: options.extraTagValues,
    limit: options.limit ?? 10,
  });
  const tGraphQL = performance.now() - tStart;

  // CRITICAL: prepend any caller-supplied "must include" txids that
  // GraphQL might be missing due to indexing lag. Without this, a fresh
  // unlock on a device whose GraphQL hasn't caught up yet picks an OLDER
  // envelope as "latest" and silently drops the user's recent edits on
  // the next save. The pinned ids come from (a) the device's own
  // localStorage record of its last save, and (b) the server's
  // /api/vault/<id>.latestTxId hint that's updated on every successful
  // /api/write. Either source is enough to defeat indexing lag.
  const seen = new Set(candidates.map((c) => c.id));
  const pinned = (options.pinnedTxIds ?? []).filter(Boolean);
  for (const id of pinned) {
    if (!seen.has(id)) {
      candidates.unshift({ id, block: null });
      seen.add(id);
    }
  }
  console.log(
    `[picker] GraphQL: ${tGraphQL.toFixed(0)}ms (${candidates.length} candidates` +
      (pinned.length ? `, ${pinned.length} pinned` : "") + ")",
  );
  if (candidates.length === 0) return null;

  // STEP 1 — fetch all candidate envelopes IN PARALLEL.
  // Previously this was a sequential for-loop, which serialized 10 network
  // round-trips × ~200–500ms each = 2–5s of unlock latency. Promise.all
  // collapses that into a single round-trip's wall-clock time.
  const tFetchStart = performance.now();
  const fetchTimes = [];
  const fetchFailures = new Set();
  const decryptFailures = new Set();
  const fetched = await Promise.all(
    candidates.map(async (node) => {
      const t0 = performance.now();
      try {
        const envelope = await fetchVaultJson(node.id, null);
        fetchTimes.push(performance.now() - t0);
        return { node, envelope };
      } catch (e) {
        console.warn(`pickLatest: fetch failed for ${node.id}:`, e?.message ?? e);
        fetchFailures.add(node.id);
        return { node, envelope: null };
      }
    }),
  );
  const tFetch = performance.now() - tFetchStart;
  const fetchMin = Math.min(...fetchTimes).toFixed(0);
  const fetchMax = Math.max(...fetchTimes).toFixed(0);
  const fetchAvg = (fetchTimes.reduce((a, b) => a + b, 0) / fetchTimes.length).toFixed(0);
  console.log(`[picker] Fetch parallel: wall=${tFetch.toFixed(0)}ms, per-envelope avg=${fetchAvg}ms (min=${fetchMin}, max=${fetchMax})`);

  // STEP 2 — decrypt the v2+ envelopes in parallel. With the shared
  // passwordMaterialCache the FIRST decrypt fills the cache; the rest
  // hit the cache and skip PBKDF2 entirely.
  // Note: Promise.all schedules them concurrently, but each await still
  // runs single-threaded on the JS event loop — that's fine, we want the
  // fetches to overlap, not the CPU work.
  const tDecryptStart = performance.now();
  const decrypted = await Promise.all(
    fetched.map(async ({ node, envelope }) => {
      if (!envelope) return null;
      const v = envelope?.v;
      if (typeof v !== "number" || v < 2) {
        console.debug(`pickLatest: skipping legacy ${node.id} (v=${v})`);
        return null;
      }
      try {
        const dec = await tryDecrypt(envelope);
        const updatedAt = new Date(dec?.vault?.updatedAt ?? 0).getTime();
        return { txid: node.id, envelope, dec, updatedAt, block: node.block ?? null };
      } catch (e) {
        console.warn(`pickLatest: decrypt failed for ${node.id}:`, e?.message ?? e);
        decryptFailures.add(node.id);
        return null;
      }
    }),
  );

  const tDecrypt = performance.now() - tDecryptStart;
  // tryDecryptOne may have wasted time inside `await prfPromise` if the
  // Passkey ceremony hadn't finished by the time fetches completed. Surface
  // that separately so the log doesn't mislead.
  const prfWait = options.prfWaitGetter?.() ?? 0;
  const realDecrypt = Math.max(0, tDecrypt - prfWait);
  console.log(
    `[picker] Decrypt parallel: ${tDecrypt.toFixed(0)}ms total ` +
    `(${realDecrypt.toFixed(0)}ms crypto + ${prfWait.toFixed(0)}ms Passkey wait, ` +
    `${decrypted.filter(Boolean).length} succeeded)`,
  );

  // STEP 3 — pick the highest updatedAt.
  let best = null;
  for (const c of decrypted) {
    if (!c) continue;
    if (!best || c.updatedAt > best.updatedAt) best = c;
  }
  console.log(`[picker] TOTAL: ${(performance.now() - tStart).toFixed(0)}ms`);
  // Stash failure sets on the result so callers can distinguish
  // "couldn't fetch from gateway" (retry/wait) from "fetched but couldn't
  // decrypt" (this device's wrap is missing → re-restore).
  if (best) {
    best.fetchFailures = fetchFailures;
    best.decryptFailures = decryptFailures;
  }
  return best;
}

/**
 * Wrap-sync helper: fetch the latest envelope for `vaultId` from Turbo
 * gateway and verify its outer ciphertext decrypts with `kVault`. If
 * yes, return that envelope so the caller can re-encrypt against ITS
 * wraps (picking up any device additions made by other devices since
 * this session unlocked). If the latest is on a different kVault chain
 * (post-rotation, hypothetical future feature), or there's no newer tx
 * than what we already hold, returns `null` and the caller falls back
 * to its current envelope.
 *
 * Cost per save: one GraphQL query + one envelope fetch + one AES-GCM
 * trial decrypt. No Passkey prompt — kVault is already in memory from
 * the unlock that started this session.
 */
async function _fetchLatestEnvelopeWithSameKVault(vaultId, currentEnvelope, kVault, cache) {
  // Query GraphQL AND the server hint in parallel. GraphQL has indexing
  // lag (Turbo: 30s+, arweave.net: 5–15min), so when another device just
  // added itself, GraphQL's "latest" can still point at our pre-add tx.
  // The server's recordWrite() updates KV instantly on every successful
  // /api/write, so it's the authoritative signal for "what's the latest
  // tx ANY device just wrote." Take whichever is newer.
  const [graphqlTxId, serverHintTxId] = await Promise.all([
    findLatestVaultTx(vaultId, {
      extraTagValues: cache?.appNameTag ? [cache.appNameTag] : [],
    }).catch(() => null),
    _fetchServerLatestTxId(vaultId),
  ]);

  // Prefer server hint when both exist and differ — it's the authoritative
  // post-write source. If only one is set, use it.
  const latestTxId = serverHintTxId ?? graphqlTxId;
  if (!latestTxId) return null;

  // Fast skip: server hint and our own cache agree → nothing new since
  // our last save / unlock.
  if (latestTxId === cache?.latestTxId) return null;

  let fetched;
  try {
    fetched = await fetchVaultJson(latestTxId, null);
  } catch {
    // Couldn't fetch — treat as "stick with current". Logged but not fatal:
    // a temporary network issue shouldn't block saves. The save will use
    // current wraps; if those are stale, the next-device unlock will
    // detect it via the load-time wrap_missing check.
    console.warn(`wrap-sync: couldn't fetch latest tx ${latestTxId}, falling back to current envelope`);
    return null;
  }

  // Same envelope version is required — wrap layouts differ across v2/v3/v4.
  if (fetched?.v !== currentEnvelope?.v) return null;

  // Verify same kVault by trial-decrypting the latest envelope's
  // ciphertext with our in-memory kVault. AES-GCM auth tag failure
  // throws — we treat that as "different kVault chain" (post-rotation
  // / Recovery re-issue / different vault entirely).
  //
  // CRITICAL: when this fails, we must NOT save with our stale wraps
  // because that would overwrite the latest envelope's [updated wraps]
  // with our [stale wraps], deepening divergence and possibly losing
  // other devices. Throw to abort the save and force the user to
  // re-restore.
  if (!(await _ciphertextDecryptsWithKVault(fetched, kVault))) {
    console.warn(
      `wrap-sync: latest tx ${latestTxId} ciphertext does not decrypt with ` +
      `our kVault — kVault chain has rotated. Aborting save to prevent overwrite.`,
    );
    throw new Error(
      "別端末でマスターパスワード変更や Recovery 再発行が行われたため、" +
      "現在の状態で保存すると最新データを上書きしてしまいます。" +
      "ロックを解除し直すか、「機種変更などで既存のドライブを復元」から再登録してください。",
    );
  }
  console.log(
    `wrap-sync: merging wraps from latest tx ${latestTxId} ` +
      `(devices=${fetched.devices?.length ?? "?"}, ` +
      `pk=${fetched.wraps?.pk?.length ?? "?"}, ` +
      `kr=${fetched.wraps?.kr?.length ?? "?"})`,
  );
  return fetched;
}

/**
 * Returns true iff `envelope.ciphertext` decrypts cleanly with `kVault`.
 * Used by wrap-sync to gate "is the latest envelope on our key chain?".
 */
async function _ciphertextDecryptsWithKVault(envelope, kVault) {
  try {
    const iv = b64uDecode(envelope.iv);
    const ct = b64uDecode(envelope.ciphertext);
    const key = await crypto.subtle.importKey(
      "raw",
      kVault,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
    await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
    return true;
  } catch {
    return false;
  }
}

/**
 * Encrypt and save a vault as a new Arweave transaction.
 *
 * If a Passkey is registered on this device, Passkey authentication runs
 * to retrieve a fresh PRF output and the vault is encrypted with the
 * 2-factor algorithm. Otherwise the password-only algorithm is used.
 *
 * @returns {{txid, vault, cost_ar, credits_remaining, alg}}
 */
export async function saveVault(vault, password) {
  const identity = readClientIdentity();
  if (!identity) throw new Error("No identity");

  const cache = readMeta();

  // Wrap sync: before re-encrypting, try to fetch the latest envelope
  // from Turbo gateway. If another device has added itself (or otherwise
  // updated wraps/devices) since this session unlocked, we want OUR new
  // save to inherit those wraps so the new envelope is decryptable by
  // every currently-authorized device. Without this, the writing device
  // would keep using its own stale wraps from unlock-time, locking
  // newer-added devices out of every subsequent save.
  //
  // We trust the latest envelope's wraps ONLY if we can prove its
  // ciphertext decrypts with OUR kVault — that confirms the latest
  // envelope is on the same kVault chain (no rotation happened) and
  // therefore its wraps unwrap to the same kVault we're encrypting with.
  let envelopeForRewrap = _currentEnvelope;
  if (
    _currentKVault &&
    (_currentEnvelope?.v === VAULT_FORMAT_V4 ||
      _currentEnvelope?.v === VAULT_FORMAT_V3 ||
      _currentEnvelope?.v === VAULT_FORMAT_V2)
  ) {
    const synced = await _fetchLatestEnvelopeWithSameKVault(
      identity.vaultId,
      _currentEnvelope,
      _currentKVault,
      cache,
    ).catch(() => null);
    if (synced) envelopeForRewrap = synced;
  }

  // Fast paths: we already have K_vault from unlock, just rotate the outer
  // ciphertext. No extra Passkey prompts on save.
  let envelope;
  if (_currentKVault && envelopeForRewrap?.v === VAULT_FORMAT_V4) {
    envelope = await reEncryptVaultV4(vault, _currentKVault, envelopeForRewrap);
    _currentEnvelope = envelope;
  } else if (_currentKVault && envelopeForRewrap?.v === VAULT_FORMAT_V3) {
    envelope = await reEncryptVaultV3(vault, _currentKVault, envelopeForRewrap);
    _currentEnvelope = envelope;
  } else if (_currentKVault && envelopeForRewrap?.v === VAULT_FORMAT_V2) {
    envelope = await reEncryptVaultV2(vault, _currentKVault, envelopeForRewrap);
    _currentEnvelope = envelope;
  } else {
    // Legacy v1 path — reached when loading an old envelope that hasn't been
    // migrated to v2 yet. Save as v1 with whatever factors are available.
    const existingSalt = cache?.salt ? b64uDecode(cache.salt) : undefined;
    let prfOutput;
    if (cache?.passkeyCredentialId && cache?.passkeyPrfEnabled !== false) {
      try {
        prfOutput = await authenticateWithPasskey(cache.passkeyCredentialId);
      } catch (e) {
        if (cache?.alg === "pbkdf2+prf-hkdf-aes256gcm") throw e;
        prfOutput = undefined;
      }
    }
    envelope = await encryptVault(vault, password, { existingSalt, prfOutput });
  }

  const body = {
    data: _envelopeToJson(envelope),
    contentType: "application/json",
    tags: {
      // Per-user anonymized App-Name (HMAC of recovery material) is the
      // only identifying tag we expose. envelope.v / envelope.alg live
      // INSIDE the JSON payload so a casual Arweave observer can't tell
      // which service this tx belongs to.
      [APP_NAME_TAG]: currentAppNameTag(),
    },
    // Optimistic concurrency: server compares this against vault.latestTxId
    // and returns 409 if another device wrote since we last loaded. Without
    // this, save would silently overwrite the newer envelope (entry data
    // AND wraps). cache.latestTxId is set on every successful unlock/save.
    expectedLatestTxId: cache?.latestTxId ?? null,
  };
  const result = await signedFetch("/api/write", "POST", body);
  if (!result.ok) {
    throw writeError(result);
  }

  // Persist meta for subsequent loads. We deliberately DO NOT cache the
  // envelope itself anymore — Turbo gateway serves data items
  // immediately and indexes them in GraphQL within seconds, so the cache
  // adds no value while creating opportunities for stale-state bugs
  // (e.g. an empty addDevice envelope from a buggy restore being
  // re-presented as "latest" forever). Identity and Passkey credentialId
  // are still persisted by their own writeMeta calls.
  const meta = {
    alg: envelope.alg,
    latestTxId: result.txid,
  };
  if (
    envelope.v === VAULT_FORMAT_V4 ||
    envelope.v === VAULT_FORMAT_V3 ||
    envelope.v === VAULT_FORMAT_V2
  ) {
    meta.salt = envelope.kdf.salt;
    meta.iterations = envelope.kdf.iterations;
  } else {
    meta.salt = envelope.salt;
    meta.iterations = envelope.iterations;
  }
  writeMeta(meta);

  return {
    txid: result.txid,
    vault,
    cost_ar: result.cost_ar,
    credits_remaining: result.vault?.credits,
    alg: envelope.alg,
  };
}

/**
 * Create a brand-new empty vault and persist it. Used the first time a user
 * confirms their Master password.
 *
 * If the device supports Passkey PRF and the caller passes `registerNewPasskey:true`,
 * a Passkey is registered FIRST, then the empty vault is encrypted with
 * both factors.
 */
export async function createVault(password, options = {}) {
  // For 2-of-3 vaults we derive the ECDSA identity deterministically from
  // the Recovery Secret so a fresh device with the Secret can reach the same
  // Vault ID. Generate the Recovery Secret FIRST, then derive everything
  // else from it.
  const wantPasskey = options.registerNewPasskey !== false;

  if (!wantPasskey) {
    // Legacy password-only creation (random identity, no Recovery Secret).
    // Still supported for devices without Passkey PRF; no device migration
    // path for these vaults.
    const identity = await ensureIdentity();
    const vault = emptyVault();
    const res = await saveVault(vault, password);
    return { vault: res.vault, txid: res.txid, alg: res.alg, recoverySecret: null };
  }

  // 1) Generate the one-time Recovery Secret.
  const recoveryString = generateRecoverySecret();
  const recoveryMaterial = await recoverySecretToMaterial(recoveryString);

  // 2) Derive the ECDSA identity deterministically from the Recovery Secret
  //    and register it with the server. Same Recovery → same Vault ID on any
  //    future device.
  const { privateKeyJwk, publicKeyJwk } = await deriveIdentityKeypair(recoveryString);
  const regResult = await generateKeypairAndRegister({ privateKeyJwk, publicKeyJwk });
  const vaultId = regResult.vaultId;

  // 3) Register a Passkey on this device.
  const { credentialId, prfEnabled } =
    await registerPasskey(vaultId.slice(0, 8), vaultId);
  storePasskey({ credentialId, prfEnabled });

  if (!prfEnabled) {
    // Authenticator doesn't support PRF — we can't do 2-of-3 properly, fall
    // back to legacy password-only save. Rare on modern platforms.
    const vault = emptyVault();
    const res = await saveVault(vault, password);
    return { vault: res.vault, txid: res.txid, alg: res.alg, recoverySecret: null };
  }

  // 4) Full 2-of-3 path: authenticate the freshly-registered Passkey once to
  //    obtain a PRF output for the three wraps.
  {
    const prfOutput = await authenticateWithPasskey(credentialId);

    const vault = emptyVault();
    // v4 envelope (multi-device + padded + tag-anonymized).
    const deviceId = currentDeviceId();
    const deviceName = currentDeviceName();
    const { envelope, kVault } = await encryptVaultV4(
      vault, password, prfOutput, recoveryMaterial,
      { deviceId, credentialId, name: deviceName },
    );
    // Per-user anonymized App-Name tag, derived deterministically from the
    // Recovery Secret material so any future device with the Recovery can
    // re-derive it and find the vault on Arweave.
    const appNameTag = await deriveAppNameTag(recoveryMaterial);

    // Write the envelope as the vault's first transaction. The App-Name
    // tag is per-user anonymized so attackers can't enumerate Arpass vaults
    // by querying GraphQL for App-Name=Arpass-Vault.
    const body = {
      data: _envelopeToJson(envelope),
      contentType: "application/json",
      tags: {
        // Only the per-user anonymized App-Name is exposed publicly.
        // Format / algorithm metadata lives inside envelope JSON.
        [APP_NAME_TAG]: appNameTag,
      },
      // First write — vault has no prior tx. Server should also see null.
      expectedLatestTxId: null,
    };
    const result = await signedFetch("/api/write", "POST", body);
    if (!result.ok) throw writeError(result);

    // Populate in-memory state for subsequent saves within this session.
    _currentKVault = kVault;
    _currentEnvelope = envelope;

    writeMeta({
      salt: envelope.kdf.salt,
      iterations: envelope.kdf.iterations,
      alg: envelope.alg,
      latestTxId: result.txid,
      appNameTag, // remember the per-user tag for future GraphQL queries
    });

    return {
      vault,
      txid: result.txid,
      alg: envelope.alg,
      recoverySecret: recoveryString, // MUST be shown to the user and confirmed
    };
  }
}

/**
 * Restore an existing vault on a fresh device.
 *
 *   - Regenerate the deterministic ECDSA identity from the Recovery Secret
 *     so this device arrives at the same Vault ID as the original.
 *   - Fetch the latest envelope from Arweave.
 *   - Decrypt with password + Recovery (wrap_pr).
 *   - Register a brand-new Passkey on this device and rotate wrap_pk and
 *     wrap_kr so daily unlocks can use password + Passkey here too.
 *   - Save the freshly-rewrapped envelope.
 *
 * After this returns the caller is fully signed in and can show the vault.
 */
export async function restoreVaultOnNewDevice(password, recoveryString, deviceNameOverride) {
  // 1) Regenerate identity from Recovery Secret.
  await restoreIdentityFromRecovery(recoveryString);

  // We need the recovery material twice — first to derive the per-user
  // App-Name tag so the GraphQL search can find the v4 envelope (which
  // wasn't tagged "Arpass-Vault"), and again later to actually decrypt.
  // Doing it once up-front avoids running the KDF chain twice.
  const recoveryMaterial = await recoverySecretToMaterial(recoveryString);
  const restoredAppNameTag = await deriveAppNameTag(recoveryMaterial);

  // 2) Find the *canonical* latest envelope. We CANNOT trust GraphQL's
  //    `sort: HEIGHT_DESC` alone — Turbo's bundler has been observed
  //    returning the createVault initial empty envelope as "first" when
  //    multiple txs are still pending (block_height = null), which would
  //    cause us to addDevice on top of an empty ciphertext and silently
  //    overwrite the user's actual entries on the next save.
  //
  //    Instead, fetch the top 10 candidates, decrypt each with the
  //    factors we have, and pick the one with the highest in-vault
  //    `updatedAt` — a value WE wrote on every save, so it's the only
  //    truly trustworthy ordering signal.
  const identity = readClientIdentity();

  // CRITICAL: ask the server for the vault's latestTxId BEFORE running
  // picker. On a fresh device there's no localStorage cache, and Turbo's
  // GraphQL takes 30+ seconds to index a fresh write — so without the
  // server hint, restore on a NEW device that the original PC just
  // re-issued Recovery for would fail with "envelope not found" until
  // GraphQL caught up. The server records latestTxId on every successful
  // /api/write (see ledger.recordWrite), so it has the most recent state.
  const serverHint = await _fetchServerLatestTxId(identity.vaultId);
  const pinnedTxIds = serverHint ? [serverHint] : [];

  // Shared PBKDF2 cache across all picker candidates (see loadLatestVault).
  const passwordMaterialCache = {};
  const tryDecrypt = async (env) => {
    if (env?.v === VAULT_FORMAT_V4) return decryptVaultV4(env, { password, recoveryMaterial, passwordMaterialCache });
    if (env?.v === VAULT_FORMAT_V3) return decryptVaultV3(env, { password, recoveryMaterial, passwordMaterialCache });
    if (env?.v === VAULT_FORMAT_V2) return decryptVaultV2(env, { password, recoveryMaterial });
    throw new Error(`unsupported envelope v=${env?.v}`);
  };
  const best = await _pickLatestDecryptableEnvelope(identity.vaultId, tryDecrypt, {
    extraTagValues: [restoredAppNameTag],
    limit: PICKER_LIMIT,
    pinnedTxIds,
  });
  if (!best) {
    throw new Error(
      "この vault に対応する暗号化エンベロープが見つからない、または復号に失敗しました。" +
        "リカバリーシークレットとマスターパスワードが正しいかご確認ください。",
    );
  }
  let envelope = best.envelope;
  if (
    envelope?.v !== VAULT_FORMAT_V2 &&
    envelope?.v !== VAULT_FORMAT_V3 &&
    envelope?.v !== VAULT_FORMAT_V4
  ) {
    throw new Error(
      "この vault は 2-of-3 形式ではないため、Recovery Secret による別端末復旧に対応していません。",
    );
  }
  console.log(
    `restoreVaultOnNewDevice: picked tx ${best.txid} ` +
      `(updatedAt=${new Date(best.updatedAt).toISOString()}, ` +
      `entries=${best.dec.vault?.entries?.length ?? "?"})`,
  );

  // 3) Use the already-decrypted result.
  let kVault = best.dec.kVault;
  let vault = best.dec.vault;
  if (envelope.v === VAULT_FORMAT_V2) {
    // Migrate v2 → v3 structure before adding this device (no crypto changes).
    const m = readMeta();
    envelope = migrateV2ToV3(envelope, {
      deviceId: m?.legacyDeviceIdForMigration ?? "dev_legacy_unknown",
      name: "（以前の端末）",
      credIdHash: "",
    });
  }

  // 4) Register a fresh Passkey on THIS device + append it as an authorized
  //    device in the envelope's pk/kr arrays. The old device's wraps remain
  //    valid — this is an ADDITIONAL device, not a replacement.
  const { credentialId, prfEnabled } =
    await registerPasskey(identity.vaultId.slice(0, 8), identity.vaultId);
  storePasskey({ credentialId, prfEnabled });
  if (!prfEnabled) {
    throw new Error("この認証器は Passkey PRF 拡張に対応していないため、端末追加できません");
  }

  const newPrf = await authenticateWithPasskey(credentialId);
  const deviceId = currentDeviceId();
  const deviceName = deviceNameOverride ?? currentDeviceName();
  // v4 carries padding; addDeviceV4 takes the same args but preserves it.
  const addDevice = envelope.v === VAULT_FORMAT_V4 ? addDeviceV4 : addDeviceV3;
  const newEnvelope = await addDevice(envelope, kVault, password, newPrf, recoveryMaterial, {
    deviceId, credentialId, name: deviceName,
  });

  // We already derived the per-user App-Name tag at the top of this
  // function (so we could pass it to the GraphQL search). Reuse it here
  // for the new save and persist it in meta below.
  const appNameTag = restoredAppNameTag;

  // 5) Save. Use the txid we picked as `expectedLatestTxId` so the server
  // returns 409 if another device wrote between our picker and now.
  const body = {
    data: _envelopeToJson(newEnvelope),
    contentType: "application/json",
    tags: {
      [APP_NAME_TAG]: appNameTag,
    },
    expectedLatestTxId: best.txid,
  };
  const saveResult = await signedFetch("/api/write", "POST", body);
  if (!saveResult.ok) {
    // Special-case 410 (migrated): the OLD vault we just decrypted is dead
    // (someone re-issued Recovery elsewhere), so the server refuses to
    // accept our addDevice save. We don't want to surface this as a hard
    // "復元失敗" — the user's data is intact and decryptable, they just
    // can't add this device to a dead vault. Hand back a read-only
    // result so the UI can show the entries with a "view-only" banner
    // and offer to re-register against the NEW vault id if the user
    // has the new Recovery secret.
    const err = writeError(saveResult, "rewrap save failed");
    if (err.code === "migrated") {
      // Persist the appNameTag we derived so the lifecycle banner /
      // future GraphQL searches still find this vault's envelopes.
      writeMeta({
        appNameTag,
        salt: envelope.kdf.salt,
        iterations: envelope.kdf.iterations,
        alg: envelope.alg,
      });
      // DO NOT update _currentKVault / _currentEnvelope to the new
      // (unsavable) envelope — the in-memory state should reflect what
      // we successfully decrypted, not what we tried to write.
      _currentKVault = kVault;
      _currentEnvelope = envelope;
      return {
        vault,
        txid: null,
        vaultId: identity.vaultId,
        readOnly: true,
        migratedTo: saveResult.newVaultId ?? null,
        message:
          "この vault は新しい Recovery Secret に移行されています。" +
          "read-only モードで開きました（保存・削除はできません）。",
      };
    }
    throw err;
  }

  _currentKVault = kVault;
  _currentEnvelope = newEnvelope;
  writeMeta({
    salt: newEnvelope.kdf.salt,
    iterations: newEnvelope.kdf.iterations,
    alg: newEnvelope.alg,
    appNameTag,
    latestTxId: saveResult.txid,
  });

  return { vault, txid: saveResult.txid, vaultId: identity.vaultId, readOnly: false };
}

/**
 * Change the Master password on the currently-unlocked vault.
 *
 * Requires: session is unlocked (so we have K_vault) AND the user re-enters
 * their Recovery Secret so both password-bearing wraps (pk, pr) can be
 * regenerated atomically.
 */
export async function changePassword(newPassword, recoveryString) {
  if (!_currentKVault || !_currentEnvelope) {
    throw new Error("ドライブのロックを解除した状態から実行してください");
  }
  const cache = readMeta();
  const credId = cache?.passkeyCredentialId;
  if (!credId) throw new Error("Passkey が登録されていません");
  const prfOutput = await authenticateWithPasskey(credId);
  const recoveryMaterial = await recoverySecretToMaterial(recoveryString);

  let newEnvelope;
  if (_currentEnvelope.v === VAULT_FORMAT_V4) {
    newEnvelope = await changePasswordV4(
      _currentEnvelope, _currentKVault, newPassword,
      prfOutput, currentDeviceId(), recoveryMaterial,
    );
  } else if (_currentEnvelope.v === VAULT_FORMAT_V3) {
    newEnvelope = await changePasswordV3(
      _currentEnvelope, _currentKVault, newPassword,
      prfOutput, currentDeviceId(), recoveryMaterial,
    );
  } else if (_currentEnvelope.v === VAULT_FORMAT_V2) {
    newEnvelope = await changePasswordV2(
      _currentEnvelope, _currentKVault, newPassword, prfOutput, recoveryMaterial,
    );
  } else {
    throw new Error("この envelope 形式では password 変更に対応していません");
  }
  await _saveRewrappedEnvelope(newEnvelope);
  return {
    alg: newEnvelope.alg,
    invalidatedOtherDevices:
      _currentEnvelope.v === VAULT_FORMAT_V3 || _currentEnvelope.v === VAULT_FORMAT_V4,
  };
}

/**
 * Rotate the Passkey binding on this device. Useful after losing a Passkey,
 * getting a new authenticator, or sharing between devices via a single
 * unlocking authenticator.
 */
export async function rotatePasskey(password, recoveryString) {
  if (!_currentKVault || !_currentEnvelope) {
    throw new Error("ドライブのロックを解除した状態から実行してください");
  }
  // v3 / v4 vaults are multi-device by construction — the natural way to
  // "rotate the Passkey on this device" is to add the device fresh
  // (registers a new credential) and remove the old credential by deviceId.
  // Force the user through that flow rather than silently writing a v2
  // envelope on top of a v3/v4 vault.
  if (_currentEnvelope.v === VAULT_FORMAT_V3 || _currentEnvelope.v === VAULT_FORMAT_V4) {
    throw new Error(
      "この端末の Passkey の単独回転は対応していません。" +
        "別端末追加フロー（Recovery Secret で新規 Passkey を登録）をご利用ください。",
    );
  }
  if (_currentEnvelope.v !== VAULT_FORMAT_V2) {
    throw new Error("このドライブ形式は Passkey 回転に対応していません");
  }
  const identity = readClientIdentity();
  const { credentialId, prfEnabled } =
    await registerPasskey(identity.vaultId.slice(0, 8), identity.vaultId);
  if (!prfEnabled) throw new Error("この認証器は Passkey PRF 拡張に対応していません");
  const newPrf = await authenticateWithPasskey(credentialId);
  const recoveryMaterial = await recoverySecretToMaterial(recoveryString);

  const newEnvelope = await changePasskeyV2(
    _currentEnvelope, _currentKVault, password, newPrf, recoveryMaterial,
  );
  await _saveRewrappedEnvelope(newEnvelope);

  // Swap the locally-remembered Passkey info to the freshly-registered one.
  storePasskey({ credentialId, prfEnabled });
  return { credentialId };
}

/**
 * Re-issue the Recovery Secret. This is a FULL identity migration:
 *   1. Generate a fresh Recovery Secret R'.
 *   2. Derive a new ECDSA identity from R'. (vault-id changes.)
 *   3. POST /api/vault/migrate signed by the OLD identity to authorize the
 *      new vault-id and transfer credit balance.
 *   4. Re-encrypt the current vault content with R' (new K_vault, new
 *      anonymized App-Name tag) and write a fresh v4 envelope at the new
 *      vault-id.
 *   5. Switch localStorage identity + meta to the new vault.
 *
 * Pre-conditions:
 *   - The session is unlocked (we hold the current vault content in memory).
 *   - We hold the old identity's private key in localStorage (for signing
 *     the migrate request).
 *   - The current device's Passkey is registered (its PRF output is needed
 *     for the new envelope's wrap_pk + wrap_kr).
 *
 * Returns: { recoverySecret: "RS1-...", oldVaultId, newVaultId }
 *
 * The caller MUST surface the new Recovery Secret to the user with a
 * one-time-display flow and require explicit confirmation before clearing
 * it from the DOM. This is the ONLY chance to capture the new secret.
 */
export async function reissueRecoverySecret(password) {
  if (!_currentKVault || !_currentEnvelope) {
    throw new Error("ドライブのロックを解除した状態から実行してください");
  }
  if (_currentEnvelope.v !== VAULT_FORMAT_V3 && _currentEnvelope.v !== VAULT_FORMAT_V4) {
    throw new Error("この envelope 形式では Recovery 再発行に対応していません");
  }
  const cache = readMeta();
  const credId = cache?.passkeyCredentialId;
  if (!credId) throw new Error("Passkey が登録されていません");

  // Decrypt the current vault content one more time so we have the JSON we
  // need to re-encrypt under the new key.
  const prfOutput = await authenticateWithPasskey(credId);
  let currentVault;
  if (_currentEnvelope.v === VAULT_FORMAT_V4) {
    const dec = await decryptVaultV4(_currentEnvelope, { password, prfOutput }, { credentialId: credId });
    currentVault = dec.vault;
  } else {
    const dec = await decryptVaultV3(_currentEnvelope, { password, prfOutput }, { credentialId: credId });
    currentVault = dec.vault;
  }

  // 1) Generate the new Recovery Secret + materials.
  const newRecoveryString = generateRecoverySecret();
  const newRecoveryMaterial = await recoverySecretToMaterial(newRecoveryString);

  // 2) Derive the new ECDSA identity deterministically from the new R.
  const newKeypair = await deriveIdentityKeypair(newRecoveryString);
  const newCanonicalPub = {
    kty: newKeypair.publicKeyJwk.kty,
    crv: newKeypair.publicKeyJwk.crv,
    x: newKeypair.publicKeyJwk.x,
    y: newKeypair.publicKeyJwk.y,
    ext: true,
    key_ops: ["verify"],
  };
  const newPublicKeyString = JSON.stringify(newCanonicalPub);

  // 3) Authenticate to /api/vault/migrate with the OLD identity so the
  //    server transfers credits.
  const migrateRes = await signedFetch("/api/vault/migrate", "POST", {
    newPublicKey: newPublicKeyString,
  });
  if (!migrateRes.ok) {
    throw new Error(migrateRes.error ?? "migrate API failed");
  }
  const newVaultId = migrateRes.newVaultId;

  // 4) Switch localStorage identity to the new keypair BEFORE we sign
  //    the next /api/write (which will use the new identity).
  const newIdentity = {
    vaultId: newVaultId,
    publicKeyJwk: newCanonicalPub,
    privateKeyJwk: newKeypair.privateKeyJwk,
    createdAt: new Date().toISOString(),
    migratedFrom: migrateRes.oldVaultId,
  };
  localStorage.setItem("arpass_client_v1", JSON.stringify(newIdentity));

  // Update local meta so subsequent operations write under the new tag.
  const newAppNameTag = await deriveAppNameTag(newRecoveryMaterial);

  // Register a fresh Passkey on this device for the new vault. The new
  // envelope's wrap_pk is keyed by THIS device's PRF + new password.
  const reg = await registerPasskey(newVaultId.slice(0, 8), newVaultId);
  if (!reg.prfEnabled) {
    throw new Error("Passkey PRF 拡張が利用できないため再発行が完了できません");
  }
  storePasskey({ credentialId: reg.credentialId, prfEnabled: true });
  const newPrf = await authenticateWithPasskey(reg.credentialId);

  // 5) Encrypt the existing vault content under the new R + new Passkey
  //    PRF, producing a fresh v4 envelope at the new vault-id. We pass
  //    the user-chosen device meta from the local meta cache.
  const deviceId = currentDeviceId();
  const deviceName = currentDeviceName();
  const { envelope: newEnvelope, kVault: newKVault } = await encryptVaultV4(
    currentVault, password, newPrf, newRecoveryMaterial,
    { deviceId, credentialId: reg.credentialId, name: deviceName },
  );

  // 6) Write the new envelope to Arweave under the new vault-id with the
  //    new anonymized App-Name tag. signedFetch will now sign with the
  //    new identity (which we just installed in localStorage above).
  const body = {
    data: _envelopeToJson(newEnvelope),
    contentType: "application/json",
    tags: {
      [APP_NAME_TAG]: newAppNameTag,
    },
    // First write under the NEW vaultId — server should have null.
    expectedLatestTxId: null,
  };
  const writeRes = await signedFetch("/api/write", "POST", body);
  if (!writeRes.ok) {
    // Rollback would be nice but is non-trivial — the server has already
    // migrated. Surface the error and hope the next save retries cleanly.
    // Wrap with writeError so 402 / insufficient_credits stays detectable
    // by the UI (e.g. to offer a "buy credits" button).
    throw writeError(writeRes, `新 envelope の書き込みに失敗: ${writeRes.error ?? "unknown"}`);
  }

  // 7) Update in-memory + persistent caches to the new state.
  _currentKVault = newKVault;
  _currentEnvelope = newEnvelope;
  writeMeta({
    salt: newEnvelope.kdf.salt,
    iterations: newEnvelope.kdf.iterations,
    alg: newEnvelope.alg,
    latestTxId: writeRes.txid,
    appNameTag: newAppNameTag,
  });

  return {
    recoverySecret: newRecoveryString,
    oldVaultId: migrateRes.oldVaultId,
    newVaultId: migrateRes.newVaultId,
    txid: writeRes.txid,
  };
}

/**
 * @deprecated Replaced by `reissueRecoverySecret()`. Kept temporarily for
 * binary compatibility with callers that haven't migrated yet — points at
 * the new flow.
 */
export async function rotateRecoverySecret(password) {
  return reissueRecoverySecret(password);
}

/**
 * List the authorized devices recorded in the current v3/v4 envelope.
 * Returns a single-entry list for v2 / v1 envelopes (they are single-device
 * by construction).
 */
export function listAuthorizedDevices() {
  if (!_currentEnvelope) return [];
  const v = _currentEnvelope.v;
  if (v !== VAULT_FORMAT_V3 && v !== VAULT_FORMAT_V4) {
    // Legacy single-device envelope.
    return [{ deviceId: currentDeviceId(), name: currentDeviceName(), current: true, legacy: true }];
  }
  const me = currentDeviceId();
  return (_currentEnvelope.devices || []).map((d) => ({
    ...d,
    current: d.deviceId === me,
  }));
}

/**
 * Remove an authorized device. Must be v3 or v4 envelope. Cannot remove
 * THIS device (caller should use `forgetClientIdentity()` for that case,
 * which also wipes the local keystore).
 */
export async function removeAuthorizedDevice(deviceId) {
  if (!_currentEnvelope) throw new Error("ドライブがロック解除されていません");
  const v = _currentEnvelope.v;
  if (v !== VAULT_FORMAT_V3 && v !== VAULT_FORMAT_V4) {
    throw new Error("ドライブのロック解除中にのみ使えます");
  }
  if (deviceId === currentDeviceId()) {
    throw new Error("この端末は自分自身なので、削除ではなく『この端末をリセット』を使ってください");
  }
  const remove = v === VAULT_FORMAT_V4 ? removeDeviceV4 : removeDeviceV3;
  const newEnvelope = remove(_currentEnvelope, deviceId);
  await _saveRewrappedEnvelope(newEnvelope);
}

/** Rename an authorized device. Metadata-only change, no crypto. */
export async function renameAuthorizedDevice(deviceId, newName) {
  if (!_currentEnvelope) throw new Error("ドライブがロック解除されていません");
  const v = _currentEnvelope.v;
  if (v !== VAULT_FORMAT_V3 && v !== VAULT_FORMAT_V4) {
    throw new Error("ドライブのロック解除中にのみ使えます");
  }
  const cleaned = String(newName || "").trim();
  if (!cleaned) throw new Error("名前は空にできません");
  const rename = v === VAULT_FORMAT_V4 ? renameDeviceV4 : renameDeviceV3;
  const newEnvelope = rename(_currentEnvelope, deviceId, cleaned);
  if (deviceId === currentDeviceId()) setCurrentDeviceName(cleaned);
  await _saveRewrappedEnvelope(newEnvelope);
}

/** Internal: save a rewrapped envelope and update local caches. */
async function _saveRewrappedEnvelope(newEnvelope) {
  const cache = readMeta();
  const body = {
    data: _envelopeToJson(newEnvelope),
    contentType: "application/json",
    tags: {
      [APP_NAME_TAG]: currentAppNameTag(),
    },
    // Optimistic concurrency — same as saveVault.
    expectedLatestTxId: cache?.latestTxId ?? null,
  };
  const result = await signedFetch("/api/write", "POST", body);
  if (!result.ok) throw writeError(result, "rewrap save failed");
  _currentEnvelope = newEnvelope;
  writeMeta({
    salt: newEnvelope.kdf.salt,
    iterations: newEnvelope.kdf.iterations,
    alg: newEnvelope.alg,
    latestTxId: result.txid,
  });
  return result;
}

function emptyVault() {
  return {
    v: 1,
    entries: [],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
}

/**
 * Check an Arweave transaction's status by id.
 * Returns { state, confirmations, blockHeight, blockIndepHash }.
 *
 *   state:
 *     "bundling"  — Turbo accepted the data item and the CDN is already
 *                   serving the bytes, but the outer bundle hasn't been
 *                   confirmed on Arweave L1 yet (typically clears in
 *                   2–5 min). The vault is already SAFE and READABLE;
 *                   only `/tx/{id}/status` hasn't caught up.
 *     "pending"   — accepted by L1 gateway, not yet mined
 *     "confirmed" — mined into a block (check `confirmations`)
 *     "not_found" — neither L1 status nor any CDN has ever seen this id
 *                   (genuinely lost / pre-propagation)
 *     "error"     — network / parse failure
 */
export async function getTxStatus(txid) {
  try {
    // For Turbo-bundled writes (BUNDLER_BACKEND=turbo) the txid we hold
    // is a *data item* id — the outer Arweave L1 transaction is the
    // bundle. arweave.net/tx/{dataItemId}/status returns 404 for these
    // even after the bundle has been mined for hours, because that
    // endpoint only resolves L1 transactions. So we ALWAYS check
    // GraphQL first: it understands data items, exposing both the
    // data-item's own block info (if its bundle is confirmed) and the
    // bundledIn field. Only if GraphQL has no record do we fall back
    // to L1 /tx/status (covers BUNDLER_BACKEND=direct writes).
    const gql = await queryTxStatusGraphQL(txid);
    if (gql) return gql;

    const r = await fetch(`${ARWEAVE_GATEWAY}/tx/${txid}/status`, { cache: "no-store" });
    if (r.status === 404) {
      // L1 doesn't know this tx yet. With Turbo, the outer bundle takes a
      // few minutes to land — but the data item is already served by the
      // Turbo CDN (and arweave.net's edge cache) the moment Turbo accepts
      // it. Probe the data endpoints to distinguish "bundling, already
      // readable" from "genuinely not found".
      const reachableVia = await probeDataReachable(txid);
      if (reachableVia) return { state: "bundling", via: reachableVia };
      return { state: "not_found" };
    }
    if (r.status === 429) {
      // Public gateway is rate-limiting us. Respect Retry-After if present.
      const ra = r.headers.get("retry-after");
      const retryAfterSeconds = ra ? Math.max(1, parseInt(ra, 10) || 60) : 60;
      return { state: "rate_limited", retryAfterSeconds };
    }
    if (r.status === 202 || r.status === 200) {
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
        // Some gateways return plain "Pending" with 200.
        return { state: "pending" };
      }
    }
    return { state: "error", httpStatus: r.status };
  } catch (e) {
    return { state: "error", message: e?.message ?? String(e) };
  }
}

/**
 * Lightweight reachability probe used when /tx/{id}/status returns 404.
 *
 * Tries the Turbo gateway first (Turbo serves data items the moment they're
 * accepted, well before the bundle is mined), then arweave.net (which has
 * its own edge cache that often catches Turbo items quickly).
 *
 * Returns the gateway base URL that responded, or null.
 *
 * Uses a Range: bytes=0-0 GET — HEAD is sometimes blocked by upstream
 * caches, and Range guarantees we don't pull the full payload just to
 * learn that something exists.
 */
async function probeDataReachable(txid) {
  const candidates = [TURBO_GATEWAY, ARWEAVE_GATEWAY];
  for (const base of candidates) {
    try {
      const r = await fetch(`${base}/${txid}`, {
        method: "GET",
        headers: { Range: "bytes=0-0" },
        cache: "no-store",
        redirect: "follow",
      });
      // 200 OK or 206 Partial Content both prove the bytes are available.
      if (r.ok || r.status === 206) return base;
    } catch {
      // Network/CORS error → try the next candidate.
    }
  }
  return null;
}

/**
 * Resolve the status of a tx (potentially a data item) via GraphQL.
 *
 * GraphQL understands data items, exposing both the data-item's own
 * `block { height timestamp }` field — which is populated once the
 * containing bundle is mined — and `bundledIn { id }` which tells us
 * the bundle has been submitted but not yet confirmed.
 *
 * Returns:
 *   { state: "confirmed", confirmations, blockHeight, blockIndepHash } when block info present
 *   { state: "bundling",  via: "turbo-graphql" } when bundledIn is set but block isn't
 *   null when GraphQL has no record of the tx (caller falls back to L1 status probe)
 */
async function queryTxStatusGraphQL(txid) {
  async function askForId(gateway, id) {
    const query = `
      query {
        transactions(ids: ["${id}"]) {
          edges { node { id block { height timestamp } bundledIn { id } } }
        }
      }
    `;
    try {
      const resp = await fetch(`${gateway}/graphql`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query }),
      });
      if (!resp.ok) return null;
      const data = await resp.json();
      return data?.data?.transactions?.edges?.[0]?.node ?? null;
    } catch {
      return null;
    }
  }

  // Try Turbo's GraphQL first — it's the fastest to know about
  // freshly-confirmed bundles. Fall back to arweave.net which carries
  // the canonical view.
  const node = (await askForId(TURBO_GATEWAY, txid)) ?? (await askForId(ARWEAVE_GATEWAY, txid));
  if (!node) return null;

  // Standard Arweave GraphQL resolves `block` on a data item to the
  // block of its containing bundle. If we got it directly, we're done.
  if (typeof node.block?.height === "number" && node.block.height > 0) {
    return {
      state: "confirmed",
      confirmations: 2,
      blockHeight: node.block.height,
      blockIndepHash: null,
    };
  }

  // Data-item .block lookup lag: Turbo's GraphQL has been observed to
  // know `bundledIn` long before it propagates the bundle's `.block`
  // info onto the data item. Probe the bundle's own status directly —
  // it's a regular L1 tx with reliable block data once mined.
  if (node.bundledIn?.id) {
    const bundle = (await askForId(TURBO_GATEWAY, node.bundledIn.id))
                ?? (await askForId(ARWEAVE_GATEWAY, node.bundledIn.id));
    if (typeof bundle?.block?.height === "number" && bundle.block.height > 0) {
      return {
        state: "confirmed",
        confirmations: 2,
        blockHeight: bundle.block.height,
        blockIndepHash: null,
        // Helpful for diagnostics in the UI's title attribute.
        confirmedVia: "bundle",
        bundleId: node.bundledIn.id,
      };
    }
    // Bundle exists but isn't mined yet.
    return { state: "bundling", via: "turbo-graphql", bundleId: node.bundledIn.id };
  }

  // GraphQL knows the data item exists (otherwise edges would be empty)
  // but neither bundle nor block info — still in Turbo's pre-submission
  // queue. Treat as bundling so the badge stays "📦 配信中".
  return { state: "bundling", via: "turbo-graphql" };
}

/**
 * Public read URL for a tx, biased toward whichever gateway will serve it
 * fastest. Used by the UI to render the link in the header badge.
 */
export function publicReadUrl(txid, { preferTurbo = true } = {}) {
  if (preferTurbo) return `${TURBO_GATEWAY}/${txid}`;
  return `${ARWEAVE_GATEWAY}/${txid}`;
}

/**
 * Make a random UUID without requiring crypto.randomUUID (not in all runtimes yet).
 */
export function newEntryId() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
