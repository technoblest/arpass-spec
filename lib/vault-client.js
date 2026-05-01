// ============================================================================
// web/lib/vault-client-v5.js
//
// Arpass v5 ハイレベル vault クライアント。
//
// app.html / UI からはこのモジュールを叩く。内部的に:
//   - vault-crypto-v5.js (暗号操作)
//   - client-auth-v5.js  (API + Arweave 読み書き、外側暗号化込み)
//   - WebAuthn (PRF)
// を組み合わせて、ユーザー操作を vault 永続化につなぐ。
//
// 主な責務:
//   - createVault (新規アカウント作成 + 初回 Arweave 書き込み)
//   - unlock (Path AB / AC / BC) → セッション開始
//   - saveVault (差分書き戻し、credit 1 消費)
//   - addCredentialOnThisDevice (新端末追加、Recovery 必須)
//   - changePassword (Master 変更、Recovery 必須)
//   - reissueRecovery_caseA / caseB (Recovery 再発行 2 種)
//   - lockSession (メモリ上の秘密を全消去)
// ============================================================================

import {
  encryptVault,
  decryptVault,
  addCredential,
  changePassword,
  changeRecovery_caseA,
  changeRecovery_caseB,
  deriveSigningKey,
  importSigningKeyPair,
  deriveVaultId,
  deriveAppNameTag,
  deriveRMat,
  hashPublicKey,
  credentialIdToHash,
  b64uEncode,
  b64uDecode,
  VAULT_FORMAT_V5,
} from "./vault-crypto.js";

import {
  readMeta,
  writeMeta,
  patchMeta,
  clearMeta,
  registerVault,
  getBalance,
  migrateAccount,
  fetchEnvelope,
  findLatestVaultTx,
  writeEnvelope,
} from "./client-auth.js";

// ---------------------------------------------------------------------------
// セッション (in-memory secrets, lockSession で消える)
// ---------------------------------------------------------------------------

let _session = null;
/*
  _session shape:
    {
      vault:           object,             復号済み vault データ
      mek:             Uint8Array(32),     対称鍵
      vaultId:         Uint8Array(16),     外側暗号化用
      appNameTag:      string,             Arweave タグ
      recoveryMaterial: Uint8Array(32) | null,
                       null は Path AB unlock で Recovery 未入力なときの値
                       (rotation や addCredential で必要なら別途入力させる)
      signingState: {
        signingPrivateKey: CryptoKey,
        signingPublicKey:  CryptoKey,
        publicKeyRaw:      Uint8Array(65),
        publicKeyJwk:      object,
      },
      currentCredIdHash: string | null,    この端末の Passkey 識別子
      currentCredentialId: Uint8Array | null,
      latestTxId:      string | null,
      lastEnvelope:    object,             直近の v5 envelope (saveVault 時に wrap を流用)
    }
*/

export function isUnlocked() { return !!_session; }
export function currentVault() { return _session?.vault ?? null; }
export function currentVaultId() { return _session?.vaultId ? b64uEncode(_session.vaultId) : null; }
export function currentLatestTxId() { return _session?.latestTxId ?? null; }
export function currentCredIdHash() { return _session?.currentCredIdHash ?? null; }
export function hasRecoveryInSession() { return !!_session?.recoveryMaterial; }

/** メモリ上の秘密を全消去。localStorage は残す (vault-id 等のキャッシュ)。 */
export function lockSession() {
  if (_session) {
    if (_session.mek) _session.mek.fill(0);
    if (_session.recoveryMaterial) _session.recoveryMaterial.fill(0);
    if (_session.signingState?.publicKeyRaw) _session.signingState.publicKeyRaw.fill(0);
  }
  _session = null;
}

async function buildSigningState(mek) {
  const sk = deriveSigningKey(mek);
  const { privateKey, publicKey } = await importSigningKeyPair(sk.privateKeyJwk, sk.publicKeyJwk);
  return {
    signingPrivateKey: privateKey,
    signingPublicKey: publicKey,
    publicKeyRaw: sk.publicKeyRaw,
    publicKeyJwk: sk.publicKeyJwk,
  };
}

async function openSession({ vault, mek, vaultId, appNameTag, recoveryMaterial,
                             credIdHash, credentialId, latestTxId, lastEnvelope }) {
  const signingState = await buildSigningState(mek);
  const publicKeyHash = await hashPublicKey(signingState.publicKeyRaw);
  patchMeta({ publicKeyHash });
  _session = {
    vault, mek, vaultId, appNameTag,
    recoveryMaterial: recoveryMaterial ?? null,
    signingState,
    currentCredIdHash: credIdHash ?? null,
    currentCredentialId: credentialId ?? null,
    latestTxId: latestTxId ?? null,
    lastEnvelope: lastEnvelope ?? null,
  };
}

// ---------------------------------------------------------------------------
// WebAuthn ヘルパー (Passkey + PRF)
// ---------------------------------------------------------------------------

const RP_ID = (typeof location !== "undefined") ? location.hostname : "arpass.io";
const PRF_SALT = new TextEncoder().encode("arpass-passkey-prf-salt-v1");

export async function createPasskey(userIdString, displayName) {
  if (!navigator.credentials?.create) throw new Error("WebAuthn unavailable");
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userIdBytes = new TextEncoder().encode(userIdString);
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { id: RP_ID, name: "Arpass" },
      user: { id: userIdBytes, name: displayName, displayName },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }], // ES256 + RS256 (browser warning 回避)
      authenticatorSelection: { userVerification: "preferred", residentKey: "preferred" },
      extensions: { prf: { eval: { first: PRF_SALT } } },
      timeout: 60000,
    },
  });
  if (!cred) throw new Error("Passkey creation cancelled");
  const ext = cred.getClientExtensionResults?.();
  const prfOutput = ext?.prf?.results?.first ? new Uint8Array(ext.prf.results.first) : null;
  if (!prfOutput) throw new Error("PRF extension required but not returned by authenticator");
  return { credentialId: new Uint8Array(cred.rawId), prfOutput };
}

export async function authenticateWithPasskey(credentialIdHint = null) {
  if (!navigator.credentials?.get) throw new Error("WebAuthn unavailable");
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const allowCredentials = credentialIdHint
    ? [{ type: "public-key", id: credentialIdHint }]
    : [];
  const cred = await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId: RP_ID,
      allowCredentials,
      userVerification: "preferred",
      extensions: { prf: { eval: { first: PRF_SALT } } },
      timeout: 60000,
    },
  });
  if (!cred) throw new Error("Passkey auth cancelled");
  const ext = cred.getClientExtensionResults?.();
  const prfOutput = ext?.prf?.results?.first ? new Uint8Array(ext.prf.results.first) : null;
  if (!prfOutput) throw new Error("PRF extension required but not returned");
  return { credentialId: new Uint8Array(cred.rawId), prfOutput };
}

// ---------------------------------------------------------------------------
// createVault — 新規アカウント
// ---------------------------------------------------------------------------

export async function createVault(password, userDisplayName) {
  if (!password) throw new Error("password required");
  // 1. Recovery Secret 生成 (画面に 1 度表示)
  const { generateRecoverySecret } = await import("./vault-crypto.js");
  const recoverySecret = generateRecoverySecret();
  const recoveryMaterial = deriveRMat(recoverySecret);
  const vaultId = deriveVaultId(recoveryMaterial);
  const appNameTag = deriveAppNameTag(recoveryMaterial);
  // 2. user.id 仮値 (vault-id 由来)
  const userId = b64uEncode(vaultId).slice(0, 22);
  // 3. Passkey 作成 → PRF
  const { credentialId, prfOutput } = await createPasskey(userId, userDisplayName);
  const credIdHash = await credentialIdToHash(credentialId);
  // 4. 空 vault → v5 envelope
  const vault = emptyVault();
  const enc = await encryptVault(vault, password, prfOutput, recoveryMaterial, credIdHash);
  // 5. 署名鍵を import → サーバ register
  const signingState = await buildSigningState(enc.mek);
  await registerVault(signingState.publicKeyRaw);
  // 6. envelope を Arweave に書く (外側 AES-GCM 経由)
  const writeResult = await writeEnvelope(enc.envelope, enc.vaultId, enc.appNameTag, signingState);
  // 7. localStorage メタ
  const publicKeyHash = await hashPublicKey(signingState.publicKeyRaw);
  writeMeta({
    vaultId: b64uEncode(enc.vaultId),
    appNameTag: enc.appNameTag,
    credIdHash,
    credentialId: b64uEncode(credentialId),
    publicKeyHash,
    latestTxId: writeResult.txid,
  });
  // 8. セッション
  await openSession({
    vault, mek: enc.mek,
    vaultId: enc.vaultId,
    appNameTag: enc.appNameTag,
    recoveryMaterial,
    credIdHash, credentialId,
    latestTxId: writeResult.txid,
    lastEnvelope: enc.envelope,
  });
  return { vault, latestTxId: writeResult.txid, recoverySecret };
}

// ---------------------------------------------------------------------------
// Unlock paths
// ---------------------------------------------------------------------------

/**
 * Path AB: Master + Passkey (日常 unlock、最速)
 */
export async function unlockWithPasswordAndPasskey(password) {
  const meta = readMeta();
  if (!meta?.vaultId || !meta?.appNameTag) {
    throw new Error("この端末で初めて利用する場合は「すでにアカウントがある」から復元してください");
  }
  const vaultIdBytes = b64uDecode(meta.vaultId);
  // Passkey ceremony (Mode A → Mode B fallback内部処理)
  const credIdHint = meta.credentialId ? b64uDecode(meta.credentialId) : null;
  const { credentialId, prfOutput } = await authenticateWithPasskey(credIdHint);
  const credIdHash = await credentialIdToHash(credentialId);
  // self-heal: localStorage の credentialId が古ければ更新
  if (!credIdHint || meta.credentialId !== b64uEncode(credentialId)) {
    patchMeta({ credentialId: b64uEncode(credentialId), credIdHash });
  }

  const txid = await resolveLatestTxIdForUnlock(meta);
  if (!txid) throw new Error("Vault が Arweave 上に見つかりません (まだ書き込みなし？)");
  const { envelope } = await fetchEnvelope(txid, vaultIdBytes);

  const { vault, mek, path } = await decryptVault(envelope, {
    password, prfOutput, credIdHash,
  });
  await openSession({
    vault, mek,
    vaultId: vaultIdBytes,
    appNameTag: meta.appNameTag,
    recoveryMaterial: null,
    credIdHash, credentialId,
    latestTxId: txid,
    lastEnvelope: envelope,
  });
  patchMeta({ latestTxId: txid });
  return { vault, latestTxId: txid, path };
}

/**
 * Path AC: Master + Recovery
 */
export async function unlockWithPasswordAndRecovery(password, recoveryString) {
  const recoveryMaterial = deriveRMat(recoveryString);
  const vaultId = deriveVaultId(recoveryMaterial);
  const appNameTag = deriveAppNameTag(recoveryMaterial);
  const txid = await findLatestVaultTx(appNameTag);
  if (!txid) throw new Error("この Recovery に対応する vault が Arweave 上に見つかりません");
  const { envelope } = await fetchEnvelope(txid, vaultId);
  const { vault, mek, path } = await decryptVault(envelope, {
    password, recoveryMaterial,
  });
  // localStorage を初期化 / 上書き
  writeMeta({
    vaultId: b64uEncode(vaultId),
    appNameTag,
    latestTxId: txid,
  });
  await openSession({
    vault, mek, vaultId, appNameTag,
    recoveryMaterial,
    credIdHash: null, credentialId: null,
    latestTxId: txid,
    lastEnvelope: envelope,
  });
  return { vault, latestTxId: txid, path };
}

/**
 * Path BC: Passkey + Recovery (Master 忘却時)
 */
export async function unlockWithPasskeyAndRecovery(recoveryString) {
  const recoveryMaterial = deriveRMat(recoveryString);
  const vaultId = deriveVaultId(recoveryMaterial);
  const appNameTag = deriveAppNameTag(recoveryMaterial);
  const txid = await findLatestVaultTx(appNameTag);
  if (!txid) throw new Error("この Recovery に対応する vault が Arweave 上に見つかりません");
  const { envelope } = await fetchEnvelope(txid, vaultId);
  const { credentialId, prfOutput } = await authenticateWithPasskey(null);
  const credIdHash = await credentialIdToHash(credentialId);
  const { vault, mek, path } = await decryptVault(envelope, {
    prfOutput, recoveryMaterial, credIdHash,
  });
  writeMeta({
    vaultId: b64uEncode(vaultId), appNameTag,
    credIdHash, credentialId: b64uEncode(credentialId),
    latestTxId: txid,
  });
  await openSession({
    vault, mek, vaultId, appNameTag,
    recoveryMaterial,
    credIdHash, credentialId,
    latestTxId: txid,
    lastEnvelope: envelope,
  });
  return { vault, latestTxId: txid, path };
}

// ---------------------------------------------------------------------------
// resolveLatestTxIdForUnlock — server hint → fallback to GraphQL
// 注: unlock 前は signingState がないので、localStorage hint と GraphQL のみ。
// ---------------------------------------------------------------------------

async function resolveLatestTxIdForUnlock(meta) {
  if (meta?.latestTxId) return meta.latestTxId;
  if (meta?.appNameTag) return await findLatestVaultTx(meta.appNameTag);
  return null;
}

// ---------------------------------------------------------------------------
// saveVault — 本体だけ差し替え (wrap 群は流用、credit 1 消費)
// ---------------------------------------------------------------------------

export async function saveVault(updatedVault) {
  if (!_session) throw new Error("locked — unlock first");
  if (!_session.lastEnvelope) throw new Error("session に直近 envelope がありません");

  // MEK と salt は不変、本体 c のみ再暗号化、wrap 群は再利用
  const ivBody = crypto.getRandomValues(new Uint8Array(12));
  const mekKey = await crypto.subtle.importKey("raw", _session.mek, { name: "AES-GCM" }, false, ["encrypt"]);
  const padded = padPlaintext(JSON.stringify(updatedVault));
  const bodyCt = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: ivBody }, mekKey, padded));

  const newEnvelope = {
    v: VAULT_FORMAT_V5,
    s: _session.lastEnvelope.s,
    i: b64uEncode(ivBody),
    c: b64uEncode(bodyCt),
    w: JSON.parse(JSON.stringify(_session.lastEnvelope.w)),
  };
  const writeResult = await writeEnvelope(
    newEnvelope, _session.vaultId, _session.appNameTag, _session.signingState
  );
  _session.vault = updatedVault;
  _session.lastEnvelope = newEnvelope;
  _session.latestTxId = writeResult.txid;
  patchMeta({ latestTxId: writeResult.txid });
  return writeResult;
}

function padPlaintext(jsonStr) {
  const enc = new TextEncoder().encode(jsonStr);
  const PAD_BUCKETS = [4*1024, 16*1024, 64*1024, 256*1024, 1024*1024, 4*1024*1024];
  const minRequired = enc.length + 1;
  let bucket = PAD_BUCKETS[PAD_BUCKETS.length - 1];
  for (const b of PAD_BUCKETS) {
    if (b - 16 >= minRequired) { bucket = b; break; }
  }
  const padded = new Uint8Array(bucket - 16);
  padded.set(enc, 0);
  padded[enc.length] = 0x80;
  return padded;
}

// ---------------------------------------------------------------------------
// addCredentialOnThisDevice — 新端末追加 (常に Recovery 必須、§8.1)
// ---------------------------------------------------------------------------

/**
 * 新端末の初回利用は unlockWithPasswordAndRecovery で開始 → MEK・recovery
 * を手元に持った状態でこの関数を呼ぶ。新 Passkey を作って AB / BC wrap を
 * envelope に追加し、Arweave に書き戻す。
 *
 * @param {string} password           もう一度確認入力させた Master
 * @param {string} userDisplayName    Passkey の表示名
 */
export async function addCredentialOnThisDevice(password, userDisplayName) {
  if (!_session) throw new Error("locked — unlock first");
  if (!_session.recoveryMaterial) {
    throw new Error("Recovery を要する操作です。Master + Recovery で unlock してください");
  }
  if (!_session.lastEnvelope) {
    throw new Error("session に直近 envelope がありません");
  }
  const userId = b64uEncode(_session.vaultId).slice(0, 22);
  const { credentialId, prfOutput } = await createPasskey(userId, userDisplayName);
  const credIdHash = await credentialIdToHash(credentialId);
  const newEnvelope = await addCredential(
    _session.lastEnvelope, _session.mek, password, _session.recoveryMaterial, prfOutput, credIdHash
  );
  const writeResult = await writeEnvelope(
    newEnvelope, _session.vaultId, _session.appNameTag, _session.signingState
  );
  _session.lastEnvelope = newEnvelope;
  _session.currentCredIdHash = credIdHash;
  _session.currentCredentialId = credentialId;
  _session.latestTxId = writeResult.txid;
  patchMeta({
    credIdHash, credentialId: b64uEncode(credentialId),
    latestTxId: writeResult.txid,
  });
  return writeResult;
}

// ---------------------------------------------------------------------------
// changePassword — Master 変更 (Recovery 必須)
// ---------------------------------------------------------------------------

export async function changePasswordUI(newPassword, recoveryString) {
  if (!_session) throw new Error("locked — unlock first");
  if (!_session.lastEnvelope) throw new Error("session に直近 envelope がありません");
  if (!_session.currentCredIdHash) {
    throw new Error("この端末に Passkey がありません — Recovery + Passkey で改めて unlock してください");
  }
  // 現端末 Passkey で再認証して PRF 取得 (新 AB wrap を作るため)
  const credIdHint = readMeta()?.credentialId ? b64uDecode(readMeta().credentialId) : null;
  const { prfOutput } = await authenticateWithPasskey(credIdHint);
  const recoveryMaterial = deriveRMat(recoveryString);
  const updatedEnv = await changePassword(
    _session.lastEnvelope, _session.mek, _session.currentCredIdHash,
    newPassword, prfOutput, recoveryMaterial
  );
  const writeResult = await writeEnvelope(
    updatedEnv, _session.vaultId, _session.appNameTag, _session.signingState
  );
  _session.lastEnvelope = updatedEnv;
  _session.latestTxId = writeResult.txid;
  patchMeta({ latestTxId: writeResult.txid });
  return writeResult;
}

// ---------------------------------------------------------------------------
// reissueRecovery — Case A / Case B
// ---------------------------------------------------------------------------

export async function reissueRecovery_caseA(password) {
  if (!_session) throw new Error("locked — unlock first");
  if (!_session.lastEnvelope) throw new Error("session に直近 envelope がありません");
  if (!_session.currentCredIdHash) {
    throw new Error("この端末に Passkey がありません — Recovery + Passkey で unlock してください");
  }
  const { generateRecoverySecret } = await import("./vault-crypto.js");
  const newRecovery = generateRecoverySecret();
  const newRMat = deriveRMat(newRecovery);
  const credIdHint = readMeta()?.credentialId ? b64uDecode(readMeta().credentialId) : null;
  const { prfOutput } = await authenticateWithPasskey(credIdHint);
  const result = await changeRecovery_caseA(
    _session.lastEnvelope, _session.mek, password, _session.currentCredIdHash, prfOutput, newRMat
  );
  const writeResult = await writeEnvelope(
    result.envelope, result.newVaultId, result.newAppNameTag, _session.signingState
  );
  _session.vaultId = result.newVaultId;
  _session.appNameTag = result.newAppNameTag;
  _session.recoveryMaterial = newRMat;
  _session.lastEnvelope = result.envelope;
  _session.latestTxId = writeResult.txid;
  writeMeta({
    vaultId: b64uEncode(result.newVaultId),
    appNameTag: result.newAppNameTag,
    credIdHash: _session.currentCredIdHash,
    credentialId: readMeta()?.credentialId,
    publicKeyHash: await hashPublicKey(_session.signingState.publicKeyRaw),
    latestTxId: writeResult.txid,
  });
  return { newRecovery, txid: writeResult.txid };
}

export async function reissueRecovery_caseB(password) {
  if (!_session) throw new Error("locked — unlock first");
  if (!_session.lastEnvelope) throw new Error("session に直近 envelope がありません");
  if (!_session.currentCredIdHash) {
    throw new Error("この端末に Passkey がありません — Recovery + Passkey で unlock してください");
  }
  const { generateRecoverySecret } = await import("./vault-crypto.js");
  const newRecovery = generateRecoverySecret();
  const newRMat = deriveRMat(newRecovery);
  const credIdHint = readMeta()?.credentialId ? b64uDecode(readMeta().credentialId) : null;
  const { prfOutput } = await authenticateWithPasskey(credIdHint);
  const result = await changeRecovery_caseB(
    _session.lastEnvelope, _session.mek, _session.vault, password,
    _session.currentCredIdHash, prfOutput, newRMat
  );
  // 旧 signingState で書き込み (まだ credit 課金は旧アカウントで)
  const writeResult = await writeEnvelope(
    result.envelope, result.newVaultId, result.newAppNameTag, _session.signingState
  );
  // サーバ migration: 旧 KV[H(oldPK)] → 新 KV[H(newPK)] へ残高移送
  await migrateAccount(_session.signingState, result.newSigningKey.publicKeyRaw);
  // 新 identity に切替
  const newSigningState = await buildSigningState(result.newMek);
  _session.mek = result.newMek;
  _session.vaultId = result.newVaultId;
  _session.appNameTag = result.newAppNameTag;
  _session.recoveryMaterial = newRMat;
  _session.signingState = newSigningState;
  _session.lastEnvelope = result.envelope;
  _session.latestTxId = writeResult.txid;
  writeMeta({
    vaultId: b64uEncode(result.newVaultId),
    appNameTag: result.newAppNameTag,
    credIdHash: _session.currentCredIdHash,
    credentialId: readMeta()?.credentialId,
    publicKeyHash: await hashPublicKey(newSigningState.publicKeyRaw),
    latestTxId: writeResult.txid,
  });
  return { newRecovery, txid: writeResult.txid };
}

// ---------------------------------------------------------------------------
// 内部ヘルパー
// ---------------------------------------------------------------------------

function emptyVault() {
  // UI (app.html) は state.vault.entries.push() でエントリ追加するので
  // entries フィールド名で揃える。credentials は端末メタデータ用 (将来 UI で使う)。
  return {
    entries: [],
    credentials: [],
    createdAt: new Date().toISOString(),
  };
}

// 残高取得 (UI から「+ クレジット購入」判定等に使う)
export async function getBalanceUI() {
  if (!_session) throw new Error("locked");
  return await getBalance(_session.signingState);
}

// ---------------------------------------------------------------------------
// Stripe Checkout — 認証付きで /api/checkout を呼んで Stripe URL を取得する。
// ---------------------------------------------------------------------------

import { signedFetch } from "./client-auth.js";

/**
 * /api/checkout に signed POST して Stripe Checkout Session URL を返す。
 * 呼び出し側 (app.html) が unlock 済みの session を持っている前提。
 *
 * @param {string} packKey   "starter-100" / "standard-500" / etc.
 * @returns {Promise<{ url: string, sessionId: string, ... }>}
 */
export async function checkoutSessionUI(packKey) {
  if (!_session) throw new Error("locked — unlock first");
  const r = await signedFetch("/api/checkout", "POST", { pack: packKey }, _session.signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) throw new Error(`checkout failed: ${j.error || r.status}`);
  return j;  // { ok: true, url, sessionId, pack, credits, priceJpy, publicKeyHash }
}
