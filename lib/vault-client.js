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
  padPlaintext,
  unpadPlaintext,
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

export async function authenticateWithPasskey(credentialIdHint = null, options = {}) {
  // Phase 5.3-J: 「hint 経路 + picker fallback」のハイブリッド。
  //
  //   - credentialIdHint がある & options.forcePicker !== true:
  //       allowCredentials = [{ id: hint }] で auto-fill 期待 (1 クリック)
  //       → ただし hint Passkey が消えてる / ユーザーがキャンセルした場合は
  //         呼び出し側が自動 retry (forcePicker:true) する
  //   - credentialIdHint なし、または forcePicker:true:
  //       allowCredentials = [] で全候補ピッカーを表示
  //
  // これで:
  //   - 通常: 1 クリック (hint で前回 Passkey が auto-select)
  //   - 別 Passkey に切替: 呼び出し側が forcePicker:true で再呼出 → picker
  //   - hint Passkey 消失: 呼び出し側が catch して forcePicker:true で再呼出
  if (!navigator.credentials?.get) throw new Error("WebAuthn unavailable");
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const usePicker = options.forcePicker || !credentialIdHint;
  const allowCredentials = usePicker
    ? []
    : [{ type: "public-key", id: credentialIdHint }];
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
  // 4. 空 vault → v5 envelope (credentials リストにこの端末を 1 個目として登録)
  const vault = emptyVault();
  vault.credentials = [{
    credIdHash,
    name: userDisplayName,
    addedAt: new Date().toISOString(),
  }];
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
 *
 * @param {string} password
 * @param {object} [options]
 *   forcePicker: 強制的にピッカーを開く (UI の「🔄 別の Passkey を選ぶ」用)
 */
export async function unlockWithPasswordAndPasskey(password, options = {}) {
  const meta = readMeta();
  if (!meta?.vaultId || !meta?.appNameTag) {
    throw new Error("この端末で初めて利用する場合は「すでにアカウントがある」から復元してください");
  }
  const vaultIdBytes = b64uDecode(meta.vaultId);

  // Phase 5.3-J: ハイブリッド経路
  //   1. forcePicker でなく credentialId hint があれば → hint で 1-click auth
  //   2. hint Passkey が消えてる / ユーザーがキャンセル → picker fallback
  //   3. picker で選択 → ここでも復号失敗なら呼び出し側で再 picker (UI 任せ)
  const credIdHint = (!options.forcePicker && meta.credentialId)
    ? b64uDecode(meta.credentialId)
    : null;

  let credentialId, prfOutput;
  try {
    ({ credentialId, prfOutput } = await authenticateWithPasskey(credIdHint, {
      forcePicker: options.forcePicker || false,
    }));
  } catch (e) {
    // hint Passkey が消えてた / NotAllowed (cancel) → picker fallback
    if (credIdHint) {
      console.log("[unlock] hint Passkey unavailable, opening picker:", e?.message);
      ({ credentialId, prfOutput } = await authenticateWithPasskey(null, { forcePicker: true }));
    } else {
      throw e;
    }
  }
  const credIdHash = await credentialIdToHash(credentialId);

  const txid = await resolveLatestTxIdForUnlock(meta);
  if (!txid) throw new Error("Vault が Arweave 上に見つかりません (まだ書き込みなし？)");
  const { envelope } = await fetchEnvelope(txid, vaultIdBytes);

  // ★ Phase 5.3-I: 復号 BEFORE patchMeta (間違った Passkey 選択時の汚染防止)
  let vault, mek, path;
  try {
    ({ vault, mek, path } = await decryptVault(envelope, { password, prfOutput, credIdHash }));
  } catch (e) {
    // この Passkey で復号できなかった → 別の Passkey を試したいユーザー向けに
    // 識別可能なエラーを投げる。呼び出し側 (UI) が「🔁 別の Passkey で再試行」
    // ボタンを出して再呼出 (forcePicker:true) すればよい。
    const retryErr = new Error(
      "選択した Passkey ではドライブを開けませんでした。「🔁 別の Passkey で再試行」を試してください。"
    );
    retryErr.code = "passkey_wrong_for_vault";
    retryErr.original = e;
    throw retryErr;
  }

  // 復号成功 → この credentialId は確かに **この vault に登録済**と確認できた。
  // ここで初めて meta を更新する。
  if (!meta.credentialId || meta.credentialId !== b64uEncode(credentialId)) {
    patchMeta({ credentialId: b64uEncode(credentialId), credIdHash });
  }
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
  const padded = padPlaintext(new TextEncoder().encode(JSON.stringify(updatedVault)));
  const bodyCt = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: ivBody }, mekKey, padded));

  const newEnvelope = {
    v: VAULT_FORMAT_V5,
    s: _session.lastEnvelope.s,
    i: b64uEncode(ivBody),
    c: b64uEncode(bodyCt),
    w: JSON.parse(JSON.stringify(_session.lastEnvelope.w)),
  };
  const writeResult = await writeEnvelope(
    newEnvelope, _session.vaultId, _session.appNameTag, _session.signingState,
    { expectedLatestTxId: _session.latestTxId }   // Phase 5.3 楽観ロック
  );
  _session.vault = updatedVault;
  _session.lastEnvelope = newEnvelope;
  _session.latestTxId = writeResult.txid;
  patchMeta({ latestTxId: writeResult.txid });
  return writeResult;
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
  // vault.credentials にも端末メタを追加 (UI の登録端末リスト用)
  if (!Array.isArray(_session.vault.credentials)) _session.vault.credentials = [];
  // 既存の credIdHash があれば置き換え (同一端末の Passkey 再登録)
  _session.vault.credentials = _session.vault.credentials.filter(c => (c.credIdHash || c.id) !== credIdHash);
  _session.vault.credentials.push({
    credIdHash,
    name: userDisplayName,
    addedAt: new Date().toISOString(),
  });
  // saveVault は本体 c を再暗号化するので、上の変更を反映するため
  // newEnvelope を一旦差し戻してから saveVault を通す
  _session.lastEnvelope = newEnvelope;
  await saveVault(_session.vault);  // ← これが本体 c に credentials を入れて再暗号化
  // saveVault が新 latestTxId / lastEnvelope を更新済み
  _session.currentCredIdHash = credIdHash;
  _session.currentCredentialId = credentialId;
  patchMeta({
    credIdHash, credentialId: b64uEncode(credentialId),
    latestTxId: _session.latestTxId,
  });
  return { txid: _session.latestTxId };
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
// refreshFromServerLatest (Phase 5.3-D)
// ---------------------------------------------------------------------------

/**
 * unlock 直後に呼ばれる想定。サーバ側 KV の最新 latestTxId を取得し、
 * 我々が今 session に持っている vault と差があるか確認する。
 *
 * - server.latestTxId === session.latestTxId → 何もしない (cache は最新)
 * - server.latestTxId !== session.latestTxId → 別端末で更新あり
 *     1. fetchEnvelope(server.latestTxId, vaultId) で新 envelope を取得
 *        (cache に hit すれば即時、なければ network。Phase 5.3 cache-first 経路)
 *     2. session に保存済の MEK で本体 c を復号 → 新 vault JSON
 *     3. session を更新 (vault / lastEnvelope / latestTxId)
 *     4. localStorage の meta.latestTxId も更新
 *
 * 楽観ロック (saveVault が送る expectedLatestTxId) は session.latestTxId を
 * 参照するため、refresh 後は最新の txid に更新されている → 上書きが可能になる。
 *
 * @returns {Promise<{
 *   refreshed: boolean,
 *   latestTxId: string | null,
 *   oldTxId?: string,
 *   vault?: object,
 *   entriesBefore?: number,
 *   entriesAfter?: number,
 * }>}
 */
export async function refreshFromServerLatest() {
  if (!_session) throw new Error("locked");
  const serverInfo = await getBalance(_session.signingState);
  const serverTxId = serverInfo?.latestTxId ?? null;
  const oldTxId = _session.latestTxId;

  if (!serverTxId) return { refreshed: false, latestTxId: oldTxId };
  if (serverTxId === oldTxId) return { refreshed: false, latestTxId: oldTxId };

  // 別端末更新を検知 → 最新 envelope を取得して再復号
  const { envelope } = await fetchEnvelope(serverTxId, _session.vaultId);
  const newVault = await _decryptBodyWithSessionMek(envelope);

  const entriesBefore = _session.vault?.entries?.length ?? 0;
  const entriesAfter  = newVault?.entries?.length ?? 0;

  _session.vault = newVault;
  _session.lastEnvelope = envelope;
  _session.latestTxId = serverTxId;
  patchMeta({ latestTxId: serverTxId });

  return {
    refreshed: true,
    latestTxId: serverTxId,
    oldTxId,
    vault: newVault,
    entriesBefore,
    entriesAfter,
  };
}

/**
 * 既に MEK は session にあるので、envelope の本体 c を直接 AES-GCM 復号する。
 * decryptVault を経由しないのは、unlock 時の factors (password / prfOutput /
 * recoveryMaterial) を session に保持していないため。MEK ベース直接復号は
 * 暗号学的に同等。
 */
async function _decryptBodyWithSessionMek(envelope) {
  if (!_session?.mek) throw new Error("locked");
  const mekKey = await crypto.subtle.importKey(
    "raw", _session.mek, { name: "AES-GCM" }, false, ["decrypt"]
  );
  const paddedBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64uDecode(envelope.i) },
    mekKey,
    b64uDecode(envelope.c)
  );
  const real = unpadPlaintext(new Uint8Array(paddedBuf));
  return JSON.parse(new TextDecoder().decode(real));
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
 * @param {Object} [opts]
 * @param {string} [opts.locale]    Stripe Checkout の locale (例: "en", "ja", "zh")
 *                                  未指定時はサーバ側で "auto"
 * @param {string} [opts.currency]  決済通貨 ("jpy" / "usd")。
 *                                  未指定時はサーバ側で "jpy" (= ja デフォルト)。
 * @returns {Promise<{ url: string, sessionId: string, currency, unitAmount, ... }>}
 */
export async function checkoutSessionUI(packKey, opts = {}) {
  if (!_session) throw new Error("locked — unlock first");
  const body = { pack: packKey };
  if (opts.locale) body.locale = opts.locale;
  if (opts.currency) body.currency = opts.currency;
  const r = await signedFetch("/api/checkout", "POST", body, _session.signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) throw new Error(`checkout failed: ${j.error || r.status}`);
  return j;  // { ok: true, url, sessionId, pack, credits, currency, unitAmount, priceJpy, publicKeyHash }
}

/**
 * envelope の w.b[] と w.c[] から、指定 credIdHash の wrap を除去する。
 * UI 設定画面の「端末を削除」フローから呼ばれる。
 *
 * 注: この関数は MEK を変更しないので、削除した端末側に MEK のコピーが
 * すでに残っていた場合は依然として復号できる。完全な「無効化」は
 * Recovery Secret rotation (Case B) で MEK を再生成する必要がある。
 *
 * @param {string} credIdHash 削除する Passkey の credIdHash (16 文字 base64url)
 */
export async function removeCredentialFromEnvelopeUI(credIdHash) {
  if (!_session) throw new Error("locked — unlock first");
  if (!_session.lastEnvelope) throw new Error("session に直近 envelope がありません");
  const env = _session.lastEnvelope;
  const newW = {
    a: env.w.a,
    b: (env.w.b || []).filter(w => w.h !== credIdHash),
    c: (env.w.c || []).filter(w => w.h !== credIdHash),
  };
  // 何も削除できなかった場合 (= 該当 credIdHash の wrap が無かった) は no-op
  if (newW.b.length === (env.w.b || []).length && newW.c.length === (env.w.c || []).length) {
    return { txid: _session.latestTxId, removed: false };
  }
  const newEnvelope = { ...env, w: newW };
  const writeResult = await writeEnvelope(
    newEnvelope, _session.vaultId, _session.appNameTag, _session.signingState
  );
  _session.lastEnvelope = newEnvelope;
  _session.latestTxId = writeResult.txid;
  patchMeta({ latestTxId: writeResult.txid });
  return { txid: writeResult.txid, removed: true };
}
