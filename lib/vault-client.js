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
  encryptVaultBusiness,
  decryptVaultBusiness,
  derivePMat,
  deriveBusinessMek,
  deriveBusinessMekKey,  // Phase 7.3-A.7: non-extractable mekKey 直接派生
  deriveBusinessMekHkdfKey,  // Phase 7.3-A.7b: 非 extractable HKDF base (= sub-key 派生用)
  derivePersonalMekHkdfKey,  // Phase 7.3-A.7d: Personal mode 用 HKDF base
  importRMatAsHkdfKey,        // Phase 7.3-A.8 part 2: rMat → 非 extractable HKDF base
  deriveOuterKeyFromHkdf,     // Phase 7.3-A.8 part 2: 非 extractable outerKey
  importRMatAsHandle,         // Stage 2c Stage D: rMat → Rust RMatKey opaque handle (= WASM 内)
  deriveOuterKeyFromRMat,     // Stage 2c Stage D: RMatKey → OuterKey handle (= WASM 派生)
  importOuterKeyAsHandle,     // Stage 2c Stage D3: raw 32 byte → OuterKey handle (= AB unlock 用)
  importMekRawAsHandle,       // Stage 2c Stage G2: raw 32 byte → MekKey handle (= openSession 用)
  importK1RawAsHandle,        // Stage 2c Stage G3: raw 32 byte → K1Key handle (= business unwrap 用)
  // === Phase 7.2-B v2 ===
  generateEmpKeypair,
  wrapEmpPrivWithK2,
  unwrapEmpPrivWithK2,
  unwrapEmpPrivWithK2Key,           // Phase 7.3-A.9 part 4: V2 K2 CryptoKey 経由
  importK2AsKeys,                   // Phase 7.3-A.9 part 4: V1 → V2 promote
  deriveBusinessMekKeyV2,           // Phase 7.3-A.9 part 4: K2 HKDF base + K1 salt
  deriveBusinessMekHkdfKeyV2,       // Phase 7.3-A.9 part 4: K2 HKDF base + K1 salt
  eciesWrapForRecipient,
  eciesUnwrapForRecipient,
  deriveKMat,
  deriveKEK,
  addCredential,
  changePassword,
  changeRecovery_caseA,
  changeRecovery_caseB,
  encryptRecoveryWithMek,
  decryptRecoveryWithMek,
  deriveSigningKey,
  importSigningKeyPair,
  deriveOuterKeyBytes,
  encodeUserIdV7,
  decodeUserIdV7,
  isUserIdV7,
  encryptVaultHwkey,
  decryptVaultHwkey,
  addHwkey,
  encodeKeyslot,
  decodeKeyslot,
  encodeUserIdHwkey,
  decodeUserIdHwkey,
  isUserIdHwkey,
  randomAppNameTag,
  deriveAppNameTag,
  deriveAllAppNameTags,
  deriveRMat,
  hashPublicKey,
  credentialIdToHash,
  b64uEncode,
  b64uDecode,
  padPlaintext,
  unpadPlaintext,
  VAULT_FORMAT_V5,
} from "/lib/vault-crypto.js?v=11331c7d";

import {
  readMeta,
  writeMeta,
  patchMeta,
  clearMeta,
  registerVault,
  signedFetch,
  getBalance,
  migrateAccount,
  fetchEnvelope,
  fetchServerVaultLatest,
  fetchServerVaultSlots,
  findLatestVaultTx,
  findLatestVaultTxAcrossTiers,
  writeEnvelope,
  writeRecordFile,
  fetchRecordFileBytes,
  writeKeyslot,
  fetchKeyslotBlob,
  lookupKeyslotTxid,
} from "./client-auth.js";

import {
  setRecordFileCache,
  getRecordFileCache,
  deleteRecordFileCache,
} from "./local-cache.js";

import {
  generateBlobKey,
  wrapKey,
  unwrapKey,
  encryptBlob,
  decryptBlob,
  // Stage 2c Stage G4 v2 (2026-06-06): Rust handle path
  generateBekHandleViaRust,
  encryptWithBekHandle,
  decryptWithBekHandle,
  wrapBekWithMekHandle,
  unwrapBekWithMekHandle,
} from "/lib/vault-crypto.js?v=11331c7d";

// ---------------------------------------------------------------------------
// セッション (in-memory secrets, lockSession で消える)
// ---------------------------------------------------------------------------

let _session = null;
/*
  _session shape:
    {
      vault:           object,             復号済み vault データ
      mek:             Uint8Array(32),     対称鍵
      outerKeyBytes:   Uint8Array(32),     外側 AES-GCM 鍵 (rMat 直接派生、Phase 7.0w-AR)
      appNameTag:      {name,value},       Arweave タグ (name/value 両方 rMat 派生)
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

// Phase 7.1: mode detection helpers
export function currentVaultMode() { return _session?.vault?.mode ?? "personal"; }
export function isPersonalMode() { return currentVaultMode() === "personal"; }
export function isBusinessMode() { return currentVaultMode() === "business"; }
export function isAdminMode()    { return currentVaultMode() === "admin"; }
export function currentCompanyId() { return _session?.vault?.companyId ?? null; }

/**
 * Phase 7.0w-AP: session 内 mek を使って vault.encryptedRecovery (v2 文字列形式)
 * を復号し、原 Recovery 文字列 ("RS1-XXXX-...") を返す。
 *
 * - encryptedRecovery が未設定 or legacy v1 形式 (rMat) → null を返す
 * - session が無い (locked) → null を返す
 * - 復号失敗 → throw
 *
 * caller (UI) は biometric ゲートで認証成功後にこの関数を呼ぶ。
 */
export async function getDecryptedRecoveryFromVault() {
  if (!_session) return null;
  // Phase 7.2-B (α): business mode でも社員自身が Recovery を保管する設計に
  //   変更されたので、 取り出しを許可 (= Personal mode 同様)。
  //   (旧 Phase 7.1-R では admin 集約保管前提だったため block していた。)
  const er = _session.vault?.encryptedRecovery;
  if (!er || er.v !== 2) return null;
  // Phase 7.3-A.7b: mekHkdfKey が session にあれば優先 (= non-extractable で raw 不要)、
  //   無ければ legacy raw mek path に fallback。
  const mekArg = _session.mekHkdfKey ?? _session.mek;
  if (!mekArg) throw new Error("session に mek / mekHkdfKey が無い");
  return await decryptRecoveryWithMek(er, mekArg);
}

/**
 * Phase 7.0w-AP: session に recoverySecret 文字列を後から注入する用。
 * 「Recovery を vault に保存」UI で user が紙から手入力した時に呼ぶ。
 * その後 saveVault を呼ぶと opportunistic inject が encryptedRecovery を vault に書く。
 */
export async function setRecoverySecretInSession(recoveryString) {
  if (!_session) throw new Error("locked");
  if (typeof recoveryString !== "string" || recoveryString.length < 4) {
    throw new Error("recoveryString invalid");
  }
  _session.recoverySecret = recoveryString;
  // Phase 7.3-A.9: rMatHkdfKey 未設定なら derive → raw は即破棄。 session には CryptoKey のみ。
  // Phase 7.4.1: raw fallback 廃止 — derive 失敗時は throw (修復可能ならエラー surface する方が安全)
  if (!_session.rMatHkdfKey) {
    const rMatRaw = deriveRMat(recoveryString);
    try {
      _session.rMatHkdfKey = await importRMatAsHkdfKey(rMatRaw);
      if (!_session.outerKey) {
        _session.outerKey = await deriveOuterKeyFromHkdf(_session.rMatHkdfKey);
      }
      // Stage 2c Stage D: Rust RMatKey opaque handle も並列 populate (= consumer は後続 stage で移行)。
      //   try-catch 内、 失敗しても既存 path に影響なし (= rMatHkdfKey はもう作られている)。
      //   Rust crypto core 未 load 時は null 返却で _session.rmat は undefined のまま。
      try {
        const rmat = await importRMatAsHandle(rMatRaw);
        if (rmat) {
          _session.rmat = rmat;
          // Stage 2c Stage D2: outerKey handle を派生して cache (= consumer 1 つで使用)。
          // WASM 内部派生 → JS heap 経由ゼロ。 失敗時は undefined のまま。
          try {
            _session.outerKeyHandle = deriveOuterKeyFromRMat(rmat);
          } catch (e2) {
            console.warn("[arpass Stage 2c-D2] outerKeyHandle derive skipped:", e2?.message || e2);
          }
        }
      } catch (e) {
        console.warn("[arpass Stage 2c-D] RMatKey handle populate skipped:", e?.message || e);
      }
    } finally {
      rMatRaw.fill(0);
    }
  }
}

/**
 * Phase 7.0w-AP fix.4: session に recoverySecret を設定し、即座に
 * vault.encryptedRecovery (v=2 形式) を in-memory で inject する。
 * Arweave 書込は行わない (caller が scheduleSave を呼んで遅延 save する設計)。
 *
 * これによって:
 *   - 即座に vault に encryptedRecovery が乗る → 直後に Show Recovery を
 *     再度押しても paper modal 出ない
 *   - 編集バッジ 'dirty' で表示される (scheduleSave 経由)
 *   - 続けてエントリ操作するもよし、即座バッジクリックで save するもよし、
 *     ロックで flush するもよし — 1 write に bundle される
 */
export async function injectEncryptedRecoveryNow(recoveryString) {
  if (!_session) throw new Error("locked");
  setRecoverySecretInSession(recoveryString);
  _session.vault.encryptedRecovery = await encryptRecoveryWithMek(recoveryString, _session.mek);
}
// Phase 7.0w-AR: currentVaultId() を削除 (vault-id 概念廃止、UI 露出も削除)
export function currentLatestTxId() { return _session?.latestTxId ?? null; }
export function currentCredIdHash() { return _session?.currentCredIdHash ?? null; }
export function hasRecoveryInSession() { return !!_session?.recoveryMaterial; }

/** メモリ上の秘密を全消去。localStorage の meta は残す (秘密値は含まない — appNameTag 等)。 */
export function lockSession() {
  if (_session) {
    if (_session.mek) _session.mek.fill(0);
    _session.mek = null;
    _session.mekKey = null;        // Phase 7.3-A.7b: CryptoKey は GC 任せだが ref 切る
    _session.mekHkdfKey = null;    // Phase 7.3-A.7b: 同上
    _session.rMatHkdfKey = null;   // Phase 7.3-A.8 part 2: 同上
    if (_session.rmat && typeof _session.rmat.free === "function") {
      try { _session.rmat.free(); } catch (_) { /* swallow */ }
    }
    _session.rmat = null;          // Stage 2c Stage D: RMatKey handle 解放
    if (_session.outerKeyHandle && typeof _session.outerKeyHandle.free === "function") {
      try { _session.outerKeyHandle.free(); } catch (_) { /* swallow */ }
    }
    _session.outerKeyHandle = null; // Stage 2c Stage D2: OuterKey handle 解放
    // Stage 2c Stage G1: 後続 stage で populate される handle 群の cleanup 足場
    //   (= G2: mekHandle 経路、 G3: k1Handle 経路、 G4: bekHandle 経路)。
    //   現時点で誰も populate しないので null check で no-op、 G2 以降で活用。
    if (_session.mekHandle && typeof _session.mekHandle.free === "function") {
      try { _session.mekHandle.free(); } catch (_) { /* swallow */ }
    }
    _session.mekHandle = null;     // Stage 2c Stage G2 (= 予定): MekKey handle
    if (_session.k1Handle && typeof _session.k1Handle.free === "function") {
      try { _session.k1Handle.free(); } catch (_) { /* swallow */ }
    }
    _session.k1Handle = null;      // Stage 2c Stage G3 (= 予定): K1Key handle
    if (_session.bekHandle && typeof _session.bekHandle.free === "function") {
      try { _session.bekHandle.free(); } catch (_) { /* swallow */ }
    }
    _session.bekHandle = null;     // Stage 2c Stage G4 (= 予定): BekKey handle (per-record)
    _session.outerKey = null;      // Phase 7.3-A.8 part 2: 同上
    if (_session.recoveryMaterial) _session.recoveryMaterial.fill(0);
    // Phase 7.0w-AR: outerKeyBytes も zeroize (AES-GCM 鍵そのもの)
    if (_session.outerKeyBytes) _session.outerKeyBytes.fill(0);
    if (_session.signingState?.publicKeyRaw) _session.signingState.publicKeyRaw.fill(0);
    _session.recoverySecret = null;
    // Phase 7.2-B v2: empPrivKey は CryptoKey なので GC 任せだが、参照消去
    _session.empPrivKey = null;
    if (_session.businessK2) _session.businessK2.fill(0);
    // Phase 7.2-B v2: admin K1 zeroize
    if (_session.k1) _session.k1.fill(0);
    if (_session.k1History) {
      for (const v of _session.k1History.values()) v.fill(0);
      _session.k1History.clear();
    }
    // Phase 7.2-B v2.4: old K1 由来 real_MEK cache の zeroize
    if (_session._oldRealMekCache) {
      for (const m of _session._oldRealMekCache.values()) m.fill(0);
      _session._oldRealMekCache.clear();
    }
  }
  _session = null;
}

/**
 * Phase 7.1-R (security): business mode signup の deposit 完了直後に、
 * Recovery を session メモリから purge する。社員端末は Recovery を
 * 持ち続けないことが設計原則 (退社後 memorize 防止)。
 *
 * 残るのは MEK / outerKeyBytes / signingState — これらは vault 操作に必須で、
 * lockSession 時 (= タブ閉じる、明示 logout) に消える。
 *
 * 注: MEK が残っていても、admin から再 deposit してもらわない限り Recovery
 * 文字列自体は復元不能 (= encryptedRecovery が vault にない + recoverySecret null)。
 */
export function _purgeRecoveryFromSession() {
  if (!_session) return;
  if (_session.recoveryMaterial) _session.recoveryMaterial.fill(0);
  _session.recoveryMaterial = null;
  _session.recoverySecret = null;
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

// Phase 7.1-AC: 新端末が device-add コード redeem に使う ephemeral signing state を生成する。
// ECDSA P-256 (Web Crypto) で完全に新規 keypair を作り、署名鍵 + 公開鍵 raw を返す。
// 同時に ECIES 復号用の private scalar (32-byte raw) も同梱する。
//   - signingPrivateKey: 既存 signedFetch が使う CryptoKey
//   - publicKeyRaw:      X-Public-Key ヘッダに乗せる 65-byte uncompressed
//   - eciesPrivateRaw:   admin から ECIES で来た payload を decrypt するため 32-byte raw scalar
export async function generateEphemeralSigningState() {
  // generateKey で extractable: true にすれば jwk export 可能 → d を取り出して ECIES 用 raw を作る
  const kp = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const pubJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const priJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  // x, y, d は b64url encoded — Uint8Array に decode
  const xB = b64uDecode(pubJwk.x);
  const yB = b64uDecode(pubJwk.y);
  const dB = b64uDecode(priJwk.d);
  if (xB.length !== 32 || yB.length !== 32 || dB.length !== 32) {
    throw new Error("ephemeral key length unexpected");
  }
  const publicKeyRaw = new Uint8Array(65);
  publicKeyRaw[0] = 0x04;
  publicKeyRaw.set(xB, 1);
  publicKeyRaw.set(yB, 33);
  // sign 用に非 extractable に再 import (実害は無いが ergonomics 揃える)
  const signKey = await crypto.subtle.importKey(
    "jwk", priJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]
  );
  return {
    signingPrivateKey: signKey,
    publicKeyRaw,
    eciesPrivateRaw: dB,  // 32-byte big-endian scalar
  };
}

// ---------------------------------------------------------------------------
// Phase 7.2-B: Business mode server-wrap helpers
// ---------------------------------------------------------------------------

// Phase 7.2-B v2: _fetchServerPubkey / _serverPubkeyCache は v1 ws field 用、 v2 では削除


/**
 * Phase 7.2-B v2: /api/corp/fetch-enc-k1 を呼んで自分用 enc_K1 blob を取得。
 * 内部は CORP_KEK 層が server で剥がされ、 ECIES wrap 状態の blob が返る。
 * caller が emp_priv で eciesUnwrapForRecipient して K1 raw を取り出す。
 *
 * @param {object} signingState  社員の current signing state (= signedFetch 認証用)
 * @param {object} [opts] { version: <int> } 旧 version 取得用
 * @returns {Promise<{ eph_pub, iv, ct, k1Version, isDeprecated }>}
 */
async function _fetchEncK1V2(signingState, opts = {}) {
  const url = opts.version != null
    ? `/api/corp/fetch-enc-k1?version=${encodeURIComponent(opts.version)}`
    : "/api/corp/fetch-enc-k1";
  const r = await signedFetch(url, "GET", null, signingState);
  const body = await r.json().catch(() => ({}));
  if (!r.ok) {
    const err = new Error(body?.error || `fetch-enc-k1 failed: ${r.status}`);
    err.code = body?.code || "fetch_error";
    err.status = r.status;
    throw err;
  }
  if (!body.ok) {
    const err = new Error(body?.error || "fetch-enc-k1 returned not-ok");
    err.code = body?.code || "server_error";
    throw err;
  }
  return body;  // { eph_pub, iv, ct, k1Version, isDeprecated }
}

/**
 * Phase 7.2-B v2: 自分の emp_pubkey を server に登録 (= signup 直後 / 機種追加時)。
 */
async function _registerEmpPubkeyV2(empPubKeyJwk, signingState) {
  const r = await signedFetch("/api/corp/register-pubkey", "POST",
    { pubkey: empPubKeyJwk }, signingState);
  const body = await r.json().catch(() => ({}));
  if (!r.ok || !body.ok) {
    const err = new Error(body?.error || "register-pubkey failed");
    err.code = body?.code || "register_error";
    throw err;
  }
  return body;
}

/**
 * Phase 7.2-B: envelope.m === "business" なら server から K1 を fetch して
 *   decryptVaultBusiness で復号、 そうでなければ従来通り decryptVault。
 *
 * 注意: business envelope は signing identity が K2 由来になるので、 unlock 後に
 *   build される signing key も K2 ベース。 caller (openSession) は businessK2 を
 *   セッションに保存して、 saveVault でも同じ signing identity を維持する。
 *
 * @param {object} envelope
 * @param {object} factors  { password?, prfOutput?, recoveryMaterial?, credIdHash? }
 * @returns {Promise<{ vault, mek, signingKey, path, businessK2: Uint8Array|null }>}
 */
/**
 * Phase 7.2-B (α): server hint で指定された txid を retry/wait で fetch する。
 *   Turbo bundler の propagation を待つ。 server が「これが latest」 と言っている以上、
 *   GraphQL fallback で古い tx を拾うのは設計上 incorrect。
 *
 * @param {string} txid          server hint の権威 txid
 * @param {Uint8Array} outerKey  outer 復号鍵
 * @param {function} [onProgress] (attempt, totalAttempts) コールバック (= UI 更新用)
 * @returns {Promise<{envelope: object} | null>}
 */
async function _fetchServerHintedWithRetry(txid, outerKey, onProgress = null) {
  const delays = [500, 1500, 3000, 6000, 10000];  // 計 21 秒、 5 retry
  const total = delays.length + 1;
  for (let attempt = 0; attempt < total; attempt++) {
    try {
      onProgress?.(attempt + 1, total);
      const r = await fetchEnvelope(txid, outerKey);
      if (r?.envelope) return r;
    } catch (e) {
      console.warn(`[fetch-hint] attempt ${attempt + 1}/${total} failed:`, e?.message);
    }
    if (attempt < delays.length) {
      await new Promise(res => setTimeout(res, delays[attempt]));
    }
  }
  return null;
}

async function decryptVaultAuto(envelope, factors) {
  // envelope v7 増分2: hwkey モード (YubiKey 専用) は専用復号経路。
  if (envelope?.m === "hwkey") {
    return await decryptVaultHwkey(envelope, factors?.prfOutput, factors?.credIdHash ?? null);
  }
  if (envelope?.m === "business") {
    const cid = envelope.cid;
    if (!cid) throw new Error("business envelope に cid (companyId) が無い");

    // v2 envelope は w_emp を持つ。 v1 (ws field) は廃止。
    if (!envelope.w_emp) {
      throw new Error("business envelope に w_emp が無い (= v1 envelope.ws は廃止、 vault re-create が必要)");
    }

    // Phase 7.2-B v2 unlock 順序:
    //  (1) factor → K2
    //  (2) K2 → emp_priv (w_emp 復号)
    //  (3) K2 → signing key
    //  (4) signing で /api/corp/fetch-enc-k1 → enc_K1 blob
    //  (5) emp_priv で ECIES unwrap → K1
    //  (6) HKDF(K1, K2) → real_MEK → body 復号

    // (1)+(6) は decryptVaultBusiness が内部でやる。ただし emp_priv 取得と K1 取得は
    // ここで先行して行う必要がある (= decryptVaultBusiness は k1Bytes を受け取る前提)。

    // (1) K2 を先に取り出す (= K1 取得には signing が必要、 signing は K2 由来)
    const k2 = await _extractK2FromBusinessEnvelope(envelope, factors);

    // (2) emp_priv を K2 で復号
    let empPrivKey;
    try {
      empPrivKey = await unwrapEmpPrivWithK2(k2, envelope.w_emp);
    } catch (e) {
      k2.fill(0);
      throw new Error(`w_emp unwrap failed: ${e?.message}`);
    }

    // (3) K2 由来の signing state を一時構築
    const tempSigning = await buildSigningState(k2);

    // Phase 7.2-B v2.2: k1Pending mode — K1 fetch を skip、 ZERO_K1 で body 復号
    if (envelope.k1Pending) {
      const zeroK1 = new Uint8Array(32);
      const result = await decryptVaultBusiness(envelope, factors, zeroK1);
      k2.fill(0);
      return {
        ...result,
        businessK2: null,  // Phase 7.4.1: V1 廃止、 result.k2 (raw) は提供されない
        empPrivKey,
        k1Version: null,
        k1Pending: true,
      };
    }

    // (4) server から自分用 enc_K1 を取得
    let encK1;
    try {
      encK1 = await _fetchEncK1V2(tempSigning);
    } catch (e) {
      if (e.code === "pending_k1_distribution") {
        // Phase 7.2-B v2.6 hotfix: 404 は次の 2 ケースありえる:
        //   (a) corp:<cid>:member:<pkH> 存在、 status=pending_k1 → admin の配布待ち
        //   (b) corp:<cid>:member:<pkH> 不存在 (= signup の register-pubkey が silent fail)
        //   → admin の pending リストにも出ないため救済不能だった。
        // 対策: 念のため emp_pub の再登録を fire-and-forget で実行してから k1_pending を返す。
        //       (b) なら次回 admin reload で pending リストに出現 → K1 配布可能に。
        //       (a) なら no-op (idempotent)。
        if (envelope.emp_pub) {
          _registerEmpPubkeyV2(envelope.emp_pub, tempSigning)
            .then(() => console.log("[decryptVaultAuto] emp_pubkey self-heal on k1_pending succeeded"))
            .catch((err) => console.warn("[decryptVaultAuto] emp_pubkey self-heal failed:", err?.message));
        }
        k2.fill(0);
        const err = new Error("K1 が未配布です。Admin に「K1 配布」 を実行してもらってください。");
        err.code = "k1_pending";
        err.original = e;
        throw err;
      }
      k2.fill(0);
      throw e;
    }

    // (5) ECIES unwrap → K1
    let k1Raw;
    try {
      k1Raw = await eciesUnwrapForRecipient(empPrivKey, encK1);
    } catch (e) {
      k2.fill(0);
      throw new Error(`ECIES unwrap failed: ${e?.message}`);
    }
    const k1 = new Uint8Array(k1Raw);

    // (6) body 復号
    const result = await decryptVaultBusiness(envelope, factors, k1);

    // memory hygiene
    k1.fill(0);
    k2.fill(0);

    return {
      ...result,
      businessK2: null,  // Phase 7.4.1: V1 廃止、 result.k2 (raw) は提供されない
      empPrivKey,           // session で保持 (= 機種追加・rotation 等で再利用)
      k1Version: encK1.k1Version ?? null,
    };
  }
  // Personal / admin: 従来通り
  const result = await decryptVault(envelope, factors);
  return { ...result, businessK2: null };
}



// Phase 7.2-B v2: _localUnwrapK1 (admin escrow fallback) は v1 specific のため削除

async function _extractK2FromBusinessEnvelope(envelope, factors) {
  const salt = b64uDecode(envelope.s);
  const haveP = !!factors?.password;
  const haveK = factors?.prfOutput instanceof Uint8Array && factors.prfOutput.length >= 16;
  const haveR = factors?.recoveryMaterial instanceof Uint8Array && factors.recoveryMaterial.length >= 32;
  if ([haveP, haveK, haveR].filter(Boolean).length < 2)
    throw new Error("K2 extract: need at least 2 factors");
  // Phase 7.4.1 hotfix (2026-06-05): envelope.kdfParams を必ず渡す。
  //   ここを渡し忘れると derivePMat が strict check で throw → unlock 不能になる。
  const pMat = haveP ? await derivePMat(factors.password, salt, envelope.kdfParams) : null;
  const kMat = haveK ? deriveKMat(factors.prfOutput) : null;
  const rMat = haveR ? factors.recoveryMaterial.slice(0, 32) : null;
  // #161: この Passkey (credIdHash) 用の wrap が envelope に存在したかを記録する。
  //   wrap はあるのに復号失敗 → Passkey は登録済 (正しい) なので、
  //   不一致要素はもう一方の factor (AB なら Master)。 caller がこれを見て
  //   "Master 違い" と "Passkey 違い" を区別する。
  let passkeyWrapPresent = false;
  // Path AB → wrap_b
  if (pMat && kMat && envelope.w?.b?.length) {
    const candidates = factors.credIdHash
      ? envelope.w.b.filter((w) => w.h === factors.credIdHash)
      : envelope.w.b;
    if (factors.credIdHash && candidates.length > 0) passkeyWrapPresent = true;
    for (const w of candidates) {
      try {
        const kek = await deriveKEK(pMat, kMat, "kek_pk");
        const k2 = await aesGcmDecryptRaw(kek, b64uDecode(w.i), b64uDecode(w.c));
        return k2;
      } catch { /* try next */ }
    }
  }
  // Path AC → wrap_a
  if (pMat && rMat && envelope.w?.a) {
    try {
      const kek = await deriveKEK(pMat, rMat, "kek_pr");
      const k2 = await aesGcmDecryptRaw(kek, b64uDecode(envelope.w.a.i), b64uDecode(envelope.w.a.c));
      return k2;
    } catch { /* try BC */ }
  }
  // Path BC → wrap_c
  if (kMat && rMat && envelope.w?.c?.length) {
    const candidates = factors.credIdHash
      ? envelope.w.c.filter((w) => w.h === factors.credIdHash)
      : envelope.w.c;
    if (factors.credIdHash && candidates.length > 0) passkeyWrapPresent = true;
    for (const w of candidates) {
      try {
        const kek = await deriveKEK(kMat, rMat, "kek_kr");
        const k2 = await aesGcmDecryptRaw(kek, b64uDecode(w.i), b64uDecode(w.c));
        return k2;
      } catch { /* try next */ }
    }
  }
  const _k2err = new Error("K2 extract failed: no wrap opened");
  _k2err.passkeyWrapPresent = passkeyWrapPresent;
  throw _k2err;
}

async function aesGcmDecryptRaw(cryptoKey, iv, ciphertext) {
  return new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, ciphertext)
  );
}


/**
 * Phase 7.3-A.9 part 2: 操作時に raw mek を transient に再派生する helper。
 * lastEnvelope と factors (= AB/AC/BC) から decryptVault を再走し、 raw mek を得る。
 * caller が即 fill(0) する規律で動作。 session 持続保管しない。
 *
 * @param {object} factors  { password?, prfOutput?, recoveryMaterial?, credIdHash? }
 * @returns {Promise<Uint8Array>} raw mek 32B (caller が fill(0) する)
 */
async function _deriveTransientMek(factors) {
  if (!_session?.lastEnvelope) throw new Error("session に lastEnvelope がない");
  // Business envelope は decryptVaultBusiness (= K1 fetch 経路)、 Personal は decryptVault
  const env = _session.lastEnvelope;
  if (env.m === "business") {
    throw new Error("_deriveTransientMek: business mode は K1 が必要なため未サポート (= 別経路で再派生)");
  }
  const result = await decryptVault(env, factors);
  // mek raw のみ抜き出し、 他は破棄
  return new Uint8Array(result.mek);
}

async function openSession({ vault, mek, mekKey, mekHkdfKey, k2AesKey, k2HkdfKey, signingKey: signingKeyFromResult,
                             outerKeyBytes, appNameTag, recoveryMaterial,
                             recoverySecret,
                             credIdHash, credentialId, latestTxId, lastEnvelope,
                             currentAppNameTag, currentTierQualifier,
                             businessK2,
                             // === Phase 7.2-B v2 追加 ===
                             empPrivKey, k1Version }) {
  // Phase 7.0: schema v1 -> v2 (records 配列追加) を on-load で migrate。
  vault = migrateVaultSchema(vault);
  // Phase 7.2-B: business mode は signing identity を K2 由来にする (= K1 rotation 不変)。
  // Phase 7.3-A.9 part 3: signingKey が caller から渡されたらそれを使う (= V2 path、 raw K2 不在)
  let signingState;
  if (signingKeyFromResult?.privateKeyJwk && signingKeyFromResult?.publicKeyJwk) {
    const { privateKey, publicKey } = await importSigningKeyPair(signingKeyFromResult.privateKeyJwk, signingKeyFromResult.publicKeyJwk);
    signingState = {
      signingPrivateKey: privateKey,
      signingPublicKey: publicKey,
      publicKeyRaw: signingKeyFromResult.publicKeyRaw,
      publicKeyJwk: signingKeyFromResult.publicKeyJwk,
    };
  } else {
    signingState = await buildSigningState(businessK2 ?? mek);
  }
  const publicKeyHash = await hashPublicKey(signingState.publicKeyRaw);
  patchMeta({ publicKeyHash });
  // Phase 7.3-A.8 part 2: rMat / outerKey の CryptoKey 派生を並行保持 (= 段階移行)。
  //   raw bytes は backward compat のため残置、 順次 caller を CryptoKey path に切替予定。
  let _rMatHkdfKey = null;
  let _outerKey = null;
  try {
    if (recoveryMaterial instanceof Uint8Array && recoveryMaterial.length === 32) {
      _rMatHkdfKey = await importRMatAsHkdfKey(recoveryMaterial);
      _outerKey = await deriveOuterKeyFromHkdf(_rMatHkdfKey);
    } else if (outerKeyBytes instanceof Uint8Array && outerKeyBytes.length === 32) {
      // recoveryMaterial 無し (= AB unlock) は outerKeyBytes から直接 import (raw 経由)
      _outerKey = await crypto.subtle.importKey(
        "raw", outerKeyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]
      );
    }
  } catch (e) {
    console.warn("[openSession] rMatHkdfKey / outerKey derive failed (non-fatal, raw fallback):", e?.message);
  }

  // Phase 7.3-A.9: raw outerKeyBytes は CryptoKey 派生後 fill(0) で破棄。 session 不在に。
  //   _session.outerKey (= 非 extractable AES-GCM) のみが outer wrap/unwrap source。
  if (_outerKey && outerKeyBytes instanceof Uint8Array) {
    outerKeyBytes.fill(0);
  }
  // Phase 7.3-A.9: rMatHkdfKey 派生成功時、 raw rMat を fill(0) で破棄。 session 不在に。
  //   addCredentialOnThisDevice 等 raw が必要な操作は factor 再入力で復元する設計。
  if (_rMatHkdfKey && recoveryMaterial instanceof Uint8Array) {
    recoveryMaterial.fill(0);
  }
  // Phase 7.3-A.9 part 2: Personal mode の raw mek も session 不在に。 mekKey + mekHkdfKey
  //   があれば raw mek は不要。 mutation 操作 (changePassword 等) は _deriveTransientMek で再派生。
  let _mekToStore = mek;
  // Stage 2c Stage G2: raw mek が一瞬存在するタイミングで MekKey handle 並列 populate。
  //   raw bytes 露出 window は既存 path と同じ (= fill(0) 直前のミリ秒)、 新規 hygiene 悪化なし。
  //   失敗しても既存 mekHkdfKey path は無傷で動作継続。 consumer 移行は G3 以降。
  let _mekHandleStore = null;
  if (mek instanceof Uint8Array && mek.length === 32) {
    try {
      _mekHandleStore = await importMekRawAsHandle(mek);
    } catch (e) {
      console.warn("[arpass Stage 2c-G2] mekHandle populate skipped:", e?.message || e);
    }
  }
  if (mekKey && mekHkdfKey && mek instanceof Uint8Array) {
    mek.fill(0);
    _mekToStore = null;
  }
  // Phase 7.3-A.9 part 4: V1 envelope (kdfV2 不在) を unlock した結果 raw businessK2 のみ持つ場合、
  //   即座に CryptoKey 化 (k2AesKey / k2HkdfKey) して raw を破棄。 以後の downstream caller は
  //   V1/V2 を区別せず k2HkdfKey / k2AesKey 経由でアクセスできる。
  let _k2AesKeyStore = k2AesKey ?? null;
  let _k2HkdfKeyStore = k2HkdfKey ?? null;
  let _businessK2Store = businessK2 ?? null;
  if (!_k2HkdfKeyStore && _businessK2Store instanceof Uint8Array && _businessK2Store.length === 32) {
    try {
      const _imported = await importK2AsKeys(_businessK2Store);
      _k2AesKeyStore = _imported.k2AesKey;
      _k2HkdfKeyStore = _imported.k2HkdfKey;
      _businessK2Store.fill(0);
      _businessK2Store = null;
    } catch (e) {
      console.warn("[openSession] V1 businessK2 -> CryptoKey promote failed (keeping raw):", e?.message);
    }
  }
  _session = {
    vault, mek: _mekToStore, mekKey: mekKey ?? null,  // Phase 7.3-A.3
    mekHkdfKey: mekHkdfKey ?? null,  // Phase 7.3-A.7b: 非 extractable HKDF base for sub-key 派生
    mekHandle: _mekHandleStore,      // Stage 2c Stage G2: Rust MekKey opaque handle (並列保管)
    rMatHkdfKey: _rMatHkdfKey,       // Phase 7.3-A.8 part 2: 非 extractable HKDF base (= rMat)
    outerKey: _outerKey,             // Phase 7.3-A.8 part 2: 非 extractable AES-GCM (= outerKey)
    outerKeyBytes: _outerKey ? null : outerKeyBytes,  // Phase 7.3-A.9: CryptoKey 派生成功時は raw 不保持
    appNameTag,
    businessK2: _businessK2Store,    // Phase 7.3-A.9 part 4: V1 promote 後は null
    k2AesKey: _k2AesKeyStore,        // Phase 7.3-A.9 part 4: V1/V2 共通 CryptoKey 経路
    k2HkdfKey: _k2HkdfKeyStore,      // Phase 7.3-A.9 part 4: V1/V2 共通 CryptoKey 経路
    recoveryMaterial: _rMatHkdfKey ? null : (recoveryMaterial ?? null),  // Phase 7.3-A.9: CryptoKey 派生成功時は raw 不保持
    recoverySecret: recoverySecret ?? null,
    signingState,
    currentCredIdHash: credIdHash ?? null,
    currentCredentialId: credentialId ?? null,
    latestTxId: latestTxId ?? null,
    lastEnvelope: lastEnvelope ?? null,
    currentAppNameTag: currentAppNameTag ?? null,
    currentTierQualifier: currentTierQualifier ?? null,
    recentlyWrittenTxIds: new Set(),
    recentlyWrittenTxIdsOrder: [],
    // === Phase 7.2-B v2: empPrivKey + k1Version ===
    empPrivKey: empPrivKey ?? null,
    k1Version: k1Version ?? null,
    // === Phase 7.2-B v2: admin の K1 を vault から hydrate ===
    k1: null,
  };

  // Phase 7.2-B v2: admin の場合、 vault.k1 (b64u) から session.k1 にロード
  // Phase 7.3-A.7e: _hydrateAdminK1FromVault 廃止。 vault.k1Current は b64u 保管されており、
  //   必要時に _decodeAdminK1FromVault() で transient decode する設計に変更。

  if (!currentAppNameTag && recoveryMaterial) {
    refreshTierQualifier().catch((e) => {
      console.warn("[vault-client] tier refresh failed (non-fatal):", e.message);
    });
  }

  // Phase 7.2-B v2.6 hotfix: business mode で emp_pub が server に未登録なら自動再登録 (self-heal)。
  //   症状: signup 時の _registerEmpPubkeyV2 が silent fail (= catch でログのみ) で、
  //         server には corpMember binding はあるが corp:<cid>:member:<pkH> が無い状態。
  //         admin から pending リストにも見えず、 K1 配布もできず、 member は永遠に unlock 不可。
  //   対策: 毎 unlock で envelope.emp_pub があれば再登録 (idempotent、 既存 pubkey なら更新のみ)。
  // Phase 7.3-A.9 part 3 hotfix 3: V2 session では businessK2 が null。
  //   business 判定は lastEnvelope.m === "business" or k2HkdfKey の存在で行う。
  const _isBusinessSession = (lastEnvelope?.m === "business") || !!businessK2 || !!k2HkdfKey;
  if (_isBusinessSession && lastEnvelope?.emp_pub) {
    _registerEmpPubkeyV2(lastEnvelope.emp_pub, signingState).then(() => {
      console.log("[openSession] emp_pubkey self-heal succeeded");
    }).catch((e) => {
      console.warn("[openSession] emp_pubkey self-heal failed (non-fatal):", e?.message);
    });
  }

  // Phase 7.2-B v2.2: k1Pending envelope なら自動 transition を fire-and-forget で起動
  //   admin が K1 配布済なら fetch-enc-k1 成功 → 実 K1 で再暗号化 → saveVault →
  //   window.dispatchEvent で UI に通知 (= app-main.js が toast 表示)
  if (lastEnvelope?.k1Pending && _isBusinessSession) {
    tryTransitionFromPending().then((r) => {
      if (r?.transitioned && typeof window !== "undefined") {
        try {
          window.dispatchEvent(new CustomEvent("arpass:k1-transitioned", {
            detail: { k1Version: r.k1Version }
          }));
        } catch (e) { /* ignore */ }
      } else if (r?.reason && r.reason !== "not_pending" && typeof window !== "undefined") {
        try {
          window.dispatchEvent(new CustomEvent("arpass:k1-pending-still", {
            detail: { reason: r.reason }
          }));
        } catch (e) { /* ignore */ }
      }
    }).catch((e) => {
      console.warn("[openSession] auto-transition failed:", e?.message);
    });
  }
}


// Phase 7.1-AI: 自分の書込 TX を session に記録 (FIFO bound 100)
function _recordWrittenTxId(txid) {
  if (!_session || !txid) return;
  if (!_session.recentlyWrittenTxIds) {
    _session.recentlyWrittenTxIds = new Set();
    _session.recentlyWrittenTxIdsOrder = [];
  }
  if (_session.recentlyWrittenTxIds.has(txid)) return;
  _session.recentlyWrittenTxIds.add(txid);
  _session.recentlyWrittenTxIdsOrder.push(txid);
  while (_session.recentlyWrittenTxIdsOrder.length > 100) {
    const oldest = _session.recentlyWrittenTxIdsOrder.shift();
    _session.recentlyWrittenTxIds.delete(oldest);
  }
}


// Phase 7.2-B v2.6: server に渡す tier 申告 (= account.vaultSlots を正しく更新するため)。
//   - businessMode (= corp 加入中) なら "corp"
//   - currentTierQualifier === "paid" or "private" なら "paid"
//   - 未確定なら "free" (= 無料層 default、 server も free 扱い)
function _resolveCurrentTier() {
  if (!_session) return "free";
  if (_session.businessMode) return "corp";
  if (_session.currentTierQualifier === "paid") return "paid";
  if (_session.currentTierQualifier === "private") return "paid";
  return "free";
}

/**
 * Phase 6.4.1: Server に現 tier を問い合わせ、currentAppNameTag を更新する。
 * Stripe 購入完了後 / 会社参加・離脱後など、tier が変わるイベントの後に呼ぶ。
 */
export async function refreshTierQualifier() {
  // Phase 7.3-A.9: rMatHkdfKey or recoveryMaterial のどちらかがあれば動く
  if (!_session || (!_session.rMatHkdfKey && !_session.recoveryMaterial)) return null;
  const qualifier = await fetchCurrentTierQualifier();
  // v2.6 hotfix: business mode (= envelope.m === "business") は signup 時に
  //   legacy tag (= deriveAppNameTag(rMat, null)) で write しているので、
  //   /api/balance の race で qualifier が "free" 等になっても currentAppNameTag を
  //   非 legacy 値で上書きしない。 unlock が legacy vlatest を引けず 404 になるバグ防止。
  const isBusinessMode = _session.lastEnvelope?.m === "business" || _session.vault?.mode === "business" || _session.vault?.mode === "admin";
  const useTier = isBusinessMode ? null : qualifier;
  // Phase 7.3-A.8 part 2d: rMatHkdfKey 経由を優先 (= raw rMat 不要)。
  //   fallback で raw rMat (= legacy path)。
  let newTag;
  if (_session.rMatHkdfKey) {
    try {
      const { deriveAppNameTagFromHkdf } = await import("/lib/vault-crypto.js?v=11331c7d");
      newTag = await deriveAppNameTagFromHkdf(_session.rMatHkdfKey, useTier);
    } catch (e) {
      console.warn("[refreshTierQualifier] HKDF path failed, falling back to raw:", e?.message);
      newTag = deriveAppNameTag(_session.recoveryMaterial, useTier);
    }
  } else {
    newTag = deriveAppNameTag(_session.recoveryMaterial, useTier);
  }
  _session.currentTierQualifier = qualifier;  // 表示・billing 用に元の値は保持
  _session.currentAppNameTag = newTag;
  // Persist to localStorage so other tabs / next page-load can pick it up.
  // Phase 7.0w-AR: tag は {name,value} オブジェクト
  patchMeta({ currentAppNameTag: newTag, currentTierQualifier: qualifier });
  return { qualifier, appNameTag: newTag };
}

// ---------------------------------------------------------------------------
// WebAuthn ヘルパー (Passkey + PRF)
// ---------------------------------------------------------------------------

const RP_ID = (typeof location !== "undefined") ? location.hostname : "arpass.io";
const PRF_SALT = new TextEncoder().encode("arpass-passkey-prf-salt-v1");

export async function createPasskey(userId, displayName, opts = {}) {
  if (!navigator.credentials?.create) throw new Error("WebAuthn unavailable");
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  // envelope v7: userId は Uint8Array (v7 user.id ペイロード、57 byte) も
  //   文字列 (旧: appNameTag.value) も受け付ける。旧 string caller は不変。
  const userIdBytes = userId instanceof Uint8Array
    ? userId
    : new TextEncoder().encode(userId);
  // Phase 7.5X revert: 7.5U で create() UV を "preferred" に split したが、
  //   PIN 設定済 YubiKey で hmac-secret PRF が UV 状態に依存する仕様のため、
  //   create-time UV=true → 後の get() UV=discouraged で PRF mismatch を
  //   起こす可能性 (= user 報告 「Android で作った vault が Android では
  //   読めない」 の原因と推定)。 UV=discouraged 一貫に戻す。
  let cred;
  try {
    cred = await navigator.credentials.create({
      publicKey: {
        challenge,
        rp: { id: RP_ID, name: "Arpass" },
        user: { id: userIdBytes, name: displayName, displayName },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }], // ES256 + RS256 (browser warning 回避)
        authenticatorSelection: {
          userVerification: opts.userVerification || "preferred",
          // envelope v7: discoverable (resident) credential なら新端末で userHandle が
          //   返り、v7 user.id を読める。v7 personal vault は requireResidentKey:true。
          residentKey: opts.requireResidentKey ? "required" : "preferred",
        },
        extensions: { prf: { eval: { first: PRF_SALT } } },
        timeout: 60000,
      },
    });
  } catch (e) {
    // Phase 7.5U: 詳細エラー診断。 「Unknown error」 系は YubiKey 容量フルが多い。
    console.error("[createPasskey] navigator.credentials.create() failed:",
      e?.name, e?.message);
    const msg = String(e?.message || "");
    if (/KEY_STORE_FULL|key store|storage[\s_]?full|insufficient[\s_]?storage/i.test(msg)) {
      const er = new Error("YubiKey の discoverable credential 容量がいっぱいです。ykman で不要な credential を削除してから再試行してください。");
      er.code = "yubikey_storage_full";
      er.original = e;
      throw er;
    }
    if (/unknown error|credential[\s_]?manager/i.test(msg)) {
      const er = new Error("YubiKey 作成に失敗 (Unknown error)。YubiKey 容量がいっぱい / PIN モード不一致 / authenticator が拒否 のいずれかが原因の可能性があります。 ykman で discoverable credential を確認してください。");
      er.code = "passkey_create_unknown";
      er.original = e;
      throw er;
    }
    throw e;
  }
  if (!cred) throw new Error("Passkey creation cancelled");
  const credentialId = new Uint8Array(cred.rawId);
  const ext = cred.getClientExtensionResults?.();
  let prfOutput = ext?.prf?.results?.first ? new Uint8Array(ext.prf.results.first) : null;
  // 多くのセキュリティキー (YubiKey 等) は create 時に PRF 出力を返さず prf.enabled のみ
  //   返す。 その場合は作成直後に get() を 1 回行い PRF 出力を取得する。 platform
  //   authenticator は通常 create 時に PRF を返すためこの追加 get は走らない (追加タッチ無し)。
  // hwkey (userVerification=discouraged) は、 create() が PRF を返しても
    //   それは create ceremony (UV あり) の PRF。 解錠は UV なしの PRF を使うため、
    //   create() の PRF は捨て、 必ず follow-up get (discouraged) の PRF を採る。
    if (!prfOutput || opts.userVerification === "discouraged") {
    console.log("[createPasskey] follow-up get() で PRF 取得 (セキュリティキー経路)");
    const got = await authenticateWithPasskey(credentialId, {
      ...(opts.followupTransports ? { transports: opts.followupTransports } : {}),
      ...(opts.userVerification ? { userVerification: opts.userVerification } : {}),
    });
    prfOutput = got?.prfOutput || null;
  }
  if (!prfOutput) throw new Error("PRF extension required but not returned by authenticator");
  return { credentialId, prfOutput };
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
    : [{
        type: "public-key",
        id: credentialIdHint,
        // transports を渡すとブラウザが対象 authenticator (YubiKey) へ直行しやすい
        //   (= specific get が picker 化されるのを防ぐ)。
        ...(Array.isArray(options.transports) && options.transports.length
          ? { transports: options.transports } : {}),
      }];
  console.log("[authenticateWithPasskey] usePicker=" + usePicker +
    " allowCredentials=" + allowCredentials.length +
    (options.forcePicker ? " (forcePicker)" : ""));
  // Phase 7.5Y refactored (Phase 7.5Z hotfix):
  //   skipPrfExtension support を 7.5Y で追加したが、 extensions を object literal の
  //   外で代入する形に変えたところ iPhone Safari NFC の 2 nd tap が落ちた user 報告。
  //   iOS Safari の publicKey object 取扱いに property ordering 依存があるのか、
  //   原因は不明だが、 元の literal placement に戻す。 spread で skipPrfExtension
  //   時のみ extensions を省く形にし、 通常時のオブジェクト構造は 7.5Y 以前と
  //   bit-identical にする。
  const _prfExt = options.skipPrfExtension ? {} : {
    extensions: {
      // PRF 拡張: specific get (allowCredentials 名指し) では spec 準拠の
      //   evalByCredential を使う。 eval のままだと一部ブラウザ (Mac Safari) が
      //   specific get を拒否する。 discoverable get は eval を使う。
      prf: (!usePicker && credentialIdHint)
        ? { evalByCredential: { [b64uEncode(credentialIdHint)]: { first: PRF_SALT } } }
        : { eval: { first: PRF_SALT } },
    },
  };
  const _getPk = {
    challenge,
    rpId: RP_ID,
    allowCredentials,
    // hwkey は PRF が UV 有無で変わるため "required" を渡す (= UV 必須)。
    userVerification: options.userVerification || "preferred",
    ..._prfExt,
    timeout: 60000,
  };
  // WebAuthn L3 hints: 呼び出し側が options.hints=["security-key"] を渡すと、
  //   ブラウザ UI を YubiKey 直行にできる (= 同期パスキー一覧のノイズを減らす)。
  //   未対応ブラウザは hints を無視するだけなので安全。
  if (Array.isArray(options.hints) && options.hints.length) _getPk.hints = options.hints;
  const cred = await navigator.credentials.get({ publicKey: _getPk });
  if (!cred) throw new Error("Passkey auth cancelled");
  const ext = cred.getClientExtensionResults?.();
  const prfOutput = ext?.prf?.results?.first ? new Uint8Array(ext.prf.results.first) : null;
  // prfOptional: picker get では PRF が返らないことがあるため、 呼び出し側が
  //   2 段 get を行えるよう「PRF 無しでも返す」モードを許可する。
  if (!prfOutput && !options.prfOptional) throw new Error("PRF extension required but not returned");
  // envelope v7: discoverable credential なら userHandle (= WebAuthn user.id) が返る。
  //   新端末で v7 user.id から outer 鍵 / appNameTag を取り出すために使う (旧 caller は無視)。
  const _uh = cred.response?.userHandle;
  const userHandle = _uh ? new Uint8Array(_uh) : null;
  return { credentialId: new Uint8Array(cred.rawId), prfOutput, userHandle };
}

// ---------------------------------------------------------------------------
// createVault — 新規アカウント
// ---------------------------------------------------------------------------

export async function createVault(password, userDisplayName, captchaToken = null, opts = {}) {
  if (!password) throw new Error("password required");
  // Phase 7.1-G: opts.mode = "personal" | "business" | "admin" を受け付ける
  //   business / admin の時は opts.companyId も渡す (= 招待 link から取得済)
  const mode = opts.mode || "personal";
  const companyId = opts.companyId || null;
  // 1. Recovery Secret 生成 (画面に 1 度表示)
  const { generateRecoverySecret } = await import("/lib/vault-crypto.js?v=11331c7d");
  const recoverySecret = generateRecoverySecret();
  const recoveryMaterial = deriveRMat(recoverySecret);
  const appNameTag = deriveAppNameTag(recoveryMaterial);  // {name,value}
  // 2. Passkey user.id (WebAuthn 内部識別子)
  //   envelope v7: 全モード (personal / business / admin) で user.id に v7 ペイロード
  //   (version + appNameTag + outerKey、57 byte) を焼き込む → 新端末でも localStorage /
  //   Recovery 無しに outer 鍵へ到達できる。encryptVaultBusiness も outer 鍵 / appNameTag を
  //   deriveOuterKeyBytes(rMat) / deriveAppNameTag(rMat) で導出する (encryptVault と同一) ため、
  //   v7 user.id 機構は business でもそのまま機能する (docs/envelope-v7-spec.md §0)。
  const userId = await encodeUserIdV7(appNameTag, deriveOuterKeyBytes(recoveryMaterial), password);
  // 3. Passkey 作成 → PRF (discoverable 必須 — 新端末で userHandle を読むため)
  const { credentialId, prfOutput } = await createPasskey(userId, userDisplayName, {
    requireResidentKey: true,
  });
  const credIdHash = await credentialIdToHash(credentialId);
  // 4. 空 vault → v5 envelope (credentials リストにこの端末を 1 個目として登録)
  // Phase 7.1-G: business mode の場合は mode + companyId を vault に焼き、
  //              admin / business 共に encryptedRecovery を inject **しない** (= admin が
  //              社員 Recovery を集約保管する設計のため社員 vault は持たない)
  const vault = emptyVault(mode, companyId);
  vault.credentials = [{
    credIdHash,
    name: userDisplayName,
    addedAt: new Date().toISOString(),
  }];
  // Phase 7.2-B (α): business mode は K1/K2 split + ECIES wrap of K1 to server pubkey
  //   Recovery は社員自身が持つ (= Personal mode 同様 encryptedRecovery を inject)
  let enc;
  let businessK2 = null;
  if (mode === "business") {
    if (!companyId) throw new Error("business mode requires companyId");
    // Phase 7.2-B v2: K1 は admin が後で server 経由で配布する。
    //   初回 signup 時はランダム K1 で body を暗号化、 admin 承認後の通常 unlock では
    //   server から fetch-enc-k1 で取り戻す。 admin 配布前は member は body を読めない。
    //   (= 「Admin の承認待ち」状態のあいだはこの envelope は復号不能)
    // Phase 7.2-B v2.6 hotfix: opts.k1Pending を bizCtx に forward。
    //   member signup (= 招待コード経由) は ZERO_K1 placeholder で envelope を作成し、
    //   admin の K1 配布後に tryTransitionFromPending で real K1 に置換する。
    //   admin signup (= 初回 corp 作成) は random K1 を生成し、 自分用 enc_K1 として保管。
    enc = await encryptVaultBusiness(vault, password, prfOutput, recoveryMaterial, credIdHash, {
      companyId,
      k1Pending: !!opts.k1Pending,
      // v2: initialK1 を省略 → encryptVaultBusiness 内で random 生成
      //   (admin signup の場合のみ。 k1Pending=true なら ZERO_K1 が使われ initialK1 は無視)
    }, recoverySecret);
    // Phase 7.3-A.9 part 3 hotfix: enc.k2 (raw) / enc.mek (raw) は廃止。
    //   businessK2 は null (= session は k2HkdfKey を使う)。 encryptedRecovery は
    //   encryptVaultBusiness 内で vaultWithRecovery に既に inject 済 (envelope body 内)。
    //   in-memory vault には mekHkdfKey 経由で同等の encryptedRecovery を再生成。
    businessK2 = null;
    if (recoverySecret && enc.mekHkdfKey) {
      try {
        vault.encryptedRecovery = await encryptRecoveryWithMek(recoverySecret, enc.mekHkdfKey);
      } catch (e) {
        console.warn("[createVault business] encryptedRecovery inject failed (non-fatal):", e?.message);
      }
    }
  } else {
    // personal / admin: 従来通り encryptedRecovery を inject
    const recoveryToInject = recoverySecret;
    enc = await encryptVault(vault, password, prfOutput, recoveryMaterial, credIdHash, recoveryToInject);
    // Phase 7.3-A.9 part 3 hotfix: enc.mek は null になった (Personal でも撲滅)。
    //   enc.mekHkdfKey を使う。
    if (recoverySecret && enc.mekHkdfKey) {
      try {
        vault.encryptedRecovery = await encryptRecoveryWithMek(recoverySecret, enc.mekHkdfKey);
      } catch (e) {
        console.warn("[createVault personal] encryptedRecovery inject failed (non-fatal):", e?.message);
      }
    }
  }
  // 5. 署名鍵を import → サーバ register (Phase 6.7-3: Turnstile token 同送)
  // Phase 7.2-B: business mode は signing identity を K2 由来にする
  //   (= openSession 内の派生と一致させる、 さもないと register/write が別 pubkey で行われ
  //    その後 saveVault が 401 / not_a_member で失敗する)
  // Phase 7.3-A.9 part 3: business mode で raw K2 が不在の場合は enc.signingKey を直接使う
  //   (= encryptVaultBusiness 内で deriveSigningKey 済)
  let signingState;
  if (mode === "business" && enc.signingKey) {
    const { importSigningKeyPair: _isk } = await import("/lib/vault-crypto.js?v=11331c7d");
    const { privateKey, publicKey } = await _isk(enc.signingKey.privateKeyJwk, enc.signingKey.publicKeyJwk);
    signingState = {
      signingPrivateKey: privateKey,
      signingPublicKey: publicKey,
      publicKeyRaw: enc.signingKey.publicKeyRaw,
      publicKeyJwk: enc.signingKey.publicKeyJwk,
    };
  } else {
    signingState = await buildSigningState(businessK2 ?? enc.mek);
  }
  await registerVault(signingState.publicKeyRaw, captchaToken);
  // 6. envelope を Arweave に書く (外側 AES-GCM 経由)
  // Phase 7.2-B/D hotfix (2026-06-05): business mode の招待コード経由 signup は
  //   writeEnvelope に inviteCode を渡す。 server が 未 member の場合に joinViaCode を
  //   先に実行して MEMBER_KEY 登録 + 通常 IP gate 適用に合流する。
  const writeResult = await writeEnvelope(
    enc.envelope, enc.outerKeyBytes, enc.appNameTag, signingState,
    {
      tier: businessK2 ? "corp" : "free",
      inviteCode: opts.inviteCode || null,  // business signup 経由のみ non-null
    },
  );
  // 7. localStorage メタ (Phase 7.0w-AR: vault-id 廃止 → outerKey 直接保存)
  const publicKeyHash = await hashPublicKey(signingState.publicKeyRaw);
  writeMeta({
    appNameTag: enc.appNameTag,
    credIdHash,
    credentialId: b64uEncode(credentialId),
    publicKeyHash,
    latestTxId: writeResult.txid,
  });
  // 8. セッション
  // Phase 7.3-A.7b/d: business / personal どちらも mekHkdfKey を session に保管。
  //   business: K1+K2 から derive、 personal: encryptVault が返した mekHkdfKey を流用。
  let _mekHkdfKey = null;
  if (mode === "business" && enc.k1 && businessK2) {
    try {
      _mekHkdfKey = await deriveBusinessMekHkdfKey(enc.k1, businessK2);
    } catch (e) {
      console.warn("[createVault] deriveBusinessMekHkdfKey failed (non-fatal):", e?.message);
    }
  } else if (enc.mekHkdfKey) {
    // Personal / admin: encryptVault が返した mekHkdfKey をそのまま使う
    _mekHkdfKey = enc.mekHkdfKey;
  }
  await openSession({
    vault, mek: enc.mek, mekKey: enc.mekKey,  // Phase 7.3-A.3
    mekHkdfKey: _mekHkdfKey,                  // Phase 7.3-A.7b/d
    // Phase 7.3-A.9 part 3: K2 を CryptoKey で session 保管 (V2 path)
    k2AesKey: enc.k2AesKey ?? null,
    k2HkdfKey: enc.k2HkdfKey ?? null,
    signingKey: enc.signingKey ?? null,
    outerKeyBytes: enc.outerKeyBytes,
    appNameTag: enc.appNameTag,
    recoveryMaterial,
    recoverySecret,    // Phase 7.0w-AP: 文字列も session に保持
    credIdHash, credentialId,
    latestTxId: writeResult.txid,
    lastEnvelope: enc.envelope,
    businessK2,        // Phase 7.2-B: business mode 用 K2 (= null for personal/admin)
    empPrivKey: mode === "business" ? (enc.empKeypair?.privKey ?? null) : null,
    k1Version: mode === "business" ? 1 : null,
  });

  // Phase 7.2-B v2: business mode signup 完了後、 emp_pubkey を server に登録
  // (= status="pending_k1" として記録、 admin が次回ログイン時に enc_K1 を配布)
  if (mode === "business" && enc.empKeypair?.pubKeyJwk) {
    try {
      await _registerEmpPubkeyV2(enc.empKeypair.pubKeyJwk, signingState);
      console.log("[createVault] emp_pubkey registered with server (status: pending_k1)");
    } catch (e) {
      console.error("[createVault] register-pubkey failed:", e?.message);
      // 致命的ではない — 後で再登録可能
    }
  }
  return { vault, latestTxId: writeResult.txid, recoverySecret };
}


// ===========================================================================
// envelope v7 増分2 — hwkey モード (YubiKey 専用) の作成・解錠
// ===========================================================================

/**
 * YubiKey 専用モードの vault を新規作成する。Master も Recovery も持たず、
 * 登録した YubiKey (>=2 本) のみで 1-of-N 解錠する。
 *
 * @param {number} keyCount         登録する YubiKey 本数 (>=2)
 * @param {string} userDisplayName  Passkey の表示名
 * @param {string|null} captchaToken
 * @param {object} [opts]  onBeforeKey?(i,total): 各 YubiKey 登録の直前に呼ぶ
 *                          (UI が「i 本目の YubiKey を挿してください」を出す用)
 * @returns {Promise<{vault, latestTxId}>}
 */
export async function createHwkeyVault(keyCount, userDisplayName, captchaToken = null, opts = {}) {
  if (!Number.isInteger(keyCount) || keyCount < 2)
    throw new Error("createHwkeyVault: YubiKey は 2 本以上必要です");

  // 1. N 本の YubiKey を登録 (各 createPasskey = WebAuthn ceremony、UV 必須)。
  //    各鍵に固有のランダム keyslot 所在タグを割り当て、user.id に焼く。
  const regs = [];  // { credentialId, prfOutput, credIdHash, keyslotTag }
  for (let i = 0; i < keyCount; i++) {
    if (typeof opts.onBeforeKey === "function") await opts.onBeforeKey(i, keyCount);
    const keyslotTag = randomAppNameTag();
    const userId = encodeUserIdHwkey(keyslotTag);
    const { credentialId, prfOutput } = await createPasskey(userId, userDisplayName, {
      requireResidentKey: true,
      userVerification: "discouraged", // hwkey: PRF を UV 非依存 (touch のみ) に固定
      followupTransports: ["usb", "nfc", "ble"],   // PRF follow-up get を YubiKey 直行に
    });
    const credIdHash = await credentialIdToHash(credentialId);
    regs.push({ credentialId, prfOutput, credIdHash, keyslotTag });
  }

  // 2. hwkey envelope を暗号化
  const vault = emptyVault("personal", null);
  vault.mode = "hwkey";
  vault.credentials = regs.map((r) => ({
    credIdHash: r.credIdHash, name: userDisplayName, addedAt: new Date().toISOString(),
  }));
  const enc = await encryptVaultHwkey(
    vault,
    regs.map((r) => r.prfOutput),
    regs.map((r) => r.credIdHash),
  );

  // 3. 署名鍵 (MEK 由来) → サーバ register
  const signingState = await buildSigningState(enc.mek);
  await registerVault(signingState.publicKeyRaw, captchaToken);

  // 4. vault 本体 blob を Arweave に書く (外層 AES-GCM 経由)
  const writeResult = await writeEnvelope(
    enc.envelope, enc.outerKeyBytes, enc.appNameTag, signingState, { tier: "free" },
  );

  // 5. 各 YubiKey の keyslot blob を書く (write-once、GraphQL で発見される)
  for (const r of regs) {
    const ksBlob = await encodeKeyslot(r.prfOutput, enc.appNameTag, enc.outerKeyBytes);
    await writeKeyslot(ksBlob, r.keyslotTag, signingState);
  }

  // 6. localStorage meta — この端末で最初に登録した鍵を current 扱い
  const thisCred = regs[0];
  const publicKeyHash = await hashPublicKey(signingState.publicKeyRaw);
  writeMeta({
    appNameTag: enc.appNameTag,
    mode: "hwkey",
    credIdHash: thisCred.credIdHash,
    credentialId: b64uEncode(thisCred.credentialId),
    publicKeyHash,
    latestTxId: writeResult.txid,
  });

  // 7. セッション
  await openSession({
    vault, mek: enc.mek, mekKey: enc.mekKey, mekHkdfKey: enc.mekHkdfKey ?? null,
    outerKeyBytes: enc.outerKeyBytes, appNameTag: enc.appNameTag,
    recoveryMaterial: null, recoverySecret: null,
    credIdHash: thisCred.credIdHash, credentialId: thisCred.credentialId,
    latestTxId: writeResult.txid, lastEnvelope: enc.envelope,
    businessK2: null, signingKey: enc.signingKey ?? null,
  });
  return { vault, latestTxId: writeResult.txid };
}

/**
 * hwkey モードの vault を YubiKey 1 本で解錠する (§7.3、1-of-N)。
 *   YubiKey → user.id (keyslot 所在タグ) → keyslot blob → outer 鍵 + vault 所在
 *   → vault 本体 → decryptVaultHwkey。Master も Recovery も localStorage も不要。
 * @param {object} [options]  forcePicker: ピッカー強制
 * @returns {Promise<{vault, latestTxId, path:"K"}>}
 */
// envelope v7 増分2: hwkey 用の堅牢な YubiKey 認証。
//   picker (allowCredentials 空) の get() は一部ブラウザ/YubiKey で PRF 拡張の
//   結果を返さない ("PRF extension required but not returned")。 その場合は
//   1 回目で確定した credentialId を使い specific allowCredentials で 2 回目の
//   get() を行って PRF を取得する。 specific get の PRF は createPasskey の
//   follow-up get と同経路で確実に返る (= 同一端末解錠が動いている実績)。
//   返り値: { credentialId, prfOutput, userHandle }
async function _authenticateHwkey({ forcePicker = false, credentialIdHint = null } = {}) {
  // 1 回目: credentialId / userHandle を取得 (PRF は picker get では返らないことがある)。
  const first = await authenticateWithPasskey(credentialIdHint, {
    forcePicker, prfOptional: true,
    // hwkey は必ず YubiKey。 transports を渡すと Safari がプラットフォーム
    //   認証器を探さず YubiKey に直行する (= 「資格情報が見つかりません」回避)。
    transports: ["usb", "nfc", "ble"],
    // PRF は UV 有無で値が変わる。 Mac Safari は "required" でも UV を省く
    //   ことがあるため、 全プラットフォームで一致させるべく UV なしに固定する。
    userVerification: "discouraged",
  });
  let { credentialId, prfOutput, userHandle } = first;
  console.log("[_authenticateHwkey] 1st get:",
    "credIdLen=" + (credentialId ? credentialId.length : 0),
    "prf=" + !!prfOutput,
    "uhLen=" + (userHandle ? userHandle.length : 0),
    "isHwkey=" + (userHandle ? isUserIdHwkey(userHandle) : false));
  // 選んだ資格情報が hwkey 形式 (= YubiKey モードのドライブの鍵) でなければ即中断。
  //   同期パスキー (他ドライブの platform passkey) を選んでしまった場合に該当。
  if (!userHandle || !isUserIdHwkey(userHandle)) {
    const er = new Error("選択された鍵は YubiKey モードのドライブのものではありません");
    er.code = "hwkey_wrong_passkey_type";
    throw er;
  }
  // 2 回目: PRF が無ければ、 確定した credentialId を名指しして PRF を取得する。
  //   hints は使わない (specific get がブラウザで picker 化されることがあるため)。
  //   transports でブラウザを YubiKey に直行させる。
  if (!prfOutput) {
    if (!credentialId || !credentialId.length) {
      const er = new Error("hwkey: 1 回目の get で credentialId を取得できませんでした");
      er.code = "hwkey_no_credential_id";
      throw er;
    }
    console.log("[_authenticateHwkey] PRF 未返却 — credentialId 名指しで 2 回目の get()");
    let second;
    try {
      second = await authenticateWithPasskey(credentialId, { transports: ["usb", "nfc", "ble"], userVerification: "discouraged" });
    } catch (e) {
      console.warn("[_authenticateHwkey] 2nd get failed:", e?.name, e?.message);
      const er = new Error("YubiKey から PRF を取得できませんでした (" + (e?.name || "error") + ": " + (e?.message || e) + ")");
      er.code = "hwkey_prf_get_failed";
      er.original = e;
      throw er;
    }
    console.log("[_authenticateHwkey] 2nd get: prf=" + !!second.prfOutput);
    prfOutput = second.prfOutput;
  }
  if (!prfOutput) throw new Error("PRF extension required but not returned");
  return { credentialId, prfOutput, userHandle };
}

// envelope v7 増分2: hwkey 認証を「1 回の WebAuthn get() だけ」行うラッパー。
//   Safari は WebAuthn get() ごとに新しいユーザー操作 (transient activation) を
//   要求するため、 2 段 get を 1 関数内で連続実行できない。 そこで「1 回 get
//   するだけ」の関数に分け、 UI 側が 2 回のクリックに分けて呼べるようにする。
//   返り値: { credentialId, prfOutput (null のことあり), userHandle }
export async function hwkeyAuthenticate({ forcePicker = false, credentialIdHint = null, transports = null } = {}) {
  const r = await authenticateWithPasskey(credentialIdHint, {
    forcePicker,
    prfOptional: true,
    // hwkey の PRF は UV 有無で値が変わる。 Mac/iPhone で UV の有無が
    //   食い違わないよう、 UV なし (touch のみ) に固定する。
    userVerification: "discouraged",
    // Phase 7.5R revert (Phase 7.5T): hints: ["security-key"] を一度追加したが、
    //   user 報告で Android Chrome の挙動を変えてしまった可能性あり (= 「Passkey 選択」
    //   UI に遷移せず CredentialManager unknown error)。 hints 無しが元々動いていた
    //   とのことなので元に戻す。 hints は WebAuthn L3 の新機能で実装差が激しく、
    //   慎重に扱う必要あり。 必要なら個別ブラウザ向けに conditional 化する。
    ...(Array.isArray(transports) && transports.length ? { transports } : {}),
  });
  // picker get (= 候補から選ぶ) のときだけ hwkey 形式を検証する。
  //   specific get では userHandle が返らないことがあるため検証しない。
  if (forcePicker && !credentialIdHint) {
    if (!r.userHandle || !isUserIdHwkey(r.userHandle)) {
      const er = new Error("選択された鍵は YubiKey モードのドライブのものではありません");
      er.code = "hwkey_wrong_passkey_type";
      throw er;
    }
  }
  console.log("[hwkeyAuthenticate] credIdLen=" + (r.credentialId ? r.credentialId.length : 0) +
    " prf=" + !!r.prfOutput + " uhLen=" + (r.userHandle ? r.userHandle.length : 0));
  return r;
}

// envelope v7 増分2: 解錠用の hwkey 認証。 localStorage meta に credentialId が
//   あれば (= この端末で登録済み) それを名指しした specific get を行い、
//   ブラウザのパスキー一覧 (picker) を出さず YubiKey に直行する。 meta が
//   無ければ (新端末) picker get。 名指しが失敗したら picker に fallback
//   (= 別の登録済み YubiKey を挿した場合などに対応)。
//   返り値: { credentialId, prfOutput, userHandle }
// Phase 7.5Z: hwkey 端末追加コードの encode/decode。
//   既存端末 (iPhone Safari / Mac Chrome 等) で credentialId + keyslotTag を
//   コード化し、 新端末 (Android Chrome) の localStorage meta に注入する用。
//   Android Chrome は picker get (allowCredentials=[]) で security key の
//   discoverable credentials を列挙できない CTAP2 実装欠落バグがあるため、
//   credentialId を事前に渡せば specific get で picker をスキップして解錠できる。
//
//   コード形式: "AP1-<b64u credentialId>-<b64u tagName>-<b64u tagValue>"
//     - AP1 = Arpass Passkey 端末追加コード v1 (prefix で形式検証)
//     - credentialId: 任意長 b64u
//     - tagName / tagValue: 短い b64u 文字列
//   ZK 影響なし: credentialId は元から WebAuthn 公開、 tag は元から Arweave 公開。
//   PRF / 暗号鍵 / Recovery は一切含まない (= 漏洩しても vault は守られる)。
export function encodeDeviceAddCode({ credentialId, keyslotTag }) {
  if (!(credentialId instanceof Uint8Array) || credentialId.length === 0)
    throw new Error("encodeDeviceAddCode: credentialId が不正");
  if (!keyslotTag?.name || !keyslotTag?.value)
    throw new Error("encodeDeviceAddCode: keyslotTag が不正");
  // Phase 7.5ZB: separator を b64u 外文字 (= ドット) に変更。
  //   旧 "AP1-...-..." は credentialId / keyslotTag の b64u 内 ハイフンと
  //   衝突して split が破綻していた (= iPhone で credentialId.b64u に "-"
  //   が含まれる確率分だけ失敗する flaky bug)。 ドット は b64u に含まれない
  //   ため確実に分離できる。
  return "AP1." + b64uEncode(credentialId) +
    "." + keyslotTag.name + "." + keyslotTag.value;
}

export function decodeDeviceAddCode(code) {
  if (typeof code !== "string") throw new Error("decodeDeviceAddCode: 文字列必須");
  const trimmed = code.trim();
  // Phase 7.5ZB: ドット separator (= 現行) を優先、 旧 ハイフン形式は対応外
  //   (= 旧形式は b64u ハイフン衝突で flaky だったため compat 維持不要)
  if (!trimmed.startsWith("AP1."))
    throw new Error("コード形式が違います (AP1. で始まる必要があります)");
  const parts = trimmed.slice(4).split(".");
  if (parts.length !== 3)
    throw new Error("コード形式が違います (要素数不一致: " + parts.length + ")");
  const [credB64u, tagName, tagValue] = parts;
  if (!credB64u || !tagName || !tagValue)
    throw new Error("コードの一部が空です");
  let credentialId;
  try { credentialId = b64uDecode(credB64u); }
  catch { throw new Error("credentialId の decode に失敗"); }
  if (credentialId.length === 0)
    throw new Error("credentialId が空");
  return { credentialId, keyslotTag: { name: tagName, value: tagValue } };
}

// Phase 7.5Y: Android Chrome 検知 (= picker mode + PRF で NotReadableError 回避用)
function _isAndroidChrome() {
  try {
    const ua = (typeof navigator !== "undefined" && navigator.userAgent) || "";
    return /Android/i.test(ua) && !/Firefox|FxiOS/i.test(ua);
  } catch { return false; }
}

export async function hwkeyAuthenticateForUnlock() {
  let hint = null;
  try {
    const meta = readMeta();
    if (meta && meta.mode === "hwkey" && meta.credentialId) {
      hint = b64uDecode(meta.credentialId);
    }
  } catch (e) {
    console.warn("[hwkeyAuthForUnlock] meta 読み取り失敗 — picker:", e?.message);
  }
  if (hint) {
    try {
      console.log("[hwkeyAuthForUnlock] meta credentialId あり — specific get (一覧なし)");
      return await hwkeyAuthenticate({
        credentialIdHint: hint,
        transports: ["usb", "nfc", "ble"],
      });
    } catch (e) {
      console.error("[hwkeyAuthForUnlock] specific get FAILED — picker に fallback:",
        "name=" + e?.name, "message=" + e?.message,
        "credIdLen=" + (hint?.length || 0));
    }
  }

  // Phase 7.5Y: Android Chrome は picker mode (allowCredentials=[]) + PRF 拡張で
  //   NotReadableError "An unknown error occurred while talking to the credential
  //   manager" を出す既知バグ。 2-tap に分けて回避する:
  //     Tap 1: PRF 拡張なしの picker get → credentialId + userHandle を発見
  //     Tap 2: specific get + PRF → PRF を取得して解錠
  //   Mac Chrome / iPhone Safari は picker + PRF で問題ないので、 1-tap 維持。
  if (_isAndroidChrome()) {
    console.log("[hwkeyAuthForUnlock] Android picker — 2-tap mode (PRF bug 回避)");
    // Tap 1: PRF なしで discover
    const discovered = await authenticateWithPasskey(null, {
      forcePicker: true,
      prfOptional: true,
      userVerification: "discouraged",
      skipPrfExtension: true,  // ← Phase 7.5Y: Android Chrome bug 回避の本命
    });
    if (!discovered.userHandle || !isUserIdHwkey(discovered.userHandle)) {
      const er = new Error("選択された鍵は YubiKey モードのドライブのものではありません");
      er.code = "hwkey_wrong_passkey_type";
      throw er;
    }
    // Tap 2: 発見した credentialId 名指しで PRF 取得
    console.log("[hwkeyAuthForUnlock] Android 2nd tap: specific get + PRF");
    return await hwkeyAuthenticate({
      credentialIdHint: discovered.credentialId,
      transports: ["usb", "nfc", "ble"],
    });
  }

  console.log("[hwkeyAuthForUnlock] picker get (1-tap)");
  return await hwkeyAuthenticate({ forcePicker: true });
}

// envelope v7 増分2: 認証済みの { credentialId, prfOutput, userHandle } から
//   keyslot 発見 → vault 取得 → 復号 → meta/session を行う (WebAuthn は呼ばない)。
// デバッグ用: バイト列の SHA-256 先頭 8 hex (= 端末間で PRF 等を比較するため。
//   一方向ハッシュなので元の秘密は復元不能)。
async function _dbgHash(bytes) {
  try {
    if (!(bytes instanceof Uint8Array)) return "n/a";
    const h = await crypto.subtle.digest("SHA-256", bytes);
    return [...new Uint8Array(h).slice(0, 4)].map((b) => b.toString(16).padStart(2, "0")).join("");
  } catch { return "?"; }
}

// envelope v7 増分2: 作成直後の Arweave blob は read 用ゲートウェイへの伝播に
//   時間がかかり、 一時的に 404 / 5xx (572 含む) になる。 「未反映」系エラーのみ
//   バックオフ付きで再試行する (合計 ~60s)。 復号失敗など他のエラーは即 throw。
async function _retryArweaveFetch(fn, label) {
  // Phase 7.5O: 最初の retry を 1s に短縮 (= upload.ardrive.io が即返する fresh write を素早く捕まえる)
  const delays = [0, 1000, 2000, 4000, 8000, 12000, 16000, 18000];  // 合計 ~61s
  let lastErr;
  for (let i = 0; i < delays.length; i++) {
    if (delays[i]) {
      console.log("[hwkeyUnlock] " + label + ": Arweave 反映待ち — " +
        Math.round(delays[i] / 1000) + "s 後に再試行 (" + i + "/" + (delays.length - 1) + ")");
      await new Promise((res) => setTimeout(res, delays[i]));
    }
    try {
      return await fn();
    } catch (e) {
      lastErr = e;
      const msg = String(e && e.message ? e.message : e);
      if (!/not available|not found|HTTP 404|HTTP 5\d\d/i.test(msg)) throw e;
      console.warn("[hwkeyUnlock] " + label + " 取得 試行 " + (i + 1) + " 未反映:", msg);
    }
  }
  throw lastErr;
}

export async function unlockWithHwkeyAuthed({ credentialId, prfOutput, userHandle, __onPhase }) {
  if (!prfOutput)
    throw new Error("PRF extension required but not returned");
  if (!userHandle || !isUserIdHwkey(userHandle))
    throw new Error("この Passkey は YubiKey モード (hwkey) の形式ではありません");

  // Phase 7.5P: 細粒度 progress callback (app-main.js から渡る)
  const _phase = typeof __onPhase === "function" ? __onPhase : () => {};

  console.log("[hwkeyUnlock] start; prfHash=" + (await _dbgHash(prfOutput)) +
    " prfLen=" + prfOutput.length + " credIdLen=" + (credentialId ? credentialId.length : 0));

  // user.id (= hwkey 形式) から keyslot 所在タグを取り出す
  const { keyslotTag } = decodeUserIdHwkey(userHandle);
  console.log("[hwkeyUnlock] keyslotTag name=" + keyslotTag.name + " value=" + keyslotTag.value);

  // keyslot blob の所在を発見 → 取得 → この YubiKey の PRF で復号。
  // Phase 7.5N: まず server KV 索引 (= 即時、 lag なし) を引く。 無ければ
  // 公開 GraphQL で fallback (= 古い keyslot や KV 索引欠落の救済)。
  _phase("phase_lookup_keyslot");
  const _tKsLookup = performance.now();
  let ksTxid = await lookupKeyslotTxid(keyslotTag);
  if (ksTxid) {
    console.log("[hwkeyUnlock] lookupKeyslotTxid (server KV) -> " + ksTxid +
      " in " + Math.round(performance.now() - _tKsLookup) + "ms");
  } else {
    console.log("[hwkeyUnlock] lookupKeyslotTxid returned null after " +
      Math.round(performance.now() - _tKsLookup) + "ms — fallback GraphQL");
    ksTxid = await findLatestVaultTx(keyslotTag);
    console.log("[hwkeyUnlock] findLatestVaultTx(keyslot GraphQL fallback) -> " + ksTxid +
      " in " + Math.round(performance.now() - _tKsLookup) + "ms");
  }
  if (!ksTxid) {
    const er = new Error("keyslot が Arweave 上に見つかりません");
    er.code = "hwkey_keyslot_not_found";
    throw er;
  }
  let ksBlob;
  _phase("phase_fetch_keyslot");
  const _tKsFetch = performance.now();
  try {
    ksBlob = await _retryArweaveFetch(() => fetchKeyslotBlob(ksTxid), "keyslot");
    console.log("[hwkeyUnlock] fetchKeyslotBlob took " + Math.round(performance.now() - _tKsFetch) + "ms");
  } catch (e) {
    console.error("[hwkeyUnlock] keyslot blob 取得失敗 (未反映):", e?.message || e);
    const er = new Error("keyslot がまだ Arweave に反映されていません");
    er.code = "hwkey_not_propagated";
    er.original = e;
    throw er;
  }
  console.log("[hwkeyUnlock] keyslot blob fetched; len=" + (ksBlob ? ksBlob.length : 0));

  let appNameTag, outerKey;
  try {
    ({ appNameTag, outerKey } = await decodeKeyslot(prfOutput, ksBlob));
  } catch (e) {
    console.error("[hwkeyUnlock] decodeKeyslot FAILED:", e?.name, e?.message);
    const er = new Error("keyslot の復号に失敗 — この YubiKey の PRF が keyslot と一致しません");
    er.code = "hwkey_keyslot_decrypt_failed";
    er.original = e;
    throw er;
  }
  console.log("[hwkeyUnlock] decodeKeyslot OK; appNameTag.value=" + appNameTag.value);

  // vault 本体を取得 → 外層復号 → hwkey 復号
  const credIdHash = await credentialIdToHash(credentialId);
  _phase("phase_resolve_vault");
  const _tVaultLookup = performance.now();
  const txid = await resolveLatestTxIdForUnlock({ appNameTag });
  console.log("[hwkeyUnlock] resolveLatestTxIdForUnlock -> " + txid +
    " in " + Math.round(performance.now() - _tVaultLookup) + "ms");
  if (!txid) {
    const er = new Error("Vault が Arweave 上に見つかりません (まだ書き込みなし？)");
    er.code = "hwkey_vault_not_found";
    throw er;
  }
  let envelope;
  _phase("phase_fetch_vault");
  const _tEnvFetch = performance.now();
  try {
    ({ envelope } = await _retryArweaveFetch(() => fetchEnvelope(txid, outerKey), "envelope"));
    console.log("[hwkeyUnlock] fetchEnvelope took " + Math.round(performance.now() - _tEnvFetch) + "ms");
  } catch (e) {
    const msg = String(e && e.message ? e.message : e);
    if (/not available|not found|HTTP 404|HTTP 5\d\d/i.test(msg)) {
      console.error("[hwkeyUnlock] envelope 未反映:", msg);
      const er = new Error("Vault がまだ Arweave に反映されていません");
      er.code = "hwkey_not_propagated";
      er.original = e;
      throw er;
    }
    console.error("[hwkeyUnlock] outer decrypt failed:", msg);
    const oErr = new Error("unlock_outer_failed_v7");
    oErr.code = "unlock_outer_failed_v7";
    oErr.original = e;
    throw oErr;
  }
  console.log("[hwkeyUnlock] fetchEnvelope OK; m=" + (envelope ? envelope.m : "?") +
    " k.len=" + (envelope && envelope.k ? envelope.k.length : 0));

  let r;
  _phase("phase_decrypt");
  try {
    r = await decryptVaultHwkey(envelope, prfOutput, credIdHash);
  } catch (e) {
    console.error("[hwkeyUnlock] decryptVaultHwkey FAILED:", e?.name, e?.message);
    const er = new Error("vault の復号に失敗しました");
    er.code = "hwkey_vault_decrypt_failed";
    er.original = e;
    throw er;
  }
  console.log("[hwkeyUnlock] decryptVaultHwkey OK");

  // meta / session
  writeMeta({
    appNameTag,
    mode: "hwkey",
    credIdHash,
    credentialId: b64uEncode(credentialId),
    latestTxId: txid,
  });
  await openSession({
    vault: r.vault, mek: r.mek, mekKey: r.mekKey, mekHkdfKey: r.mekHkdfKey ?? null,
    outerKeyBytes: outerKey, appNameTag,
    recoveryMaterial: null, recoverySecret: null,
    credIdHash, credentialId,
    latestTxId: txid, lastEnvelope: envelope,
    businessK2: null, signingKey: r.signingKey ?? null,
  });
  console.log("[hwkeyUnlock] openSession OK — unlocked");
  return { vault: r.vault, latestTxId: txid, path: "K" };
}

export async function unlockWithHwkey(options = {}) {
  const meta = readMeta();
  const credIdHint = (!options.forcePicker && meta?.credentialId)
    ? b64uDecode(meta.credentialId) : null;
  // 同一端末解錠 (credIdHint あり) は specific get 1 回で PRF まで取得できる。
  //   新端末 (picker) で PRF が 1 回で取れない場合は _authenticateHwkey が
  //   2 段 get する — Safari では UI 側の 2 クリック方式 (hwkeyAuthenticate +
  //   unlockWithHwkeyAuthed) を使うこと。
  let auth;
  try {
    auth = await _authenticateHwkey({
      forcePicker: options.forcePicker || false,
      credentialIdHint: credIdHint,
    });
  } catch (e) {
    if (credIdHint) {
      auth = await _authenticateHwkey({ forcePicker: true });
    } else { throw e; }
  }
  return unlockWithHwkeyAuthed(auth);
}

// ============================================================================
// envelope v7 増分2: hwkey (YubiKey 専用) vault に YubiKey を 1 本追加する。
//   1. 既存の登録済み YubiKey で認証 → その keyslot blob から outerKey /
//      appNameTag を、 envelope.k[] から raw MEK を取り出す。
//      (session の mek は zeroize 済みのため、 wrapMekForPrf 用に再取得が必要。)
//   2. 新しい YubiKey を登録 (createPasskey、 resident + UV 必須)。
//   3. envelope.k[] に新鍵の PRF-wrap を追加し、 新鍵専用の keyslot blob を書く。
//   4. saveVault で envelope を永続化。
//   opts.onExistingKey() / opts.onNewKey() で UI 進捗・鍵差し替え確認を行う
//   (onNewKey が throw した場合はキャンセル扱いで何も変更しない)。
// ============================================================================
export async function addHwkeyDevice(userDisplayName, opts = {}) {
  if (!_session || _session.lastEnvelope?.m !== "hwkey")
    throw new Error("addHwkeyDevice: hwkey vault がロックされていません");
  if (!_session.signingState)
    throw new Error("addHwkeyDevice: signingState 不在");

  // --- 1. 既存の YubiKey で認証 → MEK / outerKey / appNameTag を取得 ---
  if (typeof opts.onExistingKey === "function") await opts.onExistingKey();
  const ex = await _authenticateHwkey({ forcePicker: true });
  if (!ex.userHandle || !isUserIdHwkey(ex.userHandle))
    throw new Error("addHwkeyDevice: 選択された YubiKey は YubiKey モード形式ではありません");
  const exKeyslotTag = decodeUserIdHwkey(ex.userHandle).keyslotTag;
  // Phase 7.5N: server KV 索引で即時取得、 無ければ GraphQL fallback
  let exKsTxid = await lookupKeyslotTxid(exKeyslotTag);
  if (!exKsTxid) exKsTxid = await findLatestVaultTx(exKeyslotTag);
  if (!exKsTxid) throw new Error("addHwkeyDevice: 既存 YubiKey の keyslot が見つかりません");
  const exKsBlob = await fetchKeyslotBlob(exKsTxid);
  const { appNameTag, outerKey } = await decodeKeyslot(ex.prfOutput, exKsBlob);
  const exCredIdHash = await credentialIdToHash(ex.credentialId);
  const exDec = await decryptVaultHwkey(_session.lastEnvelope, ex.prfOutput, exCredIdHash);
  const mek = exDec.mek;   // raw 32B — wrapMekForPrf 用

  let newEnvelope, newCredIdHash;
  try {
    // --- 2. 新しい YubiKey を登録 ---
    if (typeof opts.onNewKey === "function") await opts.onNewKey();
    const newKeyslotTag = randomAppNameTag();
    const newUserId = encodeUserIdHwkey(newKeyslotTag);
    const { credentialId: newCredId, prfOutput: newPrf } = await createPasskey(
      newUserId, userDisplayName,
      { requireResidentKey: true, userVerification: "discouraged",
        followupTransports: ["usb", "nfc", "ble"] },
    );
    newCredIdHash = await credentialIdToHash(newCredId);

    // --- 3. envelope.k[] に追加 + 新鍵の keyslot blob を書く ---
    newEnvelope = await addHwkey(_session.lastEnvelope, mek, newPrf, newCredIdHash);
    const ksBlob = await encodeKeyslot(newPrf, appNameTag, outerKey);
    await writeKeyslot(ksBlob, newKeyslotTag, _session.signingState);
  } finally {
    // raw 秘密は必ず破棄 (キャンセル時も)。
    if (mek instanceof Uint8Array) mek.fill(0);
    if (outerKey instanceof Uint8Array) outerKey.fill(0);
  }

  // --- 4. session 更新 + 保存 (try が throw した場合はここに到達しない) ---
  _session.lastEnvelope = newEnvelope;
  const vault = _session.vault;
  if (!Array.isArray(vault.credentials)) vault.credentials = [];
  vault.credentials.push({
    credIdHash: newCredIdHash,
    name: userDisplayName,
    addedAt: new Date().toISOString(),
  });
  await saveVault(vault);
  return { credentials: vault.credentials.slice() };
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
  // envelope v7 (Master-wrap): outer 鍵は localStorage に保存しない。常に WebAuthn
  //   userHandle (= v7 user.id) から復元する。user.id 内の outer 鍵は Master で
  //   ラップされているため password で unwrap する。appNameTag は秘密でないため
  //   meta に残し、既知端末は meta から得る。
  const hasMeta = !!meta?.appNameTag;

  // Phase 5.3-J: ハイブリッド経路 (hint で 1-click → 失敗時 picker fallback)。
  //   envelope v7: 新端末は meta が無いので認証を先に実行し、 WebAuthn userHandle
  //   (= v7 user.id) から outer 鍵 / appNameTag を取り出す。
  const credIdHint = (!options.forcePicker && meta?.credentialId)
    ? b64uDecode(meta.credentialId)
    : null;

  let credentialId, prfOutput, userHandle;
  try {
    ({ credentialId, prfOutput, userHandle } = await authenticateWithPasskey(credIdHint, {
      forcePicker: options.forcePicker || false,
    }));
  } catch (e) {
    // hint Passkey が消えてた / NotAllowed (cancel) → picker fallback
    if (credIdHint) {
      console.log("[unlock] hint Passkey unavailable, opening picker:", e?.message);
      ({ credentialId, prfOutput, userHandle } = await authenticateWithPasskey(null, { forcePicker: true }));
    } else {
      throw e;
    }
  }
  const credIdHash = await credentialIdToHash(credentialId);

  // outer 鍵は localStorage に保存しない (envelope v7)。常に WebAuthn userHandle
  //   (= v7 user.id) から復元する。user.id 内の outer 鍵は Master でラップされて
  //   いる (envelope-v7-spec.md §3-4) ので password で unwrap する。appNameTag は
  //   秘密でないため、既知端末は meta から / 新端末は user.id から得る。
  let outerKeyBytes, appNameTag, freshDevice = !hasMeta;
  if (userHandle && isUserIdV7(userHandle)) {
    const _v7 = await decodeUserIdV7(userHandle, password);
    outerKeyBytes = _v7.outerKey;
    appNameTag = hasMeta ? meta.appNameTag : _v7.appNameTag;
    if (freshDevice) console.log("[unlock-AB] envelope v7: 新端末 — appNameTag を user.id から取得");
  } else {
    throw new Error("この端末のパスキーは envelope v7 形式ではありません。「すでにアカウントがある」から復元してください");
  }

  const txid = await resolveLatestTxIdForUnlock(hasMeta ? meta : { appNameTag });
  if (!txid) throw new Error("Vault が Arweave 上に見つかりません (まだ書き込みなし？)");
  // Stage 2c Stage D3 + E: outer key を Rust OuterKey handle に wrap して
  //   fetchEnvelope に渡す。 Stage E では session にも保存し、 後続 writeEnvelope
  //   path でも handle 経由で再利用する (= raw bytes 1 回作成→ 多用)。
  let _abOuterKey = null;
  try {
    _abOuterKey = await importOuterKeyAsHandle(outerKeyBytes);
    if (_abOuterKey) _session.outerKeyHandle = _abOuterKey;  // Stage E: write path 用に保存
  } catch (_e) { /* swallow → fallback to raw */ }
  let envelope;
  try {
    ({ envelope } = await fetchEnvelope(txid, _abOuterKey ?? outerKeyBytes));
  } catch (e) {
    // envelope v7 (Master-wrap): outer 鍵は user.id を Master でアンラップして得る。
    //   outer 層の AES-GCM 復号失敗 = outer 鍵が誤り = Master 取り違え、または
    //   別端末で Master 変更後に古い Passkey を選んだ (envelope-v7-spec.md §14)。
    //   UI が「別の Passkey で開錠する」を案内できるよう専用 code を付ける。
    //   network / HTTP 失敗はそのまま投げる (原因を握り潰さない)。
    if (/Outer envelope decryption failed/.test(e?.message || "")) {
      console.error("[unlock-AB] outer decrypt failed (wrong Master or stale passkey after Master change)");
      const oErr = new Error("unlock_outer_failed_v7");
      oErr.code = "unlock_outer_failed_v7";
      oErr.original = e;
      throw oErr;
    }
    throw e;
  }

  // ★ Phase 5.3-I: 復号 BEFORE patchMeta (間違った Passkey 選択時の汚染防止)
  let vault, mek, path;
  try {
    var _r = await decryptVaultAuto(envelope, { password, prfOutput, credIdHash });
    ({ vault, mek, path } = _r);
    var _businessK2_AB = _r.businessK2;
  } catch (e) {
    // Phase 7.2-B v2.6 hotfix: K1 未配布 / K1 fetch 失敗 / 機種未登録 などの
    // business mode 固有エラーは「passkey が間違い」では誤解を招くので preserve。
    // それ以外 (= crypto factor 復号失敗) は従来通り passkey_wrong_for_vault に変換し、
    // UI が「別の Passkey で再試行」ボタンを出せるようにする。
    const preserveCodes = new Set([
      "k1_pending",            // K1 が admin から未配布 (= 待機メッセージを表示)
      "k1_fetch_error",        // K1 fetch HTTP error
      "fetch_error",           // generic server fetch error
      "not_member",            // member 登録が無い (= revoked or never joined)
      "revoked",
      "company_inactive",
      "ecies_unwrap_failed",   // K1 unwrap 失敗 (= 機種追加コード 未通過)
      "w_emp_unwrap_failed",   // emp_priv unwrap 失敗 (= K2 不一致 = factor 失敗ではない)
    ]);
    if (e?.code && preserveCodes.has(e.code)) {
      console.error("[unlock-AB] bubbling preserved error:", e?.code, e?.message);
      throw e;  // bubble up with friendly code
    }
    // #161: Master 取り違えと Passkey 取り違えを区別する。
    //   passkeyWrapPresent === true は「この Passkey 用 wrap が envelope に存在した」
    //   = Passkey はこの vault に登録済 (= 正しい)。 wrap はあるのに KEK 復号が失敗した
    //   = もう一方の factor (Master) が不一致。 「別の Passkey で再試行」は誤誘導なので、
    //   master_wrong として bubble し UI に「Master を確認」を出させる。
    if (e?.passkeyWrapPresent === true) {
      console.error("[unlock-AB] master password mismatch (passkey enrolled in vault, KEK derivation failed)");
      const mErr = new Error("master_wrong");
      mErr.code = "master_wrong";
      mErr.original = e;
      throw mErr;
    }
    // 通常の crypto factor 失敗 → passkey 間違い扱い
    //   v2.6 hotfix: 真の失敗原因を必ず log。 これがないと「passkey が違う」 メッセージが
    //   どこから来たのか追跡不能になる。
    console.error("[unlock-AB] decryptVaultAuto failed (wrapping as passkey_wrong_for_vault):",
      e?.message || e, "stack:", e?.stack);
    const retryErr = new Error("passkey_wrong_for_vault");
    retryErr.code = "passkey_wrong_for_vault";
    retryErr.original = e;
    throw retryErr;
  }

  // 復号成功 → この credentialId は確かに **この vault に登録済**と確認できた。
  //   既知端末: meta を patch。 新端末 (envelope v7): meta を新規作成。
  if (freshDevice) {
    writeMeta({
      appNameTag,
      credentialId: b64uEncode(credentialId),
      credIdHash,
      latestTxId: txid,
    });
    console.log("[unlock-AB] envelope v7: 新端末の meta を新規作成");
  } else if (!meta.credentialId || meta.credentialId !== b64uEncode(credentialId)) {
    patchMeta({ credentialId: b64uEncode(credentialId), credIdHash });
  }
  await openSession({
    vault, mek, mekKey: _r?.mekKey,  // Phase 7.3-A.3
    mekHkdfKey: _r?.mekHkdfKey ?? null,  // Phase 7.3-A.7b
    outerKeyBytes,
    appNameTag,
    recoveryMaterial: null,
    credIdHash, credentialId,
    latestTxId: txid,
    lastEnvelope: envelope,
    businessK2: null,  // Phase 7.3-A.9 part 3: raw K2 廃止
    k2AesKey: _r?.k2AesKey ?? null,
    k2HkdfKey: _r?.k2HkdfKey ?? null,
    signingKey: _r?.signingKey ?? null,
    empPrivKey: _r?.empPrivKey ?? null,
    k1Version: _r?.k1Version ?? null,
  });
  patchMeta({ latestTxId: txid });
  return { vault, latestTxId: txid, path };
}

/**
 * Path AC: Master + Recovery
 */
export async function unlockWithPasswordAndRecovery(password, recoveryString, opts = {}) {
  const recoveryMaterial = deriveRMat(recoveryString);
  const outerKeyBytes = deriveOuterKeyBytes(recoveryMaterial);
  // Stage 2c Stage F: outer key を Rust OuterKey handle に wrap (= 全 fetchEnvelope で再利用)。
  //   Rust 未 load 時は null で、 fallback で raw bytes path を使う。
  let _acOuterKey = null;
  try { _acOuterKey = await importOuterKeyAsHandle(outerKeyBytes); } catch (_e) {}
  const appNameTag = deriveAppNameTag(recoveryMaterial);  // bootstrap (tier 未定) {name,value}
  // Phase 6.4.1: tier qualifier で並列検索 — 5 tier の最新 tx を 1 GraphQL で取得
  // Phase 7.1-G.3: opts.companyId が指定されていれば corp::<companyId> tag も検索に含める
  //   (= corp tier の admin が別端末から Recovery で復元する時に必要)
  const tags = deriveAllAppNameTags(recoveryMaterial, opts.companyId || null);
  // Phase 7.4.1: tags.legacy 廃止 — dev 期 envelope は救済しない
  const tagList = [tags.free, tags.paid, tags.private];
  if (tags.corp) tagList.push(tags.corp);  // 各 {name,value}
  // Phase 7.2-B (α): 優先順位を server-first に: multi-device で正しい挙動。
  //   1. server vlatest hint (= 権威、 楽観的ロックと同じ source) — multi-device で最新確実
  //   2. meta.latestTxId (= local hint、 server 不到達 / 旧 vault で vlatest 未記録時の fallback)
  //   3. GraphQL fallback (= 真の legacy 救済)
  let txid = null;
  let matchedAppName = null;
  let envelope = null;
  let serverHintTxid = null;
  for (const t of tagList) {
    if (!t?.value) continue;
    const hint = await fetchServerVaultLatest(t.value);
    if (hint?.txid) {
      serverHintTxid = hint.txid;
      console.log("[unlock-AC] server hint: latest is " + hint.txid + ", fetching with retry...");
      const r = await _fetchServerHintedWithRetry(hint.txid, outerKeyBytes, (n, total) => {
        if (n > 1) console.log(`[unlock-AC] Arweave 伝播待ち... (${n}/${total})`);
      });
      if (r?.envelope) {
        envelope = r.envelope;
        txid = hint.txid;
        matchedAppName = t;
        console.log("[unlock-AC] using server vlatest hint (= " + hint.txid + ")");
      }
      break;
    }
  }
  if (serverHintTxid && !envelope) {
    throw new Error("Server は最新を " + serverHintTxid + " と認識していますが、 Arweave からまだ取得できません (= bundling 中)。 少し待ってから再試行してください。");
  }
  // server hint 無し (= legacy vault) → meta fallback
  if (!envelope) {
    const metaTxId = readMeta()?.latestTxId;
    if (metaTxId) {
      try {
        const r = await fetchEnvelope(metaTxId, _acOuterKey ?? outerKeyBytes);
        if (r?.envelope) {
          txid = metaTxId;
          matchedAppName = readMeta()?.currentAppNameTag || readMeta()?.appNameTag || null;
          envelope = r.envelope;
          console.log("[unlock-AC] no server hint, using meta.latestTxId (= " + metaTxId + ")");
        }
      } catch (e) {
        console.warn("[unlock-AC] meta.latestTxId fetch failed:", e?.message);
      }
    }
  }
  if (!envelope) {
    // GraphQL candidates を順番に試す (phantom tx を回避)
    //   各 candidate を fetch + outer 復号 + Path AC 復号まで試行、 成功した時点で確定
    const found = await findLatestVaultTxAcrossTiers(tagList);
    if (!found?.txid) throw new Error("この Recovery に対応する vault が Arweave 上に見つかりません");
    const candidates = found.candidates || [{ txid: found.txid, appName: found.appName }];
    let lastErr = null;
    for (const cand of candidates) {
      try {
        const r = await fetchEnvelope(cand.txid, _acOuterKey ?? outerKeyBytes);
        if (!r?.envelope) continue;
        // 試しに decrypt して factors が通るか確認
        const test = await decryptVaultAuto(r.envelope, { password, recoveryMaterial });
        if (test) {
          envelope = r.envelope;
          txid = cand.txid;
          matchedAppName = cand.appName;
          console.log("[unlock-AC] selected candidate " + cand.txid + " (height=" + cand.height + ")");
          // decryptVaultAuto は既に走ったので結果を再利用、 後段の decryptVaultAuto 呼出を skip
          var _rAC_cached = test;
          break;
        }
      } catch (e) {
        lastErr = e;
        console.warn("[unlock-AC] candidate " + cand.txid + " 失敗、 次へ:", e?.message);
      }
    }
    if (!envelope) throw lastErr || new Error("どの candidate でも復号できませんでした");
  }
  // candidates iteration で _rAC_cached が set されていれば使用、 さもなくば decryptVaultAuto 再呼出
  const _rAC = (typeof _rAC_cached !== "undefined" && _rAC_cached) ? _rAC_cached : await decryptVaultAuto(envelope, {
    password, recoveryMaterial,
  });
  const { vault, mek, path } = _rAC;
  const _businessK2_AC = _rAC.businessK2;
  writeMeta({
    appNameTag,            // legacy 固定 (後方互換)
    currentAppNameTag: matchedAppName,  // 現実際の latest が居る tag
    latestTxId: txid,
  });
  await openSession({
    vault, mek, mekKey: _rAC?.mekKey,  // Phase 7.3-A.3
    mekHkdfKey: _rAC?.mekHkdfKey ?? null,  // Phase 7.3-A.7b
    outerKeyBytes, appNameTag,
    currentAppNameTag: matchedAppName,
    currentTierQualifier: null,  // refreshTierQualifier() で server から取得
    recoveryMaterial,
    recoverySecret: recoveryString,  // Phase 7.0w-AP: 文字列も session に保持
    credIdHash: null, credentialId: null,
    latestTxId: txid,
    lastEnvelope: envelope,
    businessK2: null,
    k2AesKey: _rAC?.k2AesKey ?? null,
    k2HkdfKey: _rAC?.k2HkdfKey ?? null,
    signingKey: _rAC?.signingKey ?? null,
    empPrivKey: _rAC?.empPrivKey ?? null,
    k1Version: _rAC?.k1Version ?? null,
  });
  return { vault, latestTxId: txid, path };
}

/**
 * Path BC: Passkey + Recovery (Master 忘却時)
 *
 * Phase 7.0w-AH #102 (Deep Recovery Phase A):
 *   - 4 tier 並列検索で最新 envelope を取得
 *   - credIdHash で filter せず envelope.w.c の **全 wrap_kr を総当たり**
 *     (= ローカル meta が古い / picker で別 Passkey が選ばれた / 別 deployment
 *      由来の envelope でも、PRF が一致する wrap が 1 つでもあれば復号成功)
 *   - 失敗時は options.forcePicker=true で picker 強制再表示し別 Passkey で retry
 *
 * @param {string} recoveryString  "RS1-..." 文字列
 * @param {object} [options]
 *   forcePicker: 強制的に Passkey picker を出す (= local hint を無視)
 */
export async function unlockWithPasskeyAndRecovery(recoveryString, options = {}) {
  const recoveryMaterial = deriveRMat(recoveryString);
  const outerKeyBytes = deriveOuterKeyBytes(recoveryMaterial);
  // Stage 2c Stage F: outer key を Rust OuterKey handle に wrap (= 全 fetchEnvelope で再利用)
  let _bcOuterKey = null;
  try { _bcOuterKey = await importOuterKeyAsHandle(outerKeyBytes); } catch (_e) {}
  const appNameTag = deriveAppNameTag(recoveryMaterial);  // bootstrap (tier 未定) {name,value}
  // Phase 6.4.1 + 7.1-G.3: tier qualifier で並列検索 (Path BC でも同じ防御)。
  //   options.companyId 指定があれば corp::<companyId> も検索リストに追加。
  const tags = deriveAllAppNameTags(recoveryMaterial, options.companyId || null);
  // Phase 7.4.1: tags.legacy 廃止 — dev 期 envelope は救済しない
  const tagList = [tags.free, tags.paid, tags.private];
  if (tags.corp) tagList.push(tags.corp);
  // Phase 7.2-B (α): server-first 優先順位
  let txid = null;
  let matchedAppName = null;
  let envelope = null;
  let serverHintTxid = null;
  for (const t of tagList) {
    if (!t?.value) continue;
    const hint = await fetchServerVaultLatest(t.value);
    if (hint?.txid) {
      serverHintTxid = hint.txid;
      console.log("[unlock-BC] server hint: latest is " + hint.txid + ", fetching with retry...");
      const r = await _fetchServerHintedWithRetry(hint.txid, outerKeyBytes, (n, total) => {
        if (n > 1) console.log(`[unlock-BC] Arweave 伝播待ち... (${n}/${total})`);
      });
      if (r?.envelope) {
        envelope = r.envelope;
        txid = hint.txid;
        matchedAppName = t;
        console.log("[unlock-BC] using server vlatest hint (= " + hint.txid + ")");
      }
      break;
    }
  }
  if (serverHintTxid && !envelope) {
    throw new Error("Server は最新を " + serverHintTxid + " と認識していますが、 Arweave からまだ取得できません (= bundling 中)。 少し待ってから再試行してください。");
  }
  if (!envelope) {
    const metaTxId = readMeta()?.latestTxId;
    if (metaTxId) {
      try {
        const r = await fetchEnvelope(metaTxId, _bcOuterKey ?? outerKeyBytes);
        if (r?.envelope) {
          txid = metaTxId;
          matchedAppName = readMeta()?.currentAppNameTag || readMeta()?.appNameTag || null;
          envelope = r.envelope;
          console.log("[unlock-BC] no server hint, using meta.latestTxId (= " + metaTxId + ")");
        }
      } catch (e) {
        console.warn("[unlock-BC] meta.latestTxId fetch failed:", e?.message);
      }
    }
  }
  if (!envelope) {
    // GraphQL candidates を順番に試す。 BC では outer 復号 OK までで確定
    //   (= Path BC の wrap_c 検証は後段の decryptVaultAuto で行う)
    const found = await findLatestVaultTxAcrossTiers(tagList);
    if (!found?.txid) throw new Error("この Recovery に対応する vault が Arweave 上に見つかりません");
    const candidates = found.candidates || [{ txid: found.txid, appName: found.appName }];
    let lastErr = null;
    for (const cand of candidates) {
      try {
        const r = await fetchEnvelope(cand.txid, _bcOuterKey ?? outerKeyBytes);
        if (r?.envelope) {
          envelope = r.envelope;
          txid = cand.txid;
          matchedAppName = cand.appName;
          console.log("[unlock-BC] selected candidate " + cand.txid + " (height=" + cand.height + ")");
          break;
        }
      } catch (e) {
        lastErr = e;
        console.warn("[unlock-BC] candidate " + cand.txid + " fetch 失敗、 次へ:", e?.message);
      }
    }
    if (!envelope) throw lastErr || new Error("どの candidate でも取得できませんでした");
  }
  // Phase 7.2-B (α) debug: 取得した envelope の構造を log
  console.log("[unlock-BC] fetched envelope:", {
    txid,
    metaLatestTxId: readMeta()?.latestTxId,
    sameAsMeta: txid === readMeta()?.latestTxId,
    matchedAppName,
    envelopeMode: envelope?.m,
    wrapBCount: envelope?.w?.b?.length || 0,
    wrapCCount: envelope?.w?.c?.length || 0,
    wrapBHashes: envelope?.w?.b?.map(w=>w.h),
    wrapCHashes: envelope?.w?.c?.map(w=>w.h),
  });
  const credIdHint = (!options.forcePicker && readMeta()?.credentialId)
    ? b64uDecode(readMeta().credentialId)
    : null;
  const { credentialId, prfOutput } = await authenticateWithPasskey(credIdHint, {
    forcePicker: options.forcePicker || false,
  });
  const credIdHash = await credentialIdToHash(credentialId);
  console.log("[unlock-BC] auth result:", {
    credIdHash,
    metaCredIdHash: readMeta()?.credIdHash,
    sameAsMeta: credIdHash === readMeta()?.credIdHash,
    inEnvelopeWrapC: envelope?.w?.c?.some(w => w.h === credIdHash),
  });
  // Phase 7.0w-AH #102 core: credIdHash を decryptVault に **渡さない**。
  //   → decryptVault は envelope.w.c の全 wrap を試行し、PRF が一致する 1 つを
  //     見つけたら復号成功。ローカル credIdHash が壊れていても OK。
  let vault, mek, path;
  try {
    var _rBC = await decryptVaultAuto(envelope, {
      prfOutput, recoveryMaterial,  // credIdHash 意図的に省略 = 全 wrap 総当たり
    });
    ({ vault, mek, path } = _rBC);
    var _businessK2_BC = _rBC.businessK2;
  } catch (e) {
    // Phase 7.2-B (α) debug: 実際の error 原因を console に出す
    //   (= 「deep_recovery_passkey_not_registered」 で renaming される前の生エラー)
    console.error("[unlock-BC] decryptVaultAuto 失敗:", {
      message: e?.message,
      code: e?.code,
      status: e?.status,
      stack: e?.stack?.split("\n").slice(0, 5).join("\n"),
    });
    const retryErr = new Error("deep_recovery_passkey_not_registered");
    retryErr.code = "deep_recovery_passkey_not_registered";
    retryErr.original = e;
    throw retryErr;
  }
  writeMeta({
    appNameTag,
    currentAppNameTag: matchedAppName,
    credIdHash, credentialId: b64uEncode(credentialId),
    latestTxId: txid,
  });
  await openSession({
    vault, mek, mekKey: _rBC?.mekKey,  // Phase 7.3-A.3
    mekHkdfKey: _rBC?.mekHkdfKey ?? null,  // Phase 7.3-A.7b
    outerKeyBytes, appNameTag,
    currentAppNameTag: matchedAppName,
    currentTierQualifier: null,
    recoveryMaterial,
    recoverySecret: recoveryString,  // Phase 7.0w-AP
    credIdHash, credentialId,
    latestTxId: txid,
    lastEnvelope: envelope,
    businessK2: null,
    k2AesKey: _rBC?.k2AesKey ?? null,
    k2HkdfKey: _rBC?.k2HkdfKey ?? null,
    signingKey: _rBC?.signingKey ?? null,
    empPrivKey: _rBC?.empPrivKey ?? null,
    k1Version: _rBC?.k1Version ?? null,
  });
  return { vault, latestTxId: txid, path };
}

// ---------------------------------------------------------------------------
// resolveLatestTxIdForUnlock — server hint → fallback to GraphQL
// 注: unlock 前は signingState がないので、localStorage hint と GraphQL のみ。
// ---------------------------------------------------------------------------

async function resolveLatestTxIdForUnlock(meta) {
  // Phase 7.2-B (α): server vlatest を最優先 (= 楽観的ロックと同じ source、 multi-device 安全)
  //   v2.6 hotfix: currentAppNameTag (= tier 派生) と appNameTag (= legacy null tier)
  //   の **両方** を順に試行する。 旧コードは currentAppNameTag が存在すれば appNameTag を
  //   試さなかったため、 business member の signup は legacy tag で write した のに
  //   refreshTierQualifier が race で "free" tier に上書きした localStorage を使うと
  //   vlatest:<free値> 404 → unlock 不能になっていた。
  // Phase 7.x cross-talk 修正: pkHash 安定キーで slot を直接引くのを最優先にする。
  //   pkHash (= meta.publicKeyHash) は署名鍵 HKDF(MEK / K2) のハッシュで、 tier 非依存・
  //   vault 固有・不変。 ?pk= は account.vaultSlots を直接返し、 タグ照合も
  //   latestVaultTxId フォールバックも通らないので cross-talk しない。
  if (meta?.publicKeyHash) {
    try {
      const slots = await fetchServerVaultSlots(meta.publicKeyHash);
      if (slots) {
        const pick = (slots.priority && slots[slots.priority])
          ? slots[slots.priority]
          : (slots.corp || slots.paid || slots.free || null);
        if (pick?.txid) {
          console.log("[resolveLatest-PK] using pk-slot (= " + pick.txid + ", pk=" + meta.publicKeyHash + ")");
          return pick.txid;
        }
      }
    } catch (e) {
      console.warn("[resolveLatest-PK] pk lookup failed:", e?.message);
    }
  }
  // pkHash hint 無し (= 旧 meta) → legacy: server vlatest を App-Name タグで引く。
  //   ?app= は strict 化済 (slot 不一致なら not_found、 latestVaultTxId フォールバック廃止)。
  const tagValues = [];
  if (meta?.currentAppNameTag?.value) tagValues.push(meta.currentAppNameTag.value);
  if (meta?.appNameTag?.value && meta.appNameTag.value !== meta?.currentAppNameTag?.value) {
    tagValues.push(meta.appNameTag.value);
  }
  for (const tagValue of tagValues) {
    try {
      const hint = await fetchServerVaultLatest(tagValue);
      if (hint?.txid) {
        console.log("[resolveLatest-AB] using server vlatest (= " + hint.txid + ", app=" + tagValue + ")");
        return hint.txid;
      }
    } catch (e) {
      console.warn("[resolveLatest-AB] server vlatest fetch failed for app=" + tagValue + ":", e?.message);
    }
  }
  // server hint 無し → meta fallback (= legacy or offline) → GraphQL
  if (meta?.latestTxId) return meta.latestTxId;
  if (meta?.currentAppNameTag) {
    const t = await findLatestVaultTx(meta.currentAppNameTag);
    if (t) return t;
  }
  if (meta?.appNameTag) return await findLatestVaultTx(meta.appNameTag);
  return null;
}

// ---------------------------------------------------------------------------
// saveVault — 本体だけ差し替え (wrap 群は流用、credit 1 消費)
// ---------------------------------------------------------------------------

export async function saveVault(updatedVault, opts = {}) {
  if (!_session) throw new Error("locked — unlock first");
  if (!_session.lastEnvelope) throw new Error("session に直近 envelope がありません");

  // Phase 7.0w-AH/AP: opportunistic migration — session に Recovery 原文字列があり、
  // vault にまだ encryptedRecovery (v=2 文字列形式) が無ければ inject。
  // v=1 (legacy rMat) が残っていれば v=2 で上書きして再表示可能化。
  // Phase 7.2-B: business mode は encryptedRecovery を持たない (admin が保管)
  const isBusinessMode = _session.lastEnvelope.m === "business";
  const needsInject = !isBusinessMode && _session.recoverySecret &&
    (!updatedVault.encryptedRecovery || updatedVault.encryptedRecovery.v !== 2);
  if (needsInject) {
    updatedVault = {
      ...updatedVault,
      encryptedRecovery: await encryptRecoveryWithMek(_session.recoverySecret, _session.mek),
    };
    // Phase 7.3-A.9 part 1.1: inject 直後に session から文字列を消去。 以後は
    //   vault.encryptedRecovery から復号して取り出す (= decryptRecoveryWithMek 経由)。
    _session.recoverySecret = null;
  }

  // Phase 7.2-B (α) 修正: K1 rotation は admin 意識的 (= rotate-kek 押下時) のみ。
  //   通常 save は MEK / K1 不変、 body のみ再暗号化、 envelope 構造維持 (= ws, w, etc.)。
  //   これにより wrappedBEK / wrappedCEK (= records) の orphan を防ぐ、 全社員が常時アクセス可。
  const ivBody = crypto.getRandomValues(new Uint8Array(12));
  const mekKey = _session.mekKey || await crypto.subtle.importKey("raw", _session.mek, { name: "AES-GCM" }, false, ["encrypt"]);
  const padded = padPlaintext(new TextEncoder().encode(JSON.stringify(updatedVault)));
  const bodyCt = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: ivBody }, mekKey, padded));

  // envelope v7 増分2: hwkey envelope は w (2-of-3 wrap) も s (salt) も持たず、
  //   代わりに k[] (per-YubiKey で wrap した MEK) を持つ。 hwkey と 2-of-3 で
  //   envelope 構築を分岐する。 旧コードは w を無条件 deep-clone していたため、
  //   hwkey では JSON.parse(JSON.stringify(undefined)) が例外を投げ、保存が
  //   毎回失敗していた (= 追加エントリのデータロス)。
  const isHwkeyMode = _session.lastEnvelope.m === "hwkey";
  const newEnvelope = {
    ..._session.lastEnvelope,  // m, cid, kv, ws, k などすべて保持
    v: VAULT_FORMAT_V5,
    i: b64uEncode(ivBody),
    c: b64uEncode(bodyCt),
  };
  if (isHwkeyMode) {
    // hwkey: k[] を deep clone で維持。 s / w フィールドは存在しない。
    newEnvelope.k = JSON.parse(JSON.stringify(_session.lastEnvelope.k));
  } else {
    // 2-of-3: s (salt) と w (内部 wrap 構造) を維持。
    newEnvelope.s = _session.lastEnvelope.s;
    newEnvelope.w = JSON.parse(JSON.stringify(_session.lastEnvelope.w));
  }
  // Phase 6.4.1: tier-aware App-Name を優先 (set されていれば currentAppNameTag、
  // 未 set なら legacy appNameTag に fallback)
  // Phase 7.2-B v2.6 invariant: business mode は currentAppNameTag === appNameTag (= legacy)
  //   でなければならない。 不一致を検出したら強制的に legacy を採用 + warning。
  //   refreshTierQualifier の business-mode null 強制 fix が回帰した時の検出 + 自己治癒。
  //   `isBusinessMode` は同関数の先頭で既に宣言されているので変数名を変える。
  const isBusinessSession = isBusinessMode || _session.vault?.mode === "admin";
  let writeAppName;
  if (isBusinessSession) {
    const cur = _session.currentAppNameTag;
    const leg = _session.appNameTag;
    if (cur && leg && cur.value !== leg.value) {
      console.warn("[saveVault] business mode invariant breach: currentAppNameTag !== appNameTag — forcing legacy tag for write", { cur: cur?.value, leg: leg?.value });
      _session.currentAppNameTag = leg;  // 強制復元 (= 次の unlock で localStorage も legacy になる)
    }
    writeAppName = leg ?? cur;
  } else {
    writeAppName = _session.currentAppNameTag ?? _session.appNameTag;
  }
  const writeResult = await writeEnvelope(
    newEnvelope, (_session.outerKeyHandle ?? _session.outerKey ?? _session.outerKeyBytes), writeAppName, _session.signingState,
    {
      expectedLatestTxId: _session.latestTxId,        // Phase 5.3 楽観ロック
      forceOverwrite: opts.forceOverwrite === true,   // Phase 7.1-N.3: 救済 escape hatch
      tier: _resolveCurrentTier(),                    // Phase 7.2-B v2.6: tier 申告
    }
  );
  _session.vault = updatedVault;
  _session.lastEnvelope = newEnvelope;
  _session.latestTxId = writeResult.txid;
  _recordWrittenTxId(writeResult.txid);  // Phase 7.1-AI
  patchMeta({ latestTxId: writeResult.txid });
  // Phase 7.5e: write 完了で server 側 credit が確実に減ったので、 balance cache を
  //   即無効化。 次の refreshHeader (= 直後に呼ばれる) が fresh fetch して header の
  //   credit 表示を更新する。
  invalidateBalanceCache();
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
export async function addCredentialOnThisDevice(password, userDisplayName, opts = {}) {
  if (!_session) throw new Error("locked — unlock first");
  // Phase 7.3-A.9: recoveryMaterial が session に raw 不在 (= A.9 で撲滅) でも、
  //   以下の優先順位で transient に derive する:
  //   1. _session.recoverySecret (= 文字列、 unlock 直後 / inject 前のみ)
  //   2. vault.encryptedRecovery から復号 (= 永続化済 Recovery 文字列を取り戻す)
  //   3. どちらも無ければ Recovery 再入力を要求
  let rMatTransient = _session.recoveryMaterial;
  let rMatAllocated = false;
  if (!rMatTransient) {
    let recoveryString = null;
    if (typeof _session.recoverySecret === "string" && _session.recoverySecret.length >= 4) {
      recoveryString = _session.recoverySecret;
    } else if (_session.vault?.encryptedRecovery && _session.mek) {
      try {
        recoveryString = await decryptRecoveryWithMek(_session.vault.encryptedRecovery, _session.mekHkdfKey ?? _session.mek);
      } catch (e) {
        console.warn("[addCredential] decryptRecoveryWithMek failed:", e?.message);
      }
    }
    if (typeof recoveryString === "string" && recoveryString.length >= 4) {
      rMatTransient = deriveRMat(recoveryString);
      rMatAllocated = true;
    } else {
      throw new Error("Recovery を要する操作です。Master + Recovery で unlock してください");
    }
  }
  if (!_session.lastEnvelope) {
    if (rMatAllocated) rMatTransient.fill(0);
    throw new Error("session に直近 envelope がありません");
  }
  // envelope v7: 端末追加で作るパスキーも v7 user.id を焼く。これで この端末は
  //   次回以降、localStorage 無しで outer 鍵を user.id から復元できる。outer 鍵は
  //   rMat から導出し、Master でラップして user.id に格納する (encodeUserIdV7)。
  if (!(rMatTransient instanceof Uint8Array))
    throw new Error("addCredential: rMat (bytes) が必要です — Master + Recovery で unlock し直してください");
  const _outerKeyBytesForUserId = deriveOuterKeyBytes(rMatTransient);
  const userId = await encodeUserIdV7(_session.appNameTag, _outerKeyBytesForUserId, password);
  _outerKeyBytesForUserId.fill(0);
  const { credentialId, prfOutput } = await createPasskey(userId, userDisplayName, { requireResidentKey: true });
  const credIdHash = await credentialIdToHash(credentialId);
  // Phase 7.2-B v2 (#99 戻し): Business mode の records BEK/CEK は real_MEK で wrap する。
  //   _session.mek は decryptVaultBusiness で realMek 化済 (= HKDF(K1, K2))。
  //   Personal mode は変わらず _session.mek (= MEK)。
  //   退社後の K1 ゲートを ファイル側にも効かせる目的。
  // Phase 7.3-A.9 part 2: Personal mode で raw mek が null の場合、 factor 経由 derive
  let secretToWrap = _session.mek;
  let secretAllocated = false;
  if (!secretToWrap) {
    secretToWrap = await _deriveTransientMek({ password, recoveryMaterial: rMatTransient, credIdHash: _session.currentCredIdHash });
    secretAllocated = true;
  }
  let newEnvelope;
  try {
    newEnvelope = await addCredential(
      _session.lastEnvelope, secretToWrap, password, rMatTransient, prfOutput, credIdHash
    );
  } finally {
    if (secretAllocated) secretToWrap.fill(0);
    // Phase 7.3-A.9: transient で確保した rMat は即破棄
    if (rMatAllocated) rMatTransient.fill(0);
  }
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

  // session の credential 状態は即時更新 (OS Keychain に登録済なので credIdHash は valid)
  _session.currentCredIdHash = credIdHash;
  _session.currentCredentialId = credentialId;

  // Phase 7.0w-AM.1: opts.deferSave === true なら Arweave への書き込みは行わない。
  // caller が scheduleSave(_session.vault) を呼んで dirty 状態にする (= 編集バッジ
  // 'pending' 表示) ことで、後続の entry 変更とまとめて 1 回の saveVault で flush される。
  // restore-btn など「機種追加で即座に書き込みたい」flow は deferSave 指定なし
  // (= 従来通りの即時 saveVault) を使う。
  if (opts.deferSave) {
    patchMeta({
      credIdHash, credentialId: b64uEncode(credentialId),
      // latestTxId は変更しない (Arweave 書き込み未完了)
    });
    return { txid: null, deferred: true };
  }

  // Phase 7.1-AA: saveVault が 409 を投げたケースに備え、OS Passkey の登録は
  // 既に完了しているので credIdHash / credentialId を先行 patchMeta する。
  // これをやらないと、save が失敗した端末では OS には Passkey が残るのに
  // アプリ側 meta から credentialId が消える「使えない端末」状態に陥る
  // (Yamaki 環境 2026-05-14 で発生)。latestTxId は save 成功後に上書き。
  patchMeta({
    credIdHash, credentialId: b64uEncode(credentialId),
    // latestTxId は触らない (Arweave 書き込み未完了)
  });

  // Phase 7.1-Z: opts.forceOverwrite=true なら saveVault に伝播 (= server 楽観
  // ロックを bypass)。restore 時に admin account の corrupted state を踏んだ場合に
  // UI 経由で確認後リトライする用。
  await saveVault(_session.vault, { forceOverwrite: opts.forceOverwrite === true });
  patchMeta({ latestTxId: _session.latestTxId });
  return { txid: _session.latestTxId };
}

// ---------------------------------------------------------------------------
// changePassword — Master 変更 (Recovery 必須)
// ---------------------------------------------------------------------------

export async function changePasswordUI(newPassword, recoveryString, userDisplayName) {
  if (!_session) throw new Error("locked — unlock first");
  if (!_session.lastEnvelope) throw new Error("session に直近 envelope がありません");
  if (!_session.currentCredIdHash) {
    throw new Error("この端末に Passkey がありません — Recovery + Passkey で改めて unlock してください");
  }
  // 現端末 Passkey で再認証して PRF 取得 (MEK/K2 を BC 経路で transient 復元するため)
  const credIdHint = readMeta()?.credentialId ? b64uDecode(readMeta().credentialId) : null;
  const { prfOutput } = await authenticateWithPasskey(credIdHint);
  const recoveryMaterial = deriveRMat(recoveryString);
  // Phase 7.3-A.9 part 4: secretToWrap は Personal=MEK / Business=K2。
  //   V2 business session は raw K2 を持たないので _extractK2FromBusinessEnvelope で
  //   transient に取り出す (= BC path: passkey + Recovery で envelope.w.c を復号)。
  //   Personal V2 は _deriveTransientMek で。
  let mekForReWrap = _session.businessK2 ?? _session.mek;
  let mekAllocated = false;
  const _envForReWrap = _session.lastEnvelope;
  if (!mekForReWrap) {
    if (_envForReWrap?.m === "business") {
      mekForReWrap = await _extractK2FromBusinessEnvelope(_envForReWrap, {
        prfOutput, recoveryMaterial, credIdHash: _session.currentCredIdHash,
      });
    } else {
      mekForReWrap = await _deriveTransientMek({ prfOutput, recoveryMaterial, credIdHash: _session.currentCredIdHash });
    }
    mekAllocated = true;
  }
  // envelope v7 (Option A — envelope-v7-spec.md §14): outer 鍵は Master でラップ
  //   して user.id に格納される。user.id は credential 作成後 *不変* なので、
  //   Master を変えるには新 Master でラップした user.id を持つ「新しい Passkey」を
  //   作るしかない。changePassword は全 wraps.pk を破棄し新 Passkey 用 1 個だけに
  //   するので、旧 Master はどの端末でも AB 解錠に使えなくなる。旧 Passkey は OS に
  //   残るが wrap が無く解錠不能 — ユーザーが手動削除する。
  const _outerKeyBytes = deriveOuterKeyBytes(recoveryMaterial);
  let newUserId;
  try {
    newUserId = await encodeUserIdV7(_session.appNameTag, _outerKeyBytes, newPassword);
  } finally {
    if (_outerKeyBytes instanceof Uint8Array) _outerKeyBytes.fill(0);
  }
  const _dispName = (typeof userDisplayName === "string" && userDisplayName.trim())
    ? userDisplayName.trim() : "Arpass";

  let updatedEnv, newCredentialId, newPrfOutput, newCredIdHash;
  try {
    // 新 Master でラップした user.id を持つ新 Passkey を作成
    const _created = await createPasskey(newUserId, _dispName, { requireResidentKey: true });
    newCredentialId = _created.credentialId;
    newPrfOutput = _created.prfOutput;
    newCredIdHash = await credentialIdToHash(newCredentialId);
    updatedEnv = await changePassword(
      _session.lastEnvelope, mekForReWrap, newCredIdHash,
      newPassword, newPrfOutput, recoveryMaterial
    );
  } finally {
    if (mekAllocated) mekForReWrap.fill(0);
  }

  // vault.credentials (登録端末リスト = UI 表示用) を新 Passkey に更新する。
  //   解錠の真実は envelope.w なので本体 c の再暗号化はここでは行わず、次回の
  //   saveVault で永続化される (即時反映が要るのは meta / envelope.w のみ)。
  if (Array.isArray(_session.vault?.credentials)) {
    _session.vault.credentials = _session.vault.credentials.filter(
      (c) => (c.credIdHash || c.id) !== _session.currentCredIdHash
    );
    _session.vault.credentials.push({
      credIdHash: newCredIdHash, name: _dispName, addedAt: new Date().toISOString(),
    });
  }

  const writeResult = await writeEnvelope(
    updatedEnv, (_session.outerKeyHandle ?? _session.outerKey ?? _session.outerKeyBytes), _session.appNameTag, _session.signingState,
    { tier: _resolveCurrentTier() }
  );
  _session.lastEnvelope = updatedEnv;
  _session.currentCredIdHash = newCredIdHash;
  _session.currentCredentialId = newCredentialId;
  _session.latestTxId = writeResult.txid;
  _recordWrittenTxId(writeResult.txid);  // Phase 7.1-AI
  patchMeta({
    credentialId: b64uEncode(newCredentialId),
    credIdHash: newCredIdHash,
    latestTxId: writeResult.txid,
  });
  return { ...writeResult, newPasskeyCreated: true };
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
  const { generateRecoverySecret } = await import("/lib/vault-crypto.js?v=11331c7d");
  const newRecovery = generateRecoverySecret();
  const newRMat = deriveRMat(newRecovery);
  const credIdHint = readMeta()?.credentialId ? b64uDecode(readMeta().credentialId) : null;
  const { prfOutput } = await authenticateWithPasskey(credIdHint);
  // Phase 7.3-A.9 part 4: secretToWrap は Personal=MEK / Business=K2。
  //   V2 business session は raw K2 不在 → _extractK2FromBusinessEnvelope (AB path) で transient。
  let mekForReWrap = _session.businessK2 ?? _session.mek;
  let mekAllocated = false;
  const _envForReWrap = _session.lastEnvelope;
  if (!mekForReWrap) {
    if (_envForReWrap?.m === "business") {
      mekForReWrap = await _extractK2FromBusinessEnvelope(_envForReWrap, {
        password, prfOutput, credIdHash: _session.currentCredIdHash,
      });
    } else {
      mekForReWrap = await _deriveTransientMek({ password, prfOutput, credIdHash: _session.currentCredIdHash });
    }
    mekAllocated = true;
  }
  let result;
  try {
    result = await changeRecovery_caseA(
      _session.lastEnvelope, mekForReWrap, password, _session.currentCredIdHash, prfOutput, newRMat
    );
  } finally {
    if (mekAllocated) mekForReWrap.fill(0);
  }
  const writeResult = await writeEnvelope(
    result.envelope, result.newOuterKeyBytes, result.newAppNameTag, _session.signingState,
    { tier: _resolveCurrentTier() }
  );
  _session.outerKeyBytes = result.newOuterKeyBytes;
  _session.appNameTag = result.newAppNameTag;
  _session.recoveryMaterial = newRMat;
  _session.recoverySecret = newRecovery;  // Phase 7.0w-AP
  // Phase 7.3-A.8 part 2c + A.9: changeRecovery 後の CryptoKey 再派生 + raw 破棄
  try {
    _session.rMatHkdfKey = await importRMatAsHkdfKey(newRMat);
    _session.outerKey = await deriveOuterKeyFromHkdf(_session.rMatHkdfKey);
    // raw 破棄 (= CryptoKey 派生成功時のみ)
    if (result.newOuterKeyBytes instanceof Uint8Array) result.newOuterKeyBytes.fill(0);
    _session.outerKeyBytes = null;
  } catch (e) { console.warn("[changeRecovery] CryptoKey re-derive failed:", e?.message); }
  _session.lastEnvelope = result.envelope;
  _session.latestTxId = writeResult.txid;
  _recordWrittenTxId(writeResult.txid);  // Phase 7.1-AI
  writeMeta({
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
  // Phase 7.2-B v2: Business mode (= corp 加入中) は case B (= MEK 一新) 未対応。
  //   理由: business real_MEK = HKDF(K1, K2) で、 K1 は admin が server 経由で管理、
  //   K2 は envelope の w.{a,b,c} に wrap 済。 case B (= 全 wrap 再生成 + 新 MEK で
  //   body 再暗号化) は K1/K2 split の意味論を破壊する (= K1 整合性を保ったまま K2 を
  //   rotate するか、 K1 ごと rotate するか、 設計選択が必要)。
  //   ユーザ救済としては case A (= Recovery のみ更新、 K2 据置) で十分。 元の Recovery が
  //   完全に invalidate されるためセキュリティ的にも問題なし (= AC wrap が再生成され、
  //   旧 Recovery では復号不能になる)。
  //   将来: K1 rotation + K2 rotation の combined 操作として実装予定 (post-launch)。
  if (_session.lastEnvelope?.m === "business" || _session.vault?.mode === "business") {
    const err = new Error("業務モードでは Recovery 全更新 (Case B) は未対応です。 通常の Recovery 再発行 (Case A) をご利用ください。 admin 経由で K1 rotation が必要な場合は K1 配布で個別対応してください。");
    err.code = "business_caseB_unsupported";
    throw err;
  }
  const { generateRecoverySecret } = await import("/lib/vault-crypto.js?v=11331c7d");
  const newRecovery = generateRecoverySecret();
  const newRMat = deriveRMat(newRecovery);
  const credIdHint = readMeta()?.credentialId ? b64uDecode(readMeta().credentialId) : null;
  const { prfOutput } = await authenticateWithPasskey(credIdHint);
  // Phase 7.3-A.9 part 2: transient mek
  let oldMekForRotation = _session.mek;
  let oldMekAllocated = false;
  if (!oldMekForRotation) {
    oldMekForRotation = await _deriveTransientMek({ password, prfOutput, credIdHash: _session.currentCredIdHash });
    oldMekAllocated = true;
  }
  let result;
  try {
    result = await changeRecovery_caseB(
      _session.lastEnvelope, oldMekForRotation, _session.vault, password,
      _session.currentCredIdHash, prfOutput, newRMat
    );
  } finally {
    if (oldMekAllocated) oldMekForRotation.fill(0);
  }
  // 旧 signingState で書き込み (まだ credit 課金は旧アカウントで)
  const writeResult = await writeEnvelope(
    result.envelope, result.newOuterKeyBytes, result.newAppNameTag, _session.signingState,
    { tier: _resolveCurrentTier() }
  );
  // サーバ migration: 旧 KV[H(oldPK)] → 新 KV[H(newPK)] へ残高移送
  await migrateAccount(_session.signingState, result.newSigningKey.publicKeyRaw);
  // 新 identity に切替
  const newSigningState = await buildSigningState(result.newMek);
  _session.mek = result.newMek;
  _session.outerKeyBytes = result.newOuterKeyBytes;
  _session.appNameTag = result.newAppNameTag;
  _session.recoveryMaterial = newRMat;
  // Phase 7.3-A.8 part 2c + A.9: changeRecovery_caseB 後の CryptoKey 再派生 + raw 破棄
  try {
    _session.rMatHkdfKey = await importRMatAsHkdfKey(newRMat);
    _session.outerKey = await deriveOuterKeyFromHkdf(_session.rMatHkdfKey);
    if (result.newMek instanceof Uint8Array) {
      _session.mekHkdfKey = await derivePersonalMekHkdfKey(result.newMek);
    }
    // raw 破棄
    if (result.newOuterKeyBytes instanceof Uint8Array) result.newOuterKeyBytes.fill(0);
    _session.outerKeyBytes = null;
  } catch (e) { console.warn("[changeRecovery_caseB] CryptoKey re-derive failed:", e?.message); }
  _session.recoverySecret = newRecovery;  // Phase 7.0w-AP
  // Phase 7.3-A.8 part 2c: changeRecovery 後の CryptoKey 再派生 (= 既存 session.outerKey が古い rMat 由来のため)
  try {
    _session.rMatHkdfKey = await importRMatAsHkdfKey(newRMat);
    _session.outerKey = await deriveOuterKeyFromHkdf(_session.rMatHkdfKey);
  } catch (e) { console.warn("[changeRecovery] CryptoKey re-derive failed:", e?.message); }
  _session.signingState = newSigningState;
  _session.lastEnvelope = result.envelope;
  _session.latestTxId = writeResult.txid;
  _recordWrittenTxId(writeResult.txid);  // Phase 7.1-AI
  writeMeta({
    appNameTag: result.newAppNameTag,
    credIdHash: _session.currentCredIdHash,
    credentialId: readMeta()?.credentialId,
    publicKeyHash: await hashPublicKey(newSigningState.publicKeyRaw),
    latestTxId: writeResult.txid,
  });
  return { newRecovery, txid: writeResult.txid };
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Phase 7.0e: Records (電子書類) — 単発 record の作成 / 取得 / 削除
// ---------------------------------------------------------------------------
//
// LSM-style schema (vault.records = {active, chunks, corrections, tombstones}) の
// active のみを操作する MVP API。chunk overflow は Phase 7.0i で実装。

/**
 * Phase 7.0e: 新規 record を作成。
 *   1. ファイル本体を BEK で encrypt → Arweave に書込み
 *   2. BEK を MEK で wrap → vault.records.active に push
 *   3. vault を save (server に書込み)
 *
 * @param {Object} input
 * @param {Uint8Array} input.fileBytes  ファイル本体 (raw bytes)
 * @param {string} input.mimeType        e.g. "application/pdf"
 * @param {string} input.type            "receipt" | "invoice" | "contract" | "medical" | "custom"
 * @param {string} input.date            ISO date "2026-05-09" (取引年月日)
 * @param {number} [input.amount]        金額 (任意、contract 等は不要)
 * @param {string} [input.currency]      "USD" | "JPY" | ...
 * @param {string} [input.counterparty]  取引先 (法律必須)
 * @param {string} [input.description]   備考
 * @param {string[]} [input.tags]
 * @returns {Promise<{record, latestTxId, fileTxId}>}
 */
/**
 * Phase 7.2-B v2.4: 指定 version の real_MEK を取得する (= 過去 K1 で wrap された records を読むため)。
 * - version 未指定 or current と一致 → _session.mek (= 現行 real_MEK)
 * - 旧 version → /api/corp/fetch-enc-k1?version=N で取得、 emp_priv で ECIES unwrap、
 *   HKDF(old K1, K2) で old real_MEK 派生、 session cache に保存
 * - server に該当 version が無ければ admin に restore-k1 依頼を促すエラー
 *
 * @param {number|null} k1Version
 * @returns {Promise<Uint8Array>}  real_MEK raw bytes (caller は zeroize しない、 session cache 共有)
 */
async function _getRealMekForVersion(k1Version) {
  // Personal mode: 常に _session.mek (= raw 32B、 A.9 で null になっている可能性あり)
  if (!_session) throw new Error("locked");
  if (currentVaultMode() !== "business") {
    // Phase 7.3-A.9 part 2: Personal の raw mek 撲滅により null 返却の可能性。
    //   callers (wrapKey/unwrapKey) は CryptoKey も受け取れるが、 一部 raw 期待の path で動かない。
    //   ここでは null fallback で warning。
    return _session.mek;
  }
  // current version (or version 未指定 = legacy 互換) → 現行 real_MEK
  const curVer = _session.k1Version ?? 1;
  // Phase 7.3-A.9 part 2: business で raw mek は null。 旧 path 互換のため null 返却。
  //   callers (= migrateAllRecordsToCurrentK1) が CryptoKey path に切替済。
  if (k1Version == null || k1Version === curVer) return _session.mek;
  // 旧 version → cache 参照、 無ければ fetch
  if (!_session._oldRealMekCache) _session._oldRealMekCache = new Map();
  if (_session._oldRealMekCache.has(k1Version)) return _session._oldRealMekCache.get(k1Version);
  // Phase 7.3-A.9 part 4: V1/V2 両対応。 k2HkdfKey があれば V2 path、 無ければ V1 raw K2。
  const _hasK2 = _session.businessK2 || _session.k2HkdfKey;
  if (!_hasK2 || !_session.empPrivKey) {
    throw new Error("business mode の old K1 取得には K2 (raw or CryptoKey) + empPrivKey が必要 (= session 状態不正)");
  }
  let encK1;
  try {
    encK1 = await _fetchEncK1V2(_session.signingState, { version: k1Version });
  } catch (e) {
    if (e.code === "version_not_available" || e.code === "deprecated_not_found") {
      const err = new Error(`過去 K1 v${k1Version} は server から削除済です。 admin に「📜 過去 K1 配布」を依頼してください。`);
      err.code = "old_k1_unavailable";
      err.k1Version = k1Version;
      err.original = e;
      throw err;
    }
    throw e;
  }
  const k1Raw = await eciesUnwrapForRecipient(_session.empPrivKey, encK1);
  const oldK1 = new Uint8Array(k1Raw);
  // Phase 7.3-A.9 part 4: V2 path = K2 HKDF base + K1 salt で raw mek を派生 (raw K2 不要)
  //   V1 path = legacy raw K2 で deriveBusinessMek
  //   注: caller (_getMekKeyForVersion) は raw mek を即 importKey して CryptoKey 化、 raw は破棄。
  let oldRealMek;
  if (_session.k2HkdfKey) {
    const mekBits = await crypto.subtle.deriveBits(
      {
        name: "HKDF", hash: "SHA-256",
        salt: oldK1,
        info: new TextEncoder().encode("mek-business-v2"),
      },
      _session.k2HkdfKey, 256
    );
    oldRealMek = new Uint8Array(mekBits);
  } else {
    oldRealMek = deriveBusinessMek(oldK1, _session.businessK2);
  }
  oldK1.fill(0);
  _session._oldRealMekCache.set(k1Version, oldRealMek);
  return oldRealMek;
}

/**
 * Phase 7.3-A.7c: _getRealMekForVersion を CryptoKey 返却に wrap した変種。
 *   records BEK wrap/unwrap は wrapKey/unwrapKey が CryptoKey path で raw 不要に。
 *   current version は _session.mekKey (= 非 extractable) を即 return。
 *   old version は raw を一度 import して cache (= cache も CryptoKey に置き換え)。
 *
 * @param {number|null} k1Version
 * @returns {Promise<CryptoKey>}  mekKey (AES-GCM, 非 extractable)
 */
async function _getMekKeyForVersion(k1Version) {
  if (!_session) throw new Error("locked");
  // Personal mode は session.mekKey があれば使う、 無ければ raw mek を import
  if (currentVaultMode() !== "business") {
    if (_session.mekKey) return _session.mekKey;
    if (!_session.mek) throw new Error("personal session に mek も mekKey も無い");
    return await crypto.subtle.importKey(
      "raw", _session.mek, { name: "AES-GCM" }, false,
      ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
    );
  }
  // Business mode
  const curVer = _session.k1Version ?? 1;
  if (k1Version == null || k1Version === curVer) {
    if (_session.mekKey) return _session.mekKey;
    // 異常 fallback (= mekKey が無い session)
    throw new Error("business session に mekKey が無い (= session 状態不正)");
  }
  // 旧 version: 既に CryptoKey cache があればそれを使う
  if (!_session._oldMekKeyCache) _session._oldMekKeyCache = new Map();
  if (_session._oldMekKeyCache.has(k1Version)) return _session._oldMekKeyCache.get(k1Version);
  // raw を取得 (legacy cache 共有) → 1 度だけ CryptoKey 化
  const oldRealMek = await _getRealMekForVersion(k1Version);
  const oldMekKey = await crypto.subtle.importKey(
    "raw", oldRealMek, { name: "AES-GCM" }, false,
    ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
  );
  _session._oldMekKeyCache.set(k1Version, oldMekKey);
  return oldMekKey;
}

export async function addRecordUI(input) {
  if (!_session) throw new Error("locked");
  if (!input?.fileBytes || !input?.date || !input?.type) {
    throw new Error("addRecord: fileBytes / date / type required");
  }

  const { fileBytes, mimeType, type, date, amount, currency, counterparty, title, description, tags, filename } = input;
  // Phase 7.0r-8: counterparty OR title のどちらかが必須
  const hasCounterparty = typeof counterparty === "string" && counterparty.trim().length > 0;
  const hasTitle        = typeof title === "string" && title.trim().length > 0;
  if (!hasCounterparty && !hasTitle) {
    throw new Error("addRecord: counterparty or title is required (one of them)");
  }
  // Phase 7.3-A.9 fix: _session.mek は raw 撲滅で null。 _getMekKeyForVersion(null)
  //   で現行 mekKey (= non-extractable CryptoKey) を取得し BEK を wrap する。
  //   読込側 (fetchRecordFileUI) は既に _getMekKeyForVersion 経由なので write/read 統一。
  const mek = await _getMekKeyForVersion(null);

  // 1) ファイル hash (改ざん検知用)
  const sha256 = new Uint8Array(await crypto.subtle.digest("SHA-256", fileBytes));

  // 2) BEK 生成 + ファイル encrypt
  // 重要: records ファイルには padding を適用しない (vault envelope と異なる)。
  //   - vault envelope は padPlaintext で 80/160/240 KiB バケットに padding するが
  //     records ファイルは生サイズ + AES-GCM tag (16 byte) のみで Arweave に保存。
  //   - base64 encoding は HTTP transport 専用 (server 側で b64uDecode してから
  //     raw bytes を Arweave に書く、cost 計算は raw size baseline)。
  //   → 50 KB の領収書は Arweave 上 50 KB + 16 byte = ~50 KB で課金される。
  // Stage 2c Stage G4 v2 (2026-06-06): Rust handle 経路を優先 (= raw bytes JS 露出ゼロ)。
  //   _session.mekHandle が利用可能 + Personal mode なら Rust path 使用。
  //   業務 mode or rust-crypto 未ロード時は既存 CryptoKey path に fallback。
  let ciphertext, dataIv, wrappedBEK, wrapIv;
  if (_session.mekHandle && currentVaultMode() !== "business") {
    let bekHandle = null;
    try {
      bekHandle = await generateBekHandleViaRust();
      if (!bekHandle) throw new Error("Rust BekKey.generate() unavailable");
      dataIv = crypto.getRandomValues(new Uint8Array(12));
      ciphertext = await encryptWithBekHandle(bekHandle, dataIv, fileBytes);
      const w = await wrapBekWithMekHandle(_session.mekHandle, bekHandle);
      wrappedBEK = w.wrapped;
      wrapIv = w.iv;
    } finally {
      if (bekHandle && typeof bekHandle.free === "function") {
        try { bekHandle.free(); } catch (_) {}
      }
    }
  } else {
    // 既存 path (= Phase 7.3-A.5、 業務 mode + 個人 mode で rust-crypto 未ロード時)
    const bek = await generateBlobKey({ forWrapping: true });
    const r = await encryptBlob(bek, fileBytes);
    ciphertext = r.ciphertext;
    dataIv = r.iv;
    const w = await wrapKey(mek, bek);
    wrappedBEK = w.wrapped;
    wrapIv = w.iv;
  }

  // 4) Arweave に encrypted file を write (signed fetch + tag)
  const writeRes = await writeRecordFile(ciphertext, _session.signingState);

  // Phase 7.0e refine v9: Turbo 配信が始まる (0-2 分後) までの bridge として
  // ciphertext を localStorage に cache。fetchRecordFileUI が gateway より先にこの
  // cache を見るので、書込み直後でも preview 可能。10 分経過 or gateway 成功時に evict。
  await setRecordFileCache(writeRes.txid, ciphertext).catch(() => {});

  // Phase 7.1-Y: 旧 Phase 7.0e hotfix を削除。record file の txid を
  // _session.latestTxId に書くと、続く saveVault が record file の txid を
  // expectedLatestTxId として送ってしまい、server 側 (account.latestVaultTxId
  // との比較、Phase 7.1-M) で 409 になる。
  // → record file write では session の vault-only latestTxId を変更しない。

  // 5) record メタを構築
  const id = b64uEncode(crypto.getRandomValues(new Uint8Array(16)));
  const record = {
    id,
    type,
    date,                           // ISO 取引年月日
    amount: typeof amount === "number" ? amount : null,
    currency: currency ?? "USD",
    counterparty: counterparty ?? "",
    counterpartyAlias: normalizeCounterparty(counterparty ?? ""),
    title: title ?? "",
    titleAlias: normalizeCounterparty(title ?? ""),
    description: description ?? "",
    tags: Array.isArray(tags) ? tags.slice(0, 32) : [],
    attachments: [{
      txId: writeRes.txid,
      filename: filename ?? null,
      mimeType: mimeType ?? "application/octet-stream",
      size: fileBytes.length,                                 // 平文サイズ (display 用)
      onChainBytes: writeRes.size_bytes ?? ciphertext.length, // Arweave に書かれた byte 数 (cost 計算 baseline)
      // Phase 7.0e refine: server が返す実消費 USD micro (balance から実際に減算された額)。
      // 一覧 card で「この record の消費額」として表示する。一度書いたら不変 (write 時点の price で fix)。
      consumedUsdMicro: writeRes.consumedUsdMicro ?? null,
      sha256: b64uEncode(sha256),
      encryption: {
        algorithm: "AES-GCM-256",
        wrappedBEK: b64uEncode(wrappedBEK),
        wrapIv: b64uEncode(wrapIv),
        dataIv: b64uEncode(dataIv),
        // Phase 7.2-B v2.4: business mode は K1 version を記録 → rotation 後の transparent fetch 用
        ...(currentVaultMode() === "business" && _session?.k1Version != null ? { k1Version: _session.k1Version } : {}),
      },
    }],
    createdAt: new Date().toISOString(),
    version: 1,
  };

  // 6) vault に追加 (memory のみ、実 saveVault は呼出側が scheduleSave で debounce)
  // Phase 7.0e refine v11: passwords と同じ debounce flow に統一。
  //   旧: ここで await saveVault → 連続 record 追加で vault N 回書込み (cost 高)
  //   新: 呼出側 (app-main.js) が scheduleSave(vault) を呼ぶ → 5 分間に 1 回 batch save
  // 離脱時の安全保証は save-debounce の beforeunload/pagehide/visibilitychange/lock
  // 自動 flush で best-effort 担保。詳細は save-debounce.js のドキュメント参照。
  _session.vault.records.active.push(record);
  _session.vault.recordHistory.push({
    id,
    action: "create",
    at: record.createdAt,
    version: 1,
  });

  // 注意: latestTxId は file txid のまま (vault は未 save)。次回 vault save 後に vault txid に更新される。
  return { record, fileTxId: writeRes.txid, consumedUsdMicro: writeRes.consumedUsdMicro };
}

/**
 * Phase 7.0e: 指定 record の添付ファイルを取得 (Arweave fetch + BEK 復号)。
 * @param {string} recordId
 * @param {number} [attachmentIdx=0]
 * @returns {Promise<{bytes: Uint8Array, mimeType: string}>}
 */
export async function fetchRecordFileUI(recordId, attachmentIdx = 0) {
  if (!_session) throw new Error("locked");
  const records = getCurrentRecords(_session.vault);
  const record = records.find(r => r.id === recordId);
  if (!record) throw new Error(`record not found: ${recordId}`);
  const att = record.attachments?.[attachmentIdx];
  if (!att) throw new Error(`attachment ${attachmentIdx} not found`);

  // Phase 7.0e refine v9: 書込み直後の Turbo 配信前 (0-2 分) は localStorage cache から取得。
  // Vault envelope と同じく、Turbo bundling 完了までの bridge として ciphertext を保持。
  let ciphertext = await getRecordFileCache(att.txId);
  let fromCache = !!ciphertext;
  if (!ciphertext) {
    // 1) Cache miss → gateway fetch (Turbo 配信開始済 = 通常経路)
    ciphertext = await fetchRecordFileBytes(att.txId);
    // gateway 取得成功 → cache はもう不要、evict (localStorage quota 確保)
    deleteRecordFileCache(att.txId).catch(() => {});
  }

  // 2) BEK を MEK で unwrap + 3) BEK で decrypt
  const wrappedBEK = b64uDecode(att.encryption.wrappedBEK);
  const wrapIv = b64uDecode(att.encryption.wrapIv);  // v2.5 hotfix 5: 復元漏れ
  const dataIv = b64uDecode(att.encryption.dataIv);

  let bytes;
  // Stage 2c Stage G5 (2026-06-06): Rust handle 経路を優先 (= raw bytes JS 露出ゼロ)。
  //   Personal mode + _session.mekHandle 利用可能なら handle path、 業務 mode or
  //   rust-crypto 未ロード時は既存 CryptoKey path に fallback。
  const _useRustG5 = _session?.mekHandle &&
                     currentVaultMode() !== "business" &&
                     att.encryption.k1Version == null;  // 業務 mode 由来の record は skip
  if (_useRustG5) {
    let bekHandle = null;
    try {
      bekHandle = await unwrapBekWithMekHandle(_session.mekHandle, wrappedBEK, wrapIv);
      bytes = await decryptWithBekHandle(bekHandle, dataIv, ciphertext);
    } finally {
      if (bekHandle && typeof bekHandle.free === "function") {
        try { bekHandle.free(); } catch (_) {}
      }
    }
  } else {
    // 既存 path (= 業務 mode、 旧 record (= k1Version あり)、 rust-crypto 未ロード)
    const blobWrapKey = await _getMekKeyForVersion(att.encryption.k1Version);
    const bek = await unwrapKey(blobWrapKey, wrappedBEK, wrapIv);
    bytes = await decryptBlob(bek, ciphertext, dataIv);
  }

  // 4) 改ざん検知 (sha256 突合)
  const sha256 = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  if (b64uEncode(sha256) !== att.sha256) {
    throw new Error("record file integrity check failed (sha256 mismatch)");
  }

  return { bytes, mimeType: att.mimeType };
}

// ---------------------------------------------------------------------------
// Phase 7.0g: Records 訂正 / 削除 / 履歴 (電子帳簿保存法 真実性確保要件)
// ---------------------------------------------------------------------------
//
// 電子帳簿保存法 (法 4 条 / 規 4 条) は「訂正/削除の事実+内容を確認できること」を
// 要求する。Arpass は append-only schema でこれを満たす:
//   - active[]:      原本 (immutable、最初に書込まれたもの)
//   - corrections[]: 訂正版メタ (id ごとに version を bump、version 最大が現行値)
//   - tombstones[]:  削除済 id list (UI からは非表示、recordHistory に痕跡保持)
//   - recordHistory[]: 全アクションの audit log (create/correct/delete + reason + at)
//
// 物理削除は不可。tombstone を打っても recordHistory + active[] は永久保存される。
// ファイル本体 (Arweave) もそのまま (Arweave は immutable、削除という概念がない)。

/**
 * Phase 7.0g: 既存 record の metadata を訂正。
 * 訂正版を corrections[] に append し、recordHistory に "correct" entry を残す。
 * ファイル本体 (Arweave attachment) は変更しない。再アップロードしたい場合は
 * 削除 + 新規作成が正しい運用。
 *
 * @param {string} recordId
 * @param {Object} updates  訂正したい fields のみ含む partial object
 *   - date?, amount?, currency?, counterparty?, description?, tags?, type?
 * @param {string} reason   訂正理由 (法律上の audit 痕跡として recordHistory に保存)
 * @returns {Promise<{record}>}
 */
export async function correctRecordUI(recordId, updates, reason) {
  if (!_session) throw new Error("locked");
  if (!recordId) throw new Error("correctRecord: recordId required");
  if (!reason || typeof reason !== "string" || reason.trim().length < 1) {
    throw new Error("correctRecord: reason required (electronic bookkeeping law)");
  }

  const vault = _session.vault;
  if (!vault?.records) throw new Error("vault has no records container");

  // 現行 record を取得 (corrections 適用後) — 訂正の baseline は「最新の現行値」
  const current = getCurrentRecords(vault).find(r => r.id === recordId);
  if (!current) throw new Error(`record not found or already deleted: ${recordId}`);

  // 訂正可能な field のみ accept (id / attachments / createdAt は immutable)
  const correctable = ["date", "amount", "currency", "counterparty", "title", "description", "tags", "type"];
  const cleaned = {};
  for (const k of correctable) {
    if (k in (updates ?? {})) cleaned[k] = updates[k];
  }
  if (Object.keys(cleaned).length === 0) {
    throw new Error("correctRecord: no correctable fields in updates");
  }

  // counterparty / title 訂正時は alias も再計算
  if ("counterparty" in cleaned) {
    cleaned.counterpartyAlias = normalizeCounterparty(cleaned.counterparty ?? "");
  }
  if ("title" in cleaned) {
    cleaned.titleAlias = normalizeCounterparty(cleaned.title ?? "");
  }
  // 訂正後も counterparty OR title のどちらかが必須
  const newCp    = ("counterparty" in cleaned) ? cleaned.counterparty : current.counterparty;
  const newTitle = ("title"        in cleaned) ? cleaned.title        : current.title;
  const hasCp    = typeof newCp === "string" && newCp.trim().length > 0;
  const hasTitle = typeof newTitle === "string" && newTitle.trim().length > 0;
  if (!hasCp && !hasTitle) {
    throw new Error("correctRecord: counterparty or title is required (one of them)");
  }

  // version 計算 (現行 + 1)
  const newVersion = (current.version ?? 1) + 1;

  // corrections[] に append (id を保持、active[] の元 record は不変)
  const correction = {
    id: recordId,
    version: newVersion,
    ...cleaned,
    correctedAt: new Date().toISOString(),
  };
  vault.records.corrections.push(correction);

  // audit log
  vault.recordHistory.push({
    id: recordId,
    action: "correct",
    at: correction.correctedAt,
    version: newVersion,
    fields: Object.keys(cleaned),
    reason: reason.trim().slice(0, 500),
  });

  // 呼出側 (app-main.js) が scheduleSave で debounce save する。
  return { record: { ...current, ...cleaned, version: newVersion } };
}

/**
 * Phase 7.0g: 既存 record を削除 (論理削除)。
 * tombstones[] に id を追加 + recordHistory に "delete" entry。
 * 元の active[] entry とファイル本体 (Arweave) は永久保存される。
 *
 * @param {string} recordId
 * @param {string} reason  削除理由 (法律上の audit 痕跡)
 * @returns {Promise<{recordId}>}
 */
export async function deleteRecordUI(recordId, reason) {
  if (!_session) throw new Error("locked");
  if (!recordId) throw new Error("deleteRecord: recordId required");
  if (!reason || typeof reason !== "string" || reason.trim().length < 1) {
    throw new Error("deleteRecord: reason required (electronic bookkeeping law)");
  }

  const vault = _session.vault;
  if (!vault?.records) throw new Error("vault has no records container");

  // すでに削除済か？
  const tombSet = new Set(vault.records.tombstones.map(t => t.id));
  if (tombSet.has(recordId)) {
    throw new Error(`record already deleted: ${recordId}`);
  }

  // record 存在確認 (corrections 適用後)
  const current = getCurrentRecords(vault).find(r => r.id === recordId);
  if (!current) throw new Error(`record not found: ${recordId}`);

  const at = new Date().toISOString();
  vault.records.tombstones.push({
    id: recordId,
    deletedAt: at,
    reason: reason.trim().slice(0, 500),
  });

  vault.recordHistory.push({
    id: recordId,
    action: "delete",
    at,
    reason: reason.trim().slice(0, 500),
  });

  // 呼出側が scheduleSave で debounce save。
  return { recordId };
}

/**
 * Phase 7.0g: 指定 record の履歴を取得。
 * recordHistory + corrections + tombstones を統合して時系列順に返す。
 *
 * @param {string} recordId
 * @returns {Array<{action, at, version?, fields?, reason?}>}
 */
export function getRecordHistory(recordId) {
  if (!_session) throw new Error("locked");
  const vault = _session.vault;
  if (!vault?.recordHistory) return [];
  const entries = vault.recordHistory
    .filter(h => h.id === recordId)
    .sort((a, b) => (a.at ?? "").localeCompare(b.at ?? ""));
  return entries;
}

/**
 * Phase 7.0g: 削除済 record の一覧を取得 (audit / 復元用、UI には通常非表示)。
 * @returns {Array<{id, deletedAt, reason, originalRecord}>}
 */
export function getDeletedRecords() {
  if (!_session) throw new Error("locked");
  const vault = _session.vault;
  if (!vault?.records) return [];
  const tombs = vault.records.tombstones ?? [];
  const correctionMap = new Map();
  for (const c of (vault.records.corrections ?? [])) {
    const cur = correctionMap.get(c.id);
    if (!cur || (c.version ?? 1) > (cur.version ?? 1)) correctionMap.set(c.id, c);
  }
  return tombs.map(t => {
    const orig = (vault.records.active ?? []).find(r => r.id === t.id);
    const correction = correctionMap.get(t.id);
    return {
      id: t.id,
      deletedAt: t.deletedAt,
      reason: t.reason,
      originalRecord: orig ? (correction ? { ...orig, ...correction } : orig) : null,
    };
  });
}

// ---------------------------------------------------------------------------
// Phase 7.0i: Records chunks overflow (LSM-tree 風 archival)
// ---------------------------------------------------------------------------
//
// 設計意図:
//   active[] が大きくなりすぎると vault envelope size が増え、毎回の
//   saveVault コストが線形に上がる (256KB→256KB×N records)。
//   active[] が threshold を超えたら古い records を chunk に flush し、
//   chunk は別 Arweave file として encrypted upload。vault 本体は chunk
//   reference (txId + range hint + wrapped CEK) のみ保持する。
//
// 検索 (Phase 7.0f filter): デフォルトは active のみ scan = 高速。
//   chunks の range hint (dateFrom/dateTo) を使い、必要時のみ loadChunkUI で
//   lazy fetch + decrypt。記録が少ない user は chunk 走査ゼロで完結。
//
// セキュリティ:
//   chunk ciphertext は CEK (Chunk Encryption Key) で暗号化。
//   CEK は MEK で wrap → vault.records.chunks[].encryption に保存。
//   MEK が消えれば chunk も decrypt 不能。Recovery Case A/B でも
//   MEK 復元できれば chunk 復号も追従。

const DEFAULT_CHUNK_THRESHOLD = 500;  // active が 500 件超えたら sealing 推奨
const DEFAULT_CHUNK_KEEP      = 100;  // 直近 100 件は active に残す (UI 即応性)

/**
 * Phase 7.0i: active[] が threshold を超えていれば古い分を chunk に sealing。
 *   1) active を date desc sort
 *   2) 直近 keepRecent 件を active に残す
 *   3) 残りを CEK で encrypt → Arweave に書込み (records と同じ /api/write)
 *   4) chunk reference を vault.records.chunks に append、active は recent のみに
 *   5) recordHistory に "chunk_sealed" entry
 *
 * @param {Object} [opts]
 * @param {number} [opts.threshold=500]   sealing 開始 threshold
 * @param {number} [opts.keepRecent=100]  active に残す直近件数
 * @returns {Promise<{chunkRef|null, sealed: number}>}
 */
export async function sealOldestChunkUI({ threshold = DEFAULT_CHUNK_THRESHOLD, keepRecent = DEFAULT_CHUNK_KEEP } = {}) {
  if (!_session) throw new Error("locked");
  const vault = _session.vault;
  if (!vault?.records) throw new Error("no records container");

  const active = vault.records.active ?? [];
  if (active.length <= threshold) {
    return { chunkRef: null, sealed: 0 };
  }

  // date desc sort (新しい順) — keepRecent 件を残し、残りを sealing 対象に
  const sorted = [...active].sort((a, b) => (b.date ?? "").localeCompare(a.date ?? ""));
  const recent = sorted.slice(0, keepRecent);
  const toSeal = sorted.slice(keepRecent);
  if (toSeal.length === 0) return { chunkRef: null, sealed: 0 };

  // 1) Chunk plaintext: items + sealedAt
  const chunkPlaintext = JSON.stringify({
    items: toSeal,
    sealedAt: new Date().toISOString(),
    schemaVersion: 3,
  });
  const chunkBytes = new TextEncoder().encode(chunkPlaintext);

  // 2)+3) CEK 生成 → encrypt + wrap (Stage 2c Stage G6: Rust handle 経路を優先)
  //   Personal mode + _session.mekHandle 利用可能なら Rust path、 業務 mode は既存 path。
  let ciphertext, dataIv, wrappedCEK, wrapIv;
  if (_session.mekHandle && currentVaultMode() !== "business") {
    let cekHandle = null;
    try {
      cekHandle = await generateBekHandleViaRust();  // CEK は BEK と同じ AES-256 鍵
      if (!cekHandle) throw new Error("Rust BekKey.generate() unavailable");
      dataIv = crypto.getRandomValues(new Uint8Array(12));
      ciphertext = await encryptWithBekHandle(cekHandle, dataIv, chunkBytes);
      const w = await wrapBekWithMekHandle(_session.mekHandle, cekHandle);
      wrappedCEK = w.wrapped;
      wrapIv = w.iv;
    } finally {
      if (cekHandle && typeof cekHandle.free === "function") {
        try { cekHandle.free(); } catch (_) {}
      }
    }
  } else {
    // Phase 7.3-A.5 path (= 業務 mode + Personal mode で rust-crypto 未ロード時)
    const cek = await generateBlobKey({ forWrapping: true });
    const r = await encryptBlob(cek, chunkBytes);
    ciphertext = r.ciphertext;
    dataIv = r.iv;
    const blobWrapKey2 = _session.mek;  // Phase 7.2-B v2 #99
    const w = await wrapKey(blobWrapKey2, cek);
    wrappedCEK = w.wrapped;
    wrapIv = w.iv;
  }

  // 4) Arweave に書込み (records ファイルと同じ経路)
  const writeRes = await writeRecordFile(ciphertext, _session.signingState);

  // Phase 7.1-Y: chunk file 書込みでも session の vault-only latestTxId を
  // 変更しない (= record file と同じ理由、Phase 7.1-M 以降は不要)。

  // 5) Range hint (filter で chunk を skip 判定するための meta)
  const dates = toSeal.map(r => r.date).filter(Boolean).sort();
  const chunkRef = {
    id: b64uEncode(crypto.getRandomValues(new Uint8Array(16))),
    txId: writeRes.txid,
    sealedAt: new Date().toISOString(),
    count: toSeal.length,
    range: {
      dateFrom: dates[0] ?? null,
      dateTo:   dates[dates.length - 1] ?? null,
    },
    onChainBytes: writeRes.size_bytes ?? ciphertext.length,
    consumedUsdMicro: writeRes.consumedUsdMicro ?? null,
    encryption: {
      algorithm: "AES-GCM-256",
      wrappedCEK: b64uEncode(wrappedCEK),
      // Phase 7.2-B v2.4: business mode は K1 version 記録
      ...(currentVaultMode() === "business" && _session?.k1Version != null ? { k1Version: _session.k1Version } : {}),
      wrapIv: b64uEncode(wrapIv),
      dataIv: b64uEncode(dataIv),
    },
  };

  // 6) vault state 更新 (memory のみ、saveVault は呼出側 scheduleSave)
  vault.records.chunks.push(chunkRef);
  vault.records.active = recent;
  vault.recordHistory.push({
    id: chunkRef.id,
    action: "chunk_sealed",
    at: chunkRef.sealedAt,
    count: toSeal.length,
    range: chunkRef.range,
  });

  return { chunkRef, sealed: toSeal.length };
}

/**
 * Phase 7.0i: 既存 chunk を Arweave から fetch + decrypt。
 * 検索や履歴閲覧時の lazy load 用。
 *
 * @param {string} chunkId
 * @returns {Promise<{items: Array, sealedAt: string}>}
 */
export async function loadChunkUI(chunkId) {
  if (!_session) throw new Error("locked");
  const vault = _session.vault;
  const chunk = (vault?.records?.chunks ?? []).find(c => c.id === chunkId);
  if (!chunk) throw new Error(`chunk not found: ${chunkId}`);

  // 1) ciphertext fetch (Records ファイルと同じ経路、cache-friendly)
  let ciphertext = null;
  try {
    ciphertext = await getRecordFileCache(chunk.txId);
  } catch { /* fallthrough */ }
  if (!ciphertext) {
    ciphertext = await fetchRecordFileBytes(chunk.txId);
    setRecordFileCache(chunk.txId, ciphertext).catch(() => {});
  }

  // 2)+3) CEK unwrap + decrypt (Stage 2c Stage G6: Rust handle 経路を優先)
  const wrappedCEK = b64uDecode(chunk.encryption.wrappedCEK);
  const wrapIv = b64uDecode(chunk.encryption.wrapIv);  // v2.5 hotfix 5: 復元漏れ
  const dataIv = b64uDecode(chunk.encryption.dataIv);

  let bytes;
  if (_session.mekHandle &&
      currentVaultMode() !== "business" &&
      chunk.encryption.k1Version == null) {
    let cekHandle = null;
    try {
      cekHandle = await unwrapBekWithMekHandle(_session.mekHandle, wrappedCEK, wrapIv);
      bytes = await decryptWithBekHandle(cekHandle, dataIv, ciphertext);
    } finally {
      if (cekHandle && typeof cekHandle.free === "function") {
        try { cekHandle.free(); } catch (_) {}
      }
    }
  } else {
    // 既存 path (= 業務 mode、 旧 chunk (= k1Version あり)、 rust-crypto 未ロード)
    const blobUnwrapKey = await _getMekKeyForVersion(chunk.encryption.k1Version);
    const cek = await unwrapKey(blobUnwrapKey, wrappedCEK, wrapIv);
    bytes = await decryptBlob(cek, ciphertext, dataIv);
  }

  // 4) JSON parse
  const json = JSON.parse(new TextDecoder().decode(bytes));
  if (!Array.isArray(json?.items)) {
    throw new Error("chunk JSON malformed (no items[])");
  }
  return json;
}

/**
 * Phase 7.0i: chunks の range hint で filter 適用前に skip 判定。
 * date range が overlap しない chunk は load 不要。
 *
 * @param {Object} chunkRef
 * @param {Object} [filter] {dateFrom, dateTo}
 * @returns {boolean} true なら chunk を load する必要あり
 */
export function chunkRangeOverlaps(chunkRef, filter) {
  if (!chunkRef?.range) return true;  // range 不明 → 安全側で load
  const { dateFrom, dateTo } = chunkRef.range;
  if (!filter) return true;
  if (filter.dateFrom && dateTo && dateTo < filter.dateFrom) return false;
  if (filter.dateTo   && dateFrom && dateFrom > filter.dateTo) return false;
  return true;
}

/** Phase 7.0e: counterparty 検索用 normalize (NFKC + ひらがな→カタカナ + 大文字→小文字)。 */
export function normalizeCounterparty(s) {
  if (!s) return "";
  return s.normalize("NFKC")
    .toLowerCase()
    .replace(/[\u3041-\u3096]/g, m => String.fromCharCode(m.charCodeAt(0) + 0x60));
}

// ---------------------------------------------------------------------------
// 内部ヘルパー
// ---------------------------------------------------------------------------

function emptyVault(mode = "personal", companyId = null) {
  // Phase 7.0: vault schema v3 — LSM-style 構造で records を保持。
  // Phase 7.1: mode field 追加 (personal | business | admin) — Business mode の場合は
  //   companyId / employees / policy / additionalAdmins を含む。
  //
  // entries:    パスワードエントリ (既存)
  // credentials: 端末メタデータ
  // records:    LSM-style 構造
  //   active:      直近 records (毎回 main vault に commit される、検索 fast-path)
  //   chunks:      過去の sub-vault refs (immutable、一度書いたら変えない)
  //   corrections: 過去 chunk 内 records への訂正 (id ごとの最新版、append-only)
  //   tombstones:  削除された record の id list (append-only)
  // recordHistory: 訂正/削除の audit log (法律要件: 真実性確保、append-only)
  const v = {
    mode,                                  // "personal" | "business" | "admin"
    entries: [],
    credentials: [],
    records: emptyRecordsContainer(),
    recordHistory: [],
    createdAt: new Date().toISOString(),
    schemaVersion: 3,
  };
  if (mode === "business" || mode === "admin") {
    v.companyId = companyId;
  }
  if (mode === "admin") {
    v.employees = [];                      // [{ userId, displayName, email?, publicKeyHash, encryptedRecovery, addedAt, status, ... }]
    v.policy = {                           // company-wide policy
      requireAttestation: "none",          // "none" | "platform" | "hardware"
      passwordMinLength: 12,
      deviceAddRequiresApproval: true,
      passwordChangeRequiresApproval: true,
      auditLogToArweave: false,
    };
    v.additionalAdmins = [];               // future: [{ userId, displayName, publicKeyHash, addedAt }]
  }
  return v;
}

/** Phase 7.0c: records 容器の空状態を生成。LSM-style {active, chunks, corrections, tombstones}。 */
function emptyRecordsContainer() {
  return {
    active: [],
    chunks: [],
    corrections: [],
    tombstones: [],
  };
}

/**
 * Phase 7.0c: vault の schema を最新 (v3) に on-read migrate。
 * v1 (passwords only) → v2 (records: []) → v3 (records: {active, chunks, ...}) を一括補完。
 * 既存 entries / credentials には無干渉、純粋に missing field 埋めだけ。
 */
export function migrateVaultSchema(vault) {
  if (!vault) return vault;

  // Phase 7.1: mode field 補完 (legacy vault は personal mode 扱い)
  if (typeof vault.mode !== "string") vault.mode = "personal";

  // v1 → v2: records / recordHistory フィールド補完
  if (vault.records === undefined) vault.records = emptyRecordsContainer();
  if (!Array.isArray(vault.recordHistory)) vault.recordHistory = [];

  // v2 (records が plain array) → v3 (LSM-style object) への migrate
  if (Array.isArray(vault.records)) {
    const oldArray = vault.records;
    vault.records = emptyRecordsContainer();
    vault.records.active = oldArray;  // 旧 array は active に流し込む
  }

  // v3 安全弁: 各 sub-array が欠落していれば補完
  const r = vault.records;
  if (!Array.isArray(r.active))      r.active = [];
  if (!Array.isArray(r.chunks))      r.chunks = [];
  if (!Array.isArray(r.corrections)) r.corrections = [];
  if (!Array.isArray(r.tombstones))  r.tombstones = [];

  vault.schemaVersion = 3;
  return vault;
}

/** Phase 7.0c: 現在 active な records を取得 (corrections + tombstones 適用後)。
 *  chunks は別途 lazy load (Phase 7.0i)。MVP では active のみ。 */
export function getCurrentRecords(vault) {
  if (!vault?.records) return [];
  const { active, corrections, tombstones } = vault.records;
  // 削除済 id set
  const tombSet = new Set((tombstones ?? []).map(t => t.id));
  // 訂正 map (id ごとの最新 version)
  const correctionMap = new Map();
  for (const c of (corrections ?? [])) {
    const cur = correctionMap.get(c.id);
    if (!cur || (c.version ?? 1) > (cur.version ?? 1)) correctionMap.set(c.id, c);
  }
  // active に対して corrections を override + tombstones で除外
  return (active ?? [])
    .filter(r => !tombSet.has(r.id))
    .map(r => {
      const correction = correctionMap.get(r.id);
      return correction ? { ...r, ...correction } : r;
    });
}

// 残高取得 (UI から「+ クレジット購入」判定等に使う)
// /api/balance の合流キャッシュ。 残高 polling・refreshHeader・fetchVaultStatus が
//   近接して getBalanceUI を呼んでも、 TTL の間は 1 本の fetch に束ねる。 これで
//   Cloudflare のレート制限 (429 → 数分ブロック) に当たりにくくする。
let _balanceCache = null;  // { ts, promise }
const _BALANCE_CACHE_MS = 3000;

/**
 * _balanceCache を強制無効化。 Stripe 購入 polling 開始時等、 server 側で
 * credit が増えるイベントを待つ瞬間に呼ぶと、 直後の getBalanceUI が必ず
 * fresh fetch を行う。 これを呼ばないと過去 3 秒以内の stale promise を
 * 掴んで webhook 着信を見逃すことがある。
 */
export function invalidateBalanceCache() {
  _balanceCache = null;
}

export async function getBalanceUI(opts = {}) {
  if (!_session) throw new Error("locked");
  const now = Date.now();
  // opts.force=true で cache を無視 (= write 直後の refreshHeader 等)
  if (!opts.force && _balanceCache && now - _balanceCache.ts < _BALANCE_CACHE_MS) {
    return _balanceCache.promise;
  }
  const p = getBalance(_session.signingState);
  _balanceCache = { ts: now, promise: p };
  return p;
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
 *     1. fetchEnvelope(server.latestTxId, outerKeyBytes) で新 envelope を取得
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
  // Phase 7.1-M: server の vault 専用 latest のみを使用 (account.latestTxId は record file
  // chunk write も含む umbrella なので、vault envelope decrypt には使えない)。
  // ★ latestTxId への fallback は廃止 — record tx を vault と誤認して decrypt 失敗する
  //   バグの原因になっていた (Yamaki さんの実機で確認、2026-05-13)。
  // latestVaultTxId が null なら「サーバに vault write 履歴なし」= 何もせず return。
  const serverTxId = serverInfo?.latestVaultTxId ?? null;
  const oldTxId = _session.latestTxId;

  if (!serverTxId) return { refreshed: false, latestTxId: oldTxId };
  if (serverTxId === oldTxId) return { refreshed: false, latestTxId: oldTxId };

  // Phase 7.1-AI: server が「自分が以前書いた古い TX」を返してきた場合は
  //   KV eventual consistency の遅延キャッシュ。 session を巻き戻さない。
  if (_session.recentlyWrittenTxIds?.has(serverTxId)) {
    console.warn(`[refresh] stale server cache detected — server returned ${serverTxId} but session is at ${oldTxId} (recently written). Skipping rewind.`);
    return { refreshed: false, latestTxId: oldTxId, staleCacheDetected: true };
  }

  // 別端末更新を検知 → 最新 envelope を取得して再復号
  //   Phase 7.2-B (α): bundler propagation を retry/wait で待つ (= 直近 write が
  //   まだ Turbo / Arweave 上に乗っていないケース対策、 conflict reload button から呼ばれる
  //   経路で特に重要)。
  //   v2.6 hotfix: outer decrypt 失敗は伝播ではなく cross-talk (= server pointer が
  //   別 outerKey の tx を指す)。 retry しても永久に失敗するので即座に return。
  let envelope = null;
  let lastErr = null;
  const delays = [0, 500, 1500, 3000, 6000, 10000];
  for (let i = 0; i < delays.length; i++) {
    if (delays[i] > 0) {
      console.log(`[refresh] Arweave 伝播待ち... (${i+1}/${delays.length})`);
      await new Promise(res => setTimeout(res, delays[i]));
    }
    try {
      // Stage 2c Stage D2: outerKeyHandle (= Rust OuterKey handle) があれば優先使用、 fallback で既存 path
      const r = await fetchEnvelope(serverTxId, (_session.outerKeyHandle ?? _session.outerKey ?? _session.outerKeyBytes));
      if (r?.envelope) { envelope = r.envelope; break; }
    } catch (e) {
      lastErr = e;
      // outer decrypt 失敗は retry 不能 (= server pointer が cross-talk で別 outerKey の tx)
      const msg = String(e?.message ?? "");
      if (msg.includes("Outer envelope decryption failed")) {
        console.warn(`[refresh] cross-talk detected (server pointer points to envelope with different outerKey, txid=${serverTxId}) — adopting serverTxId for next save (will overwrite cross-talk pointer)`);
        // v2.6 hotfix: cross-talk pointer を承認 → 次の saveVault が expectedLatestTxId match
        //   になり、 自分の envelope で server pointer を自然に上書きする (= self-heal)。
        //   _session.latestTxId を server の値に同期しないと、 次の save が 409 conflict で
        //   永久に失敗する (「他で書込み」 modal が誰も触ってないのに出る原因)。
        _session.latestTxId = serverTxId;
        patchMeta({ latestTxId: serverTxId });
        return { refreshed: false, latestTxId: serverTxId, crossTalkDetected: true };
      }
      console.warn(`[refresh] fetch attempt ${i+1} failed:`, e?.message);
    }
  }
  if (!envelope) {
    throw new Error("Server は " + serverTxId + " を最新としていますが、 Arweave/Turbo から取得できません (= bundling 中、 数分後に再試行してください): " + (lastErr?.message || "unknown"));
  }
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
  // Phase 7.3-A.7b: business mode は _session.mek = null だが _session.mekKey で動く。
  if (!_session?.mek && !_session?.mekKey) throw new Error("locked");

  // Phase 7.2-B v2: Business mode は K1 rotation 検知時に server から新 K1 を取り直す。
  //   v2 では envelope.w_emp から emp_priv を復号 → /api/corp/fetch-enc-k1 で新 enc_K1 取得 →
  //   eciesUnwrapForRecipient で K1 → HKDF(K1, K2) で新 real_MEK を計算する。
  //   k1Version が session のものと異なる場合 (= 別端末で rotation 発生時) も同じ flow で更新。
  let mekRaw = _session.mek;
  // Phase 7.3-A.9 part 4: V1/V2 両対応。 k2HkdfKey があれば V2 path、 無ければ V1 raw K2。
  const _refreshHasK2 = _session.businessK2 || _session.k2HkdfKey;
  if (envelope?.m === "business" && envelope?.w_emp && _refreshHasK2) {
    const cid = envelope.cid || _session.vault?.companyId;
    if (cid) {
      try {
        // emp_priv は session に既にあれば再利用、 なければ w_emp から取り直す (V1/V2 分岐)
        let empPrivKey = _session.empPrivKey;
        if (!empPrivKey) {
          if (_session.k2AesKey) {
            empPrivKey = await unwrapEmpPrivWithK2Key(_session.k2AesKey, envelope.w_emp);
          } else {
            empPrivKey = await unwrapEmpPrivWithK2(_session.businessK2, envelope.w_emp);
          }
          _session.empPrivKey = empPrivKey;
        }
        const encK1 = await _fetchEncK1V2(_session.signingState);
        const k1Raw = await eciesUnwrapForRecipient(empPrivKey, encK1);
        const k1 = new Uint8Array(k1Raw);
        // Stage 2c Stage G3: K1Key handle を並列 populate (= raw bytes window は既存と同じ)
        try {
          const _newK1Handle = await importK1RawAsHandle(k1);
          if (_newK1Handle) {
            if (_session.k1Handle && typeof _session.k1Handle.free === "function") {
              try { _session.k1Handle.free(); } catch (_) {}
            }
            _session.k1Handle = _newK1Handle;
          }
        } catch (e) {
          console.warn("[arpass Stage 2c-G3] k1Handle populate skipped (refresh path):", e?.message || e);
        }
        // Phase 7.3-A.9 part 4: V2 path で raw K2 を避ける
        let newMekKey, newMekHkdfKey;
        if (_session.k2HkdfKey) {
          newMekKey = await deriveBusinessMekKeyV2(k1, _session.k2HkdfKey, {
            usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          });
          newMekHkdfKey = await deriveBusinessMekHkdfKeyV2(k1, _session.k2HkdfKey);
        } else {
          newMekKey = await deriveBusinessMekKey(k1, _session.businessK2, {
            usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          });
          newMekHkdfKey = await deriveBusinessMekHkdfKey(k1, _session.businessK2);
        }
        k1.fill(0);
        if (_session.mek) _session.mek.fill(0);
        _session.mek = null;          // business mode raw mek 廃止
        _session.mekKey = newMekKey;
        _session.mekHkdfKey = newMekHkdfKey;
        _session.k1Version = encK1.k1Version ?? _session.k1Version ?? null;
        mekRaw = null;  // 下流の body 復号は _session.mekKey 経由に切替
      } catch (e) {
        console.warn("[refresh-decrypt] v2 K1 refetch failed, falling back to session.mek:", e?.message);
      }
    }
  }

  // Phase 7.3-A.3: session.mekKey があれば直接使う (= importKey 不要)
  const mekKey = _session.mekKey || await crypto.subtle.importKey(
    "raw", mekRaw, { name: "AES-GCM" }, false, ["decrypt"]
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

// ---------------------------------------------------------------------------
// Phase 6.3: Corporate Wallet Sharing — UI helpers
// ---------------------------------------------------------------------------

/** GET /api/corp/info — 自分の所属情報 (member/admin/none) を取得 */
/**
 * Phase 7.2-B v2: 廃止された v1 helper の互換 stub。
 *
 * v1 では admin が会社 server keypair を生成し vault.serverPrivateKeys に escrow して
 * いたが、 v2 で server keypair / company privkey の永続保管は完全撤廃された。
 * 既存 caller が壊れないよう no-op を返すだけ。
 *
 * @returns {Promise<{ ok: boolean, deprecated: boolean }>}
 */
export async function ensureAdminCorpKeypair() {
  // Phase 7.2-B v2: admin server-keypair 管理は v1 specific。 v2 では admin は自分用の
  //   K1 を生成 + 各社員に per-employee ECIES wrap で配布する設計のため、 server-side
  //   keypair は保管しない。 このヘルパーは no-op で残す (= 既存 caller が壊れないように)。
  return { ok: true, deprecated: true, message: "v2 ではこの操作は不要" };
}

export async function corpInfoUI() {
  if (!_session) throw new Error("locked");
  const r = await signedFetch("/api/corp/info", "GET", null, _session.signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`corp info failed: ${j.error || r.status}`);
  return j;  // { ok: true, member: {...}|null, admin?: {...} }
}

/** POST /api/corp/join — invite code で会社に参加 */
export async function corpJoinUI(code) {
  if (!_session) throw new Error("locked");
  const r = await signedFetch("/api/corp/join", "POST", { code }, _session.signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) throw new Error(j.error || `join failed (${r.status})`);
  return j;
}

/** POST /api/corp/leave — 会社から離脱 */
export async function corpLeaveUI() {
  if (!_session) throw new Error("locked");
  const r = await signedFetch("/api/corp/leave", "POST", {}, _session.signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) throw new Error(j.error || `leave failed (${r.status})`);
  return j;
}

/** POST /api/corp/admin/slot-create — Admin が新規 slot 発行 → invite code を返す */
export async function corpSlotCreateUI() {
  if (!_session) throw new Error("locked");
  const r = await signedFetch("/api/corp/admin/slot-create", "POST", {}, _session.signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) throw new Error(j.error || `slot-create failed (${r.status})`);
  return j;  // { ok: true, slotId, code, codeExpiry }
}

/** POST /api/corp/admin/slot-revoke — Admin が slot を切る (member binding 削除、code 再発行) */
export async function corpSlotRevokeUI(slotId) {
  if (!_session) throw new Error("locked");
  const r = await signedFetch("/api/corp/admin/slot-revoke", "POST", { slotId }, _session.signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) throw new Error(j.error || `slot-revoke failed (${r.status})`);
  return j;
}

/** POST /api/corp/admin/slot-regenerate — Admin が pending slot の code を再生成 */
export async function corpSlotRegenerateUI(slotId) {
  if (!_session) throw new Error("locked");
  const r = await signedFetch("/api/corp/admin/slot-regenerate", "POST", { slotId }, _session.signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) throw new Error(j.error || `slot-regenerate failed (${r.status})`);
  return j;
}


// ---------------------------------------------------------------------------
// Phase 7.1: Business mode UI helpers (relay + device-request + admin)
// ---------------------------------------------------------------------------

/** POST /api/corp/relay/send — ECIES 暗号化済 payload を recipient に push */
export async function corpRelaySendUI({ to, kind, payload }) {
  if (!_session) throw new Error("locked");
  const r = await signedFetch("/api/corp/relay/send", "POST", { to, kind, payload }, _session.signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) throw new Error(j.error || `relay-send failed (${r.status})`);
  return j;
}

/** GET /api/corp/relay/inbox — 自分宛 relay 一覧取得 */
export async function corpRelayInboxUI() {
  if (!_session) throw new Error("locked");
  const r = await signedFetch("/api/corp/relay/inbox", "GET", null, _session.signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) throw new Error(j.error || `relay-inbox failed (${r.status})`);
  return j;  // { ok, items: [...] }
}

/** POST /api/corp/relay/ack — 受信完了 ack → server から削除 */
export async function corpRelayAckUI(id) {
  if (!_session) throw new Error("locked");
  const r = await signedFetch("/api/corp/relay/ack", "POST", { id }, _session.signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) throw new Error(j.error || `relay-ack failed (${r.status})`);
  return j;
}

// Phase 7.1-AC: ephemeral signing state を渡せる variant (= 新端末で _session が無い時に使う)
export async function corpRelayInboxWithStateUI(signingState) {
  const r = await signedFetch("/api/corp/relay/inbox", "GET", null, signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) throw new Error(j.error || `relay-inbox failed (${r.status})`);
  return j;
}
export async function corpRelayAckWithStateUI(signingState, id) {
  const r = await signedFetch("/api/corp/relay/ack", "POST", { id }, signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) throw new Error(j.error || `relay-ack failed (${r.status})`);
  return j;
}

/** POST /api/corp/device-request/create — 社員が機種追加/Pwd 変更/Deep Recovery を request */
export async function corpDeviceRequestCreateUI({ kind, newDevicePubKey, displayName }) {
  if (!_session) throw new Error("locked");
  const r = await signedFetch("/api/corp/device-request/create", "POST",
    { kind, newDevicePubKey, displayName }, _session.signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) throw new Error(j.error || `device-request-create failed (${r.status})`);
  return j;  // { ok, reqId }
}

/** GET /api/corp/device-request/poll — 自分の request の status 確認 */
export async function corpDeviceRequestPollUI(reqId) {
  if (!_session) throw new Error("locked");
  const r = await signedFetch(`/api/corp/device-request/poll?reqId=${encodeURIComponent(reqId)}`, "GET", null, _session.signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) throw new Error(j.error || `device-request-poll failed (${r.status})`);
  return j;  // { ok, status: "pending"|"approved"|"denied"|"expired", ... }
}

/** GET /api/corp/admin/inbox — Admin が pending request 一覧取得 */
export async function corpAdminInboxUI() {
  if (!_session) throw new Error("locked");
  const r = await signedFetch("/api/corp/admin/inbox", "GET", null, _session.signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) throw new Error(j.error || `admin-inbox failed (${r.status})`);
  return j;  // { ok, items: [...] }
}

/** POST /api/corp/admin/approve — Admin が request を承認 + payload push */
export async function corpAdminApproveUI({ reqId, payload }) {
  if (!_session) throw new Error("locked");
  const r = await signedFetch("/api/corp/admin/approve", "POST", { reqId, payload }, _session.signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) throw new Error(j.error || `admin-approve failed (${r.status})`);
  return j;  // { ok, relayId }
}

/** POST /api/corp/admin/deny — Admin が request を拒否 */
export async function corpAdminDenyUI({ reqId, reason }) {
  if (!_session) throw new Error("locked");
  const r = await signedFetch("/api/corp/admin/deny", "POST", { reqId, reason }, _session.signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) throw new Error(j.error || `admin-deny failed (${r.status})`);
  return j;
}

// Phase 7.1-AC: Admin が「機種追加コード」を発行する
/** POST /api/corp/admin/device-add-code/create — admin が特定社員の機種追加コード発行 */
export async function corpAdminDeviceAddCodeCreateUI({ empPkHash, autoApprove }) {
  if (!_session) throw new Error("locked");
  if (!isAdminMode()) throw new Error("not admin mode");
  const r = await signedFetch("/api/corp/admin/device-add-code/create", "POST",
    { empPkHash, autoApprove: !!autoApprove }, _session.signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) throw new Error(j.error || `device-add-code-create failed (${r.status})`);
  return j;  // { ok, code, expiresInSeconds, autoApprove }
}

// Phase 7.2-E: ZK audit log — push / pull / ack helpers
/** POST /api/corp/audit/push — corp member auth, ECIES blob 受付 */
export async function corpAuditPushUI(encryptedB64u) {
  if (!_session) throw new Error("locked");
  const r = await signedFetch("/api/corp/audit/push", "POST", { encrypted: encryptedB64u }, _session.signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) throw new Error(j.error || `audit/push failed (${r.status})`);
  return j;
}
/** GET /api/corp/audit/pull — admin only */
export async function corpAuditPullUI() {
  if (!_session) throw new Error("locked");
  if (!isAdminMode()) throw new Error("not admin mode");
  const r = await signedFetch("/api/corp/audit/pull", "GET", null, _session.signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) throw new Error(j.error || `audit/pull failed (${r.status})`);
  return j;
}
/** POST /api/corp/audit/ack — admin only */
export async function corpAuditAckUI(ids) {
  if (!_session) throw new Error("locked");
  if (!isAdminMode()) throw new Error("not admin mode");
  const r = await signedFetch("/api/corp/audit/ack", "POST", { ids }, _session.signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) throw new Error(j.error || `audit/ack failed (${r.status})`);
  return j;
}

// Phase 7.2-A: admin が会社の IP allowlist + ネットワーク policy を更新
/** POST /api/corp/admin/set-ip-policy — admin auth */
export async function corpAdminSetIpPolicyUI({ ipAllowlist, blockPersonalFromOurNetwork, autoRotateOnOffboard, restrictReadToAllowlist }) {
  if (!_session) throw new Error("locked");
  if (!isAdminMode()) throw new Error("not admin mode");
  const body = {};
  if (Array.isArray(ipAllowlist)) body.ipAllowlist = ipAllowlist;
  if (typeof blockPersonalFromOurNetwork === "boolean") body.blockPersonalFromOurNetwork = blockPersonalFromOurNetwork;
  if (typeof autoRotateOnOffboard === "boolean") body.autoRotateOnOffboard = autoRotateOnOffboard;
  if (typeof restrictReadToAllowlist === "boolean") body.restrictReadToAllowlist = restrictReadToAllowlist;
  const r = await signedFetch("/api/corp/admin/set-ip-policy", "POST", body, _session.signingState);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) {
    const err = new Error(j.error || `set-ip-policy failed (${r.status})`);
    err.code = j.code;
    err.offender = j.offender;
    throw err;
  }
  return j;  // { ok, company: { ipAllowlist, blockPersonalFromOurNetwork, autoRotateOnOffboard } }
}

// Phase 7.1-AC: 完全 lockout した社員の新端末が code を引き換える (unauth path)
/** POST /api/corp/device-add/redeem — UNAUTHENTICATED, code is the auth */
export async function corpDeviceAddRedeemUI({ code, newDevicePubKey, displayName }) {
  const r = await fetch("/api/corp/device-add/redeem", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code, newDevicePubKey, displayName }),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) {
    const err = new Error(j.error || `redeem failed (${r.status})`);
    err.code = j.code;
    throw err;
  }
  return j;  // { ok, reqId, autoApprove, expiresInSeconds }
}

/**
 * Admin が自分の public key (= 社員の Recovery を ECIES で暗号化する宛先) を取得する用。
 * vault-client の signingState から publicKeyRaw を露出する小さな getter。
 */
export function adminPublicKeyRaw() {
  return _session?.signingState?.publicKeyRaw ?? null;
}

/**
 * Phase 7.1-F: Admin が employees[] にある社員の encryptedRecovery を MEK で decrypt して
 * Recovery 文字列を取得する。
 *
 * @param {string} employeePkHash  対象社員の publicKeyHash
 * @returns {Promise<string|null>} Recovery 文字列 "RS1-..."、見つからない場合は null
 */
export async function decryptEmployeeRecoveryUI(employeePkHash) {
  if (!_session) throw new Error("locked");
  const employees = _session.vault?.employees || [];
  const emp = employees.find(e => e.publicKeyHash === employeePkHash);
  if (!emp || !emp.encryptedRecovery) return null;
  return await decryptRecoveryWithMek(emp.encryptedRecovery, _session.mek);
}

/**
 * Phase 7.1: Admin が employees[] に新規社員を追加する (= recovery-deposit を受け取った直後)。
 * vault.employees.push() してから saveVault が必要。
 *
 * @param {object} emp { userId, displayName, email?, publicKeyHash, recovery (plaintext) }
 */
export async function addEmployeeUI({ userId, displayName, email, publicKeyHash, recovery, createdAtArweave }) {
  if (!_session) throw new Error("locked");
  if (!isAdminMode()) throw new Error("not admin mode");
  if (!recovery) throw new Error("recovery required");
  const encryptedRecovery = await encryptRecoveryWithMek(recovery, _session.mek);
  const employees = _session.vault.employees || (_session.vault.employees = []);
  // 既存に同じ publicKeyHash があれば更新 (= 機種追加後の re-deposit 等)
  const existingIdx = employees.findIndex(e => e.publicKeyHash === publicKeyHash);
  const record = {
    userId,
    displayName: displayName || userId,
    email: email || undefined,
    publicKeyHash,
    encryptedRecovery,
    addedAt: new Date().toISOString(),
    status: "active",
    createdAtArweave: createdAtArweave || undefined,
  };
  if (existingIdx >= 0) employees[existingIdx] = { ...employees[existingIdx], ...record };
  else employees.push(record);
  return record;
}

/**
 * Phase 7.1-S: admin の vault.employees[] から該当 publicKeyHash の社員を削除。
 * 退社処理フローから呼ばれる。スケジュール save は呼出側 (app-main.js) が
 * scheduleSave(currentVault()) で行う。
 *
 * @param {string} publicKeyHash 削除対象社員の publicKeyHash
 * @returns {boolean} true: 削除した、false: 該当無し
 */
export function removeEmployeeUI(publicKeyHash) {
  if (!_session) throw new Error("locked");
  if (!isAdminMode()) throw new Error("not admin mode");
  if (!Array.isArray(_session.vault.employees)) return false;
  const before = _session.vault.employees.length;
  _session.vault.employees = _session.vault.employees.filter(e => e.publicKeyHash !== publicKeyHash);
  return _session.vault.employees.length < before;
}

/**
 * 自分の signing private key を返す (= ECIES 復号で使う)。
 * signingPrivateKey は CryptoKey なので、ECDH 用の raw scalar は別途 derive 必要
 * — 既存の deriveSigningKey が privateKeyJwk.d を持っているのでそこから取り出す。
 */
export async function currentSigningPrivateKeyRaw() {
  if (!_session) return null;
  // signingState.signingPrivateKey は CryptoKey (extractable: false) のため raw 取り出し不可。
  //   署名鍵は business/admin では K2、 personal では MEK から HKDF 派生される。
  //   Phase 7.3-A 以降 raw な MEK/K2 は session に存在しないため、 非 extractable な
  //   HKDF base CryptoKey (k2HkdfKey / mekHkdfKey) から署名 scalar を transient に再導出する。
  //   business/admin は k2HkdfKey を優先 (= 署名鍵が K2 由来であるため)。
  const hkdfBase = _session.k2HkdfKey || _session.mekHkdfKey;
  if (!hkdfBase) {
    console.warn("[currentSigningPrivateKeyRaw] session に HKDF base key が無い");
    return null;
  }
  const { deriveSigningKeyFromHkdf } = await import("/lib/vault-crypto.js?v=11331c7d");
  const sk = await deriveSigningKeyFromHkdf(hkdfBase);
  return sk.privateKeyRaw;  // 32-byte big-endian scalar
}



// ---------------------------------------------------------------------------
// Phase 6.4: Tier resolution — current tier の qualifier を返す。
// /api/balance は { tier, companyId? } を含むので fetch して deriveAppNameTag
// に渡す qualifier 文字列を組み立てる。
// ---------------------------------------------------------------------------

/**
 * 現 tier に対応する App-Name qualifier 文字列を返す (未認証時は null = legacy)。
 * @returns {Promise<string|null>}
 */
export async function fetchCurrentTierQualifier() {
  if (!_session) return null;
  try {
    const r = await signedFetch("/api/balance", "GET", null, _session.signingState);
    const j = await r.json().catch(() => ({}));
    if (!j.ok) return null;
    // Phase 7.2-B (α): corp tier も legacy tag (null) を使う。
    //   corp::cid qualifier を使うと社員が Recovery 単独で unlock した時に検索リストに
    //   含まれず 404 になる。 envelope.m === "business" で識別できるため tag 分離は不要。
    if (j.tier === "corp") return null;
    if (j.tier === "private") return "private";
    if (j.tier === "paid") return "paid";
    if (j.tier === "free") return "free";
    return null;
  } catch {
    return null;
  }
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
    newEnvelope, (_session.outerKeyHandle ?? _session.outerKey ?? _session.outerKeyBytes), _session.appNameTag, _session.signingState,
    { tier: _resolveCurrentTier() }
  );
  _session.lastEnvelope = newEnvelope;
  _session.latestTxId = writeResult.txid;
  _recordWrittenTxId(writeResult.txid);  // Phase 7.1-AI
  patchMeta({ latestTxId: writeResult.txid });
  return { txid: writeResult.txid, removed: true };
}

// ============================================================================
// Phase 7.2-B v2 admin/member helpers — K1 distribution + rotation
// ============================================================================

/** Admin: 未配布社員リストを取得 (= status="pending_k1")。 */
export async function listPendingEmployees() {
  if (!_session?.signingState) throw new Error("locked — unlock first");
  const r = await signedFetch("/api/corp/pending-employees", "GET", null, _session.signingState);
  const body = await r.json().catch(() => ({}));
  if (!r.ok || !body.ok) throw new Error(body?.error || "pending-employees failed");
  return body.members || [];
}

/** Admin: active 社員リスト (= K1 rotate 用)。 */
export async function listActiveEmployees() {
  if (!_session?.signingState) throw new Error("locked — unlock first");
  const r = await signedFetch("/api/corp/active-members", "GET", null, _session.signingState);
  const body = await r.json().catch(() => ({}));
  if (!r.ok || !body.ok) throw new Error(body?.error || "active-members failed");
  return body.members || [];
}

/** Admin: 現行 K1 version を取得。 */
export async function fetchK1Version() {
  if (!_session?.signingState) throw new Error("locked — unlock first");
  const r = await signedFetch("/api/corp/k1-version", "GET", null, _session.signingState);
  const body = await r.json().catch(() => ({}));
  if (!r.ok || !body.ok) throw new Error(body?.error || "k1-version failed");
  return body;
}

/**
 * Admin: 単一社員に K1 を ECIES wrap して upload。
 * @param {string} targetPkHash
 * @param {object} empPubKeyJwk  社員 pubkey
 * @param {Uint8Array} k1Bytes   配布する K1 (32B)
 * @param {number} k1Version     現行 K1 version
 */
export async function distributeK1ToMember(targetPkHash, empPubKeyJwk, k1Bytes, k1Version) {
  if (!_session?.signingState) throw new Error("locked — unlock first");
  const encK1Blob = await eciesWrapForRecipient(empPubKeyJwk, k1Bytes);
  const r = await signedFetch("/api/corp/upload-enc-k1", "POST",
    { pkHash: targetPkHash, encK1Blob, k1Version }, _session.signingState);
  const body = await r.json().catch(() => ({}));
  if (!r.ok || !body.ok) throw new Error(body?.error || "upload-enc-k1 failed");
  return body;
}

/**
 * Admin: 未配布社員全員に K1 を配布する高レベル wrapper。
 * Admin の vault に K1 が格納されている前提 (= _session.mek が K1 を含む形 / または別経路で持つ)。
 * v2 では admin の K1 は _session.k1 (Uint8Array) に保持される (今後)。
 */
export async function distributeK1ToAllPending(excludePkHashes = null) {
  if (!_session?.signingState) throw new Error("locked — unlock first");
  if (!_session?.businessMode && _session?.vault?.mode !== "business" && _session?.vault?.mode !== "admin") {
    throw new Error("admin/business mode session required");
  }
  // Phase 7.3-A.7e: admin K1 は vault.k1Current から transient に decode し、 全配布終了後に fill(0)。
  //   _session.k1 (raw 持続) を介さない設計 (= raw 残留撲滅)。
  const k1 = _decodeAdminK1FromVault();
  if (!k1) {
    throw new Error("vault に K1 がありません。Admin UI から K1 生成 → 配布を行ってください");
  }
  try {
    const verRec = await fetchK1Version().catch(() => ({ current: 1 }));
    const k1Version = verRec.current ?? 1;
    let pending = await listPendingEmployees();
    if (excludePkHashes && excludePkHashes.size) {
      // 退社処理直後の KV 伝播遅延で削除済み member が残ることがあるため除外
      pending = pending.filter((m) => !excludePkHashes.has(m.pkHash));
    }
    const results = [];
    for (const m of pending) {
      try {
        await distributeK1ToMember(m.pkHash, m.emp_pubkey, k1, k1Version);
        results.push({ pkHash: m.pkHash, ok: true });
      } catch (e) {
        console.error("[distribute] failed for", m.pkHash, e);
        results.push({ pkHash: m.pkHash, ok: false, error: e?.message });
      }
    }
    return results;
  } finally {
    k1.fill(0);  // raw を hygiene
  }
}

/** Member: 自分の emp_pub を server に登録 (= signup 直後 / 機種追加後)。 */
export async function registerMyEmpPubkey() {
  if (!_session?.signingState) throw new Error("locked — unlock first");
  // emp_pub は envelope に emp_pub field で乗っている (= caller がそれを渡す)
  const empPubKeyJwk = _session.lastEnvelope?.emp_pub;
  if (!empPubKeyJwk) throw new Error("session の lastEnvelope に emp_pub が無い");
  return _registerEmpPubkeyV2(empPubKeyJwk, _session.signingState);
}

// ============================================================================
// Phase 7.2-B v2 admin K1 management
// ============================================================================
// Admin の K1 は vault.k1 として base64url で保存される (32 byte ランダム値)。
// 通常 unlock 後に vault.k1 を session.k1 にロード、 distribute 操作時に使う。
// K1 値 rotate は admin が再生成 → 各社員に再配布で実装 (= Task #100)。

/**
 * Phase 7.3-A.7e: admin K1 を vault.k1Current から transient に decode する helper。
 *   raw Uint8Array が caller に返るが、 caller が即座に使って fill(0) する規律。
 *   _session.k1 を介さずに毎回 b64uDecode することで raw bytes の session 残留を撲滅。
 *
 * @returns {Uint8Array|null}  K1 raw 32B (caller が fill(0) 責任を持つ)
 */
function _decodeAdminK1FromVault() {
  if (!_session?.vault) return null;
  const b64u = _session.vault?.k1Current ?? _session.vault?.k1 ?? null;
  if (!b64u) return null;
  try { return b64uDecode(b64u); } catch { return null; }
}

/**
 * Phase 7.3-A.7e: 旧 version K1 を vault.k1History から transient に decode。
 * @param {number} version
 * @returns {Uint8Array|null}  raw 32B、 caller が fill(0) 責任
 */
function _decodeAdminK1HistoryEntry(version) {
  if (!_session?.vault) return null;
  const history = Array.isArray(_session.vault.k1History) ? _session.vault.k1History : [];
  const entry = history.find(e => e.version === version);
  if (!entry?.k1) return null;
  try { return b64uDecode(entry.k1); } catch { return null; }
}

/** Admin: session.k1 / k1History の状態を返す。 */
export function currentAdminK1Status() {
  if (!_session) return { unlocked: false };
  const vault = _session.vault;
  const isAdmin = vault?.mode === "admin";
  const k1Current = vault?.k1Current ?? vault?.k1 ?? null;  // legacy vault.k1 互換
  const k1Version = vault?.k1Version ?? (k1Current ? 1 : null);
  const k1History = Array.isArray(vault?.k1History) ? vault.k1History : [];
  return {
    unlocked: true,
    isAdmin,
    hasK1: !!k1Current,
    k1Version,
    historyCount: k1History.length,
    history: k1History.map(({ version, retiredAt }) => ({ version, retiredAt })),  // raw k1 は除外
    companyId: vault?.companyId ?? null,
  };
}

/**
 * Phase 7.2-B v2 — 廃業時 Business vault 復旧用: admin vault から K1 緊急 export payload を構築する。
 *
 * 出力は会社共通鍵 K1 (current + 全 history) のみを含む。 v1 時代の "server keypair"
 * (= envelope.ws を server が wrap する設計) は v2 で完全廃止されており、 ここでは出力しない。
 *
 * セキュリティ前提 (重要): K1 単体ではどの社員 vault も復号できない。
 *   real_MEK = HKDF(K1 ‖ K2) で K2 は各社員固有 (= 各社員の 2-of-3 factor から導出)。
 *   このファイルが流出しても、 攻撃者は各社員の Master / Passkey / Recovery のうち
 *   2 つを別途入手しない限り vault を 1 件も開けない。
 *
 * admin mode (= K1 平文を自分の vault に持つ) でのみ呼べる。
 *
 * @returns {{ companyId: string|null, k1Version: number|null,
 *             k1Current: string|null, k1History: Array<{version:number,k1:string,retiredAt?:string}> }}
 */
export function getAdminK1EmergencyExport() {
  if (!_session) throw new Error("locked — unlock first");
  const vault = _session.vault;
  if (vault?.mode !== "admin")
    throw new Error("admin mode のみで実行可能 (K1 平文は admin vault にのみ存在)");
  const k1Current = vault.k1Current ?? vault.k1 ?? null;  // legacy vault.k1 互換
  if (!k1Current)
    throw new Error("K1 が未生成です。 admin tab で「K1 を生成」を実行してください。");
  const k1Version = vault.k1Version ?? 1;
  const rawHistory = Array.isArray(vault.k1History) ? vault.k1History : [];
  // history は { version, k1 (b64u), retiredAt } をそのまま出力。
  //   過去 K1 version で書かれた envelope を復号できるよう全件含める。
  const k1History = rawHistory
    .filter((e) => e && typeof e.k1 === "string" && Number.isFinite(e.version))
    .map((e) => ({ version: e.version, k1: e.k1, retiredAt: e.retiredAt ?? null }));
  return {
    companyId: vault.companyId ?? null,
    k1Version,
    k1Current,            // b64u 32B
    k1History,            // [{ version, k1 (b64u), retiredAt }]
  };
}

/**
 * Phase 7.2-B v2 — 廃業時 emergency-restore tool 用: K1 を直接与えて Business vault を復号する。
 *
 * 通常 unlock (decryptVaultAuto) は server から enc_K1 を fetch → emp_priv で ECIES unwrap して
 * K1 を得る。 server が停止した廃業後はその経路が死ぬため、 admin が export した K1 を
 * 直接受け取り decryptVaultBusiness に渡す。 server / /api/* は一切呼ばない。
 *
 * セキュリティ: k1Bytes を与えても factors (2-of-3) が無ければ K2 wrap を開けず復号は失敗する。
 *   K1 は real_MEK の片方の材料に過ぎない。
 *
 * @param {object} envelope     business envelope (Arweave から取得 or 手動 upload した v5 inner envelope)
 * @param {object} factors      { password?, prfOutput?, recoveryMaterial?, credIdHash? } — 2-of-3
 * @param {Uint8Array} k1Bytes  32 byte raw K1 (envelope.k1Version に対応する version を選択済)
 * @returns {Promise<{ vault, path }>}
 */
export async function decryptBusinessVaultWithK1(envelope, factors, k1Bytes) {
  if (!envelope || envelope.m !== "business")
    throw new Error("business envelope expected");
  if (!(k1Bytes instanceof Uint8Array) || k1Bytes.length !== 32)
    throw new Error("k1Bytes must be 32 byte Uint8Array");
  // decryptVaultBusiness が K2 wrap (w.a/b/c) の解錠と HKDF(K1‖K2) → real_MEK → body 復号を行う。
  // factors が不足/誤りなら "no K2 wrap could be opened" を投げる (= false success なし)。
  const result = await decryptVaultBusiness(envelope, factors, k1Bytes);
  return { vault: result.vault, path: result.path };
}

/**
 * Admin: K1 を新規生成 (= 初回) or rotation する。
 * - 既存 current が無ければ: version=1 で current を生成
 * - 既存 current があれば: current を k1History に push (retiredAt 付き) + 新 current を生成 (version++)
 */
export async function rotateOrCreateAdminK1() {
  if (!_session) throw new Error("locked — unlock first");
  if (_session.vault?.mode !== "admin") throw new Error("admin mode のみで実行可能");

  const v = _session.vault;
  const oldCurrent = v.k1Current ?? v.k1 ?? null;  // legacy vault.k1 も拾う
  const oldVersion = v.k1Version ?? (oldCurrent ? 1 : 0);
  let history = Array.isArray(v.k1History) ? [...v.k1History] : [];

  // rotation の場合、 旧 current を history に追加
  if (oldCurrent) {
    history.push({
      version: oldVersion,
      k1: oldCurrent,
      retiredAt: new Date().toISOString(),
    });
  }

  // 新 K1 生成
  const newK1 = crypto.getRandomValues(new Uint8Array(32));
  const newVersion = oldVersion + 1;

  v.k1Current = b64uEncode(newK1);
  v.k1Version = newVersion;
  v.k1History = history;
  // legacy field を残置すると schema 混乱するので削除
  if ("k1" in v) delete v.k1;

  // Phase 7.3-A.7e: _session.k1 は raw 保持を廃止 (= vault.k1Current から transient decode)。
  //   k1Version は便利情報として session に保持 (= raw bytes ではない)。
  _session.k1Version = newVersion;
  if (newK1) newK1.fill(0);  // raw を即破棄 (vault.k1Current に b64u で永続化済)

  await saveVault(_session.vault);
  return { ok: true, k1Version: newVersion, wasRotation: !!oldCurrent, historySize: history.length };
}

/** 後方互換: 旧 API 名を残す (= UI 側で使い続けても良いように)。 */
export const generateAndSaveAdminK1 = rotateOrCreateAdminK1;

/** Admin: 履歴から特定 version の K1 を削除する。 */
export async function deleteAdminK1FromHistory(version) {
  if (!_session) throw new Error("locked — unlock first");
  if (_session.vault?.mode !== "admin") throw new Error("admin mode のみで実行可能");
  const v = _session.vault;
  if (!Array.isArray(v.k1History)) throw new Error("K1 history が空です");
  const idx = v.k1History.findIndex((e) => e.version === version);
  if (idx === -1) throw new Error(`version ${version} は history に存在しません`);
  v.k1History.splice(idx, 1);
  // Phase 7.3-A.7e: _session.k1History は廃止 (= vault.k1History から transient decode)
  await saveVault(_session.vault);
  return { ok: true, removedVersion: version, remainingCount: v.k1History.length };
}

/**
 * Admin: 過去 K1 を特定社員に再配布する (= 14 日 TTL で server に restore)。
 * @param {string} targetPkHash
 * @param {number} version  history 内の version
 */
export async function restorePastK1ToMember(targetPkHash, version) {
  if (!_session) throw new Error("locked — unlock first");
  if (_session.vault?.mode !== "admin") throw new Error("admin mode のみで実行可能");
  // Phase 7.3-A.7e: vault.k1History から transient decode (= raw 残留撲滅)
  const oldK1 = _decodeAdminK1HistoryEntry(version);
  if (!oldK1) throw new Error(`version ${version} の K1 が admin vault history にありません`);

  try {
    // 社員 pubkey を server から取得
    const pkr = await signedFetch(`/api/corp/member-pubkey?pkH=${encodeURIComponent(targetPkHash)}`, "GET", null, _session.signingState);
    const pj = await pkr.json().catch(() => ({}));
    if (!pkr.ok || !pj.ok || !pj.emp_pubkey) throw new Error(pj?.error || "member-pubkey 取得失敗");

    // ECIES wrap with old K1
    const encK1Blob = await eciesWrapForRecipient(pj.emp_pubkey, oldK1);

    // server に restore (= 過去 version 復活)
    const r = await signedFetch("/api/corp/admin/restore-k1", "POST",
      { pkHash: targetPkHash, version, encK1Blob }, _session.signingState);
    const body = await r.json().catch(() => ({}));
    if (!r.ok || !body.ok) throw new Error(body?.error || "restore-k1 failed");
    return body;
  } finally {
    oldK1.fill(0);  // raw を hygiene
  }
}

// Phase 7.3-A.7e: _hydrateAdminK1FromVault / _hydrateAdminK1HistoryToSession は廃止。
//   raw K1 を _session に持続的に保管しない設計に変更。
//   K1 が必要な操作は _decodeAdminK1FromVault() / _decodeAdminK1HistoryEntry(version)
//   で transient に decode → 使用 → fill(0) する規律で動作する。
//   k1Version (= 番号) のみ session に保持。 raw bytes は session 不在。

/** 既存 distributeK1ToAllPending の前提条件チェックを助ける wrapper。 */
export async function distributeK1ToAllPendingSafe(excludePkHashes = null) {
  if (!_session) throw new Error("locked — unlock first");
  if (_session.vault?.mode !== "admin") throw new Error("admin mode のみで実行可能");
  // Phase 7.3-A.7e: _hydrateAdminK1FromVault 廃止 (= raw K1 を session に置かない設計)
  const k1Status = currentAdminK1Status();
  if (!k1Status?.hasK1) throw new Error("K1 が未生成です。 先に「K1 を生成」を押してください");
  return distributeK1ToAllPending(excludePkHashes);
}

/**
 * Phase 7.2-B v2.2: k1Pending mode から通常 mode へ transition する。
 * member が unlock した後 (= signup 直後 + admin の K1 配布完了後の初 unlock) に呼ぶ。
 * - server から自分用 enc_K1 を fetch
 * - ECIES unwrap で K1 取得
 * - body を HKDF(K1, K2) で再暗号化
 * - envelope.k1Pending を削除
 * - saveVault で Arweave に書込
 *
 * 戻り値: { transitioned: bool, reason?: string, k1Version?: int }
 */
export async function tryTransitionFromPending() {
  if (!_session) throw new Error("locked — unlock first");
  if (!_session.lastEnvelope?.k1Pending) {
    return { transitioned: false, reason: "not_pending" };
  }
  // Phase 7.3-A.9 part 4: V1/V2 両対応
  const _transHasK2 = _session.businessK2 || _session.k2HkdfKey;
  if (!_transHasK2 || !_session.empPrivKey) {
    return { transitioned: false, reason: "missing_keys" };
  }
  let encK1;
  try {
    encK1 = await _fetchEncK1V2(_session.signingState);
  } catch (e) {
    if (e.code === "pending_k1_distribution") {
      return { transitioned: false, reason: "k1_pending" };
    }
    throw e;
  }
  const k1Raw = await eciesUnwrapForRecipient(_session.empPrivKey, encK1);
  const k1 = new Uint8Array(k1Raw);
  // Stage 2c Stage G3: K1Key handle を並列 populate (= 既存 raw bytes window 共有)
  try {
    const _initK1Handle = await importK1RawAsHandle(k1);
    if (_initK1Handle) {
      if (_session.k1Handle && typeof _session.k1Handle.free === "function") {
        try { _session.k1Handle.free(); } catch (_) {}
      }
      _session.k1Handle = _initK1Handle;
    }
  } catch (e) {
    console.warn("[arpass Stage 2c-G3] k1Handle populate skipped (signup path):", e?.message || e);
  }
  // Phase 7.3-A.9 part 4: V2 path = K2 HKDF base 経由で mekKey 派生 (raw K2 不要)
  let realMekKey, realMekHkdfKey;
  if (_session.k2HkdfKey) {
    realMekKey = await deriveBusinessMekKeyV2(k1, _session.k2HkdfKey, {
      usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
    });
    realMekHkdfKey = await deriveBusinessMekHkdfKeyV2(k1, _session.k2HkdfKey);
  } else {
    realMekKey = await deriveBusinessMekKey(k1, _session.businessK2, {
      usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
    });
    realMekHkdfKey = await deriveBusinessMekHkdfKey(k1, _session.businessK2);
  }
  if (_session.mek) _session.mek.fill(0);
  _session.mek = null;            // Phase 7.3-A.7: business mode は raw mek 持たない
  _session.mekKey = realMekKey;
  _session.mekHkdfKey = realMekHkdfKey;  // Phase 7.3-A.7b
  k1.fill(0);                     // Phase 7.3-A.7: K1 raw は session に残さず即破棄
  _session.k1 = null;             //   (社員は配布側でないので K1 raw 不要)
  _session.k1Version = encK1.k1Version ?? 1;
  // envelope.k1Pending を削除 → saveVault の新 envelope に引き継がれない
  if (_session.lastEnvelope) {
    delete _session.lastEnvelope.k1Pending;
  }
  await saveVault(_session.vault);
  return { transitioned: true, k1Version: _session.k1Version };
}

// ============================================================================
// Phase 7.2-B v2.5 / 7.3-A.5: K1 migration helpers
// ----------------------------------------------------------------------------
// K1 rotation 後、 旧 K1 で wrap された records BEK / chunks CEK を新 real_MEK で
// re-wrap する。 ファイル本体 (= Arweave 上の ciphertext) は不変、 wrap 形式だけ更新。
// vault envelope の save 1 回で完了。
// ============================================================================

/**
 * Phase 7.2-B v2.5: 現行 K1 と異なる version で wrap された records 数を数える。
 * UI で「過去 K1 で暗号化された N 件」 banner 表示用。
 */
export function countRecordsNeedingK1Migration() {
  if (!_session?.vault) return 0;
  if (currentVaultMode() !== "business") return 0;
  const curVer = _session.k1Version;
  if (curVer == null) return 0;
  let count = 0;
  for (const rec of _session.vault.records || []) {
    for (const att of rec.attachments || []) {
      const v = att.encryption?.k1Version;
      if (v != null && v !== curVer) count++;
    }
  }
  for (const chunk of _session.vault.recordChunks || []) {
    const v = chunk.encryption?.k1Version;
    if (v != null && v !== curVer) count++;
  }
  return count;
}

/**
 * Phase 7.2-B v2.5: 過去 K1 で wrap された records BEK / chunks CEK を一括 re-wrap。
 * 各 BEK/CEK について: 旧 real_MEK で unwrap (extractable) → 新 real_MEK で wrap →
 * metadata 更新 (wrappedBEK / wrapIv / k1Version)。 最後に saveVault 1 回。
 *
 * @returns {Promise<{migrated: number, total: number, skipped: number}>}
 */
export async function migrateAllRecordsToCurrentK1() {
  if (!_session) throw new Error("locked — unlock first");
  if (currentVaultMode() !== "business") return { migrated: 0, total: 0, skipped: 0 };
  const curVer = _session.k1Version;
  if (curVer == null) throw new Error("session に k1Version がありません");

  // Phase 7.3-A.9 part 2: business mode で _session.mek が null になったので mekKey CryptoKey を使う
  const newRealMek = _session.mek ?? _session.mekKey;
  if (!newRealMek) throw new Error("session に mek/mekKey が無い");
  let migrated = 0;
  let total = 0;
  let skipped = 0;

  for (const rec of _session.vault.records || []) {
    for (const att of rec.attachments || []) {
      const enc = att.encryption;
      if (!enc?.wrappedBEK) continue;
      const v = enc.k1Version;
      if (v == null || v === curVer) continue;
      total++;
      try {
        const oldRealMek = await _getRealMekForVersion(v);
        const oldWrapped = b64uDecode(enc.wrappedBEK);
        const oldIv = b64uDecode(enc.wrapIv);
        // 旧で unwrap (extractable = re-wrap 可能に)
        const bek = await unwrapKey(oldRealMek, oldWrapped, oldIv, { extractable: true });
        // 新で wrap
        const { wrapped: newWrapped, iv: newIv } = await wrapKey(newRealMek, bek);
        enc.wrappedBEK = b64uEncode(newWrapped);
        enc.wrapIv = b64uEncode(newIv);
        enc.k1Version = curVer;
        migrated++;
        // bek は CryptoKey、 GC 任せ
      } catch (e) {
        console.error("[migrate] record attachment failed:", e?.message);
        skipped++;
      }
    }
  }

  // chunks も同様
  for (const chunk of _session.vault.recordChunks || []) {
    const enc = chunk.encryption;
    if (!enc?.wrappedCEK) continue;
    const v = enc.k1Version;
    if (v == null || v === curVer) continue;
    total++;
    try {
      const oldRealMek = await _getRealMekForVersion(v);
      const oldWrapped = b64uDecode(enc.wrappedCEK);
      const oldIv = b64uDecode(enc.wrapIv);
      const cek = await unwrapKey(oldRealMek, oldWrapped, oldIv, { extractable: true });
      const { wrapped: newWrapped, iv: newIv } = await wrapKey(newRealMek, cek);
      enc.wrappedCEK = b64uEncode(newWrapped);
      enc.wrapIv = b64uEncode(newIv);
      enc.k1Version = curVer;
      migrated++;
    } catch (e) {
      console.error("[migrate] chunk failed:", e?.message);
      skipped++;
    }
  }

  if (migrated > 0) {
    await saveVault(_session.vault);
  }
  return { migrated, total, skipped };
}

