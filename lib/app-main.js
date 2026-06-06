// Phase 7.0w-AP fix.4 priming: rs-from-paper を deferSave + scheduleSave に
// Phase 7.0w-AH cache-bust priming: vault-crypto.js / vault-client.js が更新されたが
// app-main.js content 不変だと ?v= hash が変わらず古いキャッシュが残るため、
// このコメントで content を変えて hash を強制更新する。
// ============================================================================
// lib/app-main.js
//
// Extracted from inline <script type="module"> in app.html
// to allow CSP `script-src 'self'` (no `unsafe-inline`) and achieve
// SecurityHeaders.com A+ / Mozilla Observatory A+.
//
// DO NOT add inline JS back to app.html. Add to this file instead.
// ============================================================================

import {
  // session / current-state helpers
  isUnlocked,
  currentVault,
  currentLatestTxId,
  currentCredIdHash,
  hasRecoveryInSession,
  lockSession,
  // top-level flows
  createVault,
  createHwkeyVault,
  addHwkeyDevice,
  // Phase 7.5Z: 端末追加コード (Android Chrome picker bug 救済)
  encodeDeviceAddCode,
  decodeDeviceAddCode,
  unlockWithPasswordAndPasskey,
  unlockWithHwkey,
  hwkeyAuthenticate,
  hwkeyAuthenticateForUnlock,
  unlockWithHwkeyAuthed,
  refreshFromServerLatest,
  unlockWithPasswordAndRecovery,
  unlockWithPasskeyAndRecovery,
  saveVault,
  addCredentialOnThisDevice,
  changePasswordUI,
  reissueRecovery_caseA,
  reissueRecovery_caseB,
  getBalanceUI,
  checkoutSessionUI,
  corpInfoUI,
  ensureAdminCorpKeypair,
  corpJoinUI,
  corpLeaveUI,
  corpSlotCreateUI,
  corpSlotRevokeUI,
  corpSlotRegenerateUI,
  removeEmployeeUI,
  refreshTierQualifier,
  // Phase 7.0e: Records (電子書類保管)
  addRecordUI,
  fetchRecordFileUI,
  normalizeCounterparty,
  // Phase 7.0g: 訂正/削除/履歴
  correctRecordUI,
  deleteRecordUI,
  getRecordHistory,
  getCurrentRecords,
  // Phase 7.0i: chunks overflow
  sealOldestChunkUI,
  loadChunkUI,
  chunkRangeOverlaps,
  // Phase 7.0w-AP: Recovery 表示用 helpers
  getDecryptedRecoveryFromVault,
  setRecoverySecretInSession,
  injectEncryptedRecoveryNow,
  authenticateWithPasskey,
  // Phase 7.1: Business mode helpers
  currentVaultMode,
  isPersonalMode,
  isBusinessMode,
  isAdminMode,
  currentCompanyId,
  adminPublicKeyRaw,
  currentSigningPrivateKeyRaw,
  decryptEmployeeRecoveryUI,
  addEmployeeUI,
  corpRelaySendUI,
  corpRelayInboxUI,
  corpRelayAckUI,
  corpAdminDeviceAddCodeCreateUI,
  corpAdminSetIpPolicyUI,
  corpAuditPushUI,
  corpAuditPullUI,
  corpAuditAckUI,
  corpDeviceAddRedeemUI,
  corpRelayInboxWithStateUI,
  corpRelayAckWithStateUI,
  generateEphemeralSigningState,
  corpDeviceRequestCreateUI,
  corpDeviceRequestPollUI,
  corpAdminInboxUI,
  corpAdminApproveUI,
  corpAdminDenyUI,
  // === Phase 7.2-B v2: admin K1 配布 ===
  listPendingEmployees,
  listActiveEmployees,
  fetchK1Version,
  distributeK1ToMember,
  distributeK1ToAllPending,
  distributeK1ToAllPendingSafe,
  generateAndSaveAdminK1,
  rotateOrCreateAdminK1,
  deleteAdminK1FromHistory,
  restorePastK1ToMember,
  currentAdminK1Status,
  getAdminK1EmergencyExport,
  registerMyEmpPubkey,
  tryTransitionFromPending,
  countRecordsNeedingK1Migration,
  migrateAllRecordsToCurrentK1,
} from "/lib/vault-client.js?v=51488219";
import {
  generatePassword,
  passwordStrength,
  isPasskeySupported,
  isSecureContextOk,
  isPRFCapable,
  generateRecoverySecret,
  parseRecoverySecret,
  b64uDecode,
  b64uEncode,
  // Phase 7.1: Business mode crypto helpers
  eciesEncrypt,
  eciesDecrypt,
  publicKeyFingerprint,
} from "/lib/vault-crypto.js?v=11331c7d";
// Phase 6.7: Auto-save debounce — entry CRUD で連続書込を bundle し ~5x コスト削減
import {
  initSaveDebounce,
  scheduleSave,
  flush as flushSaveDebounce,
  getStatus as getSaveStatus,
  clearPending as clearSavePending,
  resolveConflictOverwrite,
  resolveConflictDiscardLocal,
  resolveConflictCancel,
  getPendingConflict,
} from "/lib/save-debounce.js?v=0b10245b";
import {
  readMeta,
  writeMeta,
  clearMeta,
  signedFetch,
  getTxStatus as getTxStatusReal,
} from "/lib/client-auth.js?v=b1e07217";
import {
  initI18n,
  mountLangPicker,
  t as i18n_t,
  getStripeLocale,
  getStripeCurrency,
  onLangChange,
  formatPrice as i18n_formatPrice,
  getLang as i18n_getLang,
} from "/lib/i18n.js?v=409d637c";
// Phase 7.5L: app.html でも SW 登録 + 自動更新検知 (= cache クリア不要化)
import { registerServiceWorker } from "/lib/pwa-install.js?v=6b9d08f4";
registerServiceWorker();

// i18n は非ブロッキングで初期化する。
// Safari で fetch がスローな場合などに await initI18n() を top-level で呼ぶと
// app.html の他の全コード (unlock 等) がブロックされて画面が止まって見えるため、
// 初期化は fire-and-forget。失敗しても app 本体は動き続ける。
initI18n()
  .then(() => mountLangPicker("#header-lang", { compact: false }))
  .catch(err => console.warn("[i18n] init failed (app continues without i18n):", err));

// Phase 7.1-G: 招待 URL ?invite=<code> 検出 — Business mode signup の triggers
// Phase 7.1-AE.2: let 化 — 「📲 会社員: コードで参加」 から手動入力したコードを
//   後から代入できるようにする。これがないと _inviteCode = c.toUpperCase() が
//   silent TypeError で死に、create view に遷移しないバグ (Yamaki 報告)。
let _inviteCode = (() => {
  try {
    const u = new URL(location.href);
    const code = u.searchParams.get("invite");
    return code ? String(code).trim().toUpperCase() : null;
  } catch { return null; }
})();

// Phase 7.1-G: 招待 URL を持って来た時、create view に inviteBanner を表示
// Phase 7.1-AF: business mode が一目で分かる目立つ banner + signup view UI 全体を会社員モード化
function _renderInviteBanner() {
  if (!_inviteCode) return;
  const createView = document.getElementById("view-create");
  if (!createView) return;
  let banner = document.getElementById("invite-banner");
  if (banner) banner.remove();  // 再描画

  banner = document.createElement("div");
  banner.id = "invite-banner";
  banner.style.cssText = "background: linear-gradient(135deg, #FEF3C7 0%, #FDE68A 100%); border: 2px solid #F59E0B; padding: 14px 16px; border-radius: 8px; margin-bottom: 18px; line-height: 1.6;";
  banner.innerHTML = `
    <div style="font-size: 16px; font-weight: 700; margin-bottom: 6px; color: #92400E;">
      🏢 ${i18n_t("app.business_signup.banner_heading") || "会社員モードで登録"}
    </div>
    <div style="font-size: 13px; color: #1E293B;">
      ${i18n_t("app.business_signup.banner_code_label") || "招待コード"}: <code style="background: #fff; padding: 2px 6px; border-radius: 3px; font-family: ui-monospace, monospace; font-size: 12px;">${_inviteCode}</code>
    </div>
    <div style="font-size: 12px; color: #44403C; margin-top: 8px; line-height: 1.5;">
      ${i18n_t("app.business_signup.banner_explainer_html") || "・あなたの Recovery は <strong>自動的に admin に送信</strong> されます (= admin が一括管理する設計)。<br>・Recovery を画面に表示することはありません。Master パスワードだけ覚えてください。<br>⚠ <strong>admin が一度アプリを開いている必要</strong>があります。エラーが出たら admin に「admin タブを開いて」と依頼してください。"}
    </div>
  `;
  const heading = createView.querySelector(".auth-card");
  heading?.insertBefore(banner, heading.firstChild);

  // Phase 7.1-AF: signup view の他の要素も business mode に合わせて切替
  _applyBusinessSignupUI();
}

// Phase 7.1-AF: business mode signup の時、 view-create の各要素を切替
function _applyBusinessSignupUI() {
  const isBusiness = !!_inviteCode;
  // heading
  const heading = document.querySelector('#view-create h1 span[data-i18n="app.create.heading"]');
  if (heading) heading.textContent = isBusiness
    ? (i18n_t("app.create.business_heading") || "🏢 会社員として登録")
    : (i18n_t("app.create.heading") || "Arpass を始める");
  // existing-user-hint (個人/admin 用、社員には混乱するので hide)
  const exHint = document.getElementById("create-existing-user-hint");
  if (exHint) exHint.classList.toggle("hidden", isBusiness);
  // create-btn label
  const btn = document.getElementById("create-btn");
  if (btn) btn.textContent = isBusiness
    ? (i18n_t("app.create.business_button") || "会社の Vault を作成")
    : (i18n_t("app.create.button") || "セキュアドライブを作成");
  // signup_bonus hint (個人/admin 専用、社員は free 扱いなので非表示)
  const bonusHint = document.querySelector('#view-create p[data-i18n="app.create.hint_signup_bonus"]');
  if (bonusHint) bonusHint.classList.toggle("hidden", isBusiness);
  // 下部の '📲 この端末を追加登録する' リンク (= 既存個人 vault 用、社員には不要)
  const restoreSection = document.getElementById("goto-restore-link")?.closest("div");
  if (restoreSection) restoreSection.classList.toggle("hidden", isBusiness);
}



// vault-client が _session を保持しているので、署名状態を取り出すための小さな
// アクセサを加える。本当は vault-client から expose するのが綺麗だが、互換シム
// 層に置くのが簡単 (ここに集約)。
function _getSigningStateOrNull() {
  // signedFetch は signingState パラメータ必須なので、unlock 後に取れるよう
  // vault-client の内部から借りる。currentVault() 等は export されているが、
  // signingState は currently 公開してない → 簡易解として、signedFetch を
  // 直接使うのではなく、内部に直接 fetch + 署名する方が早い。
  // ここでは vault-client の getBalanceUI() / saveVault() が内部で signing
  // state を使っているので、その経路を踏襲する形で /api/checkout も
  // vault-client から呼ぶようにすべき。
  return null;
}

// ---------------------------------------------------------------------------
// v5 cutover compatibility shims
// 旧 app.html が使っていた API のうち、v5 で姿を変えたものを薄く包む。
// 大規模 UI リライト前のブリッジ層。
// ---------------------------------------------------------------------------

// hasVaultIdentity → localStorage に v5 メタ (appNameTag) があるか
// envelope v7 (2026-05-24): outerKey は localStorage に保存しなくなったため
//   appNameTag の有無で判定する (appNameTag は秘密でなく meta に残置)
function hasVaultIdentity() {
  const m = readMeta();
  return !!(m && (m.appNameTag || m.vaultId));  // vaultId は legacy fallback (削除済みでも壊さない)
}
// hasPasskey → meta に credIdHash があるか
function hasPasskey() {
  const m = readMeta();
  return !!(m && m.credIdHash);
}
// getVaultAlg → v5 では常に "v5"
function getVaultAlg() { return isUnlocked() ? "v5" : null; }
// forgetPasskey → meta から credentialId / credIdHash を消すだけ
function forgetPasskey() {
  const m = readMeta() || {};
  delete m.credentialId;
  delete m.credIdHash;
  writeMeta(m);  // Phase 7.1-W: profile-aware (no longer hardcoded key)
}
// newEntryId → ランダム ID 生成 (UI 用)
function newEntryId() {
  const b = crypto.getRandomValues(new Uint8Array(9));
  return "e_" + Array.from(b).map(x => x.toString(36).padStart(2, "0")).join("");
}
// publicReadUrl → arweave 直リンク
function publicReadUrl(txid, { preferTurbo = true } = {}) {
  const base = preferTurbo ? "https://turbo-gateway.com" : "https://arweave.net";
  return `${base}/${txid}`;
}
// readClientIdentity → v5 ではメタ + publicKeyHash
function readClientIdentity() {
  const m = readMeta();
  if (!m) return null;
  return {
    publicKeyHash: m.publicKeyHash ?? null,
    version: "v5",
  };
}
// forgetClientIdentity → v5 メタを完全消去
function forgetClientIdentity() { clearMeta(); }
// getTxStatus / fetchVaultStatus は将来再実装。今は最小スタブ。
// v5 端末リスト管理 — vault.credentials (本体 c の暗号化領域内に保持) ベース。
//
// 各端末追加時 (createVault / addCredentialOnThisDevice) に
//   vault.credentials.push({ credIdHash, name, addedAt })
// で記録される (= addCredentialOnThisDevice 内で実装、Phase 5.1)。
//
// 表示・rename・削除はすべて vault.credentials の操作 → saveVault。
// 削除は「envelope の w.b[i] / w.c[i] 該当エントリを除去」も伴うため
// removeCredentialV5 ヘルパー (vault-client) を経由する。
//
// device という言葉は v4 名残。v5 では「credential」(WebAuthn credential =
// 1 端末上の 1 Passkey) が正しいが、UI 側互換のためここでは device 名を保つ。

function listAuthorizedDevices() {
  const v = currentVault();
  if (!v) return [];
  const credentials = Array.isArray(v.credentials) ? v.credentials : [];
  const myCredIdHash = currentCredIdHash();
  return credentials.map((c) => ({
    deviceId:  c.credIdHash || c.id || "—",
    credIdHash: c.credIdHash || c.id || "—",
    name:      c.name || "(no name)",
    addedAt:   c.addedAt || null,
    current:   c.credIdHash === myCredIdHash,
  }));
}

async function renameAuthorizedDevice(id, newName) {
  const v = currentVault();
  if (!v) throw new Error("locked");
  const list = Array.isArray(v.credentials) ? v.credentials : (v.credentials = []);
  const ent = list.find((c) => (c.credIdHash || c.id) === id);
  if (!ent) throw new Error("device not found in vault.credentials");
  ent.name = newName;
  await saveVault(v);
}

async function removeAuthorizedDevice(id) {
  const v = currentVault();
  if (!v) throw new Error("locked");
  const myCredIdHash = currentCredIdHash();
  if (id === myCredIdHash) {
    throw new Error(i18n_t("app.error.cannot_delete_current_passkey"));
  }
  // 1. vault.credentials から該当 entry を除去
  const list = Array.isArray(v.credentials) ? v.credentials : (v.credentials = []);
  const before = list.length;
  v.credentials = list.filter((c) => (c.credIdHash || c.id) !== id);
  if (v.credentials.length === before) {
    throw new Error("device not found in vault.credentials");
  }
  // 2. envelope の w.b / w.c から credIdHash 該当 wrap を除去
  //    → vault-client の removeCredentialFromEnvelopeUI に委譲 (新 export)
  const { removeCredentialFromEnvelopeUI } = await import("/lib/vault-client.js?v=51488219");
  await removeCredentialFromEnvelopeUI(id);
  // 3. 本体 c も再保存 (credentials 配列を反映)
  await saveVault(v);
}

function currentDeviceId() {
  return currentCredIdHash();
}

async function getTxStatus(txid) {
  // Phase 5.1 で本実装に切替。client-auth.js の getTxStatus が Turbo +
  // arweave.net を並列で問い合わせて bundling / confirmed / pending /
  // not_found / rate_limited / error を返す。
  try {
    return await getTxStatusReal(txid);
  } catch (e) {
    return { state: "error", message: e?.message ?? String(e) };
  }
}
async function fetchVaultStatus() {
  // v5 では per-account 残高は /api/balance (署名認証付き) で取得する。
  // unlock 前 (signing state なし) は header に per-account 情報を表示しない
  // ようにするため、明示的に ok:false で返す (UI の if(s.ok){...} 内に入らない)。
  if (!isUnlocked()) {
    return { ok: false };
  }
  try {
    const j = await getBalanceUI();
    // Phase 5.3-E: 成功 → サービス健康。前回 down だった場合は復旧通知。
    if (state.serviceDown) {
      state.serviceDown = false;
      toast(i18n_t("app.toast.connected"), "ok", 5000);
      renderServiceDownBanner();
      syncReadOnlyState();
    }
    return {
      ok: true,
      // Phase 6.8: server returns estimatedWrites (Math.ceil) — UI never sees raw USD.
      credits: j.estimatedWrites ?? 0,
      // Phase 7.0w-AN: balanceUsdMicro (USD × 1e6) を直接受け取り、currency 表示に使う
      balanceUsdMicro: typeof j.balanceUsdMicro === "number" ? j.balanceUsdMicro : null,
      totalDebits: j.totalWrites ?? 0,        // 表示用 (旧フィールド名互換)
      totalCredits: j.totalWrites ?? 0,
      perWriteUsd: typeof j.perWriteUsd === "number" ? j.perWriteUsd : null,
      // Phase 7.5ZN: tier 1 baseline (vault 更新の market rate) — LP/pricing 表示と統一
      perWriteUsdBase: typeof j.perWriteUsdBase === "number" ? j.perWriteUsdBase : null,
      arUsd: typeof j.arUsd === "number" ? j.arUsd : null,
      arPriceStale: !!j.arPriceStale,
      latestTxId: j.latestTxId ?? null,
      latestTxAt: j.latestTxAt ?? null,
      migratedTo: j.migratedTo ?? null,
      frozen: !!j.frozen,
      frozenReason: j.frozenReason ?? null,
    };
  } catch (e) {
    console.warn("getBalanceUI failed:", e?.message ?? e);
    // Phase 5.3-E: 失敗パターンを分類:
    //   - network error / 5xx → サービス側問題、serviceDown フラグを立てる
    //   - 401/403 → 認証問題 (別件)、フラグは立てない
    const msg = String(e?.message ?? "");
    const looksLikeServiceDown =
      msg.includes("Failed to fetch") ||
      msg.includes("NetworkError") ||
      /\b5\d\d\b/.test(msg);  // 500-599
    if (looksLikeServiceDown && !state.serviceDown) {
      state.serviceDown = true;
      renderServiceDownBanner();
      syncReadOnlyState();
    }
    return { ok: false, error: msg };
  }
}

/**
 * Phase 5.3-E: サービスダウン時に vault view 上部に banner を出す。
 * 「読み出しは可、保存は復旧後」を明示。冪等。
 */
function renderServiceDownBanner() {
  const host = document.getElementById("service-down-banner");
  if (!host) return;
  if (!state.serviceDown) { host.innerHTML = ""; return; }
  host.innerHTML = `
    <div style="background: #FEF3C7; border-left: 4px solid #F59E0B; padding: 12px 16px; border-radius: 6px; margin-bottom: 12px; font-size: 14px; line-height: 1.6;">
      ${i18n_t("app.banner.service_down_html")}
    </div>
  `;
}

/**
 * Phase 7.x: Vault が hard cap (VAULT_SIZE_BLOCK_BYTES) の 80% 以上に達したら
 * vault view 上部に常設の警告 banner を出す。閾値を下回れば自動で消える。冪等。
 * save 時の transient toast (VAULT_SIZE_WARN_BYTES) とは別系統で、こちらは
 * 「これ以上ためると保存できなくなる」緊急度の高い恒常警告。
 */
function renderVaultCapacityBanner() {
  const host = document.getElementById("vault-capacity-banner");
  if (!host) return;
  let bytes = 0;
  try {
    if (state.vault) {
      bytes = new TextEncoder().encode(JSON.stringify(state.vault)).length;
    }
  } catch { bytes = 0; }
  if (bytes < VAULT_SIZE_BANNER_BYTES) {
    host.innerHTML = "";
    host.classList.add("hidden");
    return;
  }
  const pct = Math.min(100, Math.round((bytes / VAULT_SIZE_BLOCK_BYTES) * 100));
  host.innerHTML = i18n_t("app.banner.capacity_nearly_full_html", { pct });
  host.classList.remove("hidden");
}
import {
  generateQrSvg,
  generateDeviceAddQrSvg,
  scanQrFromCamera,
  scanQrFromImage,
  drawQrOnCanvas,
  hasNativeBarcodeDetector,
} from "/lib/qr.js?v=89be3e9f";


// Phase 5.3-J: Passkey 識別用のデフォルト表示名を組み立てる。
// picker やデバイス一覧で「どの端末の何の Passkey か」が分かるように、
// 「ブラウザ + プラットフォーム + 月日時刻」を含める。
function _defaultPasskeyDisplayName() {
  const ua = navigator.userAgent || "";
  let browser = "Browser";
  if (/Chrome\/\d/.test(ua) && !/Edg\/|OPR\//.test(ua)) browser = "Chrome";
  else if (/Edg\//.test(ua)) browser = "Edge";
  else if (/Firefox\//.test(ua)) browser = "Firefox";
  else if (/Safari\//.test(ua) && !/Chrome\//.test(ua)) browser = "Safari";
  else if (/OPR\//.test(ua)) browser = "Opera";
  // Platform をざっくり (navigator.platform は deprecated 気味だが残ってる)
  const plat = navigator.platform || "Unknown";
  let os = "Device";
  if (/Mac/i.test(plat)) os = "Mac";
  else if (/Win/i.test(plat)) os = "Windows";
  else if (/iPhone/i.test(plat)) os = "iPhone";
  else if (/iPad/i.test(plat)) os = "iPad";
  else if (/Android/i.test(navigator.userAgent || "")) os = "Android";
  else if (/Linux/i.test(plat)) os = "Linux";
  const d = new Date();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mn = String(d.getMinutes()).padStart(2, "0");
  return `${browser} on ${os} (${mm}/${dd} ${hh}:${mn})`;
}

// =====================================================================
// App state
// =====================================================================
const state = {
  password: null,          // kept in memory while unlocked
  vault: null,             // decrypted vault object
  latestTxId: null,
  filter: "",
  editingId: null,         // null = new entry, string = editing existing
  saving: false,
  bundlerReadBase: null,   // self-hosted bundler's public read URL, from /api/status
  credits: null,           // last known estimatedWrites (Math.ceil(balance / per-write)). Phase 6.8: not raw USD.
  balanceUsdMicro: null,   // Phase 7.0w-AN: last known USD balance × 1e6 (currency 表示用)
  perWriteUsd: null,       // last known "consume USD per write" (本日のコスト ¥X/回 表示元)
  arUsd: null,             // last known AR/USD spot (display 用、debug)
  readOnly: false,         // true when the active vault is migrated/frozen — saves & deletes are blocked
  // Phase 5.3-E: 課金サーバ (Cloudflare Worker + KV) の健康度。/api/balance や
  // /api/write が 5xx / network エラーで連続失敗すると true になり、UI が
  // 「読み出し専用モード」表示に切り替わる。次回 /api/* が 200 で復旧したら
  // false に戻る。読み出し自体はサーバ非依存なので vault 表示は影響なし。
  serviceDown: false,
};

// Phase 6.7: Vault プレーン JSON サイズの soft / hard 上限。
// PAD_BUCKETS = [80, 160, 240] KiB に整合。
//   60 KB 超 → 警告 toast (80 KiB バケットの上限が近い、次の保存で高コスト tier へ
//              promote される可能性。¥0.33 → ¥0.40 へ上昇)
//   230 KB 超 → 保存ブロック (240 KiB バケット最終キャパ、
//               これを超えると padPlaintext が throw して confusing なエラーが出る)
const VAULT_SIZE_WARN_BYTES  =  60 * 1024;
const VAULT_SIZE_BLOCK_BYTES = 230 * 1024;

// Phase 7.x: 永続 capacity banner の閾値。hard cap (230 KiB) の 80% に達したら
// vault view 上部に「ドライブがほぼ満杯」の常設バナーを表示する。これは save 時の
// 60 KiB transient toast とは別で、より緊急度が高い (これ以上ためると保存不可)。
const VAULT_SIZE_BANNER_BYTES = Math.round(VAULT_SIZE_BLOCK_BYTES * 0.8);

// Phase 6.8.10: 表示用「実用上限 = PAD_BUCKETS[0] = 80 KiB」。これを超えると
// 次のコスト tier (~2x, ~3x) に promote されるため、ユーザの実 actionable 閾値は
// VAULT_SIZE_BLOCK_BYTES (230 KiB hard cap) ではなく 80 KiB (cheapest tier 上限)。
// 230 KiB は server reject の最後の壁として残し、UI には見せない。
const VAULT_BUCKET_SOFT_BYTES = 80 * 1024;
const VAULT_BUCKET_TIER2_BYTES = 160 * 1024;

// Threshold below which we display a "low balance" warning in the header
// and surface a i18n_t("app.button.buy_credits_plus") CTA. Tuned to give the user a chance to
// top up before they actually hit a 402 on save.
const LOW_CREDIT_WARN = 5;

// =====================================================================
// View switching
// =====================================================================
const views = {
  picker: document.getElementById("view-profile-picker"),  // Phase 7.1-W
  create: document.getElementById("view-create"),
  "create-hwkey": document.getElementById("view-create-hwkey"),  // envelope v7 増分2
  unlock: document.getElementById("view-unlock"),
  vault: document.getElementById("view-vault"),
  recoveryShow: document.getElementById("view-recovery-show"),
  restore: document.getElementById("view-restore"),
  deviceAddRedeem: document.getElementById("view-device-add-redeem"),  // Phase 7.1-AG
};
// Phase 7.0w-U: パスワード入力欄に表示/非表示トグル (👁) を全自動付加。
// 全 <input type="password"> を <div.pw-wrap> に内包し、右端に目アイコンを置く。
// ロック解除・初期登録・Recovery 入力等、全 password 入力が対象。
// 既に attach 済の input は重複処理しない (data-pw-toggle-attached マーカー)。
const _EYE_OPEN_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>';
const _EYE_CLOSED_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-10-7-10-7a18.45 18.45 0 0 1 3.21-4.79"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 10 7 10 7a18.5 18.5 0 0 1-2.16 3.19"/><path d="m1 1 22 22"/></svg>';

function attachPasswordToggles(root = document) {
  const inputs = root.querySelectorAll('input[type="password"]:not([data-pw-toggle-attached])');
  inputs.forEach((input) => {
    input.setAttribute("data-pw-toggle-attached", "1");

    // input が既に .pw-wrap に内包されていなければラップする
    let wrap = input.parentElement;
    if (!wrap || !wrap.classList.contains("pw-wrap")) {
      wrap = document.createElement("div");
      wrap.className = "pw-wrap";
      // Phase 7.0w-X: inline style で確実に適用 (CSS specificity 問題回避)
      wrap.style.cssText = "position:relative; display:block; width:100%;";
      input.parentNode.insertBefore(wrap, input);
      wrap.appendChild(input);
    }

    // Phase 7.0w-X: input の右 padding を inline style で強制 (auth-card の :not() に負けないため)
    input.style.paddingRight = "48px";

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "pw-toggle";
    btn.tabIndex = -1;  // tab 移動を阻害しない
    btn.setAttribute("aria-label", i18n_t("app.password.toggle_show"));
    btn.innerHTML = _EYE_CLOSED_SVG;
    // Phase 7.0w-X: inline style で確実に表示 (Android Chrome で CSS が効かない事象への対応)
    btn.style.cssText =
      "position:absolute; right:6px; top:50%; transform:translateY(-50%); " +
      "z-index:10; background:transparent; border:none; cursor:pointer; " +
      "padding:6px; color:#475569; border-radius:4px; " +
      "width:36px; height:36px; line-height:0; " +
      "display:inline-flex; align-items:center; justify-content:center;";

    btn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      const isHidden = input.type === "password";
      input.type = isHidden ? "text" : "password";
      btn.innerHTML = isHidden ? _EYE_OPEN_SVG : _EYE_CLOSED_SVG;
      btn.setAttribute(
        "aria-label",
        isHidden ? i18n_t("app.password.toggle_hide") : i18n_t("app.password.toggle_show")
      );
    });

    wrap.appendChild(btn);
  });
}

function showView(name) {
  for (const [n, el] of Object.entries(views)) el.classList.toggle("hidden", n !== name);
  // Phase 7.0w-U: view 切替のたびに新規 password input にトグル付加
  attachPasswordToggles();
  if (name === "vault") {
    // pricing.html から #purchase=<pack> で来ていた場合、unlock 完了で
    // vault 画面遷移したタイミングで即 Stripe Checkout に redirect させる。
    tryConsumePendingPurchase?.();
    // Phase 7.1-C: mode に応じて UI 要素を show / hide する (= async、 fire-and-forget)
    applyVaultModeUI().catch(e => console.warn("[mode-ui] error:", e?.message ?? e));
    // Phase 7.5: PWA Share Target で受信した URL/title を unlock 後に modal へ prefill
    setTimeout(() => { try { window._maybeApplyShareData?.(); } catch {} }, 100);
  }
  // Phase 6.8.40: Turnstile は signup view (create) 表示時のみ lazy load。
  // unlock 中など他 view では Turnstile 関連の inline script / PAT challenge /
  // challenges.cloudflare.com の network 通信を一切起こさない。
  // Phase 6.8.40 / 6.8.42: signup view 表示時のみ Turnstile widget を起動。
  // 他 view に遷移する時は widget を完全破棄 → iframe / worker / PAT challenge 停止。
  if (name === "create" || name === "create-hwkey") {
    _initTurnstileSiteKey?.();
  } else {
    _destroyTurnstile?.();
  }
}

// =====================================================================
// Phase 7.1-G: Business mode signup helper — corp/join + Recovery deposit
// =====================================================================
//
// 招待コード経由で createVault した直後に呼ぶ:
//   1. corpJoinUI(code) — server に「この公開鍵を companyId に bind」
//   2. corpInfoUI() — admin の公開鍵 (b64u 65-byte uncompressed P-256) を取得
//   3. eciesEncrypt(adminPubKey, Recovery 文字列) → ciphertext payload
//   4. corpRelaySendUI({ to: adminPkHash, kind: 'recovery-deposit', payload })
//
// 失敗時 (admin 公開鍵がまだ server に届いてない等) は throw、caller が toast 表示。
async function _businessJoinAndDeposit(inviteCode, recoverySecret) {
  // Phase 7.2-B (α): Recovery deposit (admin への relay) を廃止。
  //   corp/join のみ実行 (= server に「この公開鍵を slot に bind」)。
  //   Recovery は社員自身が encryptedRecovery として自分の vault に保管 (= Personal mode 同様)。
  const joinRes = await corpJoinUI(inviteCode);
  console.log("[business-mode] joined corp:", joinRes);

  // audit push のため info を先に取得しておく
  let infoRes;
  try { infoRes = await corpInfoUI(); } catch (e) { /* non-fatal */ }
  if (infoRes) state._corpInfo = infoRes;

  // audit: 社員 signup event を admin に通知 (= ECIES で admin に届く、 admin 側で複合)
  _auditPushEvent({ action: "employee-signed-up",
    details: { companyId: infoRes?.member?.companyId, slotId: joinRes?.slotId,
               displayName: _defaultPasskeyDisplayName() || "新社員" } }).catch(() => {});

  // Phase 7.2-B (α): Recovery purge は不要 (= 社員自身が自分の vault に encryptedRecovery として保管、
  //   admin に転送する経路自体が無くなった)。 後続の addCredentialOnThisDevice 等で session.recoveryMaterial が必要。
}

// =====================================================================
// Phase 7.1-C: Vault mode UI switch
// =====================================================================
//
// mode === "personal" → 既存通り (Recovery 表示メニュー / 購入 UI 表示)
// mode === "business" → Recovery 表示メニュー hide、購入 UI hide (admin が管理)
// mode === "admin"   → Recovery 表示メニュー 表示 (= admin 自身の Recovery)、
//                      tab-admin show、購入 UI 表示 (= admin が会社の支払担当)
async function applyVaultModeUI() {
  let mode = currentVaultMode();
  let inBusiness = mode === "business";
  let inAdmin    = mode === "admin";
  const inHwkey  = mode === "hwkey";   // envelope v7 増分2: YubiKey 専用 vault

  // Phase 7.1-W: 現 profile の kind / companyId を vault.mode に合わせて relabel
  //   (= "default" として migrate された profile が会社 vault なら kind="admin"/"corp" に更新)
  try {
    const profMod = await import("/lib/profiles.js?v=5ef6de24");
    const activeId = profMod.getActiveProfileId();
    if (activeId) {
      const v = currentVault();
      if (v?.mode) {
        const kind = v.mode === "admin" ? "admin" : v.mode === "business" ? "corp" : "personal";
        profMod.updateProfile(activeId, { kind, companyId: v.companyId || undefined });
      }
    }
  } catch (e) { /* non-fatal */ }

  // Phase 7.1-G.4: server-side corp membership も判定 (vault.mode が legacy で
  // "personal" のまま corp join した user を救済)。一度 cache する。
  if (!inBusiness && !inAdmin && !inHwkey && !state._corpInfoChecked) {
    state._corpInfoChecked = true;
    try {
      const info = await corpInfoUI();
      state._corpInfo = info;
      if (info?.member) {
        const isServerAdmin = !!info.member.isAdmin;
        if (isServerAdmin) {
          // server 側 admin → admin mode 扱い + vault に mode='admin' を self-heal
          mode = "admin"; inAdmin = true;
          const v = currentVault();
          let healed = false;
          if (v && v.mode !== "admin") { v.mode = "admin"; healed = true; }
          if (v && v.companyId !== info.member.companyId) {
            v.companyId = info.member.companyId; healed = true;
          }
          // Phase 7.1-P: employees / policy / additionalAdmins 配列を必ず初期化
          //   self-heal 経路で undefined のままだと _processRecoveryDeposits や
          //   admin 一覧 render が正しく動かない
          if (v && !Array.isArray(v.employees)) { v.employees = []; healed = true; }
          if (v && !Array.isArray(v.additionalAdmins)) { v.additionalAdmins = []; healed = true; }
          if (v && !v.policy) {
            v.policy = { allowEmployeePasswordChange: false, requireRotateOnEmployeeLeave: true };
            healed = true;
          }
          if (healed) scheduleSave(v);
        } else {
          // server 側 employee → business mode 扱い + vault に mode='business' を self-heal
          mode = "business"; inBusiness = true;
          const v = currentVault();
          if (v && v.mode !== "business") {
            v.mode = "business";
            v.companyId = info.member.companyId;
            scheduleSave(v);
          }
        }
      }
    } catch (e) {
      console.warn("[mode-ui] corp/info check failed (non-fatal):", e?.message ?? e);
    }
  }

  // Tab-admin: admin mode のみ表示
  const tabAdmin = document.getElementById("tab-admin");
  if (tabAdmin) tabAdmin.classList.toggle("hidden", !inAdmin);

  // Phase 7.2-B (α): business mode でも社員自身が Recovery / Master を管理するので
  //   従来 hide していた menu を表示する (= Personal mode 同様)。
  // envelope v7 増分2: hwkey (YubiKey 専用) は Master も Recovery も持たないため、
  //   ローテーション系 / 端末一覧セクションをすべて隠す。
  //   (YubiKey の追加は sec-hwkey-devices セクションで対応。削除 UI は今後の増分。)
  for (const id of ["sec-show-recovery", "sec-pw", "sec-pk", "sec-incident", "sec-devices"]) {
    const el = document.getElementById(id);
    if (el) el.classList.toggle("hidden", inHwkey);
  }
  // hwkey 専用: 登録済み YubiKey セクションは hwkey モードでのみ表示。
  const hwkeyDevSec = document.getElementById("sec-hwkey-devices");
  if (hwkeyDevSec) hwkeyDevSec.classList.toggle("hidden", !inHwkey);
  // 設定モーダルの intro 文言を mode に合わせて差し替える。
  const settingsIntro = document.getElementById("settings-intro");
  if (settingsIntro) {
    const introKey = inHwkey ? "app.settings.intro_hwkey" : "app.settings.intro";
    settingsIntro.setAttribute("data-i18n", introKey);
    settingsIntro.textContent = i18n_t(introKey);
  }

  // 購入 UI: business mode で hide (会社が支払う、社員は購入不要)
  const buyBtns = document.querySelectorAll(
    ".purchase-pack-btn, #purchase-pack-btn, #pricing-link, .pricing-link"
  );
  buyBtns.forEach(b => b.classList.toggle("hidden", inBusiness));

  // Hint banner for business mode
  let banner = document.getElementById("business-mode-banner");
  if (inBusiness && !banner) {
    banner = document.createElement("div");
    banner.id = "business-mode-banner";
    banner.style.cssText = "background:#EFF6FF; border-left:3px solid #0EA5E9; padding:8px 12px; margin-bottom:12px; font-size:12px; color:#0C4A6E; border-radius:4px;";
    banner.innerHTML = `🏢 <strong>${i18n_t("app.business.mode_label") || "会社モード"}</strong>: ${i18n_t("app.business.banner_hint_alpha") || "会社ネットワーク内でのみ使えます。 Recovery は自分で安全に保管してください。"}`;
    const vaultView = document.getElementById("view-vault");
    if (vaultView) vaultView.insertBefore(banner, vaultView.firstChild);
  } else if (!inBusiness && banner) {
    banner.remove();
  }
}

// =====================================================================
// Toast
// =====================================================================
function toast(msg, type = "", durationMs = 3500) {
  const el = document.createElement("div");
  el.className = "toast " + type;
  el.textContent = msg;
  document.getElementById("toasts").appendChild(el);
  setTimeout(() => el.remove(), durationMs);
}

// =====================================================================
// Phase 6.7: Save status badge — debounce 中の保存状態を header に表示
// =====================================================================
function updateSaveStatusBadge(saveState, info = {}) {
  let el = document.getElementById("save-status-badge");
  if (!el) {
    // Phase 7.4: header 3 行レイアウト化により #header-meta は廃止。
    //   保存 badge は行2 wrapper (#header-status-row) に append。 #header-account
    //   (= TX 状態) の sibling になるので refreshHeader の innerHTML 書換えで
    //   消えない。 CSS (margin-left:auto) で行2 右端に寄せる。
    const target = document.getElementById("header-status-row")
                || document.querySelector("header.top")
                || document.querySelector("header");
    if (!target) return;
    el = document.createElement("span");
    el.id = "save-status-badge";
    el.style.cssText = "margin-left:8px;font-size:11px;padding:2px 8px;border-radius:8px;color:#fff;display:inline-block;vertical-align:middle;transition:background 0.2s,opacity 0.3s;";
    // Phase 6.7-7: dirty / error 時に badge クリックで即時 flush / 再試行を発火。
    // CSP 上 inline onclick は不可だが element.onclick = func は OK (function reference)。
    el.addEventListener("click", () => {
      const status = getSaveStatus();
      if (status.state === "dirty") {
        flushSaveDebounce().catch(() => {});
      } else if (status.state === "error") {
        // Phase 6.8.25: 残高不足エラーの場合は purchase modal を開く (re-try してもまた 402)
        const err = status.error;
        if (err?.code === "insufficient_credits" || err?.status === 402) {
          if (typeof window.openPurchasePackModal === "function") {
            window.openPurchasePackModal();
          }
        } else {
          flushSaveDebounce().catch(() => {});
        }
      }
    });
    target.appendChild(el);
  }
  switch (saveState) {
    case "dirty": {
      // Phase 6.7-7: 5 分 debounce、クリックで即時保存可能であることを明示。
      el.textContent = i18n_t("app.save_status.dirty");
      el.style.background = "#F59E0B";
      el.style.cursor = "pointer";
      el.style.opacity = "1";
      el.title = i18n_t("app.save_status.dirty_tooltip");
      break;
    }
    case "saving":
      el.textContent = i18n_t("app.save_status.saving");
      el.style.background = "#0EA5E9";
      el.style.cursor = "default";
      el.style.opacity = "1";
      el.title = i18n_t("app.save_status.saving_tooltip");
      break;
    case "saved": {
      // Phase 6.8: info?.credits is the new estimatedWrites (Math.ceil) returned
      // from /api/write — server-side account is sanitized so UI sees write counts only.
      const credits = info?.credits;
      el.textContent = (typeof credits === "number")
        ? i18n_t("app.save_status.saved_with_credits", { credits })
        : i18n_t("app.save_status.saved");
      el.style.background = "#10B981";
      el.style.cursor = "default";
      el.style.opacity = "1";
      el.title = i18n_t("app.save_status.saved_tooltip");
      // Sync state.credits + latestTxId from this real save
      if (typeof credits === "number") state.credits = credits;
      if (info?.txid) state.latestTxId = info.txid;
      // Auto-fade after 4 seconds when idle
      setTimeout(() => {
        if (el && el.textContent.startsWith("✓")) el.style.opacity = "0";
      }, 4000);
      // Refresh header (credits display)
      if (typeof refreshHeader === "function") refreshHeader().catch(() => {});
      // Phase 7.x: 保存完了でサイズが変わるので capacity banner を再評価。
      renderVaultCapacityBanner();
      break;
    }
    case "error": {
      // Phase 6.8.25: 402 insufficient_credits を専用表示にする
      const err = info?.error;
      const isOutOfBalance = err?.code === "insufficient_credits" || err?.status === 402;
      if (isOutOfBalance) {
        el.textContent = i18n_t("app.save_status.error_balance");
        el.title = i18n_t("app.save_status.error_balance_tooltip");
      } else {
        el.textContent = i18n_t("app.save_status.error");
        el.title = i18n_t("app.save_status.error_tooltip");
      }
      el.style.background = "#DC2626";
      el.style.cursor = "pointer";
      el.style.opacity = "1";
      break;
    }
    case "conflict": {
      // Phase 7.1-O: 楽観ロック 409 — UI modal で解決させる
      el.textContent = i18n_t("app.save_status.conflict") || "⚠ 競合";
      el.title = i18n_t("app.save_status.conflict_tooltip") || "サーバの内容と差分あり (クリックで解決)";
      el.style.background = "#F59E0B";
      el.style.cursor = "pointer";
      el.style.opacity = "1";
      _openVersionConflictModal();  // 自動表示
      break;
    }
    case "idle":
    default:
      el.style.opacity = "0";
      break;
  }
}

// =====================================================================
// Phase 7.1-O: 409 version-conflict resolution modal
// =====================================================================
function _openVersionConflictModal() {
  const bg = document.getElementById("version-conflict-bg");
  if (!bg) return;
  bg.classList.remove("hidden");
  const status = document.getElementById("version-conflict-status");
  if (status) status.textContent = "";
}
function _closeVersionConflictModal() {
  const bg = document.getElementById("version-conflict-bg");
  if (bg) bg.classList.add("hidden");
}

document.getElementById("vc-cancel-btn")?.addEventListener("click", () => {
  resolveConflictCancel();
  _closeVersionConflictModal();
  toast(i18n_t("app.version_conflict.toast_cancelled") || "キャンセルしました。編集状態を維持しています。", "info", 4000);
});

document.getElementById("vc-reload-btn")?.addEventListener("click", async () => {
  const btn = document.getElementById("vc-reload-btn");
  const status = document.getElementById("version-conflict-status");
  btn.disabled = true;
  if (status) status.textContent = i18n_t("app.version_conflict.status_reloading") || "サーバの最新を取得中…";
  try {
    const r = await refreshFromServerLatest();
    if (r?.refreshed) {
      // session の vault は client-side で更新済 → UI 反映
      state.vault = r.vault;
      state.latestTxId = r.latestTxId;
      // ローカルの編集は破棄
      resolveConflictDiscardLocal();
      renderList();
      _closeVersionConflictModal();
      toast(i18n_t("app.version_conflict.toast_reloaded") || "✅ サーバの最新を読み込みました", "ok", 5000);
    } else {
      // refreshed=false (= server に新しい vault tx が無い、または同じ txid)
      // → conflict は別原因 (= server 側の corrupted state など)。
      //   このまま「上書き保存」を推奨するメッセージに切替
      if (status) status.textContent = i18n_t("app.version_conflict.status_no_newer") ||
        "サーバ側に新しい vault は見つかりませんでした。「このデバイスで上書き保存」を選んでください。";
    }
  } catch (e) {
    if (status) status.textContent = (i18n_t("app.version_conflict.status_reload_failed") ||
      "読込に失敗: ") + (e?.message || String(e));
  } finally {
    btn.disabled = false;
  }
});

document.getElementById("vc-overwrite-btn")?.addEventListener("click", async () => {
  const btn = document.getElementById("vc-overwrite-btn");
  const status = document.getElementById("version-conflict-status");
  btn.disabled = true;
  if (status) status.textContent = i18n_t("app.version_conflict.status_overwriting") || "上書き保存中…";
  try {
    const r = await resolveConflictOverwrite();
    if (r?.ok) {
      _closeVersionConflictModal();
      toast(i18n_t("app.version_conflict.toast_overwritten") || "✅ 上書き保存しました", "ok", 5000);
    } else {
      if (status) status.textContent = (i18n_t("app.version_conflict.status_overwrite_failed") ||
        "上書き失敗: ") + (r?.error?.message || "unknown");
    }
  } catch (e) {
    if (status) status.textContent = (i18n_t("app.version_conflict.status_overwrite_failed") ||
      "上書き失敗: ") + (e?.message || String(e));
  } finally {
    btn.disabled = false;
  }
});

// =====================================================================
// Password strength meter
// =====================================================================
function renderStrength(elId, pw) {
  const el = document.getElementById(elId);
  const s = passwordStrength(pw);
  const pct = [0, 25, 50, 75, 100][s];
  const color = ["", "#DC2626", "#F59E0B", "#65A30D", "#10B981"][s];
  el.style.width = `${pct}%`;
  el.style.background = color;
}

// =====================================================================
// Create Vault flow
// =====================================================================
document.getElementById("create-pw").addEventListener("input", (e) => renderStrength("create-strength", e.target.value));

// v4.1: Passkey + WebAuthn PRF is mandatory. Block the entire signup flow
// when the environment doesn't support it, so the user doesn't get a
// half-finished registration that can't proceed past the PRF check during
// the Passkey ceremony.
(function initPasskeyAvailability() {
  const supported = isPasskeySupported() && isSecureContextOk() && isPRFCapable();
  if (!supported) {
    document.getElementById("passkey-unavailable")?.classList.remove("hidden");
    const createBtn = document.getElementById("create-btn");
    if (createBtn) {
      createBtn.disabled = true;
      createBtn.title = i18n_t("app.error.passkey_unsupported_signup");
      createBtn.style.opacity = "0.5";
      createBtn.style.cursor = "not-allowed";
    }
    // Disable the input fields too so the user doesn't waste time typing.
    for (const id of ["create-pw", "create-pw2"]) {
      const el = document.getElementById(id);
      if (el) { el.disabled = true; el.placeholder = i18n_t("app.error.use_supported_device"); }
    }
  }
})();

// Phase 6.7-3 / 6.8.42: Cloudflare Turnstile state — explicit render + destroy 対応。
// token は signup 時に backend へ送る。signup view を離れたら widget を破棄して
// PAT challenge / iframe / worker を完全停止 (console noise 防止)。
let _turnstileToken = null;
let _turnstileWidgetId = null;
let _turnstileScriptLoaded = false;
let _turnstileCurrentContainerId = null;  // Phase 7.5k: widget が今 render されている container id
window.arpassTurnstileCallback = (token) => { _turnstileToken = token; };
window.arpassTurnstileError = () => { _turnstileToken = null; };
window.arpassTurnstileExpired = () => { _turnstileToken = null; };

// Phase 6.8.42: explicit render mode に変更。
// 旧 (auto-render) では widget が一度 render されると iframe/worker が残り続けて
// signup view を離れても challenge の通信と CSP error 警告が継続していた。
// explicit mode で widgetId を保持 → showView() で create 以外に遷移時に
// _destroyTurnstile() で完全破棄 → 即座に noise 停止。
//
// meta タグの sitekey が空なら Turnstile 完全無効化 (dev/staging 互換)。
function _initTurnstileSiteKey() {
  const meta = document.querySelector('meta[name="turnstile-sitekey"]');
  const siteKey = meta?.getAttribute("content")?.trim();
  // Phase 7.5j: hwkey signup view にも Turnstile widget 追加。 active な view の
  //   container を選ぶ (= 非 hidden ancestor を持つ方)。
  const containers = [
    document.querySelector("#turnstile-container"),
    document.querySelector("#hwkey-turnstile-container"),
  ].filter(Boolean);
  const container = containers.find((c) => {
    let el = c;
    while (el) {
      if (el.classList?.contains("hidden")) return false;
      el = el.parentElement;
    }
    return true;
  }) || containers[0];
  if (!siteKey) {
    containers.forEach((c) => c.remove());
    return;
  }

  // Phase 7.5k: widget が既に render 済みで、 かつ container が変わってない (= 同じ view 再表示)
  //   なら reset で challenge 更新するだけ。 container が変わっていたら (例: create → create-hwkey
  //   遷移) widget を destroy して新 container に re-render する。
  if (_turnstileWidgetId !== null && window.turnstile) {
    if (_turnstileCurrentContainerId === container?.id) {
      try { window.turnstile.reset(_turnstileWidgetId); } catch {}
      return;
    }
    // container が変わった → 古い widget を destroy して fall through で re-render
    try { window.turnstile.remove(_turnstileWidgetId); } catch {}
    _turnstileWidgetId = null;
    _turnstileToken = null;
  }

  // 初回: api.js を explicit render mode で load (?render=explicit)
  if (!_turnstileScriptLoaded) {
    _turnstileScriptLoaded = true;
    window.arpassTurnstileOnload = () => _renderTurnstile(siteKey, container);
    const script = document.createElement("script");
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?onload=arpassTurnstileOnload&render=explicit";
    script.async = true;
    script.defer = true;
    document.head.appendChild(script);
    return;
  }

  // 2 回目以降 (script 既 load 済 + widget 未 render = destroy 後の再表示) → 直接 render
  _renderTurnstile(siteKey, container);
}

function _renderTurnstile(siteKey, container) {
  if (!window.turnstile || !container) return;
  const widget = container.querySelector(".cf-turnstile");
  if (!widget) return;
  try {
    _turnstileWidgetId = window.turnstile.render(widget, {
      sitekey: siteKey,
      callback: window.arpassTurnstileCallback,
      "error-callback": window.arpassTurnstileError,
      "expired-callback": window.arpassTurnstileExpired,
      theme: "light",
      appearance: "always",  // Phase 7.5i: iPhone Safari で widget 非表示が token 取得失敗を起こすため常時表示に変更
      // Phase 7.5ZD: arpass UI 言語を Turnstile に渡す (= OS/ブラウザ言語ではなく arpass 設定に追従)
      //   Cloudflare Turnstile 対応コード: ar, bg, cs, da, de, el, en, es, fa, fi, fr,
      //     hi, hu, id, it, ja, ko, nl, no, pl, pt-BR, ro, ru, sk, sl, sv, th, tl, tr,
      //     uk, vi, zh-cn, zh-tw (小文字)
      //   arpass の 16 言語 中、 zh-CN / zh-TW のみ大文字小文字を変換。 他は完全一致。
      language: (() => {
        const al = (i18n_getLang() || "en").toLowerCase();
        // arpass の "zh-CN" → "zh-cn"、 "pt-BR" → "pt-br"
        return al;
      })(),
    });
    _turnstileCurrentContainerId = container.id;  // Phase 7.5k: view 切替検知用
  } catch (e) {
    console.warn("[turnstile] render failed:", e?.message);
  }
}

// Phase 6.8.42: signup view を離れた時に呼ばれる。widget + iframe + worker を破棄。
function _destroyTurnstile() {
  if (_turnstileWidgetId !== null && window.turnstile) {
    try { window.turnstile.remove(_turnstileWidgetId); }
    catch (e) { console.warn("[turnstile] remove failed:", e?.message); }
    _turnstileWidgetId = null;
    _turnstileToken = null;
    _turnstileCurrentContainerId = null;  // Phase 7.5k
  }
}
// Phase 6.8.40: page init での即時 init を撤去。
// showView("create") (= signup view 表示) で lazy init する。
// 他 view (unlock / vault 等) では Turnstile を一切 load しない。
// _initTurnstileSiteKey();

document.getElementById("create-btn").addEventListener("click", async () => {
  const pw  = document.getElementById("create-pw").value;
  const pw2 = document.getElementById("create-pw2").value;
  const err = document.getElementById("create-error");
  err.classList.add("hidden");
  // envelope v7: Master 最低長 8 文字ルールを撤廃 (短い Master も可。docs/envelope-v7-spec.md §10)。
  //   空のみ不可 — 空にすると 2-of-3 の w.a が Recovery 単独扉に縮退するため。
  if (!pw) {
    err.textContent = i18n_t("app.error.master_required");
    err.classList.remove("hidden");
    return;
  }
  if (pw !== pw2) {
    err.textContent = i18n_t("app.error.passwords_not_match");
    err.classList.remove("hidden");
    return;
  }
  const btn = document.getElementById("create-btn");
  btn.disabled = true;
  // Phase 6.7-12: ここで innerHTML を直接書いていた日本語ハードコードを i18n 化。
  btn.innerHTML = `<span class="spin"></span> ${i18n_t("app.button.passkey_registering")}`;
  // Phase 7.1-W hotfix (2026-06-06): 補完 createProfile した profile id を catch から
  //   見るため try 外に宣言。 createVault 失敗時に deleteProfile で rollback する。
  let _createdProfileIdForRollback = null;
  try {
    // v5: createVault(password, displayName, captchaToken, opts)
    //   → captchaToken は env (TURNSTILE_SITE_KEY/SECRET_KEY) 設定時のみ必要、
    //      未設定 dev/staging では null でも server 側 skip される。
    // Phase 7.1-G: 招待 URL があれば mode="business" で createVault
    // Phase 7.1-W: createVault は readMeta/writeMeta を呼ぶので必ず active profile が
    //   設定されている必要がある。picker 経由なら既に active 済だが、URL 直叩きや
    //   完全新規の場合は前段の routing で profile が未作成のため、ここで補完作成する。
    {
      const profMod = await import("/lib/profiles.js?v=5ef6de24");
      if (!profMod.getActiveProfileId()) {
        const kind = _inviteCode ? "corp" : "personal";
        const prof = profMod.createProfile({ kind, label: kind === "corp" ? "会社 (作成中)" : "個人" });
        profMod.setActiveProfileId(prof.id);
        _createdProfileIdForRollback = prof.id;
      }
    }
    const displayName = _defaultPasskeyDisplayName();
    // Phase 7.2-B (α): business mode は encryptVaultBusiness が companyId を要する
    // ので、 createVault 前に lookup-code で resolve しておく。
    let createOpts = {};
    if (_inviteCode) {
      try {
        const lookupRes = await fetch("/api/corp/lookup-code?code=" + encodeURIComponent(_inviteCode));
        const lookupJ = await lookupRes.json().catch(() => ({}));
        if (!lookupRes.ok || !lookupJ.ok) {
          throw new Error(lookupJ.error || "invite code not found");
        }
        // Phase 7.2-B v2.6 hotfix: 招待コード経由の signup は必ず member。
        //   member は K1 を持たないため、 placeholder (ZERO_K1) で envelope を作り、
        //   admin の K1 配布後に tryTransitionFromPending で実 K1 に置換する。
        //   この k1Pending=true 指定がないと encryptVaultBusiness が random K1 を生成し、
        //   admin が配る K1 (= 別値) で復号できない致命的バグになる。
        // Phase 7.2-B/D hotfix (2026-06-05): inviteCode も createVault 経由で writeEnvelope に渡す。
        //   server 側で未 member 時の atomic 登録に使う。
        createOpts = { mode: "business", companyId: lookupJ.companyId, k1Pending: true, inviteCode: _inviteCode };
      } catch (lookupErr) {
        toast("招待コードの会社情報が取得できません: " + (lookupErr?.message || lookupErr), "error", 14000);
        return;
      }
    }
    const { vault, latestTxId, recoverySecret } = await createVault(pw, displayName, _turnstileToken, createOpts);
    // Phase 7.1-W: signup 完了 → profile metadata を vault.mode に合わせて更新
    try {
      const profMod = await import("/lib/profiles.js?v=5ef6de24");
      const activeId = profMod.getActiveProfileId();
      if (activeId) {
        const kind = (vault?.mode === "admin") ? "admin"
                   : (vault?.mode === "business") ? "corp"
                   : "personal";
        profMod.updateProfile(activeId, { kind, companyId: vault?.companyId || undefined });
      }
    } catch (e) { console.warn("[profile] post-signup relabel failed:", e?.message); }
    state.password = pw;
    state.vault = vault;
    state.latestTxId = latestTxId;
    await refreshHeader();
    renderList();

    // Phase 7.1-G: 招待コード経由なら corp/join + recovery deposit
    let businessDepositOk = false;
    if (_inviteCode && recoverySecret) {
      try {
        await _businessJoinAndDeposit(_inviteCode, recoverySecret);
        businessDepositOk = true;
      } catch (joinErr) {
        console.error("[business-mode] join+deposit failed:", joinErr);
        toast((i18n_t("app.business.toast.join_failed") || "会社への参加または Recovery 送信に失敗: ") + joinErr.message, "error", 14000);
        // business mode は Recovery を社員に見せない仕様なので、deposit 失敗時も
        // 画面に出さない。エラー toast を出して vault 画面に進める (admin が再招待
        // → 新規 signup で再試行する flow)。
      }
    }

    // Phase 7.1-AB: business signup (= _inviteCode あり) では Recovery 文字列を
    // 社員に絶対表示しない (admin が一元管理する設計)。deposit が成功していれば
    // admin に Recovery 預け入れ済、失敗ならエラー toast で通知済。いずれにせよ
    // vault は Arweave に書込済なので vault 画面に進める。
    if (_inviteCode) {
      // Phase 7.2-B (α): business signup でも Recovery を社員に表示する
      //   (= 旧 design は deposit で admin に送って隠していたが、 α では社員自身が保管)
      document.getElementById("invite-banner")?.remove();
      _inviteCode = null;
      _applyBusinessSignupUI();
      if (businessDepositOk) {
        toast(i18n_t("app.business.toast.signup_complete") ||
              "✅ 会社の Vault を作成しました。 Recovery を必ず保管してください。",
              "ok", 8000);
      }
      // Personal mode と同じ Recovery 表示フローへ
      if (recoverySecret) {
        document.getElementById("rs-box").textContent = recoverySecret;
        document.getElementById("rs-qr").innerHTML = generateQrSvg(recoverySecret);
        document.getElementById("rs-confirm").checked = false;
        document.getElementById("rs-continue").disabled = true;
        showView("recoveryShow");
      } else {
        initSaveDebounce({
          saveVault,
          onStatus: (state, info) => updateSaveStatusBadge(state, info),
          beforeUnloadMessage: i18n_t("app.confirm.beforeunload_unsaved"),
        });
        showView("vault");
      }
    } else if (recoverySecret) {
      // Personal/Admin: ONE TIME Recovery 表示画面
      document.getElementById("rs-box").textContent = recoverySecret;
      document.getElementById("rs-qr").innerHTML = generateQrSvg(recoverySecret);
      document.getElementById("rs-confirm").checked = false;
      document.getElementById("rs-continue").disabled = true;
      toast(i18n_t("app.toast.vault_created_3fa"), "ok");
      showView("recoveryShow");
    } else {
      // v4.1: createVault は必ず Recovery Secret を返すべき (Passkey 必須化済み)。
      // ここに来た場合は何かが想定外なので、念のため vault 画面に進めつつ警告。
      console.warn("createVault did not return a Recovery Secret — unexpected post-v4.1");
      // Phase 6.7-9: ここでも initSaveDebounce 必要 (rs-continue 経由しないため)
      initSaveDebounce({
        saveVault,
        onStatus: (state, info) => updateSaveStatusBadge(state, info),
      beforeUnloadMessage: i18n_t("app.confirm.beforeunload_unsaved"),
      });
      toast(i18n_t("app.toast.vault_created"), "ok");
      showView("vault");
    }
  } catch (e) {
    err.textContent = i18n_t("app.toast.creation_failed", { reason: e.message });
    err.classList.remove("hidden");
    // Phase 7.1-W hotfix (2026-06-06): 補完 createProfile した直後に createVault が失敗した場合、
    //   picker に空 profile が残らないよう rollback (= deleteProfile + clearActive)。
    if (_createdProfileIdForRollback) {
      try {
        const profMod = await import("/lib/profiles.js?v=5ef6de24");
        profMod.deleteProfile(_createdProfileIdForRollback);
        console.warn("[create] rolled back failed-signup profile:", _createdProfileIdForRollback);
      } catch (rbErr) {
        console.warn("[create] rollback failed:", rbErr?.message);
      }
    }
  } finally {
    btn.disabled = false;
    btn.textContent = i18n_t("app.button.create_vault_short");
  }
});

// Recovery Secret display screen: copy / print / confirm handlers
document.getElementById("rs-confirm")?.addEventListener("change", (e) => {
  document.getElementById("rs-continue").disabled = !e.target.checked;
});
document.getElementById("rs-copy")?.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(document.getElementById("rs-box").textContent);
    toast(i18n_t("app.toast.copied"), "ok");
  } catch {
    toast(i18n_t("app.toast.clipboard_access_denied"), "err");
  }
});
document.getElementById("rs-print")?.addEventListener("click", () => {
  const code = document.getElementById("rs-box").textContent;
  if (!code) { toast(i18n_t("app.toast.no_recovery_shown"), "err"); return; }
  printEmergencyKit(code);
});

// Phase 7.5ZV: 「後で印刷する」 — user に reminder を示唆して checkbox を有効化
document.getElementById("rs-print-later")?.addEventListener("click", () => {
  toast(i18n_t("app.recovery.toast_print_later") ||
        "後で印刷を忘れずに。 紙保管が最も安全です。", "ok", 6000);
  // checkbox は手動 check のままで OK (= user の意思確認)
});

// Phase 7.5ZV/ZY: 「画像で保存」 — Recovery Secret + QR を 1 枚の PNG にして
//   モバイル: Web Share API (= Save to Photos 等の共有シート)
//   PC:      ダウンロード (= ユーザが任意の場所に保存可能)
// Phase 7.5ZY: PC でも確実に動くよう、 mobile 判定で経路を分ける。
function _isMobileLike() {
  try {
    // 1) Pointer 入力が coarse (= タッチ) なら mobile 想定
    if (window.matchMedia && window.matchMedia("(pointer: coarse)").matches) return true;
    // 2) UA-CH の mobile signal
    if (navigator.userAgentData && navigator.userAgentData.mobile) return true;
    // 3) UA 文字列 fallback
    const ua = navigator.userAgent || "";
    return /Mobi|Android|iPhone|iPad|iPod/i.test(ua);
  } catch (_) {
    return false;
  }
}

document.getElementById("rs-save-image")?.addEventListener("click", async () => {
  const code = document.getElementById("rs-box").textContent;
  if (!code) { toast(i18n_t("app.toast.no_recovery_shown"), "err"); return; }
  try {
    const pngBlob = await renderRecoveryAsPng(code);
    const file = new File([pngBlob], "arpass-recovery.png", { type: "image/png" });

    // Phase 7.5ZY: mobile かつ Web Share API + files 対応なら共有シート優先
    const mobile = _isMobileLike();
    const canShareFiles = !!(navigator.canShare && navigator.canShare({ files: [file] }));

    if (mobile && canShareFiles) {
      try {
        await navigator.share({
          files: [file],
          title: "Arpass Recovery Secret",
          text: "Arpass Recovery Secret — 安全な場所に保管してください",
        });
        toast(i18n_t("app.recovery.toast_image_shared") ||
              "保存しました。 E2E 暗号化を有効にしてください。", "ok", 6000);
        return;
      } catch (e) {
        if (e?.name === "AbortError") return; // user cancel
        console.warn("[recovery] navigator.share failed, fallback to download:", e?.message ?? e);
        // fallthrough to download
      }
    }

    // PC または share API 失敗時: 通常のダウンロード
    const url = URL.createObjectURL(pngBlob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "arpass-recovery.png";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast(i18n_t("app.recovery.toast_image_downloaded") ||
          "画像をダウンロードしました。 安全な場所に保管してください。", "ok", 6000);
  } catch (e) {
    console.error("[recovery] save-image failed:", e);
    toast((i18n_t("app.recovery.toast_image_failed") || "画像保存に失敗しました") +
          ": " + (e?.message ?? e), "err");
  }
});

// Phase 7.5ZV: Recovery Secret + QR を 1 枚の PNG (= 800x1000) にレンダリング
async function renderRecoveryAsPng(code) {
  const W = 800, H = 1000;
  const canvas = document.createElement("canvas");
  canvas.width = W;
  canvas.height = H;
  const ctx = canvas.getContext("2d");

  // 背景 (dark gradient)
  const grad = ctx.createLinearGradient(0, 0, 0, H);
  grad.addColorStop(0, "#1E1B4B");
  grad.addColorStop(1, "#312E81");
  ctx.fillStyle = grad;
  ctx.fillRect(0, 0, W, H);

  // ヘッダ
  ctx.fillStyle = "#FCD34D";
  ctx.font = "700 36px ui-sans-serif, -apple-system, sans-serif";
  ctx.textAlign = "center";
  ctx.fillText("🔐 Arpass Recovery Secret", W / 2, 70);

  ctx.fillStyle = "#E0E7FF";
  ctx.font = "16px ui-sans-serif, -apple-system, sans-serif";
  ctx.fillText("(arpass.io)", W / 2, 105);

  // QR コード描画 (= existing drawQrOnCanvas を使う)
  const qrCanvas = document.createElement("canvas");
  // drawQrOnCanvas は qr.js から import
  drawQrOnCanvas(qrCanvas, code, { width: 500, margin: 24, errorCorrectionLevel: "M" });
  // 中央配置: 500x500 QR を (150, 140) に
  // 背景白
  ctx.fillStyle = "#FFFFFF";
  ctx.fillRect(140, 130, 520, 520);
  ctx.drawImage(qrCanvas, 150, 140, 500, 500);

  // テキストコード
  ctx.fillStyle = "#FCD34D";
  ctx.font = "700 24px ui-monospace, 'SF Mono', Menlo, monospace";
  ctx.textAlign = "center";
  // 長すぎる場合 折り返し (= 8 chunks of 4)
  const chunks = code.match(/.{1,12}/g) || [code];
  const startY = 700;
  chunks.forEach((chunk, i) => {
    ctx.fillText(chunk, W / 2, startY + i * 36);
  });

  // フッタ注意
  ctx.fillStyle = "#FCA5A5";
  ctx.font = "14px ui-sans-serif, -apple-system, sans-serif";
  const footerY = startY + chunks.length * 36 + 40;
  ctx.fillText("⚠ Keep this safe. Cannot be re-displayed.", W / 2, footerY);
  ctx.fillText("⚠ E2E (Advanced Data Protection) must be ON.", W / 2, footerY + 22);

  return new Promise((resolve, reject) => {
    canvas.toBlob((blob) => {
      if (blob) resolve(blob);
      else reject(new Error("Failed to encode PNG"));
    }, "image/png");
  });
}
document.getElementById("rs-continue")?.addEventListener("click", () => {
  // Securely clear the code from DOM after user confirms.
  document.getElementById("rs-box").textContent = "";
  document.getElementById("rs-qr").innerHTML = "";
  // Print-only div も念のためクリア (window.print 後の残留対策)
  clearEmergencyKit();
  // Phase 6.7-9 critical: createVault 経路でも debounce を初期化する。
  // これがないと、新規作成直後にエントリ追加 → ロックすると、scheduleSave が
  // _saveImpl 未設定で空振り → lock-btn の flushSaveDebounce も pendingVault が
  // null で何もせず → 結果としてエントリが Arweave に書き込まれず消失。
  // Yamaki さん報告 (2026-05-06): 「2 回目からはちゃんと保存される」 = unlock 経路
  // (line ~709) で初期化されるからで、createVault 経路には抜け道があった。
  initSaveDebounce({
    saveVault,
    onStatus: (state, info) => updateSaveStatusBadge(state, info),
      beforeUnloadMessage: i18n_t("app.confirm.beforeunload_unsaved"),
  });
  showView("vault");
});

// =====================================================================
// Emergency Kit (印刷専用、画面非表示)
//   - PDF ライブラリは使わない (Downloads / iCloud 残留リスク回避)
//   - window.print() で OS 印刷ダイアログを叩き、ユーザーが
//     「紙に印刷」または「PDF として保存 (自己責任)」を選ぶ
//   - 印刷後は DOM からクリアして RAM 滞留を最小化
// =====================================================================
function renderEmergencyKitInline(recoverySecret) {
  // QR 生成 (Recovery 文字列のみ。メタデータは入れない=スキャナで用途を曝さない)
  const qrSvg = generateQrSvg(recoverySecret);
  document.getElementById("pek-qr").innerHTML = qrSvg;
  document.getElementById("pek-rs").textContent = recoverySecret;
  document.getElementById("pek-date").textContent =
    new Date().toISOString().slice(0, 10);
  // アカウント表示用に user 情報があれば入れる (なければ空)
  let acct = "";
  try {
    const id = readClientIdentity?.();
    if (id?.email) acct = id.email;
  } catch {}
  document.getElementById("pek-account").textContent = acct || "(non-identified)";
}

function clearEmergencyKit() {
  document.getElementById("pek-qr").innerHTML = "";
  document.getElementById("pek-rs").textContent = "";
  document.getElementById("pek-date").textContent = "";
  document.getElementById("pek-account").textContent = "";
}

function printEmergencyKit(recoverySecret) {
  renderEmergencyKitInline(recoverySecret);
  // 描画完了を 1 frame 待ってから印刷ダイアログを開く
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      window.print();
      // 印刷ダイアログ閉じた後にクリーンアップ (ユーザーキャンセルでも実行)
      setTimeout(clearEmergencyKit, 500);
    });
  });
}

// =====================================================================
// Unlock flow
// =====================================================================
// Phase 5.3-J: 「別の Passkey で開錠する」リンクを押すと、次回 unlock
// 試行で hint をスキップしてピッカーを強制表示する。1 回限りのフラグ。
let _forcePickerNext = false;
document.getElementById("unlock-other-passkey-link")?.addEventListener("click", (e) => {
  e.preventDefault();
  _forcePickerNext = true;
  toast(i18n_t("app.toast.passkey_picker_next_unlock"), "info", 5000);
});

document.getElementById("unlock-btn").addEventListener("click", async () => {
  const isHwkey = readMeta()?.mode === "hwkey";
  const pw  = document.getElementById("unlock-pw").value;
  const err = document.getElementById("unlock-error");
  err.classList.add("hidden");
  // envelope v7 増分2: hwkey は discoverable 2 タップの共通フローに委譲する。
  //   specific get (meta.credentialId 名指し) は iPhone Safari で
  //   「資格情報が見つかりません」を出すため、 同一端末解錠も picker get を使う。
  if (isHwkey) {
    _hwkeyUnlockFlow(
      document.getElementById("unlock-btn"),
      err,
      i18n_t("app.unlock.btn_hwkey"),
    );
    return;
  }
  if (!isHwkey && !pw) return;
  const btn = document.getElementById("unlock-btn");
  btn.disabled = true;
  btn.innerHTML = `<span class="spin"></span> ${i18n_t("app.button.unlocking")}`;
  const usePicker = _forcePickerNext;
  _forcePickerNext = false;  // 1 回使ったら戻す
  try {
    // v5 Path AB: マスターパスワード + Passkey
    // Phase 7.0w-U: 自動 retry (Passkey picker 強制 open) を廃止。
    // passkey_wrong_for_vault は実態として「パスワード入力ミス」が大半なので、
    // 自動で別 Passkey を試すよりも、ユーザーに「まずパスワード確認 (👁)」を促す
    // ほうが直感的。別 Passkey を試したい場合は明示的に
    // 「🔄 別の Passkey で開錠する」リンクをクリックしてもらう設計。
    const unlockResult = isHwkey
      ? await unlockWithHwkey({ forcePicker: usePicker })
      : await unlockWithPasswordAndPasskey(pw, { forcePicker: usePicker });
    const { vault, latestTxId } = unlockResult;
    if (!isHwkey) state.password = pw;
    state.vault = vault;
    state.latestTxId = latestTxId;

    // outOfSync 検知 — v5 では unlock 直後の latestTxId と localStorage cache
    // の latestTxId を比較。差があれば「他端末で更新があった」サインなので
    // 警告 toast を出す。
    const cachedTxId = readMeta()?.latestTxId;
    let outOfSync = false, outOfSyncReason = null;
    if (cachedTxId && cachedTxId !== latestTxId) {
      outOfSync = true;
      outOfSyncReason = "newer_remote_tx";
      console.log(`[unlock] outOfSync detected: cached=${cachedTxId} remote=${latestTxId}`);
    }
    await refreshHeader();
    renderList();
    showView("vault");

    // Phase 6.7: 連続編集を bundle する debounce レイヤを初期化。
    // 30 秒の無操作で実 saveVault が走る。entry CRUD のみが scheduleSave を使い、
    // 端末追加 / Master 変更 / Recovery 再発行 等は従来通り即時 saveVault。
    initSaveDebounce({
      saveVault,
      onStatus: (state, info) => updateSaveStatusBadge(state, info),
      beforeUnloadMessage: i18n_t("app.confirm.beforeunload_unsaved"),
    });

    // Phase 5.3-D: 背景でサーバ latestTxId を検証し、別端末更新があれば
    // 自動 refetch + 再 render する。即時表示は犠牲にしない (背景処理)。
    refreshFromServerLatest()
      .then((r) => {
        if (r?.refreshed) {
          state.vault = r.vault;
          state.latestTxId = r.latestTxId;
          renderList();
          refreshHeader().catch(() => {});
          const delta = (r.entriesAfter ?? 0) - (r.entriesBefore ?? 0);
          const deltaStr = delta === 0 ? ""
                         : delta > 0  ? i18n_t("app.toast.delta_added", { delta })
                         :              i18n_t("app.toast.delta_removed", { delta });
          toast(
            i18n_t("app.toast.refreshed_with_delta", { delta: deltaStr }),
            "info", 8000
          );
        }
      })
      .catch((e) => {
        // 背景処理なので失敗は静かに log のみ。ユーザー操作を阻害しない。
        console.warn("[unlock] server-latest sync check failed:", e?.message ?? e);
      });

    if (outOfSync) {
      // Different message depending on WHY we couldn't load the latest:
      // - fetch_failed: temporary, retry helps
      // - wrap_missing: permanent, need re-restore
      const msg = outOfSyncReason === "newer_remote_tx"
        ? i18n_t("app.toast.vault_updated_other_device")
        : outOfSyncReason === "fetch_failed"
          ? i18n_t("app.toast.fetch_latest_failed")
          : outOfSyncReason === "wrap_missing"
            ? i18n_t("app.toast.outofsync_unregistered")
            : i18n_t("app.toast.data_may_be_stale");
      toast(msg, "warn", 12000);
    } else {
      toast(i18n_t("app.toast.entries_loaded", { count: vault.entries?.length ?? 0 }), "ok");
    }
  } catch (e) {
    // Phase 6.8.21: WebAuthn raw エラー (NotAllowedError 等) や
    // passkey_wrong_for_vault を親切なメッセージに変換。
    // どれにも該当しない予期せぬエラーは e.message を fallback で表示。
    let friendly;
    if (e?.code === "master_wrong") {
      // #161: envelope に この Passkey 用 wrap が在った = Passkey は登録済 (正しい)。
      //   不一致要素は Master のみ。 「別の Passkey で再試行」ではなく Master 再確認を促す。
      friendly = i18n_t("app.error.unlock_master_wrong");
      const pwInput = document.getElementById("unlock-pw");
      if (pwInput) { pwInput.focus(); pwInput.select(); }
    } else if (e?.code === "unlock_outer_failed_v7") {
      // envelope v7 (Master-wrap): outer 鍵が誤り — Master 取り違え、または別端末で
      //   Master を変更した後に古い Passkey を選んだ。下の「別の Passkey で開錠する」
      //   から新しい Passkey を選び、新しい Master を入力してもらう。
      friendly = i18n_t("app.error.unlock_outer_failed_v7");
      const pwInput = document.getElementById("unlock-pw");
      if (pwInput) { pwInput.focus(); pwInput.select(); }
    } else if (e?.code === "passkey_wrong_for_vault") {
      // Phase 7.0w-U: 自動 retry を廃止したので 1 回失敗で即この経路。
      // メッセージで「まずパスワード確認」を最優先誘導し、別 Passkey は副選択肢として残す。
      friendly = i18n_t("app.error.unlock_combo_mismatch");
      // パスワード入力欄を focus + 全選択して再入力しやすくする
      const pwInput = document.getElementById("unlock-pw");
      if (pwInput) { pwInput.focus(); pwInput.select(); }
    } else if (e?.name === "NotAllowedError") {
      // ユーザーがキャンセル / タイムアウト / 不適合な Passkey を選択
      friendly = i18n_t("app.error.passkey_cancelled");
    } else if (e?.name === "InvalidStateError") {
      friendly = i18n_t("app.error.passkey_invalid_state");
    } else if (e?.name === "SecurityError") {
      friendly = i18n_t("app.error.passkey_security");
    } else {
      // 予期せぬエラー: i18n された汎用メッセージ + 詳細を別行で
      const detail = e?.message || String(e);
      friendly = `${i18n_t("app.error.unlock_failed")} (${detail})`;
    }
    err.textContent = friendly;
    err.classList.remove("hidden");
    console.warn("[unlock] failed:", e?.name, e?.code, e?.message);
  } finally {
    btn.disabled = false;
    btn.textContent = isHwkey ? i18n_t("app.unlock.btn_hwkey") : i18n_t("app.button.unlock_short");
  }
});

document.getElementById("unlock-pw").addEventListener("keydown", (e) => {
  if (e.key === "Enter") document.getElementById("unlock-btn").click();
});

// Alternate unlock: Password + Recovery (Passkey lost / device change)
document.getElementById("unlock-pw-rs-btn")?.addEventListener("click", async () => {
  const pw = document.getElementById("unlock-pw").value;
  const rs = document.getElementById("recovery-input").value.trim();
  const err = document.getElementById("unlock-error");
  err.classList.add("hidden");
  if (!pw) { err.textContent = i18n_t("app.error.master_required"); err.classList.remove("hidden"); return; }
  if (!rs) { err.textContent = i18n_t("app.error.recovery_secret_required"); err.classList.remove("hidden"); return; }
  const btn = document.getElementById("unlock-pw-rs-btn");
  btn.disabled = true;
  const label = btn.textContent;
  btn.innerHTML = `<span class="spin"></span> ${i18n_t("app.button.recovering")}`;
  try {
    const { vault, latestTxId } = await unlockWithPasswordAndRecovery(pw, rs);
    state.password = pw;
    state.vault = vault;
    state.latestTxId = latestTxId;
    await refreshHeader();
    renderList();
    showView("vault");

    // Phase 7.0w-AI: Recovery 経路の unlock でも save-debounce を初期化する
    // (これが抜けていたため Recovery + Master / Recovery + Passkey で開いた
    //  ユーザーは編集バッジ非表示 + 保存不能の状態だった)
    initSaveDebounce({
      saveVault,
      onStatus: (s, info) => updateSaveStatusBadge(s, info),
      beforeUnloadMessage: i18n_t("app.confirm.beforeunload_unsaved"),
    });

    // Phase 7.0w-AJ: Recovery で解錠したユーザーには Passkey 自動再登録の機会を提示。
    // 紙の Recovery にアクセスできた = 本人確認済の証拠なので、Passkey 再登録の
    // 最適タイミング。yes なら addCredentialOnThisDevice を実行 → 次回からは
    // Master + Passkey (wrap_pk) で楽に開錠可能になる。
    if (window.confirm(i18n_t("app.confirm.add_passkey_after_recovery"))) {
      // Phase 7.0w-AJ.1 hotfix: addCredentialOnThisDevice の前に pre-sync を行う。
      // unlockWithPasswordAndRecovery は GraphQL findLatestVaultTx で envelope を
      // 取りに行くが、bundling lag で古い tx を返すことがある (restore-btn と同じ症状)。
      // ここで sync しないと wrap_pk 追加 → saveVault → 楽観ロック 409 で失敗する。
      try {
        const r = await refreshFromServerLatest();
        if (r?.refreshed) {
          state.vault = r.vault;
          state.latestTxId = r.latestTxId;
        }
      } catch (syncErr) {
        console.warn("[unlock-AC] pre-passkey-add sync failed (continuing):", syncErr?.message ?? syncErr);
        // best-effort: 409 が出たら下の catch でユーザーに伝える
      }
      // Phase 7.0w-AM.1: deferSave で「Passkey credential は OS Keychain に登録するが、
      // Arweave 書込は遅延」させる。続けてエントリ追加するユーザーの操作とまとめて
      // 1 回の save に bundle されるよう、scheduleSave で dirty 状態 (= 編集バッジ
      // '未保存' 表示) を立てる。
      // ユーザーが明示的にバッジクリックするかロック時の flush で実際の write が走る。
      try {
        await addCredentialOnThisDevice(pw, _defaultPasskeyDisplayName(), { deferSave: true });
        scheduleSave(state.vault);  // 編集バッジを 'dirty (未保存)' に
        toast(i18n_t("app.toast.passkey_registered_new"), "ok");
      } catch (passkeyErr) {
        console.warn("[unlock-AC] passkey add after recovery failed:", passkeyErr);
        toast(i18n_t("app.toast.unlock_ok_passkey_failed"), "warn", 8000);
      }
    }

    // Phase 5.3-F: Recovery 経路は GraphQL findLatestVaultTx 由来の古い tx
    // を返すことがあるため、サーバ side の真の latestTxId と照合して必要なら
    // refetch する。Path A と同じ背景処理。
    refreshFromServerLatest()
      .then((r) => {
        if (r?.refreshed) {
          state.vault = r.vault;
          state.latestTxId = r.latestTxId;
          renderList();
          refreshHeader().catch(() => {});
          toast(i18n_t("app.toast.refreshed_to_server_latest"), "info", 6000);
        }
      })
      .catch((e) => console.warn("[unlock-AC] sync check failed:", e?.message ?? e));

    toast(i18n_t("app.toast.recovered_with_recovery"), "ok");
  } catch (e) {
    err.textContent = i18n_t("app.toast.recovery_failed", { reason: e.message });
    err.classList.remove("hidden");
  } finally {
    btn.disabled = false;
    btn.textContent = label;
  }
});

// Alternate unlock: Passkey + Recovery (= マスターパスワード を忘れた時の救済路、Path BC)
document.getElementById("unlock-pk-rs-btn")?.addEventListener("click", async () => {
  const rs = document.getElementById("recovery-input").value.trim();
  const err = document.getElementById("unlock-error");
  err.classList.add("hidden");
  if (!rs) { err.textContent = i18n_t("app.error.recovery_secret_required"); err.classList.remove("hidden"); return; }
  const btn = document.getElementById("unlock-pk-rs-btn");
  btn.disabled = true;
  const label = btn.textContent;
  btn.innerHTML = i18n_t("app.button.recovering_progress");
  try {
    // Phase 7.2-B (α) hotfix: active profile を bootstrap (= restore-btn と同じ理由)
    try {
      const profMod = await import("/lib/profiles.js?v=5ef6de24");
      if (!profMod.getActiveProfileId()) {
        const prof = profMod.createProfile({ kind: "personal", label: "復元中" });
        profMod.setActiveProfileId(prof.id);
      }
    } catch (e) { /* non-fatal */ }

    // Phase 7.0w-AH #102: Deep Recovery Phase A — 1 回目で失敗したら
    //   picker 強制で別 Passkey を試せるよう retry loop で包む。
    let unlockResult;
    try {
      unlockResult = await unlockWithPasskeyAndRecovery(rs);
    } catch (e1) {
      if (e1?.code === "deep_recovery_passkey_not_registered") {
        // 別 Passkey 候補を試すか確認 → picker 強制で再試行
        const wantsRetry = window.confirm(
          i18n_t("app.confirm.deep_recovery_try_other_passkey") ||
          "選択した Passkey はこのドライブに登録されていません。別の Passkey を試しますか?"
        );
        if (!wantsRetry) throw e1;
        unlockResult = await unlockWithPasskeyAndRecovery(rs, { forcePicker: true });
      } else {
        throw e1;
      }
    }
    const { vault, latestTxId } = unlockResult;
    state.password = null;
    state.vault = vault;
    state.latestTxId = latestTxId;

    // Phase 5.3-F: Recovery 経路の古い tx 問題対策 — サーバ側 latestTxId と照合
    refreshFromServerLatest()
      .then((r) => {
        if (r?.refreshed) {
          state.vault = r.vault;
          state.latestTxId = r.latestTxId;
          renderList();
          refreshHeader().catch(() => {});
          toast(i18n_t("app.toast.refreshed_to_server_latest"), "info", 6000);
        }
      })
      .catch((e) => console.warn("[unlock-BC] sync check failed:", e?.message ?? e));

    // v5 設計 §7.3: BC unlock 直後に新 マスターパスワードの設定を促す。
    // Phase 7.0w-AO: 強制ではなくユーザーの選択肢として提示。
    // 「思い出すかもしれない」「今は設定したくない」場合はキャンセル可、
    // その時点では vault データは Passkey+Recovery で開ける限定状態だが、
    // 後で Settings → Master 変更 で設定できる。
    const wantsSetNow = window.confirm(i18n_t("app.confirm.set_master_after_bc_unlock"));
    if (wantsSetNow) {
      const newPw = await _promptNewMasterPassword(
        i18n_t("app.prompt.recovery_success_new_master_title") || "🔐 新しい Master Password を設定",
        i18n_t("app.prompt.recovery_success_new_master_hint") || "Master を忘れたので新しい Master を設定します。 次回からは Master + Passkey で素早く unlock できます。"
      );
      if (newPw) {  // envelope v7: Master 最低長ルール撤廃 (空のみ不可)
        try {
          updateSaveStatusBadge("saving");
          console.log("[BC-master-reset] calling changePasswordUI with newPw length=" + newPw.length);
          const r = await changePasswordUI(newPw, rs);
          console.log("[BC-master-reset] changePasswordUI returned, new txid=" + r?.txid);
          state.password = newPw;
          updateSaveStatusBadge("saved", { txid: currentLatestTxId() });
          toast(i18n_t("app.toast.master_reset"), "ok", 8000);
        } catch (cpErr) {
          console.error("[BC-master-reset] failed:", cpErr);
          updateSaveStatusBadge("error", { error: cpErr });
          toast(i18n_t("app.toast.master_reset_failed", { reason: cpErr.message }), "warn", 8000);
        }
      }
      // newPw === null (キャンセル) は無音で進む
    } else {
      toast(i18n_t("app.toast.master_later_in_settings"), "info", 6000);
    }

    await refreshHeader();
    renderList();
    showView("vault");

    // Phase 7.0w-AI: Recovery 経路の unlock でも save-debounce を初期化する
    // (これが抜けていたため Recovery + Master / Recovery + Passkey で開いた
    //  ユーザーは編集バッジ非表示 + 保存不能の状態だった)
    initSaveDebounce({
      saveVault,
      onStatus: (s, info) => updateSaveStatusBadge(s, info),
      beforeUnloadMessage: i18n_t("app.confirm.beforeunload_unsaved"),
    });

  } catch (e) {
    err.textContent = i18n_t("app.error.recovery_failed_prefix") + e.message;
    err.classList.remove("hidden");
  } finally {
    btn.disabled = false;
    btn.textContent = label;
  }
});

document.getElementById("forget-link").addEventListener("click", (e) => {
  e.preventDefault();
  if (!confirm(i18n_t("app.confirm.forget_device"))) return;
  forgetClientIdentity();
  forgetPasskey();
  localStorage.removeItem("arpass_vault_meta_v1");
  location.reload();
});

// =====================================================================
// Restore on new device (password + Recovery Secret)
// =====================================================================
document.getElementById("goto-restore-link")?.addEventListener("click", (e) => {
  e.preventDefault();
  showView("restore");
});
// Phase 7.0w-W: 機種変更ユーザー向けの目立つ位置にあるリンク (create 画面上部の警告 box 内)
document.getElementById("goto-restore-link-top")?.addEventListener("click", (e) => {
  e.preventDefault();
  showView("restore");
});
document.getElementById("goto-create-link")?.addEventListener("click", (e) => {
  e.preventDefault();
  showView("create");
});

// envelope v7: パスキー + マスターパスワードでこの端末を復元 (Recovery 不要)。
//   v7 vault は user.id に outer 鍵 / appNameTag を持つため、同期パスキー / YubiKey が
//   あれば Recovery 無しで新端末解錠できる (unlockWithPasswordAndPasskey の freshDevice 分岐)。
//   実装: active profile を確保 → 既存 unlock-btn フローを再利用 (post-unlock 処理を流用)。
document.getElementById("restore-passkey-btn")?.addEventListener("click", async () => {
  const pw = document.getElementById("restore-pw").value;
  const err = document.getElementById("restore-error");
  err?.classList.add("hidden");
  if (!pw) {
    if (err) { err.textContent = i18n_t("app.error.master_required"); err.classList.remove("hidden"); }
    return;
  }
  try {
    const profMod = await import("/lib/profiles.js?v=5ef6de24");
    if (!profMod.getActiveProfileId()) {
      const prof = profMod.createProfile({ kind: "personal", label: "復元中" });
      profMod.setActiveProfileId(prof.id);
    }
  } catch (e) {
    console.warn("[restore-passkey] profile 確保失敗 (継続):", e?.message);
  }
  // unlock view に Master を渡して既存の unlock-btn ハンドラを発火。
  //   meta 不在 + userHandle が v7 → unlockWithPasswordAndPasskey の freshDevice 分岐が
  //   userHandle から outer 鍵 / appNameTag を読み、解錠 + meta 新規作成まで行う。
  document.getElementById("unlock-pw").value = pw;
  showView("unlock");
  document.getElementById("unlock-btn").click();
});

document.getElementById("restore-btn")?.addEventListener("click", async () => {
  const pw = document.getElementById("restore-pw").value;
  const rs = document.getElementById("restore-rs").value.trim();
  const err = document.getElementById("restore-error");
  err.classList.add("hidden");
  if (!pw) { err.textContent = i18n_t("app.error.master_required"); err.classList.remove("hidden"); return; }
  if (!rs) { err.textContent = i18n_t("app.error.recovery_secret_required"); err.classList.remove("hidden"); return; }
  const btn = document.getElementById("restore-btn");
  btn.disabled = true;
  btn.innerHTML = i18n_t("app.button.adding_device_progress");
  try {
    const name = document.getElementById("restore-name").value.trim()
              || _defaultPasskeyDisplayName();

    // Phase 7.2-B (α) hotfix: restore flow も unlock 前に active profile を確保。
    //   localStorage を消して別端末から復元する場合、 active profile が無いと
    //   unlock 内部の writeMeta が 'writeMeta called without active profile' で throw する。
    //   restore 時点では personal / corp の区別はまだ分からないので暫定 personal で作る。
    //   unlock 成功後に vault.mode を見て updateProfile で kind を corp/admin に re-label する。
    try {
      const profMod = await import("/lib/profiles.js?v=5ef6de24");
      if (!profMod.getActiveProfileId()) {
        const prof = profMod.createProfile({ kind: "personal", label: "復元中" });
        profMod.setActiveProfileId(prof.id);
      }
    } catch (e) { /* non-fatal、 unlock 内部で再度 throw されるので OK */ }

    // v5: 2 ステップ — まず マスターパスワード + Recovery で unlock (Path AC) し、
    //                  続いてこの端末用 Passkey を作って envelope に追加
    let unlockRes;
    try {
      unlockRes = await unlockWithPasswordAndRecovery(pw, rs);
    } catch (e1) {
      // Phase 7.1-G.3: corp tier の vault は corp::<companyId> tag が必要。
      // legacy/free/paid/private で見つからなかったら「会社モードですか? Company ID を入力」UI で再試行。
      if (/見つかりません|not.*found/i.test(e1?.message || "")) {
        const companyId = window.prompt(
          i18n_t("app.business.prompt.company_id") ||
          "🏢 会社モードのドライブですか?\n\n会社モードならば Company ID を入力してください (admin の管理画面で確認できます、英数 ~8 文字)。\n\nキャンセル = 個人モードとして「見つからない」エラーで終了:",
          ""
        );
        if (companyId && companyId.trim()) {
          unlockRes = await unlockWithPasswordAndRecovery(pw, rs, { companyId: companyId.trim() });
        } else {
          throw e1;
        }
      } else {
        throw e1;
      }
    }
    state.password = pw;
    state.vault = unlockRes.vault;
    state.latestTxId = unlockRes.latestTxId;
    state.readOnly = false;

    // Phase 5.3-F: !!! 重要 !!!
    // unlockWithPasswordAndRecovery は GraphQL findLatestVaultTx で envelope
    // を取りに行くが、bundling lag で古い tx を返すことがある。古い envelope
    // に新 Passkey wrap を加えて save すると、新しい entries (= 別端末で追加
    // 済の vault データ) を上書き消失するリスクがある。
    // ここでは SYNC で refreshFromServerLatest を呼んでサーバ側真の latestTxId
    // を反映してから addCredentialOnThisDevice に進む。
    try {
      const r = await refreshFromServerLatest();
      if (r?.refreshed) {
        state.vault = r.vault;
        state.latestTxId = r.latestTxId;
        toast(i18n_t("app.toast.refreshed_to_server_latest_count", { count: r.entriesAfter ?? 0 }), "info", 6000);
      }
    } catch (syncErr) {
      console.warn("[restore] pre-add sync failed (continuing):", syncErr?.message ?? syncErr);
      // サーバが応答しないなら GraphQL 結果のままで進む (best-effort)
      // 楽観ロック (expectedLatestTxId) が saveVault で 409 を返してくれる
    }

    try {
      // この端末で初めて = Passkey が無い → 新規作成して wrap 追加
      const addRes = await addCredentialOnThisDevice(pw, name);
      state.latestTxId = addRes.txid;
      toast(i18n_t("app.toast.device_added"), "ok");
    } catch (passkeyErr) {
      // Phase 7.1-Z: 409 version_conflict なら confirm で「上書き」して retry。
      // server 側 latestVaultTxId が corrupted (= 別端末の record file txid を
      // 誤って指してる等) の救済路。Arweave に過去 vault は永続残るので
      // overwrite してもデータ消失ではない旨を文言で明示。
      if (passkeyErr?.code === "version_conflict" || passkeyErr?.status === 409) {
        const ok = confirm(
          (i18n_t("app.unlock_ac.conflict_confirm") ||
           "サーバの状態とこの端末で取得した内容が異なります。\n\n" +
           "「このデバイスの内容で上書き保存」して Passkey 登録を完了しますか?\n" +
           "(過去 vault は Arweave に永続残るので、後から取り出すことも可能です)")
        );
        if (ok) {
          try {
            const addRes2 = await addCredentialOnThisDevice(pw, name, { forceOverwrite: true });
            state.latestTxId = addRes2.txid;
            toast(i18n_t("app.toast.device_added") || "✅ この端末を登録しました", "ok");
          } catch (retryErr) {
            console.warn("[unlock-AC] forceOverwrite retry failed:", retryErr);
            toast((i18n_t("app.toast.unlock_ok_passkey_failed") ||
                   "ロック解除はできましたが、Passkey 登録に失敗しました: ") + (retryErr?.message || retryErr), "warn", 10000);
          }
        } else {
          toast(i18n_t("app.toast.unlock_ok_passkey_failed") ||
                "ロック解除はできましたが、Passkey 登録はキャンセルされました", "warn", 8000);
        }
      } else {
        console.warn("Passkey registration after restore failed:", passkeyErr);
        toast(i18n_t("app.toast.unlock_ok_passkey_failed") ||
              "ロック解除はできましたが、Passkey 登録に失敗しました", "warn", 8000);
      }
    }
    await refreshHeader();
    renderList();
    showView("vault");
    // Phase 7.2-B (α) hotfix: restore-btn (= 機種追加) 経路でも save-debounce を初期化
    //   これがないとエントリ編集後の自動保存が即時 fallback (= 警告 toast 出る)
    initSaveDebounce({
      saveVault,
      onStatus: (s, info) => updateSaveStatusBadge(s, info),
      beforeUnloadMessage: i18n_t("app.confirm.beforeunload_unsaved"),
    });
  } catch (e) {
    showSaveError(err, e, i18n_t("app.error.restore_failed"));
  } finally {
    btn.disabled = false;
    btn.textContent = i18n_t("app.button.add_this_device");
  }
});

// Phase 7.0w-AH #102: Deep Recovery 入口 (signup/restore view 側)
//   完全に local state を失ったが OS Keychain Passkey は残っている、かつ
//   Master Password を忘れたユーザーが Recovery + 残存 Passkey だけで救済。
//   = unlockWithPasskeyAndRecovery (credIdHash 非依存 BC unlock) を直接呼ぶ。
document.getElementById("restore-deep-recovery-btn")?.addEventListener("click", async () => {
  const rs = document.getElementById("restore-rs").value.trim();
  const err = document.getElementById("restore-error");
  err.classList.add("hidden");
  if (!rs) {
    err.textContent = i18n_t("app.error.recovery_secret_required");
    err.classList.remove("hidden");
    return;
  }
  const btn = document.getElementById("restore-deep-recovery-btn");
  btn.disabled = true;
  const label = btn.textContent;
  btn.innerHTML = i18n_t("app.button.recovering_progress");
  try {
    // 1. BC unlock — retry with picker if first Passkey is wrong
    let unlockResult;
    try {
      // force picker on first try too (no local hint to begin with)
      unlockResult = await unlockWithPasskeyAndRecovery(rs, { forcePicker: true });
    } catch (e1) {
      if (e1?.code === "deep_recovery_passkey_not_registered") {
        const wantsRetry = window.confirm(
          i18n_t("app.confirm.deep_recovery_try_other_passkey") ||
          "選択した Passkey はこのドライブに登録されていません。別の Passkey を試しますか?"
        );
        if (!wantsRetry) throw e1;
        unlockResult = await unlockWithPasskeyAndRecovery(rs, { forcePicker: true });
      } else {
        throw e1;
      }
    }
    state.password = null;
    state.vault = unlockResult.vault;
    state.latestTxId = unlockResult.latestTxId;

    // 2. background sync (= 別端末で更新があれば取り込む)
    refreshFromServerLatest()
      .then((r) => {
        if (r?.refreshed) {
          state.vault = r.vault;
          state.latestTxId = r.latestTxId;
          renderList();
          refreshHeader().catch(() => {});
          toast(i18n_t("app.toast.refreshed_to_server_latest"), "info", 6000);
        }
      })
      .catch((e) => console.warn("[deep-recovery] sync check failed:", e?.message ?? e));

    // 3. 新 Master の設定を促す (= Phase 7.2-B (α): password 型 + 二重確認の inline modal)
    const wantsSetNow = window.confirm(i18n_t("app.confirm.set_master_after_bc_unlock"));
    if (wantsSetNow) {
      const newPw = await _promptNewMasterPassword(
        i18n_t("app.prompt.recovery_success_new_master_title") || "🔐 新しい Master Password を設定",
        i18n_t("app.prompt.recovery_success_new_master_hint") || "Master を忘れたので新しい Master を設定します。 次回からは Master + Passkey で素早く unlock できます。"
      );
      if (newPw) {  // envelope v7: Master 最低長ルール撤廃 (空のみ不可)
        try {
          updateSaveStatusBadge("saving");
          console.log("[deep-recovery-master-reset] calling changePasswordUI with newPw length=" + newPw.length);
          const r = await changePasswordUI(newPw, rs);
          console.log("[deep-recovery-master-reset] changePasswordUI returned, new txid=" + r?.txid);
          state.password = newPw;
          updateSaveStatusBadge("saved", { txid: currentLatestTxId() });
          toast(i18n_t("app.toast.master_reset"), "ok", 8000);
        } catch (cpErr) {
          console.error("[deep-recovery-master-reset] failed:", cpErr);
          updateSaveStatusBadge("error", { error: cpErr });
          toast(i18n_t("app.toast.master_reset_failed", { reason: cpErr.message }), "warn", 8000);
        }
      }
    } else {
      toast(i18n_t("app.toast.master_later_in_settings"), "info", 6000);
    }

    await refreshHeader();
    renderList();
    showView("vault");

    // save-debounce 初期化 (Phase 7.0w-AI 互換)
    initSaveDebounce({
      saveVault,
      onStatus: (s, info) => updateSaveStatusBadge(s, info),
      beforeUnloadMessage: i18n_t("app.confirm.beforeunload_unsaved"),
    });
  } catch (e) {
    showSaveError(err, e, i18n_t("app.error.recovery_failed_prefix") + e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = label;
  }
});

// =====================================================================
// Security settings (factor rotations)
// =====================================================================
function openSettings() {
  // Clear all inputs + errors so nothing leaks between opens.
  ["sec-pw-new", "sec-pw-new2", "sec-pw-rs", "sec-pk-pw", "sec-pk-rs", "sec-rs-pw"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.value = "";
  });
  ["sec-pw-err", "sec-pk-err", "sec-rs-err"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.classList.add("hidden");
  });
  renderDeviceList();
  renderHwkeyDeviceList();
  loadCorpInfo();
  renderSupportId();
  // Phase 7.4: settings はアコーディオン (<details>)。 desktop は全セクション
  //   開いた状態 (= 従来 UX 維持)、 mobile は全閉 (= 画面が長すぎる対策)。
  try {
    const _isMobileSettings = window.innerWidth <= 768;
    document.querySelectorAll("#settings-bg .settings-section").forEach((d) => {
      d.open = !_isMobileSettings;
    });
  } catch (e) { /* non-fatal */ }
  // Phase 7.2-B v2 / #101: 業務モードは Recovery 全更新 (Case B) 未対応。
  //   理由: business real_MEK = HKDF(K1, K2)、 K1 は server 管理。 K2 ごと rotate は
  //   K1 整合性を破る (= post-launch で combined rotation として実装予定)。 admin
  //   経由の K1 rotation で同等のセキュリティ効果が得られる。
  try {
    const _vmode = currentVaultMode();
    const _caseB = document.querySelector('input[name="rs-case"][value="B"]');
    if (_caseB) {
      const _caseBLabel = _caseB.closest("label");
      if (_vmode === "business") {
        _caseB.disabled = true;
        _caseB.checked = false;
        const _caseA = document.querySelector('input[name="rs-case"][value="A"]');
        if (_caseA) _caseA.checked = true;
        if (_caseBLabel) {
          _caseBLabel.style.opacity = "0.45";
          _caseBLabel.style.cursor = "not-allowed";
          _caseBLabel.title = "業務モードでは Case B (= 全更新 / MEK rotation) は未対応。 admin の K1 配布で同等の効果。";
        }
      } else {
        _caseB.disabled = false;
        if (_caseBLabel) {
          _caseBLabel.style.opacity = "";
          _caseBLabel.style.cursor = "";
          _caseBLabel.title = "";
        }
      }
    }
  } catch (e) { console.warn("[openSettings] caseB toggle failed:", e?.message); }
  document.getElementById("settings-bg").classList.remove("hidden");
}

/**
 * Settings 内の「サポート用 ID」表示を最新化する。
 * publicKeyHash は client-auth.js が localStorage `arpass_vault_meta_v5`
 * に保存しているのを直接読む。クリップボードコピー用の click handler も
 * ここで idempotent に bind する (settings 開閉ごとに上書きで OK)。
 */
function renderSupportId() {
  const display = document.getElementById("support-id-display");
  const btn = document.getElementById("support-id-copy");
  if (!display || !btn) return;
  const identity = readClientIdentity();
  const pkHash = identity?.publicKeyHash || "—";
  display.textContent = pkHash;
  // idempotent: replace any prior listener by cloning
  const fresh = btn.cloneNode(true);
  btn.parentNode.replaceChild(fresh, btn);
  fresh.addEventListener("click", async () => {
    if (!pkHash || pkHash === "—") {
      toast(i18n_t("app.toast.support_id_unavailable"), "err");
      return;
    }
    try {
      await navigator.clipboard.writeText(pkHash);
      toast(i18n_t("app.toast.support_id_copied"), "ok");
    } catch (e) {
      // fallback: select the code element so user can Cmd/Ctrl+C
      const range = document.createRange();
      range.selectNodeContents(display);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      toast(i18n_t("app.toast.support_id_copy_manual"), "ok");
    }
  });
}

function renderDeviceList() {
  const host = document.getElementById("device-list");
  if (!host) return;
  host.innerHTML = "";
  const devices = listAuthorizedDevices();
  if (!devices.length) {
    host.innerHTML = `<div style="color:var(--muted); padding:8px 0;">${i18n_t("app.text.no_devices_yet")}</div>`;
    return;
  }
  for (const dev of devices) {
    const row = document.createElement("div");
    row.style.cssText =
      "display:flex; align-items:center; gap:10px; padding:10px 12px; border:1px solid var(--line); border-radius:6px; margin-bottom:8px;" +
      (dev.current ? " background: #FEF3C7;" : "");
    const name = escape(dev.name || "(no name)");
    const added = dev.addedAt ? new Date(dev.addedAt).toISOString().slice(0, 10) : "";
    const marker = dev.current ? i18n_t("app.label.this_device_marker") : "";
    // Note: there is intentionally no per-device "remove" button.
    // Removing a device's wraps does NOT actually revoke its access —
    // the device still has its Passkey-derived material plus the master
    // password, and envelopes on Arweave (where it WAS authorized) remain
    // forever decryptable to it. The honest UX for "I lost a device" is:
    //   1. Re-issue Recovery Secret from the security panel (creates a
    //      new vault id; old vault becomes a dead branch the lost device
    //      can't follow without the new Recovery)
    //   2. Rotate every site's password
    //   3. Save the new passwords against the new vault
    // We surface that flow as the canonical lost-device response below.
    const removeBtn = dev.current
      ? '' // 現セッション端末は削除不可 (UI でも見せない)
      : `<button class="btn-outline" data-action="remove" data-id="${escape(dev.deviceId)}" style="padding: 6px 10px; font-size: 13px; color: #DC2626; border-color: #FCA5A5;">${i18n_t("app.button.delete_short")}</button>`;
    row.innerHTML = `
      <div style="flex: 1; min-width: 0;">
        <div style="font-weight:600; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
          ${name}${marker}
        </div>
        <div style="font-size:12px; color:var(--muted); font-family: ui-monospace, monospace;">
          ${escape(dev.deviceId || "—").slice(0,12)} ${added ? i18n_t("app.misc.added_prefix") + added : ""}
        </div>
      </div>
      <button class="btn-outline" data-action="rename" data-id="${escape(dev.deviceId)}" style="padding: 6px 10px; font-size: 13px;">${i18n_t("app.button.rename_short")}</button>
      ${removeBtn}
    `;
    host.appendChild(row);
  }

  host.querySelectorAll('button[data-action="rename"]').forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.id;
      const current = (listAuthorizedDevices().find((d) => d.deviceId === id) || {}).name || "";
      const next = prompt(i18n_t("app.prompt.new_device_name"), current);
      if (!next || next === current) return;
      btn.disabled = true;
      try {
        await renameAuthorizedDevice(id, next);
        toast(i18n_t("app.toast.device_renamed"), "ok");
        renderDeviceList();
      } catch (e) {
        toastSaveError(e, i18n_t("app.error.change_failed"));
      } finally {
        btn.disabled = false;
      }
    });
  });

  host.querySelectorAll('button[data-action="remove"]').forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.id;
      const dev = listAuthorizedDevices().find((d) => d.deviceId === id);
      const name = dev?.name || "(no name)";
      const confirmed = confirm(
        i18n_t("app.confirm.remove_device_intro", { name }) +
        i18n_t("app.confirm.remove_device_caution_intro") +
        i18n_t("app.confirm.remove_device_li_1") +
        i18n_t("app.confirm.remove_device_li_2") +
        i18n_t("app.confirm.remove_device_li_3") +
        i18n_t("app.confirm.continue_q")
      );
      if (!confirmed) return;
      btn.disabled = true;
      try {
        await removeAuthorizedDevice(id);
        toast(i18n_t("app.toast.device_deleted"), "ok");
        renderDeviceList();
      } catch (e) {
        toastSaveError(e, i18n_t("app.error.delete_failed"));
      } finally {
        btn.disabled = false;
      }
    });
  });
}

// envelope v7 増分2: hwkey (YubiKey 専用) vault の登録済み YubiKey 一覧を描画。
function renderHwkeyDeviceList() {
  const host = document.getElementById("hwkey-device-list");
  if (!host) return;
  host.innerHTML = "";
  const vault = currentVault();
  const creds = Array.isArray(vault?.credentials) ? vault.credentials : [];
  if (!creds.length) {
    host.innerHTML = `<div style="color:var(--muted); padding:8px 0;">${i18n_t("app.hwkey_devices.empty")}</div>`;
    return;
  }
  creds.forEach((c, idx) => {
    const row = document.createElement("div");
    row.style.cssText =
      "display:flex; align-items:center; gap:10px; padding:10px 12px; border:1px solid var(--line); border-radius:6px; margin-bottom:8px;";
    const name = escape(c.name || `YubiKey ${idx + 1}`);
    const added = c.addedAt ? new Date(c.addedAt).toISOString().slice(0, 10) : "";
    row.innerHTML = `
      <div style="flex:1; min-width:0;">
        <div style="font-weight:600; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">🔑 ${name}</div>
        ${added ? `<div style="font-size:12px; color:var(--muted);">${i18n_t("app.misc.added_prefix")}${added}</div>` : ""}
      </div>`;
    host.appendChild(row);
  });
}

// envelope v7 増分2: 「+ YubiKey を追加」 — 既存鍵で認証 → 新鍵を登録 → 保存。
document.getElementById("hwkey-add-btn")?.addEventListener("click", async () => {
  const btn  = document.getElementById("hwkey-add-btn");
  const err  = document.getElementById("hwkey-add-error");
  const prog = document.getElementById("hwkey-add-progress");
  err.classList.add("hidden");
  btn.disabled = true;
  btn.innerHTML = `<span class="spin"></span> ${i18n_t("app.hwkey_devices.adding")}`;
  try {
    await addHwkeyDevice(_defaultPasskeyDisplayName(), {
      onExistingKey: () => {
        prog.classList.remove("hidden");
        prog.textContent = i18n_t("app.hwkey_devices.touch_existing");
      },
      onNewKey: async () => {
        const ok = confirm(i18n_t("app.hwkey_devices.swap_to_new"));
        if (!ok) throw new Error("cancelled");
        prog.textContent = i18n_t("app.hwkey_devices.touch_new");
      },
    });
    prog.classList.add("hidden");
    renderHwkeyDeviceList();
    toast(i18n_t("app.hwkey_devices.done"), "ok");
  } catch (e) {
    prog.classList.add("hidden");
    if (e?.message !== "cancelled") {
      console.warn("[hwkey-add] failed:", e?.name, e?.message);
      showSaveError(err, e, i18n_t("app.error.failed"));
    }
  } finally {
    btn.disabled = false;
    btn.textContent = i18n_t("app.hwkey_devices.add_btn");
  }
});

// Phase 7.5Z: 端末追加コード — 既存端末 (iPhone/Mac) で表示
document.getElementById("hwkey-devadd-show-btn")?.addEventListener("click", () => {
  // active profile の meta を読む。 hwkey で unlock 済なら credentialId と
  //   appNameTag が入っている。 これを別端末 (Android) に渡せば specific get
  //   で picker bug を回避できる。
  const m = readMeta();
  if (!m || m.mode !== "hwkey" || !m.credentialId || !m.appNameTag) {
    alert(i18n_t("app.hwkey_devadd.no_meta") || "端末追加コードを表示するための情報がありません。 まずこの端末で解錠してから試してください。");
    return;
  }
  try {
    const credBytes = b64uDecode(m.credentialId);
    const code = encodeDeviceAddCode({ credentialId: credBytes, keyslotTag: m.appNameTag });
    document.getElementById("hwkey-devadd-code-text").textContent = code;
    document.getElementById("hwkey-devadd-qr").innerHTML = generateDeviceAddQrSvg(code);
    document.getElementById("hwkey-devadd-display").classList.remove("hidden");
  } catch (e) {
    console.error("[hwkey-devadd] encode failed:", e);
    alert("コード生成に失敗: " + e.message);
  }
});

document.getElementById("hwkey-devadd-copy-btn")?.addEventListener("click", async () => {
  const text = document.getElementById("hwkey-devadd-code-text")?.textContent || "";
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    toast(i18n_t("common.copied"), "ok");
  } catch (e) {
    alert("コピーできませんでした");
  }
});

// Phase 7.5Z: 端末追加コード — 新端末 (Android) で入力
document.getElementById("goto-hwkey-devadd-input")?.addEventListener("click", (e) => {
  e.preventDefault();
  const area = document.getElementById("hwkey-devadd-input-area");
  area?.classList.toggle("hidden");
});

// Phase 7.5Z-2: カメラで QR スキャン → input に流し込む
document.getElementById("hwkey-devadd-scan-btn")?.addEventListener("click", async () => {
  const overlay = document.getElementById("qr-scan-overlay");
  const video   = document.getElementById("qr-scan-video");
  const status  = document.getElementById("qr-scan-status");
  if (!overlay || !video) {
    alert("QR スキャナ UI が見つかりません");
    return;
  }
  overlay.classList.remove("hidden");
  if (status) status.textContent = i18n_t("app.qr_scan.status_loading") || "カメラ起動中…";
  const ctrl = new AbortController();
  // overlay の閉じる動作にも対応 (既存の close ロジックを使う)
  try {
    // Phase 7.5ZU: camera + 画像ファイル の両方で受付
    const text = await scanQrCombined(video, { signal: ctrl.signal });
    overlay.classList.add("hidden");
    // AP1- 検証 + input に流し込み
    const cleaned = (text || "").trim();
    if (!cleaned.startsWith("AP1.")) {
      toast(i18n_t("app.hwkey_devadd.scan_invalid") || "AP1-... 形式のコードではありません", "err");
      return;
    }
    const input = document.getElementById("hwkey-devadd-input-text");
    if (input) {
      input.value = cleaned;
      input.dispatchEvent(new Event("input", { bubbles: true }));
    }
    toast(i18n_t("app.hwkey_devadd.scan_ok") || "コードを読み取りました", "ok");
  } catch (e) {
    overlay.classList.add("hidden");
    if (e?.name === "AbortError") return;
    if (e?.name === "NotAllowedError") {
      toast(i18n_t("app.toast.camera_denied") || "カメラへのアクセスが拒否されました", "err");
    } else {
      console.error("[hwkey-devadd-scan] failed:", e);
      toast((i18n_t("app.toast.qr_scan_failed") || "QR スキャン失敗") + ": " + (e?.message || String(e)), "err");
    }
  }
});

document.getElementById("hwkey-devadd-input-submit")?.addEventListener("click", async () => {
  const err = document.getElementById("hwkey-devadd-input-error");
  err.classList.add("hidden");
  const text = document.getElementById("hwkey-devadd-input-text")?.value || "";
  if (!text.trim()) {
    err.textContent = i18n_t("app.hwkey_devadd.input_empty") || "コードを入力してください";
    err.classList.remove("hidden");
    return;
  }
  try {
    const { credentialId, keyslotTag } = decodeDeviceAddCode(text);
    // active profile を確保 (= writeMeta 用)
    const { createProfile, setActiveProfileId, getActiveProfileId } = await import("/lib/profiles.js?v=5ef6de24");
    if (!getActiveProfileId()) {
      setActiveProfileId(createProfile({ kind: "personal", label: "YubiKey (Android)" }).id);
    }
    // meta に書き込む — Android Chrome の picker bug を回避できる specific get の準備
    writeMeta({
      mode: "hwkey",
      credentialId: b64uEncode(credentialId),
      appNameTag: keyslotTag,
    });
    toast(i18n_t("app.hwkey_devadd.input_ok") || "コードを保存しました。 YubiKey で解錠します", "ok");
    // 即座に解錠 flow へ
    _hwkeyUnlockFlow(
      document.getElementById("hwkey-devadd-input-submit"),
      err,
      i18n_t("app.hwkey_devadd.input_submit") || "コード適用 → YubiKey で開く",
    );
  } catch (e) {
    console.error("[hwkey-devadd-input] failed:", e);
    err.textContent = e?.message || String(e);
    err.classList.remove("hidden");
  }
});

function closeSettings() {
  document.getElementById("settings-bg").classList.add("hidden");
}
document.getElementById("settings-btn")?.addEventListener("click", openSettings);
document.getElementById("settings-close")?.addEventListener("click", closeSettings);
document.getElementById("settings-bg")?.addEventListener("click", (e) => {
  if (e.target.id === "settings-bg") closeSettings();
});

// --- Change password ---
document.getElementById("sec-pw-btn")?.addEventListener("click", async () => {
  const newPw = document.getElementById("sec-pw-new").value;
  const newPw2 = document.getElementById("sec-pw-new2").value;
  const rs = document.getElementById("sec-pw-rs").value.trim();
  const err = document.getElementById("sec-pw-err");
  err.classList.add("hidden");
  if (!newPw) { err.textContent = i18n_t("app.error.master_required"); err.classList.remove("hidden"); return; }
  if (newPw !== newPw2) { err.textContent = i18n_t("app.error.passwords_dont_match_short"); err.classList.remove("hidden"); return; }
  if (!rs) { err.textContent = i18n_t("app.error.recovery_required"); err.classList.remove("hidden"); return; }
  const btn = document.getElementById("sec-pw-btn");
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span> 変更中...';
  try {
    // Phase 7.0w-AT: changePasswordUI は save-debounce を経由しないので
    //   編集バッジを手動で saving → saved に遷移して視覚的に進行を伝える。
    updateSaveStatusBadge("saving");
    // 新 Passkey の表示名は通常の Passkey と同じ「ブラウザ on 機種 (MM/DD hh:mm)」形式 (ローカル時刻)
    await changePasswordUI(newPw, rs, _defaultPasskeyDisplayName());
    state.password = newPw;
    updateSaveStatusBadge("saved", { txid: currentLatestTxId() });
    await refreshHeader();
    closeSettings();
    // envelope v7 (Option A): Master 変更で この端末に新しいパスキーを作成した。
    //   共有パスキーなら新パスキーは自動同期、端末別パスキーなら他端末は Recovery
    //   で開き直す — どちらも他端末での操作が要るので必ず補足を出す。
    toast(
      i18n_t("app.toast.master_changed_local_only") +
      i18n_t("app.toast.master_other_devices_old"),
      "ok", 13000
    );
  } catch (e) {
    showSaveError(err, e, i18n_t("app.error.failed"));
  } finally {
    btn.disabled = false;
    btn.textContent = i18n_t("app.settings.btn_pw_change");
  }
});

// --- Phase 7.0w-AH/AP: Show Recovery from vault (with biometric gate) ---
document.getElementById("sec-show-rs-btn")?.addEventListener("click", async () => {
  const errEl = document.getElementById("sec-show-rs-err");
  errEl.classList.add("hidden");
  errEl.textContent = "";
  try {
    // 1. Biometric ゲート: Passkey 認証で本人確認 (PRF を取り出すわけではない、認証だけ)
    const credIdHint = readMeta()?.credentialId ? b64uDecode(readMeta().credentialId) : null;
    await authenticateWithPasskey(credIdHint);

    // 2. vault に encryptedRecovery が無い or 旧 v1 形式なら、紙からの migration を促す
    const vault = currentVault();
    const er = vault?.encryptedRecovery;
    if (!er || er.v !== 2) {
      // 紙手入力 modal を開く (続きは rs-from-paper-save handler が処理)
      document.getElementById("rs-from-paper-input").value = "";
      document.getElementById("rs-from-paper-err").classList.add("hidden");
      document.getElementById("rs-from-paper-bg").classList.remove("hidden");
      return;
    }

    // 3. 復号して modal で表示
    const recoverySecret = await getDecryptedRecoveryFromVault();
    if (!recoverySecret) {
      errEl.textContent = i18n_t("app.show_recovery.err_decrypt_failed");
      errEl.classList.remove("hidden");
      return;
    }
    _openShowRecoveryModal(recoverySecret);
  } catch (e) {
    console.warn("[show-rs] failed:", e);
    if (e?.name === "NotAllowedError") {
      // user cancelled biometric
      errEl.textContent = i18n_t("app.show_recovery.err_biometric_cancelled");
    } else {
      errEl.textContent = i18n_t("app.show_recovery.err_generic", { reason: e?.message || String(e) });
    }
    errEl.classList.remove("hidden");
  }
});

// --- Phase 7.0w-AH: paper-from-Recovery migration save ---
document.getElementById("rs-from-paper-save")?.addEventListener("click", async () => {
  const input = document.getElementById("rs-from-paper-input").value.trim();
  const errEl = document.getElementById("rs-from-paper-err");
  errEl.classList.add("hidden");
  if (!input.match(/^RS1-/i)) {
    errEl.textContent = i18n_t("app.rs_paper.err_format");
    errEl.classList.remove("hidden");
    return;
  }
  try {
    // Phase 7.0w-AP fix.4: deferSave 方式 — session 注入 + vault に in-memory で
    // encryptedRecovery を埋め、scheduleSave で編集バッジ 'dirty' を立てる。
    // 実 Arweave 書込はロック時 flush または手動バッジクリックで bundle される。
    await injectEncryptedRecoveryNow(input);
    scheduleSave(state.vault);  // 編集バッジ → '未保存' に
    document.getElementById("rs-from-paper-bg").classList.add("hidden");
    toast(i18n_t("app.toast.rs_paper_saved"), "ok", 6000);
    _openShowRecoveryModal(input);
  } catch (e) {
    errEl.textContent = i18n_t("app.rs_paper.err_save_failed", { reason: e?.message || String(e) });
    errEl.classList.remove("hidden");
  }
});
document.getElementById("rs-from-paper-cancel")?.addEventListener("click", () => {
  document.getElementById("rs-from-paper-bg").classList.add("hidden");
});

// Phase 7.0w-AH: helper — show Recovery modal をユーザーが閉じるまで開く
function _openShowRecoveryModal(recoverySecret) {
  const bg = document.getElementById("show-recovery-bg");
  const box = document.getElementById("show-rs-box");
  const qr = document.getElementById("show-rs-qr");
  box.textContent = recoverySecret;
  qr.innerHTML = generateQrSvg(recoverySecret);
  bg.classList.remove("hidden");
}

document.getElementById("show-rs-close")?.addEventListener("click", () => {
  // メモリから wipe — 表示用に DOM に残った文字列もクリア
  const box = document.getElementById("show-rs-box");
  const qr = document.getElementById("show-rs-qr");
  if (box) box.textContent = "";
  if (qr) qr.innerHTML = "";
  document.getElementById("show-recovery-bg").classList.add("hidden");
});

document.getElementById("show-rs-copy")?.addEventListener("click", () => {
  const box = document.getElementById("show-rs-box");
  if (!box?.textContent) return;
  navigator.clipboard.writeText(box.textContent).then(() => {
    toast(i18n_t("app.toast.rs_copied"), "ok", 3000);
  }).catch(() => {
    toast(i18n_t("app.toast.rs_copy_failed"), "warn", 3000);
  });
});

document.getElementById("show-rs-print")?.addEventListener("click", () => {
  // 既存の rs-print 実装を流用 — 印刷ダイアログを開く
  window.print();
});

// Phase 7.5ZZ: show-recovery 再表示画面からも 「画像で保存」 できるように
document.getElementById("show-rs-save-image")?.addEventListener("click", async () => {
  const code = document.getElementById("show-rs-box")?.textContent;
  if (!code) { toast(i18n_t("app.toast.no_recovery_shown"), "err"); return; }
  try {
    const pngBlob = await renderRecoveryAsPng(code);
    const file = new File([pngBlob], "arpass-recovery.png", { type: "image/png" });

    const mobile = _isMobileLike();
    const canShareFiles = !!(navigator.canShare && navigator.canShare({ files: [file] }));

    if (mobile && canShareFiles) {
      try {
        await navigator.share({
          files: [file],
          title: "Arpass Recovery Secret",
          text: "Arpass Recovery Secret — 安全な場所に保管してください",
        });
        toast(i18n_t("app.recovery.toast_image_shared") ||
              "保存しました。 E2E 暗号化を有効にしてください。", "ok", 6000);
        return;
      } catch (e) {
        if (e?.name === "AbortError") return;
        console.warn("[show-recovery] navigator.share failed:", e?.message ?? e);
      }
    }

    // PC または share API 失敗時: download
    const url = URL.createObjectURL(pngBlob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "arpass-recovery.png";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast(i18n_t("app.recovery.toast_image_downloaded") ||
          "画像をダウンロードしました。 安全な場所に保管してください。", "ok", 6000);
  } catch (e) {
    console.error("[show-recovery] save-image failed:", e);
    toast((i18n_t("app.recovery.toast_image_failed") || "画像保存に失敗しました") +
          ": " + (e?.message ?? e), "err");
  }
});

// --- Rotate Passkey ---
document.getElementById("sec-pk-btn")?.addEventListener("click", async () => {
  const pw = document.getElementById("sec-pk-pw").value;
  const rs = document.getElementById("sec-pk-rs").value.trim();
  const err = document.getElementById("sec-pk-err");
  err.classList.add("hidden");
  if (!pw) { err.textContent = i18n_t("app.error.current_master_required"); err.classList.remove("hidden"); return; }
  if (!rs) { err.textContent = i18n_t("app.error.recovery_required"); err.classList.remove("hidden"); return; }
  const btn = document.getElementById("sec-pk-btn");
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span> 登録中...（端末認証してください）';
  try {
    await addCredentialOnThisDevice(pw, _defaultPasskeyDisplayName());
    await refreshHeader();
    toast(i18n_t("app.toast.passkey_registered_new"), "ok");
    closeSettings();
  } catch (e) {
    showSaveError(err, e, i18n_t("app.error.failed"));
  } finally {
    btn.disabled = false;
    btn.textContent = i18n_t("app.settings.btn_pk_update");
  }
});

// --- Re-issue Recovery Secret ---
document.getElementById("sec-rs-btn")?.addEventListener("click", async () => {
  const pw = document.getElementById("sec-rs-pw").value;
  const err = document.getElementById("sec-rs-err");
  err.classList.add("hidden");
  if (!pw) { err.textContent = i18n_t("app.error.current_master_required"); err.classList.remove("hidden"); return; }
  const caseChoice = document.querySelector('input[name="rs-case"]:checked')?.value || "A";
  // Case B は本格 rotation で巻き戻せないので確認 dialog
  if (caseChoice === "B") {
    const ok = confirm(
      i18n_t("app.confirm.case_b_intro") +
      i18n_t("app.confirm.case_b_li_1") +
      i18n_t("app.confirm.case_b_li_2") +
      i18n_t("app.confirm.case_b_li_3") +
      i18n_t("app.confirm.case_b_li_4") +
      i18n_t("app.confirm.continue_q")
    );
    if (!ok) return;
  }
  const btn = document.getElementById("sec-rs-btn");
  btn.disabled = true;
  btn.innerHTML = `<span class="spin"></span> ${i18n_t("app.button.issuing")}`;
  try {
    const result = caseChoice === "B"
      ? await reissueRecovery_caseB(pw)
      : await reissueRecovery_caseA(pw);
    const recoverySecret = result.newRecovery;
    state.latestTxId = result.txid ?? null;
    // Reuse the same recovery-show view to display + require confirmation.
    document.getElementById("rs-box").textContent = recoverySecret;
    document.getElementById("rs-qr").innerHTML = generateQrSvg(recoverySecret);
    document.getElementById("rs-confirm").checked = false;
    document.getElementById("rs-continue").disabled = true;
    closeSettings();
    showView("recoveryShow");
    const caseLabel = caseChoice === "B" ? i18n_t("app.button.case_b_full_rotation") : i18n_t("app.button.case_a_light_rotation");
    toast(i18n_t("app.toast.recovery_issued", { label: caseLabel }), "ok", 8000);
  } catch (e) {
    showSaveError(err, e, i18n_t("app.error.failed"));
  } finally {
    btn.disabled = false;
    btn.textContent = i18n_t("app.button.issue_new_recovery");
  }
});

// =====================================================================
// Vault view — list + search
// =====================================================================
document.getElementById("search").addEventListener("input", (e) => {
  state.filter = e.target.value.toLowerCase();
  renderList();
});

document.getElementById("add-btn").addEventListener("click", () => {
  if (state.readOnly) {
    toast(i18n_t("app.toast.readonly_drive"), "err");
    return;
  }
  openModal(null);
});

/**
 * Toggle UI affordances that should be disabled when the active vault is
 * in read-only mode (e.g. server has migrated the vault id to a new one
 * via Recovery re-issue, or it's frozen for a chargeback dispute). We
 * preemptively dim the controls so the user understands they can't edit
 * — relying solely on the save-time 410/423 error feels surprising.
 */
function syncReadOnlyState() {
  // Phase 5.3-E: ロックの理由を統合判定
  //   readOnly: vault が migrated/frozen
  //   serviceDown: 課金サーバ (/api/*) に接続不能 — 一時的、復旧で解除
  const cantWrite = !!state.readOnly || !!state.serviceDown;
  const reason =
    state.readOnly  ? i18n_t("app.error.drive_readonly_frozen")
    : state.serviceDown ? i18n_t("app.error.cannot_connect_billing_view_only")
    : "";

  const addBtn = document.getElementById("add-btn");
  if (addBtn) {
    addBtn.disabled = cantWrite;
    addBtn.title = reason;
  }
  // Modal save button: hide entirely when read-only so the modal becomes
  // a viewer; otherwise let syncSaveButtonToCredits pick the right text.
  const saveBtn = document.getElementById("m-save");
  const deleteBtn = document.getElementById("m-delete");
  if (state.readOnly) {
    // 永久 read-only (migration/freeze) — 完全に非表示
    if (saveBtn) saveBtn.classList.add("hidden");
    if (deleteBtn) deleteBtn.classList.add("hidden");
  } else if (state.serviceDown) {
    // 一時的 down — ボタンは出すけど disabled で「💤 サービス復旧待ち」表示
    if (saveBtn) {
      saveBtn.classList.remove("hidden");
      saveBtn.disabled = true;
      saveBtn.textContent = i18n_t("app.label.waiting_service_recovery");
      saveBtn.title = i18n_t("app.error.billing_unreachable_save_blocked");
    }
    if (deleteBtn) {
      deleteBtn.disabled = true;
      deleteBtn.title = i18n_t("app.error.billing_unreachable_short");
    }
  } else {
    if (saveBtn) {
      saveBtn.classList.remove("hidden");
      saveBtn.disabled = false;
      // テキストは syncSaveButtonToCredits が再設定
    }
    if (deleteBtn) {
      deleteBtn.disabled = false;
      deleteBtn.title = "";
    }
  }
}

document.getElementById("lock-btn").addEventListener("click", async () => {
  // Phase 6.7-9: lock 前に flush。失敗 (Arweave 障害等) なら confirm で
  // user 判断を仰ぎ、データ消失を silent に起こさない。
  try {
    const status = getSaveStatus();
    if (status.state === "dirty" || status.state === "saving") {
      toast(i18n_t("app.toast.saving_in_progress"), "");
      const result = await flushSaveDebounce();
      // flushSaveDebounce は throw せず { ok, error } を返すので、戻り値 check 必須
      if (result && result.ok === false) {
        const proceed = confirm(i18n_t("app.confirm.flush_failed_proceed_lock"));
        if (!proceed) return;  // abort lock — user can retry
      }
    }
  } catch (e) {
    console.warn("[lock] flush threw before lock:", e);
    const proceed = confirm(i18n_t("app.confirm.flush_threw_proceed_lock"));
    if (!proceed) return;
  }
  // Phase 7.0w-AK: lock 時に location.reload() に戻す。
  // Phase 6.8.32 / 6.8.34 で in-place 切替に変更した理由 (CSP の inline script
  // 制約 + Cloudflare Bot Fight Mode の challenge 再起動による真っ白画面) は、
  // 以降の改修 (cache-bust 強化、_headers の Cache-Control 整備、Web Analytics 注入
  // 受容) で十分に緩和された。
  //
  // reload に戻すメリット:
  //   - state cleanup の漏れ (header / financial display / modal / 検索 input
  //     等の細々した DOM 残留) に依存しないクリーンな初期状態を保証
  //   - 旧 vault のデータが DOM に痕跡として残るリスクの排除
  //   - lockSession() の zero-fill 範囲外の閉じ忘れ object を JS GC に任せる
  //
  // flush + lockSession + clearSavePending は reload 前に実行することで、
  // 未保存変更の保護と in-memory secret の即時無効化を維持。
  clearSavePending();
  lockSession();
  location.reload();
});

function renderList() {
  // Phase 7.x: vault サイズが容量上限に近づいたら常設 banner を出す/消す。
  renderVaultCapacityBanner();
  const el = document.getElementById("list");
  const emptyEl = document.getElementById("list-empty");
  const entries = (state.vault?.entries ?? []).filter((e) => {
    // Phase 7.0r: hidden フラグ付き entries (settings 用 API キーなど) は一覧から除外
    if (e.hidden) return false;
    const q = state.filter;
    if (!q) return true;
    return (e.site || "").toLowerCase().includes(q) ||
      (e.user || "").toLowerCase().includes(q) ||
      (e.url || "").toLowerCase().includes(q);
  });
  if (!entries.length) {
    el.innerHTML = "";
    emptyEl.classList.toggle("hidden", (state.vault?.entries ?? []).length > 0);
    if ((state.vault?.entries ?? []).length > 0) {
      el.innerHTML = `<div class="empty"><p>${i18n_t("app.text.no_matching_entries")}</p></div>`;
    }
    return;
  }
  emptyEl.classList.add("hidden");
  el.innerHTML = entries.map((e) => {
    const initial = (e.site || "?")[0].toUpperCase();
    return `
      <div class="entry" data-id="${e.id}">
        <div class="favicon">${escape(initial)}</div>
        <div class="main">
          <div class="title">${escape(e.site || i18n_t("app.entry.untitled"))}</div>
          <div class="sub">${escape(e.user || "—")} ${e.url ? "· " + escape(e.url) : ""}</div>
        </div>
        <div class="actions">
          <button class="icon-btn" title="${i18n_t("app.toast.copied_user")}" data-action="copy-user" data-id="${e.id}">👤</button>
          <button class="icon-btn" title="${i18n_t("app.entry.copy_password")}" data-action="copy-pw" data-id="${e.id}">🔑</button>
        </div>
      </div>
    `;
  }).join("");

  // Row click → detail modal
  el.querySelectorAll(".entry").forEach((div) => {
    div.addEventListener("click", (ev) => {
      const btn = ev.target.closest("[data-action]");
      if (btn) {
        ev.stopPropagation();
        const id = btn.dataset.id;
        const entry = state.vault.entries.find((x) => x.id === id);
        if (!entry) return;
        if (btn.dataset.action === "copy-user") {
          navigator.clipboard.writeText(entry.user ?? "").then(() => toast(i18n_t("app.toast.copied_user"), "ok"));
        } else if (btn.dataset.action === "copy-pw") {
          navigator.clipboard.writeText(entry.pw ?? "").then(() => toast(i18n_t("app.toast.copied_password"), "ok"));
        }
        return;
      }
      openDetail(div.dataset.id);
    });
  });
}

// =====================================================================
// Detail modal
// =====================================================================
const detailBg = document.getElementById("detail-bg");
function openDetail(id) {
  const e = state.vault.entries.find((x) => x.id === id);
  if (!e) return;
  document.getElementById("d-title").textContent = e.site || i18n_t("app.entry.untitled");
  document.getElementById("d-sub").textContent = i18n_t("app.label.updated_at", { date: e.updatedAt ?? "—" });
  document.getElementById("d-user").value = e.user ?? "";
  document.getElementById("d-pw").value = e.pw ?? "";
  document.getElementById("d-pw").type = "password";
  document.getElementById("d-url").value = e.url ?? "";
  document.getElementById("d-notes").value = e.notes ?? "";
  detailBg.classList.remove("hidden");
  detailBg.dataset.id = id;
}
document.getElementById("d-close").addEventListener("click", () => detailBg.classList.add("hidden"));
document.getElementById("d-edit").addEventListener("click", () => {
  detailBg.classList.add("hidden");
  openModal(detailBg.dataset.id);
});
document.getElementById("d-user-copy").addEventListener("click", () => {
  navigator.clipboard.writeText(document.getElementById("d-user").value).then(() => toast(i18n_t("app.toast.copied_user"), "ok"));
});
document.getElementById("d-pw-copy").addEventListener("click", () => {
  navigator.clipboard.writeText(document.getElementById("d-pw").value).then(() => toast(i18n_t("app.entry.copy_password"), "ok"));
});
document.getElementById("d-pw-show").addEventListener("click", () => {
  const el = document.getElementById("d-pw");
  el.type = el.type === "password" ? "text" : "password";
});
document.getElementById("d-url-open").addEventListener("click", () => {
  const u = document.getElementById("d-url").value;
  if (u) window.open(u.startsWith("http") ? u : "https://" + u, "_blank", "noopener");
});

// =====================================================================
// Edit / Add modal
// =====================================================================
const modalBg = document.getElementById("modal-bg");
function openModal(id) {
  state.editingId = id;
  const e = id ? state.vault.entries.find((x) => x.id === id) : null;
  document.getElementById("modal-title").textContent = id ? i18n_t("app.modal.title_edit") : i18n_t("app.modal.title_add");
  document.getElementById("m-site").value  = e?.site ?? "";
  document.getElementById("m-url").value   = e?.url ?? "";
  document.getElementById("m-user").value  = e?.user ?? "";
  document.getElementById("m-pw").value    = e?.pw ?? "";
  document.getElementById("m-pw").type     = "password";
  document.getElementById("m-notes").value = e?.notes ?? "";
  document.getElementById("m-error").classList.add("hidden");
  document.getElementById("m-delete").classList.toggle("hidden", !id);
  renderStrength("m-strength", e?.pw ?? "");
  // Adapt the save button to the current credit state. If credits === 0 the
  // button becomes a i18n_t("app.button.buy_credits_emoji") CTA that redirects to /pricing.html
  // on click instead of attempting a save (which would 402).
  syncSaveButtonToCredits();
  modalBg.classList.remove("hidden");
  setTimeout(() => document.getElementById("m-site").focus(), 10);
}
document.getElementById("m-cancel").addEventListener("click", () => modalBg.classList.add("hidden"));
document.getElementById("m-pw").addEventListener("input", (e) => renderStrength("m-strength", e.target.value));
document.getElementById("m-pw-show").addEventListener("click", () => {
  const el = document.getElementById("m-pw");
  el.type = el.type === "password" ? "text" : "password";
});
document.getElementById("m-pw-gen").addEventListener("click", () => {
  const pw = generatePassword({ length: 20 });
  document.getElementById("m-pw").value = pw;
  document.getElementById("m-pw").type = "text";
  renderStrength("m-strength", pw);
});
document.getElementById("m-pw-copy").addEventListener("click", () => {
  navigator.clipboard.writeText(document.getElementById("m-pw").value).then(() => toast(i18n_t("app.entry.copy_password"), "ok"));
});

/**
 * If state.credits is known to be 0, swap the entry-modal save button into
 * a "buy credits" CTA so the user can't even attempt to save (the API
 * would return 402 anyway). The click handler below detects the same
 * condition and redirects without saving.
 *
 * Idempotent — safe to call after every refreshHeader().
 */
function syncSaveButtonToCredits() {
  const saveBtn = document.getElementById("m-save");
  if (!saveBtn) return;
  // Don't clobber the in-flight i18n_t("app.button.saving") spinner.
  if (state.saving) return;
  if (state.credits === 0) {
    saveBtn.textContent = i18n_t("app.button.buy_credits_emoji");
    saveBtn.dataset.purchaseMode = "1";
    saveBtn.title = i18n_t("app.toast.no_credits_click_buy");
  } else {
    // Phase 6.7-8: header の「未保存」badge と区別するため、modal ボタンは
    // 文脈ごとに「追加」(新規) / 「更新」(編集) を表示する。
    saveBtn.textContent = state.editingId
      ? i18n_t("app.modal.btn_update")
      : i18n_t("app.modal.btn_add");
    delete saveBtn.dataset.purchaseMode;
    saveBtn.removeAttribute("title");
  }
}

/**
 * Render an inline i18n_t("app.button.buy_credits") link inside an error element. Centralises
 * the styling so the same affordance appears everywhere a 402 surfaces.
 */
function purchaseCtaHtml() {
  // Phase 6.7-5: inline onclick は CSP で blocked。data-action で event delegation。
  return `<a href="#" data-action="open-purchase-modal" style="color:#fbbf24; text-decoration:underline; font-weight:600;">
             ${i18n_t("app.misc.purchase_with_arrow")}
           </a>`;
}

/**
 * Display an error from any vault-write path (saveVault, changePassword,
 * rotatePasskey, …) into a target element. If the error is a 402
 * (insufficient_credits), the message includes a clickable purchase CTA
 * and the cached state.credits is refreshed from the server-reported
 * value so the rest of the UI (header, save buttons) catches up
 * immediately.
 *
 * Falls back to plain text for any other error.
 *
 * @param {Element} el  An element to render the message into; class
 *                      .hidden is removed.
 * @param {Error}   e   The error thrown by saveVault / changePassword / etc.
 * @param {string}  prefix Optional Japanese prefix like i18n_t("app.error.save_failed").
 */
function showSaveError(el, e, prefix = i18n_t("app.error.failed")) {
  if (!el) return;
  if (e?.code === "insufficient_credits") {
    // Phase 6.8: server's 402 response now wraps account in sanitized form.
    const newCredits = e?.account?.estimatedWrites;
    if (typeof newCredits === "number") {
      state.credits = newCredits;
      if (typeof e.account.perWriteUsd === "number") state.perWriteUsd = e.account.perWriteUsd;
      if (typeof e.account.perWriteUsdBase === "number") state.perWriteUsdBase = e.account.perWriteUsdBase;
      // Make the new balance visible immediately rather than waiting for
      // the next /api/status round-trip.
      refreshHeader().catch(() => {});
    }
    el.innerHTML = i18n_t("app.error.insufficient_credits_cta", { cta: purchaseCtaHtml() });
  } else if (e?.code === "vault_frozen") {
    // Triggered when a Stripe dispute (chargeback) is open against this
    // vault, or when support has manually frozen it. Reads still work, but
    // new writes are blocked until the case is resolved.
    el.innerHTML =
      i18n_t("app.error.drive_frozen_contact_support") +
      i18n_t("app.error.frozen_chargeback_note");
  } else if (e?.code === "version_conflict") {
    // Optimistic concurrency: another device wrote between our last
    // load and this save. Surfacing as a hard error + re-lock CTA is
    // safer than auto-merging, which could clobber field-level edits.
    el.innerHTML =
      i18n_t("app.error.concurrent_update") + " " +
      i18n_t("app.error.save_blocked_old_data") +
      `<br><br><a href="#" id="conflict-relock-link" ` + `style="color:#fbbf24; text-decoration:underline; font-weight:600;">` +
      i18n_t("app.label.unlock_again_link");
    setTimeout(() => {
      const a = document.getElementById("conflict-relock-link");
      if (a) {
        a.addEventListener("click", (ev) => {
          ev.preventDefault();
          // Reset in-memory state and route back to unlock screen.
          state.password = null;
          state.vault = null;
          state.latestTxId = null;
          showView("unlock");
        });
      }
    }, 0);
  } else if (e?.code === "free_pool_unavailable") {
    // Phase 6.7-4: Free wallet pool 一時枯渇 (運営 topup 待ち)。
    el.innerHTML = i18n_t("app.error.free_pool_unavailable_html", { cta: purchaseCtaHtml() });
  } else if (e?.code === "private_pool_unavailable") {
    // Phase 6.7-2: Private wallet pool 一時枯渇 (Mega user 専用 wallet 在庫切れ)。
    el.innerHTML = i18n_t("app.error.private_pool_unavailable_html");
  } else if (e?.code === "migrated") {
    // Another device re-issued the Recovery Secret. Our identity is now
    // pointing at a dead vault id; we cannot write anywhere until we
    // re-register this device against the new vault id with the new
    // Recovery Secret.
    el.innerHTML =
      i18n_t("app.error.drive_migrated_new_recovery") +
      `<a href="#" id="migrated-restore-link" ` + `style="color:#fbbf24; text-decoration:underline; font-weight:600;">` +
      i18n_t("app.label.reregister_with_new_recovery_link");
    // Defer the listener attach so the element is in the DOM.
    setTimeout(() => {
      const a = document.getElementById("migrated-restore-link");
      if (a) {
        a.addEventListener("click", (ev) => {
          ev.preventDefault();
          showView("restore");
        });
      }
    }, 0);
  } else {
    el.textContent = `${prefix}: ${e?.message ?? String(e)}`;
  }
  el.classList.remove("hidden");
}

/**
 * Same idea but for paths that surface errors via toast() instead of an
 * inline element. Toasts can't render HTML safely, so for the 402 case we
 * fire a plain-language toast and additionally jump to /pricing.html
 * after a short pause so the user sees the reason before the redirect.
 */
function toastSaveError(e, prefix = i18n_t("app.error.failed")) {
  if (e?.code === "insufficient_credits") {
    // Phase 6.8: server's 402 response now wraps account in sanitized form.
    const newCredits = e?.account?.estimatedWrites;
    if (typeof newCredits === "number") {
      state.credits = newCredits;
      if (typeof e.account.perWriteUsd === "number") state.perWriteUsd = e.account.perWriteUsd;
      if (typeof e.account.perWriteUsdBase === "number") state.perWriteUsdBase = e.account.perWriteUsdBase;
      refreshHeader().catch(() => {});
    }
    toast(i18n_t("app.toast.balance_insufficient"), "err");
    setTimeout(() => { window.openPurchasePackModal?.(); }, 1800);
  } else if (e?.code === "version_conflict") {
    // Phase 5.3: 別端末で更新があった → 上書きを防ぐためロック解除し直しを促す。
    toast(i18n_t("app.error.drive_updated_other_relock"), "err", 8000);
    setTimeout(() => {
      state.password = null;
      state.vault = null;
      state.latestTxId = null;
      showView("unlock");
    }, 2000);
  } else if (e?.code === "free_pool_unavailable") {
    // Phase 6.7-4: Free 枠一時枯渇 (Standard fallback せず 503)
    toast(i18n_t("app.toast.free_pool_unavailable"), "err", 8000);
  } else if (e?.code === "private_pool_unavailable") {
    // Phase 6.7-2: Private warm pool 一時枯渇
    toast(i18n_t("app.toast.private_pool_unavailable"), "err", 8000);
  } else {
    toast(`${prefix}: ${e?.message ?? String(e)}`, "err");
  }
}

document.getElementById("m-save").addEventListener("click", async () => {
  const saveBtn = document.getElementById("m-save");
  // If we're showing the "buy credits" CTA, refresh credits first (= Stripe 完了済の
  //   credit を取りこぼさない)。 まだ 0 なら purchase modal、 そうでなければ保存に進む。
  if (saveBtn.dataset.purchaseMode) {
    try { await refreshHeader(); } catch {}
    // refreshHeader 内で syncSaveButtonToCredits が呼ばれ、 credit が反映されれば
    //   purchaseMode dataset は削除される。 再判定。
    if (saveBtn.dataset.purchaseMode) {
      window.openPurchasePackModal?.();
      return;
    }
    // credit が更新されたので、 そのまま続行 (= 「💰購入」が「追加」に変わったので保存)
  }

  const site  = document.getElementById("m-site").value.trim();
  const url   = document.getElementById("m-url").value.trim();
  const user  = document.getElementById("m-user").value.trim();
  const pw    = document.getElementById("m-pw").value;
  const notes = document.getElementById("m-notes").value;
  const err   = document.getElementById("m-error");

  if (!site) {
    err.textContent = i18n_t("app.error.required_site");
    err.classList.remove("hidden");
    return;
  }

  // Phase 5.3-Z: マスターパスワード 使い回し検出
  // Arpass の 2-of-3 設計上、Master 単独漏洩は無害だが、マスターパスワード + Recovery
  // の組み合わせで vault 解読される。マスターパスワードを他サイトと使い回すと、
  // そのサイトが漏洩した時点で「Master が第三者の手に」+「Recovery 紙が
  // どこかに保管」= 解読リスクが現実化する。ユーザーに明確警告する。
  if (state.password && pw && pw === state.password) {
    const proceed = confirm(
      i18n_t("app.confirm.master_match_warn_intro") +
      i18n_t("app.confirm.master_reuse_intro") +
      i18n_t("app.confirm.master_reuse_li_1") +
      i18n_t("app.confirm.master_reuse_li_2") +
      i18n_t("app.confirm.master_reuse_warning_save_q") +
      i18n_t("app.confirm.master_reuse_recommend")
    );
    if (!proceed) {
      err.innerHTML = i18n_t("app.toast.save_canceled_master_match");
      err.classList.remove("hidden");
      return;
    }
  }

  if (state.saving) return;

  // Phase 5.3: 保存前 vault サイズチェック。エントリ追加/更新後の JSON サイズで
  // 判定する。 server cap 384 KB を base64 + outer encryption の overhead 込みで
  // 逆算すると plaintext ~110 KB が安全な上限。
  {
    const now = new Date().toISOString();
    const trial = JSON.parse(JSON.stringify(state.vault));
    if (state.editingId) {
      const i = trial.entries.findIndex((x) => x.id === state.editingId);
      if (i >= 0) trial.entries[i] = { ...trial.entries[i], site, url, user, pw, notes, updatedAt: now };
    } else {
      trial.entries.push({ id: newEntryId(), site, url, user, pw, notes, createdAt: now, updatedAt: now });
    }
    trial.updatedAt = now;
    const trialBytes = new TextEncoder().encode(JSON.stringify(trial)).length;
    if (trialBytes > VAULT_SIZE_BLOCK_BYTES) {
      err.innerHTML = i18n_t("app.error.drive_size_limit", { kb: (trialBytes/1024).toFixed(0), blockKb: (VAULT_SIZE_BLOCK_BYTES/1024).toFixed(0) }) +
        i18n_t("app.error.tidy_old_or_short_notes") +
        i18n_t("app.error.file_attach_phase6_note");
      err.classList.remove("hidden");
      return;
    }
    if (trialBytes > VAULT_SIZE_WARN_BYTES) {
      // 警告は toast で出して保存は続行 (ブロックではない)
      toast(i18n_t("app.toast.drive_size_warning", { kb: (trialBytes/1024).toFixed(0), blockKb: (VAULT_SIZE_BLOCK_BYTES/1024).toFixed(0) }), "warn", 6000);
    }
  }

  state.saving = true;
  saveBtn.disabled = true;
  saveBtn.innerHTML = `<span class="spin"></span> ${i18n_t("app.button.saving")}`;

  try {
    const now = new Date().toISOString();
    if (state.editingId) {
      const i = state.vault.entries.findIndex((x) => x.id === state.editingId);
      state.vault.entries[i] = { ...state.vault.entries[i], site, url, user, pw, notes, updatedAt: now };
    } else {
      state.vault.entries.push({ id: newEntryId(), site, url, user, pw, notes, createdAt: now, updatedAt: now });
    }
    state.vault.updatedAt = now;
    // Phase 6.7: 即時 saveVault → debounced scheduleSave。
    // 連続編集を 30 秒の窓で 1 write に bundle する (~5x コスト削減)。
    // 実際の書込は header の status badge で進捗表示。
    scheduleSave(state.vault);
    toast(i18n_t("app.toast.entry_change_recorded"), "ok");
    modalBg.classList.add("hidden");
    renderList();
    refreshHeader();
  } catch (e) {
    showSaveError(err, e, i18n_t("app.error.save_failed"));
  } finally {
    state.saving = false;
    saveBtn.disabled = false;
    // Restore button text appropriate to the current credit state.
    // Phase 6.7-8: syncSaveButtonToCredits が editingId 文脈を見て「追加/更新」を設定する。
    syncSaveButtonToCredits();
  }
});

document.getElementById("m-delete").addEventListener("click", async () => {
  if (!state.editingId) return;
  // Even deletion costs 1 credit (it's another vault write). If the user is
  // out of credits, deletion can't be persisted — bounce them to pricing.
  if (state.credits === 0) {
    document.getElementById("m-error").innerHTML =
      i18n_t("app.error.no_credits_for_delete_cta", { cta: purchaseCtaHtml() });
    document.getElementById("m-error").classList.remove("hidden");
    return;
  }
  if (!confirm(i18n_t("app.confirm.delete_entry"))) return;
  state.vault.entries = state.vault.entries.filter((x) => x.id !== state.editingId);
  state.vault.updatedAt = new Date().toISOString();
  const saveBtn = document.getElementById("m-delete");
  saveBtn.disabled = true;
  saveBtn.textContent = i18n_t("app.button.deleting_progress");
  try {
    // Phase 6.7: 削除も debounce で bundle
    scheduleSave(state.vault);
    toast(i18n_t("app.toast.entry_deleted_recorded"), "ok");
    modalBg.classList.add("hidden");
    renderList();
    refreshHeader();
  } catch (e) {
    showSaveError(document.getElementById("m-error"), e, i18n_t("app.error.delete_failed"));
  } finally {
    saveBtn.disabled = false;
    saveBtn.textContent = i18n_t("common.delete");
  }
});

// Close modals on backdrop click
modalBg.addEventListener("click", (e) => { if (e.target === modalBg) modalBg.classList.add("hidden"); });
detailBg.addEventListener("click", (e) => { if (e.target === detailBg) detailBg.classList.add("hidden"); });

// =====================================================================
// Header — show vault id + credit balance
// =====================================================================
async function refreshHeader() {
  const identity = readClientIdentity();
  const el = document.getElementById("header-account");
  if (!identity) { el.textContent = ""; return; }
  try {
    const s = await fetchVaultStatus();
    if (s.ok) {
      // Mirror credits into client-side state so other UI surfaces (modal
      // save button, error handlers) can read it without a refetch.
      // Phase 6.8: credits 等 = estimatedWrites; perWriteUsd / arUsd は新規フィールド
      state.credits = s.credits;
      if (typeof s.balanceUsdMicro === "number") state.balanceUsdMicro = s.balanceUsdMicro;
      if (typeof s.perWriteUsd === "number") state.perWriteUsd = s.perWriteUsd;
    if (typeof s.perWriteUsdBase === "number") state.perWriteUsdBase = s.perWriteUsdBase;
      if (typeof s.arUsd === "number") state.arUsd = s.arUsd;
      // Detect vault lifecycle changes (migration / freeze) — server now
      // exposes these in the per-vault status response. If this device is
      // still pointing at a migrated old vault, surface a banner so the
      // user knows to re-restore with the new Recovery Secret instead of
      // staring at increasingly stale data.
      renderLifecycleBanner({
        migratedTo: s.migratedTo ?? null,
        frozen: !!s.frozen,
        frozenReason: s.frozenReason ?? null,
      });
      // Phase 7.4: header を 3 領域に分割描画。
      //   行1 (#header-support-id): サポート用 ID
      //   行2 (#header-account)   : 保存状態 / TX  (+ 保存 badge は JS で append)
      //   行3 (#header-balance)   : 残高 + 単価
      // 撤去: 算法アイコン (🔐) / 書込回数 (📝) / 容量 % (📦)
      //   — 一般ユーザに意味が伝わらず、 日常操作で不要。 サポート ID も含め
      //     詳細は設定画面で確認できる想定。
      const txStatusHtml = state.latestTxId ? renderTxStatusHtml(state.latestTxId) : "";
      el.innerHTML = txStatusHtml;

      // 行1 中央: サポート用 ID (= publicKeyHash の先頭 8 文字)
      const supportEl = document.getElementById("header-support-id");
      if (supportEl) {
        const pkh = identity.publicKeyHash || "";
        supportEl.innerHTML = pkh
          ? `<span aria-hidden="true">🆔</span><code title="${i18n_t("app.settings.support_id_title")}: ${pkh}">${pkh.slice(0, 8)}…</code>`
          : "";
      }

      // 行3: 残高 + 単価
      const balanceEl = document.getElementById("header-balance");
      if (balanceEl) {
        balanceEl.innerHTML = renderCreditsHtml(s.balanceUsdMicro, s.credits);
      }
      if (state.latestTxId) scheduleTxStatusPoll(state.latestTxId);
      // Reflect any current open modal's save button to the latest balance.
      syncSaveButtonToCredits();
    }
  } catch {}
}

/**
 * Render (or hide) the lifecycle banner shown above the vault view when
 * this device's vault id has been migrated to a new one (Recovery
 * re-issued elsewhere) or frozen (chargeback dispute pending). Idempotent
 * — safe to call on every header refresh.
 */
function renderLifecycleBanner({ migratedTo, frozen, frozenReason }) {
  const host = document.getElementById("lifecycle-banner");
  if (!host) return;
  // Mirror the lifecycle state into state.readOnly so the rest of the UI
  // (add button, modal save/delete) can preemptively disable edits.
  state.readOnly = !!migratedTo || !!frozen;
  syncReadOnlyState();
  if (migratedTo) {
    host.innerHTML = `
      <div style="background: #FEF3C7; border-left: 4px solid #F59E0B; padding: 14px 18px; border-radius: 6px; margin-bottom: 16px; font-size: 14px; line-height: 1.7;">
        ${i18n_t("app.banner.migrated_html")}
        <details style="margin-top: 10px; padding: 8px 12px; background: white; border-radius: 6px;">
          <summary style="cursor: pointer; color: #92400E; font-weight: 600; font-size: 13px;">
            ${i18n_t("app.banner.migrated_summary")}
          </summary>
          <div style="padding: 10px 0 4px; font-size: 13px; color: #1E293B; line-height: 1.7;">
            <div style="background: #FEE2E2; border-left: 3px solid #DC2626; padding: 8px 12px; border-radius: 4px; margin-bottom: 10px; color: #991B1B;">
              ${i18n_t("app.banner.migrated_warn_html")}
            </div>
            <a href="#" id="banner-go-restore" style="display: inline-block; background: #F59E0B; color: #1E293B; padding: 6px 12px; border-radius: 4px; text-decoration: none; font-weight: 600; font-size: 13px;">
              ${i18n_t("app.banner.migrated_btn_reregister")}
            </a>
          </div>
        </details>
      </div>
    `;
    host.classList.remove("hidden");
    const btn = document.getElementById("banner-go-restore");
    if (btn) {
      btn.addEventListener("click", (ev) => {
        ev.preventDefault();
        // Drop into the existing restore-on-new-device flow. The user
        // will type the NEW Recovery Secret which derives a different
        // vault id, so localStorage's old identity is overwritten.
        showView("restore");
      });
    }
  } else if (frozen) {
    host.innerHTML = `
      <div style="background: #FEE2E2; border-left: 4px solid #DC2626; padding: 14px 18px; border-radius: 6px; margin-bottom: 16px; font-size: 14px; line-height: 1.7; color: #1E293B;">
        ${i18n_t("app.banner.frozen_html", { reason: frozenReason ? i18n_t("app.banner.frozen_reason", { reason: escape(frozenReason) }) : "" })}
      </div>
    `;
    host.classList.remove("hidden");
  } else {
    host.innerHTML = "";
    host.classList.add("hidden");
  }
}

/**
 * Header pill for the balance. Phase 7.0w-AN: 通貨額表示に変更。
 *   - ja: ¥{int}  (固定 JPY_PER_USD=154 換算、view-only)
 *   - en/他: ${X.XX}
 * estimatedWrites は perWriteUsd の変動で揺らぐ (毎回 ±数回) ので、安定した
 * 残高表示を優先する。Stripe 課金は ja=jpy / 他=usd で実通貨整合。
 *
 * Color-codes:
 *   • 残高 0 → red, "購入する" CTA inline
 *   • 残高あり&推定回数 ≤ LOW_CREDIT_WARN → orange, "追加購入" CTA
 *   • それ以外 → muted purple, plain currency + 本日の per-write 価格 subscript
 *
 * @param {number|null} balanceUsdMicro - USD balance × 1e6
 * @param {number} credits - estimatedWrites (色判定用の参考値)
 */
function renderCreditsHtml(balanceUsdMicro, credits) {
  const n = credits ?? 0;
  const usd = (typeof balanceUsdMicro === "number") ? balanceUsdMicro / 1_000_000 : 0;
  let color = "var(--accent)";
  let cta = "";
  let title = i18n_t("app.label.credits_remaining_click_to_buy");
  if (n === 0 || usd <= 0) {
    color = "var(--red)";
    cta = ' <span style="text-decoration:underline;">' + i18n_t("app.misc.purchase_link_html_short") + '</span>';
    title = i18n_t("app.label.no_credits_click_to_buy");
  } else if (n <= LOW_CREDIT_WARN) {
    color = "#FBBF24";
    cta = ' <span style="text-decoration:underline;">' + i18n_t("app.misc.purchase_link_html_plus") + '</span>';
    title = i18n_t("app.label.credits_remaining_n_buy", { n });
  }
  // Phase 7.0w-AN.2: 残高を「整数部を主に、小数部を従に」 visual hierarchy で表示。
  // 整数部: 通常 font、小数部: font-size 0.7em + opacity 0.65 で控えめに。
  // 金融 UI の定番パターン (株価ボード、銀行アプリ、価格タグ等)。
  // 桁固定 (ja=2 桁、他=4 桁)、整数部 thousand separator も維持。
  const lang = i18n_getLang();
  let balanceLabel;
  if (lang === "ja") {
    const JPY_PER_USD = 154;
    const jpy = usd * JPY_PER_USD;
    const formatted = jpy.toLocaleString("ja-JP", {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    });
    const [intPart, decPart] = formatted.split(".");
    balanceLabel = `¥${intPart}<span style="font-size:0.7em; opacity:0.65;">.${decPart}</span>`;
  } else {
    const formatted = usd.toLocaleString("en-US", {
      minimumFractionDigits: 4,
      maximumFractionDigits: 4,
    });
    const [intPart, decPart] = formatted.split(".");
    balanceLabel = `$${intPart}<span style="font-size:0.7em; opacity:0.65;">.${decPart}</span>`;
  }
  // Phase 7.0w-AN: per-write cost を subscript として残す (cost 感覚の参考)
  const perWriteCost = perWriteCostDisplay();
  const subLabel = perWriteCost
    ? `<span style="font-size:13px; opacity:0.85; margin-left:4px;">(${perWriteCost})</span>`
    : "";
  return `<button type="button" data-action="open-purchase-modal" title="${title}" style="background:transparent; border:none; padding:2px 6px; cursor:pointer; color:${color}; text-decoration:none; font-weight:600; font-size:14px;">
            💳 ${balanceLabel}${subLabel}${cta}
          </button>`;
}

/**
 * Phase 7.0w-AN.3: format the per-write cost in user's display currency,
 * 整数部と小数部の visual hierarchy 付き (残高表示と統一)。
 *
 * lang === "ja"      → ¥X.XX/回   (固定 2 桁、整数 thousand separator)
 * その他の language  → $X.XXXX/write (固定 4 桁、整数 thousand separator)
 *
 * 小数部は font-size 0.7em + opacity 0.65 で控えめに表示 (HTML 返り値)。
 * Stripe checkout は getStripeCurrency() で ja=jpy / 他=usd を選択するので、
 * 表示通貨と決済通貨が常に一致する。
 *
 * Returns an HTML string like "¥1<small>.85</small>/回" / "$0<small>.0130</small>/write"
 * or null if unknown.
 */
function perWriteCostDisplay() {
  // Phase 7.5ZN: header display は tier 1 baseline (= LP / pricing.html と同源)。
  // 直近 write が大きいファイルでも header の cost 感覚は base rate を保つ。
  // 実際の課金は tier ごとに変動するが、 disclaimer で説明済み。
  const usd = (typeof state.perWriteUsdBase === "number" && state.perWriteUsdBase > 0)
    ? state.perWriteUsdBase
    : state.perWriteUsd;
  if (typeof usd !== "number" || !(usd > 0)) return null;
  const lang = i18n_getLang();
  const unit = i18n_t("app.label.per_write_unit");

  let formatted;
  let prefix;
  if (lang === "ja") {
    const JPY_PER_USD = 150;  // 表示専用、lp-pricing.js / pricing-main.js と統一 (Phase 7.5ZN)
    const jpy = usd * JPY_PER_USD;
    formatted = jpy.toLocaleString("ja-JP", {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    });
    prefix = "¥";
  } else {
    formatted = usd.toLocaleString("en-US", {
      minimumFractionDigits: 4,
      maximumFractionDigits: 4,
    });
    prefix = "$";
  }
  const [intPart, decPart] = formatted.split(".");
  return `${prefix}${intPart}<span style="font-size:0.78em; opacity:0.7;">.${decPart}</span>${unit}`;
}


/**
 * Phase 5.3: vault のストレージ使用率を header に表示する pill。
 * 80% 超で黄色、95% 超で赤。クリックで簡易説明 alert。
 */
function renderStorageUsageHtml(vault) {
  if (!vault) return "";
  let bytes;
  try { bytes = new TextEncoder().encode(JSON.stringify(vault)).length; }
  catch { return ""; }
  // Phase 6.8.10: 表示は「実用上限 (cheapest tier) = 80 KiB」基準。
  //   < 80 KiB  → tier 1 (cheapest)。% は 80 KiB に対する割合
  //   80-160 KiB → tier 2 (~2x コスト)。% > 100 になるが visually +X% で示す
  //   160-230 KiB → tier 3 (~3x コスト)
  //   > 230 KiB → save block (server reject)
  const softBytes = VAULT_BUCKET_SOFT_BYTES;        // 80 KiB
  const tier2Bytes = VAULT_BUCKET_TIER2_BYTES;      // 160 KiB
  const blockBytes = VAULT_SIZE_BLOCK_BYTES;        // 230 KiB hard cap

  const pctSoft = Math.round((bytes / softBytes) * 100);
  let color = "var(--muted, #94a3b8)";
  let tierLabel = "";
  if (bytes >= blockBytes) {
    color = "var(--red, #ef4444)";
    tierLabel = " 🚫";
  } else if (bytes >= tier2Bytes) {
    color = "var(--red, #ef4444)";
    tierLabel = " ⚠ Tier 3";
  } else if (bytes >= softBytes) {
    color = "#F97316";  // orange-500
    tierLabel = " ⚠ Tier 2";
  } else if (pctSoft >= 75) {
    color = "#FBBF24";  // amber-400
  }
  const kb = (bytes / 1024).toFixed(0);
  const softKb = (softBytes / 1024).toFixed(0);
  const blockKb = (blockBytes / 1024).toFixed(0);
  // 表示する % は「cheapest tier 80 KiB に対する割合」。100 を超えると
  // 次 tier に入っている合図 (色 + tierLabel)。
  const displayPct = Math.min(999, pctSoft);
  const alertMsg = i18n_t("app.alert.drive_size_full", { kb, blockKb, pct: displayPct });
  const titleText = i18n_t("app.label.drive_size_kb_short", { kb, blockKb: softKb });
  const escapedAlert = alertMsg.replace(/&/g, "&amp;").replace(/"/g, "&quot;");
  return `<button type="button" data-action="show-alert" data-alert-msg="${escapedAlert}" title="${titleText}" style="background:transparent; border:none; padding:2px 6px; cursor:pointer; color:${color}; font-weight:500; font-size:13px;">
            📦 ${displayPct}%${tierLabel}
          </button>`;
}

// Last known Arweave status per txid → displayed in header.
const txStatusCache = new Map();

// Phase 5.3-O: tx 状態の単調 (monotonic) 化。
// gateway の間欠 404 / 502 で bundling → not_found 等の i18n_t("app.tx.regression") が起きないよう、
// 「より強い状態を一度観測したら降格させない」ロジック。Arweave は永続なので
// 一度配信されたデータは消えない (false negative はネット側の問題)。
const _STATE_RANK = {
  error: 0,
  not_found: 1,
  bundling: 2,
  pending: 2,
  delivered: 3,  // 旧値、互換のため残す
  confirmed: 4,
};

/**
 * 旧 cache と新観測を比較し、降格になる更新は無視 (= 旧を維持)。
 * 同じ rank の場合は新を採用 (例: bundling → bundling、属性が更新されることがある)。
 * @returns {object} 採用された status (cache に書く前の最終決定)
 */
function _setStatusMonotonic(txid, next) {
  if (!next || typeof next !== "object" || !next.state) {
    // 不正な値は無視 (旧を維持)
    return txStatusCache.get(txid);
  }
  const prev = txStatusCache.get(txid);
  const nextRank = _STATE_RANK[next.state] ?? 0;
  const prevRank = prev?.state ? (_STATE_RANK[prev.state] ?? 0) : -1;
  if (nextRank < prevRank) {
    // 降格: 旧を維持。詳細属性 (latestPoll 等) だけは merge してもよい
    return prev;
  }
  // Phase 7.0e refine v8: cache 更新を records list の該当 badge にも broadcast。
  // 詳細 modal の polling や header polling で status が変わった瞬間、records 一覧の
  // 同 txid の badge も即時更新される (古い「受領未配信」が残らないように)。
  const stateChanged = !prev || prev.state !== next.state;
  txStatusCache.set(txid, next);
  if (stateChanged && typeof updateRecordTxBadges === "function") {
    // microtask で 1 回呼び出し (連続呼出時の DOM thrash 防止)
    queueMicrotask(() => updateRecordTxBadges());
  }
  return next;
}
let txPollTimer = null;

function renderTxStatusHtml(txid) {
  // v5: 暗号化済み blob を Arweave にそのまま渡しているため、生 URL を
  // クリックすると正体不明のバイナリが download されてしまう。これを避けるため、
  // バッジ自体は <button> にして、クリックすると tx 詳細モーダルを開く。
  // モーダル内で技術詳細・ViewBlock リンク等を disclaimer 付きで提供する。
  const short = txid.slice(0, 8) + "…";
  const status = txStatusCache.get(txid);
  let badge, badgeColor = "var(--accent)";
  if (!status) {
    badge = i18n_t("app.tx_detail.state_confirming");
  } else if (status.state === "bundling") {
    badge = i18n_t("app.tx.badge_bundling");
  } else if (status.state === "pending") {
    badge = i18n_t("app.tx.badge_propagating_short");
  } else if (status.state === "confirmed") {
    badge = i18n_t("app.tx.badge_confirmed");
  } else if (status.state === "not_found") {
    // Phase 5.3-X: 「Turbo 受領未配信」= Turbo は受領済み (失われない) だが
    // bundle 未割当で gateway 配信前 (他端末から読めない)。状態を正確に表現。
    badge = i18n_t("app.tx.badge_received");
    badgeColor = "var(--accent)";
  } else if (status.state === "rate_limited") {
    badge = i18n_t("app.tx.badge_paused");
    badgeColor = "var(--muted)";
  } else if (status.state === "error") {
    badge = i18n_t("app.tx.badge_check_failed");
    badgeColor = "var(--muted)";
  } else {
    badge = i18n_t("app.tx.badge_view_details");
    badgeColor = "var(--muted)";
  }
  // Phase 6.7-5: inline onclick は CSP で blocked。data-action で event delegation。
  // 元コードは title=i18n_t(...) と書かれていたが文字列になっていなかったので併せて修正。
  const titleText = i18n_t("app.tx.click_for_details");
  return `
    <button type="button" data-action="open-tx-detail" data-txid="${txid}" title="${titleText}" style="background:transparent; border:1px solid var(--line); border-radius:6px; padding:2px 8px; cursor:pointer; color:${badgeColor}; font-size:13px; display:inline-flex; align-items:center; gap:4px;">
      ${badge} <code style="color:inherit; font-size:12px;">${short}</code>
    </button>
  `;
}

async function pollTxStatusOnce(txid) {
  const observed = await getTxStatus(txid);
  // Phase 5.3-O: 降格を防ぐ単調更新
  const status = _setStatusMonotonic(txid, observed) ?? observed;
  // Phase 7.0p hotfix (429): refreshHeader → fetchVaultStatus → /api/balance は
  // **vault** の tx 状態を表示するためのもの。record file txid の poll では呼ばない
  // (records が N 件あると 1 renderRecordsList で N 回 /api/balance に発火し 429)。
  if (txid && txid === state.latestTxId) {
    const identity = readClientIdentity();
    const el = document.getElementById("header-account");
    if (identity && el) {
      await refreshHeader();
    }
  }
  return status;
}


// Phase 5.3-P: タブにフォーカス復帰時、cache 内の current latest tx を強制再 poll。
// long backoff 中でも即時更新される (= ユーザーが「待ってる間に確認してくれた」UX)
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState !== "visible") return;
  // Phase 7.5c: Stripe 購入完了でタブ復帰したケースを取りこぼさないため、
  //   Add Entry modal が開いていれば必ず credit を refetch する。 polling が
  //   timeout 済 / 動いてない場合の救済。
  try {
    const modalBg = document.getElementById("modal-bg");
    if (modalBg && !modalBg.classList.contains("hidden")) {
      refreshHeader().catch(() => {});
    }
  } catch {}
  for (const txid of txStatusCache.keys()) {
    const cached = txStatusCache.get(txid);
    if (cached?.state === "confirmed" && (cached.confirmations ?? 0) >= 2) continue;
    if (typeof txPollTimer !== "undefined" && txPollTimer) {
      clearTimeout(txPollTimer);
      txPollTimer = null;
    }
    pollTxStatusOnce(txid).then(() => {
      txPollErrorStreak = 0;
      scheduleTxStatusPoll(txid);
    }).catch(() => {});
    break;  // 1 件だけで十分 (latest が最も気になる)
  }
  // Stripe 購入直後の残高 polling 中なら、 タブ復帰時に即 1 回 poll して反映を待たせない
  if (_balancePollTimer && typeof _balancePollTick === "function") {
    _balancePollTick();
  }
});

// Consecutive-error / rate-limit backoff. Resets to 0 on any non-error response.
let txPollErrorStreak = 0;
const MAX_TX_POLL_ERRORS = 30;  // Phase 5.3-P: not_found backoff (max 5min) で 30 回 = ~2 時間継続

function scheduleTxStatusPoll(txid) {
  if (txPollTimer) clearTimeout(txPollTimer);
  const status = txStatusCache.get(txid);
  // Stop polling once we have ≥2 confirmations — the tx is safely permanent.
  if (status?.state === "confirmed" && (status.confirmations ?? 0) >= 2) {
    txPollErrorStreak = 0;
    return;
  }
  // Give up for the session if the gateway has been unreachable repeatedly.
  if (txPollErrorStreak >= MAX_TX_POLL_ERRORS) {
    return;
  }

  let delay;
  if (status?.state === "rate_limited") {
    // Respect Retry-After, but never poll more frequently than once a minute.
    delay = Math.max(60_000, (status.retryAfterSeconds ?? 60) * 1000);
  } else if (status?.state === "error") {
    // Exponential backoff: 30s, 60s, 120s, 240s, 480s
    delay = Math.min(480_000, 30_000 * Math.pow(2, txPollErrorStreak));
  } else if (status?.state === "confirmed") {
    delay = 120_000; // 2 min between "any confirmation" and "deeply confirmed"
  } else if (status?.state === "not_found") {
    // Phase 5.3-P: 5s → 10s → 20s → 60s → 120s → 300s (Phase 7.5e で前半短縮)
    const backoff = [5, 10, 20, 60, 120, 300];
    delay = (backoff[Math.min(txPollErrorStreak, backoff.length - 1)]) * 1000;
  } else if (status?.state === "bundling") {
    // Phase 7.5e: bundling 状態 = Turbo CDN で取れる状態。 user が画面を
    // 見ている時に「Turbo配信中」のまま 60s 待たされるのは UX 悪い。 15s に
    // 短縮 (= Arweave block 昇格は通常 30-60s で起きるので 1-2 周期で確認可能)。
    delay = 15_000;
  } else if (!status) {
    // Phase 5.3-Q: 初回 poll を 8s → 2s に短縮。「⏳ 確認中」表示時間を最小化。
    delay = 2_000;
  } else {
    // pending — Phase 7.5e: 30s → 10s (= 確認反映を高速化、 各 user 個別 polling
    // で gateway 負荷も限定的)。
    delay = 10_000;
  }

  txPollTimer = setTimeout(async () => {
    const next = await pollTxStatusOnce(txid);
    if (next.state === "rate_limited" || next.state === "error" || next.state === "not_found") {
      txPollErrorStreak += 1;
    } else {
      txPollErrorStreak = 0;
    }
    if (next.state !== "confirmed" || (next.confirmations ?? 0) < 2) {
      scheduleTxStatusPoll(txid);
    }
  }, delay);
}

// =====================================================================
// Utility
// =====================================================================
function escape(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[c]);
}

// =====================================================================
// Init
// =====================================================================
// =====================================================================
// Phase 7.1-W: Profile picker — routing + handlers
// =====================================================================

async function _routeOnStartup({ forcePicker = false } = {}) {
  // Phase 7.1-AE.3 撤回 (2026-06-06): 起動時 auto-prune を削除。
  //   理由: prune が false positive で使える vault を消す事例が user 実機で発生した。
  //   代替: Phase 7.1-AD の picker 赤バッジ + 手動削除 UI で「使えない profile」 を
  //         user に判断させる方が安全。 _pruneEmptyProfiles() は手動呼出 用に
  //         関数定義のみ残す (= 必要なら debug console 等から呼べる)。
  const { listProfiles, getActiveProfileId, setActiveProfileId } = await import("/lib/profiles.js?v=5ef6de24");
  const profiles = listProfiles();

  // Detect invite URL — もし profile が既に 1+ ある状態で invite を踏んだなら
  // 「会社用 profile を新規作成しますか?」を picker 経由で誘導する。
  const hasInvite = !!_inviteCode;

  if (profiles.length === 0) {
    // 完全新規 user — 古い flow (= signup view) へ。
    // signup 完了時に createProfile + setActiveProfileId が呼ばれる。
    showView("create");
    return;
  }

  if (profiles.length === 1 && !hasInvite && !forcePicker) {
    // 1 profile only + 起動時 → 自動選択 → unlock
    setActiveProfileId(profiles[0].id);
    _showUnlockOrCreate();
    return;
  }

  // 2+ profiles / invite / 明示的切替要求 → picker
  _renderProfilePicker(profiles, hasInvite);
}

function _renderProfilePicker(profiles, hasInvite) {
  const list = document.getElementById("picker-list");
  if (!list) { showView("create"); return; }
  list.innerHTML = "";
  for (const p of profiles) {
    // Phase 7.1-AD: 空 meta (outerKey/vaultId 無し) の profile は赤枠で表示し、
    // クリック時は unlock view に行く代わりに「これは空です、削除しますか?」
    // を出す。誤った migration / 中断された signup の救済用 UI。
    const metaRaw = localStorage.getItem(`arpass_vault_meta_v5__${p.id}`);
    let isEmpty = false;
    try {
      const meta = JSON.parse(metaRaw || "null");
      isEmpty = !meta || (typeof meta === "object" && !meta.appNameTag && !meta.vaultId);
    } catch { isEmpty = true; }

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "btn-outline";
    btn.style.cssText = "width:100%; padding:14px 16px; text-align:left; display:flex; align-items:center; justify-content:space-between; gap:12px;" +
      (isEmpty ? " border-color:#DC2626; background:#FEF2F2;" : "");
    const icon = p.kind === "admin" ? "🏢" : p.kind === "corp" ? "🏬" : "🏠";
    const emptyBadge = isEmpty
      ? ` <span style="background:#DC2626; color:#fff; padding:1px 6px; border-radius:3px; font-size:10px; margin-left:6px;">${i18n_t("app.picker.empty_profile_badge") || "空 (使用不可)"}</span>`
      : "";
    const labelHtml = `<span style="font-weight:600; font-size:14px;">${icon} ${escapeHtml(p.label)}${emptyBadge}</span>`;
    const subHtml = `<span style="font-size:11px; opacity:0.6;">${(p.lastUsedAt || "").slice(0, 10)}</span>`;
    btn.innerHTML = `<div>${labelHtml}<br><span style="font-size:11px; opacity:0.5;">${escapeHtml(p.kind)}${p.companyId ? " — " + escapeHtml(p.companyId.slice(0,8)) : ""}</span></div>${subHtml}`;
    btn.addEventListener("click", async () => {
      const { setActiveProfileId, deleteProfile } = await import("/lib/profiles.js?v=5ef6de24");
      if (isEmpty) {
        const ok = confirm(
          (i18n_t("app.picker.empty_profile_delete_confirm") ||
           "この profile (\"{label}\") は vault データが空で使用できません。\n\n削除しますか?\n(削除しても Arweave 上のデータは影響されません)")
          .replace("{label}", p.label)
        );
        if (ok) {
          deleteProfile(p.id);
          _routeOnStartup();
        }
        return;
      }
      setActiveProfileId(p.id);
      _showUnlockOrCreate();
    });
    list.appendChild(btn);
  }
  showView("picker");

  // invite banner — まだ invite を消費していない場合のみ
  if (hasInvite) {
    const note = document.createElement("div");
    note.style.cssText = "background:#FEF3C7; border-left:3px solid #F59E0B; padding:10px 12px; border-radius:6px; margin-top:14px; font-size:13px; line-height:1.6;";
    note.innerHTML = (i18n_t("app.picker.invite_hint") ||
      "📨 会社からの招待 URL を検知しました。「+ 新しいドライブを追加」から会社用の別ドライブを作成してください (既存のドライブは影響を受けません)。");
    list.appendChild(note);
  }
}

function _showUnlockOrCreate() {
  if (!hasVaultIdentity()) {
    showView("create");
  } else if (readMeta()?.mode === "hwkey") {
    // envelope v7 増分2: YubiKey 専用 vault — パスワード欄を隠し YubiKey 解錠に。
    showView("unlock");
    _applyHwkeyUnlockView();
    refreshHeader().catch(() => {});
  } else {
    showView("unlock");
    if (hasPasskey() || getVaultAlg() === "pbkdf2+prf-hkdf-aes256gcm") {
      document.getElementById("unlock-passkey-hint").classList.remove("hidden");
      document.getElementById("unlock-subtitle").textContent =
        i18n_t("app.unlock.subtitle_password_with_passkey");
    }
    document.getElementById("unlock-pw").focus();
    refreshHeader().catch(() => {});
  }
}

// envelope v7 増分2: view-unlock を hwkey (YubiKey 専用) 用に切り替える。
//   パスワード欄・パスキーヒントを隠し、subtitle / ボタンを YubiKey 用に。
function _applyHwkeyUnlockView() {
  const pw = document.getElementById("unlock-pw");
  if (pw) {
    pw.classList.add("hidden");
    pw.value = "";
    const pwLabel = document.querySelector('label[for="unlock-pw"]');
    if (pwLabel) pwLabel.classList.add("hidden");
  }
  document.getElementById("unlock-passkey-hint")?.classList.add("hidden");
  const sub = document.getElementById("unlock-subtitle");
  if (sub) sub.textContent = i18n_t("app.unlock.subtitle_hwkey");
  const btn = document.getElementById("unlock-btn");
  if (btn) btn.textContent = i18n_t("app.unlock.btn_hwkey");
}

// envelope v7 増分2: YubiKey 専用モードの作成フロー
document.getElementById("goto-hwkey-create")?.addEventListener("click", (e) => {
  e.preventDefault();
  if (_isMacSafari()) {
    // Mac Safari は WebAuthn 仕様差で他ブラウザ/他端末と共有不可。
    //   ブロックはせず注意喚起のみ (作成は許可)。
    toast(i18n_t("app.hwkey.mac_safari_unsupported"), "warn", 14000);
  }
  showView("create-hwkey");
});
// envelope v7 増分2: 別の端末に YubiKey を持ってきたときの「この端末で開く」。
//   unlockWithHwkey は localStorage meta 不要 — YubiKey の userHandle が運ぶ
//   keyslot 所在タグから Arweave 上の keyslot blob と vault を辿り、解錠後に
//   meta をこの端末へ書き込むところまで自己完結する。
// envelope v7 増分2: 別端末で YubiKey からドライブを開く。
//   Safari は WebAuthn get() ごとに新しいユーザー操作を要求するため、
//   PRF が 1 回の get で取れない場合は「もう一度タップ」に分ける。
let _hwkeyUnlockBusy = false;

// envelope v7 増分2: Mac の Safari 判定。 Mac Safari は WebAuthn PRF が
//   他ブラウザと非互換で YubiKey モードが使えない (= keyslot 復号不可)。
//   iPad は UA が "Macintosh" になるため maxTouchPoints で実機 Mac と区別。
function _isMacSafari() {
  try {
    const ua = navigator.userAgent || "";
    const isApple = /Macintosh|Mac OS X/.test(ua);
    const isIOS = /iPhone|iPad|iPod/.test(ua);
    const isRealMac = isApple && !isIOS && (navigator.maxTouchPoints || 0) <= 1;
    const isSafari = /Safari\//.test(ua) &&
      !/(Chrome|Chromium|CriOS|Edg|EdgiOS|OPR|OPiOS|FxiOS|Firefox)/.test(ua);
    return isRealMac && isSafari;
  } catch { return false; }
}

// Phase 7.5S: Android Chrome の CredentialManager API は USB security key
//   経由の WebAuthn PRF 拡張をまだ完全サポートしていない (Chrome 132+ で
//   段階的対応)。 加えて PIN 設定済 YubiKey では UV モード差で PRF 値が
//   別物になるため、 iPhone で作った hwkey vault は Android Chrome で
//   開けない (現状の不可避制限)。
//   user に 「Mac/PC Chrome 推奨」 を事前案内するために検知 helper を用意。
function _isAndroid() {
  try {
    return /Android/i.test(navigator.userAgent || "");
  } catch { return false; }
}

async function _finishHwkeyUnlock(r) {
  state.vault = r.vault;
  state.latestTxId = r.latestTxId;
  await refreshHeader();
  renderList();
  showView("vault");
  initSaveDebounce({
    saveVault,
    onStatus: (st, info) => updateSaveStatusBadge(st, info),
    beforeUnloadMessage: i18n_t("app.confirm.beforeunload_unsaved"),
  });
  toast(i18n_t("app.hwkey_unlock.done"), "ok");
}

// envelope v7 増分2: hwkey 解錠の共通フロー (discoverable 2 タップ)。
//   同一端末・新端末どちらも同じ。 picker get (allowCredentials 空) は
//   iPhone/Mac Safari でも素直に YubiKey に直行する。 一方 specific get
//   (meta.credentialId 名指し) は iPhone Safari で「資格情報が見つかりません」
//   を出すため使わない。
//   1 回目: YubiKey を特定。 2 回目: その鍵を名指しして PRF を取得 → 解錠。
//     (PRF は必ず specific get で取る。 picker get の PRF は keyslot と
//      一致しないことがある。)
//   btn: 文言切替の対象要素 / err: エラー表示要素 / idleLabel: 通常時の文言。
async function _hwkeyUnlockFlow(btn, err, idleLabel) {
  if (_hwkeyUnlockBusy) return;
  _hwkeyUnlockBusy = true;
  if (err) err.classList.add("hidden");
  if (btn) {
    btn.style.pointerEvents = "none";
    btn.style.opacity = "0.6";
    btn.textContent = i18n_t("app.hwkey_unlock.checking");
  }
  // Phase 7.5P: 段階別 progress + console.time で「どこが遅いか」を可視化
  const _t0 = performance.now();
  const _phase = (key) => {
    const dt = Math.round(performance.now() - _t0);
    // Phase 7.5P: vault-client.js から phase キーが渡ってくる場合は i18n_t で解決
    const label = (typeof key === "string" && /^phase_/.test(key))
      ? (i18n_t("app.hwkey_unlock." + key) || key)
      : key;
    console.log("[hwkey-unlock] +" + dt + "ms — " + label);
    if (btn) btn.textContent = label;
  };
  try {
    _phase("phase_passkey");
    const a = await hwkeyAuthenticateForUnlock();
    _phase("phase_lookup");
    const { createProfile, setActiveProfileId, getActiveProfileId } = await import("/lib/profiles.js?v=5ef6de24");
    if (!getActiveProfileId()) {
      setActiveProfileId(createProfile({ kind: "personal", label: "YubiKey" }).id);
    }
    // unlockWithHwkeyAuthed が内部で更に細かい段階を出すように設定
    a.__onPhase = _phase;
    await _finishHwkeyUnlock(await unlockWithHwkeyAuthed(a));
    console.log("[hwkey-unlock] DONE total=" + Math.round(performance.now() - _t0) + "ms");
  } catch (e2) {
    console.warn("[hwkey-unlock] failed:", e2?.name, e2?.code, e2?.message);
    if (err) {
      if (e2?.name === "NotAllowedError") {
        err.textContent = i18n_t("app.error.passkey_cancelled");
      } else if (e2?.code === "hwkey_wrong_passkey_type") {
        err.textContent = i18n_t("app.hwkey_unlock.wrong_key");
      } else if (e2?.code === "hwkey_not_propagated") {
        err.textContent = i18n_t("app.hwkey_unlock.not_propagated");
      } else if (e2?.code === "hwkey_keyslot_decrypt_failed" && _isMacSafari()) {
        // Mac Safari は WebAuthn 仕様差で他ブラウザ作成の vault を開けない。
        //   「共有不可」の注意文言で理由を説明する。
        err.textContent = i18n_t("app.hwkey.mac_safari_unsupported");
      } else {
        err.textContent = `${i18n_t("app.hwkey_unlock.err")} (${e2?.code || e2?.message || String(e2)})`;
      }
      err.classList.remove("hidden");
    }
  } finally {
    _hwkeyUnlockBusy = false;
    if (btn) {
      btn.style.pointerEvents = "";
      btn.style.opacity = "";
      btn.textContent = idleLabel;
    }
  }
}

document.getElementById("goto-hwkey-unlock")?.addEventListener("click", (e) => {
  e.preventDefault();
  if (_isMacSafari()) {
    // Mac Safari は共有不可。 ブロックはせず注意喚起のみ (解錠は続行)。
    toast(i18n_t("app.hwkey.mac_safari_unsupported"), "warn", 14000);
  }
  // Phase 7.5T: Android Chrome 検知は残すが、 過剰警告は外す。
  //   user 報告で 「以前は Android 動いていた」 とのこと → 軽率な「未対応」 表示は
  //   逆効果。 unlock を素直に試行し、 失敗時のエラーから原因を切り分ける。
  _hwkeyUnlockFlow(
    document.getElementById("goto-hwkey-unlock"),
    document.getElementById("create-error"),
    i18n_t("app.create.goto_hwkey_unlock"),
  );
});
document.getElementById("hwkey-create-back")?.addEventListener("click", () => {
  showView("create");
});
document.getElementById("hwkey-create-btn")?.addEventListener("click", async () => {
  const err  = document.getElementById("hwkey-create-error");
  const prog = document.getElementById("hwkey-create-progress");
  err.classList.add("hidden");
  if (!document.getElementById("hwkey-ack")?.checked) {
    err.textContent = i18n_t("app.hwkey_create.err_ack");
    err.classList.remove("hidden");
    return;
  }
  const keyCount = parseInt(document.getElementById("hwkey-count")?.value, 10) || 2;
  const btn = document.getElementById("hwkey-create-btn");
  btn.disabled = true;
  btn.innerHTML = `<span class="spin"></span> ${i18n_t("app.hwkey_create.creating")}`;
  try {
    const { createProfile, setActiveProfileId, getActiveProfileId } = await import("/lib/profiles.js?v=5ef6de24");
    if (!getActiveProfileId()) {
      const p = createProfile({ kind: "personal", label: "YubiKey" });
      setActiveProfileId(p.id);
    }
    const r = await createHwkeyVault(keyCount, _defaultPasskeyDisplayName(), _turnstileToken, {
      onBeforeKey: (i, total) => {
        prog.classList.remove("hidden");
        // 2 本目以降は、同じ鍵を二重登録しないよう差し替えを待つ。
        if (i > 0) {
          const ok = confirm(i18n_t("app.hwkey_create.swap_prompt", { n: i + 1, total }));
          if (!ok) throw new Error("cancelled");
        }
        prog.textContent = i18n_t("app.hwkey_create.progress", { n: i + 1, total });
      },
    });
    prog.classList.add("hidden");
    state.vault = r.vault;
    state.latestTxId = r.latestTxId;
    await refreshHeader();
    renderList();
    showView("vault");
    initSaveDebounce({
      saveVault,
      onStatus: (st, info) => updateSaveStatusBadge(st, info),
      beforeUnloadMessage: i18n_t("app.confirm.beforeunload_unsaved"),
    });
    toast(i18n_t("app.hwkey_create.done"), "ok");
  } catch (e) {
    prog.classList.add("hidden");
    console.warn("[hwkey-create] failed:", e?.name, e?.message);
    showSaveError(err, e, i18n_t("app.error.failed"));
  } finally {
    btn.disabled = false;
    btn.textContent = i18n_t("app.hwkey_create.button");
  }
});

// ロック画面 → picker に戻る (= プロファイル切替)
document.getElementById("unlock-switch-profile-link")?.addEventListener("click", async (e) => {
  e.preventDefault();
  const { clearActiveProfile } = await import("/lib/profiles.js?v=5ef6de24");
  clearActiveProfile();
  _routeOnStartup({ forcePicker: true });
});

// 「+ 新しいドライブを追加」 — picker 内で発火
document.getElementById("picker-new-btn")?.addEventListener("click", async () => {
  // Phase 7.1-W hotfix (2026-06-06): ここで createProfile しない。
  //   理由: user が create view でリロード / 戻る すると 「空 profile」 が picker に残り、
  //   繰り返すと husk が増える regression があった。
  //   createProfile は create-btn click 時 (= line ~1177 のフォールバック) で行う。
  const { clearActiveProfile } = await import("/lib/profiles.js?v=5ef6de24");
  clearActiveProfile();
  _renderCreateBackToPicker();
  showView("create");
});

// Phase 7.1-W hotfix (2026-06-06): create view 上の 「← ドライブ一覧に戻る」 link
async function _renderCreateBackToPicker() {
  const { listProfiles } = await import("/lib/profiles.js?v=5ef6de24");
  const profiles = listProfiles();
  const el = document.getElementById("create-back-to-picker");
  if (!el) return;
  // profile が 1 つ以上ある場合のみ link を表示 (= 0 個なら戻る先がない)
  if (profiles.length >= 1) el.classList.remove("hidden");
  else el.classList.add("hidden");
}

document.getElementById("create-back-to-picker-link")?.addEventListener("click", (e) => {
  e.preventDefault();
  _routeOnStartup({ forcePicker: true });
});

// Phase 7.1-AC: 「📲 機種追加コードで復旧」 picker 内で発火
// Phase 7.1-AE: 統一入口 _startBusinessJoinFlow に差し替え (招待 / 機種追加 共通)
document.getElementById("picker-device-add-btn")?.addEventListener("click", async () => {
  await _startBusinessJoinFlow();
});

// Phase 7.1-AD: create view (= 0 profile 状態) からも入れる
document.getElementById("create-device-add-btn")?.addEventListener("click", async () => {
  await _startBusinessJoinFlow();
});
// Phase 7.1-AG: device-add redeem view ボタン handler
document.getElementById("dar-submit")?.addEventListener("click", async () => {
  const codeEl = document.getElementById("dar-code");
  const nameEl = document.getElementById("dar-devicename");
  const pwEl = document.getElementById("dar-master");
  const submitBtn = document.getElementById("dar-submit");
  const errEl = document.getElementById("dar-error");
  errEl?.classList.add("hidden");

  const code = (codeEl?.value || "").trim();
  const displayName = ((nameEl?.value || "").trim() || "新端末").slice(0, 100);
  const masterPw = pwEl?.value || "";

  if (code.length < 6 || code.length > 16) {
    _dar_showError(i18n_t("app.device_add.code_format_error") || "コード形式が不正です (6-16 文字)");
    codeEl?.focus();
    return;
  }
  if (!masterPw) {
    _dar_showError(i18n_t("app.device_add.master_required") || "マスターパスワードを入力してください");
    pwEl?.focus();
    return;
  }
  if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = i18n_t("app.device_add.submitting") || "コード送信中…"; }
  try {
    await _dar_runRedeem({ code, displayName, masterPw });
  } finally {
    if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = i18n_t("app.device_add.submit_btn") || "✅ コードで取得"; }
  }
});

document.getElementById("dar-cancel-form")?.addEventListener("click", () => {
  _routeOnStartup({ forcePicker: true });
});


// Phase 7.1-AE.3: 空 (vault_meta が outerKey/vaultId を持たない) profile を一括削除。
// signup 中断、createVault 失敗等で残った husk を放置せず prune する。返り値は削除件数。
async function _pruneEmptyProfiles() {
  const { listProfiles, deleteProfile } = await import("/lib/profiles.js?v=5ef6de24");
  const profiles = listProfiles();
  let pruned = 0;
  for (const p of profiles) {
    const metaRaw = localStorage.getItem(`arpass_vault_meta_v5__${p.id}`);
    let isEmpty = false;
    try {
      const meta = JSON.parse(metaRaw || "null");
      isEmpty = !meta || (typeof meta === "object" && !meta.appNameTag && !meta.vaultId);
    } catch { isEmpty = true; }
    if (isEmpty) {
      try { deleteProfile(p.id); pruned++; } catch (e) { console.warn("[prune] delete failed:", p.id, e?.message); }
    }
  }
  if (pruned > 0) console.log(`[prune] removed ${pruned} empty profile(s)`);
  return pruned;
}

// Phase 7.1-AE: 統一入口 — 招待コード (新規) と機種追加コード (2台目以降) を
// 同じプロンプトで受け、フォーマットで自動分岐する。
//   - ARPASS-XXXX-XXXX (BASE32, ハイフン区切り) → 新規 signup (URL ?invite=... と同等の flow)
//   - 8 文字 b64u-safe        → 機種追加 (= device-add redeem)
async function _startBusinessJoinFlow() {
  try {
    // Phase 7.1-AE.3 撤回 (2026-06-06): auto-prune 削除。 上 _routeOnStartup の注釈参照。
    const code = window.prompt(
      i18n_t("app.business_join.prompt_code"),
      ""
    );
    if (!code) return;
    const c = code.trim();

    // Format 判別
    const isInviteFormat = /^ARPASS-[A-Z0-9]+-[A-Z0-9]+$/i.test(c);
    const isDeviceAddFormat = /^[A-Za-z0-9_-]{6,16}$/.test(c) && !isInviteFormat;

    if (isInviteFormat) {
      // 新規社員 signup フロー: _inviteCode を set して create view に行く
      _inviteCode = c.toUpperCase();
      const { createProfile, setActiveProfileId } = await import("/lib/profiles.js?v=5ef6de24");
      const profile = createProfile({ kind: "corp", label: i18n_t("app.business_join.profile_label_pending") });
      setActiveProfileId(profile.id);
      // create view に行くと createVault({mode:'business'}) が動く (_inviteCode の存在で分岐)
      _renderInviteBanner();
      showView("create");
      toast(i18n_t("app.business_join.toast_invite_detected"), "info", 6000);
    } else if (isDeviceAddFormat) {
      // 機種追加 (= 2 台目以降): 既存 device-add redeem flow に pre-fill で投入
      await _startDeviceAddRedeemFlow(c);
    } else {
      alert(i18n_t("app.business_join.code_format_error"));
    }
  } catch (e) {
    // Phase 7.1-AE.2: silent failure を防ぐため try/catch でエラー可視化
    console.error("[business-join] flow failed:", e);
    alert((i18n_t("app.business_join.flow_error_prefix") || "エラー: ") + (e?.message || String(e)));
  }
}

async function _startDeviceAddRedeemFlow(preFilledCode = null) {
  // Phase 7.1-AG: prompt() 連発を廃止し、view-device-add-redeem の form/progress UI を使う。
  const formWrap = document.getElementById("dar-form-wrap");
  const progressWrap = document.getElementById("dar-progress-wrap");
  const codeEl = document.getElementById("dar-code");
  const nameEl = document.getElementById("dar-devicename");
  const pwEl = document.getElementById("dar-master");
  const errEl = document.getElementById("dar-error");
  const submitBtn = document.getElementById("dar-submit");

  // 初期化: form 表示、入力欄リセット
  errEl?.classList.add("hidden");
  if (formWrap) formWrap.classList.remove("hidden");
  if (progressWrap) progressWrap.classList.add("hidden");
  if (codeEl) codeEl.value = preFilledCode || "";
  if (nameEl) nameEl.value = _defaultPasskeyDisplayName() || "新端末";
  if (pwEl) pwEl.value = "";
  if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = i18n_t("app.device_add.submit_btn") || "✅ コードで取得"; }

  showView("deviceAddRedeem");
  // 最初に focus すべき欄
  if (preFilledCode) {
    (pwEl || nameEl || codeEl)?.focus();
  } else {
    codeEl?.focus();
  }
}

// Phase 7.1-AG: 送信処理は submit button 経由 (= 既存 prompt() 連発を分離)
async function _dar_runRedeem({ code, displayName, masterPw }) {
  const errEl = document.getElementById("dar-error");
  const formWrap = document.getElementById("dar-form-wrap");
  const progressWrap = document.getElementById("dar-progress-wrap");
  const progressMsg = document.getElementById("dar-progress-msg");
  const pollStatus = document.getElementById("dar-poll-status");
  const countdownEl = document.getElementById("dar-countdown");

  // 1. ephemeral key
  let ephemeral;
  try {
    ephemeral = await generateEphemeralSigningState();
  } catch (e) {
    _dar_showError((i18n_t("app.device_add.ephemeral_failed") || "鍵生成失敗: ") + (e?.message || e));
    return;
  }
  const newDevicePubKeyB64 = b64uEncode(ephemeral.publicKeyRaw);

  // 2. redeem
  let redeemRes;
  try {
    redeemRes = await corpDeviceAddRedeemUI({ code, newDevicePubKey: newDevicePubKeyB64, displayName });
  } catch (e) {
    _dar_showError((i18n_t("app.device_add.redeem_failed") || "コード引き換え失敗: ") + (e?.message || e));
    return;
  }

  // 3. form → progress mode へ
  if (formWrap) formWrap.classList.add("hidden");
  if (progressWrap) progressWrap.classList.remove("hidden");
  if (progressMsg) {
    progressMsg.textContent = redeemRes.autoApprove
      ? (i18n_t("app.device_add.progress_msg_auto") || "コード受領。admin の自動承認を待っています…")
      : (i18n_t("app.device_add.progress_msg_manual") || "コード受領。admin の手動承認をお待ちください。 admin のアプリが起動中だと数秒〜数分で完了します。");
  }

  // 4. polling: 10 分まで、5 秒毎に inbox 確認、count-down 表示
  const startedAt = Date.now();
  const TIMEOUT_MS = 10 * 60 * 1000;
  let recoveryStr = null;
  let cancelled = false;

  // cancel button setup
  const cancelBtn = document.getElementById("dar-cancel-progress");
  const cancelHandler = () => { cancelled = true; };
  cancelBtn?.addEventListener("click", cancelHandler, { once: true });

  // count-down ticker
  const tickInterval = setInterval(() => {
    const remaining = TIMEOUT_MS - (Date.now() - startedAt);
    if (remaining <= 0) { clearInterval(tickInterval); return; }
    const m = Math.floor(remaining / 60000);
    const s = Math.floor((remaining % 60000) / 1000);
    if (countdownEl) countdownEl.textContent = `${m}:${s.toString().padStart(2, "0")}`;
  }, 1000);

  try {
    let pollCount = 0;
    while (Date.now() - startedAt < TIMEOUT_MS && !cancelled) {
      pollCount++;
      if (pollStatus) pollStatus.textContent = (i18n_t("app.device_add.poll_status_polling") || "承認確認中") + ` (${pollCount})`;
      await new Promise(r => setTimeout(r, 5000));
      if (cancelled) break;
      try {
        const inbox = await corpRelayInboxWithStateUI(ephemeral);
        const grant = (inbox?.items || []).find(it => it.kind === "recovery-grant");
        if (grant) {
          // ECIES decrypt
          const wrappedBytes = b64uDecode(grant.payload);
          const wrapped = JSON.parse(new TextDecoder().decode(wrappedBytes));
          const eciesPayload = {
            ephemeralPublicKey: b64uDecode(wrapped.ephemeralPublicKey),
            iv:                 b64uDecode(wrapped.iv),
            ciphertext:         b64uDecode(wrapped.ciphertext),
          };
          const { eciesDecrypt } = await import("/lib/vault-crypto.js?v=11331c7d");
          const ptBytes = await eciesDecrypt(ephemeral.eciesPrivateRaw, eciesPayload);
          const ptStr = new TextDecoder().decode(ptBytes);
          try {
            const obj = JSON.parse(ptStr);
            recoveryStr = obj?.recovery || ptStr;
          } catch {
            recoveryStr = ptStr;
          }
          try { await corpRelayAckWithStateUI(ephemeral, grant.id); } catch (e) { console.warn("ack failed:", e?.message); }
          break;
        }
      } catch (e) {
        console.warn("[device-add] inbox poll error:", e?.message);
      }
    }
  } finally {
    clearInterval(tickInterval);
  }

  if (cancelled) {
    toast(i18n_t("app.device_add.toast_cancelled") || "機種追加をキャンセルしました", "info", 4000);
    _routeOnStartup({ forcePicker: true });
    return;
  }
  if (!recoveryStr) {
    _dar_showError(i18n_t("app.device_add.poll_timeout") || "admin の承認待ちタイムアウト (10 分)。\nadmin に承認を依頼するか、再度コード発行してもらってください。");
    // form モードに戻す
    if (progressWrap) progressWrap.classList.add("hidden");
    if (formWrap) formWrap.classList.remove("hidden");
    return;
  }

  if (pollStatus) pollStatus.textContent = i18n_t("app.device_add.poll_status_received") || "Recovery 受信 → vault 開錠中…";

  // 5. profile 作成 + unlock + Passkey 登録
  try {
    const { createProfile, setActiveProfileId } = await import("/lib/profiles.js?v=5ef6de24");
    const profile = createProfile({ kind: "corp", label: i18n_t("app.device_add.profile_label") || "会社" });
    setActiveProfileId(profile.id);
    const { vault, latestTxId } = await unlockWithPasswordAndRecovery(masterPw, recoveryStr);
    state.password = masterPw;
    state.vault = vault;
    state.latestTxId = latestTxId;
    state.readOnly = false;
    initSaveDebounce({
      saveVault,
      onStatus: (s, info) => updateSaveStatusBadge(s, info),
      beforeUnloadMessage: i18n_t("app.confirm.beforeunload_unsaved"),
    });
    try {
      await addCredentialOnThisDevice(masterPw, displayName, { deferSave: true });
      scheduleSave(state.vault);
      toast(i18n_t("app.device_add.toast_done") || "✅ 新端末を登録しました。次回からは Master + Passkey で開錠できます", "ok", 8000);
    } catch (passkeyErr) {
      console.warn("[device-add] passkey register failed:", passkeyErr);
      toast(i18n_t("app.toast.unlock_ok_passkey_failed") || "解錠成功。Passkey 登録は後で設定 → 「🔐 この端末の Passkey を登録」から行ってください", "warn", 10000);
    }
    await refreshHeader();
    renderList();
    showView("vault");
  } catch (e) {
    _dar_showError((i18n_t("app.device_add.unlock_failed") || "Vault 開錠失敗: ") + (e?.message || e) + "\n(Master パスワードが違うか、Recovery と vault が一致しません)");
    if (progressWrap) progressWrap.classList.add("hidden");
    if (formWrap) formWrap.classList.remove("hidden");
  }
}

function _dar_showError(msg) {
  const errEl = document.getElementById("dar-error");
  if (errEl) {
    errEl.textContent = msg;
    errEl.classList.remove("hidden");
  } else {
    alert(msg);
  }
}


// 「削除」モード — picker 内
document.getElementById("picker-delete-mode-btn")?.addEventListener("click", async () => {
  const { listProfiles, deleteProfile } = await import("/lib/profiles.js?v=5ef6de24");
  const profiles = listProfiles();
  if (profiles.length === 0) return;
  const labels = profiles.map((p, i) => `${i + 1}. ${p.label} (${p.kind}${p.companyId ? " — " + p.companyId.slice(0,8) : ""})`).join("\n");
  const ans = window.prompt(
    (i18n_t("app.picker.delete_prompt") ||
     "削除するドライブの番号を入力してください (取消不能、localStorage の該当 namespace を全消去):\n\n") + labels,
    ""
  );
  if (!ans) return;
  const idx = parseInt(ans.trim(), 10) - 1;
  if (idx < 0 || idx >= profiles.length || isNaN(idx)) return;
  const target = profiles[idx];
  if (!confirm((i18n_t("app.picker.delete_confirm") || "本当に削除しますか? ") + target.label)) return;
  deleteProfile(target.id);
  toast(i18n_t("app.picker.delete_done") || "削除しました", "ok", 3000);
  // re-render
  _routeOnStartup();
});


/**
 * Phase 7.2-B (α): inline modal で新 Master password を入力させる。
 * password 型 input + 二重確認 + 8 文字バリデーション付き。
 *
 * @param {string} title       (heading text)
 * @param {string} hint        (subtitle text)
 * @returns {Promise<string|null>}  確定なら新 password、 キャンセルなら null
 */
function _promptNewMasterPassword(title, hint) {
  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.style.cssText = "position:fixed; inset:0; background:rgba(0,0,0,0.5); z-index:9999; display:flex; align-items:center; justify-content:center; padding:16px;";
    const box = document.createElement("div");
    box.style.cssText = "background:white; border-radius:12px; padding:20px; max-width:420px; width:100%; box-shadow:0 8px 32px rgba(0,0,0,0.2); font-family:inherit;";
    box.innerHTML = `
      <h3 style="margin:0 0 8px; font-size:16px; font-weight:600;">${title}</h3>
      <p style="margin:0 0 14px; font-size:13px; color:#555; line-height:1.5;">${hint}</p>
      <label style="display:block; font-size:12px; margin-bottom:4px;">${i18n_t("app.label.new_master") || "新しい Master Password"}</label>
      <input type="password" id="_pmpw1" autocomplete="new-password" style="width:100%; padding:8px 10px; border:1px solid #ccc; border-radius:6px; font-size:14px; margin-bottom:10px; box-sizing:border-box;" >
      <label style="display:block; font-size:12px; margin-bottom:4px;">${i18n_t("app.label.confirm_master") || "もう一度入力 (確認)"}</label>
      <input type="password" id="_pmpw2" autocomplete="new-password" style="width:100%; padding:8px 10px; border:1px solid #ccc; border-radius:6px; font-size:14px; margin-bottom:8px; box-sizing:border-box;">
      <p id="_pmpwErr" style="margin:0 0 12px; color:#dc2626; font-size:12px; min-height:1.2em;"></p>
      <div style="display:flex; gap:8px; justify-content:flex-end;">
        <button type="button" id="_pmpwCancel" style="padding:8px 14px; border:1px solid #ccc; background:white; border-radius:6px; cursor:pointer; font-size:13px;">${i18n_t("app.button.cancel") || "キャンセル"}</button>
        <button type="button" id="_pmpwOk" style="padding:8px 14px; border:0; background:#2563eb; color:white; border-radius:6px; cursor:pointer; font-size:13px;">${i18n_t("app.button.set_master") || "設定する"}</button>
      </div>
    `;
    overlay.appendChild(box);
    document.body.appendChild(overlay);
    const pw1El = box.querySelector("#_pmpw1");
    const pw2El = box.querySelector("#_pmpw2");
    const errEl = box.querySelector("#_pmpwErr");
    const okBtn = box.querySelector("#_pmpwOk");
    const cancelBtn = box.querySelector("#_pmpwCancel");
    setTimeout(() => pw1El.focus(), 50);
    function cleanup() { document.body.removeChild(overlay); }
    function submit() {
      const v1 = pw1El.value;
      const v2 = pw2El.value;
      if (!v1) { errEl.textContent = i18n_t("app.error.master_required") || "マスターパスワードを入力してください"; pw1El.focus(); return; }
      if (v1 !== v2) { errEl.textContent = i18n_t("app.error.master_mismatch") || "確認入力が一致しません"; pw2El.focus(); return; }
      cleanup(); resolve(v1);
    }
    okBtn.addEventListener("click", submit);
    cancelBtn.addEventListener("click", () => { cleanup(); resolve(null); });
    pw2El.addEventListener("keydown", (e) => { if (e.key === "Enter") submit(); });
    pw1El.addEventListener("keydown", (e) => { if (e.key === "Enter") pw2El.focus(); });
    overlay.addEventListener("click", (e) => { if (e.target === overlay) { cleanup(); resolve(null); } });
  });
}

(async function init() {
  // Discover the self-hosted bundler read endpoint. It resolves data items
  // immediately, well before arweave.net has unbundled them.
  try {
    const r = await fetch("/api/status", { cache: "no-store" });
    if (r.ok) {
      const s = await r.json();
      state.bundlerReadBase = s.bundler_read_base ?? null;
    }
  } catch {}

  // Phase 7.1-W: profile-aware routing
  //   0 profile          → signup (= 完全新規)
  //   1 profile + meta   → そのまま unlock
  //   1 profile no meta  → signup (= profile はあるが vault 未作成、稀)
  //   2+ profile         → picker (active 指定があってもユーザに確認させる)
  //   ただし URL に ?invite=... があれば「新会社 profile を作る」flow を提案
  await _routeOnStartup();

  // Phase 7.0w-W: 初回 attach (showView 内でも呼んでいるが、modal 等の動的に
  // 表示される password 入力にも漏らさず attach する保険)
  attachPasswordToggles();

  // Phase 7.0w-W: DOM 変化を監視して新規追加された password input にも自動 attach。
  // 設定モーダル等で動的に表示される input を取りこぼさないため。
  if (typeof MutationObserver !== "undefined") {
    const _pwObserver = new MutationObserver((mutations) => {
      for (const m of mutations) {
        for (const node of m.addedNodes) {
          if (node.nodeType === 1 && (
            node.matches?.('input[type="password"]') ||
            node.querySelector?.('input[type="password"]')
          )) {
            attachPasswordToggles();
            return;
          }
        }
      }
    });
    _pwObserver.observe(document.body, { childList: true, subtree: true });
  }
})();

// =====================================================================
// Pricing からの「#purchase=<packKey>」hash 受信 → unlock 後 auto checkout
//
// pricing.html で「このプランを購入」を押すと location.href = '/app.html#purchase=X'
// にリダイレクトされる。app.html ロード時に hash を保持しておき、unlock 完了
// 後に signedFetch /api/checkout を kick して Stripe URL に飛ばす。
// =====================================================================

let _pendingPurchasePack = null;

(function readPurchaseHashOnLoad() {
  const m = location.hash.match(/[#&]purchase=([A-Za-z0-9_-]+)/);
  if (m) {
    _pendingPurchasePack = decodeURIComponent(m[1]);
    // 履歴を汚さないため hash は除去
    history.replaceState(null, "", location.pathname + location.search);
    console.log("[purchase] queued from pricing.html:", _pendingPurchasePack);
  }
})();

async function tryConsumePendingPurchase() {
  if (!_pendingPurchasePack || !isUnlocked()) return false;
  const packKey = _pendingPurchasePack;
  _pendingPurchasePack = null;
  // 確認モーダル経由で window.open する (直接 user click → popup block 回避 +
  // 元 app.html を navigate しない = unlock 状態保持)
  showPurchaseConfirmModal(packKey);
  return true;
}

/**
 * 決済確認モーダルを表示。「続ける」ボタン直接クリックで Stripe を新タブで開く。
 * これにより:
 *   - 元 app.html は unlocked のまま残る
 *   - 決済完了後に戻ってきても unlock 不要
 *   - ブラウザの popup blocker をすり抜ける (= window.open が user gesture 内で実行)
 */
function showPurchaseConfirmModal(packKey) {
  // PACK_CATALOG (上で定義済) から jpy / usdCents を引く
  const p = PACK_CATALOG.find(x => x.key === packKey) || { nameKey: packKey, jpy: 0, usdCents: 0, credits: 0 };
  const name = i18n_t(p.nameKey);
  const bg = document.getElementById("purchase-confirm-bg");
  document.getElementById("purchase-confirm-pack").textContent = name;
  // 言語別価格表示: ja は ¥、それ以外は USD (実際の Stripe 課金額) + JPY 併記
  const lang = i18n_getLang();
  let priceLabel;
  if (lang === "ja") {
    priceLabel = `¥${p.jpy.toLocaleString()}`;
  } else {
    const usd = (p.usdCents || 0) / 100;
    const usdStr = (usd >= 1) ? `$${usd.toFixed(usd % 1 === 0 ? 0 : 2)}` : `$${usd.toFixed(2)}`;
    priceLabel = usdStr;  // Phase 6.8.17: JPY 併記を撤去
  }
  document.getElementById("purchase-confirm-jpy").textContent = priceLabel;
  document.getElementById("purchase-confirm-go").dataset.pack = packKey;
  bg.classList.remove("hidden");
}

document.getElementById("purchase-confirm-go")?.addEventListener("click", async (e) => {
  const packKey = e.currentTarget.dataset.pack;
  const bg = document.getElementById("purchase-confirm-bg");
  const btn = e.currentTarget;
  btn.disabled = true;
  btn.innerHTML = `<span class="spin"></span> ${i18n_t("app.button.preparing_stripe")}`;
  // Safari 対策: 新タブは click と同期で開かないと popup block される (await 後は不可)。
  const stripeWin = window.open("", "_blank");
  try {
    const j = await checkoutSessionUI(packKey, { locale: getStripeLocale(), currency: getStripeCurrency() });
    if (!j?.url) throw new Error("checkout response missing url");
    // 新タブで Stripe を開く (この click handler 内なので popup block されない)
    // Stripe を開く: click と同期で開いた空タブ (stripeWin) に URL を流し込む。
    // 注意: 'noopener' は付けない — pay-success.html が window.opener.close()
    // に頼って自動 close する設計のため、opener 関係を保つ必要がある。
    if (stripeWin) stripeWin.location.href = j.url;
    else window.location.href = j.url; // 空タブも開けなかった時は同タブ遷移
    bg.classList.add("hidden");
    // 残高 polling 開始 (Stripe webhook が届いて KV 更新されるのを検知)
    startBalancePolling(packKey);
    toast(i18n_t("app.toast.stripe_opened"), "ok", 12000);
  } catch (err) {
    if (stripeWin) stripeWin.close();
    console.error("checkout failed:", err);
    toast(i18n_t("app.toast.checkout_prep_failed", { reason: err.message ?? err }), "err", 8000);
  } finally {
    btn.disabled = false;
    btn.innerHTML = i18n_t("app.purchase_confirm.btn_go");
  }
});

document.getElementById("purchase-confirm-cancel")?.addEventListener("click", () => {
  document.getElementById("purchase-confirm-bg").classList.add("hidden");
});

// =====================================================================
// パック選択モーダル (in-app purchase entry point)
//   - /pricing.html への navigate を完全に置き換え
//   - unlock 状態を保ったまま window.open(_blank) で Stripe を開く
//   - direct user click でないと popup block されるので、パックカードの
//     click handler 内で checkoutSessionUI + window.open を呼ぶ
// =====================================================================

// Phase 6.8.1: pack catalog uses bonus-equivalent USD micro deposits.
// estimatedWrites is computed from current AR/USD price (state.perWriteUsd).
// bonusJpy = 「実質 ¥X 分」表示用の bonus-included クレジット相当。
const PACK_CATALOG = [
  { key: "starter-100",  nameKey: "pricing.pack_starter_name",  depositUsdMicro:   1_950_000, jpy:   300, usdCents:   200, bonusJpy:   300 },
  { key: "standard-500", nameKey: "pricing.pack_standard_name", depositUsdMicro:   9_740_000, jpy:  1000, usdCents:   700, bonusJpy:  1500, highlight: true },
  { key: "heavy-2500",   nameKey: "pricing.pack_heavy_name",    depositUsdMicro:  48_700_000, jpy:  5000, usdCents:  3300, bonusJpy:  7500 },
  { key: "mega-10000",   nameKey: "pricing.pack_mega_name",     depositUsdMicro:  97_400_000, jpy: 15000, usdCents: 10000, bonusJpy: 15000 },
];

function _packEstimatedWrites(p) {
  const usd = state.perWriteUsd;
  if (typeof usd !== "number" || !(usd > 0)) return null;
  const consumeUsdMicro = Math.round(usd * 1_000_000);
  if (consumeUsdMicro <= 0) return null;
  return Math.ceil(p.depositUsdMicro / consumeUsdMicro);
}

window.openPurchasePackModal = function () {
  if (!isUnlocked()) {
    toast(i18n_t("app.error.unlock_failed"), "err");
    return;
  }
  const wrap = document.getElementById("purchase-pack-list");
  wrap.innerHTML = "";
  // 言語別の価格表示: ja は ¥、それ以外は USD (= 実際の Stripe 課金額) + JPY 併記
  const lang = i18n_getLang();
  const isJa = (lang === "ja");
  const showBoth = !isJa;
  for (const p of PACK_CATALOG) {
    let mainPrice, perWriteDisplay, subPrice;
    // Phase 6.8: per-write は本日の AR/USD レートから計算 (固定 credits 廃止)。
    if (isJa) {
      mainPrice = `¥${p.jpy.toLocaleString()}`;
      if (typeof state.perWriteUsd === "number" && state.perWriteUsd > 0) {
        const perJpy = state.perWriteUsd * 154;
        const fixedJpy = perJpy < 10 ? perJpy.toFixed(2) : perJpy.toFixed(1);
        perWriteDisplay = `¥${fixedJpy}`;
      } else {
        perWriteDisplay = "—";
      }
      subPrice = "";
    } else {
      const usd = p.usdCents / 100;
      mainPrice = (usd >= 1) ? `$${usd.toFixed(usd % 1 === 0 ? 0 : 2)}` : `$${usd.toFixed(2)}`;
      if (typeof state.perWriteUsd === "number" && state.perWriteUsd > 0) {
        const w = state.perWriteUsd;
        perWriteDisplay = (w >= 0.01) ? `$${w.toFixed(3)}` : `$${w.toFixed(4)}`;
      } else {
        perWriteDisplay = "—";
      }
      subPrice = "";  // Phase 6.8.17: JPY 併記を撤去
    }
    // 本日のレートで「約 N 回」表示
    const estWrites = _packEstimatedWrites(p);
    const writesUnit = i18n_t("app.label.writes_unit");
    const todayLine = (estWrites !== null)
      ? `<div style="font-size:11px; color:var(--accent); font-weight:600; margin-top:1px;">${i18n_t("pricing.today_estimated_writes", { n: estWrites.toLocaleString(), unit: writesUnit })}</div>`
      : "";
    const card = document.createElement("button");
    card.type = "button";
    card.dataset.pack = p.key;
    card.style.cssText = `
      display: grid; grid-template-columns: 1fr auto auto; gap: 10px; align-items: center;
      padding: 14px 16px; background: var(--paper); border: 1px solid var(--line);
      border-radius: 10px; cursor: pointer; text-align: left;
      transition: background 0.15s, border-color 0.15s;
      ${p.highlight ? "border-color: var(--accent); background: linear-gradient(135deg, #FEF3C7 0%, #FFFFFF 50%);" : ""}
    `;
    card.onmouseenter = () => { card.style.background = "#F1F5F9"; };
    card.onmouseleave = () => { card.style.background = p.highlight ? "linear-gradient(135deg, #FEF3C7 0%, #FFFFFF 50%)" : "var(--paper)"; };
    card.innerHTML = `
      <div>
        <div style="font-size: 15px; font-weight: 600;">
          ${p.highlight ? `<span style="color: var(--accent); font-size: 11px; margin-right: 6px;">${i18n_t("pricing.popular_badge")}</span>` : ""}
          ${i18n_t(p.nameKey)}
        </div>
        <div style="font-size: 11px; color: var(--muted); margin-top: 2px;">
          ${perWriteDisplay} / ${i18n_t("pricing.per_write")}
        </div>
        ${(() => {
          if (!(p.bonusJpy && p.bonusJpy > p.jpy)) return "";
          const amt = isJa ? `¥${p.bonusJpy.toLocaleString()}` : `$${Math.round(p.bonusJpy / 154)}`;
          return `<div style="font-size:11px; color:#059669; font-weight:700; margin-top:1px;">${i18n_t("pricing.bonus_equivalent", { amount: amt })}</div>`;
        })()}
        ${todayLine}
      </div>
      <div style="text-align: right;">
        <div style="font-size: 16px; font-weight: 700; color: var(--accent);">
          ${mainPrice}
        </div>
        ${subPrice}
      </div>
      <div style="font-size: 18px; color: var(--accent);">→</div>
    `;
    card.addEventListener("click", () => initiatePackPurchase(p.key, card));
    wrap.appendChild(card);
  }
  document.getElementById("purchase-pack-bg").classList.remove("hidden");
};

async function initiatePackPurchase(packKey, originBtnEl) {
  // direct user click → popup block 回避できる context
  if (originBtnEl) {
    originBtnEl.style.pointerEvents = "none";
    originBtnEl.style.opacity = "0.6";
  }
  // Safari 対策: 新タブは click と同期で開かないと popup block される (await 後は不可)。
  const stripeWin = window.open("", "_blank");
  try {
    const j = await checkoutSessionUI(packKey, { locale: getStripeLocale(), currency: getStripeCurrency() });
    if (!j?.url) throw new Error("checkout response missing url");
    // 新タブで Stripe を開く
    // Stripe を開く: click と同期で開いた空タブ (stripeWin) に URL を流し込む。
    // 注意: 'noopener' は付けない — pay-success.html が window.opener.close()
    // に頼って自動 close する設計のため、opener 関係を保つ必要がある。
    if (stripeWin) stripeWin.location.href = j.url;
    else window.location.href = j.url; // 空タブも開けなかった時は同タブ遷移
    // 残高 polling 開始
    startBalancePolling(packKey);
    // モーダル閉じる
    document.getElementById("purchase-pack-bg").classList.add("hidden");
    toast(i18n_t("app.toast.stripe_opened"), "ok", 12000);
  } catch (e) {
    if (stripeWin) stripeWin.close();
    console.error("pack purchase failed:", e);
    toast(i18n_t("app.toast.checkout_failed", { reason: e.message ?? e }), "err", 8000);
  } finally {
    if (originBtnEl) {
      originBtnEl.style.pointerEvents = "";
      originBtnEl.style.opacity = "";
    }
  }
}

document.getElementById("purchase-pack-cancel")?.addEventListener("click", () => {
  document.getElementById("purchase-pack-bg").classList.add("hidden");
});
document.getElementById("purchase-pack-bg")?.addEventListener("click", (e) => {
  if (e.target.id === "purchase-pack-bg") {
    document.getElementById("purchase-pack-bg").classList.add("hidden");
  }
});

/**
 * 残高 polling (新タブで決済中、本タブで credit 加算を待つ)。
 * 即時 + 5 秒ごとに /api/balance を確認 (タブ復帰時も即発火、429 時は指数バックオフ)、増えたら toast で通知。
 * 最大 3 分ポーリング、その後停止。
 */
let _balancePollTimer = null;     // 次の tick の setTimeout ハンドル
let _balancePollTick = null;      // 進行中の poll の即時 poll トリガ (visibilitychange 用)
let _balancePollGen = 0;          // poll 世代 — startBalancePolling 再呼び出しで旧 tick を無効化
function startBalancePolling(packKey = null) {
  if (_balancePollTimer) { clearTimeout(_balancePollTimer); _balancePollTimer = null; }
  const myGen = ++_balancePollGen;
  // Phase 7.5e: Stripe 購入直後の startBalancePolling 開始時に balance cache を
  //   強制無効化。 これがないと過去 3 秒以内の getBalanceUI が返した stale
  //   credit promise を tick が掴んで、 webhook 着信を見逃す。
  try {
    import("/lib/vault-client.js?v=51488219").then(({ invalidateBalanceCache }) => {
      invalidateBalanceCache?.();
    }).catch(() => {});
  } catch {}
  const startedAt = Date.now();
  // Phase 7.5g: estimatedWrites は「今日のレートでの書込み可能回数の見積もり」で、
  //   AR/USD レート変動でも揺らぐため purchase 検知の indicator には不適。
  //   balanceUsdMicro (= USD × 1e6 の生残高) を見る。 Stripe 増額・write 消費のみで
  //   動く monotonic な値なので、 Stripe 着信を確実に観測できる。
  const initialBalance = (typeof state.balanceUsdMicro === "number") ? state.balanceUsdMicro : 0;
  const initialCredits = state.credits;  // display 比較用 (差分 toast の writes 回数算出)
  // Business/Family (mega-10000) のみ Stripe webhook が createCompany を呼び admin 昇格する。
  //   webhook は「credit 加算 → createCompany」の順で実行するため、 credit 反映を観測した
  //   瞬間にはまだ admin 昇格が KV に届いていないことがある。 credit を観測した時点で即停止
  //   すると admin 昇格を取りこぼす (= 管理メニューが出ない) ので、 admin 検知まで polling を
  //   継続する。 credit 反映と admin 昇格を独立した 2 目標として扱う。
  const expectAdmin = packKey === "mega-10000";
  let creditsReflected = false;
  let adminPromoted = false;
  let _running = false;       // tick の再入防止
  let _lastPollAt = 0;        // 直近 poll 時刻 (visibilitychange デバウンス用)
  // Phase 7.5d: BASE_MS を 5s → 2.5s に短縮 (= 429 storm 対策で 5s に上げていたが、
  //   client side _balanceCache (3s TTL) + 指数バックオフ + 4s デバウンスで rate-limit は
  //   独立に防げる)。 Stripe webhook 着信を user 体感で「即」反映する。
  const BASE_MS = 2500;       // 基本ポーリング間隔 (2.5s)
  const MAX_MS = 30000;       // 429 / エラー時のバックオフ上限
  let _delay = BASE_MS;
  const _stopped = () =>
    myGen !== _balancePollGen                                  // 新しい poll が始まった
    || Date.now() - startedAt > 10 * 60_000                    // Phase 7.5e: 3 → 10 分 (webhook 遅延対策)
    || (creditsReflected && (adminPromoted || !expectAdmin));  // 目標達成
  const _stop = () => {
    if (myGen !== _balancePollGen) return;  // 旧世代の tick — 現行 poll の timer は触らない
    if (_balancePollTimer) { clearTimeout(_balancePollTimer); _balancePollTimer = null; }
    _balancePollTick = null;
  };
  // 1 周期の処理。即時 1 回 → setTimeout 自走、 タブ復帰時にも発火する。
  //   429 / エラー時は次周期を指数バックオフ (BASE→×2→…→MAX) してサーバ負荷を抑える。
  const tick = async () => {
    if (_running) return;                    // 前の tick がまだ実行中
    if (_stopped()) { _stop(); return; }
    _running = true;
    _lastPollAt = Date.now();
    let hadError = false;
    try {
      // --- 目標 A: credit 反映 (1 回だけ) ---
      // Phase 7.5g: balanceUsdMicro (monotonic USD 残高) で purchase 検知。
      //   estimatedWrites は AR/USD レート変動で揺らぐので使わない。
      //   表示用 toast は残高増分を ¥/$ で表示 (UI と整合)。
      if (!creditsReflected) {
        const s = await getBalanceUI({ force: true });
        const newBalance = (typeof s.balanceUsdMicro === "number") ? s.balanceUsdMicro : null;
        if (newBalance !== null && newBalance > initialBalance) {
          creditsReflected = true;
          const newCredits = (typeof s.estimatedWrites === "number") ? s.estimatedWrites : (initialCredits ?? 0);
          state.credits = newCredits;
          state.balanceUsdMicro = newBalance;
          // 増分 USD を ja=¥ (×154 換算)、 他=$ で表示。 桁は ¥は整数、 $は小数2桁。
          const addedUsd = (newBalance - initialBalance) / 1_000_000;
          const lang = i18n_getLang();
          let amountStr;
          if (lang === "ja") {
            const jpy = Math.round(addedUsd * 154);
            amountStr = `¥${jpy.toLocaleString("ja-JP")}`;
          } else {
            amountStr = `$${addedUsd.toFixed(2)}`;
          }
          await refreshHeader();
          toast(i18n_t("app.toast.credits_reflected", { amount: amountStr }), "ok", 8000);
        }
      }
      // --- 目標 B: admin 昇格検知 (Business/Family 購入時のみ、 1 回だけ) ---
      if (expectAdmin && !adminPromoted) {
        const freshCorpInfo = await corpInfoUI();
        state._corpInfo = freshCorpInfo;
        state._corpInfoChecked = true;
        if (freshCorpInfo?.member?.isAdmin) {
          adminPromoted = true;
          // admin に昇格 → vault.mode を admin に self-heal
          const v = currentVault();
          let healed = false;
          if (v && v.mode !== "admin") { v.mode = "admin"; healed = true; }
          if (v && v.companyId !== freshCorpInfo.member.companyId) {
            v.companyId = freshCorpInfo.member.companyId; healed = true;
          }
          // applyVaultModeUI と同じ配列/policy 初期化 (= renderAdminConsole /
          //   _processRecoveryDeposits が不整合にならないように)。
          if (v && !Array.isArray(v.employees)) { v.employees = []; healed = true; }
          if (v && !Array.isArray(v.additionalAdmins)) { v.additionalAdmins = []; healed = true; }
          if (v && !v.policy) {
            v.policy = { allowEmployeePasswordChange: false, requireRotateOnEmployeeLeave: true };
            healed = true;
          }
          if (healed) scheduleSave(v);
          // UX #117: profile.kind / companyId を更新して drive picker 表示も追従
          try {
            const profMod = await import("/lib/profiles.js?v=5ef6de24");
            const activeId = profMod.getActiveProfileId();
            if (activeId) {
              profMod.updateProfile(activeId, {
                kind: "admin",
                companyId: freshCorpInfo.member.companyId,
              });
            }
          } catch (e) {
            console.warn("[balance-poll] profile.kind update failed:", e?.message);
          }
          // UI 更新: applyVaultModeUI を full 適用 (tab-admin 表示 / 購入 UI / banner 等を
          //   re-unlock と同じ状態に) + admin console 描画。
          try {
            await applyVaultModeUI();
            await renderAdminConsole();
          } catch (e) {
            console.warn("[balance-poll] admin UI render failed:", e?.message);
          }
          toast(i18n_t("app.toast.admin_unlocked") || "🎉 管理メニューが利用可能になりました", "ok", 12000);
        }
      }
    } catch (e) {
      // 429 (Too Many Requests) を含むエラー → 次周期をバックオフして storm を防ぐ。
      hadError = true;
      console.warn("[balance-poll] error, will back off:", e?.message || e);
    } finally { _running = false; }
    if (_stopped()) { _stop(); return; }
    // 成功 → BASE に戻す。 エラー (429 等) → 指数バックオフ。
    _delay = hadError ? Math.min(_delay * 2, MAX_MS) : BASE_MS;
    _balancePollTimer = setTimeout(tick, _delay);
  };
  // visibilitychange からの即時 poll トリガ。 直近 poll から間が空いている時だけ。
  _balancePollTick = () => {
    if (_running) return;
    if (Date.now() - _lastPollAt < 4000) return;          // デバウンス (4 秒)
    if (_balancePollTimer) { clearTimeout(_balancePollTimer); _balancePollTimer = null; }
    tick();
  };
  tick();  // 即時 1 回 (最初の周期を待たない)
}

// =====================================================================
// Arweave 保存ステータス 詳細モーダル (v5、外側暗号化対応)
//   - tx status バッジ <button> がクリックされると window.openTxDetailModal()
//     を呼ぶ
//   - モーダル内で status / size / 暗号化説明 / 技術リンクを表示
//   - リンクは disclaimer 付き details 内に格納 (誤クリック防止)
// =====================================================================

window.openTxDetailModal = async function (txid) {
  if (!txid) return;
  const bg = document.getElementById("tx-detail-bg");
  const txidEl = document.getElementById("tx-detail-txid");
  const linkVB = document.getElementById("tx-detail-link-viewblock");
  const linkT  = document.getElementById("tx-detail-link-turbo");
  const linkA  = document.getElementById("tx-detail-link-arweave");

  txidEl.value = txid;
  linkVB.href = `https://viewblock.io/arweave/tx/${txid}`;
  linkT.href  = `https://turbo-gateway.com/${txid}?t=${Date.now()}`;
  linkA.href  = `https://arweave.net/${txid}?t=${Date.now()}`;

  // 既知の status (キャッシュ) から初期表示
  renderTxDetailStatus(txStatusCache.get(txid), txid);
  bg.classList.remove("hidden");

  // 最新 status を取りに行く (UI ブロックしない)
  await refreshTxDetailModal(txid);
};

/**
 * 詳細モーダルが開いている状態で、status を再取得して
 *   - モーダル内表示を更新
 *   - txStatusCache を更新
 *   - ヘッダーバッジも refreshHeader() で再描画
 *   - confirmed (>= 2 confirms) でなければ scheduleTxStatusPoll を走らせる
 * を一括で行う。「🔄 今すぐ再確認」ボタンと openTxDetailModal の両方から呼ぶ。
 */
async function refreshTxDetailModal(txid) {
  const refreshBtn = document.getElementById("tx-detail-refresh");
  if (refreshBtn) {
    refreshBtn.disabled = true;
    refreshBtn.innerHTML = `<span class="spin"></span> ${i18n_t("app.tx.refresh_checking")}`;
  }
  try {
    // Phase 5.3-Y: 手動再確認は forceProbe で全 source 叩く (Turbo bundleId なし時も)
    const observedFresh = await getTxStatus(txid, { forceProbe: true });
    const fresh = _setStatusMonotonic(txid, observedFresh) ?? observedFresh;
    renderTxDetailStatus(fresh, txid);
    // ヘッダーバッジを最新に
    try { await refreshHeader(); } catch {}
    // 必要なら polling を再起動 (confirmed && >=2 conf なら停止)
    if (typeof scheduleTxStatusPoll === "function") scheduleTxStatusPoll(txid);
  } catch (e) {
    console.warn("refreshTxDetailModal failed:", e?.message ?? e);
    toast(i18n_t("app.toast.status_fetch_failed", { reason: e?.message ?? e }), "err");
  } finally {
    if (refreshBtn) {
      refreshBtn.disabled = false;
      refreshBtn.innerHTML = i18n_t("app.tx_detail.btn_refresh");
    }
  }
}

async function renderTxDetailStatus(status, txid) {
  const stateEl = document.getElementById("tx-detail-state");
  const timeEl = document.getElementById("tx-detail-time");
  const sizeEl = document.getElementById("tx-detail-size");
  if (!status) {
    stateEl.textContent = i18n_t("app.tx.checking_status");
    timeEl.textContent = "—";
  } else if (status.state === "bundling") {
    stateEl.innerHTML = i18n_t("app.tx.badge_bundling_html");
    timeEl.textContent = i18n_t("app.tx.bundling_explain");
  } else if (status.state === "pending") {
    stateEl.innerHTML = i18n_t("app.tx.badge_propagating_html");
    timeEl.textContent = i18n_t("app.tx.propagating_explain");
  } else if (status.state === "confirmed") {
    const conf = status.confirmations != null ? i18n_t("app.tx.confirmations_count", { n: status.confirmations }) : "—";
    const block = status.blockHeight ?? "?";
    stateEl.innerHTML = i18n_t("app.tx.badge_confirmed_html");
    timeEl.innerHTML = i18n_t("app.tx.confirmed_block_count", { block, conf });
  } else if (status.state === "not_found") {
    // Phase 5.3-X: 「Turbo 受領未配信」表現に変更
    stateEl.innerHTML = i18n_t("app.tx.badge_received_html");
    timeEl.innerHTML = i18n_t("app.tx.received_explain_html");
  } else if (status.state === "rate_limited") {
    stateEl.innerHTML = i18n_t("app.tx.badge_rate_limited_html");
    timeEl.textContent = i18n_t("app.tx.rate_limited_retry", { seconds: status.retryAfterSeconds ?? 60 });
  } else {
    stateEl.innerHTML = i18n_t("app.tx.badge_unknown_html");
    timeEl.textContent = status?.note ?? i18n_t("app.tx.unknown_explain");
  }
  // size 表示。Phase 5.1 で /api/balance に latestTxSize を持たせるよう
  // 拡張済み。getTxStatus は size を返さない (= GraphQL で取れない) ので、
  // 元 app の state.balanceCache か、開いているなら getBalanceUI 経由で取得する。
  let sizeText = "—";
  try {
    if (typeof getBalanceUI === "function") {
      const bal = await getBalanceUI();
      if (bal?.latestTxId === txid && typeof bal.latestTxSize === "number") {
        const kb = (bal.latestTxSize / 1024).toFixed(1);
        sizeText = `${bal.latestTxSize.toLocaleString()} bytes (${kb} KB)`;
      }
    }
  } catch { /* balance fetch 失敗時は dash 維持 */ }
  sizeEl.innerHTML = i18n_t("app.tx.size_label_html", { size: sizeText });
}

document.getElementById("tx-detail-close")?.addEventListener("click", () => {
  document.getElementById("tx-detail-bg").classList.add("hidden");
});
document.getElementById("tx-detail-refresh")?.addEventListener("click", () => {
  const txid = document.getElementById("tx-detail-txid")?.value;
  if (txid) refreshTxDetailModal(txid);
});
document.getElementById("tx-detail-bg")?.addEventListener("click", (e) => {
  if (e.target.id === "tx-detail-bg") {
    document.getElementById("tx-detail-bg").classList.add("hidden");
  }
});
document.getElementById("tx-detail-copy")?.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(document.getElementById("tx-detail-txid").value);
    toast(i18n_t("app.toast.txid_copied"), "ok");
  } catch {
    toast(i18n_t("app.toast.clipboard_access_denied"), "err");
  }
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    const bg = document.getElementById("tx-detail-bg");
    if (bg && !bg.classList.contains("hidden")) bg.classList.add("hidden");
  }
});

// =====================================================================
// QR スキャナ — 4 つの Recovery 入力欄から共通利用
//   - .qr-scan-btn[data-target="<input id>"] が押されたら Recovery を読む
//   - BarcodeDetector → 失敗時 jsQR の順で試す (qr.js が制御)
//   - 入力欄に流し込んだら自動で focus、change/input イベントも発火
//   - 不正値 (RS1- で始まらない等) は入れず、エラー toast
// =====================================================================
let _qrScanAbort = null;

async function openQrScanForTarget(targetInputId) {
  const overlay = document.getElementById("qr-scan-overlay");
  const video   = document.getElementById("qr-scan-video");
  const status  = document.getElementById("qr-scan-status");

  overlay.classList.remove("hidden");
  status.textContent = i18n_t("app.qr_scan.status_loading");

  // Abort any previous scan still in flight
  if (_qrScanAbort) _qrScanAbort.abort();
  _qrScanAbort = new AbortController();
  const signal = _qrScanAbort.signal;

  try {
    if (!hasNativeBarcodeDetector()) {
      status.textContent = i18n_t("app.qr.no_native_loading_fallback");
    } else {
      status.textContent = i18n_t("app.qr.point_at_frame");
    }
    // Phase 7.5ZU: camera + 画像ファイル の両方で受付
    const text = await scanQrCombined(video, { signal });
    closeQrScan();
    handleScannedRecovery(text, targetInputId);
  } catch (e) {
    if (e?.name === "AbortError") {
      // ユーザーキャンセル: 既に closeQrScan 済み
    } else if (e?.name === "NotAllowedError") {
      closeQrScan();
      toast(i18n_t("app.toast.camera_denied"), "err");
    } else {
      closeQrScan();
      toast(i18n_t("app.toast.qr_scan_failed", { reason: e?.message || String(e) }), "err");
    }
  }
}

function closeQrScan() {
  if (_qrScanAbort) {
    _qrScanAbort.abort();
    _qrScanAbort = null;
  }
  document.getElementById("qr-scan-overlay").classList.add("hidden");
  // Phase 7.5ZU: file picker のリスナをクリーンアップ
  const fileInput = document.getElementById("qr-scan-image-file");
  if (fileInput && fileInput._currentHandler) {
    fileInput.removeEventListener("change", fileInput._currentHandler);
    fileInput._currentHandler = null;
    fileInput.value = "";
  }
}

/**
 * Phase 7.5ZU: camera 起動 と 画像ファイル選択 を並行で待ち、 先に来た QR を返す。
 * 既存の scanQrFromCamera は signal による abort 可能なので、 file 側が先に成功
 * したら abort してから return。
 *
 * @param {HTMLVideoElement} videoEl
 * @param {{ signal?: AbortSignal }} opts
 * @returns {Promise<string>}
 */
async function scanQrCombined(videoEl, opts = {}) {
  const ctrl = opts.signal ? null : new AbortController();
  const signal = opts.signal || ctrl.signal;
  const fileInput = document.getElementById("qr-scan-image-file");

  return new Promise((resolve, reject) => {
    let settled = false;

    const finish = (err, text) => {
      if (settled) return;
      settled = true;
      if (fileInput && fileInput._currentHandler) {
        fileInput.removeEventListener("change", fileInput._currentHandler);
        fileInput._currentHandler = null;
        fileInput.value = "";
      }
      if (ctrl && !ctrl.signal.aborted) ctrl.abort();
      if (err) reject(err);
      else resolve(text);
    };

    // File 側
    if (fileInput) {
      const handler = async (e) => {
        const file = e.target.files?.[0];
        if (!file || settled) return;
        try {
          const text = await scanQrFromImage(file);
          finish(null, text);
        } catch (err) {
          finish(err);
        }
      };
      fileInput._currentHandler = handler;
      fileInput.addEventListener("change", handler);
    }

    // Camera 側
    scanQrFromCamera(videoEl, { signal })
      .then((text) => finish(null, text))
      .catch((err) => {
        // file 側で既に解決済みなら無視 (= ctrl.abort 由来の AbortError は無視)
        if (settled && err?.name === "AbortError") return;
        // 2026-06-05 fix: camera permission denied (= NotAllowedError) は
        //   reject せず file picker path を生かす。 これがないと user が一度
        //   camera 拒否すると 「二度と確認されなくなり、 どうしようもない」
        //   状態になる (= browser が deny を覚えていて再 prompt しない仕様)。
        //   file 入力で QR 画像を選んでもらえれば scan 続行できる。
        if (err?.name === "NotAllowedError" || /permission denied|NotAllowed/i.test(err?.message || "")) {
          console.warn("[qr-scan] camera permission denied; file picker still available");
          // modal の status 文言を更新して、 file picker が使えることを明示
          const statusEl = document.getElementById("qr-scan-status");
          if (statusEl) {
            try {
              statusEl.textContent = i18n_t("app.qr_scan.status_camera_denied");
              statusEl.style.color = "#ffcccc";
              statusEl.style.fontWeight = "600";
            } catch (_) { /* swallow */ }
          }
          // file picker ボタンを視覚的に強調 (= pulsing で目立たせる)
          const fileLabel = document.querySelector('label[for="qr-scan-image-file"]');
          if (fileLabel) {
            fileLabel.style.background = "#ffeb3b";
            fileLabel.style.boxShadow = "0 0 0 4px rgba(255, 235, 59, 0.4)";
            fileLabel.style.transform = "scale(1.05)";
          }
          // user に file upload を案内する toast
          try { toast(i18n_t("app.toast.qr_camera_denied_use_file"), "warn"); } catch (_) {}
          return;  // promise を reject せず file 側の change event を待つ
        }
        finish(err);
      });
  });
}

function handleScannedRecovery(text, targetInputId) {
  // 軽い形式チェック (細かい妥当性は呼び出し先のクライアントで再検証される)
  const cleaned = (text || "").trim().toUpperCase();
  if (!cleaned.startsWith("RS1-")) {
    toast(i18n_t("app.toast.qr_invalid_secret"), "err");
    return;
  }
  const input = document.getElementById(targetInputId);
  if (!input) return;
  input.value = cleaned;
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
  input.focus();
  toast(i18n_t("app.toast.recovery_scanned"), "ok");
}

// イベント委譲: どの .qr-scan-btn が押されても 1 か所で受ける
document.addEventListener("click", (e) => {
  const btn = e.target?.closest?.(".qr-scan-btn");
  if (!btn) return;
  e.preventDefault();
  const targetId = btn.getAttribute("data-target");
  if (!targetId) return;
  openQrScanForTarget(targetId);
});

// Phase 6.7-5: data-action 属性付き要素の click を delegation で受ける。
// 動的生成 HTML (purchaseCtaHtml / creditBadgeHtml / renderStorageUsageHtml /
// renderTxStatusHtml 等) に inline onclick を書くと CSP で blocked になるため、
// data-action="..." を付けてここで一括 dispatch する。
document.addEventListener("click", (e) => {
  const el = e.target?.closest?.("[data-action]");
  if (!el) return;
  const action = el.getAttribute("data-action");
  switch (action) {
    case "open-purchase-modal":
      e.preventDefault();
      window.openPurchasePackModal?.();
      break;
    case "open-tx-detail": {
      e.preventDefault();
      const txid = el.getAttribute("data-txid");
      if (txid) window.openTxDetailModal?.(txid);
      break;
    }
    case "show-alert": {
      e.preventDefault();
      const msg = el.getAttribute("data-alert-msg");
      if (msg) {
        // HTML で escape された &amp; / &quot; を元に戻す
        const decoded = msg.replace(/&quot;/g, '"').replace(/&amp;/g, "&");
        alert(decoded);
      }
      break;
    }
    default:
      // 未知の data-action は無視 (将来追加分の forward compat)
      break;
  }
});

// キャンセルボタン
document.getElementById("qr-scan-cancel")?.addEventListener("click", closeQrScan);

// Esc キーでもキャンセル可能
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !document.getElementById("qr-scan-overlay").classList.contains("hidden")) {
    closeQrScan();
  }
});

// =====================================================================
// Phase 6.3 v2: Slot-based Corporate UI handlers
//
// Server has no PII (no labels). Admin's labels live in admin's vault under
// `corpSlots: { [slotId]: {label, addedAt} }` and merged client-side at render.
// =====================================================================

function _corpShow(stateId) {
  for (const id of ["corp-loading", "corp-none", "corp-member", "corp-admin"]) {
    const el = document.getElementById(id);
    if (el) el.classList.toggle("hidden", id !== stateId);
  }
}

function _corpMsg(elemId, text, kind = "ok") {
  const el = document.getElementById(elemId);
  if (!el) return;
  el.textContent = text;
  el.style.color = kind === "err" ? "#DC2626" : "#059669";
  el.classList.remove("hidden");
  setTimeout(() => el.classList.add("hidden"), 6000);
}

function _corpFmtDate(iso) {
  if (!iso) return "—";
  try { return new Date(iso).toISOString().slice(0, 10); }
  catch { return iso; }
}

// Read admin's per-slot labels from vault.corpSlots (no server roundtrip)
function _readSlotLabels() {
  const v = (typeof currentVault === "function") ? currentVault() : null;
  return (v && v.corpSlots && typeof v.corpSlots === "object") ? v.corpSlots : {};
}

// Persist a label change to admin's vault
async function _setSlotLabel(slotId, label) {
  const v = currentVault();
  if (!v.corpSlots) v.corpSlots = {};
  if (label) v.corpSlots[slotId] = { label, addedAt: v.corpSlots[slotId]?.addedAt || new Date().toISOString() };
  else delete v.corpSlots[slotId];
  await saveVault(v);
}

async function loadCorpInfo() {
  _corpShow("corp-loading");
  let info;
  try { info = await corpInfoUI(); }
  catch (e) {
    const root = document.getElementById("sec-corp");
    if (root) root.style.display = "none";
    return;
  }
  const root = document.getElementById("sec-corp");
  if (root) root.style.display = "";

  if (!info.member) { _corpShow("corp-none"); return; }

  if (info.member.isAdmin && info.admin) {
    _corpShow("corp-admin");
    document.getElementById("corp-admin-id").textContent = info.member.companyId;
    document.getElementById("corp-admin-count").textContent = `${info.admin.currentSlots} / ${info.admin.maxSlots}`;

    const labels = _readSlotLabels();
    const tbl = document.getElementById("corp-slots-table");
    if (!tbl) return;

    const rows = info.admin.slots.map(s => {
      const labelData = labels[s.slotId];
      const labelText = labelData?.label || "";
      const labelDisplay = labelText
        ? `<span style="font-weight:600;">${escape(labelText)}</span>`
        : `<span style="color:var(--muted); font-style:italic;" data-i18n="app.corp.label_unnamed">(無名)</span>`;

      let statusBadge, actions;
      if (s.isAdmin) {
        statusBadge = `<span style="color:#5B21B6; font-weight:600;" data-i18n="app.corp.status_admin">👑 管理者 (あなた)</span>`;
        actions = "";
      } else if (s.status === "active") {
        statusBadge = `<span style="color:#059669;" data-i18n="app.corp.status_active">🟢 使用中</span>`;
        actions = `<button class="btn-outline" data-action="rename" data-slot="${escape(s.slotId)}" style="padding:4px 10px; font-size:12px;">${i18n_t("app.corp.btn_rename") || "ラベル"}</button>
                   <button class="btn-outline" data-action="revoke" data-slot="${escape(s.slotId)}" style="padding:4px 10px; font-size:12px; color:#DC2626; border-color:#FCA5A5;">${i18n_t("app.corp.btn_revoke") || "切断"}</button>`;
      } else if (s.status === "pending") {
        statusBadge = `<span style="color:#F59E0B;" data-i18n="app.corp.status_pending">🟡 招待中</span>
                      <div style="font-family:ui-monospace,monospace; font-size:11px; color:#5B21B6; word-break:break-all; margin-top:2px;">${escape(s.code)}</div>
                      <div style="font-size:11px; color:var(--muted); margin-top:2px;">${i18n_t("app.corp.label_expiry") || "有効期限"}: ${_corpFmtDate(s.codeExpiry)}</div>`;
        actions = `<button class="btn-outline" data-action="rename" data-slot="${escape(s.slotId)}" style="padding:4px 10px; font-size:12px;">${i18n_t("app.corp.btn_rename") || "ラベル"}</button>
                   <button class="btn-outline" data-action="copy" data-code="${escape(s.code)}" style="padding:4px 10px; font-size:12px;">📋</button>
                   <button class="btn-outline" data-action="regenerate" data-slot="${escape(s.slotId)}" style="padding:4px 10px; font-size:12px;">${i18n_t("app.corp.btn_regenerate") || "再発行"}</button>
                   <button class="btn-outline" data-action="revoke" data-slot="${escape(s.slotId)}" style="padding:4px 10px; font-size:12px; color:#DC2626; border-color:#FCA5A5;">${i18n_t("app.corp.btn_revoke") || "削除"}</button>`;
      } else {
        statusBadge = `<span style="color:var(--muted);">${escape(s.status)}</span>`;
        actions = "";
      }

      return `<div style="display:grid; grid-template-columns: 1fr 1.4fr auto; gap:8px; padding:8px 0; border-bottom:1px solid var(--line); align-items:center;">
        <div>${labelDisplay}<div style="font-size:10px; color:var(--muted); font-family:ui-monospace,monospace;">${escape(s.slotId)}</div></div>
        <div>${statusBadge}</div>
        <div style="display:flex; gap:4px; flex-wrap:wrap; justify-content:flex-end;">${actions}</div>
      </div>`;
    });

    tbl.innerHTML = rows.join("");

    // Wire button handlers
    tbl.querySelectorAll('button[data-action="rename"]').forEach(btn => {
      btn.addEventListener("click", async () => {
        const slotId = btn.dataset.slot;
        const cur = _readSlotLabels()[slotId]?.label || "";
        const next = prompt(i18n_t("app.corp.prompt_label") || "Slot のラベル (空欄で削除):", cur);
        if (next === null) return;
        try {
          await _setSlotLabel(slotId, next.trim() || null);
          _corpMsg("corp-admin-msg", i18n_t("app.corp.toast_label_saved") || "ラベルを保存しました", "ok");
          await loadCorpInfo();
        } catch (e) { _corpMsg("corp-admin-msg", e.message, "err"); }
      });
    });

    tbl.querySelectorAll('button[data-action="copy"]').forEach(btn => {
      btn.addEventListener("click", async () => {
        try { await navigator.clipboard.writeText(btn.dataset.code); _corpMsg("corp-admin-msg", i18n_t("app.corp.toast_code_copied") || "コードをコピーしました", "ok"); }
        catch { _corpMsg("corp-admin-msg", "clipboard error", "err"); }
      });
    });

    tbl.querySelectorAll('button[data-action="regenerate"]').forEach(btn => {
      btn.addEventListener("click", async () => {
        if (!confirm(i18n_t("app.corp.confirm_regenerate") || "コードを再生成します。古いコードは即無効になります。")) return;
        btn.disabled = true;
        try {
          await corpSlotRegenerateUI(btn.dataset.slot);
          _corpMsg("corp-admin-msg", i18n_t("app.corp.toast_regenerated") || "再生成しました", "ok");
          await loadCorpInfo();
        } catch (e) { _corpMsg("corp-admin-msg", e.message, "err"); }
        finally { btn.disabled = false; }
      });
    });

    tbl.querySelectorAll('button[data-action="revoke"]').forEach(btn => {
      btn.addEventListener("click", async () => {
        const slotId = btn.dataset.slot;
        const labelText = _readSlotLabels()[slotId]?.label || `slot ${slotId}`;
        if (!confirm((i18n_t("app.corp.confirm_revoke") || "「{label}」を切断/削除します。続行しますか?").replace("{label}", labelText))) return;
        btn.disabled = true;
        try {
          await corpSlotRevokeUI(slotId);
          // Also delete vault label
          await _setSlotLabel(slotId, null);
          _corpMsg("corp-admin-msg", i18n_t("app.corp.toast_revoked") || "切断しました", "ok");
          await loadCorpInfo();
        } catch (e) { _corpMsg("corp-admin-msg", e.message, "err"); }
        finally { btn.disabled = false; }
      });
    });

    return;
  }

  // Member (non-admin)
  _corpShow("corp-member");
  document.getElementById("corp-member-id").textContent = info.member.companyId;
  document.getElementById("corp-member-slot").textContent = info.member.slotId;
}

document.getElementById("corp-join-btn")?.addEventListener("click", async () => {
  const codeEl = document.getElementById("corp-join-code");
  const code = (codeEl?.value || "").trim().toUpperCase();
  if (!code) { _corpMsg("corp-join-msg", i18n_t("app.corp.err_code_required") || "招待コードを入力してください", "err"); return; }
  const btn = document.getElementById("corp-join-btn");
  btn.disabled = true;
  try {
    await corpJoinUI(code);
    // Phase 6.4.1: 会社に参加 → tier が "corp::companyId" に変わる
    await refreshTierQualifier().catch(() => {});
    _corpMsg("corp-join-msg", i18n_t("app.corp.toast_joined") || "会社に参加しました", "ok");
    if (codeEl) codeEl.value = "";
    await loadCorpInfo();
  } catch (e) { _corpMsg("corp-join-msg", e.message || "join failed", "err"); }
  finally { btn.disabled = false; }
});

document.getElementById("corp-leave-btn")?.addEventListener("click", async () => {
  if (!confirm(i18n_t("app.corp.confirm_leave") || "会社から離脱します。次回の書込み課金は個人 wallet から発生します。続行しますか?")) return;
  const btn = document.getElementById("corp-leave-btn");
  btn.disabled = true;
  try {
    await corpLeaveUI();
    // Phase 6.4.1: 離脱 → tier が個人 (paid/free) に戻る
    await refreshTierQualifier().catch(() => {});
    _corpMsg("corp-leave-msg", i18n_t("app.corp.toast_left") || "会社から離脱しました", "ok");
    await loadCorpInfo();
  } catch (e) { _corpMsg("corp-leave-msg", e.message || "leave failed", "err"); }
  finally { btn.disabled = false; }
});

document.getElementById("corp-slot-create-btn")?.addEventListener("click", async () => {
  const labelEl = document.getElementById("corp-new-slot-label");
  const label = (labelEl?.value || "").trim();
  const btn = document.getElementById("corp-slot-create-btn");
  btn.disabled = true;
  try {
    const r = await corpSlotCreateUI();
    if (label) await _setSlotLabel(r.slotId, label);
    _corpMsg("corp-admin-msg", (i18n_t("app.corp.toast_slot_created") || "新規 slot 発行: ") + r.code, "ok");
    if (labelEl) labelEl.value = "";
    await loadCorpInfo();
  } catch (e) { _corpMsg("corp-admin-msg", e.message || "create failed", "err"); }
  finally { btn.disabled = false; }
});


// =====================================================================
// Phase 7.0d-e: Records (電子書類保管) UI
// =====================================================================
//
// view-vault 内のタブ navigation (Passwords / Records) と、
// records アップロード modal、一覧 rendering を扱う。
//
// records は state.vault.records.active に格納される。検索や訂正/削除は
// 後 phase で実装。MVP は create + list + detail プレビューのみ。

// ---- Tab navigation ---------------------------------------------------
function _switchVaultTab(name) {
  const passTab = document.getElementById("tab-passwords");
  const recTab  = document.getElementById("tab-records");
  const adminTab = document.getElementById("tab-admin");
  const passContent = document.getElementById("vault-tab-content-passwords");
  const recContent  = document.getElementById("vault-tab-content-records");
  const adminContent = document.getElementById("vault-tab-content-admin");
  if (!passTab || !recTab || !passContent || !recContent) return;

  const active = (el) => {
    if (!el) return;
    el.style.borderBottomColor = "var(--accent)";
    el.style.opacity = "1";
    el.setAttribute("aria-selected", "true");
    el.classList.add("active");
  };
  const inactive = (el) => {
    if (!el) return;
    el.style.borderBottomColor = "transparent";
    el.style.opacity = "0.65";
    el.setAttribute("aria-selected", "false");
    el.classList.remove("active");
  };
  const hideContent = (el) => { if (el) el.classList.add("hidden"); };
  const showContent = (el) => { if (el) el.classList.remove("hidden"); };

  if (name === "records") {
    active(recTab); inactive(passTab); inactive(adminTab);
    hideContent(passContent); showContent(recContent); hideContent(adminContent);
    renderRecordsList();
  } else if (name === "admin") {
    active(adminTab); inactive(passTab); inactive(recTab);
    hideContent(passContent); hideContent(recContent); showContent(adminContent);
    renderAdminConsole();
  } else {
    active(passTab); inactive(recTab); inactive(adminTab);
    hideContent(recContent); hideContent(adminContent); showContent(passContent);
  }
}

document.getElementById("tab-passwords")?.addEventListener("click", () => _switchVaultTab("passwords"));
document.getElementById("tab-records")?.addEventListener("click",   () => _switchVaultTab("records"));
document.getElementById("tab-admin")?.addEventListener("click",     () => _switchVaultTab("admin"));

// =====================================================================
// Phase 7.1-F: Admin console
// =====================================================================

/**
 * Admin console を render する (= tab-admin が clicked time)。
 * - company info 表示
 * - admin-invite-btn handler 経由で slot-create を叩く
 * - admin-inbox-list を /api/corp/admin/inbox から取得して描画
 * - admin-employees-list を session.vault.employees から描画
 */
async function renderAdminConsole() {
  if (!isAdminMode()) {
    // 安全弁: business / personal mode の人が誤って admin tab を踏んだら戻す
    _switchVaultTab("passwords");
    return;
  }

  const v = currentVault();

  // Phase 7.2-B (α): 自社の corpKeypair を未保持なら自動 setup
  //   未 setup の状態だと社員が server-pubkey を取得できず signup 失敗するので、
  //   admin が admin tab に入った時点で常に確認 + 必要なら生成 + upload + escrow。
  //   通常は alreadyExisted=true で即 return、 初回だけ生成 + saveVault が走る。
  if (v?.companyId) {
    try {
      const r = await ensureAdminCorpKeypair();
      if (r?.justCreated) {
        console.log("[admin] corpKeypair v" + r.version + " を生成しました (= 社員 signup 可能になりました)");
        // simple toast 風通知 (admin tab に何か表示する場所があれば差し込む)
        const nameEl = document.getElementById("admin-company-name");
        if (nameEl && !nameEl.dataset.keypairNotice) {
          nameEl.dataset.keypairNotice = "1";
          const notice = document.createElement("div");
          notice.style.cssText = "margin-top:8px;padding:6px 10px;background:#e7f5ff;border:1px solid #6dc7e0;border-radius:6px;font-size:12px;color:#0a4d63";
          notice.textContent = "🔐 会社の暗号鍵 v" + r.version + " を生成しました";
          nameEl.parentElement?.appendChild(notice);
        }
        // audit push
        _auditPushEvent({
          action: "corp-keypair-uploaded",
          details: { companyId: v.companyId, version: r.version, initial: true }
        }).catch(() => {});
      } else if (r?.missingEscrow) {
        console.warn("[admin] 自端末に corpKeypair private が無い (= 別端末で生成済?)。 会社運用に支障あり");
      }
    } catch (e) {
      console.error("[admin] ensureAdminCorpKeypair failed:", e?.message ?? e);
      alert("会社の暗号鍵セットアップに失敗: " + (e?.message || e) + "\n\n社員の招待 / signup が動作しない可能性があります。");
    }
  }

  // 1. Company info
  const nameEl = document.getElementById("admin-company-name");
  const idEl   = document.getElementById("admin-company-id");
  if (nameEl) nameEl.textContent = v?.companyName || v?.companyId || "—";
  if (idEl)   idEl.textContent   = v?.companyId || "—";

  // 2. Employees list — Phase 7.1-P: corp/info の server-side member 一覧と
  //    vault.employees の Recovery 保管状況を merge して描画
  //    Phase 7.2-B v2.6 #131: listActiveEmployees / listPendingEmployees も並列取得して
  //      「壊れた member」 (= slot active なのに corp:<cid>:member:<pkH> 不在) を検出。
  try {
    const [info, activeRes, pendingRes] = await Promise.allSettled([
      corpInfoUI(),
      listActiveEmployees(),
      listPendingEmployees(),
    ]);
    const infoVal = info.status === "fulfilled" ? info.value : null;
    if (infoVal) state._corpInfo = infoVal;
    const activePkSet = new Set((activeRes.status === "fulfilled" ? activeRes.value : []).map(m => m.pkHash));
    const pendingPkSet = new Set((pendingRes.status === "fulfilled" ? pendingRes.value : []).map(m => m.pkHash));
    _renderAdminEmployeesList(v?.employees || [], infoVal, { activePkSet, pendingPkSet });
  } catch (e) {
    console.warn("[admin] corp/info failed (rendering vault.employees only):", e?.message);
    _renderAdminEmployeesList(v?.employees || [], null);
  }

  // Phase 7.2-B (α): 旧 design の inbox / recovery-deposit 処理は廃止
  //   - _refreshAdminInbox: 機種追加コード方式の admin auto-approve が α では機能しない
  //     (= admin が社員 Recovery を保管していない)
  //   - _processRecoveryDeposits: 社員から admin への ECIES relay は α では送信されない
  //   関数自体は残置 (= #65 cleanup で削除予定)

// Phase 7.2-B v2: K1 buttons bind (idempotent)
  const k1GenBtn = document.getElementById("admin-k1-generate-btn");
  if (k1GenBtn && !k1GenBtn.dataset.bound) {
    k1GenBtn.dataset.bound = "1";
    k1GenBtn.addEventListener("click", () => _onAdminK1Generate().catch(console.error));
  }
  const k1RotBtn = document.getElementById("admin-k1-rotate-btn");
  if (k1RotBtn && !k1RotBtn.dataset.bound) {
    k1RotBtn.dataset.bound = "1";
    k1RotBtn.addEventListener("click", () => _onAdminK1Rotate().catch(console.error));
  }
  const k1DistBtn = document.getElementById("admin-k1-distribute-btn");
  if (k1DistBtn && !k1DistBtn.dataset.bound) {
    k1DistBtn.dataset.bound = "1";
    k1DistBtn.addEventListener("click", () => _onAdminK1Distribute().catch(console.error));
  }

  // Phase 7.2-A: Render network policy input from cached corp info
  _renderAdminNetPolicy();

  // Phase 7.2-B v2: K1 配布 UI を render
  _renderAdminK1Section().catch((e) => console.error("[admin-k1]", e));

  // Phase 7.2-B v2.6 #132: K1 配布の完全自動化 — admin 画面開いた瞬間に pending member
  //   居れば自動 distribute (= ボタン押下不要)。 ZK 維持: client-side で wrap、
  //   server は ECIES blob を中継するのみ。
  //   admin K1 未生成の場合は skip (= admin が手動で 'K1 を生成' を押すまで何もしない)。
  // Phase 7.3-A.9 hotfix: 初期 burst 後 (= 2s delay) に発火、 rate-limit 回避
  setTimeout(async () => {
    try {
      const status = currentAdminK1Status();
      if (!status?.hasK1) return;  // K1 未生成なので skip
      const _offboarded = _offboardedPkSet();
      const pending = (await listPendingEmployees())
        .filter((m) => !_offboarded.has(m.pkHash));
      if (!pending || pending.length === 0) return;  // 配布対象なし (退社直後の stale を除外済)
      // Phase 7.3-A.10 #169-followup: 配布完了後に renderAdminConsole() が
      //   この setTimeout を再 arm し、 KV 伝播遅延 (flapping) で同じ pending が
      //   再出現 → 再配布 → toast / K1 ボタンが点滅するループになっていた。
      //   直近の自動配布から 30s 以内は自動配布を抑止する (手動ボタンは別経路で常時可)。
      if (Date.now() - _lastAutoK1DistributeAt < 30_000) return;
      _lastAutoK1DistributeAt = Date.now();
      console.log(`[admin-auto-k1] ${pending.length} 名の K1 未配布社員を自動配布`);
      const results = await distributeK1ToAllPendingSafe(_offboarded);
      const okCount = results.filter(r => r.ok).length;
      const failCount = results.length - okCount;
      if (okCount > 0) {
        toast(`🎉 新規社員 ${okCount} 名に K1 を自動配布しました` + (failCount > 0 ? ` (${failCount} 名失敗)` : ""), "ok", 10000);
        await _renderAdminK1Section();
        // employees list 再描画 (active 扱いに更新)
        renderAdminConsole().catch(() => {});
      } else if (failCount > 0) {
        console.warn("[admin-auto-k1] 全配布失敗:", results);
      }
    } catch (e) {
      const msg = String(e?.message || "");
      if (msg.includes("429") || msg.toLowerCase().includes("rate")) {
        // rate-limit (429) は無視。 admin が手動で配布ボタン押せば動く。
        console.log("[admin-auto-k1] rate-limited; retry on next admin tab open or manual button click");
      } else {
        console.warn("[admin-auto-k1] auto-distribute failed (non-fatal):", e?.message);
      }
    }
  }, 2000);
}

/**
 * Phase 7.2-B v2.1: K1 配布管理 UI を render する。
 *   - vault.k1Current (= admin の K1) の存在 + version 表示
 *   - K1 履歴 (k1History) 表示 + 各エントリに 🗑️ 削除 button
 *   - pending 社員数を fetch して 📤 配布 button 表示
 *   - 既存 K1 がある場合は 🔄 rotate button 表示
 */
// 退社処理直後の KV (eventual consistency) 伝播遅延で、 revokeSlot が削除済みの
//   member レコードが listPendingEmployees に一時的に残り、 退社者が「未配布社員」
//   として K1 配布ボタン / 自動配布の対象に出てしまう。 直近退社した pkHash を
//   grace 期間 (KV 伝播待ち) のあいだ pending 判定から除外する。
const _recentlyOffboarded = new Map();  // pkHash -> offboarded timestamp(ms)
const _OFFBOARD_GRACE_MS = 90_000;
// Phase 7.3-A.10 #169-followup: 自動 K1 配布の自己ループ抑止用スロットル。
let _lastAutoK1DistributeAt = 0;
function _markOffboarded(pkHash) {
  if (pkHash) _recentlyOffboarded.set(pkHash, Date.now());
}
function _isRecentlyOffboarded(pkHash) {
  const t = _recentlyOffboarded.get(pkHash);
  if (t === undefined) return false;
  if (Date.now() - t > _OFFBOARD_GRACE_MS) { _recentlyOffboarded.delete(pkHash); return false; }
  return true;
}
function _offboardedPkSet() {
  const set = new Set();
  for (const pk of [..._recentlyOffboarded.keys()]) {
    if (_isRecentlyOffboarded(pk)) set.add(pk);
  }
  return set;
}

async function _renderAdminK1Section() {
  const stateEl = document.getElementById("admin-k1-state");
  const genBtn  = document.getElementById("admin-k1-generate-btn");
  const rotBtn  = document.getElementById("admin-k1-rotate-btn");
  const distBtn = document.getElementById("admin-k1-distribute-btn");
  const histDetails = document.getElementById("admin-k1-history-details");
  const histCountEl = document.getElementById("admin-k1-history-count");
  const histListEl  = document.getElementById("admin-k1-history-list");
  const errEl   = document.getElementById("admin-k1-error");
  const resEl   = document.getElementById("admin-k1-result");
  if (!stateEl || !genBtn || !distBtn) return;

  errEl?.classList.add("hidden");
  resEl?.classList.add("hidden");

  const status = currentAdminK1Status();
  const v = currentVault();
  const hasK1 = !!status.hasK1;

  if (!hasK1) {
    stateEl.textContent = "未生成";
    stateEl.style.color = "#B45309";
    genBtn.style.display = "";
    if (rotBtn) rotBtn.style.display = "none";
    distBtn.style.display = "none";
    if (histDetails) histDetails.style.display = "none";
    return;
  }

  stateEl.textContent = `✅ 生成済 (current: v${status.k1Version})`;
  stateEl.style.color = "#047857";
  genBtn.style.display = "none";
  if (rotBtn) rotBtn.style.display = "";

  // History 表示
  const history = Array.isArray(v?.k1History) ? v.k1History : [];
  if (history.length > 0 && histDetails && histListEl) {
    histDetails.style.display = "";
    if (histCountEl) histCountEl.textContent = String(history.length);
    histListEl.innerHTML = "";
    for (const entry of history) {
      const row = document.createElement("div");
      row.style.cssText = "display: flex; align-items: center; gap: 8px; padding: 4px 6px; background: #F9FAFB; border-radius: 4px;";
      const dateStr = entry.retiredAt ? new Date(entry.retiredAt).toLocaleString("ja-JP") : "—";
      row.innerHTML = `<span style="flex: 0 0 60px; font-weight: 600;">v${entry.version}</span>` +
        `<span style="flex: 1; opacity: 0.7;">退役: ${dateStr}</span>`;
      const delBtn = document.createElement("button");
      delBtn.className = "btn-outline";
      delBtn.style.cssText = "padding: 2px 8px; font-size: 11px; color: #DC2626; border-color: #FCA5A5;";
      delBtn.textContent = "🗑️ 削除";
      delBtn.addEventListener("click", () => _onAdminK1DeleteHistory(entry.version));
      row.appendChild(delBtn);
      histListEl.appendChild(row);
    }
  } else if (histDetails) {
    histDetails.style.display = "none";
  }

  // Pending 社員数
  try {
    const pending = (await listPendingEmployees())
      .filter((m) => !_isRecentlyOffboarded(m.pkHash));
    if (pending.length === 0) {
      distBtn.style.display = "none";
    } else {
      distBtn.style.display = "";
      distBtn.textContent = `📤 ${pending.length} 名の未配布社員に K1 を配布`;
    }
  } catch (e) {
    // Phase 7.3-A.10 #169-followup: pending 取得が失敗 (KV 伝播揺らぎ / 429 等) した
    //   ときにボタンを投機的に表示すると、 成功時の「0 名 → 非表示」と交互になり点滅する。
    //   取得失敗時はボタンの表示状態を一切変更しない (= 直前の確定状態を維持)。
    console.warn("[admin-k1] pending fetch failed (ボタン状態は維持):", e?.message);
  }
}

async function _onAdminK1Rotate() {
  const errEl = document.getElementById("admin-k1-error");
  const resEl = document.getElementById("admin-k1-result");
  const btn   = document.getElementById("admin-k1-rotate-btn");
  if (!btn) return;
  if (!confirm("K1 を新 version に rotate します。 既存 K1 は履歴に保管されます。\n\n続行しますか？\n(rotate 後、 全 active 社員に新 K1 を配布する必要があります)")) return;
  errEl?.classList.add("hidden");
  resEl?.classList.add("hidden");
  btn.disabled = true;
  btn.textContent = "rotate 中…";
  try {
    const r = await rotateOrCreateAdminK1();
    if (resEl) {
      resEl.classList.remove("hidden");
      resEl.textContent = `🔄 K1 を v${r.k1Version} に rotate しました。 履歴サイズ: ${r.historySize}。 続けて全社員に再配布が必要です。`;
    }
    _auditPushEvent({ action: "admin-k1-rotated", details: { version: r.k1Version, historySize: r.historySize } }).catch(() => {});
    btn.disabled = false;
    btn.textContent = "🔄 K1 を rotate (新 version 生成)";
    await _renderAdminK1Section();
  } catch (e) {
    console.error("[admin-k1-rotate]", e);
    if (errEl) {
      errEl.classList.remove("hidden");
      errEl.textContent = "❌ " + (e?.message || e);
    }
    btn.disabled = false;
    btn.textContent = "🔄 K1 を rotate (新 version 生成)";
  }
}

async function _onAdminK1DeleteHistory(version) {
  const errEl = document.getElementById("admin-k1-error");
  const resEl = document.getElementById("admin-k1-result");
  if (!confirm(`K1 v${version} を履歴から削除します。\n\nこの version で暗号化された社員の過去レコードは、 今後配布できなくなります (= 当該社員がまだ移行していない場合、 復号不能)。\n\n続行しますか？`)) return;
  errEl?.classList.add("hidden");
  resEl?.classList.add("hidden");
  try {
    const r = await deleteAdminK1FromHistory(version);
    if (resEl) {
      resEl.classList.remove("hidden");
      resEl.textContent = `🗑️ K1 v${r.removedVersion} を履歴から削除しました。 残り ${r.remainingCount} 件`;
    }
    _auditPushEvent({ action: "admin-k1-history-deleted", details: { version } }).catch(() => {});
    await _renderAdminK1Section();
  } catch (e) {
    console.error("[admin-k1-del]", e);
    if (errEl) {
      errEl.classList.remove("hidden");
      errEl.textContent = "❌ " + (e?.message || e);
    }
  }
}

/** 社員一覧から呼ぶ: 特定社員に過去 K1 を再配布 */
async function _onAdminK1RestoreToMember(targetPkHash) {
  const v = currentVault();
  const history = Array.isArray(v?.k1History) ? v.k1History : [];
  if (history.length === 0) {
    alert("過去 K1 が履歴にありません。");
    return;
  }
  const versions = history.map((e) => e.version).sort((a, b) => b - a);
  const verStr = prompt(`配布する過去 K1 の version を入力してください。\n利用可能: ${versions.join(", ")}\n\n社員: ${targetPkHash.slice(0, 16)}...`, String(versions[0]));
  if (!verStr) return;
  const version = parseInt(verStr, 10);
  if (!history.some((e) => e.version === version)) {
    alert(`version ${version} は履歴にありません`);
    return;
  }
  try {
    const r = await restorePastK1ToMember(targetPkHash, version);
    alert(`✅ v${version} を社員に配布しました (14 日有効)。`);
    _auditPushEvent({ action: "admin-k1-restored-to-member", details: { version, targetPkHash } }).catch(() => {});
  } catch (e) {
    console.error("[admin-k1-restore]", e);
    alert("❌ " + (e?.message || e));
  }
}
if (typeof window !== "undefined") {
  window._onAdminK1RestoreToMember = _onAdminK1RestoreToMember;
}


async function _onAdminK1Generate() {
  const errEl = document.getElementById("admin-k1-error");
  const resEl = document.getElementById("admin-k1-result");
  const btn   = document.getElementById("admin-k1-generate-btn");
  if (!btn) return;
  errEl?.classList.add("hidden");
  resEl?.classList.add("hidden");
  btn.disabled = true;
  btn.textContent = "生成中…";
  try {
    const r = await generateAndSaveAdminK1();
    if (resEl) {
      resEl.classList.remove("hidden");
      resEl.textContent = `✅ K1 を生成して vault に保存しました (version: ${r.k1Version})。 続けて社員に配布できます。`;
    }
    _auditPushEvent({ action: "admin-k1-generated", details: { version: r.k1Version } }).catch(() => {});
    // Phase 7.2-B v2.5 hotfix: button 状態を明示的に戻す (= _renderAdminK1Section が失敗しても button 復旧)
    btn.disabled = false;
    btn.textContent = "🎲 K1 を生成して保存";
    // re-render
    try {
      await _renderAdminK1Section();
    } catch (rerr) {
      console.error("[admin-k1-gen] _renderAdminK1Section failed (UI 更新だけ失敗、 K1 自体は保存済):", rerr);
    }
  } catch (e) {
    console.error("[admin-k1-gen]", e);
    if (errEl) {
      errEl.classList.remove("hidden");
      errEl.textContent = "❌ " + (e?.message || e);
    }
    btn.disabled = false;
    btn.textContent = "🎲 K1 を生成して保存";
  }
}

async function _onAdminK1Distribute() {
  const errEl = document.getElementById("admin-k1-error");
  const resEl = document.getElementById("admin-k1-result");
  const btn   = document.getElementById("admin-k1-distribute-btn");
  if (!btn) return;
  errEl?.classList.add("hidden");
  resEl?.classList.add("hidden");
  btn.disabled = true;
  btn.textContent = "配布中…";
  try {
    const results = await distributeK1ToAllPendingSafe();
    const okCount = results.filter(r => r.ok).length;
    const failCount = results.length - okCount;
    if (resEl) {
      resEl.classList.remove("hidden");
      resEl.textContent = `✅ 配布完了: ${okCount} 名成功` + (failCount > 0 ? ` / ${failCount} 名失敗` : "");
    }
    _auditPushEvent({
      action: "admin-k1-distributed",
      details: { okCount, failCount, total: results.length }
    }).catch(() => {});
    await _renderAdminK1Section();
    // employees list も再描画 (status="active" に変わったので)
    renderAdminConsole().catch(() => {});
  } catch (e) {
    console.error("[admin-k1-dist]", e);
    if (errEl) {
      errEl.classList.remove("hidden");
      errEl.textContent = "❌ " + (e?.message || e);
    }
    btn.disabled = false;
    btn.textContent = "📤 未配布社員に K1 を配布";
  }
}

/**
 * Phase 7.1-P: vault.employees (= Recovery 保管済の社員) と server-side slots
 *   (corp/info → admin.slots[]) を merge して一覧描画する。
 *
 * 各 slot について:
 *   - vault.employees に該当 pkHash あり → "✅ Recovery 取り込み済"
 *   - vault.employees に未登録          → "⚠ Recovery 未取り込み (社員に再送信を依頼)"
 *
 * これにより admin は server-side membership と Recovery deposit の同期状況を
 * 一覧で確認でき、未取り込みの社員に再 deposit を促せる。
 */
function _renderAdminEmployeesList(employees, corpInfo, healthData = {}) {
  const listEl = document.getElementById("admin-employees-list");
  const emptyEl = document.getElementById("admin-employees-empty");
  if (!listEl) return;
  // Phase 7.2-B v2.6 #131: server-side member health 情報。 渡されない場合は legacy 表示。
  const activePkSet = healthData.activePkSet || null;
  const pendingPkSet = healthData.pendingPkSet || null;
  Array.from(listEl.children).forEach(c => { if (c !== emptyEl) c.remove(); });

  // Build server-side slots list (= non-admin members)
  const slots = (corpInfo?.admin?.slots || []).filter(s => !s.isAdmin && s.status === "active" && s.usedByPkHash);
  const empsByPk = new Map((employees || []).map(e => [e.publicKeyHash, e]));

  // Union: 各 server slot を 1 row + (server slot に居ない vault.employee は orphan として末尾追加)
  const rows = [];
  for (const slot of slots) {
    const emp = empsByPk.get(slot.usedByPkHash);
    // Phase 7.2-B (α): active slot は全て「在籍中」 扱い (= Recovery deposit 概念無し)
    rows.push({ slot, emp, source: "deposited" });
    if (emp) empsByPk.delete(slot.usedByPkHash);
  }
  // Orphan vault.employees (= corp/info に該当 slot 無し、退社済等)
  for (const emp of empsByPk.values()) {
    rows.push({ slot: null, emp, source: "orphan" });
  }

  if (rows.length === 0) {
    if (emptyEl) emptyEl.classList.remove("hidden");
    return;
  }
  if (emptyEl) emptyEl.classList.add("hidden");

  for (const { slot, emp, source } of rows) {
    const row = document.createElement("div");
    row.style.cssText = "display:flex; align-items:center; justify-content:space-between; padding:8px 10px; border:1px solid var(--line); border-radius:6px; font-size:13px; gap:8px;";
    let nameHtml, statusHtml, idHtml;
    if (source === "deposited") {
      // Phase 7.2-B (α): emp が無い (vault.employees に保存していない) 場合は slot ID + pkHash で識別
      // #166: admin が招待時に付けた slot ラベル (社員名) を最優先で表示する。
      const _slotLabel = slot?.slotId ? (_readSlotLabels()[slot.slotId]?.label || "") : "";
      const displayName = _slotLabel || emp?.displayName || emp?.userId || ("社員 " + (slot.slotId || ""));
      nameHtml = `<span style="font-weight:600;">${escapeHtml(displayName)}</span>` +
                 (emp?.email ? `<span style="opacity:0.6; margin-left:6px;">(${escapeHtml(emp.email)})</span>` : "");
      // Phase 7.2-B (α): 「📲 機種追加コード」 ボタンは廃止 (旧 design で admin が Recovery
      //   を保管していた前提の機能、 α では社員自身が Recovery を持つので不要)。
      // Phase 7.2-B v2.6 #131: server-side health badge — pubkey 未登録 / K1 未配布 を可視化。
      const slotPk = slot.usedByPkHash || emp?.publicKeyHash || "";
      let healthBadge = `<span style="color:#10B981; font-size:12px;">✅ ${i18n_t("app.admin.emp_status.active_alpha") || "在籍中"}</span>`;
      if (activePkSet || pendingPkSet) {
        if (activePkSet?.has(slotPk)) {
          healthBadge = `<span style="color:#10B981; font-size:12px;">✅ ${i18n_t("app.admin.emp_status.active_alpha") || "在籍中"} (K1 配布済)</span>`;
        } else if (pendingPkSet?.has(slotPk)) {
          healthBadge = `<span style="color:#F59E0B; font-size:12px;">⏳ K1 配布待ち</span>`;
        } else {
          healthBadge = `<span style="color:#DC2626; font-size:12px;">⚠ 未活性化 (社員ログイン未完了 — 退社処理推奨)</span>`;
        }
      }
      statusHtml = healthBadge +
                   ` <button type="button" class="btn-outline emp-rename-btn" ` +
                   `data-slot-id="${escapeHtml(slot.slotId)}" ` +
                   `data-current="${escapeHtml(_slotLabel)}" ` +
                   `style="margin-left:8px; font-size:11px; padding:2px 8px;">` +
                   `${i18n_t("app.admin.btn_rename_emp") || "✏️ 名前"}</button>` +
                   ` <button type="button" class="btn-outline emp-offboard-btn" ` +
                   `data-slot-id="${escapeHtml(slot.slotId)}" ` +
                   `data-pk-hash="${escapeHtml(slotPk)}" ` +
                   `data-display-name="${escapeHtml(displayName)}" ` +
                   `style="margin-left:8px; font-size:11px; padding:2px 8px; color:#991B1B; border-color:#FCA5A5;">` +
                   `${i18n_t("app.admin.btn_offboard") || "🔴 退社処理"}</button>`;
      idHtml = `<code style="font-size:10px; opacity:0.4;">${escapeHtml((emp?.publicKeyHash || slot.usedByPkHash || "").slice(0, 12))}…</code>`;
    } else if (source === "pending") {
      nameHtml = `<span style="font-weight:600; opacity:0.7;">${i18n_t("app.admin.emp_pending_name_alpha") || "(社員 — 未参加)"}</span>` +
                 `<span style="opacity:0.5; margin-left:6px;">slot ${escapeHtml(slot.slotId)}</span>`;
      statusHtml = `<span style="color:#F59E0B; font-size:12px;">📤 ${i18n_t("app.admin.emp_status.invited_alpha") || "招待コード送付済 (未参加)"}</span>` +
                   ` <button type="button" class="btn-outline emp-revoke-btn" data-slot-id="${escapeHtml(slot.slotId)}" ` +
                   `style="margin-left:8px; font-size:11px; padding:2px 8px;">${i18n_t("app.admin.btn_revoke_reinvite") || "🔄 取り消して再招待"}</button>`;
      idHtml = `<code style="font-size:10px; opacity:0.4;">${escapeHtml((slot.usedByPkHash || "").slice(0, 12))}…</code>`;
    } else {
      // orphan
      nameHtml = `<span style="font-weight:600; opacity:0.5;">${escapeHtml(emp.displayName || emp.userId)}</span>` +
                 `<span style="opacity:0.5; margin-left:6px;">(${i18n_t("app.admin.emp_orphan") || "離脱済"})</span>`;
      statusHtml = `<span style="color:#94A3B8; font-size:12px;">— ${i18n_t("app.admin.emp_status.orphan_alpha") || "離脱済"}</span>`;
      idHtml = `<code style="font-size:10px; opacity:0.4;">${escapeHtml((emp.publicKeyHash || "").slice(0, 12))}…</code>`;
    }
    row.innerHTML = `
      <div style="flex:1; min-width:0;">${nameHtml}<br>${statusHtml}</div>
      ${idHtml}
    `;
    listEl.appendChild(row);
  }

  // Phase 7.1-AC: "📲 機種追加コード" ボタン handler — admin が完全 lockout 救済用コード発行
  listEl.querySelectorAll(".emp-device-add-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const pkHash = btn.dataset.pkHash;
      const displayName = btn.dataset.displayName || "(社員)";
      if (!pkHash) return;
      const autoApprove = confirm(
        i18n_t("app.admin.confirm_device_add_auto", { name: displayName })
      );
      btn.disabled = true;
      const orig = btn.textContent;
      btn.textContent = i18n_t("app.admin.btn_issuing") || "発行中…";
      try {
        const res = await corpAdminDeviceAddCodeCreateUI({ empPkHash: pkHash, autoApprove });
        // Phase 7.2-E.4a: audit (機種追加コード発行) — code 自体は audit に残さない
        _auditPushEvent({ action: "device-add-code-issued",
          details: { targetEmpPkHash: pkHash, displayName, autoApprove,
                     expiresInSeconds: res.expiresInSeconds } }).catch(() => {});
        const minutes = Math.ceil(res.expiresInSeconds / 60);
        const lines = [
          (i18n_t("app.admin.code_issued_header") || "📲 機種追加コードを発行しました"),
          "",
          (i18n_t("app.admin.code_label") || "コード") + ":  " + res.code,
          (i18n_t("app.admin.code_for") || "対象") + ":  " + displayName,
          (i18n_t("app.admin.code_ttl") || "有効期限") + ":  " + minutes + (i18n_t("app.admin.code_min") || " 分"),
          (i18n_t("app.admin.code_mode") || "モード") + ":  " + (autoApprove ? (i18n_t("app.admin.code_auto_approve") || "自動承認") : (i18n_t("app.admin.code_manual_approve") || "承認必須")),
          "",
          (i18n_t("app.admin.code_instruction") || "このコードを社員の新端末で入力してもらってください。一回限り、TTL 後は失効します。"),
        ];
        window.prompt(lines.join("\n"), res.code);  // prompt にしておくとコピーしやすい
      } catch (e) {
        toast((i18n_t("app.admin.toast_code_failed") || "コード発行失敗: ") + (e?.message || e), "err", 8000);
      } finally {
        btn.disabled = false;
        btn.textContent = orig;
      }
    });
  });

  // Phase 7.1-S: "退社処理" ボタン handler — slot revoke + vault.employees 削除
  // #166-followup: 社員名 (slot ラベル) を社員一覧から直接変更する。
  listEl.querySelectorAll(".emp-rename-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const slotId = btn.dataset.slotId;
      if (!slotId) return;
      const cur = btn.dataset.current || "";
      const next = prompt(i18n_t("app.corp.prompt_label") || "社員名 (空欄で削除):", cur);
      if (next === null) return;
      try {
        // 即時保存 (debounce キューは通さない)。 saveVault は必ず新 Arweave TX を書く。
        //   TX バッジは saveVault の呼び出し側が更新する設計なので、 ここで明示更新する
        //   (= 通常編集と同じく「保存中」→「保存済み (新 txid)」を表示)。
        updateSaveStatusBadge("saving");
        await _setSlotLabel(slotId, next.trim() || null);
        updateSaveStatusBadge("saved", { txid: currentLatestTxId() });
        toast(i18n_t("app.corp.toast_label_saved") || "✅ 名前を保存しました", "ok", 4000);
        await renderAdminConsole();
      } catch (e) {
        updateSaveStatusBadge("error", { error: e });
        toast((e?.message || String(e)), "err", 5000);
      }
    });
  });
  listEl.querySelectorAll(".emp-offboard-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const slotId = btn.dataset.slotId;
      const pkHash = btn.dataset.pkHash;
      const displayName = btn.dataset.displayName || "(社員)";
      if (!slotId || !pkHash) return;

      const confirmMsg = i18n_t("app.admin.confirm_offboard", { name: displayName });

      if (!confirm(confirmMsg)) return;
      btn.disabled = true;
      btn.textContent = i18n_t("app.admin.btn_offboarding") || "退社処理中…";

      try {
        await corpSlotRevokeUI(slotId);
        _markOffboarded(pkHash);  // KV 伝播遅延中の pending 誤判定を防ぐ
        removeEmployeeUI(pkHash);
        scheduleSave(currentVault());
        await flushSaveDebounce().catch(() => {});
        toast(
          (i18n_t("app.admin.toast_offboarded") || "✅ {name} さんの退社処理が完了しました").replace("{name}", displayName),
          "ok", 6000
        );
        // Phase 7.2-E.4a: audit (退社処理)
        _auditPushEvent({ action: "employee-offboarded",
          details: { slotId, empPkHash: pkHash, displayName } }).catch(() => {});
        renderAdminConsole().catch(() => {});
      } catch (e) {
        toast(
          (i18n_t("app.admin.toast_offboard_failed") || "退社処理失敗: ") + (e?.message || String(e)),
          "err", 6000
        );
        btn.disabled = false;
        btn.textContent = i18n_t("app.admin.btn_offboard") || "🔴 退社処理";
      }
    });
  });

  // Phase 7.1-Q: "取り消して再招待" ボタン handler を全 row に bind
  listEl.querySelectorAll(".emp-revoke-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const slotId = btn.dataset.slotId;
      if (!slotId) return;
      const ok = confirm(
        i18n_t("app.admin.confirm_revoke_reinvite") ||
        "この社員の登録を取り消して、新しい招待コードを発行します。\n" +
        "もう一度この社員に招待 URL を送って signup し直してもらうと、\n" +
        "Recovery が改めて admin に届きます。続行しますか？"
      );
      if (!ok) return;
      btn.disabled = true;
      btn.textContent = i18n_t("app.admin.btn_revoking") || "取消中…";
      try {
        const r = await corpSlotRevokeUI(slotId);
        toast(
          (i18n_t("app.admin.toast_revoked_with_code") ||
           "✅ 招待を再発行しました。新コード: ") + (r?.code || "(発行済)"),
          "ok", 10000
        );
        // Phase 7.2-E.4a: audit (slot revoke + 再招待)
        _auditPushEvent({ action: "slot-revoked-reinvited",
          details: { slotId, newCodeIssued: !!r?.code } }).catch(() => {});
        // re-render
        renderAdminConsole().catch(() => {});
      } catch (e) {
        toast((i18n_t("app.admin.toast_revoke_failed") || "取消失敗: ") + (e?.message || String(e)), "err", 6000);
        btn.disabled = false;
        btn.textContent = i18n_t("app.admin.btn_revoke_reinvite") || "🔄 取り消して再招待";
      }
    });
  });
}

/**
 * Phase 7.1-G.2: Admin が relay inbox から「recovery-deposit (社員 signup 直後)」を
 * 取得・処理する。
 *
 * Each pending deposit について:
 *   1. ECIES 復号 (admin の signing private key で)
 *   2. JSON payload (= { recovery, displayName, ... }) を取り出す
 *   3. addEmployeeUI で vault.employees に追加 (encryptRecoveryWithMek 経由で再暗号化)
 *   4. corpRelayAckUI で server から relay 削除
 *   5. scheduleSave で vault 変更を flush
 */
async function _processRecoveryDeposits() {
  let inbox;
  try {
    const r = await corpRelayInboxUI();
    inbox = r?.items || [];
  } catch (e) {
    console.warn("[admin] relay inbox fetch failed:", e?.message ?? e);
    return;
  }
  const deposits = inbox.filter(it => it.kind === "recovery-deposit");
  if (deposits.length === 0) return;

  // admin の signing private key (= ECIES decrypt 用 raw scalar)
  const adminPrivKeyRaw = await currentSigningPrivateKeyRaw();
  if (!adminPrivKeyRaw) {
    console.warn("[admin] cannot get private key — skipping recovery-deposit processing");
    return;
  }

  let processedCount = 0;
  for (const dep of deposits) {
    try {
      // 1. Decode the wrapped payload (= b64u of JSON of ECIES envelope)
      const wrappedBytes = b64uDecode(dep.payload);
      const wrappedJson = new TextDecoder().decode(wrappedBytes);
      const wrapped = JSON.parse(wrappedJson);
      const eciesPayload = {
        ephemeralPublicKey: b64uDecode(wrapped.ephemeralPublicKey),
        iv:                 b64uDecode(wrapped.iv),
        ciphertext:         b64uDecode(wrapped.ciphertext),
      };
      // 2. ECIES decrypt
      const plaintextBytes = await eciesDecrypt(adminPrivKeyRaw, eciesPayload);
      const plaintext = new TextDecoder().decode(plaintextBytes);
      const meta = JSON.parse(plaintext);
      if (!meta?.recovery) throw new Error("decrypted payload missing recovery");
      // 3. Add to vault.employees[] (encryptRecoveryWithMek で admin の MEK で再暗号化)
      await addEmployeeUI({
        userId: dep.from,  // 社員の publicKeyHash を userId として使う
        displayName: meta.displayName || dep.from.slice(0, 12),
        publicKeyHash: dep.from,
        recovery: meta.recovery,
      });
      // 4. Ack to server (= delete the relay entry)
      try { await corpRelayAckUI(dep.id); } catch (e) { console.warn("[admin] ack failed (non-fatal):", e?.message); }
      processedCount++;
    } catch (e) {
      console.error("[admin] failed to process deposit:", dep.id, e?.message);
    }
  }

  if (processedCount > 0) {
    toast((i18n_t("app.admin.toast.recovery_deposits_processed") || "🆕 新社員 Recovery を ") + processedCount + (i18n_t("app.admin.toast.recovery_deposits_processed_unit") || " 件処理しました"), "ok", 6000);
    // session.vault を変更したので Arweave に flush する必要あり
    scheduleSave(currentVault());
    // Phase 7.1-AH: corp/info を再 fetch してから _renderAdminEmployeesList を呼ぶ。
    // 旧版は state._corpInfo を流用していたが、それだと server-side slot が古いまま
    // 'orphan/離脱済' 誤判定が起きていた (Yamaki 報告)。
    try {
      const freshInfo = await corpInfoUI();
      state._corpInfo = freshInfo;
      _renderAdminEmployeesList(currentVault()?.employees || [], freshInfo);
    } catch (e) {
      console.warn("[admin] corpInfoUI refresh after deposit failed (fallback to cached):", e?.message);
      _renderAdminEmployeesList(currentVault()?.employees || [], state._corpInfo || null);
    }
  }
}

async function _refreshAdminInbox() {
  const listEl = document.getElementById("admin-inbox-list");
  const emptyEl = document.getElementById("admin-inbox-empty");
  if (!listEl) return;

  let items = [];
  try {
    const r = await corpAdminInboxUI();
    items = r?.items || [];
  } catch (e) {
    console.warn("[admin] inbox fetch failed:", e?.message ?? e);
    return;
  }

  // Clear all children except emptyEl
  Array.from(listEl.children).forEach(c => { if (c !== emptyEl) c.remove(); });

  if (items.length === 0) {
    if (emptyEl) emptyEl.classList.remove("hidden");
    return;
  }
  if (emptyEl) emptyEl.classList.add("hidden");

  for (const req of items) {
    const row = document.createElement("div");
    const isAutoApprove = req.autoApprove === true;
    row.style.cssText = "border:1px solid " + (isAutoApprove ? "#10B981" : "#F59E0B") +
                        "; border-radius:6px; padding:10px 12px; background:" +
                        (isAutoApprove ? "#ECFDF5" : "#FFFBEB") + ";";
    const kindLabel = ({
      "device-add": "📲 機種追加",
      "password-change": "🔑 Master 変更",
      "deep-recovery": "🆘 全機種紛失復旧",
    })[req.kind] || req.kind;
    const autoBadge = isAutoApprove
      ? `<span style="background:#10B981; color:#fff; padding:1px 6px; border-radius:3px; font-size:10px; margin-left:6px;">自動承認</span>`
      : "";
    row.innerHTML = `
      <p style="margin:0 0 6px; font-size:13px;">
        <strong>${kindLabel}</strong>${autoBadge} from
        <code style="font-size:11px;">${escapeHtml((req.employeePkHash || "").slice(0, 16))}…</code>
      </p>
      <p style="margin:0 0 8px; font-size:11px; opacity:0.6;">
        端末名: ${escapeHtml(req.displayName || "—")} ·
        作成: ${escapeHtml(req.createdAt || "")}` +
        (req.redeemedFromIp ? ` · IP: <code>${escapeHtml(req.redeemedFromIp)}</code>` : "") +
      `
      </p>
      <div style="display:flex; gap:6px;">
        <button class="btn-primary admin-approve-btn" data-req-id="${escapeHtml(req.reqId)}"
                data-emp-pkhash="${escapeHtml(req.employeePkHash)}"
                data-new-device-pubkey="${escapeHtml(req.newDevicePubKey)}"
                style="font-size:12px;">${isAutoApprove ? "⚡ 自動承認実行" : "✅ 承認"}</button>
        <button class="btn-outline admin-deny-btn" data-req-id="${escapeHtml(req.reqId)}"
                style="font-size:12px;">❌ 拒否</button>
      </div>
    `;
    listEl.appendChild(row);
  }

  // Phase 7.1-AC: autoApprove フラグ付の項目は admin が来た瞬間に自動承認実行
  // (= admin がアプリを開いてさえいれば admin の操作なしに Recovery が relay 配信される)
  const autoItems = items.filter(it => it.autoApprove === true);
  if (autoItems.length > 0) {
    for (const req of autoItems) {
      try {
        // 仮想 button オブジェクトで _adminApprove を再利用
        const fakeBtn = {
          dataset: {
            reqId: req.reqId,
            empPkhash: req.employeePkHash,
            newDevicePubkey: req.newDevicePubKey,
          },
          disabled: false,
          textContent: "",
        };
        await _adminApprove(fakeBtn);
      } catch (e) {
        console.warn("[admin] auto-approve failed for", req.reqId, e?.message ?? e);
      }
    }
  }
}

// Admin: invite link 生成
document.getElementById("admin-invite-btn")?.addEventListener("click", async () => {
  const btn = document.getElementById("admin-invite-btn");
  const errEl = document.getElementById("admin-invite-error");
  const resultEl = document.getElementById("admin-invite-result");
  const urlEl = document.getElementById("admin-invite-url");
  errEl?.classList.add("hidden");
  resultEl?.classList.add("hidden");
  btn.disabled = true;
  const label = btn.textContent;
  btn.textContent = "生成中…";
  try {
    // #166: 招待時に入力された社員名を slot ラベルとして保存する。
    //   旧実装はこの入力 (admin-invite-display) を読まず捨てていた。
    const nameEl = document.getElementById("admin-invite-display");
    const empName = (nameEl?.value || "").trim().slice(0, 60);
    const r = await corpSlotCreateUI();
    if (!r?.code) throw new Error("no code returned");
    // slot ラベル (= 社員名) を admin vault に保存。 失敗しても招待コード自体は有効。
    if (empName && r.slotId) {
      try { await _setSlotLabel(r.slotId, empName); }
      catch (le) { console.warn("[invite] slot label save failed:", le?.message); }
    }
    // Phase 7.1-AE.2: URL ではなく code のみを表示 (phishing 防止)
    if (urlEl) urlEl.value = r.code;
    if (nameEl) nameEl.value = "";
    resultEl?.classList.remove("hidden");
  } catch (e) {
    if (errEl) {
      errEl.textContent = (i18n_t("app.admin.invite_error_prefix") || "招待コード生成エラー: ") + (e?.message ?? e);
      errEl.classList.remove("hidden");
    }
  } finally {
    btn.disabled = false;
    btn.textContent = label;
  }
});

// Admin: inbox 再読み込み
document.getElementById("admin-inbox-refresh")?.addEventListener("click", () => {
  _refreshAdminInbox().catch(() => {});
});

// Admin: approve / deny via event delegation
document.getElementById("admin-inbox-list")?.addEventListener("click", async (ev) => {
  const approveBtn = ev.target.closest(".admin-approve-btn");
  const denyBtn    = ev.target.closest(".admin-deny-btn");
  if (approveBtn) {
    await _adminApprove(approveBtn);
  } else if (denyBtn) {
    await _adminDeny(denyBtn);
  }
});

async function _adminApprove(btn) {
  const reqId = btn.dataset.reqId;
  const empPkHash = btn.dataset.empPkhash;
  const newDevicePubKeyB64 = btn.dataset.newDevicePubkey;
  if (!reqId || !empPkHash || !newDevicePubKeyB64) return;

  btn.disabled = true;
  const label = btn.textContent;
  btn.textContent = "承認中…";
  try {
    // 1. Decrypt employee's Recovery from admin's vault (= MEK decrypt 内部で処理)
    const recovery = await decryptEmployeeRecoveryUI(empPkHash);
    if (!recovery) throw new Error("この社員の Recovery が admin の vault に見つかりません");
    // 2. ECIES encrypt with the new device's public key
    const newDevicePubKey = b64uDecode(newDevicePubKeyB64);
    const enc = new TextEncoder();
    const payload = await eciesEncrypt(newDevicePubKey, enc.encode(recovery));
    // 3. Serialize ECIES payload to b64url JSON
    const payloadJson = JSON.stringify({
      ephemeralPublicKey: b64uEncode(payload.ephemeralPublicKey),
      iv:                 b64uEncode(payload.iv),
      ciphertext:         b64uEncode(payload.ciphertext),
    });
    const payloadB64 = b64uEncode(new TextEncoder().encode(payloadJson));
    // 4. Send to server (= relay creation)
    await corpAdminApproveUI({ reqId, payload: payloadB64 });
    // Phase 7.2-E.4a: audit (device-add 承認)
    _auditPushEvent({ action: "device-add-approved",
      details: { reqId, empPkHash } }).catch(() => {});
    toast(i18n_t("app.admin.toast.approved") || "✅ 承認しました。社員側で受信されます (24h 以内)。", "ok", 6000);
    await _refreshAdminInbox();
  } catch (e) {
    toast((i18n_t("app.admin.toast.approve_failed") || "❌ 承認失敗: ") + (e?.message ?? e), "error", 8000);
    btn.disabled = false;
    btn.textContent = label;
  }
}

async function _adminDeny(btn) {
  const reqId = btn.dataset.reqId;
  if (!reqId) return;
  const reason = window.prompt(i18n_t("app.admin.prompt.deny_reason") || "拒否理由 (任意、空でも OK):", "") || "";
  btn.disabled = true;
  const label = btn.textContent;
  btn.textContent = "拒否中…";
  try {
    await corpAdminDenyUI({ reqId, reason });
    // Phase 7.2-E.4a: audit (device-add 拒否)
    _auditPushEvent({ action: "device-add-denied",
      details: { reqId, reasonProvided: !!reason } }).catch(() => {});
    toast(i18n_t("app.admin.toast.denied") || "拒否しました", "ok", 5000);
    await _refreshAdminInbox();
  } catch (e) {
    toast((i18n_t("app.admin.toast.deny_failed") || "❌ 拒否失敗: ") + (e?.message ?? e), "error", 8000);
    btn.disabled = false;
    btn.textContent = label;
  }
}




// Phase 7.2-E: Audit event を ECIES(adminPubKey) で wrap + server に push (best effort)
async function _auditPushEvent(eventObj) {
  try {
    const { eciesEncrypt } = await import("/lib/vault-crypto.js?v=11331c7d");
    const info = state._corpInfo;
    const adminPubKeyB64u = info?.admin?.adminPublicKey || info?.member?.adminPublicKey;
    if (!adminPubKeyB64u) {
      // admin の pubkey が分からなければ push しない (= silent skip)
      console.warn("[audit] adminPublicKey not available, skip event push");
      return;
    }
    const pubRaw = b64uDecode(adminPubKeyB64u);
    if (pubRaw.length !== 65 || pubRaw[0] !== 0x04) {
      console.warn("[audit] invalid adminPublicKey format");
      return;
    }
    const fullEvent = {
      ...eventObj,
      at: new Date().toISOString(),
      // actor は server 側で signed request の pkHash から自動 set される (= fromPkHash field)
    };
    const enc = new TextEncoder();
    const payload = await eciesEncrypt(pubRaw, enc.encode(JSON.stringify(fullEvent)));
    const wrapped = JSON.stringify({
      ephemeralPublicKey: b64uEncode(payload.ephemeralPublicKey),
      iv:                 b64uEncode(payload.iv),
      ciphertext:         b64uEncode(payload.ciphertext),
    });
    const payloadB64 = b64uEncode(new TextEncoder().encode(wrapped));
    await corpAuditPushUI(payloadB64);
  } catch (e) {
    // 監査ログ送信は best effort、 失敗してもメイン操作には影響させない
    console.warn("[audit] push failed (non-fatal):", e?.message);
  }
}

// Phase 7.2-A: Admin: Network policy (IP allowlist) save handler
document.getElementById("admin-netpolicy-save-btn")?.addEventListener("click", async () => {
  const inputEl = document.getElementById("admin-ip-allowlist-input");
  const resultEl = document.getElementById("admin-netpolicy-result");
  const errEl = document.getElementById("admin-netpolicy-error");
  const btn = document.getElementById("admin-netpolicy-save-btn");
  resultEl?.classList.add("hidden");
  errEl?.classList.add("hidden");

  // Parse textarea: 1 行 1 CIDR、 # 以降コメント、 空行スキップ
  const lines = (inputEl?.value || "")
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(l => l.length > 0 && !l.startsWith("#"));

  // Phase 7.2-D: block-personal toggle 取得
  const blockPersonalEl = document.getElementById("admin-netpolicy-block-personal");
  const blockPersonal = !!blockPersonalEl?.checked;
  // Phase 7.2-F: restrict-read toggle 取得 (= 「読み出しも社内のみ」)
  const restrictReadEl = document.getElementById("admin-netpolicy-restrict-read");
  const restrictRead = !!restrictReadEl?.checked;

  btn.disabled = true;
  const orig = btn.textContent;
  btn.textContent = i18n_t("app.admin.netpolicy_saving") || "保存中…";
  try {
    const res = await corpAdminSetIpPolicyUI({
      ipAllowlist: lines,
      blockPersonalFromOurNetwork: blockPersonal,
      restrictReadToAllowlist: restrictRead,
    });
    // Phase 7.2 hotfix: 保存成功後に state._corpInfo を更新 (= 即座に reload しても残る)
    if (res?.company && state._corpInfo?.admin) {
      state._corpInfo.admin.ipAllowlist = res.company.ipAllowlist || [];
      state._corpInfo.admin.blockPersonalFromOurNetwork = res.company.blockPersonalFromOurNetwork === true;
      state._corpInfo.admin.restrictReadToAllowlist = res.company.restrictReadToAllowlist === true;
    }
    // Phase 7.2-E: audit event を push (= 非同期、 失敗しても save 成功は変わらない)
    _auditPushEvent({
      action: "set-ip-policy",
      details: {
        ipAllowlistCount: lines.length,
        blockPersonalFromOurNetwork: blockPersonal,
        restrictReadToAllowlist: restrictRead,
      },
    }).catch(() => {});
    if (resultEl) {
      const count = (res?.company?.ipAllowlist || []).length;
      resultEl.textContent = (i18n_t("app.admin.netpolicy_save_ok") || "✅ 保存しました ({count} 件の CIDR)").replace("{count}", count);
      resultEl.classList.remove("hidden");
    }
  } catch (e) {
    if (errEl) {
      let msg;
      if (e.code === "invalid_cidr") {
        msg = (i18n_t("app.admin.netpolicy_invalid_cidr") || "不正な CIDR: ") + (e.offender || "");
      } else if (e.code === "too_many") {
        msg = i18n_t("app.admin.netpolicy_too_many") || "CIDR が多すぎます (上限 1024)";
      } else if (e.code === "admin_ip_not_in_allowlist") {
        // (legacy code、 7.2-D.2 修正前の whole-list check 用)
        msg = e.message || (i18n_t("app.admin.netpolicy_admin_not_in_list") ||
          "あなたの現在 IP が allowlist に含まれていません。 allowlist 内のいずれかの IP からアクセスして save してください (VPN 経由でも OK)。");
      } else if (e.code === "added_cidr_not_containing_admin") {
        msg = e.message || (i18n_t("app.admin.netpolicy_added_cidr_invalid") ||
          "新規追加した CIDR の中に admin の現在 IP を含まないものが含まれています。 admin がその CIDR 内に居る状態で save してください (VPN 経由でも OK)。");
      } else if (e.code === "admin_ip_unknown") {
        msg = i18n_t("app.admin.netpolicy_admin_ip_unknown") || "admin の現在 IP が判定できませんでした。 もう一度試してください。";
      } else {
        msg = (i18n_t("app.admin.netpolicy_save_failed") || "保存失敗: ") + (e?.message || e);
      }
      errEl.textContent = msg;
      errEl.classList.remove("hidden");
    }
  } finally {
    btn.disabled = false;
    btn.textContent = orig;
  }
});

// Phase 7.2-E: Admin: 監査ログ取得 + 復号 + 表示
let _adminAuditCache = [];

/**
 * Phase 7.2-E.5: 復号済 audit events を vault.auditLog[] に append (新規 id のみ)。
 * 最大 1000 件保持、 超過は古いものを drop。
 * @param {Array} decryptedEvents
 * @returns {number} append された新規 event 数
 */
function _persistAuditEventsImpl(decryptedEvents) {
  const v = currentVault();
  if (!v) return 0;
  if (!Array.isArray(v.auditLog)) v.auditLog = [];
  const existingIds = new Set(v.auditLog.map(e => e.id));
  let added = 0;
  for (const ev of decryptedEvents || []) {
    if (!ev?.id) continue;
    if (existingIds.has(ev.id)) continue;
    v.auditLog.push(ev);
    existingIds.add(ev.id);
    added++;
  }
  if (v.auditLog.length > 1000) {
    v.auditLog.sort((a, b) => (a.id < b.id ? 1 : -1));  // newest first
    v.auditLog = v.auditLog.slice(0, 1000);
  }
  if (added > 0) {
    // 保存は debounce 経由で遅延 (= 同期 saveVault は重い、 別 ack 操作と batch)
    try { scheduleSave?.(v); } catch (e) { /* non-fatal */ }
  }
  return added;
}
// ============================================================================
// Phase 7.2-B v2: 緊急復旧用 会社共通鍵 (K1) export
// ----------------------------------------------------------------------------
// v1 時代は "server keypair" (= envelope.ws を server が wrap する設計) を export して
// いたが、 v2 で ws/server keypair は完全廃止された。 v2 では各社員 vault が
// real_MEK = HKDF(K1 ‖ K2) で暗号化されており、 K1 は admin vault の k1Current /
// k1History に平文 (b64u) で存在する。 サービス終了後は server の unwrap-k1 が死ぬため、
// admin がこの K1 を export し、 各社員が arpass-emergency-restore.html で
// 自分の factors (2-of-3) と合わせて vault を復号する。
//
// セキュリティ: K1 単体ではどの vault も開けない。 K2 (= 各社員固有、 各人の
// Master/Passkey/Recovery 由来) が別途必要。 このファイルが流出しても攻撃者は
// 各社員の 2-of-3 factor を入手しない限り 1 件も復号できない。
// ============================================================================
document.getElementById("admin-emergency-export-btn")?.addEventListener("click", async () => {
  const btn = document.getElementById("admin-emergency-export-btn");
  const resultEl = document.getElementById("admin-emergency-export-result");
  const errorEl = document.getElementById("admin-emergency-export-error");
  resultEl?.classList.add("hidden");
  errorEl?.classList.add("hidden");

  if (!isAdminMode()) {
    if (errorEl) {
      errorEl.textContent = (i18n_t("app.admin.emergency_export_no_keys") ||
        "K1 を export できるのは admin mode のみです。 admin vault を unlock してから再試行してください。");
      errorEl.classList.remove("hidden");
    }
    return;
  }

  // K1 export payload を admin vault から構築 (= getAdminK1EmergencyExport が
  //   admin mode / K1 存在チェックを行い、 未生成なら throw する)。
  let k1Export;
  try {
    k1Export = getAdminK1EmergencyExport();
  } catch (e) {
    if (errorEl) {
      errorEl.textContent = (i18n_t("app.admin.emergency_export_no_keys") ||
        "K1 が admin vault にありません。 admin tab で「K1 を生成」を実行してから再試行してください。") +
        (e?.message ? ` (${e.message})` : "");
      errorEl.classList.remove("hidden");
    }
    return;
  }

  // 二重確認
  const confirmMsg = (i18n_t("app.admin.emergency_export_confirm") ||
    "🆘 緊急復旧用の export です。\n\n" +
    "本当に Arpass のサービスが利用できない状況ですか?\n" +
    "この JSON には会社共通鍵 K1 が含まれます。 各社員が自分の 2-of-3 factor と\n" +
    "合わせて使うことで、 server なしで vault を復号できます。\n\n" +
    "続行しますか? (= JSON ファイルをダウンロード)");
  if (!confirm(confirmMsg)) return;
  const confirmMsg2 = (i18n_t("app.admin.emergency_export_confirm2") ||
    "最終確認: この K1 ファイルは信頼できる経路 (物理手渡し / 暗号化 USB 等) でのみ\n" +
    "社員に配布してください。 続行しますか?");
  if (!confirm(confirmMsg2)) return;

  btn.disabled = true;
  try {
    const cid = k1Export.companyId || null;
    const exportPayload = {
      kind: "arpass-business-k1-emergency-export",
      version: 2,
      companyId: cid,
      generatedAt: new Date().toISOString(),
      generatedByAdminPkHash: readMeta()?.publicKeyHash || readMeta()?.credIdHash || null,
      warning: "This file contains the company-common key K1 for Business mode vaults. " +
               "K1 alone CANNOT decrypt any vault — each employee also needs 2 of their own " +
               "3 factors (Master password / Passkey / Recovery). Distribute only after the " +
               "Arpass service has permanently shut down, over a trusted channel. " +
               "Use with arpass-emergency-restore.html on each employee device.",
      // K1 material (b64u, 32 byte each)
      k1Version: k1Export.k1Version,                  // current K1 version
      k1Current: k1Export.k1Current,                  // b64u
      k1History: k1Export.k1History,                  // [{ version, k1 (b64u), retiredAt }]
    };

    const blob = new Blob([JSON.stringify(exportPayload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `arpass-business-k1-${cid || "company"}-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 3000);

    // audit push
    _auditPushEvent({
      action: "emergency-k1-export",
      details: {
        companyId: cid,
        k1Version: k1Export.k1Version,
        historyCount: Array.isArray(k1Export.k1History) ? k1Export.k1History.length : 0,
        atShutdown: true,
      },
    }).catch(() => {});

    if (resultEl) {
      resultEl.innerHTML =
        "✅ 会社共通鍵 (K1) の JSON file をダウンロードしました。<br>" +
        "<strong>取扱注意:</strong> このファイルには会社共通鍵 K1 が含まれます。 " +
        "K1 単体では vault は開けません (= 各社員の 2-of-3 factor が別途必要) が、 " +
        "信頼できる経路 (= 物理的手渡し / 暗号化 USB 等) でのみ社員に配布してください。<br>" +
        "社員は <code>arpass-emergency-restore.html</code> でこの JSON と自分の Master / Recovery を入力し、 " +
        "server なしで vault を復号できます。";
      resultEl.classList.remove("hidden");
    }
    toast(i18n_t("app.admin.emergency_export_toast_ok") || "✅ K1 緊急 export 完了", "ok", 8000);
  } catch (e) {
    console.error("[emergency-export] failed:", e);
    if (errorEl) {
      errorEl.textContent = (i18n_t("app.admin.emergency_export_failed_prefix") || "Export 失敗: ") + (e?.message || String(e));
      errorEl.classList.remove("hidden");
    }
  } finally {
    btn.disabled = false;
  }
});

// ============================================================================
// Phase 7.2-B v2: 旧 KEK rotation handler は廃止
// ----------------------------------------------------------------------------
// v1 の "server keypair" rotation (= /api/corp/admin/upload-keypair +
// /api/corp/admin/rotate-kek を叩き、 privateKeyJwk を vault.serverPrivateKeys に
// escrow する設計) は v2 で完全に撤廃された。 v2 では company privkey / server
// keypair の server-side 永続保管は存在せず、 鍵 rotation は会社共通鍵 K1 の
// rotation (= admin K1 セクションの rotateOrCreateAdminK1) に一本化されている。
//
// vault.serverPrivateKeys は v1 のデッドフィールド。 ここでは一切書き込まない。
// 旧ボタン (#admin-kek-rotate-btn) が DOM に残っていても、 誤操作で v1 API を
// 叩かないよう no-op の説明ハンドラに置き換える。
// ============================================================================
document.getElementById("admin-kek-rotate-btn")?.addEventListener("click", () => {
  const resultEl = document.getElementById("admin-kek-rotate-result");
  const errorEl = document.getElementById("admin-kek-rotate-error");
  resultEl?.classList.add("hidden");
  if (errorEl) {
    errorEl.textContent = (i18n_t("app.admin.kek_rotate_deprecated") ||
      "この機能は廃止されました。 鍵の rotation は「会社共通鍵 (K1)」セクションの " +
      "「K1 を rotate」から実行してください。");
    errorEl.classList.remove("hidden");
  }
});

document.getElementById("admin-audit-refresh-btn")?.addEventListener("click", async () => {
  const listEl = document.getElementById("admin-audit-list");
  const emptyEl = document.getElementById("admin-audit-empty");
  const errEl = document.getElementById("admin-audit-error");
  const ackBtn = document.getElementById("admin-audit-ack-btn");
  errEl?.classList.add("hidden");
  if (listEl) {
    Array.from(listEl.children).forEach(c => { if (c !== emptyEl) c.remove(); });
  }
  try {
    const r = await corpAuditPullUI();
    const items = r?.items || [];
    if (items.length === 0) {
      if (emptyEl) {
        emptyEl.textContent = i18n_t("app.admin.audit_empty_pulled") || "(監査ログは現在ありません)";
        emptyEl.classList.remove("hidden");
      }
      if (ackBtn) ackBtn.disabled = true;
      _adminAuditCache = [];
      return;
    }
    if (emptyEl) emptyEl.classList.add("hidden");

    // ECIES 復号: admin の signing 秘密鍵 (= ECDH 用 raw scalar) が必要
    const { currentSigningPrivateKeyRaw } = await import("/lib/vault-client.js?v=51488219");
    const adminPrivKeyRaw = await currentSigningPrivateKeyRaw();
    if (!adminPrivKeyRaw) throw new Error("admin private key not available");

    const { eciesDecrypt } = await import("/lib/vault-crypto.js?v=11331c7d");
    const decryptedEvents = [];
    for (const item of items) {
      try {
        const wrappedBytes = b64uDecode(item.encrypted);
        const wrapped = JSON.parse(new TextDecoder().decode(wrappedBytes));
        const payload = {
          ephemeralPublicKey: b64uDecode(wrapped.ephemeralPublicKey),
          iv:                 b64uDecode(wrapped.iv),
          ciphertext:         b64uDecode(wrapped.ciphertext),
        };
        const ptBytes = await eciesDecrypt(adminPrivKeyRaw, payload);
        const event = JSON.parse(new TextDecoder().decode(ptBytes));
        decryptedEvents.push({ id: item.id, fromPkHash: item.fromPkHash, serverCreatedAt: item.createdAt, event });
      } catch (e) {
        decryptedEvents.push({ id: item.id, fromPkHash: item.fromPkHash, serverCreatedAt: item.createdAt, decryptError: e?.message || String(e) });
      }
    }
    _adminAuditCache = decryptedEvents;
    // Phase 7.2-E.5: vault に永続化 (新規 id だけ append)
    const persistAdded = _persistAuditEventsImpl(decryptedEvents);

    // 表示: vault.auditLog (= 永続) を newest-first で render
    // (= 直近 pull + 過去 ack 済 を合わせた完全な履歴)
    const vaultEntries = (currentVault()?.auditLog || []).slice();
    vaultEntries.sort((a, b) => (a.id < b.id ? 1 : -1));
    const displayList = vaultEntries.length > 0 ? vaultEntries : decryptedEvents;

    for (const e of displayList) {
      const row = document.createElement("div");
      row.style.cssText = "border: 1px solid var(--line); border-radius: 6px; padding: 8px 10px; font-size: 12px; line-height: 1.5;";
      row.classList.add("audit-row");
      row.dataset.action = e.event?.action || "";
      row.dataset.actor = e.fromPkHash || "";
      row.dataset.timestamp = e.event?.at || e.serverCreatedAt || "";
      const t = e.event?.at || e.serverCreatedAt;
      const action = e.event?.action || (e.decryptError ? `[decrypt error: ${e.decryptError}]` : "(unknown)");
      const detail = e.event?.details ? `<code style="font-size: 11px; opacity: 0.7;">${escapeHtml(JSON.stringify(e.event.details))}</code>` : "";
      const actor = e.fromPkHash ? `<code style="font-size: 11px; opacity: 0.6;">${escapeHtml(e.fromPkHash.slice(0, 12))}…</code>` : "";
      row.innerHTML =
        `<div style="display: flex; gap: 10px; align-items: baseline;">` +
        `<strong>${escapeHtml(action)}</strong>` +
        `<span style="font-size: 11px; opacity: 0.7;">${escapeHtml(t || "")}</span>` +
        `${actor}` +
        `</div>` +
        (detail ? `<div style="margin-top: 4px;">${detail}</div>` : "");
      listEl?.appendChild(row);
    }
    if (ackBtn) {
      ackBtn.disabled = false;
      ackBtn.textContent = (i18n_t("app.admin.audit_ack_btn_n") || "✅ 全て確認済 (= server から削除) [{n} 件]").replace("{n}", decryptedEvents.length);
    }
  } catch (e) {
    if (errEl) {
      errEl.textContent = (i18n_t("app.admin.audit_failed") || "監査ログ取得失敗: ") + (e?.message || e);
      errEl.classList.remove("hidden");
    }
  }
});

// Phase 7.2-E.6: filter + export
function _adminAuditApplyFilter() {
  const fAction = (document.getElementById("admin-audit-filter-action")?.value || "").trim().toLowerCase();
  const fActor  = (document.getElementById("admin-audit-filter-actor")?.value || "").trim().toLowerCase();
  const fFrom   = document.getElementById("admin-audit-filter-from")?.value || "";
  const fTo     = document.getElementById("admin-audit-filter-to")?.value || "";
  const rows = document.querySelectorAll(".audit-row");
  let shownCount = 0;
  for (const row of rows) {
    let visible = true;
    const action = (row.dataset.action || "").toLowerCase();
    const actor  = (row.dataset.actor || "").toLowerCase();
    const ts     = row.dataset.timestamp || "";
    if (fAction && !action.includes(fAction)) visible = false;
    if (fActor && !actor.startsWith(fActor)) visible = false;
    if (fFrom && ts && ts < fFrom) visible = false;
    if (fTo && ts && ts > fTo + "T23:59:59Z") visible = false;
    row.style.display = visible ? "" : "none";
    if (visible) shownCount++;
  }
  return shownCount;
}
["admin-audit-filter-action", "admin-audit-filter-actor", "admin-audit-filter-from", "admin-audit-filter-to"].forEach(id => {
  document.getElementById(id)?.addEventListener("input", _adminAuditApplyFilter);
  document.getElementById(id)?.addEventListener("change", _adminAuditApplyFilter);
});
document.getElementById("admin-audit-filter-clear-btn")?.addEventListener("click", () => {
  for (const id of ["admin-audit-filter-action", "admin-audit-filter-actor", "admin-audit-filter-from", "admin-audit-filter-to"]) {
    const el = document.getElementById(id);
    if (el) el.value = "";
  }
  _adminAuditApplyFilter();
});

// Phase 7.2-E.6: JSON / CSV export
function _adminAuditGetEntries() {
  return (currentVault()?.auditLog || _adminAuditCache || []).slice();
}
function _downloadFile(filename, content, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}
document.getElementById("admin-audit-export-json-btn")?.addEventListener("click", () => {
  const entries = _adminAuditGetEntries();
  if (entries.length === 0) {
    toast(i18n_t("app.admin.audit_export_empty") || "エクスポートする監査ログがありません", "warn", 4000);
    return;
  }
  const data = JSON.stringify({
    exportedAt: new Date().toISOString(),
    companyId: state.vault?.companyId,
    count: entries.length,
    events: entries,
  }, null, 2);
  const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  _downloadFile(`arpass-audit-${stamp}.json`, data, "application/json");
});
document.getElementById("admin-audit-export-csv-btn")?.addEventListener("click", () => {
  const entries = _adminAuditGetEntries();
  if (entries.length === 0) {
    toast(i18n_t("app.admin.audit_export_empty") || "エクスポートする監査ログがありません", "warn", 4000);
    return;
  }
  // CSV columns: id, timestamp, action, fromPkHash, details(JSON), serverCreatedAt
  const escape = (s) => {
    if (s == null) return "";
    const str = String(s);
    if (/[",\n\r]/.test(str)) return `"${str.replace(/"/g, '""')}"`;
    return str;
  };
  const lines = ["id,timestamp,action,fromPkHash,details,serverCreatedAt"];
  for (const e of entries) {
    lines.push([
      escape(e.id),
      escape(e.event?.at || e.serverCreatedAt),
      escape(e.event?.action || (e.decryptError ? `[decrypt error]` : "")),
      escape(e.fromPkHash),
      escape(e.event?.details ? JSON.stringify(e.event.details) : ""),
      escape(e.serverCreatedAt),
    ].join(","));
  }
  const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  _downloadFile(`arpass-audit-${stamp}.csv`, "\uFEFF" + lines.join("\n"), "text/csv;charset=utf-8");
});

document.getElementById("admin-audit-ack-btn")?.addEventListener("click", async () => {
  const errEl = document.getElementById("admin-audit-error");
  errEl?.classList.add("hidden");
  if (_adminAuditCache.length === 0) return;
  if (!confirm(i18n_t("app.admin.audit_ack_confirm") ||
    "監査ログを server から削除します。 取得しなおせなくなる前に、 必要なら自分で記録してください。 続行しますか?")) return;
  try {
    const ids = _adminAuditCache.map(e => e.id);
    await corpAuditAckUI(ids);
    _adminAuditCache = [];
    // Re-render empty
    const listEl = document.getElementById("admin-audit-list");
    const emptyEl = document.getElementById("admin-audit-empty");
    const ackBtn = document.getElementById("admin-audit-ack-btn");
    if (listEl) {
      Array.from(listEl.children).forEach(c => { if (c !== emptyEl) c.remove(); });
    }
    if (emptyEl) {
      emptyEl.textContent = i18n_t("app.admin.audit_acked") || "(全て削除しました)";
      emptyEl.classList.remove("hidden");
    }
    if (ackBtn) {
      ackBtn.disabled = true;
      ackBtn.textContent = i18n_t("app.admin.audit_ack_btn") || "✅ 全て確認済 (= server から削除)";
    }
  } catch (e) {
    if (errEl) {
      errEl.textContent = (i18n_t("app.admin.audit_ack_failed") || "削除失敗: ") + (e?.message || e);
      errEl.classList.remove("hidden");
    }
  }
});

// Phase 7.2-A: Admin: 現在の IP を確認 (= /api/whoami)
document.getElementById("admin-netpolicy-whoami-btn")?.addEventListener("click", async () => {
  const resultEl = document.getElementById("admin-netpolicy-whoami-result");
  if (resultEl) {
    resultEl.classList.remove("hidden");
    resultEl.textContent = i18n_t("app.admin.netpolicy_whoami_loading") || "取得中…";
  }
  try {
    const r = await fetch("/api/whoami", { method: "GET", headers: { "Cache-Control": "no-store" } });
    const j = await r.json();
    if (!j.ok || !j.ip) throw new Error("no IP returned");
    if (resultEl) {
      const cidrSuggestion = j.kind === "ipv6"
        ? `${j.ip}/128  # この端末 1 つだけ`
        : `${j.ip}/32  # この端末 1 つだけ`;
      resultEl.innerHTML =
        `🔍 <strong>${i18n_t("app.admin.netpolicy_whoami_label_yourip") || "あなたの現在の IP"}</strong> (${j.kind || "?"}):<br>` +
        `<code style="font-size: 14px;">${j.ip}</code><br>` +
        `<br>` +
        `<strong>${i18n_t("app.admin.netpolicy_whoami_label_suggest") || "allowlist に追加するなら"}:</strong><br>` +
        `<code>${cidrSuggestion}</code><br>` +
        `${j.cfIpCountry ? `<small>(${i18n_t("app.admin.netpolicy_whoami_label_country") || "country"}: ${j.cfIpCountry})</small><br>` : ""}` +
        `<br>` +
        `<small style="opacity: 0.7;">${i18n_t("app.admin.netpolicy_whoami_note") || "💡 社員も自分の IP を確認したい時は、 admin に伝えるか arpass.io/api/whoami を直接ブラウザで開いてください。"}</small>`;
    }
  } catch (e) {
    if (resultEl) {
      resultEl.textContent = (i18n_t("app.admin.netpolicy_whoami_failed") || "IP 取得失敗: ") + (e?.message || e);
    }
  }
});

// Phase 7.2-A: Admin: Network policy reset (= 制限なしに戻す)
document.getElementById("admin-netpolicy-reset-btn")?.addEventListener("click", async () => {
  const inputEl = document.getElementById("admin-ip-allowlist-input");
  const resultEl = document.getElementById("admin-netpolicy-result");
  const errEl = document.getElementById("admin-netpolicy-error");
  resultEl?.classList.add("hidden");
  errEl?.classList.add("hidden");

  if (!confirm(i18n_t("app.admin.netpolicy_reset_confirm") ||
    "IP allowlist を空にして 'ネットワーク制限なし' に戻します。 続行しますか?")) return;

  try {
    await corpAdminSetIpPolicyUI({ ipAllowlist: [], blockPersonalFromOurNetwork: false, restrictReadToAllowlist: false });
    if (inputEl) inputEl.value = "";
    const blockPersonalEl = document.getElementById("admin-netpolicy-block-personal");
    if (blockPersonalEl) blockPersonalEl.checked = false;
    const restrictReadEl = document.getElementById("admin-netpolicy-restrict-read");
    if (restrictReadEl) restrictReadEl.checked = false;
    if (resultEl) {
      resultEl.textContent = i18n_t("app.admin.netpolicy_reset_ok") || "✅ ネットワーク制限を解除しました";
      resultEl.classList.remove("hidden");
    }
  } catch (e) {
    if (errEl) {
      errEl.textContent = (i18n_t("app.admin.netpolicy_save_failed") || "保存失敗: ") + (e?.message || e);
      errEl.classList.remove("hidden");
    }
  }
});

// Phase 7.2-A: renderAdminConsole 時に現在の policy を input に反映
async function _renderAdminNetPolicy() {
  const inputEl = document.getElementById("admin-ip-allowlist-input");
  if (!inputEl) return;
  try {
    let info = state._corpInfo;
    // state._corpInfo が空なら直接 fetch (= 防御的に二重化、 renderAdminConsole で
    // 既に fetch + cache されているはずだが念のため)
    if (!info?.admin) {
      try {
        const { corpInfoUI } = await import("/lib/vault-client.js?v=51488219");
        info = await corpInfoUI();
        state._corpInfo = info;
      } catch (e) {
        console.warn("[netpolicy] corpInfoUI failed:", e?.message);
      }
    }
    if (info?.admin?.ipAllowlist && info.admin.ipAllowlist.length > 0) {
      inputEl.value = info.admin.ipAllowlist.join("\n");
    } else {
      inputEl.value = "";  // 制限なし状態を反映
    }
    const blockPersonalEl = document.getElementById("admin-netpolicy-block-personal");
    if (blockPersonalEl) {
      blockPersonalEl.checked = info?.admin?.blockPersonalFromOurNetwork === true;
    }
    // Phase 7.2-F: restrict-read toggle 復元
    const restrictReadEl = document.getElementById("admin-netpolicy-restrict-read");
    if (restrictReadEl) {
      restrictReadEl.checked = info?.admin?.restrictReadToAllowlist === true;
    }
  } catch (e) {
    console.warn("[netpolicy] render failed:", e?.message);
  }
}

// records タブからも lock 押せる
document.getElementById("records-lock-btn")?.addEventListener("click", () => {
  document.getElementById("lock-btn")?.click();
});

// ---- Records list rendering ------------------------------------------
function renderRecordsList() {
  const listEl = document.getElementById("records-list");
  const emptyEl = document.getElementById("records-list-empty");
  if (!listEl) return;
  // Phase 7.0g: corrections override + tombstones 除外 (audit-correct view)
  const allRecords = state.vault ? getCurrentRecords(state.vault) : [];

  if (allRecords.length === 0) {
    emptyEl?.classList.remove("hidden");
    emptyEl.querySelector("h2")?.setAttribute("data-i18n", "app.records.empty_heading");
    listEl.innerHTML = "";
    updateRecordsFilterCount(0, 0);
    return;
  }

  // Phase 7.0f: filter 適用 (quick search + 詳細 filter の組合わせ AND)
  const filtered = applyRecordsFilter(allRecords);

  if (filtered.length === 0) {
    emptyEl?.classList.remove("hidden");
    // フィルタ結果 0 件のメッセージに切替 (i18n key を一時 swap)
    const h2 = emptyEl.querySelector("h2");
    const p = emptyEl.querySelector("p:not([style])");
    if (h2) { h2.textContent = i18n_t("app.records.empty_filtered_heading"); }
    if (p)  { p.textContent  = i18n_t("app.records.empty_filtered_text"); }
    listEl.innerHTML = "";
    updateRecordsFilterCount(0, allRecords.length);
    return;
  }
  emptyEl?.classList.add("hidden");
  updateRecordsFilterCount(filtered.length, allRecords.length);

  // 新しい順 (createdAt desc)
  const sorted = [...filtered].sort((a, b) => (b.createdAt ?? "").localeCompare(a.createdAt ?? ""));
  listEl.innerHTML = "";
  for (const r of sorted) {
    const att = r.attachments?.[0] ?? {};
    // Phase 7.0e refine v5: card を <div role="button"> に。renderTxStatusHtml が
    // 内部に <button> を返すため nested button の HTML 不正回避。
    const card = document.createElement("div");
    card.setAttribute("role", "button");
    card.tabIndex = 0;
    card.dataset.recordId = r.id;
    card.dataset.txid = att.txId ?? "";
    card.style.cssText = `
      display: grid; grid-template-columns: auto 1fr auto; gap: 12px; align-items: center;
      padding: 12px 14px; background: var(--paper); border: 1px solid var(--line);
      border-radius: 10px; cursor: pointer; text-align: left; margin-bottom: 8px; width: 100%;
    `;
    const typeIcon = ({ receipt: "🧾", invoice: "📄", contract: "📜", medical: "🏥", custom: "📋" })[r.type] ?? "📋";
    const amountStr = (typeof r.amount === "number" && r.amount > 0)
      ? formatRecordAmount(r.amount, r.currency)
      : "—";

    const sizeStr = att.onChainBytes ? formatFileSize(att.onChainBytes) : (att.size ? formatFileSize(att.size) : "");
    const costStr = formatRecordConsumedCost(att.consumedUsdMicro);
    // Phase 7.0e refine v5: 既存 Vault 用 renderTxStatusHtml + txStatusCache を流用。
    // 確認前は「確認中」、bundling/pending/confirmed/received/error を正確表示。
    // クリックで window.openTxDetailModal (data-action delegation) → ViewBlock リンク + 再確認 button。
    const txStatusBadgeHtml = att.txId ? renderTxStatusHtml(att.txId) : "";

    card.innerHTML = `
      <div style="font-size:24px;">${typeIcon}</div>
      <div>
        <div style="font-weight:600; font-size:14px;">${escapeHtml(r.counterparty || r.title || i18n_t("app.records.no_counterparty"))}</div>
        <div style="font-size:12px; color:var(--muted); margin-top:2px;">
          ${escapeHtml(r.date)} · ${escapeHtml(r.type)}
          ${r.description ? " · " + escapeHtml(r.description.slice(0, 40)) : ""}
        </div>
        <div style="font-size:11px; color:var(--muted); margin-top:4px; display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
          ${sizeStr ? `<span>📎 ${escapeHtml(sizeStr)}</span>` : ""}
          ${costStr ? `<span style="color:var(--accent); font-weight:600;">💸 ${escapeHtml(costStr)}</span>` : ""}
          ${txStatusBadgeHtml}
        </div>
      </div>
      <div style="font-weight:700; color:var(--accent); font-size:14px;">${escapeHtml(amountStr)}</div>
    `;
    // card click → record detail modal、ただし内部 tx-detail button への click は除外
    card.addEventListener("click", (e) => {
      if (e.target.closest("[data-action='open-tx-detail']")) return;
      openRecordDetail(r.id);
    });
    card.addEventListener("keydown", (e) => {
      if (e.target.closest("[data-action='open-tx-detail']")) return;
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        openRecordDetail(r.id);
      }
    });
    listEl.appendChild(card);
  }

  // Phase 7.0e refine v5: 各 record の tx status を実確認 (既存 pollTxStatusOnce 流用)。
  // 共有の txStatusCache 経由で renderTxStatusHtml は cache 更新後に正しく表示される。
  // confirmed (≥2 confirmations) は cache hit で skip、再 fetch 不要。
  pollAllRecordTxStatuses().catch(e => console.warn("[records] tx status poll failed:", e?.message));
}

/** Phase 7.0e refine v5: 各 record の txid に対して pollTxStatusOnce を発火 + cache 更新後に
 *  list 内 badge HTML を最小再描画。並列 max 4 (gateway 過負荷防止)。
 *  既に confirmed (≥2 confirmations) は cache hit でスキップ → 冗長 fetch ゼロ。 */
let _lastRecordsPollAt = 0;
const RECORDS_POLL_COOLDOWN_MS = 15_000;  // 15 秒間は重複 poll を抑止 (429 防止)
async function pollAllRecordTxStatuses({ force = false } = {}) {
  // Phase 7.0p hotfix: filter 入力 / tab 切替で renderRecordsList が連続 trigger されると
  // 全 record txs を毎回 poll → /api/balance 経由で 429 になる。短期 cooldown で抑制。
  // force=true (visibility 変化など) の場合は即時 poll。
  const now = Date.now();
  if (!force && (now - _lastRecordsPollAt) < RECORDS_POLL_COOLDOWN_MS) {
    return;
  }
  _lastRecordsPollAt = now;

  const cards = document.querySelectorAll("#records-list [data-record-id]");
  const txids = Array.from(new Set(
    Array.from(cards).map(c => c.dataset.txid).filter(Boolean)
  ));
  const todo = txids.filter(txid => {
    const cached = txStatusCache.get(txid);
    return !(cached?.state === "confirmed" && (cached.confirmations ?? 0) >= 2);
  });
  if (todo.length === 0) return;

  const queue = todo.slice();
  const concurrency = 4;
  let anyUpdated = false;
  const workers = Array.from({ length: concurrency }, async () => {
    while (queue.length > 0) {
      const txid = queue.shift();
      try {
        await pollTxStatusOnce(txid);
        anyUpdated = true;
      } catch (e) { /* skip individual fail */ }
    }
  });
  await Promise.all(workers);

  if (anyUpdated) updateRecordTxBadges();

  // bundling/pending/received 状態が残っていれば 30s 後に再 poll
  const stillPending = todo.some(txid => {
    const c = txStatusCache.get(txid);
    return c?.state === "bundling" || c?.state === "pending" || c?.state === "received";
  });
  if (stillPending) {
    if (_recordsTxPollTimer) clearTimeout(_recordsTxPollTimer);
    _recordsTxPollTimer = setTimeout(() => {
      _recordsTxPollTimer = null;
      // Phase 7.0p: 自前 30s timer は cooldown を bypass (意図的な再 poll)
      pollAllRecordTxStatuses({ force: true }).catch(() => {});
    }, 30_000);
  }
}
let _recordsTxPollTimer = null;

/** record list 内の tx badge HTML だけ最小再描画 (DOM jitter 防止)。 */
function updateRecordTxBadges() {
  const cards = document.querySelectorAll("#records-list [data-record-id]");
  for (const card of cards) {
    const txid = card.dataset.txid;
    if (!txid) continue;
    const oldBadge = card.querySelector("[data-action='open-tx-detail']");
    if (!oldBadge || oldBadge.dataset.txid !== txid) continue;
    const newWrapper = document.createElement("div");
    newWrapper.innerHTML = renderTxStatusHtml(txid);
    const newBadge = newWrapper.firstElementChild;
    if (newBadge) oldBadge.replaceWith(newBadge);
  }
}

/** Phase 7.0e refine: 1 record の実消費額 (USD micro) を locale-aware で format。
 *  ja → ¥X.XX (USD_PER_USD で換算)、他言語 → $X.XXXX。
 *  null や 0 のときは空文字 (table cluttering 防止)。 */
function formatRecordConsumedCost(usdMicro) {
  // Phase 7.0t: 0 円も明示的に表示 (Turbo Free Tier で無料だったことを示す)。
  // null/undefined のときだけ '' を返して非表示。
  if (usdMicro == null) return "";
  const lang = i18n_getLang();
  if (usdMicro === 0) {
    return lang === "ja" ? "¥0 (無料)" : "$0 (free)";
  }
  if (usdMicro < 0) return "";  // ありえないがガード
  const usd = usdMicro / 1_000_000;
  if (lang === "ja") {
    const JPY_PER_USD = 154;
    const jpy = usd * JPY_PER_USD;
    if (jpy < 1) return `¥${jpy.toFixed(2)}`;
    if (jpy < 10) return `¥${jpy.toFixed(2)}`;
    return `¥${jpy.toFixed(1)}`;
  }
  if (usd < 0.001) return `$${usd.toFixed(5)}`;
  if (usd < 0.01)  return `$${usd.toFixed(4)}`;
  if (usd < 1)    return `$${usd.toFixed(3)}`;
  return `$${usd.toFixed(2)}`;
}

// Phase 7.0e refine v5: 独自 cache / poll は撤廃、上の pollAllRecordTxStatuses が
// 既存 txStatusCache + pollTxStatusOnce を流用して動作する。

function formatRecordAmount(amount, currency) {
  try {
    const symbol = ({ USD: "$", JPY: "¥", EUR: "€", GBP: "£", CNY: "¥", KRW: "₩" })[currency] ?? (currency + " ");
    if (currency === "JPY" || currency === "KRW") {
      return `${symbol}${Math.round(amount).toLocaleString()}`;
    }
    return `${symbol}${amount.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  } catch {
    return `${amount} ${currency}`;
  }
}

function escapeHtml(s) {
  if (s == null) return "";
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

// ---- Add Record modal -------------------------------------------------
let _recordsPickedFile = null;  // File object

document.getElementById("records-add-btn")?.addEventListener("click", () => {
  _recordsPickedFile = null;
  // form リセット
  const todayIso = new Date().toISOString().slice(0, 10);
  setVal("records-m-type", "receipt");
  setVal("records-m-date", todayIso);
  setVal("records-m-amount", "");
  setVal("records-m-counterparty", "");
  setVal("records-m-title", "");
  setVal("records-m-description", "");
  setVal("records-m-tags", "");
  document.getElementById("records-file-prompt")?.classList.remove("hidden");
  document.getElementById("records-file-info")?.classList.add("hidden");
  document.getElementById("records-modal-error")?.classList.add("hidden");
  document.getElementById("records-upload-progress")?.classList.add("hidden");
  // Phase 7.0r-4: ファイル preview reset (modal 開き直し時)
  _clearRecordsFilePreview();
  // Phase 7.0r: OCR row reset (file 未選択 + key 未設定なら隠す)
  document.getElementById("records-ocr-row")?.classList.add("hidden");
  document.getElementById("records-ocr-progress")?.classList.add("hidden");
  document.getElementById("records-ocr-result")?.classList.add("hidden");
  const ocrBtn = document.getElementById("records-ocr-btn");
  if (ocrBtn) ocrBtn.disabled = false;
  document.getElementById("records-modal-bg")?.classList.remove("hidden");
});

document.getElementById("records-modal-cancel")?.addEventListener("click", () => {
  document.getElementById("records-modal-bg")?.classList.add("hidden");
  _recordsPickedFile = null;
  _clearRecordsFilePreview();
});

// Phase 7.0v-3: 圧縮ボタン click handler (image only, user-driven)
document.getElementById("records-compress-btn")?.addEventListener("click", async (e) => {
  e.stopPropagation();  // Phase 7.0v-4: file-drop に bubble させない (picker 再起動防止)
  if (!_recordsPickedFile) return;
  const btn = document.getElementById("records-compress-btn");
  const oversizeWarn = document.getElementById("records-file-size-warn");
  if (btn) {
    btn.disabled = true;
    btn.textContent = i18n_t("app.records.compressing") || "🗜️ 圧縮中…";
  }
  try {
    const { compressImageIfNeeded } = await import("/lib/image-compress.js?v=2d299d83");
    // 1 MB 以下も圧縮可能にするため、現在 size より少し小さい maxBytes を target に
    const target = Math.min(800 * 1024, Math.max(150 * 1024, Math.floor(_recordsPickedFile.size * 0.5)));
    const result = await compressImageIfNeeded(_recordsPickedFile, { maxBytes: target });
    if (result.compressed) {
      _recordsPickedFile = result.file;
      const orig = formatFileSize(result.originalSize);
      const comp = formatFileSize(result.compressedSize);
      setText("records-file-name", result.file.name);
      setText("records-file-size", `${comp} ⬇️ ${orig}`);
      setText("records-file-type", result.file.type);
      _renderRecordsFilePreview(result.file);
      if (btn) {
        const tmpl = i18n_t("app.records.compress_btn_done") || "✅ 圧縮済 ({orig} → {comp}) — もう一度押して再圧縮可";
        btn.textContent = tmpl.replace("{orig}", orig).replace("{comp}", comp);
        btn.disabled = false;
      }
      // 1 MB 超警告を消す (圧縮で 1 MB 以下になっていれば)
      if (result.file.size <= 1024 * 1024) {
        oversizeWarn?.classList.add("hidden");
      }
      document.getElementById("records-modal-error")?.classList.add("hidden");
    } else {
      if (btn) {
        btn.textContent = i18n_t("app.records.compress_btn_failed") || "🗜️ 圧縮できませんでした (decode 不可な形式の可能性)";
        btn.disabled = false;
      }
      showRecordsModalError(
        i18n_t("app.records.compress_decode_fail") || "画像の decode に失敗しました (HEIC を対応外環境で開いた等)"
      );
    }
  } catch (e) {
    console.error("[records] compress click failed:", e);
    if (btn) {
      btn.textContent = i18n_t("app.records.compress_btn_error") || "🗜️ 圧縮失敗";
      btn.disabled = false;
    }
    showRecordsModalError(
      (i18n_t("app.records.compress_error") || "圧縮中エラー") + ": " + (e?.message ?? String(e))
    );
  }
});

// Phase 7.0v-4: 別のファイル選択 (明示切替) — 既存 preview を clear して picker を開く
document.getElementById("records-file-replace")?.addEventListener("click", (e) => {
  e.stopPropagation();
  // state reset
  _recordsPickedFile = null;
  _clearRecordsFilePreview();
  // UI reset
  document.getElementById("records-file-prompt")?.classList.remove("hidden");
  document.getElementById("records-file-info")?.classList.add("hidden");
  document.getElementById("records-modal-error")?.classList.add("hidden");
  document.getElementById("records-file-size-warn")?.classList.add("hidden");
  document.getElementById("records-file-actions")?.classList.add("hidden");
  document.getElementById("records-ocr-row")?.classList.add("hidden");
  // 直接 picker を開く (file-drop click handler は _recordsPickedFile が null なので OK)
  document.getElementById("records-file-input")?.click();
});

// File input handler
document.getElementById("records-file-drop")?.addEventListener("click", (e) => {
  // Phase 7.0v-4: ファイル選択済の場合は picker を開かない (圧縮ボタン等の click が
  // bubble up して再 picker が出る bug 防止)。'別のファイル' ボタンで明示的に切替。
  if (_recordsPickedFile) return;
  // 既存 preview 内の link/button click は stopPropagation 済 (preview-open 等)
  document.getElementById("records-file-input")?.click();
});

document.getElementById("records-file-input")?.addEventListener("change", (e) => {
  const f = e.target.files?.[0];
  if (f) handleRecordsFilePicked(f);
});

// Drag & drop
const dropZone = document.getElementById("records-file-drop");
if (dropZone) {
  ["dragenter", "dragover"].forEach(ev => dropZone.addEventListener(ev, (e) => {
    e.preventDefault(); e.stopPropagation();
    dropZone.style.borderColor = "var(--accent)";
  }));
  ["dragleave", "drop"].forEach(ev => dropZone.addEventListener(ev, (e) => {
    e.preventDefault(); e.stopPropagation();
    dropZone.style.borderColor = "var(--line)";
  }));
  dropZone.addEventListener("drop", (e) => {
    const f = e.dataTransfer?.files?.[0];
    if (f) handleRecordsFilePicked(f);
  });
}

function handleRecordsFilePicked(file) {
  // Phase 7.0v-3: 自動圧縮を撤廃、user-driven 圧縮へ。
  //   - 即 preview + サイズ表示 (圧縮しない)
  //   - 1 MB 超 → 警告表示 (image なら圧縮ボタン誘導、それ以外なら error)
  //   - 圧縮ボタン click で初めて圧縮を実行
  //   - 1 MB 以下 image でも圧縮可 (ユーザー選択)
  const MAX_BYTES = 1024 * 1024;            // 保存上限
  const MAX_RAW_BYTES = 30 * 1024 * 1024;   // 受付上限 30 MB (Live Photo / ProRAW 対策)

  if (file.size > MAX_RAW_BYTES) {
    showRecordsModalError(i18n_t("app.records.error_too_large", { max: "30 MB" }));
    return;
  }

  const imageExtRe = /\.(jpe?g|png|webp|gif|heic|heif|bmp|tiff?|avif)$/i;
  const isImage = file.type.startsWith("image/") || imageExtRe.test(file.name || "");

  // 即 preview + size 表示 (圧縮なし)
  _recordsPickedFile = file;
  document.getElementById("records-file-prompt")?.classList.add("hidden");
  document.getElementById("records-file-info")?.classList.remove("hidden");
  setText("records-file-name", file.name);
  setText("records-file-size", formatFileSize(file.size));
  setText("records-file-type", file.type || "(unknown)");
  document.getElementById("records-modal-error")?.classList.add("hidden");
  _renderRecordsFilePreview(file);

  // 圧縮アクションエリアの表示制御
  const actionsEl = document.getElementById("records-file-actions");
  const compressBtn = document.getElementById("records-compress-btn");
  const oversizeWarn = document.getElementById("records-file-size-warn");
  const oversize = file.size > MAX_BYTES;

  if (isImage) {
    actionsEl?.classList.remove("hidden");
    if (compressBtn) {
      compressBtn.classList.remove("hidden");
      const tmpl = i18n_t("app.records.compress_btn_label") || "🗜️ 圧縮する ({size} → 通常 200-500 KB)";
      compressBtn.textContent = tmpl.replace("{size}", formatFileSize(file.size));
      compressBtn.disabled = false;
    }
  } else {
    actionsEl?.classList.add("hidden");
    compressBtn?.classList.add("hidden");
  }

  // 1 MB 超の警告
  if (oversize) {
    oversizeWarn?.classList.remove("hidden");
    if (oversizeWarn) {
      oversizeWarn.textContent = isImage
        ? (i18n_t("app.records.oversize_image_hint") || "⚠️ 1 MB 超 — 圧縮ボタンで小さくしてください")
        : (i18n_t("app.records.oversize_other_hint") || "⚠️ 1 MB 超 — 保存できません (画像のみ圧縮可、その他は手動で縮小してください)");
    }
  } else {
    oversizeWarn?.classList.add("hidden");
  }

  // Phase 7.0v-4: ファイル名を Document title に自動 prefill (空欄時のみ、 user 入力を上書きしない)。
  //   OCR が動けば後で OCR 抽出結果に上書きされる (= 上位優先)。 これで「取引先 or タイトル必須」
  //   検証は実質常に通る → submit 時のエラーで mobile 下部スクロールが消える。
  try {
    const titleEl = document.getElementById("records-m-title");
    if (titleEl && !titleEl.value.trim() && file.name) {
      // 拡張子を 1 つだけ削る (例 "Invoice-2026-05.pdf" → "Invoice-2026-05")
      const baseName = file.name.replace(/\.[^.\/]+$/, "").trim();
      if (baseName) titleEl.value = baseName.slice(0, 256);
    }
  } catch (e) { /* prefill 失敗は致命的でない */ }

  // OCR ボタン表示 (圧縮するかしないかに関わらず image/PDF + key 設定済 で表示)
  const ocrRow = document.getElementById("records-ocr-row");
  if (ocrRow) {
    const isOcrCandidate = isImage || file.type === "application/pdf";
    if (isOcrCandidate && _getOpenaiApiKey()) {
      ocrRow.classList.remove("hidden");
      document.getElementById("records-ocr-progress")?.classList.add("hidden");
      document.getElementById("records-ocr-result")?.classList.add("hidden");
      const btn = document.getElementById("records-ocr-btn");
      if (btn) btn.disabled = false;
    } else {
      ocrRow.classList.add("hidden");
    }
  }
}

function formatFileSize(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / 1024 / 1024).toFixed(2) + " MB";
}

function showRecordsModalError(msg, focusFieldId = null) {
  const el = document.getElementById("records-modal-error");
  if (!el) return;
  el.textContent = msg;
  el.classList.remove("hidden");
  // Phase 7.0v-4: モバイルでもエラーが見えるよう該当フィールドへ scroll + focus、
  //   エラー要素自体も viewport 内へ。
  try {
    const target = focusFieldId ? document.getElementById(focusFieldId) : el;
    if (target) {
      target.scrollIntoView({ behavior: "smooth", block: "center" });
      if (focusFieldId) {
        // focus は scroll 完了後で十分。 即 focus すると iOS で virtual keyboard が
        // scroll を妨げることがある。
        setTimeout(() => { target.focus(); }, 350);
      }
    }
  } catch (e) { /* scroll/focus 失敗は致命的でない */ }
}

function setVal(id, v) { const el = document.getElementById(id); if (el) el.value = v; }
function setText(id, v) { const el = document.getElementById(id); if (el) el.textContent = v; }

// Save handler
document.getElementById("records-modal-save")?.addEventListener("click", async () => {
  const errEl = document.getElementById("records-modal-error");
  errEl?.classList.add("hidden");

  if (!_recordsPickedFile) {
    showRecordsModalError(i18n_t("app.records.error_no_file"));
    return;
  }
  // Phase 7.0v-3: 1 MB validate at save time (user-driven compression)
  const SAVE_MAX_BYTES = 1024 * 1024;
  if (_recordsPickedFile.size > SAVE_MAX_BYTES) {
    showRecordsModalError(
      i18n_t("app.records.error_save_too_large")
        || "ファイルが 1 MB を超えています。画像は 🗜️ 圧縮ボタンで縮小してから保存してください。"
    );
    return;
  }
  const type        = document.getElementById("records-m-type")?.value;
  const date        = document.getElementById("records-m-date")?.value;
  const currency    = document.getElementById("records-m-currency")?.value;
  const amountRaw   = document.getElementById("records-m-amount")?.value;
  const counterparty = document.getElementById("records-m-counterparty")?.value?.trim();
  const title       = document.getElementById("records-m-title")?.value?.trim();
  const description = document.getElementById("records-m-description")?.value?.trim();
  const tagsRaw     = document.getElementById("records-m-tags")?.value?.trim();

  if (!date) { showRecordsModalError(i18n_t("app.records.error_no_date"), "records-m-date"); return; }
  // Phase 7.0r-8: counterparty OR title のどちらか必須
  // Phase 7.0v-4: title はファイル名で auto-prefill されているのでほぼ常に通るはず。
  //   それでも空なら counterparty 側へ scroll/focus する (ファイルが name 無し等)。
  if (!counterparty && !title) {
    showRecordsModalError(
      i18n_t("app.records.error_no_cp_or_title") || "取引先または書類名のどちらかは必須です",
      "records-m-counterparty"
    );
    return;
  }

  const amount = amountRaw ? Number(amountRaw) : null;
  if (amountRaw && (!Number.isFinite(amount) || amount < 0)) {
    showRecordsModalError(i18n_t("app.records.error_bad_amount"));
    return;
  }
  const tags = tagsRaw ? tagsRaw.split(/[,、]/).map(s => s.trim()).filter(Boolean) : [];

  // Show progress indicator
  const saveBtn = document.getElementById("records-modal-save");
  if (saveBtn) saveBtn.disabled = true;
  document.getElementById("records-upload-progress")?.classList.remove("hidden");

  try {
    const buf = await _recordsPickedFile.arrayBuffer();
    const fileBytes = new Uint8Array(buf);
    await addRecordUI({
      fileBytes,
      mimeType: _recordsPickedFile.type,
      type,
      date,
      amount,
      currency,
      counterparty,
      title,
      description,
      tags,
      filename: _recordsPickedFile.name,
    });
    // 成功 → modal 閉じる + 一覧再描画
    document.getElementById("records-modal-bg")?.classList.add("hidden");
    _recordsPickedFile = null;
    // Phase 7.0e refine v12 (yamaki 指摘):
    //   header 上部の TX は **vault の TX** であるべき。file の txid は記録 card 側に
    //   表示されるが、上部 TX badge は「現在の vault が Arweave 上のどの版か」を表す。
    //   よって state.latestTxId は file write 後も触らず、vault save 完了後に
    //   updateSaveStatusBadge (save-debounce callback) が新 vault txid で update する。
    //
    //   _session.latestTxId は addRecordUI 内 hotfix で file txid に update されている
    //   (server 側 KV の latestTxId と同期、optimistic lock 用)。これは header 表示には使わない。
    //   header は state.latestTxId (= 直近 vault save の txid) を見る。

    // Phase 7.0e refine v11: vault save を debounce (passwords と同じ flow)。
    // 連続 record 追加で vault writes を 1 回に集約。
    // 離脱時の自動 flush は save-debounce が beforeunload/pagehide/visibilitychange/lock で対応。
    scheduleSave(state.vault);

    renderRecordsList();
    toast(i18n_t("app.records.toast_added"), "");
    // refreshHeader: server から最新 balance + estimated writes を取得して UI 同期。
    // state.latestTxId は変更しない (vault save 後に save-debounce callback が更新)
    // ので、header の TX badge は「以前の vault txid」のまま表示される (vault は未変更だから正しい)。
    refreshHeader().catch(() => {});
  } catch (e) {
    console.error("[records] addRecord failed:", e);
    // Phase 7.5ZE: insufficient_credits の場合は textContent ではなく innerHTML で
    //   購入 CTA リンクを表示 (= 旧版は <a href=...> が raw text で出ていた)
    if (e?.code === "insufficient_credits" || e?.status === 402) {
      const errEl2 = document.getElementById("records-modal-error");
      if (errEl2) {
        // server response の最新 balance を state に反映 (= showSaveError と同じ処理)
        const newCredits = e?.account?.estimatedWrites;
        if (typeof newCredits === "number") {
          state.credits = newCredits;
          if (typeof e.account.perWriteUsd === "number") state.perWriteUsd = e.account.perWriteUsd;
      if (typeof e.account.perWriteUsdBase === "number") state.perWriteUsdBase = e.account.perWriteUsdBase;
          refreshHeader().catch(() => {});
        }
        errEl2.innerHTML = i18n_t("app.error.insufficient_credits_cta", { cta: purchaseCtaHtml() });
        errEl2.classList.remove("hidden");
      }
    } else {
      showRecordsModalError(e?.message ?? "Upload failed");
    }
  } finally {
    if (saveBtn) saveBtn.disabled = false;
    document.getElementById("records-upload-progress")?.classList.add("hidden");
  }
});

// ---- Record detail modal ----------------------------------------------
async function openRecordDetail(recordId) {
  // Phase 7.0g: corrections 適用後の current view を表示。削除済 (tombstone) はそもそも一覧に出ない。
  const records = state.vault ? getCurrentRecords(state.vault) : [];
  const r = records.find(x => x.id === recordId);
  if (!r) return;
  _currentDetailRecordId = recordId;

  // メタ表示
  const titleEl = document.getElementById("records-detail-title");
  if (titleEl) titleEl.textContent = r.counterparty || r.title || i18n_t("app.records.no_counterparty");
  const meta = document.getElementById("records-detail-meta");
  if (meta) {
    const amountStr = (typeof r.amount === "number" && r.amount > 0) ? formatRecordAmount(r.amount, r.currency) : "—";
    meta.innerHTML = `
      <div><strong>${escapeHtml(i18n_t("app.records.field_type"))}:</strong> ${escapeHtml(r.type)}</div>
      <div><strong>${escapeHtml(i18n_t("app.records.field_date"))}:</strong> ${escapeHtml(r.date)}</div>
      <div><strong>${escapeHtml(i18n_t("app.records.field_amount"))}:</strong> ${escapeHtml(amountStr)}</div>
      ${r.counterparty ? `<div><strong>${escapeHtml(i18n_t("app.records.field_counterparty"))}:</strong> ${escapeHtml(r.counterparty)}</div>` : ""}
      ${r.title ? `<div><strong>${escapeHtml(i18n_t("app.records.field_title"))}:</strong> ${escapeHtml(r.title)}</div>` : ""}
      ${r.description ? `<div><strong>${escapeHtml(i18n_t("app.records.field_description"))}:</strong> ${escapeHtml(r.description)}</div>` : ""}
      ${(r.tags?.length) ? `<div><strong>${escapeHtml(i18n_t("app.records.field_tags"))}:</strong> ${r.tags.map(t => `<span style="display:inline-block; padding:2px 6px; background:var(--paper); border:1px solid var(--line); border-radius:6px; font-size:12px; margin-right:4px;">${escapeHtml(t)}</span>`).join("")}</div>` : ""}
      ${r.createdAt ? `<div><strong>${escapeHtml(i18n_t("app.records.field_created_at") || "Written at")}:</strong> ${escapeHtml(new Date(r.createdAt).toLocaleString())}</div>` : ""}
      <div style="margin-top:8px; padding:8px 10px; background:var(--paper); border-radius:6px; font-size:12px; color:var(--muted); border:1px solid var(--line);">
        <div style="display:flex; gap:14px; flex-wrap:wrap; align-items:center;">
          ${(r.attachments?.[0]?.consumedUsdMicro != null) ? `<span style="color:var(--accent); font-weight:600;">💸 ${escapeHtml(i18n_t("app.records.field_cost") || "Cost")}: ${escapeHtml(formatRecordConsumedCost(r.attachments[0].consumedUsdMicro))}</span>` : ""}
          ${r.attachments?.[0]?.onChainBytes ? `<span>📎 ${escapeHtml(i18n_t("app.records.field_onchain_size") || "On-chain")}: ${escapeHtml(formatFileSize(r.attachments[0].onChainBytes))}</span>` : (r.attachments?.[0]?.size ? `<span>📎 ${escapeHtml(formatFileSize(r.attachments[0].size))}</span>` : "")}
        </div>
        <div style="margin-top:6px;">
          Arweave tx: <code style="font-size:11px;">${escapeHtml(r.attachments?.[0]?.txId ?? "")}</code>
        </div>
        ${r.attachments?.[0]?.sha256 ? `<div style="margin-top:4px; font-size:11px; word-break:break-all;"><strong>SHA-256:</strong> <code style="font-size:10px;">${escapeHtml(r.attachments[0].sha256)}</code></div>` : ""}
      </div>
      ${(r.version ?? 1) > 1 ? `<div style="margin-top:6px;"><span style="display:inline-block; padding:2px 8px; background:#fef3c7; color:#92400e; border-radius:6px; font-size:11px; font-weight:600;">${escapeHtml(i18n_t("app.records.corrected_badge") || "訂正済")} v${r.version}</span></div>` : ""}
    `;
  }

  // ファイル preview (lazy load) + Tx status (one-shot)
  const previewEl = document.getElementById("records-detail-preview");
  if (previewEl) {
    previewEl.innerHTML = `<div style="text-align:center; padding:30px; color:var(--muted);">${escapeHtml(i18n_t("app.records.loading_file"))}</div>`;
  }

  document.getElementById("records-detail-bg")?.classList.remove("hidden");

  // ファイル名 (download attribute と表示用)
  const att = r.attachments?.[0] ?? {};
  const safeFilename = (att.filename || `record-${r.id.slice(0, 8)}.${(att.mimeType ?? "").split("/")[1] ?? "bin"}`)
    .replace(/[\\/:*?"<>|]/g, "_");

  // 旧 blob URL があれば revoke (重複生成防止)
  if (_currentDetailBlobUrl) {
    try { URL.revokeObjectURL(_currentDetailBlobUrl); } catch {}
    _currentDetailBlobUrl = null;
  }

  try {
    const { bytes, mimeType } = await fetchRecordFileUI(recordId);
    const blob = new Blob([bytes], { type: mimeType });
    const url = URL.createObjectURL(blob);
    _currentDetailBlobUrl = url;

    if (previewEl) {
      // Download ボタンは常に表示
      const downloadBtnHtml = `
        <div style="display:flex; gap:8px; margin-bottom:12px; flex-wrap:wrap;">
          <a href="${url}" download="${escapeHtml(safeFilename)}" class="btn-outline"
             style="text-decoration:none; padding:8px 14px; display:inline-flex; align-items:center; gap:6px;">
            ⬇️ <span data-i18n="app.records.btn_download">Download</span> (${escapeHtml(safeFilename)})
          </a>
          <a href="${url}" target="_blank" rel="noopener" class="btn-outline"
             style="text-decoration:none; padding:8px 14px;">
            🔗 <span data-i18n="app.records.btn_open_new_tab">Open in new tab</span>
          </a>
        </div>
      `;

      // 形式別プレビュー
      let previewBlock = "";
      if (mimeType === "application/pdf") {
        // <embed> は CSP object-src \'none\' で block。<iframe> + frame-src blob: で OK
        previewBlock = `<iframe src="${url}#toolbar=1" type="application/pdf"
                              style="width:100%; height:520px; border:1px solid var(--line); border-radius:8px;"
                              title="PDF preview"></iframe>`;
      } else if (mimeType.startsWith("image/")) {
        previewBlock = `<img src="${url}" alt="receipt"
                             style="max-width:100%; max-height:520px; border:1px solid var(--line); border-radius:8px; display:block;" />`;
      } else {
        previewBlock = `<div style="padding:20px; background:var(--paper); border-radius:8px; color:var(--muted);">
          ${escapeHtml(i18n_t("app.records.no_inline_preview"))}
        </div>`;
      }
      previewEl.innerHTML = downloadBtnHtml + previewBlock;
    }
  } catch (e) {
    console.error("[records] fetchRecordFile failed:", e);
    if (previewEl) {
      previewEl.innerHTML = `<div style="color:var(--red); padding:20px;">${escapeHtml(i18n_t("app.records.error_load_failed"))}: ${escapeHtml(e?.message ?? "")}</div>`;
    }
  }

  // Phase 7.0e refine v3 fix: vault.records.active は書込み成功後にのみ追加される。
  // Arweave 確定状態の再チェックは冗長 (Turbo 経由で書いた以上 L1 到達は決定論的)。
  // → 詳細 modal でも tx status check を撤廃、Arweave gateway への呼出ゼロ。
}

// Detail modal の blob URL を保持 (close 時に revoke)
let _currentDetailBlobUrl = null;
// Phase 7.0g: 詳細 modal で開いている record の id (edit/delete handler から参照)
let _currentDetailRecordId = null;

document.getElementById("records-detail-close")?.addEventListener("click", () => {
  document.getElementById("records-detail-bg")?.classList.add("hidden");
  _currentDetailRecordId = null;
  // Phase 7.0e fix: blob URL を確実に GC するため revoke
  if (_currentDetailBlobUrl) {
    try { URL.revokeObjectURL(_currentDetailBlobUrl); } catch {}
    _currentDetailBlobUrl = null;
  }
});

// ---- 既存 lock handler から records-modal も clear するように補強 -----
// Phase 6.8.34 の lock handler を後追いで拡張するのは難しいので、
// initial show 時に records-modal も hidden 化する保証だけ追加。
// (既に showView で他 view 表示時は state クリアされているので追加処理は不要)



// =====================================================================
// Phase 7.0f: Records 検索/フィルタ (Option C: simple + detailed)
// =====================================================================
//
// 法律要件 (電子帳簿保存法) を満たす検索:
//   - 取引年月日 (date)、取引金額 (amount)、取引先 (counterparty) で検索
//   - 範囲指定 (日付 / 金額)
//   - 複合検索 (2 項目以上の組合わせ AND)
//
// UI:
//   - quick search 1 行 (counterparty / description / type / date / amount に
//     fuzzy match) — 普段使い
//   - 折りたたみ「詳細フィルタ」(🎛️ ボタン) — 税務調査時の証跡
//   - 両方 AND 適用

const _recordsFilter = {
  quick: "",          // quick search (1 行)
  dateFrom: "",       // YYYY-MM-DD
  dateTo: "",
  amountMin: null,
  amountMax: null,
  counterparty: "",
  type: "",           // "" = all
  tags: "",           // comma-separated, "tag1,tag2" → 各 tag が含まれるかチェック
};

/** 全 records から filter 適用後の subset を返す (renderRecordsList から呼ばれる)。 */
function applyRecordsFilter(records) {
  const f = _recordsFilter;
  const quick = f.quick.trim();
  const quickN = quick ? normalizeCounterparty(quick) : "";  // 日本語正規化

  return records.filter(r => {
    // 詳細 filter (date 範囲)
    if (f.dateFrom && (r.date ?? "") < f.dateFrom) return false;
    if (f.dateTo   && (r.date ?? "") > f.dateTo)   return false;

    // 詳細 filter (amount 範囲)
    if (Number.isFinite(f.amountMin) && (typeof r.amount !== "number" || r.amount < f.amountMin)) return false;
    if (Number.isFinite(f.amountMax) && (typeof r.amount !== "number" || r.amount > f.amountMax)) return false;

    // 詳細 filter (counterparty / title 部分一致 OR 検索、日本語正規化)
    if (f.counterparty.trim()) {
      const cN = normalizeCounterparty(f.counterparty);
      const rN = normalizeCounterparty(r.counterparty ?? "") + " " + normalizeCounterparty(r.counterpartyAlias ?? "")
                + " " + normalizeCounterparty(r.title ?? "") + " " + normalizeCounterparty(r.titleAlias ?? "");
      if (!rN.includes(cN)) return false;
    }

    // 詳細 filter (type)
    if (f.type && r.type !== f.type) return false;

    // 詳細 filter (tags) — 入力された全 tag が含まれる AND
    if (f.tags.trim()) {
      const wantTags = f.tags.split(/[,、]/).map(s => s.trim().toLowerCase()).filter(Boolean);
      const recTags = (r.tags ?? []).map(t => String(t).toLowerCase());
      if (!wantTags.every(want => recTags.some(rt => rt.includes(want)))) return false;
    }

    // quick search (counterparty / description / type / date / amount にまたがる fuzzy)
    if (quick) {
      const haystack = [
        normalizeCounterparty(r.counterparty ?? ""),
        normalizeCounterparty(r.counterpartyAlias ?? ""),
        normalizeCounterparty(r.title ?? ""),
        normalizeCounterparty(r.titleAlias ?? ""),
        normalizeCounterparty(r.description ?? ""),
        r.type ?? "",
        r.date ?? "",
        typeof r.amount === "number" ? String(r.amount) : "",
        (r.tags ?? []).join(" ").toLowerCase(),
      ].join(" ");
      if (!haystack.includes(quickN)) return false;
    }

    return true;
  });
}

/** Filter UI の入力値を _recordsFilter に sync して renderRecordsList を呼ぶ。 */
function _readFilterInputsAndRender() {
  _recordsFilter.quick        = document.getElementById("records-search")?.value ?? "";
  _recordsFilter.dateFrom     = document.getElementById("records-filter-date-from")?.value ?? "";
  _recordsFilter.dateTo       = document.getElementById("records-filter-date-to")?.value ?? "";
  const minRaw = document.getElementById("records-filter-amount-min")?.value;
  const maxRaw = document.getElementById("records-filter-amount-max")?.value;
  _recordsFilter.amountMin    = (minRaw === "" || minRaw == null) ? null : Number(minRaw);
  _recordsFilter.amountMax    = (maxRaw === "" || maxRaw == null) ? null : Number(maxRaw);
  _recordsFilter.counterparty = document.getElementById("records-filter-counterparty")?.value ?? "";
  _recordsFilter.type         = document.getElementById("records-filter-type")?.value ?? "";
  _recordsFilter.tags         = document.getElementById("records-filter-tags")?.value ?? "";
  renderRecordsList();
}

function _clearRecordsFilter() {
  for (const id of [
    "records-search",
    "records-filter-date-from", "records-filter-date-to",
    "records-filter-amount-min", "records-filter-amount-max",
    "records-filter-counterparty",
    "records-filter-tags",
  ]) {
    const el = document.getElementById(id);
    if (el) el.value = "";
  }
  const typeEl = document.getElementById("records-filter-type");
  if (typeEl) typeEl.value = "";
  _readFilterInputsAndRender();
}

/** "N / M 件" 表示。フィルタ適用時のみ詳細 panel に出す。 */
function updateRecordsFilterCount(shown, total) {
  const el = document.getElementById("records-filter-count");
  if (!el) return;
  if (shown === total) {
    el.textContent = i18n_t("app.records.filter_count_all", { n: total });
  } else {
    el.textContent = i18n_t("app.records.filter_count_filtered", { n: shown, total });
  }
}

// ---- Event wiring ----
// quick search input (debounce 200ms)
let _recordsSearchDebounce = null;
document.getElementById("records-search")?.addEventListener("input", () => {
  if (_recordsSearchDebounce) clearTimeout(_recordsSearchDebounce);
  _recordsSearchDebounce = setTimeout(() => {
    _recordsSearchDebounce = null;
    _readFilterInputsAndRender();
  }, 200);
});

// 詳細フィルタトグル
document.getElementById("records-filter-toggle")?.addEventListener("click", () => {
  const panel = document.getElementById("records-filter-panel");
  if (!panel) return;
  panel.classList.toggle("hidden");
});

// 各詳細フィルタ入力 (input / change で即適用)
for (const id of [
  "records-filter-date-from", "records-filter-date-to",
  "records-filter-amount-min", "records-filter-amount-max",
  "records-filter-counterparty",
  "records-filter-type",
  "records-filter-tags",
]) {
  const el = document.getElementById(id);
  if (!el) continue;
  el.addEventListener("input",  () => _readFilterInputsAndRender());
  el.addEventListener("change", () => _readFilterInputsAndRender());
}

// Clear ボタン
document.getElementById("records-filter-clear")?.addEventListener("click", () => _clearRecordsFilter());


// =====================================================================
// Phase 7.0g: 訂正 / 削除 / 履歴 (electronic bookkeeping law audit trail)
// =====================================================================
//
// 詳細 modal の「✏️ Edit」「🗑️ Delete」「📜 History」ボタンの handler。
// すべて _currentDetailRecordId を起点に動作する。

// ---- Edit (訂正) modal ----------------------------------------------
function _openEditModal() {
  if (!_currentDetailRecordId) return;
  const r = (state.vault ? getCurrentRecords(state.vault) : []).find(x => x.id === _currentDetailRecordId);
  if (!r) return;
  // 現行値で pre-fill
  setVal("records-e-type",        r.type ?? "receipt");
  setVal("records-e-date",        r.date ?? "");
  setVal("records-e-currency",    r.currency ?? "USD");
  setVal("records-e-amount",      typeof r.amount === "number" ? String(r.amount) : "");
  setVal("records-e-counterparty", r.counterparty ?? "");
  setVal("records-e-title",        r.title ?? "");
  setVal("records-e-description", r.description ?? "");
  setVal("records-e-tags",        Array.isArray(r.tags) ? r.tags.join(", ") : "");
  setVal("records-e-reason",      "");
  document.getElementById("records-edit-error")?.classList.add("hidden");
  document.getElementById("records-edit-bg")?.classList.remove("hidden");
}

function _showEditError(msg) {
  const el = document.getElementById("records-edit-error");
  if (!el) return;
  el.textContent = msg;
  el.classList.remove("hidden");
}

document.getElementById("records-detail-edit")?.addEventListener("click", () => {
  _openEditModal();
});

document.getElementById("records-edit-cancel")?.addEventListener("click", () => {
  document.getElementById("records-edit-bg")?.classList.add("hidden");
});

document.getElementById("records-edit-save")?.addEventListener("click", async () => {
  if (!_currentDetailRecordId) return;
  const reason = (document.getElementById("records-e-reason")?.value ?? "").trim();
  if (!reason) {
    _showEditError(i18n_t("app.records.edit_reason_required") || "訂正理由は必須です (法律要件)");
    return;
  }
  // 現行値と比較して、変更された field のみ送信
  const r = (state.vault ? getCurrentRecords(state.vault) : []).find(x => x.id === _currentDetailRecordId);
  if (!r) return;

  const newType        = document.getElementById("records-e-type")?.value ?? "";
  const newDate        = document.getElementById("records-e-date")?.value ?? "";
  const newCurrency    = document.getElementById("records-e-currency")?.value ?? "";
  const newAmountRaw   = document.getElementById("records-e-amount")?.value ?? "";
  const newAmount      = newAmountRaw === "" ? null : Number(newAmountRaw);
  const newCounterparty = (document.getElementById("records-e-counterparty")?.value ?? "").trim();
  const newTitle        = (document.getElementById("records-e-title")?.value ?? "").trim();
  const newDescription = (document.getElementById("records-e-description")?.value ?? "").trim();
  const newTagsRaw     = (document.getElementById("records-e-tags")?.value ?? "").trim();
  const newTags        = newTagsRaw ? newTagsRaw.split(/[,、]/).map(s => s.trim()).filter(Boolean) : [];

  const updates = {};
  if (newType        !== r.type)         updates.type = newType;
  if (newDate        !== (r.date ?? "")) updates.date = newDate;
  if (newCurrency    !== (r.currency ?? ""))         updates.currency = newCurrency;
  if ((newAmount ?? null) !== (r.amount ?? null))    updates.amount = newAmount;
  if (newCounterparty !== (r.counterparty ?? ""))    updates.counterparty = newCounterparty;
  if (newTitle        !== (r.title ?? ""))           updates.title = newTitle;
  if (newDescription !== (r.description ?? ""))      updates.description = newDescription;
  if (JSON.stringify(newTags) !== JSON.stringify(r.tags ?? [])) updates.tags = newTags;

  if (Object.keys(updates).length === 0) {
    _showEditError(i18n_t("app.records.edit_no_changes") || "変更がありません");
    return;
  }

  const saveBtn = document.getElementById("records-edit-save");
  if (saveBtn) saveBtn.disabled = true;
  try {
    await correctRecordUI(_currentDetailRecordId, updates, reason);
    // vault は memory のみ更新 → debounce save
    scheduleSave(state.vault);
    document.getElementById("records-edit-bg")?.classList.add("hidden");
    document.getElementById("records-detail-bg")?.classList.add("hidden");
    if (_currentDetailBlobUrl) {
      try { URL.revokeObjectURL(_currentDetailBlobUrl); } catch {}
      _currentDetailBlobUrl = null;
    }
    _currentDetailRecordId = null;
    renderRecordsList();
  } catch (e) {
    // Phase 7.5ZE: insufficient_credits 専用ハンドリング — HTML CTA を innerHTML で表示
    if (e?.code === "insufficient_credits" || e?.status === 402) {
      const editErr = document.getElementById("records-edit-error");
      if (editErr) {
        const newCredits = e?.account?.estimatedWrites;
        if (typeof newCredits === "number") {
          state.credits = newCredits;
          if (typeof e.account.perWriteUsd === "number") state.perWriteUsd = e.account.perWriteUsd;
      if (typeof e.account.perWriteUsdBase === "number") state.perWriteUsdBase = e.account.perWriteUsdBase;
          refreshHeader().catch(() => {});
        }
        editErr.innerHTML = i18n_t("app.error.insufficient_credits_cta", { cta: purchaseCtaHtml() });
        editErr.classList.remove("hidden");
      }
    } else {
      _showEditError(e?.message ?? String(e));
    }
  } finally {
    if (saveBtn) saveBtn.disabled = false;
  }
});

// ---- Delete (論理削除) modal ----------------------------------------
function _openDeleteModal() {
  if (!_currentDetailRecordId) return;
  setVal("records-d-reason", "");
  document.getElementById("records-delete-error")?.classList.add("hidden");
  document.getElementById("records-delete-bg")?.classList.remove("hidden");
}

function _showDeleteError(msg) {
  const el = document.getElementById("records-delete-error");
  if (!el) return;
  el.textContent = msg;
  el.classList.remove("hidden");
}

document.getElementById("records-detail-delete")?.addEventListener("click", () => {
  _openDeleteModal();
});

document.getElementById("records-delete-cancel")?.addEventListener("click", () => {
  document.getElementById("records-delete-bg")?.classList.add("hidden");
});

document.getElementById("records-delete-confirm")?.addEventListener("click", async () => {
  if (!_currentDetailRecordId) return;
  const reason = (document.getElementById("records-d-reason")?.value ?? "").trim();
  if (!reason) {
    _showDeleteError(i18n_t("app.records.delete_reason_required") || "削除理由は必須です (法律要件)");
    return;
  }
  const btn = document.getElementById("records-delete-confirm");
  if (btn) btn.disabled = true;
  try {
    await deleteRecordUI(_currentDetailRecordId, reason);
    scheduleSave(state.vault);
    document.getElementById("records-delete-bg")?.classList.add("hidden");
    document.getElementById("records-detail-bg")?.classList.add("hidden");
    if (_currentDetailBlobUrl) {
      try { URL.revokeObjectURL(_currentDetailBlobUrl); } catch {}
      _currentDetailBlobUrl = null;
    }
    _currentDetailRecordId = null;
    renderRecordsList();
  } catch (e) {
    _showDeleteError(e?.message ?? String(e));
  } finally {
    if (btn) btn.disabled = false;
  }
});

// ---- History (audit log) modal --------------------------------------
function _openHistoryModal() {
  if (!_currentDetailRecordId) return;
  const entries = getRecordHistory(_currentDetailRecordId);
  const listEl = document.getElementById("records-history-list");
  if (!listEl) return;

  if (entries.length === 0) {
    listEl.innerHTML = `<div style="padding:20px; color:var(--muted); text-align:center;">${escapeHtml(i18n_t("app.records.history_empty") || "履歴なし")}</div>`;
  } else {
    const actionLabel = (a) => ({
      create:  i18n_t("app.records.history_action_create")  || "作成",
      correct: i18n_t("app.records.history_action_correct") || "訂正",
      delete:  i18n_t("app.records.history_action_delete")  || "削除",
    })[a] || a;

    const actionColor = (a) => ({
      create:  { bg: "#dcfce7", fg: "#166534" },
      correct: { bg: "#fef3c7", fg: "#92400e" },
      delete:  { bg: "#fee2e2", fg: "#991b1b" },
    })[a] || { bg: "var(--paper)", fg: "var(--ink)" };

    // create entry のコストを attachment から取得 (record-specific)
    const r = (state.vault ? getCurrentRecords(state.vault) : []).find(x => x.id === _currentDetailRecordId);
    const createdCost = r?.attachments?.[0]?.consumedUsdMicro ?? 0;
    const createdSize = r?.attachments?.[0]?.onChainBytes ?? r?.attachments?.[0]?.size ?? 0;

    listEl.innerHTML = entries.map(e => {
      const c = actionColor(e.action);
      const at = e.at ? new Date(e.at).toLocaleString() : "";
      const fields = Array.isArray(e.fields) && e.fields.length > 0
        ? `<div style="margin-top:4px; font-size:11px; color:var(--muted);">${escapeHtml(i18n_t("app.records.history_fields") || "変更 fields")}: ${e.fields.map(f => escapeHtml(f)).join(", ")}</div>`
        : "";
      const reason = e.reason
        ? `<div style="margin-top:4px;"><strong style="font-size:11px; color:var(--muted);">${escapeHtml(i18n_t("app.records.history_reason") || "理由")}:</strong> ${escapeHtml(e.reason)}</div>`
        : "";
      // Phase 7.0p: create entry に書込み時コスト + on-chain size を表示 (audit 用途)
      // correct/delete は vault 更新のみで個別の Arweave write を伴わない (debounce 共有)。
      const cost = (e.action === "create" && createdCost != null)
        ? `<div style="margin-top:4px; font-size:11px;"><span style="color:var(--accent); font-weight:600;">💸 ${escapeHtml(i18n_t("app.records.field_cost") || "Cost")}: ${escapeHtml(formatRecordConsumedCost(createdCost))}</span>${createdSize ? ` <span style="color:var(--muted);"> · 📎 ${escapeHtml(formatFileSize(createdSize))}</span>` : ""}</div>`
        : "";
      return `<div style="border:1px solid var(--line); border-radius:8px; padding:10px; margin-bottom:8px; background:var(--paper);">
        <div style="display:flex; gap:8px; align-items:center;">
          <span style="display:inline-block; padding:2px 10px; background:${c.bg}; color:${c.fg}; border-radius:6px; font-size:11px; font-weight:600;">
            ${escapeHtml(actionLabel(e.action))}${e.version ? ` v${e.version}` : ""}
          </span>
          <span style="font-size:12px; color:var(--muted);">${escapeHtml(at)}</span>
        </div>
        ${cost}
        ${fields}
        ${reason}
      </div>`;
    }).join("");
  }

  document.getElementById("records-history-bg")?.classList.remove("hidden");
}

document.getElementById("records-detail-history")?.addEventListener("click", () => {
  _openHistoryModal();
});

document.getElementById("records-history-close")?.addEventListener("click", () => {
  document.getElementById("records-history-bg")?.classList.add("hidden");
});


// =====================================================================
// Phase 7.0i: chunks overflow + lazy load (LSM-style archival)
// =====================================================================
//
// active[] が大きくなった時、UI から手動 sealing できる「🗄️ Archive」ボタン。
// 自動 sealing は今のところ off (誤操作防止) — user が threshold 超え警告を
// 確認してから明示的に archive する流れ。

const ARCHIVE_RECOMMEND_THRESHOLD = 500;
const ARCHIVE_KEEP_RECENT = 100;

// archive ボタンの表示制御 (renderRecordsList の最後に呼ぶ)
function _maybeShowArchiveButton() {
  const btn = document.getElementById("records-archive-btn");
  if (!btn) return;
  const activeCount = state.vault?.records?.active?.length ?? 0;
  if (activeCount >= ARCHIVE_RECOMMEND_THRESHOLD) {
    btn.classList.remove("hidden");
    btn.title = i18n_t("app.records.archive_btn_title", { count: activeCount, keep: ARCHIVE_KEEP_RECENT })
      || `${activeCount} records — archive older entries (keep ${ARCHIVE_KEEP_RECENT} recent)`;
  } else {
    btn.classList.add("hidden");
  }
}

// renderRecordsList の最後で _maybeShowArchiveButton を呼ぶよう、wrapping 関数で hook
const _origRenderRecordsList = renderRecordsList;
// renderRecordsList 自体は後付け wrap が困難 (function declaration)。代わりに
// renderRecordsList の呼び出し箇所すべてで明示的に _maybeShowArchiveButton を呼ぶ
// のは保守困難なので、archive button toggle を tab 切替時 + scheduleSave 後の
// re-render 等で都度評価する。MVP としては tab 切替時に評価。

// Records タブを開いた時に archive button 状態を更新
document.querySelectorAll('[data-tab="records"]').forEach(el => {
  el.addEventListener("click", () => {
    setTimeout(_maybeShowArchiveButton, 50);
  });
});

document.getElementById("records-archive-btn")?.addEventListener("click", async () => {
  if (!state.vault) return;
  const activeCount = state.vault.records?.active?.length ?? 0;
  const sealCount = activeCount - ARCHIVE_KEEP_RECENT;
  if (sealCount <= 0) {
    return;
  }
  const confirmMsg = i18n_t("app.records.archive_confirm", { sealCount, keep: ARCHIVE_KEEP_RECENT })
    || `${sealCount} 件の古い records を 1 つの暗号化 chunk として Arweave にアーカイブし、active には直近 ${ARCHIVE_KEEP_RECENT} 件のみ残します。\n\n料金: chunk size に応じて 1 回分の Arweave 書込み費用がかかります。\n\n続行しますか？`;
  if (!confirm(confirmMsg)) return;

  const btn = document.getElementById("records-archive-btn");
  if (btn) btn.disabled = true;
  try {
    const { chunkRef, sealed } = await sealOldestChunkUI({
      threshold: ARCHIVE_RECOMMEND_THRESHOLD,
      keepRecent: ARCHIVE_KEEP_RECENT,
    });
    if (chunkRef) {
      // chunk write は server-side latestTxId KV を bump 済 → vault save も必要
      scheduleSave(state.vault);
      alert(i18n_t("app.records.archive_done", { sealed, range: `${chunkRef.range.dateFrom} ~ ${chunkRef.range.dateTo}` })
        || `${sealed} 件をアーカイブしました (${chunkRef.range.dateFrom} ~ ${chunkRef.range.dateTo})`);
      renderRecordsList();
      _maybeShowArchiveButton();
    }
  } catch (e) {
    console.error("[archive] failed:", e);
    alert((i18n_t("app.records.archive_error") || "アーカイブ失敗") + ": " + (e?.message ?? String(e)));
  } finally {
    if (btn) btn.disabled = false;
  }
});

// 起動時にも archive button を評価 (unlock 後 records タブ表示済の場合)
window.addEventListener("load", () => setTimeout(_maybeShowArchiveButton, 500));


// =====================================================================
// Phase 7.0r-4: Records modal ファイル preview (image / PDF サムネイル)
// =====================================================================

let _recordsFilePreviewBlobUrl = null;

function _renderRecordsFilePreview(file) {
  const previewEl = document.getElementById("records-file-preview");
  if (!previewEl) return;
  // 旧 blob URL を revoke (memory leak 防止)
  if (_recordsFilePreviewBlobUrl) {
    try { URL.revokeObjectURL(_recordsFilePreviewBlobUrl); } catch {}
    _recordsFilePreviewBlobUrl = null;
  }
  const url = URL.createObjectURL(file);
  _recordsFilePreviewBlobUrl = url;

  // Phase 7.0r-5: クリックすると新タブでフルサイズ表示。
  //   parent (#records-file-drop) は click でファイルピッカーを開く handler が
  //   付いているので、preview からの click event を stopPropagation して
  //   ピッカーの誤起動を防ぐ。
  const openLinkLabel = i18n_t("app.records.preview_open_in_tab") || "🔗 新しいタブで開く";

  if (file.type.startsWith("image/")) {
    previewEl.innerHTML = `
      <a href="${url}" target="_blank" rel="noopener"
         data-action="preview-open"
         style="display:inline-block; margin-top:8px; cursor:zoom-in;"
         title="${escape(openLinkLabel)}">
        <img src="${url}" alt="preview"
             style="max-width:100%; max-height:140px; border:1px solid var(--line); border-radius:6px; display:block;" />
      </a>
      <a href="${url}" target="_blank" rel="noopener"
         data-action="preview-open"
         style="display:inline-block; margin-top:6px; font-size:12px; color:var(--accent); text-decoration:none;">
        ${escape(openLinkLabel)}
      </a>
    `;
  } else if (file.type === "application/pdf") {
    previewEl.innerHTML = `
      <div data-action="preview-open" style="margin-top:8px;">
        <iframe src="${url}#toolbar=0&navpanes=0&view=FitH"
                style="width:100%; height:160px; border:1px solid var(--line); border-radius:6px; display:block;"
                title="PDF preview"></iframe>
        <a href="${url}" target="_blank" rel="noopener"
           data-action="preview-open"
           style="display:inline-block; margin-top:6px; font-size:12px; color:var(--accent); text-decoration:none;">
          ${escape(openLinkLabel)}
        </a>
      </div>
    `;
  } else if (
    file.type.startsWith("text/") ||
    file.type === "application/json" ||
    file.type === "application/xml" ||
    /\.(txt|md|csv|tsv|json|xml|log|js|ts|py|sh|yaml|yml)$/i.test(file.name || "")
  ) {
    // Phase 7.0t: テキスト系は先頭 4KB を <pre> でプレビュー。
    file.slice(0, 4096).text().then(snippet => {
      const trimmed = snippet.length === 4096 ? snippet + "\n…" : snippet;
      const safeSnippet = escape(trimmed);
      previewEl.innerHTML = `
        <pre data-action="preview-open"
             style="margin-top:8px; max-height:160px; overflow:auto; padding:8px 10px; background:var(--paper); border:1px solid var(--line); border-radius:6px; font-size:11px; line-height:1.5; white-space:pre-wrap; word-break:break-all; font-family:'SF Mono',Menlo,Consolas,monospace; color:var(--ink);">${safeSnippet}</pre>
        <a href="${url}" target="_blank" rel="noopener"
           data-action="preview-open"
           style="display:inline-block; margin-top:6px; font-size:12px; color:var(--accent); text-decoration:none;">
          ${escape(openLinkLabel)}
        </a>
      `;
      previewEl.querySelectorAll('[data-action="preview-open"]').forEach(el => {
        el.addEventListener("click", (e) => e.stopPropagation());
      });
    }).catch(() => {
      previewEl.innerHTML = "";
    });
  } else {
    // Phase 7.0t: その他 (Word/Excel/binary 等) は file icon + ダウンロードリンク
    const iconForType = (t, name) => {
      const n = (name || "").toLowerCase();
      if (n.endsWith(".docx") || n.endsWith(".doc")) return "📝";
      if (n.endsWith(".xlsx") || n.endsWith(".xls")) return "📊";
      if (n.endsWith(".pptx") || n.endsWith(".ppt")) return "📽️";
      if (n.endsWith(".zip") || n.endsWith(".7z") || n.endsWith(".tar") || n.endsWith(".gz")) return "🗜️";
      if (t.startsWith("audio/")) return "🎵";
      if (t.startsWith("video/")) return "🎬";
      return "📎";
    };
    const icon = iconForType(file.type, file.name);
    const noPreviewLabel = i18n_t("app.records.preview_not_available") || "プレビューはこの形式に未対応です";
    previewEl.innerHTML = `
      <div data-action="preview-open"
           style="margin-top:8px; padding:14px; background:var(--paper); border:1px solid var(--line); border-radius:6px; display:flex; gap:12px; align-items:center;">
        <div style="font-size:32px;">${icon}</div>
        <div style="flex:1; font-size:12px; color:var(--muted);">
          ${escape(noPreviewLabel)}
        </div>
        <a href="${url}" target="_blank" rel="noopener"
           data-action="preview-open"
           download="${escape(file.name || 'file')}"
           style="font-size:12px; color:var(--accent); text-decoration:none;">
          ⬇ ${escape(i18n_t("app.records.btn_download") || "ダウンロード")}
        </a>
      </div>
    `;
  }

  // preview 領域内の click は parent の file-picker handler に bubble させない
  previewEl.querySelectorAll('[data-action="preview-open"]').forEach(el => {
    el.addEventListener("click", (e) => e.stopPropagation());
  });
}

function _clearRecordsFilePreview() {
  if (_recordsFilePreviewBlobUrl) {
    try { URL.revokeObjectURL(_recordsFilePreviewBlobUrl); } catch {}
    _recordsFilePreviewBlobUrl = null;
  }
  const previewEl = document.getElementById("records-file-preview");
  if (previewEl) previewEl.innerHTML = "";
}


// =====================================================================
// Phase 7.0r: BYO-key OCR (OpenAI gpt-4o-mini)
// =====================================================================
//
// ユーザー所有の OpenAI API キーで領収書画像から date/amount/counterparty を
// 自動抽出。画像は browser → OpenAI 直送、Arpass server を経由しない。
//
// API キーの保管:
//   vault.entries に hidden flag 付きで保存 (entries 一覧には出ない)。
//   site = "__arpass.openai.apiKey" (sentinel、UI 上は使わない)。
//   pw   = sk-... (MEK で encrypted、Arweave に書込み済)。
//   Lock で消滅、再 unlock で復活、Recovery でも復元 OK。

const OPENAI_KEY_ENTRY_SITE = "__arpass.openai.apiKey";

/** vault から OpenAI key を取得 (見つからなければ null)。 */
function _getOpenaiApiKey() {
  const entries = state.vault?.entries ?? [];
  const e = entries.find(x => x.hidden && x.site === OPENAI_KEY_ENTRY_SITE);
  return e?.pw ?? null;
}

/** vault に OpenAI key を保存 (既存があれば update、無ければ新規)。 */
function _setOpenaiApiKey(apiKey) {
  if (!state.vault) return;
  if (!Array.isArray(state.vault.entries)) state.vault.entries = [];
  const now = new Date().toISOString();
  const idx = state.vault.entries.findIndex(x => x.hidden && x.site === OPENAI_KEY_ENTRY_SITE);
  if (idx >= 0) {
    state.vault.entries[idx] = { ...state.vault.entries[idx], pw: apiKey, updatedAt: now };
  } else {
    state.vault.entries.push({
      id: newEntryId(),
      site: OPENAI_KEY_ENTRY_SITE,
      url: "https://platform.openai.com/",
      user: "openai-api-key",
      pw: apiKey,
      notes: "Phase 7.0r: BYO-key OCR — DO NOT delete via passwords UI",
      hidden: true,                  // ← 一覧から除外する目印
      createdAt: now,
      updatedAt: now,
    });
  }
  scheduleSave(state.vault);
}

/** vault から OpenAI key を削除。 */
function _clearOpenaiApiKey() {
  if (!state.vault) return;
  if (!Array.isArray(state.vault.entries)) return;
  state.vault.entries = state.vault.entries.filter(x => !(x.hidden && x.site === OPENAI_KEY_ENTRY_SITE));
  scheduleSave(state.vault);
}

// ---- Settings UI: OCR key 入力 / 保存 / 削除 ----
function _refreshOcrKeyStatus() {
  const statusEl = document.getElementById("ocr-key-status");
  const inputEl = document.getElementById("ocr-key-input");
  const errEl = document.getElementById("ocr-key-error");
  if (!statusEl) return;
  const key = _getOpenaiApiKey();
  errEl?.classList.add("hidden");
  if (key) {
    const masked = key.slice(0, 7) + "..." + key.slice(-4);
    statusEl.innerHTML = `<span style="color:var(--green);">✅ ${escape(i18n_t("app.settings.ocr_active") || "設定済")}</span> <code style="font-size:11px; color:var(--muted);">${escape(masked)}</code>`;
    if (inputEl) inputEl.value = "";
  } else {
    statusEl.innerHTML = `<span style="color:var(--muted);">${escape(i18n_t("app.settings.ocr_not_set") || "未設定 — OCR 機能は無効")}</span>`;
  }
}

document.getElementById("settings-btn")?.addEventListener("click", () => {
  // settings modal が開いた時 status を refresh (既存 click ハンドラに加えて)
  setTimeout(_refreshOcrKeyStatus, 50);
});

document.getElementById("ocr-key-save")?.addEventListener("click", async () => {
  const inputEl = document.getElementById("ocr-key-input");
  const errEl = document.getElementById("ocr-key-error");
  const saveBtn = document.getElementById("ocr-key-save");
  if (!inputEl) return;
  const key = inputEl.value.trim();
  if (!key) {
    if (errEl) {
      errEl.textContent = i18n_t("app.settings.ocr_err_empty") || "API キーを入力してください";
      errEl.classList.remove("hidden");
    }
    return;
  }
  if (saveBtn) saveBtn.disabled = true;
  errEl?.classList.add("hidden");
  try {
    const { validateApiKey } = await import("/lib/ocr-vision.js?v=08f6235e");
    await validateApiKey(key);  // 401 等なら throw
    _setOpenaiApiKey(key);
    _refreshOcrKeyStatus();
  } catch (e) {
    if (errEl) {
      errEl.textContent = (i18n_t("app.settings.ocr_err_validate") || "検証失敗") + ": " + (e?.message ?? String(e));
      errEl.classList.remove("hidden");
    }
  } finally {
    if (saveBtn) saveBtn.disabled = false;
  }
});

document.getElementById("ocr-key-clear")?.addEventListener("click", () => {
  if (!_getOpenaiApiKey()) return;
  if (!confirm(i18n_t("app.settings.ocr_clear_confirm") || "OpenAI API キーを削除しますか？ OCR 機能が無効になります。")) return;
  _clearOpenaiApiKey();
  _refreshOcrKeyStatus();
});

// ---- Records modal の OCR ボタン ----
//
// 初回のみ confirm dialog を出す。OK なら以降この session 中は出さない (sessionStorage)。
function _ocrFirstUseConfirmed() {
  try { return sessionStorage.getItem("arpass.ocr.confirmed") === "1"; }
  catch { return false; }
}
function _markOcrFirstUseConfirmed() {
  try { sessionStorage.setItem("arpass.ocr.confirmed", "1"); }
  catch {}
}

document.getElementById("records-ocr-btn")?.addEventListener("click", async () => {
  const btn = document.getElementById("records-ocr-btn");
  const progress = document.getElementById("records-ocr-progress");
  const statusEl = document.getElementById("records-ocr-status");
  const resultEl = document.getElementById("records-ocr-result");
  if (!btn) return;

  // Phase 7.0r-10: image または PDF に対応
  const isOcrSupported = _recordsPickedFile && (
    _recordsPickedFile.type.startsWith("image/") ||
    _recordsPickedFile.type === "application/pdf"
  );
  if (!isOcrSupported) {
    showRecordsModalError(i18n_t("app.records.ocr_image_only") || "OCR は画像 / PDF ファイルのみ対応です");
    return;
  }

  const apiKey = _getOpenaiApiKey();
  if (!apiKey) {
    showRecordsModalError(i18n_t("app.records.ocr_no_key") || "API キーが未設定です。設定 (⚙️) から登録してください。");
    return;
  }

  // 初回の confirmation (画像が OpenAI に送信される件)
  if (!_ocrFirstUseConfirmed()) {
    const ok = confirm(
      i18n_t("app.records.ocr_first_use_confirm")
      || "この画像は OpenAI (api.openai.com) に直接送信されます。Arpass server は経由しません。\n\nOpenAI のプライバシーポリシーが適用されます。続行しますか？"
    );
    if (!ok) return;
    _markOcrFirstUseConfirmed();
  }

  btn.disabled = true;
  progress?.classList.remove("hidden");
  resultEl?.classList.add("hidden");
  if (statusEl) statusEl.textContent = i18n_t("app.records.ocr_uploading") || "画像を送信中…";

  try {
    const { runVisionOcr } = await import("/lib/ocr-vision.js?v=08f6235e");
    const { suggested } = await runVisionOcr(_recordsPickedFile, apiKey, {
      // Phase 7.0r-5: UI ロケールを渡して description/tags の言語を固定
      // (受取書側の言語に依存させると英語混じりになる問題を解消)
      uiLang: i18n_getLang(),
      onProgress: (stage) => {
        if (!statusEl) return;
        const map = {
          pdf_loading:   i18n_t("app.records.ocr_pdf_loading")   || "PDF を読込中…",
          pdf_rendering: i18n_t("app.records.ocr_pdf_rendering") || "PDF をレンダリング中…",
          pdf_encoding:  i18n_t("app.records.ocr_pdf_encoding")  || "PDF を画像に変換中…",
          uploading:     i18n_t("app.records.ocr_uploading")     || "画像を送信中…",
          analyzing:     i18n_t("app.records.ocr_analyzing")     || "OCR 解析中…",
          parsing:       i18n_t("app.records.ocr_parsing")       || "結果を解析中…",
        };
        statusEl.textContent = map[stage] || stage;
      },
    });

    // 抽出結果を fields に適用 (OCR が値を返したら常に上書き)。
    // 注: '空 field のみ上書き' だと、modal 開いた時のデフォルト値 (date=今日)
    //     や user pre-fill が OCR 結果より優先されてしまうバグがあった。
    //     OCR ボタン click は明示的 user 操作なので、結果は常に上書きで OK。
    //     誤読は records-ocr-result の '読取完了 — 内容を確認/編集してください'
    //     表示で review を促す設計。
    const sug = suggested || {};
    let filled = 0;
    if (sug.date) {
      const dateEl = document.getElementById("records-m-date");
      if (dateEl) { dateEl.value = sug.date; filled++; }
    }
    if (sug.amount != null) {
      const amtEl = document.getElementById("records-m-amount");
      if (amtEl) { amtEl.value = String(sug.amount); filled++; }
    }
    if (sug.currency) {
      const curEl = document.getElementById("records-m-currency");
      if (curEl && [...curEl.options].some(o => o.value === sug.currency)) {
        curEl.value = sug.currency; filled++;
      }
    }
    if (sug.counterparty) {
      const cpEl = document.getElementById("records-m-counterparty");
      if (cpEl) { cpEl.value = sug.counterparty; filled++; }
    }
    if (sug.title) {
      const titleEl = document.getElementById("records-m-title");
      if (titleEl) { titleEl.value = sug.title; filled++; }
    }
    if (sug.type) {
      const typeEl = document.getElementById("records-m-type");
      if (typeEl && [...typeEl.options].some(o => o.value === sug.type)) {
        typeEl.value = sug.type; filled++;
      }
    }
    if (sug.description) {
      const descEl = document.getElementById("records-m-description");
      if (descEl) { descEl.value = sug.description; filled++; }
    }
    if (Array.isArray(sug.tags) && sug.tags.length > 0) {
      const tagsEl = document.getElementById("records-m-tags");
      if (tagsEl) { tagsEl.value = sug.tags.join(", "); filled++; }
    }

    progress?.classList.add("hidden");
    if (resultEl) {
      resultEl.textContent =
        (i18n_t("app.records.ocr_done") || "読取完了 — 内容を確認/編集してください")
        + ` (${filled} ${i18n_t("app.records.ocr_filled_count") || "fields"})`;
      resultEl.classList.remove("hidden");
    }
    btn.disabled = false;
  } catch (e) {
    console.error("OCR failed:", e);
    progress?.classList.add("hidden");
    btn.disabled = false;
    showRecordsModalError(
      (i18n_t("app.records.ocr_error") || "OCR 失敗") + ": " + (e?.message ?? String(e))
    );
  }
});


// =====================================================================
// Phase 7.0r-9: Records CSV export (text データのダウンロード)
// =====================================================================
//
// ユーザー要望: '画像やファイルのダウンロードは、実はいざという時だけで、
// 日付、取引先、金額、備考等、テキストで管理しているデータのダウンロードが
// 一番使われそうです。'
//
// 仕様:
//   - getCurrentRecords (corrections override + tombstones 除外) ベース
//   - UTF-8 BOM 付き → Excel で日本語が文字化けしない
//   - 改行・カンマ・引用符を含むセルは "..." で囲み、内側の " は "" にエスケープ
//   - tags は ;セミコロン区切り (CSV カンマと衝突回避)
//   - filename: arpass-records-YYYY-MM-DD.csv

function _csvEscape(value) {
  if (value == null) return "";
  const s = String(value);
  // RFC 4180: 改行 / , / " を含めば quote 必須、内側の " は "" に
  if (/[",\n\r]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

function _buildRecordsCsv(records) {
  const headers = [
    "id", "type", "date",
    "counterparty", "title",
    "amount", "currency",
    "description", "tags",
    "createdAt", "version",
    "txId", "onChainBytes", "consumedUsdMicro", "sha256",
    "arweave_url",
  ];
  const lines = [headers.map(_csvEscape).join(",")];
  for (const r of records) {
    const att = r.attachments?.[0] ?? {};
    const tags = Array.isArray(r.tags) ? r.tags.join(";") : "";
    const row = [
      r.id ?? "",
      r.type ?? "",
      r.date ?? "",
      r.counterparty ?? "",
      r.title ?? "",
      typeof r.amount === "number" ? String(r.amount) : "",
      r.currency ?? "",
      r.description ?? "",
      tags,
      r.createdAt ?? "",
      r.version ?? 1,
      att.txId ?? "",
      att.onChainBytes ?? "",
      att.consumedUsdMicro ?? "",
      att.sha256 ?? "",
      att.txId ? `https://viewblock.io/arweave/tx/${att.txId}` : "",
    ];
    lines.push(row.map(_csvEscape).join(","));
  }
  return lines.join("\r\n") + "\r\n";  // CRLF (Excel friendly)
}

function _exportRecordsCsv() {
  if (!state.vault) return;
  const records = getCurrentRecords(state.vault);
  if (records.length === 0) {
    alert(i18n_t("app.records.csv_empty") || "出力する records がありません");
    return;
  }
  // 日付 desc で sort して見やすく
  const sorted = [...records].sort((a, b) => (b.date ?? "").localeCompare(a.date ?? ""));
  const csv = _buildRecordsCsv(sorted);
  // UTF-8 BOM (﻿) を先頭に付加 → Excel for Windows で日本語が正しく開く
  const bom = "﻿";
  const blob = new Blob([bom + csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const today = new Date().toISOString().slice(0, 10);
  const a = document.createElement("a");
  a.href = url;
  a.download = `arpass-files-${today}.csv`;
  a.style.display = "none";
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 100);
}

document.getElementById("records-csv-btn")?.addEventListener("click", () => {
  _exportRecordsCsv();
});


// Phase 7.1-G: 招待 URL を持って来た時は signup 画面に banner を出す
if (typeof _renderInviteBanner === "function") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", _renderInviteBanner);
  } else {
    _renderInviteBanner();
  }
}

/**
 * Phase 7.2-B v2.2: unlock 直後に呼ぶ。 k1Pending mode なら admin の K1 配布を取りに行き、
 * 取れたら自動 transition (= 実 K1 で再暗号化 + saveVault)、 取れなければ pending 継続。
 */
async function _maybeTransitionFromK1Pending() {
  try {
    const r = await tryTransitionFromPending();
    if (r.transitioned) {
      try { toast(`✅ Admin から K1 を受け取りました (v${r.k1Version})`, "ok", 5000); } catch {}
      console.log("[k1-transition]", r);
    } else if (r.reason === "k1_pending") {
      try { toast("ℹ️ Admin の K1 配布待ちです", "info", 6000); } catch {}
    } else if (r.reason !== "not_pending") {
      console.log("[k1-transition] skipped:", r.reason);
    }
  } catch (e) {
    console.warn("[k1-transition] error:", e?.message);
  }
}
if (typeof window !== "undefined") {
  window._maybeTransitionFromK1Pending = _maybeTransitionFromK1Pending;
  // Phase 7.2-B v2.2: openSession の auto-transition から通知を受け取って toast 表示
  window.addEventListener("arpass:k1-transitioned", (ev) => {
    const v = ev.detail?.k1Version ?? "?";
    try { toast(`✅ Admin から K1 を受け取りました (v${v})`, "ok", 5000); } catch {}
  });
  window.addEventListener("arpass:k1-pending-still", (ev) => {
    const reason = ev.detail?.reason ?? "unknown";
    if (reason === "k1_pending") {
      try { toast("ℹ️ Admin の K1 配布待ちです", "info", 6000); } catch {}
    }
  });
}

/**
 * Phase 7.2-B v2.5: vault tab top の K1 migration banner を render する。
 * vault 表示時に呼ぶ。 N=0 なら hidden。
 */
function _renderK1MigrationBanner() {
  const banner = document.getElementById("k1-migration-banner");
  const countEl = document.getElementById("k1-migration-count");
  if (!banner || !countEl) return;
  let count = 0;
  try { count = countRecordsNeedingK1Migration(); } catch {}
  if (count > 0) {
    countEl.textContent = String(count);
    banner.classList.remove("hidden");
  } else {
    banner.classList.add("hidden");
  }
}

async function _onK1MigrateClick() {
  const btn = document.getElementById("k1-migrate-btn");
  const resEl = document.getElementById("k1-migrate-result");
  if (!btn) return;
  resEl?.classList.add("hidden");
  btn.disabled = true;
  btn.textContent = "再暗号化中…";
  try {
    const r = await migrateAllRecordsToCurrentK1();
    if (resEl) {
      resEl.classList.remove("hidden");
      let msg = `✅ ${r.migrated}/${r.total} 件を最新 K1 で再暗号化しました`;
      if (r.skipped > 0) msg += ` (失敗 ${r.skipped} 件 — admin に過去 K1 再配布依頼が必要かも)`;
      resEl.textContent = msg;
    }
    _auditPushEvent({
      action: "records-k1-migrated",
      details: { migrated: r.migrated, total: r.total, skipped: r.skipped }
    }).catch(() => {});
    _renderK1MigrationBanner();
  } catch (e) {
    console.error("[k1-migrate]", e);
    if (resEl) {
      resEl.classList.remove("hidden");
      resEl.style.background = "#FEF2F2";
      resEl.style.borderLeftColor = "#DC2626";
      resEl.textContent = "❌ " + (e?.message || e);
    }
    btn.disabled = false;
    btn.textContent = "📦 再暗号化";
  }
}
// expose + bind
if (typeof window !== "undefined") {
  window._renderK1MigrationBanner = _renderK1MigrationBanner;
  // Phase 7.2-B v2.5 hotfix: admin K1 セクションの手動リフレッシュ用 (= UI stuck 時の救済)
  window._renderAdminK1Section = _renderAdminK1Section;
  // banner button のクリックは idempotent bind
  const tryBind = () => {
    const b = document.getElementById("k1-migrate-btn");
    if (b && !b.dataset.bound) {
      b.dataset.bound = "1";
      b.addEventListener("click", () => _onK1MigrateClick().catch(console.error));
    }
  };
  // app boot 時 + showView vault 時に bind
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", tryBind);
  } else {
    tryBind();
  }
  // showView('vault') 後にも呼ばれるよう、 グローバル expose
  window._tryBindK1MigrateBtn = tryBind;
}



// ============================================================================
// Phase 7.5: PWA Share Target — Service Worker でインターセプトした共有データを
//   pull して、 vault unlock 後にエントリ追加モーダルに prefill する。
//   ネットワーク側に URL/title は出ない (SW が /share-target/pull で in-memory
//   応答するため)。 ZK 設計維持。
// ============================================================================

let _pendingShareData = null;  // { url, title, text } or null

// URL から hostname を抽出 (= サイト名 default 候補)。 純粋 client 計算、 ZK OK。
function _hostnameFromUrl(urlStr) {
  if (!urlStr || typeof urlStr !== "string") return "";
  try {
    const u = new URL(urlStr);
    return (u.hostname || "").replace(/^www\./, "");
  } catch { return ""; }
}

// SW から共有データを取り出す。 SW が active でなければ null。
async function _pullShareData() {
  try {
    const r = await fetch("/share-target/pull", { method: "GET", cache: "no-store" });
    if (!r.ok) return null;
    const data = await r.json();
    return data || null;
  } catch (e) {
    console.warn("[share-target] pull failed:", e?.message);
    return null;
  }
}

// vault unlock 後に共有データがあれば Add Entry modal に prefill して開く
async function _maybeApplyShareData() {
  if (!_pendingShareData) return;
  const sd = _pendingShareData;
  _pendingShareData = null;  // 1 回限り

  if (state?.readOnly) {
    toast(i18n_t("app.toast.readonly_drive") || "現在 read-only モードのため追加できません", "err");
    return;
  }

  // URL から site name を組み立て (title > hostname > 空)
  const siteFromTitle = (sd.title || "").trim().slice(0, 256);
  const siteFromUrl = _hostnameFromUrl(sd.url);
  const siteName = siteFromTitle || siteFromUrl || "";
  const urlValue = (sd.url || "").trim().slice(0, 2048);

  // Add Entry modal を開いて prefill
  try {
    openModal(null);
    setTimeout(() => {
      const siteEl = document.getElementById("m-site");
      const urlEl  = document.getElementById("m-url");
      if (siteEl && !siteEl.value) siteEl.value = siteName;
      if (urlEl && !urlEl.value) urlEl.value = urlValue;
      // user フォーカスは password へ (= 次に user 入力すべき欄)
      document.getElementById("m-user")?.focus();
    }, 50);
  } catch (e) {
    console.warn("[share-target] apply share data failed:", e?.message);
  }
}

// Boot 時の share data チェック。 URL に ?shared=1 が付いていれば SW から pull
async function _checkShareDataOnBoot() {
  try {
    const params = new URLSearchParams(location.search);
    if (params.get("shared") !== "1") return;

    // ?shared=1 を URL から削除 (= reload で再 prefill しない)
    params.delete("shared");
    const newSearch = params.toString();
    history.replaceState(null, "", location.pathname + (newSearch ? "?" + newSearch : ""));

    _pendingShareData = await _pullShareData();
    if (_pendingShareData) {
      console.log("[share-target] received share:", {
        hasUrl: !!_pendingShareData.url,
        hasTitle: !!_pendingShareData.title,
      });
      // unlock 済みなら即適用。 未 unlock なら _pendingShareData は保持され、
      //   showView("vault") が呼ばれたタイミングで _maybeApplyShareData が走る
      if (_session?.vault) {
        _maybeApplyShareData();
      }
    }
  } catch (e) {
    console.warn("[share-target] boot check failed:", e?.message);
  }
}

// vault unlock 時 (= showView("vault") の後) にも share data 適用を試みる
if (typeof window !== "undefined") {
  window._maybeApplyShareData = _maybeApplyShareData;
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", _checkShareDataOnBoot);
} else {
  _checkShareDataOnBoot();
}


// ============================================================================
// Phase 7.5b: クリップボードから URL を貼り付け (iOS Safari + Android 両対応)
//   iOS Safari は Share Target API 非対応のため、 clipboard を読む手段でカバー。
//   user gesture (= ボタン押下) 内で navigator.clipboard.readText() を呼ぶ必要あり。
//   ZK 維持: clipboard 内容はクライアント側のみ、 ネットワークに出さない。
// ============================================================================

// 一般的な TLD (= scheme なし URL の判定用)。 完全網羅ではなく、 typo / 普通の単語との
//   衝突 (e.g. "dr. smith.") を防ぐためのホワイトリスト。 amazon.co.jp などの二段 TLD
//   も .co\.jp \| .com\.au \| .gov\.uk... 等を別途 array で列挙する。
const _COMMON_TLDS = new Set([
  "com","net","org","io","co","ai","app","dev","biz","info","me","tv",
  "us","uk","jp","cn","kr","tw","hk","de","fr","it","es","ru","br","in","au","ca","nz","sg",
  "edu","gov","mil","xyz","tech","store","shop","blog","news","online","cloud","page","site"
]);

// 二段 TLD (e.g. co.jp, com.au)。 _COMMON_TLDS の中身と組み合わせる。
const _SECOND_TLDS = new Set([
  "co.jp","ne.jp","or.jp","ac.jp","go.jp","ed.jp",
  "co.uk","ac.uk","gov.uk","org.uk","ltd.uk",
  "com.au","com.br","com.cn","com.tw","com.hk","co.kr","co.nz","co.in"
]);

function _looksLikeDomain(token) {
  // "a.b" or "a.b.c" 形式、 各 label は ASCII 英数 + ハイフン (国際化ドメインは扱わない)
  if (!/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(token)) return false;
  const parts = token.toLowerCase().split(".");
  // 2 段 TLD (co.jp 等) も判定
  if (parts.length >= 3) {
    const tail2 = parts.slice(-2).join(".");
    if (_SECOND_TLDS.has(tail2)) return true;
  }
  const last = parts[parts.length - 1];
  return _COMMON_TLDS.has(last);
}

function _extractUrlFromText(text) {
  if (!text || typeof text !== "string") return "";
  // 1) https?://...
  const m = text.match(/https?:\/\/[^\s]+/i);
  if (m) return m[0].slice(0, 2048);
  // 2) www.... → https:// を補う
  const m2 = text.match(/(?:^|\s)(www\.[^\s]+)/i);
  if (m2) return ("https://" + m2[1]).slice(0, 2048);
  // 3) scheme なしの bare domain (= amazon.co.jp/dp/...) を TLD ホワイトリストで判定
  //    全体トークン (whitespace 区切り) で domain 形式のもの 1 つを拾う
  const tokens = text.split(/[\s\u3000]+/);
  for (const t of tokens) {
    if (!t) continue;
    // path 切り出し
    const slashIdx = t.indexOf("/");
    const domainPart = slashIdx >= 0 ? t.slice(0, slashIdx) : t;
    if (_looksLikeDomain(domainPart)) {
      return ("https://" + t).slice(0, 2048);
    }
  }
  return "";
}

async function _pasteUrlFromClipboard() {
  if (!navigator?.clipboard?.readText) {
    toast(i18n_t("app.toast.clipboard_unsupported") || "このブラウザは Clipboard API 非対応", "err");
    return;
  }
  if (state?.readOnly) {
    toast(i18n_t("app.toast.readonly_drive") || "read-only モードでは追加できません", "err");
    return;
  }
  let text = "";
  try {
    text = await navigator.clipboard.readText();
  } catch (e) {
    // iOS: 許可されなかった or 何もコピーされていない
    toast(i18n_t("app.toast.clipboard_no_url") || "クリップボードに URL が見つかりません", "err");
    return;
  }
  const url = _extractUrlFromText(text);
  if (!url) {
    // 受信したテキストの冒頭を toast に含めて、 何が来たのか可視化 (Universal
    //   Clipboard 経由で Mac の clipboard が来た場合に状況把握できる)。
    const preview = (text || "").replace(/\s+/g, " ").trim().slice(0, 60);
    const msg = preview
      ? `${i18n_t("app.toast.clipboard_no_url") || "クリップボードに URL が見つかりません"} (\"${preview}${(text||"").length > 60 ? "…" : ""}\")`
      : (i18n_t("app.toast.clipboard_no_url") || "クリップボードに URL が見つかりません");
    toast(msg, "err", 6000);
    return;
  }
  // Add Entry modal を開いて prefill (Share Target と同じ流れ)
  try {
    openModal(null);
    setTimeout(() => {
      const siteEl = document.getElementById("m-site");
      const urlEl  = document.getElementById("m-url");
      const hostname = _hostnameFromUrl(url);
      if (siteEl && !siteEl.value) siteEl.value = hostname || "";
      if (urlEl && !urlEl.value) urlEl.value = url;
      document.getElementById("m-user")?.focus();
    }, 50);
  } catch (e) {
    console.warn("[paste-url] open modal failed:", e?.message);
  }
}

document.getElementById("paste-url-btn")?.addEventListener("click", () => {
  _pasteUrlFromClipboard().catch(e => console.warn("[paste-url] error:", e?.message));
});
