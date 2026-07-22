// ============================================================================
// Arpass — Emergency Business Vault Restore tool (Phase 7.2-B v2)
// ----------------------------------------------------------------------------
// Standalone, server-independent recovery tool. After Arpass (the operator) has
// permanently shut down, business-mode vaults can no longer fetch the company
// key K1 from the server. This tool lets an employee decrypt their own business
// vault offline using:
//
//   (1) their own 2-of-3 unlock factors (Master password + Recovery here),
//   (2) the company key K1 exported by the admin
//       (kind: "arpass-business-k1-emergency-export", from app.html's
//        "Emergency Export" -- see app-main.js),
//   (3) their encrypted vault envelope, fetched directly from the public
//       Arweave network (GraphQL find + arweave.net data fetch) -- NO /api/*.
//
// SECURITY MODEL (must hold):
//   real_MEK = HKDF(K1 || K2). K1 is company-common; K2 is per-employee and is
//   derived from THIS employee's own 2-of-3 factors. The K1 file ALONE grants
//   no access -- an attacker holding K1 still needs 2 of the employee's own 3
//   factors (Master / Passkey / Recovery) to open even a single vault. This
//   tool never weakens that: it only supplies K1 directly in place of the dead
//   server fetch; the K2-wrap unwrap (w.a/b/c) still requires real factors.
// ============================================================================

// 個人 (Master + Recovery / Passkey) の復号は pure-JS (WebCrypto + noble、WASM 非依存)。
import {
  deriveRMat,
  deriveAllAppNameTags,
  deriveAppNameTag,
  deriveOuterKeyBytes,
  unwrapEnvelopeOuter,
  decryptVault,
  b64uEncode,
  b64uDecode,
  unwrapBek,
  decryptFileWithBek,
} from "/lib/emergency-recover-purejs.js?v=f5603e48";
// business K1 / WebAuthn 経路のみ本体 (Rust WASM) を利用。
import {
  decodeUserIdV7,
  credentialIdToHash,
  unwrapBekWithMekHandle,
  decryptWithBekHandle,
} from "/lib/vault-crypto.js?v=6bb1e228";

import {
  decryptBusinessVaultWithK1,
  authenticateWithPasskey,
} from "/lib/vault-client.js?v=adb3cd17";

// ---- minimal i18n (JA + EN only; full 16-locale i18n intentionally not used) ----
const STRINGS = {
  ja: {
    step1_err_factors: "マスターパスワードとリカバリーキーの両方を入力してください。",
    step2_err_load: "K1 ファイルを読み込めませんでした: ",
    step2_err_kind: "このファイルは Arpass の K1 緊急 export ファイルではありません (kind 不一致)。",
    step2_ok: "K1 ファイルを読み込みました。",
    step3_finding: "Arweave 上であなたの vault を検索中…",
    step3_fetching: "暗号化された vault を Arweave から取得中…",
    step3_notfound: "このリカバリーキーに対応する vault が Arweave 上に見つかりませんでした。 リカバリーキーを確認するか、 envelope ファイルを手動でアップロードしてください。",
    step3_fetchfail: "vault データを Arweave から取得できませんでした。 少し待って再試行するか、 envelope ファイルを手動でアップロードしてください。",
    decrypt_ok: "復号に成功しました。",
    decrypt_fail: "復号に失敗しました。 入力した factor / K1 / envelope のいずれかが正しくない可能性があります: ",
    decrypt_no_k1ver: "envelope の K1 version に対応する K1 が export ファイルに含まれていません (version ",
    not_business: "この envelope は business mode の vault ではありません。",
    entries_empty: "(この vault にパスワードエントリはありません)",
    decrypting: "vault を復号中…",
    file_download: "復号してダウンロード",
    file_decrypting: "復号中…",
    file_fail: "失敗",
    files_none: "(この vault にファイルはありません)",
  },
  en: {
    step1_err_factors: "Enter both your Master password and Recovery key.",
    step2_err_load: "Could not read the K1 file: ",
    step2_err_kind: "This file is not an Arpass K1 emergency-export file (kind mismatch).",
    step2_ok: "K1 file loaded.",
    step3_finding: "Searching for your vault on Arweave…",
    step3_fetching: "Fetching your encrypted vault from Arweave…",
    step3_notfound: "No vault matching this Recovery key was found on Arweave. Double-check the Recovery key, or upload the envelope file manually.",
    step3_fetchfail: "Could not fetch the vault data from Arweave. Wait a moment and retry, or upload the envelope file manually.",
    decrypt_ok: "Decryption succeeded.",
    decrypt_fail: "Decryption failed. One of your factors / K1 / envelope may be incorrect: ",
    decrypt_no_k1ver: "The K1 version in the envelope is not present in the export file (version ",
    not_business: "This envelope is not a business-mode vault.",
    entries_empty: "(This vault has no password entries.)",
    decrypting: "Decrypting vault…",
    file_download: "Decrypt & download",
    file_decrypting: "Decrypting…",
    file_fail: "Failed",
    files_none: "(This vault has no files.)",
  },
};
function detectLang() {
  const l = (navigator.language || "en").toLowerCase();
  return l.startsWith("ja") ? "ja" : "en";
}
let LANG = detectLang();
function t(key) { return (STRINGS[LANG] && STRINGS[LANG][key]) || STRINGS.en[key] || key; }

// ---- DOM helpers ----
const $ = (id) => document.getElementById(id);
function show(el) { el && el.classList.remove("hidden"); }
function hide(el) { el && el.classList.add("hidden"); }
function setStatus(el, msg, kind) {
  if (!el) return;
  el.textContent = msg;
  el.className = "status " + (kind || "");
  show(el);
}

// ---- tool state ----
const state = {
  k1Export: null,        // parsed { k1Version, k1Current, k1History, companyId }
  envelope: null,        // decrypted-outer inner business envelope
  decryptedVault: null,  // plaintext vault object
  mek: null,             // 個人経路: raw MEK 32B (pure-JS records BEK unwrap 用)
  mekKey: null,          // business経路: MekKey handle (WASM records BEK unwrap 用)
  entries: null,
};

// ============================================================================
// Server-independent Arweave fetch.
//   GraphQL find: arweave.net + turbo-gateway.com /graphql (public, no auth)
//   Data fetch:   arweave.net/<txid> + turbo-gateway.com/<txid>
//   NO /api/* of the (defunct) Arpass server is ever called.
// ============================================================================
const ARWEAVE_GATEWAYS = ["https://arweave.net", "https://turbo-gateway.com"];
const GQL_TIMEOUT_MS = 8000;
const DATA_TIMEOUT_MS = 30000;

function gqlQuery(tag) {
  const safe = (x) => String(x).replace(/[^A-Za-z0-9_-]/g, "");
  return `query {
    transactions(
      tags: [{ name: "${safe(tag.name)}", values: ["${safe(tag.value)}"] }]
      sort: HEIGHT_DESC
      first: 5
    ) { edges { node { id block { height } } } }
  }`;
}

async function gqlAtGateway(gateway, tag) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), GQL_TIMEOUT_MS);
  try {
    const resp = await fetch(`${gateway}/graphql`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: gqlQuery(tag) }),
      signal: ctrl.signal,
    });
    clearTimeout(timer);
    if (!resp.ok) return [];
    const data = await resp.json();
    return (data?.data?.transactions?.edges ?? []).map((e) => ({
      txid: e.node.id,
      height: e.node.block?.height ?? Number.MAX_SAFE_INTEGER,
    }));
  } catch {
    clearTimeout(timer);
    return [];
  }
}

/**
 * Find candidate vault txids for a given Recovery key, directly from Arweave.
 * Returns txids sorted newest-first (highest block height first).
 */
async function findVaultTxCandidates(recoveryMaterial) {
  // The employee's tier is unknown, so probe all tier tags in parallel.
  // business/corp vault の最新 tx は legacy tag (= deriveAppNameTag(rMat, null)) で書かれる
  //   (refreshTierQualifier/saveVault が business を null tier に強制、 fetchCurrentTierQualifier も
  //   corp→null)。 personal は tier (free/paid/private)。 corp::cid tag は一切 write されないので probe しない。
  const tags = deriveAllAppNameTags(recoveryMaterial, null);
  const legacyTag = deriveAppNameTag(recoveryMaterial, null);  // business/corp は legacy tag で write
  const tagList = [legacyTag, tags.free, tags.paid, tags.private].filter((x) => x && x.name && x.value);
  const jobs = [];
  for (const tag of tagList) {
    for (const gw of ARWEAVE_GATEWAYS) jobs.push(gqlAtGateway(gw, tag));
  }
  const results = (await Promise.all(jobs)).flat();
  const seen = new Set();
  const candidates = [];
  for (const r of results) {
    if (seen.has(r.txid)) continue;
    seen.add(r.txid);
    candidates.push(r);
  }
  candidates.sort((a, b) => b.height - a.height);
  return candidates;
}

/** Fetch a raw blob for a txid directly from public Arweave gateways. */
async function fetchBlobFromArweave(txid) {
  const errors = [];
  for (const gw of ARWEAVE_GATEWAYS) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), DATA_TIMEOUT_MS);
    try {
      const r = await fetch(`${gw}/${txid}`, { cache: "no-store", signal: ctrl.signal });
      clearTimeout(timer);
      if (r.ok) return new Uint8Array(await r.arrayBuffer());
      errors.push(`${gw}: HTTP ${r.status}`);
    } catch (e) {
      clearTimeout(timer);
      errors.push(`${gw}: ${e?.message ?? e}`);
    }
  }
  throw new Error(errors.join("; "));
}

/**
 * Locate + fetch + outer-decrypt the employee's business envelope from Arweave.
 * @returns {Promise<object>} inner business envelope
 */
async function loadEnvelopeFromArweave(recoveryMaterial) {
  const outerKeyBytes = deriveOuterKeyBytes(recoveryMaterial);
  const candidates = await findVaultTxCandidates(recoveryMaterial);
  if (candidates.length === 0) {
    const err = new Error(t("step3_notfound"));
    err.code = "not_found";
    throw err;
  }
  let lastErr = null;
  for (const cand of candidates) {
    try {
      const blob = await fetchBlobFromArweave(cand.txid);
      const envelope = await unwrapEnvelopeOuter(blob, outerKeyBytes);
      // outer-decrypt succeeded -> this txid belongs to this Recovery key.
      return envelope;
    } catch (e) {
      lastErr = e;
    }
  }
  const err = new Error(t("step3_fetchfail") + (lastErr?.message ? ` (${lastErr.message})` : ""));
  err.code = "fetch_failed";
  throw err;
}

// ============================================================================
// K1 selection -- pick the K1 raw bytes matching envelope.k1Version.
// ============================================================================
// recovery fix: 災害復旧では k1Version メタが不正確なこと (rotation 直後等) があるため、
//   version 選択 K1 を最優先しつつ export 内の全 K1 (current + history) を候補化して総当たりする。
function allK1Candidates(k1Export, envelopeK1Version) {
  const out = [];
  if (!k1Export) return out;  // pending vault 等、 K1 ファイル無しでも呼べるように
  const seen = new Set();
  const push = (b64u, ver) => {
    if (!b64u || seen.has(b64u)) return;
    seen.add(b64u);
    try {
      const bytes = b64uDecode(b64u);
      if (bytes instanceof Uint8Array && bytes.length === 32) out.push({ bytes, version: ver ?? null });
    } catch { /* skip corrupt */ }
  };
  const hist = Array.isArray(k1Export.k1History) ? k1Export.k1History : [];
  // 1) envelope.k1Version に対応する K1 を最優先
  const wanted = envelopeK1Version;
  if (wanted != null && wanted !== k1Export.k1Version) {
    const entry = hist.find((e) => e && e.version === wanted);
    if (entry) push(entry.k1, entry.version);
  }
  // 2) current
  push(k1Export.k1Current, k1Export.k1Version);
  // 3) 全 history (version 不明・metadata 不一致への保険)
  for (const e of hist) if (e) push(e.k1, e.version);
  return out;
}

function selectK1Bytes(k1Export, envelopeK1Version) {
  // Default to current version when envelope omits k1Version (legacy envelopes).
  const wanted = (envelopeK1Version == null) ? k1Export.k1Version : envelopeK1Version;
  let b64u = null;
  if (wanted === k1Export.k1Version || wanted == null) {
    b64u = k1Export.k1Current;
  } else {
    const hist = Array.isArray(k1Export.k1History) ? k1Export.k1History : [];
    const entry = hist.find((e) => e && e.version === wanted);
    if (entry) b64u = entry.k1;
  }
  if (!b64u && wanted != null && wanted !== k1Export.k1Version) {
    const err = new Error(t("decrypt_no_k1ver") + wanted + ").");
    err.code = "k1_version_missing";
    throw err;
  }
  if (!b64u) b64u = k1Export.k1Current;
  const bytes = b64uDecode(b64u);
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new Error("K1 must decode to exactly 32 bytes (corrupt K1 file?).");
  }
  return bytes;
}

// ============================================================================
// Render decrypted vault (read-only) + CSV/JSON export.
// ============================================================================
function escapeHtml(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function vaultEntries(vault) {
  // Business vault schema: entries[] = { id, site, url, user, pw, notes, ... }
  return Array.isArray(vault?.entries) ? vault.entries : [];
}

function renderVault(vault) {
  const entries = vaultEntries(vault);
  const listEl = $("vault-list");
  listEl.innerHTML = "";
  if (entries.length === 0) {
    listEl.innerHTML = `<p class="muted">${escapeHtml(t("entries_empty"))}</p>`;
  } else {
    const rows = entries.map((e, i) => `
      <tr>
        <td>${escapeHtml(e.site || e.name || "")}</td>
        <td>${escapeHtml(e.user || e.username || "")}</td>
        <td><code>${escapeHtml(e.pw || e.password || "")}</code> <button class="copy-btn" type="button" data-copy="${i}">📋</button></td>
        <td>${escapeHtml(e.url || "")}</td>
        <td>${escapeHtml(e.notes || "")}</td>
      </tr>`).join("");
    listEl.innerHTML = `
      <table class="vault-table">
        <thead><tr>
          <th>Site</th><th>User</th><th>Password</th><th>URL</th><th>Notes</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  }
  $("vault-count").textContent = String(entries.length);
  state.entries = entries;
  listEl.querySelectorAll("button.copy-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const e = state.entries[Number(btn.getAttribute("data-copy"))];
      const pw = e?.pw || e?.password || "";
      try { await navigator.clipboard.writeText(pw); btn.textContent = "✓"; setTimeout(() => { btn.textContent = "📋"; }, 1200); } catch (_) {}
    });
  });
  show($("result-section"));
}

// ============================================================================
// Files (Records) — 各添付を BEK で復号してダウンロード。
//   record file は envelope とは別の Arweave tx (BEK 暗号化)。 mekKey で BEK を
//   unwrap → 直 Arweave 取得 → decryptWithBekHandle → download。 server 不要。
// ============================================================================
function renderFiles(vault) {
  const active = Array.isArray(vault?.records?.active) ? vault.records.active : [];
  const items = [];
  for (const rec of active) {
    const atts = Array.isArray(rec?.attachments) ? rec.attachments : [];
    for (const att of atts) items.push({ rec, att });
  }
  const listEl = $("files-list");
  $("files-count").textContent = String(items.length);
  if (items.length === 0) { hide($("files-section")); return; }
  listEl.innerHTML = "";
  items.forEach(({ rec, att }, i) => {
    const name = att.filename || rec.title || ("file-" + (i + 1));
    const kb = att.size ? " \u00b7 " + (att.size / 1024).toFixed(1) + " KB" : "";
    const row = document.createElement("div");
    row.className = "file-row";
    row.innerHTML = '<div class="fmeta"><div class="fname">' + escapeHtml(name) + '</div>'
      + '<div class="fsub">' + escapeHtml(att.mimeType || "") + kb
      + (rec.title && rec.title !== name ? " \u00b7 " + escapeHtml(rec.title) : "") + '</div></div>';
    const btn = document.createElement("button");
    btn.className = "btn-mini"; btn.type = "button"; btn.textContent = t("file_download");
    btn.addEventListener("click", () => downloadRecordFile(att, name, btn));
    row.appendChild(btn);
    listEl.appendChild(row);
  });
  show($("files-section"));
}

async function downloadRecordFile(att, name, btn) {
  const enc = att.encryption || {};
  if ((!state.mek && !state.mekKey) || !enc.wrappedBEK || !enc.wrapIv || !enc.dataIv || !att.txId) {
    btn.textContent = t("file_fail"); return;
  }
  const orig = btn.textContent; btn.disabled = true; btn.textContent = t("file_decrypting");
  try {
    const ct = await fetchBlobFromArweave(att.txId);
    const wb = b64uDecode(enc.wrappedBEK), wiv = b64uDecode(enc.wrapIv), div = b64uDecode(enc.dataIv);
    let bytes;
    if (state.mek) {
      // pure-JS: MEK(raw) → BEK(raw) → file
      const bek = await unwrapBek(state.mek, wb, wiv);
      bytes = await decryptFileWithBek(bek, div, ct);
    } else {
      // business (WASM handle) 経路
      const bekH = await unwrapBekWithMekHandle(state.mekKey, wb, wiv);
      bytes = await decryptWithBekHandle(bekH, div, ct);
    }
    download(name, bytes, att.mimeType || "application/octet-stream");
    btn.textContent = "\u2713";
    setTimeout(() => { btn.textContent = orig; btn.disabled = false; }, 1500);
  } catch (e) {
    console.error("[emergency-restore] file decrypt failed:", e);
    btn.textContent = t("file_fail"); btn.disabled = false;
  }
}

function download(filename, text, mime) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 3000);
}

function exportJSON() {
  if (!state.decryptedVault) return;
  download(`arpass-vault-${Date.now()}.json`,
    JSON.stringify(state.decryptedVault, null, 2), "application/json");
}

function csvCell(s) {
  const v = String(s == null ? "" : s);
  return /[",\n\r]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
}

function exportCSV() {
  if (!state.decryptedVault) return;
  const entries = vaultEntries(state.decryptedVault);
  const header = ["site", "user", "password", "url", "notes"];
  const lines = [header.join(",")];
  for (const e of entries) {
    lines.push([
      csvCell(e.site || e.name || ""),
      csvCell(e.user || e.username || ""),
      csvCell(e.pw || e.password || ""),
      csvCell(e.url || ""),
      csvCell(e.notes || ""),
    ].join(","));
  }
  download(`arpass-vault-${Date.now()}.csv`, lines.join("\r\n"), "text/csv");
}

// ============================================================================
// Main: run the decryption.
// ============================================================================
async function runDecrypt() {
  const statusEl = $("decrypt-status");
  hide($("result-section"));
  hide($("files-section"));
  hide(statusEl);

  // ---- (1) factors ----
  const masterPw = $("master-password").value;
  const recoveryKey = $("recovery-key").value.trim();
  if (!masterPw || !recoveryKey) {
    setStatus(statusEl, t("step1_err_factors"), "err");
    return;
  }

  // K1 は business mode のみ必須 (envelope mode を見てから判定)。

  $("decrypt-btn").disabled = true;
  try {
    const recoveryMaterial = deriveRMat(recoveryKey);

    // ---- envelope: manual upload takes priority, else fetch from Arweave ----
    let envelope = state.envelope;
    if (!envelope) {
      setStatus(statusEl, t("step3_finding"), "info");
      envelope = await loadEnvelopeFromArweave(recoveryMaterial);
      state.envelope = envelope;
    }

    const factors = { password: masterPw, recoveryMaterial };
    let result;
    if (envelope?.m === "business") {
      // ---- Business mode: K1 必須 (会社共通鍵)。 ただし k1Pending vault は ZERO_K1 暗号化なので不要 ----
      if (!state.k1Export && !envelope.k1Pending) {
        setStatus(statusEl, t("step2_err_load") + "(no file)", "err");
        return;
      }
      setStatus(statusEl, t("decrypting"), "info");
      // recovery fix: version 選択 K1 を先頭に、 export 内の全 K1 を総当たりで復号試行。
      //   (K2 は factor 由来で GCM 認証付きなので、 body tag mismatch は K1 不一致を意味する。)
      const k1cands = allK1Candidates(state.k1Export, envelope.k1Version ?? null);
      // recovery fix: k1Pending (= signup 後 K1 未配布 or transition 未完了) の vault は
      //   body が ZERO_K1 で暗号化されている。 会社 K1 では復号できないため ZERO_K1 候補を追加。
      //   pending は先頭 (= 最速)、 それ以外も末尾に保険として試す (GCM 認証で誤一致なし)。
      if (envelope.k1Pending) k1cands.unshift({ bytes: new Uint8Array(32), version: 0 });
      else k1cands.push({ bytes: new Uint8Array(32), version: 0 });
      if (k1cands.length === 0) {
        setStatus(statusEl, t("step2_err_load") + "(no valid 32B K1 in file)", "err");
        return;
      }
      let lastErr = null;
      for (const cand of k1cands) {
        try {
          result = await decryptBusinessVaultWithK1(envelope, factors, cand.bytes);
          break;  // 復号成功
        } catch (e) {
          lastErr = e;
        } finally {
          try { cand.bytes.fill(0); } catch {}
        }
      }
      if (!result) throw lastErr || new Error("decrypt failed (all K1 candidates exhausted)");
    } else {
      // ---- Personal mode (2-of-3、 K1 不要): Master + Recovery で AC 復号 ----
      setStatus(statusEl, t("decrypting"), "info");
      result = await decryptVault(envelope, factors);
    }

    // ---- render read-only + offer export ----
    state.decryptedVault = result.vault;
    state.mekKey = result.mekKey ?? null;
    setStatus(statusEl, t("decrypt_ok"), "ok");
    renderVault(result.vault);
    renderFiles(result.vault);
  } catch (e) {
    console.error("[emergency-restore] decrypt failed:", e);
    const msg = (e?.code === "not_found" || e?.code === "fetch_failed" || e?.code === "k1_version_missing")
      ? e.message
      : t("decrypt_fail") + (e?.message || String(e));
    setStatus($("decrypt-status"), msg, "err");
  } finally {
    $("decrypt-btn").disabled = false;
  }
}

// ============================================================================
// Passkey-based recovery (Recovery key が無い時): Master + Passkey の 2-of-3 AB。
//   Passkey の user.id(v7, 57B)が appNameTag と outer 鍵(Master でアンラップ)を運ぶ。
//   それで Arweave の過去版を探し、 新しい順に AB 復号を試す。
// ============================================================================
async function findVaultTxByTag(tag) {
  const jobs = [];
  for (const gw of ARWEAVE_GATEWAYS) jobs.push(gqlAtGateway(gw, tag));
  const results = (await Promise.all(jobs)).flat();
  const seen = new Set();
  const out = [];
  for (const r of results) { if (!seen.has(r.txid)) { seen.add(r.txid); out.push(r); } }
  out.sort((a, b) => b.height - a.height);
  return out;
}

async function runDecryptPasskey() {
  const statusEl = $("decrypt-status");
  hide($("result-section"));
  hide($("files-section"));
  hide(statusEl);
  const masterPw = $("master-password").value;
  if (!masterPw) { setStatus(statusEl, t("step1_err_factors"), "err"); return; }

  const btn = $("decrypt-btn-passkey");
  if (btn) btn.disabled = true;
  try {
    setStatus(statusEl, "Passkey で認証中…(古いパスキーを選んでください)", "info");
    const a1 = await authenticateWithPasskey(null, { forcePicker: true, prfOptional: true });
    const userHandle = a1.userHandle;
    const credentialId = a1.credentialId;
    if (!(userHandle instanceof Uint8Array) || userHandle.length !== 57) {
      setStatus(statusEl, "選んだパスキーが v7(57B user.id)ではありません。別のパスキーを試してください。", "err");
      return;
    }
    let prfOutput = a1.prfOutput;
    if (!prfOutput) {
      const a2 = await authenticateWithPasskey(credentialId, { userVerification: "discouraged" });
      prfOutput = a2.prfOutput;
    }
    if (!prfOutput) { setStatus(statusEl, "PRF を取得できませんでした。", "err"); return; }

    setStatus(statusEl, "ドライブを探しています…", "info");
    const decoded = await decodeUserIdV7(userHandle, masterPw);
    const tag = decoded.appNameTag;   // decodeUserIdV7 は {name, value}(b64u 文字列)を返す
    const candidates = await findVaultTxByTag(tag);
    if (candidates.length === 0) {
      setStatus(statusEl, "Arweave 上に vault が見つかりません(Master かパスキーが違う可能性)。", "err");
      return;
    }
    const credIdHash = await credentialIdToHash(credentialId);
    const factors = { password: masterPw, prfOutput, credIdHash };

    setStatus(statusEl, t("decrypting") + " (過去版を新しい順に試行)", "info");
    let result = null;
    for (const cand of candidates) {
      try {
        const blob = await fetchBlobFromArweave(cand.txid);
        const inner = await unwrapEnvelopeOuter(blob, decoded.outerKey);
        const r = await decryptVault(inner, factors);
        if (r?.vault) { result = r; break; }
      } catch (_) { /* この版は壊れ/不一致 → 古い版へ */ }
    }
    if (!result?.vault) {
      setStatus(statusEl, t("decrypt_fail") + "(候補 " + candidates.length + " 版すべて開けませんでした)", "err");
      return;
    }
    state.decryptedVault = result.vault;
    state.mekKey = result.mekKey ?? null;
    setStatus(statusEl, t("decrypt_ok"), "ok");
    renderVault(result.vault);
    renderFiles(result.vault);
  } catch (e) {
    console.error("[emergency-restore passkey] failed:", e);
    setStatus($("decrypt-status"), t("decrypt_fail") + (e?.message || String(e)), "err");
  } finally {
    if (btn) btn.disabled = false;
  }
}

// ============================================================================
// Wire up UI.
// ============================================================================
function applyLang() {
  document.documentElement.lang = LANG;
  for (const el of document.querySelectorAll("[data-ja]")) {
    el.textContent = LANG === "ja" ? el.getAttribute("data-ja") : el.getAttribute("data-en");
  }
  for (const el of document.querySelectorAll("[data-ja-ph]")) {
    el.placeholder = LANG === "ja" ? el.getAttribute("data-ja-ph") : el.getAttribute("data-en-ph");
  }
}

function init() {
  applyLang();

  $("lang-toggle")?.addEventListener("click", () => {
    LANG = LANG === "ja" ? "en" : "ja";
    applyLang();
  });

  // K1 file load
  $("k1-file")?.addEventListener("change", async (ev) => {
    const file = ev.target.files?.[0];
    const statusEl = $("k1-status");
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      if (parsed?.kind !== "arpass-business-k1-emergency-export") {
        setStatus(statusEl, t("step2_err_kind"), "err");
        state.k1Export = null;
        return;
      }
      if (typeof parsed.k1Current !== "string") {
        setStatus(statusEl, t("step2_err_kind"), "err");
        state.k1Export = null;
        return;
      }
      state.k1Export = {
        k1Version: parsed.k1Version ?? 1,
        k1Current: parsed.k1Current,
        k1History: Array.isArray(parsed.k1History) ? parsed.k1History : [],
        companyId: parsed.companyId ?? null,
      };
      const histN = state.k1Export.k1History.length;
      setStatus(statusEl,
        t("step2_ok") + (state.k1Export.companyId ? ` (companyId: ${state.k1Export.companyId})` : "") +
        (histN > 0 ? ` [+${histN} historical]` : ""),
        "ok");
    } catch (e) {
      setStatus(statusEl, t("step2_err_load") + (e?.message || String(e)), "err");
      state.k1Export = null;
    }
  });

  // Optional manual envelope upload (fallback when Arweave fetch fails)
  $("envelope-file")?.addEventListener("change", async (ev) => {
    const file = ev.target.files?.[0];
    const statusEl = $("envelope-status");
    if (!file) { state.envelope = null; return; }
    try {
      const buf = new Uint8Array(await file.arrayBuffer());
      // The manual file may be either: (a) the raw outer-wrapped blob from
      // Arweave, or (b) an already-decrypted-outer inner envelope JSON.
      let envelope = null;
      try {
        const asJson = JSON.parse(new TextDecoder().decode(buf));
        if (asJson && asJson.m === "business") envelope = asJson;
      } catch { /* not JSON -> treat as outer-wrapped blob below */ }
      if (envelope) {
        state.envelope = envelope;
        setStatus(statusEl,
          LANG === "ja" ? "envelope ファイルを読み込みました (内側 JSON)。"
                        : "Envelope file loaded (inner JSON).",
          "ok");
        return;
      }
      // Outer-wrapped blob: needs the Recovery key to derive the outer key.
      const recoveryKey = $("recovery-key").value.trim();
      if (!recoveryKey) {
        setStatus(statusEl,
          LANG === "ja" ? "outer-wrapped blob です。 先にリカバリーキーを入力してください。"
                        : "This is an outer-wrapped blob. Enter the Recovery key first.",
          "err");
        state.envelope = null;
        return;
      }
      const outerKey = deriveOuterKeyBytes(deriveRMat(recoveryKey));
      const envelope2 = await unwrapEnvelopeOuter(buf, outerKey);
      state.envelope = envelope2;
      setStatus(statusEl,
        LANG === "ja" ? "envelope ファイルを読み込みました (outer 復号成功)。"
                      : "Envelope file loaded (outer-decrypted).",
        "ok");
    } catch (e) {
      setStatus(statusEl, t("step2_err_load") + (e?.message || String(e)), "err");
      state.envelope = null;
    }
  });

  $("decrypt-btn")?.addEventListener("click", runDecrypt);
  $("decrypt-btn-passkey")?.addEventListener("click", runDecryptPasskey);
  $("export-json-btn")?.addEventListener("click", exportJSON);
  $("export-csv-btn")?.addEventListener("click", exportCSV);

  // Passkey / YubiKey (WebAuthn) は RP ID = arpass.io に origin 拘束される。
  //   ミラー(github.io 等)や localhost からは arpass.io の資格情報を呼べないので、
  //   同一 origin(arpass.io)以外では「Passkey で復旧」を隠し、Master+Recovery に誘導する。
  //   (arpass.io 上で配信された同一ツールでは従来どおり表示・機能する。)
  if (location.hostname !== "arpass.io") {
    const pkBtn = $("decrypt-btn-passkey");
    if (pkBtn) {
      hide(pkBtn);
      const note = document.createElement("p");
      note.className = "hint";
      note.setAttribute("data-ja", "\u203b Passkey / YubiKey は WebAuthn の仕様上 arpass.io と同一 origin でのみ使えます。 このミラーからは Master + Recovery をご利用ください。");
      note.setAttribute("data-en", "Note: Passkey / YubiKey (WebAuthn) only work on the arpass.io origin. From this mirror, use Master + Recovery.");
      note.textContent = LANG === "ja" ? note.getAttribute("data-ja") : note.getAttribute("data-en");
      pkBtn.parentElement && pkBtn.parentElement.appendChild(note);
    }
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
