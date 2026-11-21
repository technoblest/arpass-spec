// ============================================================================
// web/lib/quick-unlock.js — 素早い解錠 (quick unlock) の端末側の保存とサーバ API
// ----------------------------------------------------------------------------
// 設計書: Arpass_素早い解錠_設計書.md §3.3〜3.7。 暗号 (封・開封・署名) は vault-crypto.js の
//   quSeal / quOpen / quSign (Rust)。 組み立ては vault-client.js (enrollQuickUnlock など)。
//
// 端末に置くもの (設計書 §3.7):
//   - localStorage の別キー `arpass_qu_v1__<profileId>` だけ。 meta (arpass_vault_meta_v5__*) には入れない
//     (meta には秘密を入れない決まりがあり、 writeMeta が meta をまるごと置き換えるので黙って消える)。
//     lint-security (34) が、 このキーをこのファイル以外で使っていないか確かめる。
//   - 中身: { v:1, offered, on, enrollment: { id, kind, credId, credIdHash, epoch, createdAt, expiresAt,
//            iv?, ct? } }。 iPhone のアプリ ("native") では iv / ct (blob) は Keychain に置き、 ここには
//     置かない。 ブラウザ ("browser"、 段階 3) だけが iv / ct をここに置く。
//   - y、 Kwrap、 Kprf、 pMat、 userIdKek、 PRF は保存しない。
//
// WASM: qu_* は rust-crypto の WASM (web/lib/rust-crypto/) にある。 CI (build-rust-crypto.yml) が作る
//   「rebuild WASM」コミットは [skip ci] なので、 Cloudflare Pages はそれを配信しない。 Rust を変えたあとは
//   web/ を触るコミットを 1 つ足して、 build hashes と配信を走らせる (2026-11-09)。 そのコミットの
//   メッセージに、 角かっこ付きの skip 指示の文字列そのものを書かないこと (書くとそのコミットも飛ばされる)。
//   Rust を変えていなくても、 CI の rustc の版が変わると WASM が作り直される (2026-11-14 の本番、 b6841cf0)。
//   そのときも同じく web/ のコミットを足す。
// ============================================================================

import { signedFetch } from "./client-auth.js?v=20bb8232";
import { getActiveProfileId } from "./profiles.js?v=7762257b";

const QU_STORAGE_PREFIX = "arpass_qu_v1__";

function _quKey(profileId) {
  if (typeof profileId !== "string" || !profileId) return null;
  return QU_STORAGE_PREFIX + profileId;
}

export function activeQuProfileId() {
  try { return getActiveProfileId() || null; } catch { return null; }
}

/** この端末 (今のプロファイル) の素早い解錠の状態。 無ければ既定値。 */
export function readQuState(profileId = activeQuProfileId()) {
  const k = _quKey(profileId);
  const empty = { v: 1, offered: false, on: false, enrollment: null };
  if (!k) return empty;
  try {
    const s = JSON.parse(localStorage.getItem(k) || "null");
    if (!s || s.v !== 1) return empty;
    return { ...empty, ...s };
  } catch { return empty; }
}

export function writeQuState(state, profileId = activeQuProfileId()) {
  const k = _quKey(profileId);
  if (!k) return;
  const clean = {
    v: 1,
    offered: !!state.offered,
    on: !!state.on,
    enrollment: state.enrollment ? { ...state.enrollment } : null,
  };
  // native の blob は Keychain。 ここに iv / ct を残さない。
  if (clean.enrollment && clean.enrollment.kind === "native") {
    delete clean.enrollment.iv;
    delete clean.enrollment.ct;
  }
  try { localStorage.setItem(_quKey(profileId), JSON.stringify(clean)); } catch (e) {
    console.warn("[quick-unlock] state save failed:", e?.message);
  }
}

export function patchQuState(patch, profileId = activeQuProfileId()) {
  writeQuState({ ...readQuState(profileId), ...patch }, profileId);
}

export function clearQuEnrollment(profileId = activeQuProfileId()) {
  patchQuState({ enrollment: null }, profileId);
}

export function removeQuState(profileId) {
  const k = _quKey(profileId);
  if (k) { try { localStorage.removeItem(k); } catch (_) {} }
}

// ---------------------------------------------------------------------------
// サーバ API (functions/api/quick-unlock/*)
// ---------------------------------------------------------------------------

async function _json(res) {
  let body = null;
  try { body = await res.json(); } catch { body = null; }
  return { status: res.status, body: body || { ok: false, code: "bad_response" } };
}

function _err(code, message, extra = {}) {
  const e = new Error(message || code);
  e.code = code;
  Object.assign(e, extra);
  return e;
}

/** 登録 (署名あり)。 @returns {Promise<{id, y, epoch, kind, createdAt, expiresAt}>} */
export async function quEnrollApi(signingState, { id, Q, kind, labelEnc }) {
  const r = await _json(await signedFetch("/api/quick-unlock/enroll", "POST", { id, Q, kind, labelEnc: labelEnc ?? null }, signingState, { timeoutMs: 20000 }));
  if (r.status !== 200 || !r.body.ok) throw _err(r.body.code || "enroll_failed", r.body.error, { status: r.status, count: r.body.count, limit: r.body.limit });
  return r.body;
}

/** nonce をもらう (署名なし)。 */
export async function quChallengeApi(id) {
  const res = await fetch("/api/quick-unlock/challenge", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id }),
    signal: AbortSignal.timeout(15000),
  });
  const r = await _json(res);
  if (r.status !== 200 || !r.body.ok || typeof r.body.nonce !== "string") throw _err(r.body.code || "challenge_failed", r.body.error, { status: r.status });
  return r.body.nonce;
}

/** 署名を送って y をもらう (署名なし)。 失敗はどの理由でも not_found。 */
export async function quEvalApi(id, nonce, sig) {
  const res = await fetch("/api/quick-unlock/eval", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id, nonce, sig }),
    signal: AbortSignal.timeout(15000),
  });
  const r = await _json(res);
  if (r.status !== 200 || !r.body.ok || typeof r.body.y !== "string") throw _err(r.body.code || "eval_failed", r.body.error, { status: r.status });
  return r.body.y;
}

/** 一覧 (署名あり)。 @returns {Promise<{epoch, epochReason, limit, devices}>} */
export async function quListApi(signingState, { self = null } = {}) {
  // self: この端末の登録の id。 KV の list が新しい登録をまだ返さないときも、 サーバーが直接確かめて足す (list.js)。
  const path = "/api/quick-unlock/list" + (self ? "?self=" + encodeURIComponent(self) : "");
  const r = await _json(await signedFetch(path, "GET", null, signingState, { timeoutMs: 20000 }));
  if (r.status !== 200 || !r.body.ok) throw _err(r.body.code || "list_failed", r.body.error, { status: r.status });
  return r.body;
}

/** 1 台を外す (署名あり)。 */
export async function quRevokeApi(signingState, id) {
  const r = await _json(await signedFetch("/api/quick-unlock/revoke", "POST", { id }, signingState, { timeoutMs: 20000 }));
  if (r.status !== 200 || !r.body.ok) throw _err(r.body.code || "revoke_failed", r.body.error, { status: r.status });
  return r.body;
}

/** 行の名前を変える (署名あり、 2026-11-17)。 labelEnc は端末で暗号化した名前。 他人の・外した・使えない行は 404 (not_found)。 */
export async function quRenameApi(signingState, id, labelEnc) {
  const r = await _json(await signedFetch("/api/quick-unlock/rename", "POST", { id, labelEnc }, signingState, { timeoutMs: 20000 }));
  if (r.status !== 200 || !r.body.ok) throw _err(r.body.code || "rename_failed", r.body.error, { status: r.status });
  return r.body;
}

/** すべて外す = epoch を上げる (署名あり)。 ok で返らなければ throw (呼び出し側は先へ進まない)。 */
export async function quRevokeAllApi(signingState, reason = "user") {
  const r = await _json(await signedFetch("/api/quick-unlock/revoke", "POST", { all: true, reason }, signingState, { timeoutMs: 20000 }));
  if (r.status !== 200 || !r.body.ok || !Number.isInteger(r.body.epoch)) throw _err(r.body.code || "epoch_failed", r.body.error, { status: r.status });
  return r.body;
}
