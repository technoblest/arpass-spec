// ============================================================================
// web/lib/profiles.js — Phase 7.1-W
//
// 「Profile」 = ブラウザ内に共存する独立 vault entry。
//   - 個人モード vault
//   - 会社モード社員 vault (companyId 単位)
//   - 会社モード admin vault
//   - 別の Recovery で作った別 vault (引っ越し中など)
//
// 各 profile は完全独立した localStorage namespace を持つ:
//   arpass_vault_meta_v5__<profileId>          — meta (outerKey, appNameTag, latestTxId, ...)
//   arpass.envCache__<profileId>               — envelope cache
//   arpass.recCache__<profileId>.<txid>        — record file cache
//
// 起動時に profiles を列挙、複数あれば picker UI、1 個なら自動選択、0 個なら signup。
//
// 既存 user (legacy single profile) は最初の getActiveProfileId() 呼出で透明 migrate される:
//   旧 key "arpass_vault_meta_v5" が見つかったら → profile.id="default" として profile.json
//   に登録 + 旧 key を "arpass_vault_meta_v5__default" に rename。
// ============================================================================

import { t as _i18nT } from "./i18n.js?v=a97271a3";
const PROFILES_KEY = "arpass_profiles_v1";
const ACTIVE_KEY   = "arpass_active_profile_v1";
const LEGACY_META_KEY = "arpass_vault_meta_v5";

function _newProfileId() {
  const b = new Uint8Array(12);
  crypto.getRandomValues(b);
  return Array.from(b).map(x => x.toString(16).padStart(2, "0")).join("");
}

function _readProfilesRaw() {
  try { return JSON.parse(localStorage.getItem(PROFILES_KEY) || "null"); }
  catch { return null; }
}

function _writeProfilesRaw(profiles) {
  localStorage.setItem(PROFILES_KEY, JSON.stringify(profiles));
}

function _migrateLegacyIfNeeded() {
  if (_readProfilesRaw()) return;

  const legacyMeta = localStorage.getItem(LEGACY_META_KEY);
  if (!legacyMeta) {
    _writeProfilesRaw([]);
    return;
  }

  // Phase 7.1-AD: legacy meta が "{}" や非 JSON な「空」状態だったら profile を作らない。
  // 過去に forgetClientIdentity 後の writeMeta({...null, ...undef}) 等で {} が
  // 残った user が「使えない空 profile を picker で見る」状態を防ぐ。
  let parsed = null;
  try { parsed = JSON.parse(legacyMeta); } catch { parsed = null; }
  const isUsable = parsed && typeof parsed === "object" &&
                   (parsed.appNameTag);
  if (!isUsable) {
    console.warn("[profiles] legacy meta found but empty/invalid — discarding, no profile created");
    localStorage.removeItem(LEGACY_META_KEY);
    _writeProfilesRaw([]);
    return;
  }

  const id = "default";
  const profile = {
    id,
    kind: "personal",
    label: null,  // 2026-07-12: 自動ラベルは null (表示は displayLabel が言語で構成)
    createdAt: new Date().toISOString(),
    lastUsedAt: new Date().toISOString(),
  };
  _writeProfilesRaw([profile]);
  localStorage.setItem(ACTIVE_KEY, id);
  localStorage.setItem(`${LEGACY_META_KEY}__${id}`, legacyMeta);
  localStorage.removeItem(LEGACY_META_KEY);
  console.log("[profiles] migrated legacy single-profile user → id=default");
}

export function listProfiles() {
  _migrateLegacyIfNeeded();
  const profiles = _readProfilesRaw() || [];
  return [...profiles].sort((a, b) => (b.lastUsedAt || "").localeCompare(a.lastUsedAt || ""));
}

export function getActiveProfileId() {
  _migrateLegacyIfNeeded();
  return localStorage.getItem(ACTIVE_KEY) || null;
}

export function setActiveProfileId(id) {
  _migrateLegacyIfNeeded();
  if (!id) {
    localStorage.removeItem(ACTIVE_KEY);
    return;
  }
  const profiles = _readProfilesRaw() || [];
  const p = profiles.find(x => x.id === id);
  if (!p) throw new Error(`profile ${id} not found`);
  p.lastUsedAt = new Date().toISOString();
  _writeProfilesRaw(profiles);
  localStorage.setItem(ACTIVE_KEY, id);
}

export function clearActiveProfile() {
  localStorage.removeItem(ACTIVE_KEY);
}

export function createProfile({ kind = "personal", companyId = null, label = null } = {}) {
  _migrateLegacyIfNeeded();
  const id = _newProfileId();
  const profiles = _readProfilesRaw() || [];
  const profile = {
    id,
    kind,
    companyId: companyId || undefined,
    // 2026-07-12: 自動ラベルは文字列を保存しない (null)。文字列を保存するのは
    //   ユーザーが明示的に命名した時だけ。表示は displayLabel() が現在の言語で構成する。
    label: label || null,
    createdAt: new Date().toISOString(),
    lastUsedAt: new Date().toISOString(),
  };
  profiles.push(profile);
  _writeProfilesRaw(profiles);
  return profile;
}

export function deleteProfile(id) {
  _migrateLegacyIfNeeded();
  let profiles = _readProfilesRaw() || [];
  profiles = profiles.filter(p => p.id !== id);
  _writeProfilesRaw(profiles);
  const suffix = `__${id}`;
  const allKeys = Object.keys(localStorage);
  for (const k of allKeys) {
    if (k.endsWith(suffix) || k.includes(`${suffix}.`)) localStorage.removeItem(k);
  }
  if (getActiveProfileId() === id) clearActiveProfile();
}

export function updateProfile(id, patch) {
  _migrateLegacyIfNeeded();
  const profiles = _readProfilesRaw() || [];
  const p = profiles.find(x => x.id === id);
  if (!p) return;
  Object.assign(p, patch);
  if (patch.kind || patch.companyId) {
    if (!patch.label) p.label = null;  // 2026-07-12: 自動ラベルは null 正本
  }
  p.lastUsedAt = new Date().toISOString();
  _writeProfilesRaw(profiles);
}

function _defaultLabel(kind, companyId) {
  if (kind === "personal") return "個人";
  if (kind === "admin" && companyId) return `会社 admin (${companyId.slice(0, 8)})`;
  if (kind === "admin") return "会社 admin";
  if (kind === "corp" && companyId) return `会社 (${companyId.slice(0, 8)})`;
  return "会社";
}

export function activeMetaKey() {
  const id = getActiveProfileId();
  if (!id) return null;
  return `${LEGACY_META_KEY}__${id}`;
}

export function activeEnvCacheKey() {
  const id = getActiveProfileId();
  if (!id) return null;
  return `arpass.envCache__${id}`;
}

export function activeRecCacheKeyPrefix() {
  const id = getActiveProfileId();
  if (!id) return null;
  return `arpass.recCache__${id}.`;
}


// ============================================================================
// Phase 7.1-AE: drive 識別子付き自動命名 + 重複 profile 統合
// ----------------------------------------------------------------------------
// 背景: createProfile は「アクティブが無ければ作る」だけで drive 重複検出が無く、
//   かつ既定ラベルが "個人"/"YubiKey" 固定だったため、同一 drive の行が複数でき
//   全部同名で見分けがつかない事故が起きた。以下で
//     (a) meta から安定識別子 (publicKeyHash) を取り出し見分けやすいラベルを自動付与
//     (b) 同一 drive(同 publicKeyHash) の重複行を 1 つに統合
//   を行う。localStorage のポインタ整理のみで Arweave / YubiKey には一切触れない。
// ============================================================================

function _metaOf(id) {
  try { return JSON.parse(localStorage.getItem(`${LEGACY_META_KEY}__${id}`) || "null"); }
  catch { return null; }
}

// drive を一意に識別する安定キー。publicKeyHash(=H(署名公開鍵)) は MEK 由来で
// drive ごとに一意なため最優先。未 unlock で未確定なら appNameTag / credentialId。
function _driveIdentity(meta) {
  if (!meta || typeof meta !== "object") return null;
  if (meta.publicKeyHash) return "pk:" + meta.publicKeyHash;
  const tag = (meta.appNameTag && meta.appNameTag.value) ||
              (meta.currentAppNameTag && meta.currentAppNameTag.value);
  if (tag) return "tag:" + tag;
  if (meta.credentialId) return "cred:" + meta.credentialId;
  return null;
}

// 自動生成ラベルか(=上書きしてよいか)。ユーザーが付けたカスタム名は保護する。
function _isAutoLabel(label, profile) {
  if (!label) return true;
  if (label === _defaultLabel(profile.kind, profile.companyId)) return true;
  if (/^(🔑\s)?.+(\s·\s[A-Za-z0-9_\-]{1,8}|\([A-Za-z0-9_\-]{1,8}\))$/.test(label)) return true; // 本関数が作る形式(旧·/新カッコ両対応)
  const generic = ["個人", "YubiKey", "YubiKey (Android)", "YubiKey (iOS)",
                   "復元中", "デフォルト", "会社", "会社 admin", "会社 (作成中)"];
  return generic.includes(label);
}

// 2026-07-12: 表示用ラベル。自動生成ラベル (個人/会社系) は保存値 (日本語=正本) を
//   書き換えずに、表示時だけ現在の言語で再構成する。ユーザーが手動で付けた名前は
//   そのまま返す。保存値を localize しないのは _isAutoLabel の判定を壊さないため。
export function displayLabel(p) {
  if (!p) return "";
  if (!_isAutoLabel(p.label, p)) return p.label;   // カスタム名は不変
  const meta = _metaOf(p.id) || {};
  const base = _localizedDefaultLabel(p.kind, p.companyId);
  const idRaw = _driveIdentity(meta);
  const marker = meta.mode === "hwkey" ? "🔑 " : "";
  if (!idRaw) return marker + base;
  return `${marker}${base}(${idRaw.split(":")[1].slice(0, 6)})`;
}

// t() は欠落時に「キー文字列そのもの」を返す仕様なので、キーが返ってきたら
// フォールバック (ja 正本) を使う。辞書ロード前・旧キャッシュの JSON でも安全。
function _trOr(key, fb) {
  const v = _i18nT(key);
  return (v && v !== key) ? v : fb;
}

function _localizedDefaultLabel(kind, companyId) {
  const frag = companyId ? ` (${companyId.slice(0, 8)})` : "";
  // コード内フォールバックは製品方針どおり英語 (保存正本の日本語とは別物)
  if (kind === "personal") return _trOr("app.profile.label_personal", "Personal");
  if (kind === "admin") return _trOr("app.profile.label_corp_admin", "Company admin") + frag;
  if (kind === "corp") return _trOr("app.profile.label_corp", "Company") + frag;
  return _trOr("app.profile.label_corp", "Company");
}

// 2026-07-12: _labelFromMeta (自動ラベル文字列をストレージへ書き戻す方式) は廃止。
//   表示は displayLabel() が毎回構成するため、ストレージには null を置くのが正本。

/** 全 profile のラベルを meta 由来で一括更新 (カスタム名は保護)。起動時に呼ぶと
 *  picker の全行が識別子付きで表示される (active 以外も改名されるように)。 */
export function relabelAllAuto() {
  // 2026-07-12: 役割変更 — 旧版は自動ラベル文字列 (日本語) を書き戻していたが、
  //   現在は「過去に保存された自動ラベル文字列を null へ正規化する」一回きりの
  //   マイグレーションとして機能する (起動時に呼ばれる)。カスタム名は不変。
  const profiles = _readProfilesRaw() || [];
  let changed = false;
  for (const p of profiles) {
    if (p.label != null && _isAutoLabel(p.label, p)) { p.label = null; changed = true; }
  }
  if (changed) {
    _writeProfilesRaw(profiles);
    console.log("[profiles] normalized legacy auto labels to null");
  }
}

/** active profile のラベルを meta 由来で更新 (カスタム名は保護、変化時のみ書込み)。 */
export function refreshActiveLabel() {
  const id = getActiveProfileId();
  if (!id) return;
  const profiles = _readProfilesRaw() || [];
  const p = profiles.find(x => x.id === id);
  if (!p) return;
  if (!_isAutoLabel(p.label, p)) return;          // ユーザー命名は触らない
  if (p.label != null) {                          // 2026-07-12: null 正本へ正規化のみ
    p.label = null;
    _writeProfilesRaw(profiles);                  // lastUsedAt は触らない(並び順維持)
  }
}

/**
 * 同一 drive(同 _driveIdentity) の重複 profile を 1 つに統合する。
 * keeper 選定: active > latestTxId あり > lastUsedAt 新しい。
 * keeper に欠けている fresh フィールドは dup から補完してから dup を削除。
 * 戻り値: 削除した profile 数。Arweave/YubiKey には影響しない(localStorage 整理のみ)。
 */
export function dedupeProfiles() {
  _migrateLegacyIfNeeded();
  const profiles = _readProfilesRaw() || [];
  const active = getActiveProfileId();
  const groups = new Map();
  for (const p of profiles) {
    const key = _driveIdentity(_metaOf(p.id));
    if (!key) continue;                            // 未確定 profile は対象外
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(p);
  }
  let removed = 0;
  for (const arr of groups.values()) {
    if (arr.length < 2) continue;
    arr.sort((a, b) => {
      if (a.id === active) return -1;
      if (b.id === active) return 1;
      const am = _metaOf(a.id), bm = _metaOf(b.id);
      const at = am && am.latestTxId ? 1 : 0, bt = bm && bm.latestTxId ? 1 : 0;
      if (at !== bt) return bt - at;
      return (b.lastUsedAt || "").localeCompare(a.lastUsedAt || "");
    });
    const keeper = arr[0];
    const km = _metaOf(keeper.id) || {};
    let kmChanged = false;
    // 同一 vault に「normal(=Master+Passkey で開く)」エントリが 1 つでもあれば、
    // survivor は normal を優先 — keeper が hwkey でも mode フラグを外し、
    // YubiKey 専用画面に固定されないようにする (Passkey/YubiKey どちらでも開ける)。
    const anyNormal = arr.some(p => { const m = _metaOf(p.id); return !(m && m.mode === "hwkey"); });
    if (anyNormal && km.mode === "hwkey") { delete km.mode; kmChanged = true; }
    for (let i = 1; i < arr.length; i++) {
      const dm = _metaOf(arr[i].id) || {};
      for (const f of ["credIdHash", "credentialId", "latestTxId", "currentAppNameTag",
                       "currentTierQualifier", "appNameTag", "publicKeyHash"]) {
        if (km[f] == null && dm[f] != null) { km[f] = dm[f]; kmChanged = true; }
      }
      deleteProfile(arr[i].id);                    // pointer + cache 削除のみ
      removed++;
    }
    if (kmChanged) localStorage.setItem(`${LEGACY_META_KEY}__${keeper.id}`, JSON.stringify(km));
  }
  if (removed) console.log(`[profiles] dedupeProfiles: merged ${removed} duplicate(s)`);
  return removed;
}
