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
    label: "デフォルト",
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
    label: label || _defaultLabel(kind, companyId),
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
    if (!patch.label) p.label = _defaultLabel(p.kind, p.companyId);
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
