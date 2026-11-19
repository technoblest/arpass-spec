// =====================================================================
// passkey-stores.js — パスキーの保管場所 (iCloud キーチェーン、 Google パスワードマネージャー、
//   Windows Hello、 1Password、 YubiKey など) を「登録されている端末」の一覧に出すための部品。
//
// 2026-11-17 (八巻さんの希望): 登録のとき、 作成応答の authenticatorData から AAGUID (16 byte、
//   保管場所の種類を表す番号) を読み、 vault.credentials の行の store に入れる。 行は暗号化された
//   本体の中なので、 サーバーには出ない。 AAGUID は attestation "none" のままで読む (証明書は
//   求めない)。 全部 0 で返す環境もあるので、 その時は登録した環境 (OS・ブラウザ・アプリ) と
//   authenticatorAttachment / transports で代わりの説明を出す。 前からある行 (store なし) は
//   「不明（以前の登録）」。
//
// store の形 (どれも省略あり):
//   { aaguid: "fbfc3007-154e-…" (全部 0 もそのまま残す), attachment: "platform" | "cross-platform",
//     transports: ["internal", "hybrid", …], os: "Mac", browser: "Chrome", app: "ios" | "android" }
// =====================================================================

// 名前が "@" で始まるものは i18n キー app.pk_store.p_<名前> を使う (言語ごとに呼び名が違うもの)。
const AAGUID_GROUPS = {
  // passkeydeveloper/passkey-authenticator-aaguids の aaguid.json (2026-11-17 取得)
  "TeamPass": ["7c30bceff0354e2191755c985b4b239c"],
  "Monica Pass": ["6d6f6e6963614d33a001706173736b79"],
  "AliasVault": ["a11a5faa9f324b8c8c5d2f7d13e8c942"],
  "@google": ["ea9b8d664d011d213ce4b6b48cb575d4"],
  "@chrome_mac": ["adce000235bcc60a648b0b25f1f05503"],
  "Windows Hello": ["08987058cadc4b81b6e130de50dcbe96", "9ddd1817af5a4672a2b93e3dd95000a9", "6028b017b1d44c02b4b3afcdafc96bb2"],
  "@apple_managed": ["dd4ec289e01d41c9bb8970fa845d4bf2"],
  "Dashlane": ["531126d6e717415c93203d9aa6981239"],
  "1Password": ["bada5566a7aa401fbd9645619a55120d"],
  "NordPass": ["b84e404815dc4dd08640f4f60813c8af"],
  "Keeper": ["0ea242b443c44a1b8b17dd6d0b6baec6"],
  "Sésame": ["891494da2c904d31a9cd4eab0aed1309"],
  "Enpass": ["f38095407f1449c1a8b38f813b225541"],
  "Chromium Browser": ["b53976664885aa6bcebfe52262a439a2"],
  "@edge_mac": ["771b48fdd3d44f749232fc157ab0507a"],
  "IDmelon": ["39a5647e1853446ca1f6a79bae9f5bc7"],
  "Bitwarden": ["d548826e79b4db40a3d811116f7e8349"],
  "@apple": ["fbfc3007154e4ecc8c0b6e020557d7bd"],
  "Samsung Pass": ["53414d53554e47000000000000000000"],
  "Thales Bio iOS SDK": ["66a0ccb3bd6a191fee06e375c50b9846"],
  "Thales Bio Android SDK": ["8836336af5900921301d46427531eee6"],
  "Thales PIN Android SDK": ["cd69adb53c7adeb931776800ea6cb72a"],
  "Thales PIN iOS SDK": ["17290f1ec21234d01423365d729f09d9"],
  "Proton Pass": ["50726f746f6e5061737350726f746f6e"],
  "KeePassXC": ["fdb141b25d84443e8a354698c205a502"],
  "KeePassDX": ["eaecdef21c3156348639f1cbd9c00a08"],
  "KeePassPasskey": ["9addb28cb46f4402808f019651441ff3"],
  "ToothPic Passkey Provider": ["cc45f64e52a2451b831a4edd8022a202"],
  "iPasswords": ["bfc748bb34294faab9f97cfa9f3b76d0"],
  "Zoho Vault": ["b35a26b28f6e4697ab1dd44db4da28c6"],
  "LastPass": ["b78a0a556ef8d246a042ba0f6d55050c"],
  "Devolutions": ["de503f9c21a44f76b4b7558eb55c6f89"],
  "LogMeOnce": ["22248c4c7a1246e29a4144291b373a4d"],
  "Kaspersky Password Manager": ["a10c6dd9465e42268198c7c44b91c555"],
  "pwSafe": ["d350af5203514ba2acd3dfeeadc3f764"],
  "Microsoft Password Manager": ["d345266801fd4c12926c83a4204853aa"],
  "initial": ["6d212b28a2c14638b3755932070f62e9"],
  "Heimlane Vault": ["d49b2120b86541918ceabe84a52b0485"],
  "Share Credentials": ["93fea28e9b0841d0b66320c36b008e70"],
  "Sherlocked": ["e8b7f4a2c3d5e6f7890ab1c2d3e4f567"],
  "Sticky Password Manager": ["d9be9d39e6a64c28a58132b044d986e4"],
  "Passwall": ["7061737377616c6c6669646f32303236"],
  "Burp Suite Navigation Recorder": ["c9cadfc989a9489ea25ac7e86a4d5f15"],
  "Norton Password Manager": ["fa37f553f9b64adbac538bbb57ebdf0d"],
  "Avast Password Manager": ["a4a2d88e979643569164e2a5a8bd019c"],
  "Avira Password Manager": ["e7db2bd3f2fe4d71ad787e7aa166cfd1"],
  "AVG Password Manager": ["6bb49926160a4306a1004eb39ba6ac45"],
  "Hey Be Safe": ["da583154ce164cdf9fe61dba788c0998"],
  "Fenko Vault": ["d2717a32985148a89961b264c97a411a"],
  "Royal Vault": ["65c97700f5ef4d5c8a42f30e45ac94b7"],
  "Parcel": ["5ca471bba56d46ada49667e70e9ed9fb"],
  "Uniqkey": ["45e3057eb2f948ed912f9b901e153b16"],
  "PassCard": ["87f5ec51f7214feb9fe4be18c4971894"],
  "WALLIX Vault": ["477b05cd7f784fe7b62927247f296138"],
  "Password Depot": ["53e7a7a5e75f4d3d948312fc779cdf23"],
  "iPass Secure Auth": ["cb6f666638ea48739161ff456a82d316"],
  "Idira": ["9c1f2b6e4d3a4f7c8b215e6a7d8c9f01"],
  "U2 Secured": ["9f8a3b2c1d4e4f6a8b0c2e1d3c4b5a69"],
  "Keyholm": ["69840def9dcf4632bf876ac2e451b4f5"],
  "CyberFOX Password Manager": ["35d5ea15ab244416bdd1f204c9bce1b6"],
  "fidont": ["f1d0badc0def4f1d8badc0def1d0badc"],
  "Authn8": ["c4ed941c86d34532a6a9bc42b80d5c38"],
  "Fobb Security": ["441f5bada8ec45728094ee73a1c7cec7"],
  "Pleasant Password Server": ["16a5a15d72444563856da5167d8b9783"],
  "Cyclop Passkey": ["7c596f1a3e424b8d9a0f5d2ce1b84493"],
  // FIDO Alliance MDS3 の Yubico 製品 (2026-11-17 取得)
  "Security Key NFC by Yubico": ["b7d3f68e88a6471e9ecf2df26d041ede", "a4e9fc6d4cbe4758b8ba37598bb5bbaa", "e77e3c6405e3428b88240cbeb04b829d", "760eda3600aa4d29855b4012a182cdeb"],
  "Security Key NFC by Yubico Enterprise Edition": ["47ab2fb466ac41849ae186be814012d5", "ed042a3a4b224455bb69a267b652ae7e", "0bb43545fd2c418587ddfeb0b2916ace", "9ff4cc6561544fffba099e2af7882ad2", "72c6b72d85124c6683599d3d10d9222f", "2772ce93eb4b40908b73330f48477d73"],
  "Security Key by Yubico": ["f8a011f38c0a4d15800617111f9edc7d", "b92c3f9ac0144056887f140a2501163b"],
  "Security Key by Yubico with NFC": ["149a20218ef6413396b881f8d5b7f1f5", "6d44ba9bf6ec2e49b9300c8fe920cb73"],
  "YubiKey 5 CCN Series with NFC": ["3aa78eb1ddd846a8a8218f8ec57a7bd5", "eb7ef748cbe04b40b8f607bd2d592d35", "3ec9c8d3a5a7415ba7b5f1d606368d3f", "4fc84f1625454e53b8fc7bf4d7282a10"],
  "YubiKey 5 FIPS Series": ["73bb0cd4e50249b89c6fb59445bf720b", "57f7de54c8074eabb1c61c9be7984e92", "905b4cb4ed6f4da992fc45e0d4e9b5c7", "d2fbd093ee62488d9dad1e36389f8826"],
  "YubiKey 5 FIPS Series with Lightning": ["8520342148f943559bc88a53846e5083", "7b96457de3cd432b9cebc9fdd7ef7432", "3a662962c6d44023bebb98ae92e78e20", "9e66c661e428452aa8fb51f7ed088acf", "5b0e46badb0244acb979ca9b84f5e335"],
  "YubiKey 5 FIPS Series with NFC": ["fcc0118fcd45435b8da19782b2da0715", "c1f9a0bc1dd2404ab27f8e29047a43fd", "79f3c8ba9e35484b8f4753a5a0f5c630", "ce6bf97f9f694ba7903297adc6ca5cf1", "62e54e98c2094df3b692de71bb6a8528"],
  "YubiKey 5 Series": ["19083c3d83834b18bc038f1c9ab2fd1b", "cb69481e8ff7403993ec0a2729a154a8", "ee882879721c491397753dfcce97072a", "ff4dac45ede84ec2acedcf66103f4335", "0a3571579b184c8a920ed156e972b2f8", "4599062e69264fe795669e8fb1aedaa0", "524de2de982f49b4a7692b5e3b73ad79", "20ac7a17c814483393fe539f0d5e3389"],
  "YubiKey 5 Series with Lightning": ["c5ef55ffad9a4b9fb580adebafe026d0", "a02167b9ae714ac79a0706432ebb6f1c", "246731496c8642e798d9433fb5b73296", "03012cb74fb242e79e8da81f10e2a5e9", "b90e7dc1316e4feea25a56a666a670fe", "3b24bf491d454484a91713175df0867b", "c3479970e58a4f70836f853bf42fb063", "3124e301f14e4e38876dfbeeb090e7bf"],
  "YubiKey 5 Series with NFC": ["fa2b99dc9e3942578f924a30d23c4118", "2fc0579f811347eab116bb5a8db9202a", "d7781e5de35346aaafe23ca49f13332a", "a25342c03cdc44148e46f4807fca511c", "f4ce5fc057d346f5a736efb7d5bc63b5", "7dab85a5d16d4eafa7ef4c1385b151c5", "41e39911c6694811b860c6ad0b411b96", "1ac71f64468d4fe0bef10e5f2f551f18", "6ab56fad881f4a43acb20be065924522", "9eb7eabc9db549a1b6c3555a802093f4", "34f5766d15364a2490330e294e510fb0"],
  "YubiKey 5 Series with NFC Enhanced PIN": ["662ef48a95e24aaaa6c15b9c40375824", "b2c1a50bdad84dc7ba4d0ce9597904bc", "0ebd9f2cf685441c8c3ea02a234a840a", "9a3f2abda73d439c9ee71b53a857eaa7"],
  "YubiKey Bio Series FIDO Edition": ["9dd8d5932213438a97f8d6b813d51c27", "add924330d694026816629b25bce64e9", "d8522d9f575b486688a9ba99fa02f35b", "dd86a2da86a04cbeb4624bd31f57bc6f", "7409272d1ff94e109fc9ac0019c124fd", "ad08c78a4e4149b986a2ac15b06899e2", "8c39ee867f9a4a959ba3f6b097e5c2ee", "83c47309aabb410884708be838b573cb"],
  "YubiKey Bio Series Multi-protocol Edition": ["ba0a926640d840489786d710b5474752", "9806a2c8c0da478eb4ca620005d34182", "dc5e949df93943b39877a85c7186b753", "90636e1fef8243bfbdcf5255f139d12f", "347449134f574e6ea527e9ec3c4b94e6", "7d1351a6e0974852b8bfc9ac5c9ce4a3", "6ec5cff2a0f94169945bf33b563f7b99", "97e6a830c952474095fc7c78dc97ce47", "58276709bb4b4bb3baf160eea99282a7"],
};

const _NAME_BY_AAGUID = new Map();
for (const [name, ids] of Object.entries(AAGUID_GROUPS)) for (const id of ids) _NAME_BY_AAGUID.set(id, name);

const ZERO_AAGUID = "00000000-0000-0000-0000-000000000000";

function _hex(b) { return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join(""); }

// authenticatorData → AAGUID ("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")。 attested credential data
//   (flags の bit 6) が無い・短いときは null。 全部 0 のときは ZERO_AAGUID をそのまま返す。
export function aaguidFromAuthData(ad) {
  if (!(ad instanceof Uint8Array) || ad.length < 55) return null;
  if (!(ad[32] & 0x40)) return null;
  const h = _hex(ad.subarray(37, 53));
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

// attestationObject (CBOR の map) から authData の byte 列を取り出す。 getAuthenticatorData() が
//   無いブラウザ向け。 読めなければ null。 map / array / bytes / text / 整数 / 単純値だけを読む。
export function authDataFromAttestationObject(bytes) {
  if (!(bytes instanceof Uint8Array)) return null;
  let p = 0;
  const need = (n) => { if (p + n > bytes.length) throw new Error("cbor: short"); };
  const readLen = (info) => {
    if (info < 24) return info;
    const n = info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : info === 27 ? 8 : -1;
    if (n < 0) throw new Error("cbor: indefinite");
    need(n);
    let v = 0;
    for (let i = 0; i < n; i++) v = v * 256 + bytes[p++];
    return v;
  };
  const item = (depth) => {
    if (depth > 8) throw new Error("cbor: deep");
    need(1);
    const b = bytes[p++], major = b >> 5, info = b & 31;
    if (major === 7) { if (info >= 24) readLen(info); return null; }
    const len = readLen(info);
    if (major === 0) return len;
    if (major === 1) return -1 - len;
    if (major === 2 || major === 3) {
      need(len);
      const s = bytes.subarray(p, p + len); p += len;
      return major === 2 ? s : new TextDecoder().decode(s);
    }
    if (major === 4) { const a = []; for (let i = 0; i < len; i++) a.push(item(depth + 1)); return a; }
    if (major === 5) {
      const m = new Map();
      for (let i = 0; i < len; i++) { const k = item(depth + 1); m.set(k, item(depth + 1)); }
      return m;
    }
    if (major === 6) return item(depth + 1);   // tag は中身だけ
    throw new Error("cbor: type");
  };
  try {
    const top = item(0);
    const ad = top instanceof Map ? top.get("authData") : null;
    return ad instanceof Uint8Array ? new Uint8Array(ad) : null;
  } catch (_) {
    return null;
  }
}

// 登録した環境 (どの OS の、 どのブラウザ / Arpass アプリで作ったか)。 navigator.userAgent と
//   アプリの印 (iOS: webkit.messageHandlers、 Android: TWA の referrer) から読む。
export function registrationEnv(g = globalThis) {
  const nav = g?.navigator || {};
  const ua = String(nav.userAgent || "");
  const plat = String(nav.platform || "");
  let os = null;
  if (/iPhone/i.test(ua) || /iPhone/i.test(plat)) os = "iPhone";
  else if (/iPad/i.test(ua) || /iPad/i.test(plat) || (/Mac/i.test(plat) && (nav.maxTouchPoints || 0) > 1)) os = "iPad";
  else if (/Android/i.test(ua)) os = "Android";
  else if (/Mac/i.test(plat) || /Macintosh/.test(ua)) os = "Mac";
  else if (/Win/i.test(plat) || /Windows/.test(ua)) os = "Windows";
  else if (/CrOS/.test(ua)) os = "ChromeOS";
  else if (/Linux/i.test(plat) || /Linux/.test(ua)) os = "Linux";
  let app = null;
  try {
    const mh = g?.webkit?.messageHandlers;
    if (mh && (mh.arpassPurchase || mh.arpassHwkey || mh.arpassAutofill)) app = "ios";
  } catch (_) {}
  if (!app) {
    try { if (String(g?.document?.referrer || "").startsWith("android-app://io.arpass.twa")) app = "android"; } catch (_) {}
  }
  let browser = null;
  if (!app) {
    if (/EdgA?\/|EdgiOS\/|Edg\//.test(ua)) browser = "Edge";
    else if (/OPR\/|OPiOS\//.test(ua)) browser = "Opera";
    else if (/SamsungBrowser\//.test(ua)) browser = "Samsung Internet";
    else if (/Firefox\/|FxiOS\//.test(ua)) browser = "Firefox";
    else if (/CriOS\/|Chrome\//.test(ua)) browser = "Chrome";
    else if (/Safari\//.test(ua)) browser = "Safari";
  }
  const out = {};
  if (os) out.os = os;
  if (browser) out.browser = browser;
  if (app) out.app = app;
  return out;
}

const _TRANSPORTS = new Set(["usb", "nfc", "ble", "smart-card", "hybrid", "internal"]);

// navigator.credentials.create() の結果から、 行に入れる store を作る。 秘密は含まない
//   (AAGUID は保管場所の機種の番号、 attachment / transports はブラウザが出す種別)。
export function passkeyStoreInfo(cred, env = null) {
  const out = {};
  let ad = null;
  try {
    if (typeof cred?.response?.getAuthenticatorData === "function") ad = new Uint8Array(cred.response.getAuthenticatorData());
  } catch (_) { ad = null; }
  if (!ad || ad.length < 55) {
    try {
      const ao = cred?.response?.attestationObject;
      if (ao) ad = authDataFromAttestationObject(new Uint8Array(ao));
    } catch (_) {}
  }
  const aaguid = ad ? aaguidFromAuthData(ad) : null;
  if (aaguid) out.aaguid = aaguid;
  const att = cred?.authenticatorAttachment;
  if (att === "platform" || att === "cross-platform") out.attachment = att;
  let tr = [];
  try { if (typeof cred?.response?.getTransports === "function") tr = cred.response.getTransports(); } catch (_) { tr = []; }
  if (Array.isArray(tr)) {
    const t = tr.filter((x) => _TRANSPORTS.has(x));
    if (t.length) out.transports = t;
  }
  if (env && typeof env === "object") {
    if (typeof env.os === "string") out.os = env.os;
    if (typeof env.browser === "string") out.browser = env.browser;
    if (env.app === "ios" || env.app === "android") out.app = env.app;
  }
  return out;
}

// 既知の AAGUID → 表示名。 知らない・全部 0 のときは null。
export function passkeyProviderName(aaguid, t) {
  if (typeof aaguid !== "string" || aaguid === ZERO_AAGUID) return null;
  const name = _NAME_BY_AAGUID.get(aaguid.toLowerCase().replace(/-/g, ""));
  if (!name) return null;
  return name.startsWith("@") ? t("app.pk_store.p_" + name.slice(1)) : name;
}

function _envLabel(s, t) {
  const os = typeof s.os === "string" ? s.os : null;
  if (s.app === "ios" || s.app === "android") {
    return t("app.pk_store.env_app", { os: os || (s.app === "ios" ? "iPhone" : "Android") });
  }
  const br = typeof s.browser === "string" ? s.browser : null;
  if (os && br) return t("app.pk_store.env_browser", { os, browser: br });
  return os || br || null;
}

// 一覧の 1 行に出す保管場所の説明 (「保管場所: 」は付けない)。
//   t(key, vars) は i18n_t。 store が無い行 (この機能の前に登録) は「不明（以前の登録）」。
export function describePasskeyStore(row, t) {
  const s = row && typeof row.store === "object" && row.store ? row.store : null;
  if (!s) return t("app.pk_store.unknown_old");
  let name = passkeyProviderName(s.aaguid, t);
  if (!name) {
    const tr = Array.isArray(s.transports) ? s.transports : [];
    const keyLike = tr.some((x) => x === "usb" || x === "nfc" || x === "ble" || x === "smart-card");
    if (s.attachment === "cross-platform" || (!s.attachment && keyLike && !tr.includes("internal"))) {
      name = !keyLike && tr.includes("hybrid") ? t("app.pk_store.kind_phone") : t("app.pk_store.kind_security_key");
    } else if (s.attachment === "platform") {
      name = t("app.pk_store.kind_builtin");
    } else {
      name = t("app.pk_store.unknown");
    }
  }
  const env = _envLabel(s, t);
  return env ? t("app.pk_store.with_env", { store: name, env }) : name;
}

export const _internals = { AAGUID_GROUPS, ZERO_AAGUID };
