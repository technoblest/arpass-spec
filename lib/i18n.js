// ============================================================================
// web/lib/i18n.js
//
// Arpass 多言語化レイヤ（v1）
//
// - 16 言語サポート（ja を原本、en を翻訳ハブ、残り14言語は機械翻訳＋人間レビュー）
// - 法的ローカライズはしない（準拠法 = 日本法 / 提供地 = 日本）
// - 翻訳辞書は /i18n/{lang}.json から fetch（キャッシュ + ETag 任せ）
// - DOM 適用: data-i18n / data-i18n-html / data-i18n-placeholder / data-i18n-title
// - 言語切替時は localStorage に保存し、Stripe Checkout の locale にも引き継ぐ
// - RTL 言語（ar）対応: html[dir="rtl"] を切り替え
// - 未定義キー: en 辞書にフォールバック → それでも無ければキー文字列をそのまま返却
// ============================================================================

// ---------------------------------------------------------------------------
// 価格表示の通貨設定
// ---------------------------------------------------------------------------
//
// 設計方針 (Plan A):
//   - 課金は常に JPY (Stripe checkout で currency: "jpy")。Stripe Connect /
//     海外子会社不要。日本企業として一貫。
//   - 日本語表示は ¥XXX (native)。
//   - 非日本語表示は USD 概算 ($X.XX) + 「Billed in JPY」disclaimer。
//   - 1 つの言語につき 1 通貨で固定 (例: フランス語 = USD 表示、EUR ではない)。
//     これは "global English standard" 方針で、ターゲット市場が広いため
//     EUR/GBP/CNY... と無限に分岐させるよりシンプル。USD はどの国の利用者
//     も「だいたいの値段感」として認識できる。
//   - 為替レートは固定値で年 1〜2 回見直し。年間の実換算とのズレは Stripe
//     側のカード会社レートで吸収される。
//
// レート更新時の注意: 全言語ファイルに散らばっていないので、ここ 1 箇所
// だけ書き換えれば全表示に反映される。
//
// 2026-Q2 時点のレート: 1 USD ≈ 150 JPY
const JPY_PER_USD = 150;

// JPY 値を表示用通貨にフォーマット。
//   formatPrice(300)            → "$2"   (現言語が ja 以外)
//   formatPrice(300, "ja")      → "¥300"
//   formatPrice(2, "en")        → "$0.02"
//   formatPrice(15000, "en")    → "$100"
//   formatPrice(5000, "en", { suffix: "+" })  → "$33+"
//
// 丸め方針: 1 ドル未満は ceil to cents（過小表示を避け、ユーザーが「思ったより
// 高かった」とならないように切上）。1 ドル以上は近似（display は必ず近似値）。
export function formatPrice(jpyAmount, lang, opts = {}) {
  const targetLang = lang || _lang;
  const suffix = opts.suffix || "";
  if (targetLang === "ja") {
    return "¥" + Math.round(jpyAmount).toLocaleString("ja-JP") + suffix;
  }
  // 非日本語 = USD 概算
  const usd = jpyAmount / JPY_PER_USD;
  let formatted;
  if (usd < 1) {
    // セント単位、過小表示を避けるため切上 (¥2 = $0.0133 → $0.02 表示)
    formatted = "$" + (Math.ceil(usd * 100) / 100).toFixed(2);
  } else {
    formatted = "$" + Math.round(usd).toLocaleString("en-US");
  }
  return formatted + suffix;
}

// 各言語のメタ情報（picker 表示用、RTL 判定用、Stripe locale マッピング用）
//
// `stripeLocale` は Stripe Checkout Session の `locale` に渡せる値。
// Stripe の対応言語: https://docs.stripe.com/payments/checkout/customization/appearance#supported-languages
// 対応外の言語は `auto` にフォールバック（Stripe 側で User-Agent から推定）。
export const LANGUAGES = {
  ja:      { label: "日本語",         native: "日本語",          dir: "ltr", stripeLocale: "ja", stripeCurrency: "jpy" },
  en:      { label: "English",         native: "English",         dir: "ltr", stripeLocale: "en", stripeCurrency: "usd" },
  "zh-CN": { label: "简体中文",        native: "简体中文",        dir: "ltr", stripeLocale: "zh", stripeCurrency: "usd" },
  "zh-TW": { label: "繁體中文",        native: "繁體中文",        dir: "ltr", stripeLocale: "zh-TW", stripeCurrency: "usd" },
  ko:      { label: "한국어",          native: "한국어",          dir: "ltr", stripeLocale: "ko", stripeCurrency: "usd" },
  es:      { label: "Español",         native: "Español",         dir: "ltr", stripeLocale: "es", stripeCurrency: "usd" },
  "pt-BR": { label: "Português (BR)",  native: "Português (BR)",  dir: "ltr", stripeLocale: "pt-BR", stripeCurrency: "usd" },
  de:      { label: "Deutsch",         native: "Deutsch",         dir: "ltr", stripeLocale: "de", stripeCurrency: "usd" },
  fr:      { label: "Français",        native: "Français",        dir: "ltr", stripeLocale: "fr", stripeCurrency: "usd" },
  it:      { label: "Italiano",        native: "Italiano",        dir: "ltr", stripeLocale: "it", stripeCurrency: "usd" },
  ru:      { label: "Русский",         native: "Русский",         dir: "ltr", stripeLocale: "ru", stripeCurrency: "usd" },
  id:      { label: "Bahasa Indonesia", native: "Bahasa Indonesia", dir: "ltr", stripeLocale: "id", stripeCurrency: "usd" },
  vi:      { label: "Tiếng Việt",      native: "Tiếng Việt",      dir: "ltr", stripeLocale: "vi", stripeCurrency: "usd" },
  hi:      { label: "हिन्दी",            native: "हिन्दी",            dir: "ltr", stripeLocale: "auto", stripeCurrency: "usd" }, // Stripe locale 未対応
  ar:      { label: "العربية",          native: "العربية",          dir: "rtl", stripeLocale: "auto", stripeCurrency: "usd" }, // Stripe locale 未対応
  tr:      { label: "Türkçe",          native: "Türkçe",          dir: "ltr", stripeLocale: "tr", stripeCurrency: "usd" },
};

export const SUPPORTED = Object.keys(LANGUAGES);
export const FALLBACK = "en";
export const DEFAULT = "ja"; // 原本

const LS_KEY = "arpass.lang.v1";
const I18N_BASE = "/i18n";

// ---------------------------------------------------------------------------
// 内部状態
// ---------------------------------------------------------------------------

let _dict = {};       // 現在ロード中の辞書 (lang → flat key/value)
let _fallbackDict = {}; // FALLBACK (en) の辞書、欠損キー補完用
let _lang = DEFAULT;
let _ready = false;
const _listeners = new Set();

// ---------------------------------------------------------------------------
// 言語検出
// ---------------------------------------------------------------------------

/**
 * navigator.languages を順に走査して、SUPPORTED 内で最初にマッチするものを返す。
 * 完全一致 → 言語サブタグ（例: "en-US" → "en"）の順で照合。
 * 何もマッチしなければ null。
 */
function _detectFromBrowser() {
  const prefs = (navigator.languages && navigator.languages.length)
    ? navigator.languages
    : [navigator.language || ""];

  for (const raw of prefs) {
    if (!raw) continue;
    // 完全一致 (例: "zh-TW")
    if (SUPPORTED.includes(raw)) return raw;
    // 大小文字違いを正規化 (例: "zh-tw" → "zh-TW")
    const normalized = SUPPORTED.find(s => s.toLowerCase() === raw.toLowerCase());
    if (normalized) return normalized;
    // ベース言語マッチ (例: "en-GB" → "en")
    const base = raw.split("-")[0].toLowerCase();
    if (base === "zh") {
      // 中国語は地域でデフォルト分岐
      if (raw.toLowerCase().includes("tw") || raw.toLowerCase().includes("hk")) return "zh-TW";
      return "zh-CN";
    }
    if (base === "pt") return "pt-BR"; // Portugal も BR にフォールバック
    const baseMatch = SUPPORTED.find(s => s === base);
    if (baseMatch) return baseMatch;
  }
  return null;
}

/**
 * 採用すべき言語を決定:
 *   1. URL path prefix (/en/, /zh-CN/, /tr/ 等) — 静的化された per-language ページ
 *   2. ?lang= クエリパラメータ
 *   3. localStorage に保存済みのユーザー選択
 *   4. ブラウザ言語からの自動検出
 *   5. DEFAULT (ja)
 *
 * #1 は Phase 7.5ZH で追加: /tr/help.html のような静的版に訪れたとき、
 * localStorage の言語より URL の言語を優先する (= URL と表示の整合)。
 * ただし localStorage には書き込まない (= root / に戻ったときの user 設定保存)。
 * 結果として: URL-driven nav は URL 言語、 picker での切替は localStorage に従う。
 */
function _resolveInitialLang() {
  // 1. URL path prefix を最優先
  try {
    const m = window.location.pathname.match(/^\/([a-z]{2}(?:-[A-Z]{2})?)\//);
    if (m && SUPPORTED.includes(m[1])) return m[1];
  } catch (_) {}

  // 2. ?lang= クエリ
  try {
    const url = new URL(window.location.href);
    const q = url.searchParams.get("lang");
    if (q && SUPPORTED.includes(q)) return q;
  } catch (_) {}

  // 3. localStorage
  try {
    const stored = localStorage.getItem(LS_KEY);
    if (stored && SUPPORTED.includes(stored)) return stored;
  } catch (_) {}

  // 4. ブラウザ
  const detected = _detectFromBrowser();
  if (detected) return detected;

  // 5. デフォルト
  return DEFAULT;
}

/**
 * 現在の URL が /xx/ または /xx-XX/ prefix 配下かどうか。
 * (= 静的化 per-language ページにいる場合 true)
 */
function _isOnLangPrefixedPage() {
  try {
    const m = window.location.pathname.match(/^\/([a-z]{2}(?:-[A-Z]{2})?)\//);
    return !!(m && SUPPORTED.includes(m[1]));
  } catch (_) {
    return false;
  }
}

/**
 * 同じページ (= ファイル名) を別言語ディレクトリで構築。
 * /tr/help.html, en → /en/help.html
 * /help.html, en    → /en/help.html
 * /index.html, ja   → /index.html (default は prefix なし)
 */
function _buildLangPrefixedUrl(targetLang) {
  try {
    const path = window.location.pathname;
    // 現在の path から最後の segment (= ファイル名 or "")
    let basename = path.replace(/^\/([a-z]{2}(?:-[A-Z]{2})?)\//, "/");
    if (basename === "/" || basename === "") basename = "/index.html";
    if (targetLang === DEFAULT) return basename;  // ja は root
    return `/${targetLang}${basename}`;
  } catch (_) {
    return null;
  }
}

// ---------------------------------------------------------------------------
// 辞書読み込み
// ---------------------------------------------------------------------------

const _dictCache = new Map();

async function _loadDict(lang) {
  if (_dictCache.has(lang)) return _dictCache.get(lang);
  const url = `${I18N_BASE}/${lang}.json`;
  try {
    // 2026-07-12: "default" だと端末によっては deploy 後も古い辞書を使い続け、
    //   新キーが key-echo → 英語フォールバック表示になる (実機で発生)。
    //   "no-cache" は ETag 再検証付き (= 変更なしなら 304 で軽い)。
    const res = await fetch(url, { cache: "no-cache" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const json = await res.json();
    _dictCache.set(lang, json);
    return json;
  } catch (e) {
    console.warn(`[i18n] failed to load ${url}:`, e);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * 初期化 - DOMContentLoaded 後に呼ぶ。
 * 自動で初期言語を解決し、辞書をロードして DOM に適用する。
 */
export async function initI18n() {
  const initial = _resolveInitialLang();
  // FALLBACK 辞書 (en) を先にロード → 欠損キー埋め用
  if (FALLBACK !== initial) {
    _fallbackDict = (await _loadDict(FALLBACK)) || {};
  }
  await setLang(initial, { skipPersist: true });
  _ready = true;
}

/**
 * 言語を切り替える。辞書をロード → DOM 全体に適用 → リスナ通知。
 * @param {string} lang
 * @param {{ skipPersist?: boolean }} opts
 */
export async function setLang(lang, opts = {}) {
  if (!SUPPORTED.includes(lang)) lang = FALLBACK;

  const dict = await _loadDict(lang);
  if (!dict) {
    console.warn(`[i18n] dict missing for ${lang}, falling back to ${FALLBACK}`);
    lang = FALLBACK;
    _dict = _fallbackDict;
  } else {
    _dict = dict;
  }
  _lang = lang;

  // FALLBACK 辞書を後追いで読む（初期化時にスキップしていた場合）
  if (lang !== FALLBACK && Object.keys(_fallbackDict).length === 0) {
    _fallbackDict = (await _loadDict(FALLBACK)) || {};
  }

  // <html> 属性更新
  document.documentElement.lang = lang;
  document.documentElement.dir = LANGUAGES[lang]?.dir || "ltr";

  // 永続化
  if (!opts.skipPersist) {
    try { localStorage.setItem(LS_KEY, lang); } catch (_) {}
  }

  applyTranslations();

  // リスナ通知
  for (const fn of _listeners) {
    try { fn(lang); } catch (e) { console.warn("[i18n] listener error:", e); }
  }
}

/**
 * 現在の言語コードを返す。
 */
export function getLang() {
  return _lang;
}

/**
 * 現在の Stripe locale を返す。Checkout Session 作成時に渡す。
 */
export function getStripeLocale() {
  return LANGUAGES[_lang]?.stripeLocale || "auto";
}


/**
 * 現在の言語の Stripe 決済通貨コードを返す。
 * ja → "jpy", それ以外 → "usd" を想定。
 * checkoutSessionUI({ currency }) に渡す。
 */
export function getStripeCurrency() {
  const e = LANGUAGES[_lang];
  return e?.stripeCurrency || "jpy";
}

/**
 * キーから翻訳文字列を取得。{name} の placeholder を vars で展開。
 * 欠損時は en にフォールバック → それでもなければキーをそのまま返す（開発時に気付けるよう）。
 */
export function t(key, vars) {
  let s = _dict?.[key];
  if (s == null) s = _fallbackDict?.[key];
  if (s == null) s = key;
  if (vars && typeof s === "string") {
    for (const [k, v] of Object.entries(vars)) {
      s = s.replaceAll(`{${k}}`, String(v));
    }
  }
  return s;
}

/**
 * 言語変更を購読する。返り値は unsubscribe 関数。
 */
export function onLangChange(fn) {
  _listeners.add(fn);
  return () => _listeners.delete(fn);
}

/**
 * DOM 全体に翻訳を適用する。
 * - data-i18n="key"             → textContent
 * - data-i18n-html="key"        → innerHTML（HTML を含む文字列用、要 trust）
 * - data-i18n-placeholder="key" → input/textarea の placeholder
 * - data-i18n-title="key"       → title 属性
 * - data-i18n-aria-label="key"  → aria-label 属性
 */
export function applyTranslations(root) {
  const scope = root || document;
  scope.querySelectorAll("[data-i18n]").forEach(el => {
    const key = el.getAttribute("data-i18n");
    if (key) el.textContent = t(key);
  });
  scope.querySelectorAll("[data-i18n-html]").forEach(el => {
    const key = el.getAttribute("data-i18n-html");
    if (key) el.innerHTML = t(key);
  });
  scope.querySelectorAll("[data-i18n-placeholder]").forEach(el => {
    const key = el.getAttribute("data-i18n-placeholder");
    if (key) el.setAttribute("placeholder", t(key));
  });
  scope.querySelectorAll("[data-i18n-title]").forEach(el => {
    const key = el.getAttribute("data-i18n-title");
    if (key) el.setAttribute("title", t(key));
  });
  scope.querySelectorAll("[data-i18n-aria-label]").forEach(el => {
    const key = el.getAttribute("data-i18n-aria-label");
    if (key) el.setAttribute("aria-label", t(key));
  });
  // ページタイトル
  const titleEl = document.querySelector("title[data-i18n]");
  if (titleEl) {
    document.title = t(titleEl.getAttribute("data-i18n"));
  }
  // meta description
  const descEl = document.querySelector('meta[name="description"][data-i18n]');
  if (descEl) {
    descEl.setAttribute("content", t(descEl.getAttribute("data-i18n")));
  }
}

/**
 * 言語ピッカーをマウントする。
 * @param {HTMLElement|string} target  挿入先 (要素か CSS セレクタ)
 * @param {{ compact?: boolean }} opts compact=true で 2 文字表記に
 */
export function mountLangPicker(target, opts = {}) {
  const host = typeof target === "string" ? document.querySelector(target) : target;
  if (!host) return;

  const select = document.createElement("select");
  select.className = "i18n-picker";
  select.setAttribute("aria-label", "Language / 言語");
  for (const code of SUPPORTED) {
    const opt = document.createElement("option");
    opt.value = code;
    opt.textContent = opts.compact ? code.toUpperCase() : LANGUAGES[code].native;
    if (code === _lang) opt.selected = true;
    select.appendChild(opt);
  }
  select.addEventListener("change", (e) => {
    const newLang = e.target.value;
    // Phase 7.5ZR: picker 変更は静的化対象ページなら常に URL ナビゲーション。
    // root / から en 選択 → /en/index.html に移動。
    // /tr/ から ja 選択 → /index.html に移動。
    // 静的化対象でない (= pricing.html / security.html 等) は JS swap のみ。
    try { localStorage.setItem(LS_KEY, newLang); } catch (_) {}
    const STATIC_RENDERED = new Set(["/index.html", "/help.html", "/"]);
    let basename = window.location.pathname.replace(/^\/([a-z]{2}(?:-[A-Z]{2})?)\//, "/");
    if (basename === "" || basename === "/") basename = "/index.html";
    if (STATIC_RENDERED.has(basename)) {
      const targetUrl = _buildLangPrefixedUrl(newLang);
      if (targetUrl && targetUrl !== window.location.pathname) {
        window.location.href = targetUrl + window.location.hash;
        return;
      }
    }
    setLang(newLang);
  });

  // 言語変更時にピッカーの選択値を同期
  onLangChange(lang => { select.value = lang; });

  host.appendChild(select);
  return select;
}
