// ============================================================================
// web/lib/dicewords.js — ダイスの言葉 (Master をランダムな単語 8 語で作る)
// ----------------------------------------------------------------------------
// 設計: Arpass_素早い解錠_設計書.md 6 章 (6.1〜6.9)。
//
// Master の中身は「常に英語の語を小文字にして、半角スペース 1 つでつないだもの」。
//   例: "cat umbrella apple station star shoe mountain"
// 各国語は表示と入力のためだけに使う。入力された語は番号に直し、英語の語に
// 置き換えてから Argon2id に入れる (vault-crypto.js は今までどおり、正規化せずに
// UTF-8 にする)。各国語の文字列は Argon2id に一切入らない。
//
// 単語表: web/lib/wordlist/<lang>.json (英語 1296 語 = 6^4、並び順は固定)。
//   英語の表と並び順は、一度出したら変えない (変えると紙に書いた言葉が通らない)。
//   各国語は、あとから別名を足せる (消さない)。
//
// 照合の決まり (6.3 節) はこのファイルにだけ書く。復旧ツールのブラウザ版
// (emergency-restore-main.js) もこのファイルを import する。Python 版
// (tools/recover-personal.py) は同じ決まりを Python で書き直しており、
// web/lib/wordlist/test-vectors.json で 3 つが同じ番号になることを確かめる
// (scripts/test-dicewords.mjs、tools/recover-personal.py --self-test)。
//
// ⚠️ ここの正規化を変えるときは、Python 版も同時に変え、test-vectors.json を
//    作り直して両方で通すこと。正規化を変えても Master の中身 (英語) は
//    変わらないが、昔は通った入力が通らなくなるおそれがある。
// ============================================================================

export const WORDLIST_VERSION = 1;
export const WORDLIST_ID = "arpass-words-v1";
export const WORD_COUNT = 1296; // 6^4: サイコロ 4 個で 1 語
export const MASTER_WORDS = 8;  // 8 語に固定 (6.5 節、2026-11-09 に 7 語から変えた)。選ばせない。
// log2(1296) * 8 = 82.71 bits (出た順のまま)
export const MASTER_BITS = Math.round(Math.log2(WORD_COUNT) * MASTER_WORDS);
// 覚えやすく並べ替えたときの下限: 順番の分 log2(8!) = 15.30 bits を引く (どの 8 語かだけを当てればよいとみなす)
// 82.71 - 15.30 = 67.41 bits
export const MASTER_BITS_REORDERED = Math.floor(Math.log2(WORD_COUNT) * MASTER_WORDS - Math.log2(factorial(MASTER_WORDS)));
function factorial(n) { let r = 1; for (let i = 2; i <= n; i++) r *= i; return r; }

// 表を持つ言語 (アプリの 16 言語と同じ)。zh-CN と zh-TW は 1 つのファイル (zh.json)
// を共有し、簡体字と繁体字をどちらでも受け付ける。
export const WORDLIST_LANGS = [
  "en", "ja", "zh-CN", "zh-TW", "ko", "es", "pt-BR", "de",
  "fr", "it", "ru", "id", "vi", "hi", "ar", "tr",
];

// ---------------------------------------------------------------------------
// 1. 全言語に共通の前処理
//    NFKC → 小文字 (言語によらない toLowerCase) → ゼロ幅の文字を除く → 前後の空白を除く
// ---------------------------------------------------------------------------

// ゼロ幅の文字 (どこにあっても除く): ZWSP, ZWNJ, ZWJ, WORD JOINER, BOM
const ZERO_WIDTH_RE = /[​‌‍⁠﻿]/g;
// 空白とみなす文字。NFKC のあとなので、全角スペースや NBSP は U+0020 になっている。
// Python 版と同じ集合にするため、\s ではなく明示する。
const WS_CLASS = " \\t\\n\\r\\f\\v\\u0085\\u1680\\u2028\\u2029";
const TRIM_RE = new RegExp(`^[${WS_CLASS}]+|[${WS_CLASS}]+$`, "g");
const WS_ALL_RE = new RegExp(`[${WS_CLASS}]+`, "g");

export function normalizeCommon(s) {
  let t = String(s ?? "").normalize("NFKC").toLowerCase();
  t = t.replace(ZERO_WIDTH_RE, "");
  t = t.replace(TRIM_RE, "");
  return t;
}

// アクセント記号 (結合文字) を外す。ラテン文字の言語とベトナム語の「外した形」だけに使う。
// ヒンディー語の母音記号などを壊さないよう、ほかの言語には使わない。
const COMBINING_RE = /\p{M}/gu;
function stripMarks(s) {
  return s.normalize("NFD").replace(COMBINING_RE, "").normalize("NFC");
}

// ---------------------------------------------------------------------------
// 2. 言語ごとの照合の形 (6.3 節の表)
//    fold(lang, s): 入力にも表の語にも同じ関数をかけ、出た文字列 (照合の形) で比べる。
//    tableKeys(lang, form): 表の語 1 つが受け付ける照合の形の集合 (ドイツ語だけ 2 つ)。
// ---------------------------------------------------------------------------

const LATIN_STRIP_LANGS = new Set(["es", "pt-BR", "fr", "it"]);

// 語の中に空白を認める言語 (6.3 節の決まり 4、2026-11-09 に広げた)。
// 照合では語の中の空白を除いてつなぐ (rumah sakit = rumahsakit)。貼り付けは
// splitPasted が表の語で区切れる分け方を探す。入力欄では空白で次の欄へ進まない。
export const SPACED_LANGS = new Set(["vi", "id", "tr", "ar", "hi"]);

// インドネシア語の繰り返しのハイフン (kupu-kupu)。照合では除く。
// NFKC のあとなので、全角の「－」は "-"、U+2011 は U+2010 になっている。
const HYPHEN_RE = /[-\u2010\u2011\u2012\u2013\u2212]/g;

// 日本語: カタカナ → ひらがな (ァ U+30A1 .. ヶ U+30F6 → -0x60)。ー は残す。
function kataToHira(s) {
  let out = "";
  for (const ch of s) {
    const c = ch.codePointAt(0);
    out += (c >= 0x30A1 && c <= 0x30F6) ? String.fromCodePoint(c - 0x60) : ch;
  }
  return out;
}

// アラビア語: 母音記号 (U+064B–U+065F, U+0670) とタトウィール (U+0640) を除き、
// أ إ آ → ا、ى → ي、ة → ه にそろえる。
const AR_MARKS_RE = /[ً-ٰٟـ]/g;
function foldArabic(s) {
  return s.replace(AR_MARKS_RE, "")
    .replace(/[أإآ]/g, "ا")
    .replace(/ى/g, "ي")
    .replace(/ة/g, "ه");
}

export function fold(lang, s) {
  let t = normalizeCommon(s);
  switch (lang) {
    case "en":
      return t;
    case "ja":
      return kataToHira(t);
    case "zh-CN": case "zh-TW": case "ko":
      return t; // NFKC 済み (韓国語は字母がまとまって音節になる)
    case "de":
      t = t.replace(/ä/g, "ae").replace(/ö/g, "oe").replace(/ü/g, "ue").replace(/ß/g, "ss");
      return stripMarks(t);
    case "tr":
      t = t.replace(/ı/g, "i");
      // İ は小文字にすると i + U+0307 になり、stripMarks で i になる。語の中の空白を除く
      return stripMarks(t).replace(WS_ALL_RE, "");
    case "id":
      return stripMarks(t).replace(WS_ALL_RE, "").replace(HYPHEN_RE, "");
    case "vi":
      return t.replace(WS_ALL_RE, ""); // 語の中の空白を除いてつなぐ。声調記号は残す
    case "ru":
      return t.replace(/ё/g, "е");
    case "ar":
      return foldArabic(t).replace(WS_ALL_RE, "");
    case "hi":
      // ヌクタ (U+093C) を除く (NFKC で क़ は क + ़ に分かれている)。
      // チャンドラビンドゥ ँ (U+0901) はアヌスヴァーラ ं (U+0902) にそろえる (गाँव = गांव)。
      return t.replace(/\u093C/g, "").replace(/\u0901/g, "\u0902").replace(WS_ALL_RE, "");
    default:
      if (LATIN_STRIP_LANGS.has(lang)) return stripMarks(t);
      return t;
  }
}

// ベトナム語の「外した形」。外した形が表の中で 1 つに決まる語だけ、外しても受け付ける。
export function foldViStripped(s) {
  return stripMarks(fold("vi", s)).replace(/đ/g, "d");
}

// ベトナム語: 入力に記号 (声調記号と đ) が 1 つもないか。外した形で受け付けるのはこのときだけ
// (記号を打ったのに合わないときは、別の語に寄せず「表にない語」にする)。
function viUnmarked(s) {
  return foldViStripped(s) === fold("vi", s);
}

export function tableKeys(lang, form) {
  const keys = new Set([fold(lang, form)]);
  if (lang === "de") {
    // ドイツ語: アクセント記号を外した形 (Käse → kase) でも受け付ける
    const base = normalizeCommon(form).replace(/ß/g, "ss");
    keys.add(stripMarks(base));
  }
  return keys;
}

// ---------------------------------------------------------------------------
// 3. 単語表の読み込み
// ---------------------------------------------------------------------------

// 表のファイル名。zh-CN と zh-TW は zh.json を共有する。
export function wordlistFile(lang) {
  return (lang === "zh-CN" || lang === "zh-TW") ? "zh" : lang;
}

const _rawCache = new Map();

async function fetchJson(file) {
  if (_rawCache.has(file)) return _rawCache.get(file);
  const p = (async () => {
    const url = new URL(`./wordlist/${file}.json`, import.meta.url);
    const res = await fetch(url, { cache: "no-cache" });
    if (!res.ok) throw new Error(`wordlist ${file}: HTTP ${res.status}`);
    return res.json();
  })();
  _rawCache.set(file, p);
  try { return await p; } catch (e) { _rawCache.delete(file); throw e; }
}

// テストや Node から、fetch を使わずに表を渡すための入口。
export function primeWordlist(file, json) {
  _rawCache.set(file, Promise.resolve(json));
}

// raw JSON → 言語ごとの { display[], forms[][] }
//   en.json : { words: ["aardvark", ...] }
//   zh.json : { words: [{ cn, tw, f: [...], p: [...] }, ...] }
//   その他  : { words: [["表示", "別名", ...], ...] }  (先頭が表示の形)
function entriesFor(lang, raw) {
  const words = raw.words;
  if (!Array.isArray(words) || words.length !== WORD_COUNT) {
    throw new Error(`wordlist ${lang}: expected ${WORD_COUNT} words`);
  }
  if (lang === "en") {
    return { display: words.slice(), forms: words.map((w) => [w]) };
  }
  if (lang === "zh-CN" || lang === "zh-TW") {
    const key = lang === "zh-CN" ? "cn" : "tw";
    return {
      display: words.map((e) => e[key]),
      forms: words.map((e) => [e.cn, e.tw, ...(e.f || [])]),
      pinyin: words.map((e) => e.p || []),
    };
  }
  return { display: words.map((e) => e[0]), forms: words.map((e) => e.slice()) };
}

/**
 * 照合器を作る。受け付けるのは、その言語の表と英語の表 (6.3 節)。
 * @returns {Promise<Matcher>}
 */
export async function loadMatcher(lang) {
  if (!WORDLIST_LANGS.includes(lang)) lang = "en";
  const enRaw = await fetchJson("en");
  const raw = lang === "en" ? enRaw : await fetchJson(wordlistFile(lang));
  return buildMatcher(lang, raw, enRaw);
}

export function buildMatcher(lang, raw, enRaw) {
  const en = entriesFor("en", enRaw);
  const loc = lang === "en" ? en : entriesFor(lang, raw);

  // 照合の形 → 番号。英語の語も同じ fold をかけて入れる (英語は ASCII なので形は変わらない)。
  const exact = new Map();
  const add = (key, idx) => {
    if (!key) return;
    const prev = exact.get(key);
    if (prev === undefined) exact.set(key, idx);
    else if (prev !== idx) exact.set(key, -1); // 表の不具合 (検査で弾く)。照合では拒否する
  };
  for (let i = 0; i < WORD_COUNT; i++) {
    for (const f of loc.forms[i]) for (const k of tableKeys(lang, f)) add(k, i);
    add(fold(lang, en.display[i]), i);
  }

  // ベトナム語: 外した形が 1 つに決まる語だけ
  let stripped = null;
  if (lang === "vi") {
    const counts = new Map();
    for (let i = 0; i < WORD_COUNT; i++) {
      const seen = new Set();
      for (const f of loc.forms[i]) seen.add(foldViStripped(f));
      for (const k of seen) {
        const prev = counts.get(k);
        counts.set(k, prev === undefined ? i : (prev === i ? i : -1));
      }
    }
    stripped = new Map();
    for (const [k, i] of counts) if (i >= 0 && !exact.has(k)) stripped.set(k, i);
  }

  // 候補を絞るための一覧 (照合の形, 番号)
  const keyList = [];
  for (const [k, i] of exact) if (i >= 0) keyList.push([k, i]);
  if (stripped) for (const [k, i] of stripped) keyList.push([k, i]);
  keyList.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));

  // 韓国語は字母に分けて前方一致を見る (IME で組み立て中の音節も候補に出せる)
  const prefixForm = lang === "ko" ? koJamo : (x) => x;
  const prefixList = keyList.map(([k, i]) => [prefixForm(k), i]);

  function lookup(token) {
    const k = fold(lang, token);
    if (!k) return -1;
    const i = exact.get(k);
    if (i !== undefined) return i;
    if (stripped && viUnmarked(token)) {
      const j = stripped.get(foldViStripped(token));
      if (j !== undefined) return j;
    }
    return -1;
  }

  // 打った分で候補を出す。返すのは番号の配列 (重複なし、表の順)。
  function candidates(partial, limit = 8) {
    const k = fold(lang, partial);
    if (!k) return [];
    const p = prefixForm(k);
    const pStripped = lang === "vi" && viUnmarked(partial) ? prefixForm(foldViStripped(partial)) : null;
    const hits = new Set();
    for (const [key, i] of prefixList) {
      if (key.startsWith(p) || (pStripped && key.startsWith(pStripped))) hits.add(i);
    }
    return [...hits].sort((a, b) => a - b).slice(0, limit);
  }

  return {
    lang,
    display: (i) => loc.display[i],
    english: (i) => en.display[i],
    lookup,
    candidates,
    // 貼り付けた文字列を語に分ける (6.4 節)。返すのは文字列の配列。
    // 語の中に空白を認める言語で、分け方が 1 つに決まらないときは null。
    split: (text, want = MASTER_WORDS) => splitPasted(lang, text, lookup, want),
  };
}

// ---------------------------------------------------------------------------
// 4. 貼り付けの区切り (6.4 節)
//    ふつうの言語: 半角スペース、全角スペース、改行、読点 (、 ， ,) で区切る。
//    語の中に空白を認める言語 (SPACED_LANGS): 改行と読点で区切ったあと、空白の部分は、
//    表の語だけで区切れる分け方を探す。
//      1. want 語ちょうどの分け方が 1 つだけ → それを選ぶ (2 つ以上 → null)
//      2. want 語の分け方がない → 分け方が全体で 1 つだけならそれ (数語だけの貼り付け)、
//         2 つ以上なら null
//      3. 表の語だけでは区切れない (打ち間違いなど) → 長い方から (MAX_PARTS まで) つなぎ、残りは 1 つずつ
//         (欄に入れて赤く出すため。この場合 8 語そろって通ることはない)
//    null は「欄に入れず、1 語ずつ入れてもらう」の意味。
// ---------------------------------------------------------------------------

// Python 版と同じ集合にするため明示する。NFKC のあとなので、全角スペースは U+0020、
// ， は "," 、､ は 、 になっている。アラビア語の読点 (،) も区切りにする。
const SPLIT_RE = new RegExp(`[${WS_CLASS}\\u3001,\\u060C]+`, "u");
// 語の中に空白を認める言語で、必ず語の境目になるもの (改行と読点) と、語の中にもありうるもの
const HARD_SPLIT_RE = /[\n\r\f\v\u0085\u2028\u2029\u3001,\u060C]+/u;
const SOFT_SPLIT_RE = /[ \t\u1680]+/u;
// 1 語が空白で分かれる数の上限。表の語はこれ以下にする (wordlist-check.mjs が確かめる)
export const MAX_PARTS = 6;
const MAX_TOKENS = 64;  // これより長い貼り付けは分け方を探さない (空白で分けただけを返す)

export function splitPasted(lang, text, lookup, want = MASTER_WORDS) {
  const s = String(text ?? "").normalize("NFKC");
  if (!SPACED_LANGS.has(lang) || !lookup) return s.split(SPLIT_RE).filter(Boolean);

  const toks = []; // 空白で分けた部分
  const end = [];  // その部分を含む塊 (改行・読点の間) の終わりの位置。語は塊をまたがない
  for (const chunk of s.split(HARD_SPLIT_RE)) {
    const parts = chunk.split(SOFT_SPLIT_RE).filter(Boolean);
    const e = toks.length + parts.length;
    for (const p of parts) { toks.push(p); end.push(e); }
  }
  const T = toks.length;
  if (T === 0) return [];
  if (T > MAX_TOKENS) return toks;
  const word = (p, n) => toks.slice(p, p + n).join(" ");
  const span = (p) => Math.min(MAX_PARTS, end[p] - p);

  // ways[p][c]: toks[p..] を表の語 c 個に分ける分け方の数 (2 で頭打ち)
  // first[p][c]: そのときの最初の語が使う部分の数 (分け方が 1 つのときの道筋)
  const ways = Array.from({ length: T + 1 }, () => new Array(T + 1).fill(0));
  const first = Array.from({ length: T + 1 }, () => new Array(T + 1).fill(0));
  ways[T][0] = 1;
  for (let p = T - 1; p >= 0; p--) {
    for (let n = 1; n <= span(p); n++) {
      if (lookup(word(p, n)) < 0) continue;
      for (let c = 1; c <= T - p; c++) {
        const w = ways[p + n][c - 1];
        if (!w) continue;
        if (!ways[p][c]) first[p][c] = n;
        ways[p][c] = Math.min(2, ways[p][c] + w);
      }
    }
  }
  const build = (c) => {
    const out = [];
    for (let p = 0; p < T; c--) { const n = first[p][c]; out.push(word(p, n)); p += n; }
    return out;
  };
  const exact = want >= 1 && want <= T ? ways[0][want] : 0;
  if (exact === 1) return build(want);
  if (exact >= 2) return null;
  let total = 0, only = 0;
  for (let c = 1; c <= T; c++) if (ways[0][c]) { total += ways[0][c]; only = c; }
  if (total === 1) return build(only);
  if (total >= 2) return null;

  // 表の語だけでは区切れない: 長い方からつなぐ (最大 MAX_PARTS 個)
  const out = [];
  for (let p = 0; p < T;) {
    let took = 1;
    for (let n = span(p); n >= 2; n--) if (lookup(word(p, n)) >= 0) { took = n; break; }
    out.push(word(p, took));
    p += took;
  }
  return out;
}

// ---------------------------------------------------------------------------
// 5. 韓国語の字母分解 (打つキーの単位)
//    音節を初声・中声・終声に分け、複合の母音と終声は打つ字母に分ける (ㅘ → ㅗㅏ、ㄳ → ㄱㅅ)。
//    濃音 (ㄲ ㄸ ㅃ ㅆ ㅉ) は Shift で 1 打なので 1 字母のまま。
// ---------------------------------------------------------------------------

const KO_L = "ㄱㄲㄴㄷㄸㄹㅁㅂㅃㅅㅆㅇㅈㅉㅊㅋㅌㅍㅎ";
const KO_V = ["ㅏ","ㅐ","ㅑ","ㅒ","ㅓ","ㅔ","ㅕ","ㅖ","ㅗ","ㅗㅏ","ㅗㅐ","ㅗㅣ","ㅛ","ㅜ","ㅜㅓ","ㅜㅔ","ㅜㅣ","ㅠ","ㅡ","ㅡㅣ","ㅣ"];
const KO_T = ["","ㄱ","ㄲ","ㄱㅅ","ㄴ","ㄴㅈ","ㄴㅎ","ㄷ","ㄹ","ㄹㄱ","ㄹㅁ","ㄹㅂ","ㄹㅅ","ㄹㅌ","ㄹㅍ","ㄹㅎ","ㅁ","ㅂ","ㅂㅅ","ㅅ","ㅆ","ㅇ","ㅈ","ㅊ","ㅋ","ㅌ","ㅍ","ㅎ"];
// 互換字母 (IME が組み立て中に出す単独の字母) の複合を分ける
const KO_COMPAT_SPLIT = {
  "ㄳ": "ㄱㅅ", "ㄵ": "ㄴㅈ", "ㄶ": "ㄴㅎ", "ㄺ": "ㄹㄱ", "ㄻ": "ㄹㅁ", "ㄼ": "ㄹㅂ",
  "ㄽ": "ㄹㅅ", "ㄾ": "ㄹㅌ", "ㄿ": "ㄹㅍ", "ㅀ": "ㄹㅎ", "ㅄ": "ㅂㅅ",
  "ㅘ": "ㅗㅏ", "ㅙ": "ㅗㅐ", "ㅚ": "ㅗㅣ", "ㅝ": "ㅜㅓ", "ㅞ": "ㅜㅔ", "ㅟ": "ㅜㅣ", "ㅢ": "ㅡㅣ",
};

export function koJamo(s) {
  let out = "";
  for (const ch of String(s)) {
    const c = ch.codePointAt(0);
    if (c >= 0xAC00 && c <= 0xD7A3) {
      const n = c - 0xAC00;
      out += KO_L[Math.floor(n / 588)] + KO_V[Math.floor((n % 588) / 28)] + KO_T[n % 28];
    } else if (c >= 0x1100 && c <= 0x1112) {
      out += KO_L[c - 0x1100];          // 初声の字母 (NFKC が互換字母をこれに変える)
    } else if (c >= 0x1161 && c <= 0x1175) {
      out += KO_V[c - 0x1161];          // 中声
    } else if (c >= 0x11A8 && c <= 0x11C2) {
      out += KO_T[c - 0x11A7];          // 終声
    } else {
      out += KO_COMPAT_SPLIT[ch] || ch;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// 6. 語を選ぶ (6.5 節)
// ---------------------------------------------------------------------------

/**
 * 端末の乱数で n 語の番号を選ぶ。余りを使わない選び方 (1296 は 2 のべき乗では
 * ないので、範囲外の値は捨てて引き直す)。
 *   Uint16 (0..65535) のうち 0..64799 (= 1296 × 50) だけを使い、% 1296 する。
 */
export function randomIndices(n = MASTER_WORDS, rng = defaultRng) {
  const LIMIT = WORD_COUNT * Math.floor(65536 / WORD_COUNT); // 64800
  const out = [];
  const buf = new Uint16Array(16);
  while (out.length < n) {
    rng(buf);
    for (const v of buf) {
      if (v >= LIMIT) continue;
      out.push(v % WORD_COUNT);
      if (out.length === n) break;
    }
  }
  buf.fill(0);
  return out;
}

function defaultRng(buf) {
  globalThis.crypto.getRandomValues(buf);
}

// サイコロ 4 個の目 ("1".."6" × 4) → 番号。表の順は 1111, 1112, … 6666。
export function diceToIndex(dice) {
  const d = String(dice ?? "").normalize("NFKC").replace(WS_ALL_RE, "");
  if (!/^[1-6]{4}$/.test(d)) return -1;
  let i = 0;
  for (const ch of d) i = i * 6 + (ch.charCodeAt(0) - 49);
  return i;
}

export function indexToDice(i) {
  let s = "";
  for (let k = 0; k < 4; k++) { s = String((i % 6) + 1) + s; i = Math.floor(i / 6); }
  return s;
}

/**
 * 番号の並び → Master の文字列 (英語の小文字を半角スペース 1 つでつなぐ)。
 * これだけが Argon2id に入る。
 */
export function masterFromIndices(indices, englishWords) {
  if (!Array.isArray(indices) || indices.length !== MASTER_WORDS) {
    throw new Error(`dicewords: need exactly ${MASTER_WORDS} words`);
  }
  return indices.map((i) => {
    if (!Number.isInteger(i) || i < 0 || i >= WORD_COUNT) throw new Error("dicewords: bad index");
    return englishWords(i);
  }).join(" ");
}

// ---------------------------------------------------------------------------
// 7. 共有のテストの値で自分を確かめる (ブラウザ版の復旧ツールの #dicewords-selftest から呼ぶ)
//    Python 版と同じ test-vectors.json を、このモジュールの隣の wordlist/ から読む。
// ---------------------------------------------------------------------------
export async function runVectorSelfTest() {
  const url = new URL("./wordlist/test-vectors.json", import.meta.url);
  const vec = await (await fetch(url, { cache: "no-cache" })).json();
  const matchers = new Map();
  const M = async (lang) => {
    if (!matchers.has(lang)) matchers.set(lang, await loadMatcher(lang));
    return matchers.get(lang);
  };
  let pass = 0;
  const fails = [];
  const check = (cond, what) => { if (cond) pass++; else fails.push(what); };
  for (const c of vec.fold || []) {
    check(fold(c.lang, c.input) === c.key && JSON.stringify([...tableKeys(c.lang, c.input)].sort()) === JSON.stringify(c.keys)
      && (c.lang !== "vi" || foldViStripped(c.input) === c.vi), `fold ${c.lang} ${JSON.stringify(c.input)}`);
  }
  for (const c of vec.lookup) check((await M(c.lang)).lookup(c.input) === c.index, `lookup ${c.lang} ${JSON.stringify(c.input)}`);
  for (const c of vec.split) {
    const m = await M(c.lang);
    const got = c.want === undefined ? m.split(c.text) : m.split(c.text, c.want);
    check(JSON.stringify(got) === JSON.stringify(c.tokens), `split ${c.lang} ${JSON.stringify(c.text)}`);
  }
  for (const c of vec.master || []) {
    const m = await M(c.lang);
    const toks = m.split(c.text) || [];
    const idx = toks.map((t) => m.lookup(t));
    const got = toks.length === MASTER_WORDS && idx.every((x) => x >= 0) ? masterFromIndices(idx, m.english) : null;
    check(got === c.master, `master ${c.lang} ${JSON.stringify(c.text)}`);
  }
  return { pass, fail: fails.length, fails: fails.slice(0, 20) };
}
