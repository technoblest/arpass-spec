// ============================================================================
// web/lib/dicewords-ui.js — ダイスの言葉の画面部品 (設計書 6.4〜6.6 節)
// ----------------------------------------------------------------------------
//   mountDiceInput(container, opts)   語ごとの 8 つの入力欄 (候補つき)
//   mountMasterInput(pwInput, opts)   解錠などの「今のマスター」欄に、
//                                     「ダイスの言葉」と「文字で入力」の切り替えを付ける
//   mountMasterCreate(container, opts) 作る画面 / 変える画面 (ダイスの言葉 8 語だけ。並べ替えと 1 語の差し替えができる)
//   printMasterMemo(...)              マスターのメモを印刷 (PDF のライブラリは使わない)
//
// どの部品も、出すのは「英語の小文字を半角スペース 1 つでつないだ文字列」だけ。
// それを既存の <input type="password"> の value に入れるので、解錠・作成の処理は
// 今までどおり input.value を読めばよい。英語に直した文字列は画面に出さない。
// 1 行の欄 (文字で入力) には、何の正規化もかけない。
// ============================================================================

import {
  loadMatcher, randomIndices, diceToIndex, indexToDice, masterFromIndices,
  MASTER_WORDS, MASTER_BITS, MASTER_BITS_REORDERED, WORDLIST_LANGS, WORDLIST_ID, SPACED_LANGS, fold,
} from "./dicewords.js?v=2b44ba46";

// 言語の名前 (i18n.js の LANGUAGES と同じ。復旧ツールは i18n.js を読まないので、ここに持つ)
export const LANG_NAMES = {
  ja: "日本語", en: "English", "zh-CN": "简体中文", "zh-TW": "繁體中文", ko: "한국어",
  es: "Español", "pt-BR": "Português (BR)", de: "Deutsch", fr: "Français", it: "Italiano",
  ru: "Русский", id: "Bahasa Indonesia", vi: "Tiếng Việt", hi: "हिन्दी", ar: "العربية", tr: "Türkçe",
};

// i18n の辞書がない場所 (復旧ツール) でも動くよう、英語の文言を持っておく。
const FALLBACK_EN = {
  "app.dice.mode_dice": "Dice words (8 words)",
  "app.dice.mode_text": "Type as text",
  "app.dice.lang_label": "Word list language",
  "app.dice.ja_hint": "",
  "app.dice.field_label": "Word {n}",
  "app.dice.status_done": "✓ All 8 words entered",
  "app.dice.status_left": "{n} more word(s)",
  "app.dice.not_in_list": "Not in the word list",
  "app.dice.loading": "Loading the word list…",
  "app.dice.load_failed": "Could not load the word list. Check your connection and try again.",
  "app.dice.paste_hint": "You can also paste all 8 words at once.",
  "app.dice.spaced_hint": "Some words contain a space. Press Enter or Tab to go to the next box.",
  "app.dice.paste_ambiguous": "These words can be split in more than one way. Paste them separated by commas, or type them one by one.",
  "app.dice.text_hint": "For a Master you chose yourself. Type it exactly as before.",
  "app.dice.create_intro": "Your Master is 8 words picked at random on this device (dice words). Write it on paper and keep it safe.",
  "app.dice.strength": "Strength: 8 words · about 83 bits",
  "app.dice.strength_reordered": "Strength: 8 words, reordered · at least about 67 bits",
  "app.dice.arrange_hint": "To remember them more easily, you can drag ⠿ or use ↑↓ to put the words in an order that tells a story. If a word is unfamiliar, ↻ replaces just that word with another random word (as many times as you need). Please do not keep replacing words until you get ones you like — that makes your Master easier to guess.",
  "app.dice.drag": "Drag to reorder",
  "app.dice.move_up": "Move word {n} up",
  "app.dice.move_down": "Move word {n} down",
  "app.dice.replace": "Replace word {n} with another random word",
  "app.dice.regenerate": "🎲 Pick a different set",
  "app.dice.use_dice": "Make it with real dice",
  "app.dice.use_random": "Let this device pick",
  "app.dice.dice_hint": "Roll 4 dice and enter the numbers from left to right (e.g. 3516). Do this 8 times.",
  "app.dice.dice_invalid": "Enter four digits from 1 to 6",
  "app.dice.paper_lang": "Language to write on paper",
  "app.dice.print_btn": "🖨 Print the Master memo",
  "app.dice.copy_hint": "If you cannot print, copy these 8 words with their numbers onto paper by hand.",
  "app.dice.separate_warn": "Keep the Master memo in a different place from your Recovery kit. Anyone who has both can open your drive.",
  "app.dice.written_btn": "I wrote it down → Check",
  "app.dice.confirm_intro": "To check, look at your paper and type the 8 words once.",
  "app.dice.confirm_ok": "✓ Matches your paper",
  "app.dice.confirm_mismatch": "Some words differ from your paper. Please check again.",
  "app.dice.back_to_words": "← Back to the words",
  "app.dice.need_confirm": "You have not checked your Master yet. Look at your paper and type the 8 words.",
  "app.dice.memo_title": "Arpass Master memo",
  "app.dice.memo_date": "Created",
  "app.dice.memo_list": "Word list",
  "app.dice.memo_col_no": "No.",
  "app.dice.memo_col_word": "Word",
  "app.dice.memo_col_en": "English",
  "app.dice.memo_col_dice": "Dice",
  "app.dice.memo_drive": "Drive name (optional, by hand):",
  "app.dice.memo_warn_title": "⚠ Important",
  "app.dice.memo_warn_1": "This is your Arpass Master. You need it to add a new device and to recover after the service ends.",
  "app.dice.memo_warn_2": "Keep it in a different place from your Recovery kit. Anyone who has both can open your drive.",
  "app.dice.memo_warn_3": "Do not photograph or copy this paper, and do not show it to anyone.",
  "app.dice.memo_warn_4": "When typing, you can use the English words or the words in the language above.",
  "app.dice.memo_restore": "Even after the service ends, this memo and your Recovery kit open your drive with the recovery tool.",
  "app.dice.change_intro": "Your new Master is also made of dice words (8 words).",
};

function makeTr(tr) {
  return (key, vars) => {
    let s = tr ? tr(key, vars) : null;
    if (!s || s === key) s = FALLBACK_EN[key] ?? key;
    if (vars) for (const [k, v] of Object.entries(vars)) s = s.split(`{${k}}`).join(String(v));
    return s;
  };
}

// ---------------------------------------------------------------------------
// 見た目 (どのページでも使えるよう、ここで <style> を足す)
// ---------------------------------------------------------------------------
const CSS = `
.dw-box { margin: 6px 0 4px; }
.dw-langrow { display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin: 0 0 8px; font-size: 13px; }
.dw-langrow select { padding: 5px 8px; font-size: 13px; border:1px solid #CBD5E1; border-radius: 6px; background:#fff; }
.dw-hint { font-size: 12px; color: #64748B; margin: 0 0 8px; line-height: 1.5; }
.dw-fields { list-style: none; padding: 0; margin: 0; display: grid; grid-template-columns: 1fr; gap: 6px; }
@media (min-width: 520px) { .dw-fields { grid-template-columns: 1fr 1fr; } }
.dw-field { position: relative; display: flex; align-items: center; gap: 6px; }
.dw-num { flex: 0 0 22px; text-align: right; font-size: 12px; color: #64748B; font-variant-numeric: tabular-nums; }
.dw-field input { flex: 1 1 auto; min-width: 0; padding: 8px 10px; font-size: 15px; border: 1px solid #CBD5E1; border-radius: 6px; background:#fff; }
.dw-field input:focus { outline: 2px solid #A78BFA; outline-offset: 0; border-color: #7C3AED; }
.dw-field.dw-ok input { border-color: #10B981; background: #F0FDF4; }
.dw-field.dw-bad input { border-color: #DC2626; background: #FEF2F2; }
.dw-gloss { flex: 0 0 auto; font-size: 11px; color: #047857; max-width: 40%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.dw-field.dw-bad .dw-gloss { color: #DC2626; }
.dw-cands { position: absolute; left: 28px; right: 0; top: 100%; z-index: 50; display: none; flex-wrap: wrap; gap: 4px;
  background: #fff; border: 1px solid #CBD5E1; border-radius: 6px; padding: 6px; box-shadow: 0 6px 18px rgba(15,23,42,.12); }
.dw-cands.dw-open { display: flex; }
.dw-cand { border: 1px solid #E2E8F0; background: #F8FAFC; border-radius: 5px; padding: 4px 8px; font-size: 13px; cursor: pointer; }
.dw-cand small { color: #64748B; margin-left: 4px; }
.dw-cand.dw-enter { border-color: #A78BFA; }
.dw-cand .dw-key { color: #7C3AED; margin-left: 4px; font-size: 11px; }
.dw-cand:hover, .dw-cand:focus { background: #EDE9FE; border-color: #A78BFA; }
.dw-status { font-size: 13px; margin-top: 8px; min-height: 1.3em; color: #64748B; }
.dw-status.dw-done { color: #047857; font-weight: 600; }
.dw-status.dw-err { color: #DC2626; }
.dw-tabs { display: flex; gap: 0; margin: 4px 0 8px; border: 1px solid #CBD5E1; border-radius: 8px; overflow: hidden; width: fit-content; max-width: 100%; }
.dw-tab { border: 0; background: #fff; padding: 7px 12px; font-size: 13px; cursor: pointer; color: #334155; }
.dw-tab + .dw-tab { border-left: 1px solid #CBD5E1; }
.dw-tab[aria-selected="true"] { background: #5B21B6; color: #fff; font-weight: 600; }
/* 列の数は置き場所の幅で決める (作る画面のカードは狭い)。語の途中では折り返さない */
.dw-words { position: relative; list-style: none; padding: 0; margin: 8px 0; display: grid; grid-template-columns: repeat(auto-fill, minmax(min(100%, 230px), 1fr)); gap: 6px; }
.dw-word { display: flex; align-items: center; gap: 8px; padding: 8px 10px; border: 1px solid #E2E8F0; border-radius: 6px; background: #F8FAFC; }
.dw-word b { font-size: 17px; word-break: keep-all; overflow-wrap: anywhere; }
.dw-word .dw-wen { font-size: 12px; color: #475569; }
.dw-word .dw-wdice { margin-left: auto; font-size: 11px; color: #94A3B8; font-variant-numeric: tabular-nums; }
.dw-wmain { flex: 1 1 auto; min-width: 0; display: flex; flex-wrap: wrap; align-items: baseline; gap: 2px 8px; }
.dw-wbtns { flex: 0 0 auto; display: inline-flex; gap: 3px; }
/* つかみ所 ⠿: 行の左端いっぱいを押さえられるようにする。指で押さえてもスクロールや文字選択にしない */
.dw-grip { flex: 0 0 auto; align-self: stretch; display: flex; align-items: center; margin: -8px -4px -8px -10px; padding: 0 6px 0 10px;
  color: #94A3B8; cursor: grab; touch-action: none; user-select: none; -webkit-user-select: none; -webkit-touch-callout: none; }
.dw-grip:hover { color: #7C3AED; }
.dw-grip svg { display: block; }
.dw-words.dw-sorting, .dw-words.dw-sorting * { cursor: grabbing; user-select: none; -webkit-user-select: none; }
.dw-word.dw-dragging { position: relative; z-index: 5; background: #fff; border-color: #A78BFA; box-shadow: 0 8px 20px rgba(15,23,42,.18); }
.dw-word.dw-dragging .dw-grip { color: #7C3AED; }
.dw-ibtn { border: 1px solid #CBD5E1; background: #fff; border-radius: 5px; min-width: 30px; height: 28px; padding: 0 6px; font-size: 14px; line-height: 1; cursor: pointer; color: #334155; }
.dw-ibtn:hover:not(:disabled) { background: #EDE9FE; border-color: #A78BFA; }
.dw-ibtn:disabled { opacity: .3; cursor: default; }
.dw-strength { display: inline-block; font-size: 13px; font-weight: 600; color: #047857; background: #ECFDF5; border: 1px solid #A7F3D0; border-radius: 999px; padding: 3px 10px; margin: 4px 0; }
.dw-warn { font-size: 13px; line-height: 1.6; background: #FEF3C7; border-left: 3px solid #F59E0B; border-radius: 6px; padding: 10px 12px; margin: 10px 0; }
.dw-actions { display: flex; flex-wrap: wrap; gap: 8px; margin: 8px 0; }
.dw-btn { border: 1px solid #CBD5E1; background: #fff; border-radius: 8px; padding: 8px 12px; font-size: 13px; cursor: pointer; }
.dw-btn:hover { background: #F1F5F9; }
.dw-btn-primary { background: #5B21B6; color: #fff; border-color: #5B21B6; font-weight: 600; }
.dw-btn-primary:hover { background: #7C3AED; }
.dw-dicegrid { list-style: none; padding: 0; margin: 8px 0; display: grid; gap: 6px; }
.dw-dicerow { display: flex; align-items: center; gap: 8px; }
.dw-dicerow input { width: 7em; padding: 7px 9px; font-size: 15px; letter-spacing: 2px; border: 1px solid #CBD5E1; border-radius: 6px; font-variant-numeric: tabular-nums; }
.dw-dicerow .dw-diceword { font-size: 14px; }
.dw-link { background: none; border: 0; color: #5B21B6; text-decoration: underline; cursor: pointer; font-size: 13px; padding: 0; }
#print-master-memo { display: none; }
@media print {
  body.dw-printing > *:not(#print-master-memo) { display: none !important; }
  body.dw-printing #print-master-memo { display: block !important; color: #000; background: #fff;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Hiragino Sans", "Noto Sans JP", system-ui, sans-serif; }
  #print-master-memo h1 { font-size: 18pt; margin: 0 0 3mm; }
  #print-master-memo .pmm-meta { font-size: 9pt; color: #333; margin-bottom: 5mm; line-height: 1.6; }
  #print-master-memo table { width: 100%; border-collapse: collapse; font-size: 13pt; margin: 2mm 0 5mm; }
  #print-master-memo th, #print-master-memo td { border: 1px solid #000; padding: 2.5mm 3mm; text-align: left; }
  #print-master-memo th { font-size: 9pt; background: #eee; }
  #print-master-memo td.pmm-no, #print-master-memo td.pmm-dice { font-variant-numeric: tabular-nums; font-size: 10pt; width: 12%; }
  #print-master-memo .pmm-warn { border: 1.5px solid #000; padding: 3mm; font-size: 9.5pt; line-height: 1.55; }
  #print-master-memo .pmm-warn ul { margin: 1mm 0 0 5mm; padding: 0; }
  #print-master-memo .pmm-drive { margin: 6mm 0 4mm; font-size: 10pt; border-bottom: 1px solid #000; padding-bottom: 6mm; }
  #print-master-memo .pmm-foot { font-size: 8pt; color: #555; margin-top: 5mm; }
}
`;

function ensureCss() {
  if (document.getElementById("dw-style")) return;
  const st = document.createElement("style");
  st.id = "dw-style";
  st.textContent = CSS;
  document.head.appendChild(st);
}

// つかみ所の 6 つの点 (⠿)。フォントによって点字の文字が出ないことがあるので絵で描く
const GRIP_SVG = '<svg width="10" height="16" viewBox="0 0 10 16" fill="currentColor" aria-hidden="true">'
  + [2, 8, 14].map((y) => `<circle cx="2" cy="${y}" r="1.6"/><circle cx="8" cy="${y}" r="1.6"/>`).join("") + "</svg>";

// いちばん近い、縦にスクロールする親 (なければ文書全体)。
// body も調べる: app.html はスマートフォンの幅で html, body に height: 100% と overflow-x: hidden を付けるので、
// body の overflow-y が auto になり、ページ全体ではなく body がスクロールする
function scrollParent(n) {
  for (let p = n.parentElement; p && p !== document.documentElement; p = p.parentElement) {
    const oy = getComputedStyle(p).overflowY;
    if ((oy === "auto" || oy === "scroll") && p.scrollHeight > p.clientHeight) return p;
  }
  return document.scrollingElement || document.documentElement;
}

// 欄 el のまわりのスクロールの位置 (縦にスクロールする親と、文書全体) を覚え、settle() のあと 700ms のあいだ、
// ずれたらその位置に戻す (pickCand)。そのあいだに画面に指が触れたら、人が動かしているので戻すのをやめる。
// 最後に、そのときフォーカスのある欄が見えていなければ、見える所まで動かす。
function holdScroll(elm) {
  const targets = [];
  for (let p = elm.parentElement; p && p !== document.documentElement; p = p.parentElement) {
    const oy = getComputedStyle(p).overflowY;
    if ((oy === "auto" || oy === "scroll") && p.scrollHeight > p.clientHeight) targets.push(p);
  }
  const se = document.scrollingElement || document.documentElement;
  if (!targets.includes(se)) targets.push(se);
  const saved = targets.map((t) => [t, t.scrollTop]);
  const restore = () => { for (const [t, y] of saved) if (Math.abs(t.scrollTop - y) > 1) t.scrollTop = y; };
  let done = false;
  const onScroll = () => { if (!done) restore(); };
  const stop = () => {
    if (done) return;
    done = true;
    document.removeEventListener("scroll", onScroll, true);
    window.visualViewport?.removeEventListener("resize", onScroll);
    document.removeEventListener("touchstart", stop, true);
  };
  // blur の時点から見張る (キーボードが閉じかけたときのスクロールも戻す)
  document.addEventListener("scroll", onScroll, true);
  window.visualViewport?.addEventListener("resize", onScroll);
  document.addEventListener("touchstart", stop, true);
  return {
    settle() {
      if (done) return;
      restore();
      setTimeout(() => {
        if (done) return;
        restore();
        stop();
        const a = document.activeElement;
        if (!a || !a.getBoundingClientRect) return;
        const vv = window.visualViewport;
        const top = vv ? vv.offsetTop : 0, h = vv ? vv.height : window.innerHeight;
        const r = a.getBoundingClientRect();
        if (r.top < top || r.bottom > top + h) a.scrollIntoView({ block: "nearest" });
      }, 700);
    },
  };
}

function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k === "text") e.textContent = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children) if (c != null) e.append(c);
  return e;
}

// 決まった文言の要素には data-i18n を付ける。アプリの i18n.js (applyTranslations) が、
// 辞書を読み終えたときや言語を変えたときに、ここの文言も差し替えてくれる。
function tx(T, tag, attrs, key) {
  const e = el(tag, { ...attrs, "data-i18n": key, text: T(key) });
  return e;
}
function setTx(T, e, key) { e.setAttribute("data-i18n", key); e.textContent = T(key); }

function langSelect(current, onChange) {
  const sel = el("select", { "aria-label": "language" });
  for (const code of WORDLIST_LANGS) {
    const o = el("option", { value: code, text: LANG_NAMES[code] || code });
    if (code === current) o.selected = true;
    sel.append(o);
  }
  sel.addEventListener("change", () => onChange(sel.value));
  return sel;
}

// 入力に使う IME がある言語 (組み立て中に音節が確定していくので、頭だけで補完しない)
const NO_PREFIX_COMPLETE = new Set(["ko"]);

const LS_LANG = "arpass.diceWords.lang";
const LS_MODE = "arpass.diceWords.inputMode";
function lsGet(k) { try { return localStorage.getItem(k); } catch { return null; } }
function lsSet(k, v) { try { localStorage.setItem(k, v); } catch {} }

export function defaultDiceLang(uiLang) {
  const saved = lsGet(LS_LANG);
  if (saved && WORDLIST_LANGS.includes(saved)) return saved;
  return WORDLIST_LANGS.includes(uiLang) ? uiLang : "en";
}

// ---------------------------------------------------------------------------
// 1. 語ごとの入力欄
// ---------------------------------------------------------------------------

/**
 * @param {HTMLElement} container
 * @param {{ lang?: string, tr?: Function, onChange?: (indices:number[]|null, matcher)=>void,
 *           onSubmit?: Function, showLangSelect?: boolean, rememberLang?: boolean }} opts
 */
export function mountDiceInput(container, opts = {}) {
  ensureCss();
  const T = makeTr(opts.tr);
  let lang = opts.lang || "en";
  let matcher = null;
  let pending = null; // 頭で補完したあと、続けて打たれた文字を吸い込むための状態
  const n = MASTER_WORDS;
  const fields = [];

  const box = el("div", { class: "dw-box" });
  const status = el("div", { class: "dw-status", role: "status", "aria-live": "polite" });
  const jaHint = tx(T, "span", {}, "app.dice.ja_hint");
  const spacedHint = tx(T, "span", {}, "app.dice.spaced_hint");
  const hint = el("p", { class: "dw-hint" }, jaHint, " ", spacedHint, " ", tx(T, "span", {}, "app.dice.paste_hint"));
  const list = el("ol", { class: "dw-fields" });

  if (opts.showLangSelect !== false) {
    const row = el("div", { class: "dw-langrow" },
      tx(T, "span", {}, "app.dice.lang_label"),
      langSelect(lang, (v) => { if (opts.rememberLang !== false) lsSet(LS_LANG, v); setLang(v); }));
    box.append(row);
  }
  box.append(hint, list, status);
  container.append(box);

  for (let i = 0; i < n; i++) {
    const input = el("input", {
      type: "text", autocomplete: "off", autocapitalize: "off", autocorrect: "off",
      spellcheck: "false", "aria-label": T("app.dice.field_label", { n: i + 1 }),
      "data-lpignore": "true", "data-1p-ignore": "true", enterkeyhint: i === n - 1 ? "done" : "next",
    });
    const gloss = el("span", { class: "dw-gloss" });
    const cands = el("div", { class: "dw-cands", role: "listbox" });
    const li = el("li", { class: "dw-field" }, el("span", { class: "dw-num", text: String(i + 1) }), input, gloss, cands);
    list.append(li);
    const f = { i, input, gloss, cands, li, idx: -1, composing: false, afterCompose: null };
    fields.push(f);

    input.addEventListener("compositionstart", () => { f.composing = true; });
    input.addEventListener("compositionend", () => {
      f.composing = false;
      // 組み立て中に候補が押されていたら、その語で確定する (pickCand)。打った字での照合はしない。
      // blur() の中で知らせが来るブラウザもあるので、blur が済んでから動かす
      const run = f.afterCompose;
      if (run) { f.afterCompose = null; queueMicrotask(run); return; }
      evaluate(f, { auto: true });
    });
    input.addEventListener("beforeinput", (e) => onBeforeInput(f, e));
    input.addEventListener("input", (e) => {
      f.idx = -1;
      if (e.isComposing || f.composing) { evaluate(f, { composing: true }); return; }
      evaluate(f, { auto: e.inputType !== "deleteContentBackward" && e.inputType !== "deleteContentForward" });
    });
    input.addEventListener("keydown", (e) => onKeyDown(f, e));
    input.addEventListener("blur", () => {
      setTimeout(() => { if (document.activeElement && f.cands.contains(document.activeElement)) return; closeCands(f); }, 120);
      if (!f.composing) evaluate(f, { final: true });
    });
    input.addEventListener("paste", (e) => onPaste(f, e));
  }

  function updateHint() {
    jaHint.style.display = lang === "ja" ? "" : "none";
    spacedHint.style.display = SPACED_LANGS.has(lang) ? "" : "none";
    for (const f of fields) {
      f.input.lang = lang;
      f.input.dir = lang === "ar" ? "auto" : "ltr";
    }
  }

  function closeCands(f) { f.cands.classList.remove("dw-open"); f.cands.textContent = ""; }

  // enterIdx: 打った形とぴったり同じ語 (Enter か Tab で確定する)。先頭に出して印を付ける。
  function showCands(f, list, enterIdx = -1) {
    f.cands.textContent = "";
    if (!list.length || !matcher) { f.cands.classList.remove("dw-open"); return; }
    if (enterIdx >= 0) list = [enterIdx, ...list.filter((x) => x !== enterIdx)];
    for (const idx of list) {
      const loc = matcher.display(idx), en = matcher.english(idx);
      const b = el("button", { type: "button", class: "dw-cand" + (idx === enterIdx ? " dw-enter" : ""), role: "option", tabindex: "-1" }, loc);
      if (lang !== "en" && loc !== en) b.append(el("small", { text: en }));
      if (idx === enterIdx) b.append(el("span", { class: "dw-key", text: "↵" }));
      b.addEventListener("mousedown", (ev) => ev.preventDefault());
      b.addEventListener("click", () => pickCand(f, idx));
      f.cands.append(b);
    }
    f.cands.classList.add("dw-open");
  }

  // 候補を押した: その語で確定して次の欄へ。
  // かな入力などの組み立て中 (下線の付いた字が残っている間) に値を書き換えて次の欄へ移ると、iPhone (WebKit) では
  // 枠 (フォーカス) だけが次の欄に移り、キーボードは前の欄の組み立てのまま止まる (打っても何も入らず、欄を押し直す
  // 必要があった。2026-11-13 八巻さん)。先に欄から外して組み立てを確定させ、確定 (compositionend) が済んでから
  // 値を入れて次の欄へ移る。組み立て中でなければ、今までどおりすぐに移る。
  //   欄から外すと、iPhone ではキーボードが閉じかけて画面が元の位置へスクロールし、次の欄へ移るとまた動く
  //   (2026-11-13 八巻さん「移動時にスクロールして元の位置に毎回戻ります」)。押したときのスクロールの位置を覚えておき、
  //   次の欄へ移ったあと、しばらく (キーボードに合わせて画面が動く間) その位置に戻す (holdScroll)。
  //   組み立てを確定させる方法は blur のほかに見つからなかった (選択範囲を動かす・値を入れ直すは、iPhone では確定しない)。
  function pickCand(f, idx) {
    const hold = f.composing ? holdScroll(f.input) : null;
    const run = () => { confirm(f, idx, false); moveNext(f, hold ? { preventScroll: true } : undefined); hold?.settle(); };
    if (!f.composing) { run(); return; }
    f.afterCompose = run;
    f.input.blur();
    // 確定の知らせが来ないブラウザでも止まらないように
    setTimeout(() => {
      if (f.afterCompose !== run) return;
      f.afterCompose = null;
      f.composing = false;
      run();
    }, 300);
  }

  function setState(f, state) {
    f.li.classList.toggle("dw-ok", state === "ok");
    f.li.classList.toggle("dw-bad", state === "bad");
    f.input.setAttribute("aria-invalid", state === "bad" ? "true" : "false");
  }

  // 確定: 欄に表の語を入れる。英語で打ったなら英語、ほかはその言語の表示の形。
  function confirm(f, idx, viaEnglish) {
    f.idx = idx;
    const loc = matcher.display(idx), en = matcher.english(idx);
    f.input.value = viaEnglish ? en : loc;
    f.gloss.textContent = (!viaEnglish && lang !== "en" && loc !== en) ? en : "";
    setState(f, "ok");
    closeCands(f);
    changed();
  }

  function typedViaEnglish(text, idx) {
    return fold("en", text) === fold("en", matcher.english(idx)) ||
      (fold("en", matcher.english(idx)).startsWith(fold("en", text)) && /^[a-z]+$/.test(fold("en", text)));
  }

  function evaluate(f, { composing = false, final = false, auto = false } = {}) {
    if (!matcher) return;
    const v = f.input.value;
    f.gloss.textContent = "";
    if (!v.trim()) { f.idx = -1; setState(f, null); closeCands(f); changed(); return; }
    const cands = matcher.candidates(v, 9);
    if (composing) { setState(f, null); showCands(f, cands); changed(); return; }
    const exact = matcher.lookup(v);
    // ぴったり同じ語があっても、別の語の頭でもあるとき (pan / panda、rumah / rumah sakit) は
    // 自動では確定しない。Enter か Tab (final) で、ぴったり同じ語を確定する (6.4 節)。
    if (exact >= 0 && (cands.length <= 1 || final)) {
      const wasConfirmed = f.idx === exact;
      confirm(f, exact, typedViaEnglish(v, exact));
      if (auto && !wasConfirmed) moveNext(f);
      return;
    }
    if (cands.length === 1 && auto && !NO_PREFIX_COMPLETE.has(lang) && [...fold(lang, v)].length >= 2) {
      // 頭だけで 1 語に決まった: 補完して次の欄へ。続けて打たれた残りの文字は吸い込む。
      const idx = cands[0];
      const viaEn = typedViaEnglish(v, idx);
      const typed = fold(lang, v);
      const full = fold(lang, viaEn ? matcher.english(idx) : matcher.display(idx));
      confirm(f, idx, viaEn);
      // 残りの文字は、次に入力を受ける欄で吸い込む。最後の欄では次の欄がないので同じ欄で、
      // 埋まった欄へ移ったときはその語を変えずに吸い込む (keep: その欄の今の値)。
      const target = moveNext(f) || f;
      if (full.startsWith(typed)) pending = { field: target, rest: [...full.slice(typed.length)], keep: target.input.value };
      return;
    }
    f.idx = -1;
    if (cands.length === 0 || final) {
      setState(f, "bad");
      f.gloss.textContent = T("app.dice.not_in_list");
      closeCands(f);
    } else {
      setState(f, null);
      showCands(f, cands, exact);
    }
    changed();
  }

  function onBeforeInput(f, e) {
    if (!pending || pending.field !== f) { pending = null; return; }
    if (e.inputType !== "insertText" || f.input.value !== pending.keep) { pending = null; return; }
    const ch = e.data || "";
    if (ch && fold(lang, ch) === "") {
      // 空白や、照合で消える字 (インドネシア語のハイフンなど) は吸い込む。語の中に空白を
      // 認める言語では、補完した語の残りがあるあいだは吸い込み続ける (rumah sakit jiwa)。
      e.preventDefault();
      if (!SPACED_LANGS.has(lang) || !pending.rest.length) pending = null;
      return;
    }
    if (pending.rest.length && fold(lang, ch) === pending.rest[0]) {
      e.preventDefault();
      pending.rest.shift();
      return;
    }
    pending = null;
  }

  function onKeyDown(f, e) {
    if (e.isComposing || f.composing || e.keyCode === 229) return;
    if (e.key === "Enter") {
      e.preventDefault();
      evaluate(f, { final: true });
      if (f.idx >= 0) {
        if (value()) { opts.onSubmit?.(); return; }
        moveNext(f);
      }
      return;
    }
    if (e.key === " " && !SPACED_LANGS.has(lang)) {
      e.preventDefault();
      if (!f.input.value.trim()) return;
      evaluate(f, { final: true });
      if (f.idx >= 0) moveNext(f);
      return;
    }
    if (e.key === "Backspace" && f.input.value === "" && f.i > 0) {
      e.preventDefault();
      const prev = fields[f.i - 1].input;
      prev.focus();
      const L = prev.value.length; prev.setSelectionRange(L, L);
      return;
    }
    if (e.key === "ArrowDown" && f.cands.classList.contains("dw-open")) {
      e.preventDefault();
      f.cands.querySelector("button")?.focus();
    }
    if (e.key === "Escape") closeCands(f);
  }

  function onPaste(f, e) {
    const text = e.clipboardData?.getData("text") ?? "";
    if (!matcher) return;
    const parts = matcher.split(text, n - f.i);
    if (parts === null) {
      // 語の中に空白を認める言語で、分け方が 1 つに決まらない: 欄には入れない (6.4 節)
      e.preventDefault();
      status.textContent = T("app.dice.paste_ambiguous");
      status.classList.remove("dw-done");
      status.classList.add("dw-err");
      return;
    }
    if (parts.length <= 1) return; // 1 語なら普通に貼る
    e.preventDefault();
    let k = f.i;
    for (const part of parts) {
      if (k >= n) break;
      const g = fields[k];
      g.input.value = part;
      g.idx = -1;
      evaluate(g, { final: true });
      k++;
    }
    const nextEmpty = fields.find((g) => g.idx < 0) || fields[Math.min(k, n - 1)];
    nextEmpty.input.focus();
  }

  function moveNext(f, focusOpts) {
    const next = fields.slice(f.i + 1).find((g) => g.idx < 0) || fields[f.i + 1];
    if (next) next.input.focus(focusOpts);
    return next || null;
  }

  function value() {
    if (fields.some((f) => f.idx < 0)) return null;
    return fields.map((f) => f.idx);
  }

  // 8 語の組が変わったときだけ知らせる (読み込みが終わっただけでは呼ばない)
  let lastKey = "";
  function changed() {
    const v = value();
    const left = fields.filter((f) => f.idx < 0).length;
    status.classList.remove("dw-err");
    status.classList.toggle("dw-done", !!v);
    status.textContent = v ? T("app.dice.status_done") : (left < n ? T("app.dice.status_left", { n: left }) : "");
    const key = v ? v.join(",") + "@" + lang : "";
    if (key === lastKey) return;
    lastKey = key;
    opts.onChange?.(v, matcher);
  }

  async function setLang(l) {
    lang = WORDLIST_LANGS.includes(l) ? l : "en";
    updateHint();
    status.classList.remove("dw-done", "dw-err");
    status.textContent = T("app.dice.loading");
    for (const f of fields) f.input.disabled = true;
    try {
      const m = await loadMatcher(lang);
      if (m.lang !== lang) return;
      matcher = m;
      for (const f of fields) { f.input.disabled = false; if (f.input.value.trim()) { f.idx = -1; evaluate(f, { final: true }); } }
      changed();
    } catch (e) {
      console.warn("[dicewords] load failed:", e?.message || e);
      status.textContent = T("app.dice.load_failed");
      status.classList.add("dw-err");
      for (const f of fields) f.input.disabled = false;
    }
  }

  updateHint();
  const ready = setLang(lang);

  return {
    ready,
    value,
    get lang() { return lang; },
    get matcher() { return matcher; },
    setLang,
    focus() { (fields.find((f) => f.idx < 0) || fields[0]).input.focus(); },
    clear() {
      pending = null;
      for (const f of fields) { f.afterCompose = null; f.input.value = ""; f.idx = -1; f.gloss.textContent = ""; setState(f, null); closeCands(f); }
      status.textContent = "";
      status.classList.remove("dw-done", "dw-err");
      lastKey = "";
      opts.onChange?.(null, matcher);
    },
    setError(msg) { status.textContent = msg; status.classList.remove("dw-done"); status.classList.add("dw-err"); },
    destroy() { box.remove(); },
  };
}

// ---------------------------------------------------------------------------
// 2. 今のマスターを入れる欄 (解錠・端末の追加など)
//    「ダイスの言葉」と「文字で入力」を切り替える。文字で入力の欄は元の input そのまま。
// ---------------------------------------------------------------------------

/**
 * @param {HTMLInputElement} pwInput 既存の <input type="password">
 * @param {{ tr?: Function, uiLang?: string, onSubmit?: Function, defaultMode?: "dice"|"text" }} opts
 */
export function mountMasterInput(pwInput, opts = {}) {
  ensureCss();
  const T = makeTr(opts.tr);
  const outer = pwInput.closest(".pw-wrap") || pwInput;
  const tabs = el("div", { class: "dw-tabs", role: "tablist" });
  const tDice = tx(T, "button", { type: "button", class: "dw-tab", role: "tab" }, "app.dice.mode_dice");
  const tText = tx(T, "button", { type: "button", class: "dw-tab", role: "tab" }, "app.dice.mode_text");
  tabs.append(tDice, tText);
  const diceWrap = el("div");
  const textHint = tx(T, "p", { class: "dw-hint" }, "app.dice.text_hint");
  outer.parentNode.insertBefore(tabs, outer);
  outer.parentNode.insertBefore(diceWrap, outer);
  outer.parentNode.insertBefore(textHint, outer.nextSibling);

  let mode = null;
  let dice = null;
  const setPw = (s) => {
    pwInput.value = s;
    pwInput.dispatchEvent(new Event("input", { bubbles: true }));
  };

  function setMode(m, { save = true, focus = false, clear = true } = {}) {
    if (m === mode) return;
    mode = m;
    if (save) lsSet(LS_MODE, m);
    tDice.setAttribute("aria-selected", m === "dice" ? "true" : "false");
    tText.setAttribute("aria-selected", m === "text" ? "true" : "false");
    // 切り替えたら、前の方式で入れた値は消す (最初に付けたときは、すでに入っている値を残す)
    if (clear) setPw("");
    if (m === "dice") {
      outer.style.display = "none";
      textHint.style.display = "none";
      diceWrap.style.display = "";
      if (!dice) {
        dice = mountDiceInput(diceWrap, {
          tr: opts.tr,
          lang: defaultDiceLang(opts.uiLang || "en"),
          onChange: (idx, matcher) => setPw(idx && matcher ? masterFromIndices(idx, matcher.english) : ""),
          onSubmit: opts.onSubmit,
        });
      } else if (clear) {
        dice.clear();
      }
      if (focus) dice.ready.then(() => dice.focus());
    } else {
      outer.style.display = "";
      textHint.style.display = "";
      diceWrap.style.display = "none";
      if (clear) dice?.clear();
      if (focus) pwInput.focus();
    }
  }
  tDice.addEventListener("click", () => setMode("dice", { focus: true }));
  tText.addEventListener("click", () => setMode("text", { focus: true }));

  const saved = lsGet(LS_MODE);
  setMode(saved === "text" || saved === "dice" ? saved : (opts.defaultMode || "dice"), { save: false, clear: false });

  return {
    get mode() { return mode; },
    setMode,
    clear() { setPw(""); dice?.clear(); },
    focus() { if (mode === "dice") dice?.ready.then(() => dice.focus()); else pwInput.focus(); },
    setError(msg) { if (mode === "dice") dice?.setError(msg); },
  };
}

// ---------------------------------------------------------------------------
// 3. 作る画面 / 変える画面 (ダイスの言葉 8 語だけ。自分で決めるマスターは出さない)
//    出た 8 語は、物語にするために並べ替えられる (↑↓)。なじみのない語は、その語だけを
//    乱数の別の語に差し替えられる (↻、何度でも)。2026-11-09 に八巻さんが決めた。
// ---------------------------------------------------------------------------

/**
 * @param {HTMLElement} container
 * @param {{ tr?: Function, uiLang?: string, introKey?: string,
 *           onConfirmed: (master:string)=>void, onInvalidate?: ()=>void }} opts
 */
export function mountMasterCreate(container, opts = {}) {
  ensureCss();
  const T = makeTr(opts.tr);
  let lang = defaultDiceLang(opts.uiLang || "en");
  let matcher = null;
  let indices = null;
  // slots[k]: indices[k] が最初に出たときの位置。並べ替えたかどうか (強さの表示) を見るのに使う。
  // サイコロで作るときは null (目を入れる順は人が決めるので、出た順がない)。
  let slots = null;
  let useDice = false;
  let confirmInput = null;

  const root = el("div", { class: "dw-box" });
  container.append(root);
  const stepA = el("div");
  const stepB = el("div");
  root.append(stepA, stepB);

  const status = el("div", { class: "dw-status" });
  const words = el("ol", { class: "dw-words", "aria-live": "polite" });
  const diceGrid = el("ol", { class: "dw-dicegrid" });
  const diceInputs = [];

  const regenBtn = tx(T, "button", { type: "button", class: "dw-btn" }, "app.dice.regenerate");
  const modeBtn = el("button", { type: "button", class: "dw-link" });
  const printBtn = tx(T, "button", { type: "button", class: "dw-btn" }, "app.dice.print_btn");
  const nextBtn = tx(T, "button", { type: "button", class: "dw-btn dw-btn-primary" }, "app.dice.written_btn");
  const strengthEl = tx(T, "div", { class: "dw-strength" }, "app.dice.strength");
  const arrangeHint = tx(T, "p", { class: "dw-hint" }, "app.dice.arrange_hint");

  // introKey: null で説明を出さない (作る画面は、上に同じ説明があるため)
  if (opts.introKey !== null) stepA.append(tx(T, "p", { class: "dw-hint" }, opts.introKey || "app.dice.create_intro"));
  stepA.append(
    el("div", { class: "dw-langrow" },
      tx(T, "span", {}, "app.dice.paper_lang"),
      langSelect(lang, (v) => { lsSet(LS_LANG, v); setLang(v); })),
    strengthEl,
    words, arrangeHint, diceGrid,
    el("div", { class: "dw-actions" }, regenBtn, modeBtn),
    tx(T, "p", { class: "dw-hint" }, "app.dice.copy_hint"),
    tx(T, "div", { class: "dw-warn" }, "app.dice.separate_warn"),
    el("div", { class: "dw-actions" }, printBtn, nextBtn),
    status,
  );

  for (let i = 0; i < MASTER_WORDS; i++) {
    const inp = el("input", { type: "text", inputmode: "numeric", maxlength: "4", autocomplete: "off",
      "aria-label": T("app.dice.field_label", { n: i + 1 }), placeholder: "1–6 ×4" });
    const out = el("span", { class: "dw-diceword" });
    diceGrid.append(el("li", { class: "dw-dicerow" }, el("span", { class: "dw-num", text: String(i + 1) }), inp, out));
    diceInputs.push({ inp, out });
    inp.addEventListener("input", () => {
      inp.value = inp.value.normalize("NFKC").replace(/[^1-6]/g, "").slice(0, 4);
      readDice();
      if (inp.value.length === 4 && diceInputs[i + 1]) diceInputs[i + 1].inp.focus();
    });
  }

  function reordered() { return !!slots && slots.some((x, k) => x !== k); }
  function strengthKey() { return reordered() ? "app.dice.strength_reordered" : "app.dice.strength"; }
  function updateStrength() { setTx(T, strengthEl, strengthKey()); }

  function renderWords() {
    words.textContent = "";
    updateStrength();
    if (!indices || !matcher) return;
    const last = indices.length - 1;
    indices.forEach((idx, k) => {
      const loc = matcher.display(idx), en = matcher.english(idx);
      const ib = (cls, text, key, disabled, fn) => {
        const b = el("button", { type: "button", class: "dw-ibtn " + cls, text, disabled,
          "aria-label": T(key, { n: k + 1 }), title: T(key, { n: k + 1 }) });
        b.addEventListener("click", fn);
        return b;
      };
      // つかみ所は指とマウス用。キーボードと読み上げは ↑↓ のボタンで並べ替える
      const grip = el("span", { class: "dw-grip", "aria-hidden": "true", title: T("app.dice.drag") });
      grip.innerHTML = GRIP_SVG;
      grip.addEventListener("pointerdown", (e) => startDrag(e, li));
      grip.addEventListener("pointermove", dragMove);
      grip.addEventListener("pointerup", (e) => endDrag(e, false));
      grip.addEventListener("pointercancel", (e) => endDrag(e, true));
      grip.addEventListener("lostpointercapture", (e) => endDrag(e, false));
      const li = el("li", { class: "dw-word", "data-k": String(k) },
        grip,
        el("span", { class: "dw-num", text: String(k + 1) }),
        el("span", { class: "dw-wmain" },
          el("b", { text: loc, lang }),
          (lang !== "en" && loc !== en) ? el("span", { class: "dw-wen", text: en }) : null,
          el("span", { class: "dw-wdice", text: "🎲 " + indexToDice(idx) })),
        el("span", { class: "dw-wbtns" },
          ib("dw-up", "↑", "app.dice.move_up", k === 0, () => move(k, -1)),
          ib("dw-down", "↓", "app.dice.move_down", k === last, () => move(k, 1)),
          ib("dw-rep", "↻", "app.dice.replace", false, () => replaceWord(k))));
      words.append(li);
    });
  }

  // 並べ替え: 隣と入れ替える。押したボタンに焦点を残す (続けて押せるように)
  function move(k, d) {
    const j = k + d;
    if (!indices || j < 0 || j >= indices.length) return;
    [indices[k], indices[j]] = [indices[j], indices[k]];
    [slots[k], slots[j]] = [slots[j], slots[k]];
    changedWords();
    const li = words.children[j];
    const want = li?.querySelector(d < 0 ? ".dw-up" : ".dw-down");
    (want && !want.disabled ? want : li?.querySelector(d < 0 ? ".dw-down" : ".dw-up"))?.focus();
  }

  // ドラッグで並べ替え (つかみ所 ⠿)。HTML の drag and drop は iPhone の指では動かないので、
  // pointer events で作る。つかんだ行は指に付いてきて、ほかの行は空いた所へ詰める。
  // 置き場所は、つかんだ行の中心にいちばん近い行の位置 (列が 2 つ以上でも同じ考え方で決まる)。
  // 離したときに indices と slots を並べ直す。途中で取り消されたら (pointercancel) 元の順に戻す。
  let drag = null;

  function startDrag(e, li) {
    if (drag || !indices || (e.pointerType === "mouse" && e.button !== 0)) return;
    e.preventDefault();
    const grip = e.currentTarget;
    try { grip.setPointerCapture(e.pointerId); } catch { /* 取れなくても動かせる */ }
    const r = li.getBoundingClientRect();
    drag = { li, id: e.pointerId, x: e.clientX, y: e.clientY,
      offX: e.clientX - r.left, offY: e.clientY - r.top, raf: 0, scroller: scrollParent(words) };
    drag.overTop = overlayBottom(drag.scroller);
    li.classList.add("dw-dragging");
    words.classList.add("dw-sorting");
    drag.raf = requestAnimationFrame(autoScroll);
  }

  function dragMove(e) {
    if (!drag || e.pointerId !== drag.id) return;
    e.preventDefault();
    drag.x = e.clientX;
    drag.y = e.clientY;
    placeDragged();
  }

  function placeDragged() {
    const { li } = drag;
    const lr = words.getBoundingClientRect();
    const left = drag.x - lr.left - drag.offX, top = drag.y - lr.top - drag.offY;
    const cx = left + li.offsetWidth / 2, cy = top + li.offsetHeight / 2;
    const items = [...words.children];
    let to = 0, best = Infinity;
    items.forEach((it, i) => {
      const dx = cx - (it.offsetLeft + it.offsetWidth / 2), dy = cy - (it.offsetTop + it.offsetHeight / 2);
      const d = dx * dx + dy * dy;
      if (d < best) { best = d; to = i; }
    });
    const from = items.indexOf(li);
    if (to !== from) {
      // つかんだ行そのものは DOM の中で動かさない (動かすと pointer capture が外れるブラウザがある)。
      // 間の行を前後に移す
      slide(items.filter((it) => it !== li), () => {
        if (to > from) for (let i = from + 1; i <= to; i++) words.insertBefore(items[i], li);
        else { const after = li.nextSibling; for (let i = to; i < from; i++) words.insertBefore(items[i], after); }
      });
      [...words.children].forEach((it, i) => { const n = it.querySelector(".dw-num"); if (n) n.textContent = String(i + 1); });
    }
    li.style.transform = `translate(${left - li.offsetLeft}px, ${top - li.offsetTop}px)`;
  }

  // 詰める行を、元の場所から新しい場所へすべらせる (FLIP)
  function slide(others, mutate) {
    const before = others.map((it) => [it.offsetLeft, it.offsetTop]);
    mutate();
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    others.forEach((it, i) => {
      const dx = before[i][0] - it.offsetLeft, dy = before[i][1] - it.offsetTop;
      if (!dx && !dy) return;
      it.style.transition = "none";
      it.style.transform = `translate(${dx}px, ${dy}px)`;
      void it.offsetWidth;
      it.style.transition = "transform .15s ease";
      it.style.transform = "";
    });
  }

  // 指が画面の上端・下端に近いときは、その方向へ少しずつスクロールする
  // (つかみ所の上ではページがスクロールしないので、長い一覧の端へ運べるように)
  function autoScroll() {
    if (!drag) return;
    const sc = drag.scroller;
    const isDoc = sc === document.scrollingElement || sc === document.documentElement;
    const vh = window.visualViewport?.height ?? window.innerHeight;
    const r = isDoc ? { top: 0, bottom: vh } : sc.getBoundingClientRect();
    const top = Math.max(r.top, 0, drag.overTop), bottom = Math.min(r.bottom, vh), edge = 48;
    // 一覧の端が端の帯より内側に見えたら、その方向へは進めない (一覧の外までスクロールしない。
    // 帯の分だけ余分に進めるのは、Safari の下のツールバーのように重なる物があっても最後の語が見えるように)
    const lr = words.getBoundingClientRect();
    let v = 0;
    if (drag.y < top + edge && lr.top < top + edge) v = -Math.ceil((top + edge - drag.y) / 4);
    else if (drag.y > bottom - edge && lr.bottom > bottom - edge) v = Math.ceil((drag.y - (bottom - edge)) / 4);
    if (v) {
      const was = sc.scrollTop;
      sc.scrollTop = was + Math.max(-14, Math.min(14, v));
      if (sc.scrollTop !== was) placeDragged();
    }
    drag.raf = requestAnimationFrame(autoScroll);
  }

  // スクロールする箱の上に固定で重なっている物 (app.html の上のヘッダーは sticky) の下端。
  // 上の端の帯はそこから測る (ヘッダーの裏に隠れた所へ運ぶときに、ヘッダーの上まで指を運ばなくてよいように)。
  // 一覧を含む物 (モーダルの背景など) は重なっている物ではないので数えない
  function overlayBottom(sc) {
    const isDoc = sc === document.scrollingElement || sc === document.documentElement;
    const y = (isDoc ? 0 : Math.max(sc.getBoundingClientRect().top, 0)) + 1;
    let el = document.elementFromPoint(words.getBoundingClientRect().left + 1, y);
    for (; el && el !== document.body && el !== document.documentElement; el = el.parentElement) {
      const pos = getComputedStyle(el).position;
      if ((pos === "fixed" || pos === "sticky") && !el.contains(words)) return el.getBoundingClientRect().bottom;
    }
    return 0;
  }

  function endDrag(e, cancel) {
    if (!drag || e.pointerId !== drag.id) return;
    const { li } = drag;
    cancelAnimationFrame(drag.raf);
    drag = null;
    words.classList.remove("dw-sorting");
    if (!words.contains(li) || !indices) return;
    const order = [...words.children].map((it) => Number(it.dataset.k));
    if (cancel || order.every((k, i) => k === i)) { renderWords(); return; }
    indices = order.map((k) => indices[k]);
    slots = slots && order.map((k) => slots[k]);
    changedWords();
  }

  // 差し替え: その語だけを乱数の別の語にする (今の 8 語にない語)。位置 (slots) は変えない
  function replaceWord(k) {
    if (!indices) return;
    let v;
    do { v = randomIndices(1)[0]; } while (indices.includes(v));
    indices[k] = v;
    changedWords();
    words.children[k]?.querySelector(".dw-rep")?.focus();
  }

  function changedWords() {
    invalidate();
    renderWords();
  }

  function readDice() {
    const got = diceInputs.map(({ inp, out }) => {
      const idx = diceToIndex(inp.value);
      out.textContent = "";
      if (inp.value.length === 4 && idx < 0) out.textContent = T("app.dice.dice_invalid");
      if (idx >= 0 && matcher) {
        const loc = matcher.display(idx), en = matcher.english(idx);
        out.textContent = (lang !== "en" && loc !== en) ? `${loc} (${en})` : en;
      }
      return idx;
    });
    const ok = got.every((x) => x >= 0);
    setIndices(ok ? got : null, { render: false });
  }

  function setIndices(v, { render = true } = {}) {
    indices = v;
    slots = v && !useDice ? v.map((_, k) => k) : null;
    invalidate();
    if (render) renderWords();
    printBtn.disabled = !indices;
    nextBtn.disabled = !indices;
  }

  function generate() { setIndices(randomIndices(MASTER_WORDS)); }

  function setMode(dice) {
    useDice = dice;
    setTx(T, modeBtn, dice ? "app.dice.use_random" : "app.dice.use_dice");
    regenBtn.style.display = dice ? "none" : "";
    words.style.display = dice ? "none" : "";
    arrangeHint.style.display = dice ? "none" : "";
    diceGrid.style.display = dice ? "" : "none";
    if (dice) {
      for (const d of diceInputs) { d.inp.value = ""; d.out.textContent = ""; }
      setIndices(null);
      status.textContent = T("app.dice.dice_hint");
      diceInputs[0].inp.focus();
    } else {
      status.textContent = "";
      generate();
    }
  }

  async function setLang(l) {
    lang = l;
    try {
      matcher = await loadMatcher(lang);
      status.classList.remove("dw-err");
      renderWords();
      if (useDice) readDice();
      if (confirmInput) confirmInput.setLang(lang);
    } catch (e) {
      status.textContent = T("app.dice.load_failed");
      status.classList.add("dw-err");
    }
  }

  function invalidate() {
    if (confirmInput) { confirmInput.destroy(); confirmInput = null; }
    stepB.textContent = "";
    stepB.style.display = "none";
    stepA.style.display = "";
    opts.onInvalidate?.();
  }

  function toConfirm() {
    if (!indices) return;
    stepA.style.display = "none";
    stepB.style.display = "";
    stepB.textContent = "";
    const cStatus = el("div", { class: "dw-status" });
    const back = tx(T, "button", { type: "button", class: "dw-link" }, "app.dice.back_to_words");
    back.addEventListener("click", () => {
      if (confirmInput) { confirmInput.destroy(); confirmInput = null; }
      stepB.style.display = "none"; stepA.style.display = "";
      opts.onInvalidate?.();
    });
    stepB.append(tx(T, "p", { class: "dw-hint" }, "app.dice.confirm_intro"));
    const holder = el("div");
    stepB.append(holder, cStatus, el("div", { class: "dw-actions" }, back));
    const want = indices.slice();
    confirmInput = mountDiceInput(holder, {
      tr: opts.tr, lang,
      onChange: (v, m) => {
        if (!v) { cStatus.textContent = ""; cStatus.className = "dw-status"; opts.onInvalidate?.(); return; }
        if (v.every((x, k) => x === want[k])) {
          cStatus.textContent = T("app.dice.confirm_ok");
          cStatus.className = "dw-status dw-done";
          opts.onConfirmed?.(masterFromIndices(want, m.english));
        } else {
          cStatus.textContent = T("app.dice.confirm_mismatch");
          cStatus.className = "dw-status dw-err";
          opts.onInvalidate?.();
        }
      },
    });
    confirmInput.ready.then(() => confirmInput?.focus());
  }

  regenBtn.addEventListener("click", generate);
  modeBtn.addEventListener("click", () => setMode(!useDice));
  printBtn.addEventListener("click", () => { if (indices && matcher) printMasterMemo({ indices, matcher, tr: opts.tr, strengthKey: strengthKey() }); });
  nextBtn.addEventListener("click", toConfirm);

  stepB.style.display = "none";
  const ready = setLang(lang).then(() => setMode(false));

  return {
    ready,
    reset() {
      // 作り終えたら、画面から語を消す (メモリに残る時間を短くする)
      indices = null;
      slots = null;
      words.textContent = "";
      for (const d of diceInputs) { d.inp.value = ""; d.out.textContent = ""; }
      invalidate();
      setMode(false);
    },
    destroy() { indices = null; invalidate(); root.remove(); },
  };
}

// ---------------------------------------------------------------------------
// 4. マスターのメモを印刷 (Recovery キットと同じ作り。PDF のライブラリは使わない)
// ---------------------------------------------------------------------------
export function printMasterMemo({ indices, matcher, tr, strengthKey = "app.dice.strength" }) {
  ensureCss();
  const T = makeTr(tr);
  let host = document.getElementById("print-master-memo");
  if (!host) {
    host = el("div", { id: "print-master-memo", "aria-hidden": "true" });
    document.body.append(host);
  }
  host.textContent = "";
  const lang = matcher.lang;
  const table = el("table");
  const head = el("tr", {}, el("th", { text: T("app.dice.memo_col_no") }), el("th", { text: T("app.dice.memo_col_word") + ` (${LANG_NAMES[lang] || lang})` }));
  if (lang !== "en") head.append(el("th", { text: T("app.dice.memo_col_en") }));
  head.append(el("th", { text: T("app.dice.memo_col_dice") }));
  table.append(head);
  indices.forEach((idx, k) => {
    const tr2 = el("tr", {}, el("td", { class: "pmm-no", text: String(k + 1) }), el("td", { text: matcher.display(idx), lang }));
    if (lang !== "en") tr2.append(el("td", { text: matcher.english(idx) }));
    tr2.append(el("td", { class: "pmm-dice", text: indexToDice(idx) }));
    table.append(tr2);
  });
  const ul = el("ul");
  for (const k of ["memo_warn_1", "memo_warn_2", "memo_warn_3", "memo_warn_4"]) ul.append(el("li", { text: T("app.dice." + k) }));
  host.append(
    el("h1", { text: "🔑 " + T("app.dice.memo_title") }),
    el("div", { class: "pmm-meta" },
      `${T("app.dice.memo_date")}: ${new Date().toISOString().slice(0, 10)}`, el("br"),
      `${T("app.dice.memo_list")}: ${LANG_NAMES[lang] || lang} · ${WORDLIST_ID} · ${T(strengthKey)}`),
    table,
    el("div", { class: "pmm-drive", text: T("app.dice.memo_drive") }),
    el("div", { class: "pmm-warn" }, el("strong", { text: T("app.dice.memo_warn_title") }), ul),
    el("p", { class: "pmm-foot", text: T("app.dice.memo_restore") + " — arpass.io/arpass-emergency-restore.html · github.com/technoblest/arpass-spec" }),
  );
  document.body.classList.add("dw-printing");
  const cleanup = () => {
    document.body.classList.remove("dw-printing");
    host.textContent = "";
    window.removeEventListener("afterprint", cleanup);
  };
  window.addEventListener("afterprint", cleanup);
  requestAnimationFrame(() => requestAnimationFrame(() => {
    window.print();
    setTimeout(cleanup, 1000);
  }));
}

export { MASTER_BITS, MASTER_BITS_REORDERED };
