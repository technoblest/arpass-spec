// ============================================================================
// web/lib/qr.js
//
// QR コード生成・スキャンの薄いラッパー。
//
// 生成: qrcode-generator (Kazuhiko Arase / MIT, vendored at lib/vendor/) を
//       使い、SVG 文字列または Canvas 上に描画する。
//
// スキャン: BarcodeDetector ネイティブ API を優先、未対応環境でのみ jsQR
//          (Cosmo Wolfe / Apache-2.0, vendored at lib/vendor/) を遅延読み込み。
//          jsQR は ~250 KB あるので、対応環境では一切ロードしない。
//
// セキュリティ方針:
//   - QR の中身は Recovery Secret 文字列「のみ」。メタデータは入れない
//     (写真撮影されたとき、QR スキャナアプリで用途がバレないようにするため)。
//   - PDF ライブラリは一切使わない (Downloads 残留・iCloud 同期リスク)。
//     印刷は呼び出し側の window.print() に任せる。
//   - スキャナのカメラフレームはメモリ内のみ、ファイル書き出しなし。
// ============================================================================

import { qrcode } from "./vendor/qrcode-generator.mjs";

// ---------------------------------------------------------------------------
// 生成
// ---------------------------------------------------------------------------

/**
 * テキストから QR の SVG 文字列を生成する。
 *
 * Recovery Secret (RS1-XXXX-... 43 文字, 大文字英数 + ハイフン) を想定。
 * QR のバージョン (= 解像度) と誤り訂正レベルを Recovery 用に最適化:
 *   - typeNumber: 4 (33×33 セル) — alphanumeric mode で 50 文字まで入る
 *                                  (Level Q でも余裕)
 *   - errorCorrectionLevel: 'Q' (25% の冗長度) — 紙が折れたり汚れても読める
 *
 * 別用途で QR を作るときは options で typeNumber / level を上書き可能。
 */
export function generateQrSvg(text, opts = {}) {
  const {
    typeNumber = 4,
    level = "Q",
    cellSize = 6,
    margin = 4,
  } = opts;

  const qr = qrcode(typeNumber, level);
  qr.addData(text);
  qr.make();
  return qr.createSvgTag({ cellSize, margin, scalable: true });
}

// Phase 7.5Z: hwkey 端末追加コード用 QR 生成。
//   コード形式は "AP1-<credentialId b64u>-<tagName>-<tagValue>" で長さ ~80 chars。
//   Recovery 用とは別関数にして lint:security #5 (= generateQrSvg は Recovery
//   専用) に違反しないようにする。 内部は同じ qrcode-generator を使う。
//
//   AP1 コードは公開情報 (credentialId / tagName / tagValue は元から公開) なので
//   QR を覗かれても vault のセキュリティ影響はない (= Recovery とは性質が異なる)。
export function generateDeviceAddQrSvg(text, opts = {}) {
  // Phase 7.5Z hotfix: typeNumber=6 では Level Q byte mode の容量 76 byte
  //   しかなく、 ~100 byte の AP1- コードが overflow していた (user 報告)。
  //   typeNumber=12 + Level M で 367 byte 収容、 余裕を持って ~150 byte
  //   コードまで安全 (= 将来 credentialサイズが伸びても余裕あり)。
  const {
    typeNumber = 12,   // 65×65、 Level M で 367 byte
    level = "M",
    cellSize = 4,
    margin = 4,
  } = opts;
  const qr = qrcode(typeNumber, level);
  qr.addData(text);
  qr.make();
  return qr.createSvgTag({ cellSize, margin, scalable: true });
}

// 2026-10-28: 2段階認証 (TOTP) の otpauth:// URI 用 QR。 緊急復旧ツール
//   (emergency-restore-main.js) が他の認証アプリへ秘密キーを移すためだけに使う
//   (docs/totp-spec.md §2-5 / §7-4。 lint:security で呼び出し元を緊急復旧ツールに限定)。
//   URI の長さは秘密キーと発行元・アカウント名で変わるので typeNumber は自動 (0)。
export function generateOtpauthQrSvg(text, opts = {}) {
  const {
    typeNumber = 0,
    level = "M",
    cellSize = 4,
    margin = 4,
  } = opts;
  const qr = qrcode(typeNumber, level);
  qr.addData(text);
  qr.make();
  return qr.createSvgTag({ cellSize, margin, scalable: true });
}

/** 既存の <canvas> に QR を描画する。 */
export function drawQrOnCanvas(canvas, text, opts = {}) {
  const {
    typeNumber = 4,
    level = "Q",
    cellSize = 6,
    margin = 4,
  } = opts;

  const qr = qrcode(typeNumber, level);
  qr.addData(text);
  qr.make();

  const moduleCount = qr.getModuleCount();
  const sideCells = moduleCount + margin * 2;
  const sidePx = sideCells * cellSize;
  canvas.width = sidePx;
  canvas.height = sidePx;

  const ctx = canvas.getContext("2d");
  ctx.fillStyle = "#FFFFFF";
  ctx.fillRect(0, 0, sidePx, sidePx);
  ctx.fillStyle = "#000000";
  for (let r = 0; r < moduleCount; r++) {
    for (let c = 0; c < moduleCount; c++) {
      if (qr.isDark(r, c)) {
        ctx.fillRect(
          (c + margin) * cellSize,
          (r + margin) * cellSize,
          cellSize,
          cellSize,
        );
      }
    }
  }
}

// ---------------------------------------------------------------------------
// スキャン
// ---------------------------------------------------------------------------

let _jsqrPromise = null;
async function loadJsQrLazy() {
  if (!_jsqrPromise) {
    // jsqr.js は UMD で window.jsQR にぶら下がる。動的 import で 1 回だけロード。
    _jsqrPromise = import("./vendor/jsqr.js").then(() => {
      return globalThis.jsQR || null;
    }).catch((err) => {
      _jsqrPromise = null;
      throw err;
    });
  }
  return _jsqrPromise;
}

/**
 * カメラを起動して QR を 1 件読み取り、文字列を返す。
 *
 * BarcodeDetector が利用可能ならそちらを使う (Chrome/Edge デスクトップ・モバイル、
 * Safari 17+)。利用不可なら jsQR を遅延ロードして polyfill する。
 */
export async function scanQrFromCamera(videoEl, opts = {}) {
  const { signal, scanIntervalMs = 200 } = opts;

  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    throw new Error("カメラ API が使えません (HTTPS で開いていますか？)");
  }

  const stream = await navigator.mediaDevices.getUserMedia({
    video: { facingMode: "environment" },
    audio: false,
  });

  videoEl.srcObject = stream;
  videoEl.setAttribute("playsinline", "true");
  videoEl.muted = true;
  await videoEl.play();

  const cleanup = () => {
    stream.getTracks().forEach((t) => t.stop());
    videoEl.srcObject = null;
  };

  if (signal) {
    if (signal.aborted) {
      cleanup();
      throw new DOMException("Scan aborted", "AbortError");
    }
    signal.addEventListener("abort", cleanup, { once: true });
  }

  // ---- 1) BarcodeDetector ネイティブパス ----
  if ("BarcodeDetector" in globalThis) {
    try {
      const supported = await globalThis.BarcodeDetector.getSupportedFormats();
      if (supported.includes("qr_code")) {
        const detector = new globalThis.BarcodeDetector({ formats: ["qr_code"] });

        return await new Promise((resolve, reject) => {
          let stopped = false;
          const onAbort = () => {
            stopped = true;
            reject(new DOMException("Scan aborted", "AbortError"));
          };
          if (signal) signal.addEventListener("abort", onAbort, { once: true });

          const tick = async () => {
            if (stopped) return;
            try {
              const results = await detector.detect(videoEl);
              if (results && results.length > 0 && results[0].rawValue) {
                stopped = true;
                cleanup();
                resolve(results[0].rawValue);
                return;
              }
            } catch {
              // detect の一時失敗は無視して継続
            }
            if (!stopped) {
              if ("requestVideoFrameCallback" in HTMLVideoElement.prototype) {
                videoEl.requestVideoFrameCallback(tick);
              } else {
                setTimeout(tick, scanIntervalMs);
              }
            }
          };
          tick();
        });
      }
    } catch {
      // BarcodeDetector があってもエラーする環境 → jsQR fallback
    }
  }

  // ---- 2) jsQR fallback ----
  const jsQR = await loadJsQrLazy();
  if (!jsQR) {
    cleanup();
    throw new Error("QR スキャナを初期化できません (jsQR ロード失敗)");
  }

  return await new Promise((resolve, reject) => {
    let stopped = false;
    const onAbort = () => {
      stopped = true;
      reject(new DOMException("Scan aborted", "AbortError"));
    };
    if (signal) signal.addEventListener("abort", onAbort, { once: true });

    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d", { willReadFrequently: true });

    const tick = () => {
      if (stopped) return;
      if (videoEl.readyState === videoEl.HAVE_ENOUGH_DATA) {
        canvas.width = videoEl.videoWidth;
        canvas.height = videoEl.videoHeight;
        ctx.drawImage(videoEl, 0, 0, canvas.width, canvas.height);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const result = jsQR(imageData.data, imageData.width, imageData.height, {
          inversionAttempts: "dontInvert",
        });
        if (result && result.data) {
          stopped = true;
          cleanup();
          resolve(result.data);
          return;
        }
      }
      setTimeout(tick, scanIntervalMs);
    };
    tick();
  });
}

/**
 * 画像ファイルから QR コードを 1 件読み取り、文字列を返す。
 * Phase 7.5ZU: モバイル user が camera 起動できない / Photo から読みたい時用。
 *
 * BarcodeDetector が利用可能ならそちらを使う (画像 input 形式は ImageBitmap)、
 * 未対応なら jsQR で同様に Canvas 経由で読み取る。
 *
 * @param {Blob|File} file - ファイル選択された画像
 * @returns {Promise<string>} QR コードの decode 結果文字列
 */
export async function scanQrFromImage(file) {
  if (!file || !(file instanceof Blob)) {
    throw new Error("Invalid file");
  }

  // ---- 1) BarcodeDetector path (= ImageBitmap 入力) ----
  if ("BarcodeDetector" in globalThis && globalThis.createImageBitmap) {
    try {
      const detector = new BarcodeDetector({ formats: ["qr_code"] });
      const bitmap = await createImageBitmap(file);
      const codes = await detector.detect(bitmap);
      bitmap.close && bitmap.close();
      if (codes && codes.length > 0 && codes[0].rawValue) {
        return codes[0].rawValue;
      }
      // detect 成功だが QR 見つからず → fallback (jsQR の方が頑張る場合もある)
    } catch (e) {
      console.warn("[qr] BarcodeDetector image scan failed, fallback to jsQR:", e?.message ?? e);
    }
  }

  // ---- 2) jsQR fallback ----
  const jsQR = await loadJsQrLazy();
  if (!jsQR) throw new Error("QR decoder unavailable");

  const dataUrl = await new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(new Error("Failed to read file"));
    reader.readAsDataURL(file);
  });

  const img = await new Promise((resolve, reject) => {
    const i = new Image();
    i.onload = () => resolve(i);
    i.onerror = () => reject(new Error("Failed to load image"));
    i.src = dataUrl;
  });

  const canvas = document.createElement("canvas");
  // 大きすぎる画像はリサイズ (= jsQR は遅いので max 1024)
  const MAX = 1024;
  let w = img.naturalWidth, h = img.naturalHeight;
  if (Math.max(w, h) > MAX) {
    const scale = MAX / Math.max(w, h);
    w = Math.round(w * scale);
    h = Math.round(h * scale);
  }
  canvas.width = w;
  canvas.height = h;
  const ctx = canvas.getContext("2d");
  ctx.drawImage(img, 0, 0, w, h);
  const imageData = ctx.getImageData(0, 0, w, h);
  const result = jsQR(imageData.data, imageData.width, imageData.height, {
    inversionAttempts: "attemptBoth",  // 画像は黒背景もありうるので両方試す
  });
  if (result && result.data) return result.data;
  throw new Error("No QR code detected in image");
}

/**
 * BarcodeDetector が利用可能かのヒント表示用 (同期判定)。
 * 完全な判定には async getSupportedFormats が必要だが、UI ヒントには十分。
 */
export function hasNativeBarcodeDetector() {
  return "BarcodeDetector" in globalThis;
}
