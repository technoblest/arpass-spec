// ============================================================================
// Arpass — Client-side vault cryptography
// ----------------------------------------------------------------------------
// Two supported envelope algorithms:
//
//   alg = "pbkdf2-sha256-aes256gcm"
//     Master password → PBKDF2-SHA-256 (600K iter) → AES-256-GCM key.
//     Fallback for devices without Passkey PRF. No hardware factor.
//
//   alg = "pbkdf2+prf-hkdf-aes256gcm"
//     Master password → PBKDF2 → 256-bit "password bits"
//     Passkey (WebAuthn + PRF extension) → 256-bit "PRF bits"
//     concat → HKDF-SHA-256 → AES-256-GCM key.
//     Two-factor: password alone or Passkey alone can't derive the key.
//
// Both share the same envelope shape (`v`, `salt`, `iv`, `ciphertext`), so
// a single decrypt path can handle either. Phase 1 will swap PBKDF2 for
// Argon2id (libsodium.js) while keeping these labels.
// ============================================================================

const KDF_ITERATIONS = 600_000;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const VAULT_FORMAT = 1;

export const ALG_PBKDF2_ONLY = "pbkdf2-sha256-aes256gcm";
export const ALG_PBKDF2_PLUS_PRF = "pbkdf2+prf-hkdf-aes256gcm";

// WebAuthn PRF input label. Changing this would invalidate existing vaults.
const PRF_SALT_LABEL = "arpass-vault-prf-v1";

// ----- base64url helpers -----
export function b64uEncode(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (const b of arr) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64uDecode(str) {
  // Pad to a multiple of 4: length % 4 = 2 needs "==", 3 needs "=".
  const padLen = (4 - (str.length % 4)) % 4;
  const padded = str.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(padLen);
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// ----- Key derivation -----
async function deriveKey(password, saltBytes, iterations = KDF_ITERATIONS) {
  const passKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
    passKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * Encrypt a vault JSON object.
 *
 * If `prfOutput` is supplied, the key is derived from both the password and
 * the PRF output (combined via HKDF). Otherwise the password alone is used.
 *
 * @param {object} vault   the plain vault object ({v, entries, ...})
 * @param {string} password  the Master password
 * @param {object} [options]
 * @param {Uint8Array} [options.existingSalt]  reuse a prior salt; if absent, a fresh salt is generated
 * @param {Uint8Array} [options.prfOutput]     32-byte Passkey PRF output; enables 2-factor encryption
 */
export async function encryptVault(vault, password, options = {}) {
  const salt = options.existingSalt ?? crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));

  const key = options.prfOutput
    ? await deriveKeyWithPRF(password, salt, options.prfOutput, KDF_ITERATIONS)
    : await deriveKey(password, salt, KDF_ITERATIONS);

  const plaintext = new TextEncoder().encode(JSON.stringify(vault));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext),
  );

  return {
    v: VAULT_FORMAT,
    alg: options.prfOutput ? ALG_PBKDF2_PLUS_PRF : ALG_PBKDF2_ONLY,
    iterations: KDF_ITERATIONS,
    salt: b64uEncode(salt),
    iv: b64uEncode(iv),
    ciphertext: b64uEncode(ciphertext),
  };
}

/**
 * Decrypt an envelope. The envelope's `alg` field selects the derivation:
 *   - ALG_PBKDF2_ONLY      → password alone
 *   - ALG_PBKDF2_PLUS_PRF  → password + prfOutput (required)
 *
 * Throws with a friendly Error on auth failure.
 */
export async function decryptVault(envelope, password, prfOutput) {
  if (envelope?.v !== VAULT_FORMAT) {
    throw new Error(`Unsupported vault version: ${envelope?.v}`);
  }
  const salt = b64uDecode(envelope.salt);
  const iv = b64uDecode(envelope.iv);
  const ciphertext = b64uDecode(envelope.ciphertext);

  let key;
  if (envelope.alg === ALG_PBKDF2_ONLY) {
    key = await deriveKey(password, salt, envelope.iterations);
  } else if (envelope.alg === ALG_PBKDF2_PLUS_PRF) {
    if (!prfOutput) {
      throw new Error(
        "This vault requires Passkey authentication. Please authenticate with your Passkey.",
      );
    }
    key = await deriveKeyWithPRF(password, salt, prfOutput, envelope.iterations);
  } else {
    throw new Error(`Unsupported vault algorithm: ${envelope.alg}`);
  }

  let plaintextBuf;
  try {
    plaintextBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      ciphertext,
    );
  } catch {
    throw new Error("Decryption failed — wrong password, Passkey, or corrupted vault");
  }
  return JSON.parse(new TextDecoder().decode(plaintextBuf));
}

// ---------------------------------------------------------------------------
// Key derivation with Passkey PRF: combine password-derived bits with
// the Passkey's PRF output via HKDF. Either factor alone is insufficient.
// ---------------------------------------------------------------------------
async function deriveKeyWithPRF(password, salt, prfOutput, iterations) {
  // 1) password → 256 password bits via PBKDF2
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const passwordBits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    passwordKey,
    256,
  );

  // 2) concat 32B password bits || first 32B of PRF output
  const combined = new Uint8Array(64);
  combined.set(new Uint8Array(passwordBits), 0);
  combined.set(prfOutput.slice(0, 32), 32);

  // 3) HKDF-SHA-256 → AES-256-GCM key
  const ikm = await crypto.subtle.importKey("raw", combined, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      salt,
      info: new TextEncoder().encode("arpass-combined-key-v1"),
      hash: "SHA-256",
    },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

// ============================================================================
// WebAuthn / Passkey helpers
// ============================================================================

export function isPasskeySupported() {
  return !!(
    typeof window !== "undefined" &&
    window.PublicKeyCredential &&
    navigator.credentials &&
    navigator.credentials.create
  );
}

export function isSecureContextOk() {
  if (typeof window === "undefined") return false;
  if (typeof window.isSecureContext === "boolean") return window.isSecureContext;
  const proto = window.location.protocol;
  const host = window.location.hostname;
  if (proto === "https:") return true;
  if (proto === "http:" && (host === "localhost" || host === "127.0.0.1" || host === "[::1]")) return true;
  return false;
}

/**
 * Register a new Passkey with PRF extension requested. Returns
 * { credentialId, prfEnabled, rpId }.
 *
 * If the authenticator doesn't support PRF, `prfEnabled` is false — the
 * caller should fall back to password-only encryption.
 *
 * @param {string} displayName    human-readable name for the Passkey (e.g. vault short-id)
 * @param {string} userIdString   stable unique user id; we use the vault-id
 */
export async function registerPasskey(displayName, userIdString) {
  if (!isPasskeySupported()) {
    throw new Error("このブラウザは Passkey (WebAuthn) に対応していません");
  }
  if (!isSecureContextOk()) {
    throw new Error("Passkey は HTTPS または localhost でのみ動作します (file:// 不可)");
  }
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userIdBytes = new TextEncoder().encode(userIdString).slice(0, 64);

  const cred = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: {
        name: "Arpass",
        id: window.location.hostname || "localhost",
      },
      user: {
        id: userIdBytes,
        name: displayName,
        displayName,
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },    // ES256
        { type: "public-key", alg: -257 },  // RS256
      ],
      authenticatorSelection: {
        // "platform" = この端末の組み込み認証器のみ受け入れる
        // (iOS: iCloud Keychain, Android: Google Password Manager,
        // macOS: Touch ID + iCloud Keychain, Windows: Windows Hello)。
        // 未指定だと OS が「別デバイス / USB セキュリティキー」を
        // 選択肢として出してしまい、ユーザが「キーチェーンに保存」を
        // 選べなくなる事があった。Arpass の信頼モデルでは端末ローカル
        // の Passkey + マスターパスワード + Recovery の3要素が前提なので、
        // 外部認証器は許容しない。
        authenticatorAttachment: "platform",
        // "preferred" を維持: "required" にすると iCloud Keychain が
        // 同期不可な環境 (iCloud サインアウト/同期 OFF) で create が
        // ブラウザに弾かれて「Passkey がそもそも作れない」状態になる
        // ため。preferred でも platform 認証器なら通常は discoverable
        // credential になる。
        residentKey: "preferred",
        userVerification: "required",
      },
      extensions: {
        prf: { eval: { first: new TextEncoder().encode(PRF_SALT_LABEL) } },
      },
      timeout: 60000,
    },
  });
  const ext = cred.getClientExtensionResults?.() ?? {};
  const prfEnabled = !!(ext.prf && ext.prf.enabled);
  return {
    credentialId: b64uEncode(new Uint8Array(cred.rawId)),
    prfEnabled,
    rpId: window.location.hostname || "localhost",
  };
}

/**
 * Authenticate with a previously registered Passkey and retrieve the
 * 32-byte PRF output. Throws if the authenticator won't emit PRF.
 *
 * @param {string} credentialIdB64u    the credentialId returned by registerPasskey
 * @returns {Promise<Uint8Array>}      32 bytes of PRF output
 */
export async function authenticateWithPasskey(credentialIdB64u) {
  if (!isPasskeySupported() || !isSecureContextOk()) {
    throw new Error("Passkey が利用できません（HTTPS / localhost 環境で実行してください）");
  }
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const credId = b64uDecode(credentialIdB64u);
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      allowCredentials: [{ type: "public-key", id: credId }],
      userVerification: "required",
      extensions: {
        prf: { eval: { first: new TextEncoder().encode(PRF_SALT_LABEL) } },
      },
      timeout: 60000,
    },
  });
  const ext = assertion.getClientExtensionResults?.() ?? {};
  const prfOutput = ext.prf && ext.prf.results && ext.prf.results.first;
  if (!prfOutput) {
    throw new Error("この認証器は Passkey PRF 拡張に対応していません");
  }
  return new Uint8Array(prfOutput).slice(0, 32);
}

// ============================================================================
// Recovery Secret — shown once at registration, kept by the user on paper.
// ============================================================================

/**
 * Generate a human-friendly 32-byte Recovery Secret formatted as
 *   RS1-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
 * (128-bit entropy encoded as 8 groups of 4 base32 chars.) The user writes
 * or prints this. Losing this AND the Passkey AND the password is
 * unrecoverable by design.
 */
export function generateRecoverySecret() {
  const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  // 32 base32 chars × 5 bits = 160 bits of entropy. We generate 32 random
  // bytes and pick 5 bits from each via modulo — unbiased because 256 / 32
  // divides exactly.
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let s = "";
  for (const b of bytes) s += BASE32[b % 32];
  const groups = [];
  for (let i = 0; i < 8; i++) groups.push(s.slice(i * 4, (i + 1) * 4));
  return "RS1-" + groups.join("-");
}

/** Parse a Recovery Secret back into bytes. Returns null if malformed. */
export function parseRecoverySecret(s) {
  if (!s) return null;
  const cleaned = s.replace(/\s/g, "").toUpperCase();
  const m = cleaned.match(/^RS1-([A-Z2-7]{4}-){7}[A-Z2-7]{4}$/);
  if (!m) return null;
  return cleaned;
}

// ----- Password generator -----
const POOLS = {
  lower: "abcdefghijklmnopqrstuvwxyz",
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digit: "0123456789",
  symbol: "!@#$%^&*-_=+?.,:;",
};

/**
 * Generate a cryptographically strong random password.
 * Options:
 *   length   (default 20)
 *   lower    (default true)
 *   upper    (default true)
 *   digit    (default true)
 *   symbol   (default true)
 */
export function generatePassword(options = {}) {
  const length = Math.max(8, Math.min(128, options.length ?? 20));
  const pools = [];
  if (options.lower !== false) pools.push(POOLS.lower);
  if (options.upper !== false) pools.push(POOLS.upper);
  if (options.digit !== false) pools.push(POOLS.digit);
  if (options.symbol !== false) pools.push(POOLS.symbol);
  if (pools.length === 0) pools.push(POOLS.lower + POOLS.upper + POOLS.digit);

  const combined = pools.join("");
  const out = [];
  // Guarantee at least one char from each selected pool.
  for (const pool of pools) out.push(pickOne(pool));
  // Fill the rest from the combined alphabet.
  for (let i = out.length; i < length; i++) out.push(pickOne(combined));
  // Fisher-Yates shuffle using crypto random.
  for (let i = out.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out.join("");
}

function pickOne(alphabet) {
  return alphabet[randomInt(alphabet.length)];
}

function randomInt(max) {
  // Rejection sampling for unbiased result.
  const limit = Math.floor(0xFFFFFFFF / max) * max;
  const buf = new Uint32Array(1);
  while (true) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % max;
  }
}

/**
 * Score a password's strength 0-4 (NIST-style guesstimate).
 * 0 = very weak, 4 = very strong. Pure heuristic, not a real entropy calc.
 */
export function passwordStrength(pw) {
  if (!pw) return 0;
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 16) score++;
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^\w]/].filter((r) => r.test(pw)).length;
  if (classes >= 3) score++;
  if (classes === 4 && pw.length >= 12) score++;
  return Math.min(4, score);
}

// ============================================================================
// v2 envelope: 2-of-3 key wrapping
// ----------------------------------------------------------------------------
// Three factors exist: Master password (P), Passkey PRF (K), Recovery Secret
// (R). A random 256-bit K_vault encrypts the actual Vault payload. K_vault is
// then wrapped three times, once per unique pair of factors:
//
//     wrap_pk = AES-GCM(K_vault) with KEK derived from P + K
//     wrap_pr = AES-GCM(K_vault) with KEK derived from P + R
//     wrap_kr = AES-GCM(K_vault) with KEK derived from K + R
//
// Any two factors unlock the vault. Losing any single factor is survivable:
// - Lost device (no Passkey): unlock via P + R (wrap_pr)
// - Forgot password:         unlock via K + R (wrap_kr)
// - Lost paper (Recovery):   unlock via P + K (wrap_pk) — normal daily use
//
// All three wraps live in the same envelope so an attacker has no surface to
// choose or omit factors. K_vault is stable for the life of the vault; only
// the outer ciphertext (and its IV) is re-generated on every save.
//
// Envelope shape:
//   {
//     "v": 2,
//     "alg": "arpass-2of3-v1",
//     "kdf": { "name": "pbkdf2-sha256", "iterations": 600000, "salt": "<b64u>" },
//     "iv": "<b64u>",             // IV for the outer Vault ciphertext
//     "ciphertext": "<b64u>",     // Vault JSON encrypted with K_vault
//     "wraps": {
//       "pk": { "iv": "...", "ct": "..." },
//       "pr": { "iv": "...", "ct": "..." },
//       "kr": { "iv": "...", "ct": "..." }
//     }
//   }
// ============================================================================

export const ALG_2OF3_V1 = "arpass-2of3-v1";
export const VAULT_FORMAT_V2 = 2;

/**
 * Normalize a Recovery Secret string into 32 bytes of keying material.
 * Accepts the RS1-XXXX-XXXX-... format produced by generateRecoverySecret().
 * Returns a Uint8Array(32) ready for HKDF, or throws on malformed input.
 */
export async function recoverySecretToMaterial(rsString) {
  const parsed = parseRecoverySecret(rsString);
  if (!parsed) {
    throw new Error("Recovery Secret の形式が正しくありません (RS1-XXXX-XXXX-…)");
  }
  // We treat the 32 base32 chars after the "RS1-" prefix as the secret's raw
  // key material. HKDF-Expand to a canonical 32 bytes for downstream use.
  const chars = parsed.slice(4).replace(/-/g, ""); // 32 chars
  const secretBytes = new TextEncoder().encode(chars);
  const ikm = await crypto.subtle.importKey("raw", secretBytes, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      salt: new TextEncoder().encode("arpass-recovery-v1"),
      info: new TextEncoder().encode("recovery-material"),
      hash: "SHA-256",
    },
    ikm,
    256,
  );
  return new Uint8Array(bits);
}

/**
 * PBKDF2-derive 32 password bits. Used as factor material for v2.
 */
async function passwordToMaterial(password, salt, iterations) {
  const passKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    passKey,
    256,
  );
  return new Uint8Array(bits);
}

/**
 * Derive a 256-bit KEK from two 32-byte factor materials + salt + an info label.
 * The info label ensures each wrap gets a cryptographically distinct KEK even
 * though the underlying factor materials may overlap across wraps.
 */
async function deriveKEK(factorA, factorB, salt, infoLabel) {
  const combined = new Uint8Array(factorA.length + factorB.length);
  combined.set(factorA, 0);
  combined.set(factorB, factorA.length);
  const ikm = await crypto.subtle.importKey("raw", combined, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      salt,
      info: new TextEncoder().encode(infoLabel),
      hash: "SHA-256",
    },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** Wrap (encrypt) a 32-byte K_vault with a KEK. Returns {iv, ct} as b64u strings. */
async function wrapKey(kVaultBytes, kekKey) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, kekKey, kVaultBytes),
  );
  return { iv: b64uEncode(iv), ct: b64uEncode(ct) };
}

/** Unwrap (decrypt) a wrapped K_vault. Returns raw 32 bytes, or throws. */
async function unwrapKey(wrap, kekKey) {
  if (!wrap?.iv || !wrap?.ct) throw new Error("wrap が壊れています");
  const iv = b64uDecode(wrap.iv);
  const ct = b64uDecode(wrap.ct);
  const buf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, kekKey, ct);
  return new Uint8Array(buf);
}

/**
 * Create a v2 envelope. Requires all three factors at vault creation time.
 *
 *   vault            — plain vault JSON object
 *   password         — Master password string
 *   prfOutput        — 32-byte Uint8Array from Passkey PRF
 *   recoveryMaterial — 32-byte Uint8Array from recoverySecretToMaterial()
 *
 * Optionally pass `existingSalt` (Uint8Array) to reuse a vault's salt across
 * regenerations (e.g. during migration). Otherwise a fresh salt is generated.
 */
export async function encryptVaultV2(vault, password, prfOutput, recoveryMaterial, options = {}) {
  const salt = options.existingSalt ?? crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const kVault = options.existingKVault ?? crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));

  // Encrypt the vault with K_vault.
  const kVaultKey = await crypto.subtle.importKey(
    "raw", kVault, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
  const plaintext = new TextEncoder().encode(JSON.stringify(vault));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, kVaultKey, plaintext),
  );

  // Derive three factor materials.
  const pMat = await passwordToMaterial(password, salt, KDF_ITERATIONS);
  const kMat = prfOutput.slice(0, 32);
  const rMat = recoveryMaterial.slice(0, 32);

  // Three KEKs → three wraps.
  const kek_pk = await deriveKEK(pMat, kMat, salt, "arpass-wrap-pk-v1");
  const kek_pr = await deriveKEK(pMat, rMat, salt, "arpass-wrap-pr-v1");
  const kek_kr = await deriveKEK(kMat, rMat, salt, "arpass-wrap-kr-v1");

  const wraps = {
    pk: await wrapKey(kVault, kek_pk),
    pr: await wrapKey(kVault, kek_pr),
    kr: await wrapKey(kVault, kek_kr),
  };

  return {
    envelope: {
      v: VAULT_FORMAT_V2,
      alg: ALG_2OF3_V1,
      kdf: {
        name: "pbkdf2-sha256",
        iterations: KDF_ITERATIONS,
        salt: b64uEncode(salt),
      },
      iv: b64uEncode(iv),
      ciphertext: b64uEncode(ciphertext),
      wraps: {
        pk: wraps.pk,
        pr: wraps.pr,
        kr: wraps.kr,
      },
    },
    kVault, // returned so callers can cache it in-memory for later re-encrypt
  };
}

/**
 * Re-encrypt a vault using an already-known K_vault. No factor derivation
 * required — suitable for save-while-unlocked, which is the common path.
 *
 * Preserves the wraps from `existingEnvelope` (factors haven't changed), only
 * rotates the outer IV + ciphertext. Returns a fresh v2 envelope.
 */
export async function reEncryptVaultV2(vault, kVault, existingEnvelope) {
  if (existingEnvelope?.v !== VAULT_FORMAT_V2) {
    throw new Error(`reEncryptVaultV2: expected v=2 envelope, got v=${existingEnvelope?.v}`);
  }
  const kVaultKey = await crypto.subtle.importKey(
    "raw", kVault, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const plaintext = new TextEncoder().encode(JSON.stringify(vault));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, kVaultKey, plaintext),
  );
  return {
    ...existingEnvelope,
    iv: b64uEncode(iv),
    ciphertext: b64uEncode(ciphertext),
    // wraps, kdf, alg, v unchanged — same K_vault, same factors
  };
}

/**
 * Decrypt a v2 envelope. Provide any two of three factors.
 *
 *   factors = {
 *     password?: string,
 *     prfOutput?: Uint8Array(32+),
 *     recoveryMaterial?: Uint8Array(32),
 *   }
 *
 * Returns { vault, kVault, wrapUsed } where wrapUsed is "pk" | "pr" | "kr".
 * Throws if too few factors or decryption fails.
 */
export async function decryptVaultV2(envelope, factors) {
  if (envelope?.v !== VAULT_FORMAT_V2 || envelope?.alg !== ALG_2OF3_V1) {
    throw new Error(`Unsupported v2 envelope: v=${envelope?.v}, alg=${envelope?.alg}`);
  }
  const salt = b64uDecode(envelope.kdf.salt);
  const iterations = envelope.kdf.iterations ?? KDF_ITERATIONS;

  const have = {
    p: typeof factors?.password === "string" && factors.password.length > 0,
    k: factors?.prfOutput instanceof Uint8Array && factors.prfOutput.length >= 32,
    r: factors?.recoveryMaterial instanceof Uint8Array && factors.recoveryMaterial.length >= 32,
  };
  const count = (have.p ? 1 : 0) + (have.k ? 1 : 0) + (have.r ? 1 : 0);
  if (count < 2) {
    throw new Error("2-of-3 復号には 3つの要素のうち 2つが必要です");
  }

  // Derive only the materials we have, to minimize expensive PBKDF2 runs.
  const pMat = have.p ? await passwordToMaterial(factors.password, salt, iterations) : null;
  const kMat = have.k ? factors.prfOutput.slice(0, 32) : null;
  const rMat = have.r ? factors.recoveryMaterial.slice(0, 32) : null;

  // Pick the wrap for the pair of factors we have.
  let kekKey, wrapKey_, wrapUsed;
  if (have.p && have.k) {
    kekKey = await deriveKEK(pMat, kMat, salt, "arpass-wrap-pk-v1");
    wrapKey_ = envelope.wraps.pk;
    wrapUsed = "pk";
  } else if (have.p && have.r) {
    kekKey = await deriveKEK(pMat, rMat, salt, "arpass-wrap-pr-v1");
    wrapKey_ = envelope.wraps.pr;
    wrapUsed = "pr";
  } else if (have.k && have.r) {
    kekKey = await deriveKEK(kMat, rMat, salt, "arpass-wrap-kr-v1");
    wrapKey_ = envelope.wraps.kr;
    wrapUsed = "kr";
  } else {
    throw new Error("unreachable");
  }

  let kVault;
  try {
    kVault = await unwrapKey(wrapKey_, kekKey);
  } catch {
    throw new Error("復号失敗：提供された要素が envelope と一致しません");
  }

  // Decrypt the outer ciphertext with K_vault.
  const kVaultKey = await crypto.subtle.importKey(
    "raw", kVault, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
  const iv = b64uDecode(envelope.iv);
  const ct = b64uDecode(envelope.ciphertext);
  let plainBuf;
  try {
    plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, kVaultKey, ct);
  } catch {
    throw new Error("Vault 本体の復号に失敗しました（envelope 壊れ？）");
  }
  const vault = JSON.parse(new TextDecoder().decode(plainBuf));
  return { vault, kVault, wrapUsed };
}

/**
 * Rotate the wraps in an existing v2 envelope without re-encrypting the outer
 * ciphertext. Use case: user registers a new Passkey on a new device, or
 * generates a new Recovery Secret. Pass in the new factor materials; we
 * re-compute all three wraps so every pair continues to work post-rotation.
 *
 * Caller must already have K_vault (e.g. from a successful decrypt call).
 */
/**
 * Rotate just the password. wrap_pk and wrap_pr are re-derived with the new
 * password; wrap_kr is untouched (it doesn't involve the password). Cheap:
 * no outer re-encryption of the vault body.
 */
export async function changePasswordV2(envelope, kVault, newPassword, prfOutput, recoveryMaterial) {
  if (envelope?.v !== VAULT_FORMAT_V2) throw new Error("v=2 envelope only");
  const salt = b64uDecode(envelope.kdf.salt);
  const iterations = envelope.kdf.iterations;
  const pMat_new = await passwordToMaterial(newPassword, salt, iterations);
  const kMat = prfOutput.slice(0, 32);
  const rMat = recoveryMaterial.slice(0, 32);
  const kek_pk_new = await deriveKEK(pMat_new, kMat, salt, "arpass-wrap-pk-v1");
  const kek_pr_new = await deriveKEK(pMat_new, rMat, salt, "arpass-wrap-pr-v1");
  return {
    ...envelope,
    wraps: {
      pk: await wrapKey(kVault, kek_pk_new),
      pr: await wrapKey(kVault, kek_pr_new),
      kr: envelope.wraps.kr,
    },
  };
}

/**
 * Rotate just the Passkey. wrap_pk and wrap_kr are re-derived with the new
 * Passkey's PRF output; wrap_pr is untouched. Used when registering a new
 * Passkey on a new device or replacing a lost Passkey.
 */
export async function changePasskeyV2(envelope, kVault, password, newPrfOutput, recoveryMaterial) {
  if (envelope?.v !== VAULT_FORMAT_V2) throw new Error("v=2 envelope only");
  const salt = b64uDecode(envelope.kdf.salt);
  const iterations = envelope.kdf.iterations;
  const pMat = await passwordToMaterial(password, salt, iterations);
  const kMat_new = newPrfOutput.slice(0, 32);
  const rMat = recoveryMaterial.slice(0, 32);
  const kek_pk_new = await deriveKEK(pMat, kMat_new, salt, "arpass-wrap-pk-v1");
  const kek_kr_new = await deriveKEK(kMat_new, rMat, salt, "arpass-wrap-kr-v1");
  return {
    ...envelope,
    wraps: {
      pk: await wrapKey(kVault, kek_pk_new),
      pr: envelope.wraps.pr,
      kr: await wrapKey(kVault, kek_kr_new),
    },
  };
}

/**
 * Rotate just the Recovery Secret. wrap_pr and wrap_kr are re-derived with
 * the new Recovery material; wrap_pk is untouched. Issued when the user has
 * lost their Recovery paper and wants a fresh one.
 */
export async function changeRecoveryV2(envelope, kVault, password, prfOutput, newRecoveryMaterial) {
  if (envelope?.v !== VAULT_FORMAT_V2) throw new Error("v=2 envelope only");
  const salt = b64uDecode(envelope.kdf.salt);
  const iterations = envelope.kdf.iterations;
  const pMat = await passwordToMaterial(password, salt, iterations);
  const kMat = prfOutput.slice(0, 32);
  const rMat_new = newRecoveryMaterial.slice(0, 32);
  const kek_pr_new = await deriveKEK(pMat, rMat_new, salt, "arpass-wrap-pr-v1");
  const kek_kr_new = await deriveKEK(kMat, rMat_new, salt, "arpass-wrap-kr-v1");
  return {
    ...envelope,
    wraps: {
      pk: envelope.wraps.pk,
      pr: await wrapKey(kVault, kek_pr_new),
      kr: await wrapKey(kVault, kek_kr_new),
    },
  };
}

export async function rewrapVaultV2(envelope, kVault, newFactors) {
  if (envelope?.v !== VAULT_FORMAT_V2) {
    throw new Error("rewrapVaultV2: v=2 envelope のみ対応");
  }
  const salt = b64uDecode(envelope.kdf.salt);
  const iterations = envelope.kdf.iterations ?? KDF_ITERATIONS;

  const pMat = await passwordToMaterial(newFactors.password, salt, iterations);
  const kMat = newFactors.prfOutput.slice(0, 32);
  const rMat = newFactors.recoveryMaterial.slice(0, 32);

  const kek_pk = await deriveKEK(pMat, kMat, salt, "arpass-wrap-pk-v1");
  const kek_pr = await deriveKEK(pMat, rMat, salt, "arpass-wrap-pr-v1");
  const kek_kr = await deriveKEK(kMat, rMat, salt, "arpass-wrap-kr-v1");

  return {
    ...envelope,
    wraps: {
      pk: await wrapKey(kVault, kek_pk),
      pr: await wrapKey(kVault, kek_pr),
      kr: await wrapKey(kVault, kek_kr),
    },
  };
}

// ============================================================================
// Minimal P-256 (secp256r1) math — deterministic identity from Recovery Secret
// ----------------------------------------------------------------------------
// WebCrypto can't derive a P-256 keypair from a seed; it only generates random
// ones. To let a fresh device regenerate the same signing identity (and hence
// the same Vault ID) from the user's Recovery Secret, we compute the public
// point ourselves. This module implements just enough: scalar → (x, y) on the
// P-256 curve. Signature generation still uses WebCrypto via JWK import.
//
// Not suitable for secret-dependent control flow; used only for public key
// derivation where side channels are not a concern (public output).
// ============================================================================

const P256_p  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFn;
const P256_n  = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551n;
const P256_a  = P256_p - 3n;
const P256_Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296n;
const P256_Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5n;

function p256Mod(a) { const r = a % P256_p; return r < 0n ? r + P256_p : r; }

function p256ModInv(a) {
  // Fermat's little theorem on the prime p.
  return p256ModPow(a, P256_p - 2n);
}

function p256ModPow(base, exp) {
  let result = 1n;
  base = p256Mod(base);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = p256Mod(result * base);
    e >>= 1n;
    base = p256Mod(base * base);
  }
  return result;
}

// Points: null == point at infinity; otherwise [x, y] BigInt pair.
function p256Double(P) {
  if (P === null) return null;
  const [x, y] = P;
  if (y === 0n) return null;
  const s = p256Mod((3n * x * x + P256_a) * p256ModInv(2n * y));
  const xr = p256Mod(s * s - 2n * x);
  const yr = p256Mod(s * (x - xr) - y);
  return [xr, yr];
}

function p256Add(P, Q) {
  if (P === null) return Q;
  if (Q === null) return P;
  const [x1, y1] = P;
  const [x2, y2] = Q;
  if (x1 === x2) {
    if (y1 === y2) return p256Double(P);
    return null; // P + (-P) = ∞
  }
  const s = p256Mod((y2 - y1) * p256ModInv(x2 - x1));
  const xr = p256Mod(s * s - x1 - x2);
  const yr = p256Mod(s * (x1 - xr) - y1);
  return [xr, yr];
}

function p256ScalarMul(k, P) {
  if (k <= 0n) throw new Error("P-256 scalar must be positive");
  let R = null;
  let addend = P;
  let kk = k;
  while (kk > 0n) {
    if (kk & 1n) R = p256Add(R, addend);
    addend = p256Double(addend);
    kk >>= 1n;
  }
  return R;
}

function bytesToBigint(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

function bigintToBytes(n, length = 32) {
  if (n < 0n) throw new Error("negative bigint");
  const out = new Uint8Array(length);
  let x = n;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  if (x !== 0n) throw new Error("bigint does not fit in given length");
  return out;
}

/**
 * Derive an ECDSA P-256 keypair deterministically from a Recovery Secret.
 * Used so that a fresh device entering the user's Recovery Secret recovers
 * the same signing identity (and hence the same Vault ID) as the original
 * device.
 *
 * Returns JWKs suitable for `crypto.subtle.importKey("jwk", …)`.
 */
export async function deriveIdentityKeypair(recoveryString) {
  const recoveryMaterial = await recoverySecretToMaterial(recoveryString);
  const ikm = await crypto.subtle.importKey("raw", recoveryMaterial, "HKDF", false, ["deriveBits"]);
  const seedBits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      salt: new TextEncoder().encode("arpass-identity-v1"),
      info: new TextEncoder().encode("p256-keypair"),
      hash: "SHA-256",
    },
    ikm,
    256,
  );

  // Reduce the seed to a scalar in [1, n-1] — mapping 32 random bytes into
  // the curve order range. Uniformity is near-perfect at 256 bits so simple
  // mod works (bias is < 2^-128).
  let d = bytesToBigint(new Uint8Array(seedBits));
  d = (d % (P256_n - 1n)) + 1n;

  // Compute public point Q = dG.
  const Q = p256ScalarMul(d, [P256_Gx, P256_Gy]);
  if (Q === null) throw new Error("degenerate public point");
  const [x, y] = Q;

  const xB64 = b64uEncode(bigintToBytes(x));
  const yB64 = b64uEncode(bigintToBytes(y));
  const dB64 = b64uEncode(bigintToBytes(d));

  return {
    privateKeyJwk: {
      kty: "EC", crv: "P-256",
      d: dB64, x: xB64, y: yB64,
      ext: true,
      key_ops: ["sign"],
    },
    publicKeyJwk: {
      kty: "EC", crv: "P-256",
      x: xB64, y: yB64,
      ext: true,
      key_ops: ["verify"],
    },
  };
}

/**
 * Compute the Vault ID for a given public JWK. Mirrors the server's
 * `deriveVaultId()` in functions/_lib/auth.js so client and server agree.
 */
export async function deriveVaultIdFromPublicJwk(publicKeyJwk) {
  const canonical = {
    kty: publicKeyJwk.kty,
    crv: publicKeyJwk.crv,
    x: publicKeyJwk.x,
    y: publicKeyJwk.y,
    ext: true,
    key_ops: ["verify"],
  };
  const bytes = new TextEncoder().encode(JSON.stringify(canonical));
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return b64uEncode(hash).slice(0, 32);
}

// ============================================================================
// v3 envelope: multi-device 2-of-3
// ----------------------------------------------------------------------------
// Extends v2 so more than one device can unlock the same Vault at the same
// time (PC + phone + tablet, all concurrent). The K_vault → wrap pattern is
// preserved; only the "how many of each wrap" changes.
//
// Key differences from v2:
//   - wraps.pk is now an ARRAY (one entry per authorized Passkey)
//   - wraps.kr is now an ARRAY (one entry per authorized Passkey)
//   - wraps.pr stays SINGULAR (Password and Recovery are user-wide, not per
//     device; one wrap covers every device)
//   - envelope carries a `devices` array with human-readable metadata
//
// Password / Recovery rotations: the current device's pk/kr wraps can be
// re-derived locally, but other devices' PRFs are not available here. Those
// entries are DELETED from the arrays on rotation, forcing other devices to
// re-authorize via the remaining 2-of-3 path (typically P+R with the new
// password). Industry-standard behavior — same as 1Password / Bitwarden when
// master password rotates.
// ============================================================================

export const VAULT_FORMAT_V3 = 3;
export const ALG_2OF3_V2 = "arpass-2of3-v2";

/** Stable per-device id. Generated once, stored in localStorage meta. */
export function generateDeviceId() {
  if (typeof crypto.randomUUID === "function") {
    return "dev_" + crypto.randomUUID().replace(/-/g, "").slice(0, 16);
  }
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  return "dev_" + b64uEncode(bytes).slice(0, 16);
}

/** Default device name from UA / timestamp. User can rename later. */
export function defaultDeviceName() {
  const ua = (typeof navigator !== "undefined" && navigator.userAgent) || "";
  let platform = "端末";
  if (/iPhone/.test(ua)) platform = "iPhone";
  else if (/iPad/.test(ua)) platform = "iPad";
  else if (/Android/.test(ua)) platform = "Android";
  else if (/Macintosh/.test(ua)) platform = "Mac";
  else if (/Windows/.test(ua)) platform = "Windows";
  else if (/Linux/.test(ua)) platform = "Linux";
  const date = new Date().toISOString().slice(0, 10);
  return `${platform} (${date})`;
}

/** Short identifier for matching a wrap to its Passkey credential. */
async function credIdDigest(credentialIdB64u) {
  const bytes = new TextEncoder().encode(credentialIdB64u);
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return b64uEncode(hash.slice(0, 8));
}

/**
 * Create a fresh v3 envelope with a single initial device.
 */
export async function encryptVaultV3(vault, password, prfOutput, recoveryMaterial, initialDevice) {
  if (!initialDevice?.deviceId || !initialDevice?.credentialId) {
    throw new Error("encryptVaultV3: initialDevice must have deviceId + credentialId");
  }
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const kVault = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));

  const kVaultKey = await crypto.subtle.importKey(
    "raw", kVault, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
  const plaintext = new TextEncoder().encode(JSON.stringify(vault));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, kVaultKey, plaintext),
  );

  const pMat = await passwordToMaterial(password, salt, KDF_ITERATIONS);
  const kMat = prfOutput.slice(0, 32);
  const rMat = recoveryMaterial.slice(0, 32);

  const kek_pr = await deriveKEK(pMat, rMat, salt, "arpass-wrap-pr-v1");
  const kek_pk = await deriveKEK(pMat, kMat, salt, "arpass-wrap-pk-v1");
  const kek_kr = await deriveKEK(kMat, rMat, salt, "arpass-wrap-kr-v1");

  const now = new Date().toISOString();
  const ch = await credIdDigest(initialDevice.credentialId);
  const name = initialDevice.name ?? defaultDeviceName();

  const pkEntry = { deviceId: initialDevice.deviceId, credIdHash: ch, name, addedAt: now, ...await wrapKey(kVault, kek_pk) };
  const krEntry = { deviceId: initialDevice.deviceId, credIdHash: ch, ...await wrapKey(kVault, kek_kr) };

  return {
    envelope: {
      v: VAULT_FORMAT_V3,
      alg: ALG_2OF3_V2,
      kdf: {
        name: "pbkdf2-sha256",
        iterations: KDF_ITERATIONS,
        salt: b64uEncode(salt),
      },
      iv: b64uEncode(iv),
      ciphertext: b64uEncode(ciphertext),
      wraps: {
        pr: await wrapKey(kVault, kek_pr),
        pk: [pkEntry],
        kr: [krEntry],
      },
      devices: [{ deviceId: initialDevice.deviceId, name, addedAt: now }],
    },
    kVault,
  };
}

/**
 * Decrypt a v3 envelope. Provide any two of three factors, plus an optional
 * `deviceHint` (the current device's credentialId) so we know which array
 * entry to try first. If the hint doesn't match, we try all entries as a
 * fallback so the unlock still works across device wipes / re-registrations.
 */
export async function decryptVaultV3(envelope, factors, deviceHint = {}) {
  if (envelope?.v !== VAULT_FORMAT_V3 || envelope?.alg !== ALG_2OF3_V2) {
    throw new Error(`Unsupported v3 envelope: v=${envelope?.v}, alg=${envelope?.alg}`);
  }
  const salt = b64uDecode(envelope.kdf.salt);
  const iterations = envelope.kdf.iterations ?? KDF_ITERATIONS;

  const have = {
    p: typeof factors?.password === "string" && factors.password.length > 0,
    k: factors?.prfOutput instanceof Uint8Array && factors.prfOutput.length >= 32,
    r: factors?.recoveryMaterial instanceof Uint8Array && factors.recoveryMaterial.length >= 32,
  };
  const count = (have.p ? 1 : 0) + (have.k ? 1 : 0) + (have.r ? 1 : 0);
  if (count < 2) {
    throw new Error("2-of-3 復号には 3つの要素のうち 2つが必要です");
  }

  // pMat reuse — see decryptVaultV4 for rationale. Stores the in-flight
  // promise so concurrent (Promise.all) decrypts share a single PBKDF2.
  let pMat = null;
  if (have.p) {
    const cache = factors.passwordMaterialCache;
    if (
      cache &&
      cache.materialPromise &&
      cache.saltB64u === envelope.kdf.salt &&
      cache.iterations === iterations
    ) {
      pMat = await cache.materialPromise;
    } else {
      const promise = passwordToMaterial(factors.password, salt, iterations);
      if (cache && typeof cache === "object") {
        cache.materialPromise = promise;
        cache.saltB64u = envelope.kdf.salt;
        cache.iterations = iterations;
      }
      pMat = await promise;
    }
  }
  const kMat = have.k ? factors.prfOutput.slice(0, 32) : null;
  const rMat = have.r ? factors.recoveryMaterial.slice(0, 32) : null;

  async function tryUnwrapArray(wraps, kekKey) {
    // Try the hinted wrap first, then fall back to all others. Ordered-first
    // so the common path is one attempt.
    const hintedCid = deviceHint?.credentialId
      ? await credIdDigest(deviceHint.credentialId)
      : null;
    const ordered = hintedCid
      ? [
          ...wraps.filter((w) => w.credIdHash === hintedCid),
          ...wraps.filter((w) => w.credIdHash !== hintedCid),
        ]
      : wraps;
    for (const w of ordered) {
      try { return { kVault: await unwrapKey(w, kekKey), deviceId: w.deviceId }; } catch {}
    }
    throw new Error("どの端末 wrap も復号できません");
  }

  let unwrapResult;
  let wrapUsed;
  if (have.p && have.r) {
    const kek_pr = await deriveKEK(pMat, rMat, salt, "arpass-wrap-pr-v1");
    unwrapResult = { kVault: await unwrapKey(envelope.wraps.pr, kek_pr), deviceId: null };
    wrapUsed = "pr";
  } else if (have.p && have.k) {
    const kek_pk = await deriveKEK(pMat, kMat, salt, "arpass-wrap-pk-v1");
    unwrapResult = await tryUnwrapArray(envelope.wraps.pk, kek_pk);
    wrapUsed = "pk";
  } else if (have.k && have.r) {
    const kek_kr = await deriveKEK(kMat, rMat, salt, "arpass-wrap-kr-v1");
    unwrapResult = await tryUnwrapArray(envelope.wraps.kr, kek_kr);
    wrapUsed = "kr";
  } else {
    throw new Error("unreachable");
  }

  const { kVault, deviceId: deviceIdUsed } = unwrapResult;
  const kVaultKey = await crypto.subtle.importKey(
    "raw", kVault, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
  const iv = b64uDecode(envelope.iv);
  const ct = b64uDecode(envelope.ciphertext);
  let plainBuf;
  try {
    plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, kVaultKey, ct);
  } catch {
    throw new Error("Vault 本体の復号失敗（envelope 壊れ？）");
  }
  const vault = JSON.parse(new TextDecoder().decode(plainBuf));
  return { vault, kVault, wrapUsed, deviceIdUsed };
}

/** Rotate only the outer ciphertext on a v3 envelope — for routine saves. */
export async function reEncryptVaultV3(vault, kVault, existingEnvelope) {
  if (existingEnvelope?.v !== VAULT_FORMAT_V3) {
    throw new Error(`reEncryptVaultV3: expected v=3 envelope, got v=${existingEnvelope?.v}`);
  }
  const kVaultKey = await crypto.subtle.importKey(
    "raw", kVault, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const plaintext = new TextEncoder().encode(JSON.stringify(vault));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, kVaultKey, plaintext),
  );
  return {
    ...existingEnvelope,
    iv: b64uEncode(iv),
    ciphertext: b64uEncode(ciphertext),
  };
}

/**
 * Add a new device to an existing v3 envelope. Caller must already hold
 * K_vault (i.e. they successfully unlocked on this device) and must collect
 * the new device's Passkey PRF output.
 */
export async function addDeviceV3(envelope, kVault, password, newDevicePrf, recoveryMaterial, newDeviceMeta) {
  if (envelope?.v !== VAULT_FORMAT_V3) throw new Error("v=3 envelope only");
  if (!newDeviceMeta?.deviceId || !newDeviceMeta?.credentialId) {
    throw new Error("addDeviceV3: newDeviceMeta.deviceId and .credentialId required");
  }
  const salt = b64uDecode(envelope.kdf.salt);
  const iterations = envelope.kdf.iterations;
  const pMat = await passwordToMaterial(password, salt, iterations);
  const kMat_new = newDevicePrf.slice(0, 32);
  const rMat = recoveryMaterial.slice(0, 32);

  const kek_pk = await deriveKEK(pMat, kMat_new, salt, "arpass-wrap-pk-v1");
  const kek_kr = await deriveKEK(kMat_new, rMat, salt, "arpass-wrap-kr-v1");
  const ch = await credIdDigest(newDeviceMeta.credentialId);
  const now = new Date().toISOString();
  const name = newDeviceMeta.name ?? defaultDeviceName();

  // If the device already exists (by id), replace its entry; otherwise append.
  const pkFiltered = (envelope.wraps.pk || []).filter((w) => w.deviceId !== newDeviceMeta.deviceId);
  const krFiltered = (envelope.wraps.kr || []).filter((w) => w.deviceId !== newDeviceMeta.deviceId);
  const dFiltered  = (envelope.devices  || []).filter((d) => d.deviceId !== newDeviceMeta.deviceId);

  return {
    ...envelope,
    wraps: {
      pr: envelope.wraps.pr,
      pk: [...pkFiltered, { deviceId: newDeviceMeta.deviceId, credIdHash: ch, name, addedAt: now, ...await wrapKey(kVault, kek_pk) }],
      kr: [...krFiltered, { deviceId: newDeviceMeta.deviceId, credIdHash: ch, ...await wrapKey(kVault, kek_kr) }],
    },
    devices: [...dFiltered, { deviceId: newDeviceMeta.deviceId, name, addedAt: now }],
  };
}

/** Remove a device from the arrays. No crypto needed — just filter. */
export function removeDeviceV3(envelope, deviceId) {
  if (envelope?.v !== VAULT_FORMAT_V3) throw new Error("v=3 envelope only");
  return {
    ...envelope,
    wraps: {
      pr: envelope.wraps.pr,
      pk: (envelope.wraps.pk || []).filter((w) => w.deviceId !== deviceId),
      kr: (envelope.wraps.kr || []).filter((w) => w.deviceId !== deviceId),
    },
    devices: (envelope.devices || []).filter((d) => d.deviceId !== deviceId),
  };
}

/** Rename a device's display label (metadata only). */
export function renameDeviceV3(envelope, deviceId, newName) {
  if (envelope?.v !== VAULT_FORMAT_V3) throw new Error("v=3 envelope only");
  return {
    ...envelope,
    wraps: {
      ...envelope.wraps,
      pk: (envelope.wraps.pk || []).map((w) => w.deviceId === deviceId ? { ...w, name: newName } : w),
    },
    devices: (envelope.devices || []).map((d) => d.deviceId === deviceId ? { ...d, name: newName } : d),
  };
}

/**
 * Change master password on a v3 envelope. The universal wrap_pr is rotated
 * with the new password; THIS device's wrap_pk is also rotated. Every OTHER
 * device's wrap_pk is DELETED — they can't be re-derived without each
 * device's PRF — so those devices must re-authorize on their next unlock via
 * P+R with the new password. The save path re-appends them automatically.
 */
export async function changePasswordV3(envelope, kVault, newPassword, thisDevicePrf, thisDeviceId, recoveryMaterial) {
  if (envelope?.v !== VAULT_FORMAT_V3) throw new Error("v=3 envelope only");
  const salt = b64uDecode(envelope.kdf.salt);
  const iterations = envelope.kdf.iterations;
  const pMat_new = await passwordToMaterial(newPassword, salt, iterations);
  const kMat_this = thisDevicePrf.slice(0, 32);
  const rMat = recoveryMaterial.slice(0, 32);

  const kek_pr_new = await deriveKEK(pMat_new, rMat, salt, "arpass-wrap-pr-v1");
  const kek_pk_new = await deriveKEK(pMat_new, kMat_this, salt, "arpass-wrap-pk-v1");

  const thisPk = (envelope.wraps.pk || []).find((w) => w.deviceId === thisDeviceId);
  const updatedThisPk = thisPk
    ? { ...thisPk, ...await wrapKey(kVault, kek_pk_new) }
    : null;

  return {
    ...envelope,
    wraps: {
      pr: await wrapKey(kVault, kek_pr_new),
      pk: updatedThisPk ? [updatedThisPk] : [],
      kr: envelope.wraps.kr, // Passkey-only wraps, no password dep
    },
    // devices metadata is NOT pruned here — the UI can still list them,
    // they'll just need to re-authenticate themselves on next unlock.
    // But the array filter happens automatically on re-add (same deviceId).
    passwordChangedAt: new Date().toISOString(),
  };
}

/**
 * Re-issue the Recovery Secret. pr and THIS device's kr get rotated with the
 * new Recovery material; other devices' kr entries are dropped (we can't
 * re-derive them without their PRF).
 */
export async function changeRecoveryV3(envelope, kVault, password, thisDevicePrf, thisDeviceId, newRecoveryMaterial) {
  if (envelope?.v !== VAULT_FORMAT_V3) throw new Error("v=3 envelope only");
  const salt = b64uDecode(envelope.kdf.salt);
  const iterations = envelope.kdf.iterations;
  const pMat = await passwordToMaterial(password, salt, iterations);
  const kMat_this = thisDevicePrf.slice(0, 32);
  const rMat_new = newRecoveryMaterial.slice(0, 32);

  const kek_pr_new = await deriveKEK(pMat, rMat_new, salt, "arpass-wrap-pr-v1");
  const kek_kr_new = await deriveKEK(kMat_this, rMat_new, salt, "arpass-wrap-kr-v1");

  const thisKr = (envelope.wraps.kr || []).find((w) => w.deviceId === thisDeviceId);
  const updatedThisKr = thisKr
    ? { ...thisKr, ...await wrapKey(kVault, kek_kr_new) }
    : null;

  return {
    ...envelope,
    wraps: {
      pr: await wrapKey(kVault, kek_pr_new),
      pk: envelope.wraps.pk, // no Recovery dep
      kr: updatedThisKr ? [updatedThisKr] : [],
    },
    recoveryChangedAt: new Date().toISOString(),
  };
}

/**
 * Migrate a v2 envelope to v3 as a single-device v3. Existing v2 wraps are
 * valid v3 wraps (same HKDF labels, same K_vault derivation) so no crypto
 * re-derivation is required — only structural reshaping.
 */
export function migrateV2ToV3(v2envelope, deviceMeta) {
  if (v2envelope?.v !== VAULT_FORMAT_V2) throw new Error("migrateV2ToV3: v=2 expected");
  const { deviceId, name, credIdHash } = deviceMeta;
  if (!deviceId) throw new Error("migrateV2ToV3: deviceMeta.deviceId required");
  const now = new Date().toISOString();
  return {
    v: VAULT_FORMAT_V3,
    alg: ALG_2OF3_V2,
    kdf: v2envelope.kdf,
    iv: v2envelope.iv,
    ciphertext: v2envelope.ciphertext,
    wraps: {
      pr: v2envelope.wraps.pr,
      pk: [{ deviceId, credIdHash: credIdHash ?? "", name: name ?? defaultDeviceName(), addedAt: now, ...v2envelope.wraps.pk }],
      kr: [{ deviceId, credIdHash: credIdHash ?? "", ...v2envelope.wraps.kr }],
    },
    devices: [{ deviceId, name: name ?? defaultDeviceName(), addedAt: now }],
    migratedFromV2At: now,
  };
}

// ============================================================================
// v4 envelope: padding + per-user anonymized Arweave tags
// ----------------------------------------------------------------------------
// v4 is structurally identical to v3 (same wraps shape) but with two
// privacy-hardening additions:
//
//   1. Plaintext is padded to a fixed bucket size before encryption, so the
//      outer ciphertext does NOT leak the number of vault entries. We pad to
//      ~110 KiB ± 5 KiB (jitter). The plaintext is prefixed with a 4-byte
//      length so decrypt knows how many bytes are real vs padding.
//
//   2. The Arweave tag App-Name and vault-id-tag-value are derived per user
//      from the Recovery Secret material via HMAC. This stops third parties
//      from enumerating "all Arpass vaults" via App-Name=Arpass-Vault.
//
// Why padding to ~110 KiB specifically:
//   - 100 KiB is Turbo's free-tier ceiling. We deliberately exceed it (110
//     KiB) so writes go through Turbo's paid tier — this matches Technoblest's
//     "we want to actually pay for what we use" philosophy.
//   - Plaintext padding: 100 entries fits comfortably in 10 KiB, so 110 KiB
//     is safe headroom and indistinguishable across users with 1 vs 1000
//     entries. Vaults with >100 KiB of entries (rare) would spill to the next
//     bucket (220 KiB).
// ============================================================================

export const VAULT_FORMAT_V4 = 4;
// Earlier versions wrote an `alg` field into v4 envelopes (originally
// "arpass-2of3-v3", later "2of3-v3"). Both are redundant with `v: 4`
// — the envelope schema version uniquely identifies the algorithm.
// New v4 envelopes omit `alg` entirely; decrypt simply ignores it for
// backward compat with envelopes that still have it.
export const ALG_2OF3_V3 = "2of3-v3";  // exported for any external tooling that still references it

// Padding bucket: target 115 KiB ± 5 KiB → range [110, 120] KiB.
// We deliberately stay above Turbo's freeUploadLimitBytes (currently 107520
// = 105 KiB) so EVERY write actually consumes Turbo credits — preserves the
// "we pay per write" philosophy. The minimum (110 KiB = 112640 B) is ~5 KiB
// above the free threshold, leaving safety margin in case ArDrive bumps it
// slightly. If the threshold ever exceeds 110 KiB we'll need to bump these
// constants.
const PADDING_TARGET_BYTES = 115 * 1024;        // 115 KiB
const PADDING_JITTER_BYTES = 5 * 1024;          // ±5 KiB
const PADDING_MIN_BYTES    = PADDING_TARGET_BYTES - PADDING_JITTER_BYTES;
const PADDING_MAX_BYTES    = PADDING_TARGET_BYTES + PADDING_JITTER_BYTES;
const PADDING_LENGTH_PREFIX = 4;                // u32 big-endian original length

/**
 * Pad arbitrary plaintext bytes to a randomly-chosen size between
 * PADDING_MIN_BYTES and PADDING_MAX_BYTES. The first 4 bytes record the
 * original length so unpad() can recover the real content.
 *
 * If the plaintext is larger than PADDING_MAX_BYTES, we round up to the next
 * multiple of PADDING_TARGET_BYTES (so a 200 KiB vault pads to 220 KiB, etc.)
 * — preserves bucket-shape privacy at the cost of more storage for power users.
 */
export function padPlaintext(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError("padPlaintext: expected Uint8Array");
  }
  const realLen = bytes.length;
  if (realLen > 0xFFFFFFFF) throw new Error("plaintext too large");

  let target;
  if (realLen + PADDING_LENGTH_PREFIX <= PADDING_MAX_BYTES) {
    // Random size in [MIN, MAX] inclusive.
    const span = PADDING_MAX_BYTES - PADDING_MIN_BYTES + 1;
    const jitter = crypto.getRandomValues(new Uint32Array(1))[0] % span;
    target = PADDING_MIN_BYTES + jitter;
  } else {
    // Spill to the next bucket multiple.
    const buckets = Math.ceil((realLen + PADDING_LENGTH_PREFIX) / PADDING_TARGET_BYTES);
    target = buckets * PADDING_TARGET_BYTES;
  }

  const out = new Uint8Array(target);
  // Length prefix (u32 big-endian).
  out[0] = (realLen >>> 24) & 0xff;
  out[1] = (realLen >>> 16) & 0xff;
  out[2] = (realLen >>> 8)  & 0xff;
  out[3] = realLen & 0xff;
  // Real bytes.
  out.set(bytes, PADDING_LENGTH_PREFIX);
  // Random padding for the rest. Random rather than zeros so the ciphertext
  // doesn't have a long run that could weaken cryptanalysis (defense in
  // depth — AES-GCM is already secure against this).
  // Note: WebCrypto getRandomValues caps at 65,536 bytes per call, so we
  // fill in chunks for larger paddings.
  const padOffset = PADDING_LENGTH_PREFIX + realLen;
  const RAND_CHUNK = 65536;
  for (let off = padOffset; off < target; off += RAND_CHUNK) {
    const remaining = Math.min(RAND_CHUNK, target - off);
    const chunk = new Uint8Array(out.buffer, out.byteOffset + off, remaining);
    crypto.getRandomValues(chunk);
  }
  return out;
}

/** Reverse padPlaintext: read length prefix, slice the real bytes. */
export function unpadPlaintext(padded) {
  if (!(padded instanceof Uint8Array) || padded.length < PADDING_LENGTH_PREFIX) {
    throw new Error("unpadPlaintext: input too small to contain length prefix");
  }
  const realLen =
    (padded[0] << 24) | (padded[1] << 16) | (padded[2] << 8) | padded[3];
  if (realLen < 0 || realLen + PADDING_LENGTH_PREFIX > padded.length) {
    throw new Error("unpadPlaintext: invalid length prefix");
  }
  return padded.subarray(PADDING_LENGTH_PREFIX, PADDING_LENGTH_PREFIX + realLen);
}

/**
 * Derive a per-user anonymized App-Name tag value from the Recovery Secret
 * material. The tag value is deterministic per user, so the user can find
 * their own vault on a fresh device by re-deriving it. Attackers without the
 * Recovery Secret cannot enumerate Arpass vaults via tag search.
 *
 * Output is a 16-character base64url string with no recognizable prefix.
 */
export async function deriveAppNameTag(recoveryMaterial) {
  const ikm = await crypto.subtle.importKey("raw", recoveryMaterial, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      salt: new TextEncoder().encode("arpass-app-tag-v1"),
      info: new TextEncoder().encode("App-Name"),
      hash: "SHA-256",
    },
    ikm,
    96, // 12 bytes → 16 base64url chars
  );
  return b64uEncode(new Uint8Array(bits));
}

/**
 * v4 encrypt: build a v4 envelope with padded plaintext + standard 2-of-3
 * key wrapping. Same factors as v3 — different envelope version + padding.
 */
export async function encryptVaultV4(vault, password, prfOutput, recoveryMaterial, initialDevice) {
  if (!initialDevice?.deviceId || !initialDevice?.credentialId) {
    throw new Error("encryptVaultV4: initialDevice must have deviceId + credentialId");
  }
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const kVault = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));

  const kVaultKey = await crypto.subtle.importKey(
    "raw", kVault, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
  const plaintext = new TextEncoder().encode(JSON.stringify(vault));
  const padded = padPlaintext(plaintext);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, kVaultKey, padded),
  );

  const pMat = await passwordToMaterial(password, salt, KDF_ITERATIONS);
  const kMat = prfOutput.slice(0, 32);
  const rMat = recoveryMaterial.slice(0, 32);

  const kek_pr = await deriveKEK(pMat, rMat, salt, "arpass-wrap-pr-v1");
  const kek_pk = await deriveKEK(pMat, kMat, salt, "arpass-wrap-pk-v1");
  const kek_kr = await deriveKEK(kMat, rMat, salt, "arpass-wrap-kr-v1");

  const now = new Date().toISOString();
  const ch = await credIdDigest(initialDevice.credentialId);
  const name = initialDevice.name ?? defaultDeviceName();

  return {
    envelope: {
      v: VAULT_FORMAT_V4,
      kdf: {
        name: "pbkdf2-sha256",
        iterations: KDF_ITERATIONS,
        salt: b64uEncode(salt),
      },
      iv: b64uEncode(iv),
      ciphertext: b64uEncode(ciphertext),
      wraps: {
        pr: await wrapKey(kVault, kek_pr),
        pk: [{ deviceId: initialDevice.deviceId, credIdHash: ch, name, addedAt: now, ...await wrapKey(kVault, kek_pk) }],
        kr: [{ deviceId: initialDevice.deviceId, credIdHash: ch, ...await wrapKey(kVault, kek_kr) }],
      },
      devices: [{ deviceId: initialDevice.deviceId, name, addedAt: now }],
    },
    kVault,
  };
}

/**
 * v4 decrypt: same factor selection as v3, plus unpad after decrypt.
 */
export async function decryptVaultV4(envelope, factors, deviceHint = {}) {
  if (envelope?.v !== VAULT_FORMAT_V4) {
    throw new Error(`Unsupported envelope version for v4 decrypt: v=${envelope?.v}`);
  }
  // Note: we no longer check envelope.alg — the field is omitted in
  // current envelopes and `v: 4` uniquely identifies the algorithm.
  // Legacy envelopes that still carry alg ("2of3-v3" or "arpass-2of3-v3")
  // are simply ignored — the field is informational only.
  const salt = b64uDecode(envelope.kdf.salt);
  const iterations = envelope.kdf.iterations ?? KDF_ITERATIONS;

  const have = {
    p: typeof factors?.password === "string" && factors.password.length > 0,
    k: factors?.prfOutput instanceof Uint8Array && factors.prfOutput.length >= 32,
    r: factors?.recoveryMaterial instanceof Uint8Array && factors.recoveryMaterial.length >= 32,
  };
  const count = (have.p ? 1 : 0) + (have.k ? 1 : 0) + (have.r ? 1 : 0);
  if (count < 2) throw new Error("2-of-3 復号には 3つの要素のうち 2つが必要です");

  // pMat reuse: caller may hand in a mutable cache object so the picker can
  // amortize the (~150ms) PBKDF2 step across all candidates. Same vault →
  // same salt + iterations → same pMat. We store the IN-FLIGHT PROMISE
  // (not the resolved value) so concurrent decrypts (Promise.all) all
  // await the same single PBKDF2 invocation instead of each starting
  // their own.
  let pMat = null;
  if (have.p) {
    const cache = factors.passwordMaterialCache;
    if (
      cache &&
      cache.materialPromise &&
      cache.saltB64u === envelope.kdf.salt &&
      cache.iterations === iterations
    ) {
      pMat = await cache.materialPromise;
    } else {
      const promise = passwordToMaterial(factors.password, salt, iterations);
      if (cache && typeof cache === "object") {
        cache.materialPromise = promise;
        cache.saltB64u = envelope.kdf.salt;
        cache.iterations = iterations;
      }
      pMat = await promise;
    }
  }
  const kMat = have.k ? factors.prfOutput.slice(0, 32) : null;
  const rMat = have.r ? factors.recoveryMaterial.slice(0, 32) : null;

  async function tryUnwrapArray(wraps, kekKey) {
    const hintedCid = deviceHint?.credentialId
      ? await credIdDigest(deviceHint.credentialId)
      : null;
    const ordered = hintedCid
      ? [
          ...wraps.filter((w) => w.credIdHash === hintedCid),
          ...wraps.filter((w) => w.credIdHash !== hintedCid),
        ]
      : wraps;
    for (const w of ordered) {
      try { return { kVault: await unwrapKey(w, kekKey), deviceId: w.deviceId }; } catch {}
    }
    throw new Error("どの端末 wrap も復号できません");
  }

  let unwrapResult;
  let wrapUsed;
  if (have.p && have.r) {
    const kek_pr = await deriveKEK(pMat, rMat, salt, "arpass-wrap-pr-v1");
    unwrapResult = { kVault: await unwrapKey(envelope.wraps.pr, kek_pr), deviceId: null };
    wrapUsed = "pr";
  } else if (have.p && have.k) {
    const kek_pk = await deriveKEK(pMat, kMat, salt, "arpass-wrap-pk-v1");
    unwrapResult = await tryUnwrapArray(envelope.wraps.pk, kek_pk);
    wrapUsed = "pk";
  } else if (have.k && have.r) {
    const kek_kr = await deriveKEK(kMat, rMat, salt, "arpass-wrap-kr-v1");
    unwrapResult = await tryUnwrapArray(envelope.wraps.kr, kek_kr);
    wrapUsed = "kr";
  } else {
    throw new Error("unreachable");
  }

  const { kVault, deviceId: deviceIdUsed } = unwrapResult;
  const kVaultKey = await crypto.subtle.importKey(
    "raw", kVault, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
  const iv = b64uDecode(envelope.iv);
  const ct = b64uDecode(envelope.ciphertext);
  let paddedBuf;
  try {
    paddedBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, kVaultKey, ct);
  } catch {
    throw new Error("Vault 本体の復号失敗（envelope 壊れ？）");
  }
  const real = unpadPlaintext(new Uint8Array(paddedBuf));
  const vault = JSON.parse(new TextDecoder().decode(real));
  return { vault, kVault, wrapUsed, deviceIdUsed };
}

/** Rotate the outer ciphertext on a v4 envelope, preserving wraps + devices. */
export async function reEncryptVaultV4(vault, kVault, existingEnvelope) {
  if (existingEnvelope?.v !== VAULT_FORMAT_V4) {
    throw new Error(`reEncryptVaultV4: expected v=4 envelope, got v=${existingEnvelope?.v}`);
  }
  const kVaultKey = await crypto.subtle.importKey(
    "raw", kVault, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const plaintext = new TextEncoder().encode(JSON.stringify(vault));
  const padded = padPlaintext(plaintext);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, kVaultKey, padded),
  );
  return {
    ...existingEnvelope,
    // Drop the legacy `alg` field if it was present in older envelopes —
    // current schema relies on `v: 4` alone to identify the algorithm.
    alg: undefined,
    iv: b64uEncode(iv),
    ciphertext: b64uEncode(ciphertext),
  };
}

/**
 * Migrate v3 envelope to v4 by re-encrypting with padding. Wraps are preserved
 * (same K_vault, same factors). Caller must already hold K_vault from a
 * successful v3 decrypt.
 *
 * Note: this changes the outer ciphertext (now padded), so a fresh tx must be
 * written to Arweave. Old v3 envelopes on chain remain readable but stale.
 */
export async function migrateV3ToV4(v3envelope, kVault, vault) {
  if (v3envelope?.v !== VAULT_FORMAT_V3) {
    throw new Error("migrateV3ToV4: v=3 expected");
  }
  const kVaultKey = await crypto.subtle.importKey(
    "raw", kVault, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const plaintext = new TextEncoder().encode(JSON.stringify(vault));
  const padded = padPlaintext(plaintext);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, kVaultKey, padded),
  );
  return {
    ...v3envelope,
    v: VAULT_FORMAT_V4,
    alg: undefined,    // drop legacy v3 alg string
    iv: b64uEncode(iv),
    ciphertext: b64uEncode(ciphertext),
    migratedFromV3At: new Date().toISOString(),
  };
}

/** Add a device — same as v3 but for v4 envelope. */
export async function addDeviceV4(envelope, kVault, password, newDevicePrf, recoveryMaterial, newDeviceMeta) {
  if (envelope?.v !== VAULT_FORMAT_V4) throw new Error("v=4 envelope only");
  if (!newDeviceMeta?.deviceId || !newDeviceMeta?.credentialId) {
    throw new Error("addDeviceV4: newDeviceMeta.deviceId and .credentialId required");
  }
  const salt = b64uDecode(envelope.kdf.salt);
  const iterations = envelope.kdf.iterations;
  const pMat = await passwordToMaterial(password, salt, iterations);
  const kMat_new = newDevicePrf.slice(0, 32);
  const rMat = recoveryMaterial.slice(0, 32);

  const kek_pk = await deriveKEK(pMat, kMat_new, salt, "arpass-wrap-pk-v1");
  const kek_kr = await deriveKEK(kMat_new, rMat, salt, "arpass-wrap-kr-v1");
  const ch = await credIdDigest(newDeviceMeta.credentialId);
  const now = new Date().toISOString();
  const name = newDeviceMeta.name ?? defaultDeviceName();

  const pkFiltered = (envelope.wraps.pk || []).filter((w) => w.deviceId !== newDeviceMeta.deviceId);
  const krFiltered = (envelope.wraps.kr || []).filter((w) => w.deviceId !== newDeviceMeta.deviceId);
  const dFiltered  = (envelope.devices  || []).filter((d) => d.deviceId !== newDeviceMeta.deviceId);

  return {
    ...envelope,
    alg: undefined,    // drop legacy alg field — `v: 4` is sufficient
    wraps: {
      pr: envelope.wraps.pr,
      pk: [...pkFiltered, { deviceId: newDeviceMeta.deviceId, credIdHash: ch, name, addedAt: now, ...await wrapKey(kVault, kek_pk) }],
      kr: [...krFiltered, { deviceId: newDeviceMeta.deviceId, credIdHash: ch, ...await wrapKey(kVault, kek_kr) }],
    },
    devices: [...dFiltered, { deviceId: newDeviceMeta.deviceId, name, addedAt: now }],
  };
}

/** Remove a device from v4. */
export function removeDeviceV4(envelope, deviceId) {
  if (envelope?.v !== VAULT_FORMAT_V4) throw new Error("v=4 envelope only");
  return {
    ...envelope,
    alg: undefined,    // drop legacy alg field
    wraps: {
      pr: envelope.wraps.pr,
      pk: (envelope.wraps.pk || []).filter((w) => w.deviceId !== deviceId),
      kr: (envelope.wraps.kr || []).filter((w) => w.deviceId !== deviceId),
    },
    devices: (envelope.devices || []).filter((d) => d.deviceId !== deviceId),
  };
}

/** Rename a device in v4. */
export function renameDeviceV4(envelope, deviceId, newName) {
  if (envelope?.v !== VAULT_FORMAT_V4) throw new Error("v=4 envelope only");
  return {
    ...envelope,
    alg: undefined,    // drop legacy alg field
    wraps: {
      ...envelope.wraps,
      pk: (envelope.wraps.pk || []).map((w) => w.deviceId === deviceId ? { ...w, name: newName } : w),
    },
    devices: (envelope.devices || []).map((d) => d.deviceId === deviceId ? { ...d, name: newName } : d),
  };
}

/** Change password on v4. Same invariants as v3. */
export async function changePasswordV4(envelope, kVault, newPassword, thisDevicePrf, thisDeviceId, recoveryMaterial) {
  if (envelope?.v !== VAULT_FORMAT_V4) throw new Error("v=4 envelope only");
  const salt = b64uDecode(envelope.kdf.salt);
  const iterations = envelope.kdf.iterations;
  const pMat_new = await passwordToMaterial(newPassword, salt, iterations);
  const kMat_this = thisDevicePrf.slice(0, 32);
  const rMat = recoveryMaterial.slice(0, 32);

  const kek_pr_new = await deriveKEK(pMat_new, rMat, salt, "arpass-wrap-pr-v1");
  const kek_pk_new = await deriveKEK(pMat_new, kMat_this, salt, "arpass-wrap-pk-v1");

  const thisPk = (envelope.wraps.pk || []).find((w) => w.deviceId === thisDeviceId);
  const updatedThisPk = thisPk ? { ...thisPk, ...await wrapKey(kVault, kek_pk_new) } : null;

  return {
    ...envelope,
    alg: undefined,    // drop legacy alg field
    wraps: {
      pr: await wrapKey(kVault, kek_pr_new),
      pk: updatedThisPk ? [updatedThisPk] : [],
      kr: envelope.wraps.kr,
    },
    passwordChangedAt: new Date().toISOString(),
  };
}
