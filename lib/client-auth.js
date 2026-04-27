// ============================================================================
// Arpass Client Auth Helper
// ----------------------------------------------------------------------------
// Browser-side ECDSA P-256 keypair management and request signing.
//
// On first use, generateKeypairAndRegister() creates a keypair, registers the
// public key with the backend (POST /api/vault/register), and stores the
// private key in localStorage. Subsequent requests are signed by
// signedFetch(), which transparently adds X-Vault-Id, X-Timestamp, and
// X-Signature headers.
//
// ⚠️ Local-storage-only private keys are a known weakness. In a later phase,
// we'll encrypt the private key with a KDF of the user's master password
// before persisting (so stealing the browser profile isn't enough).
// ============================================================================

const STORAGE_KEY = "arpass_client_v1";
const KEY_ALGO = { name: "ECDSA", namedCurve: "P-256" };
const SIG_ALGO = { name: "ECDSA", hash: "SHA-256" };

// ----- base64url -----
function b64urlFromBytes(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ----- client identity -----
export function hasClientIdentity() {
  return !!localStorage.getItem(STORAGE_KEY);
}

export function readClientIdentity() {
  const raw = localStorage.getItem(STORAGE_KEY);
  return raw ? JSON.parse(raw) : null;
}

export function forgetClientIdentity() {
  localStorage.removeItem(STORAGE_KEY);
}

async function importPrivate(jwk) {
  return crypto.subtle.importKey("jwk", jwk, KEY_ALGO, false, ["sign"]);
}

/**
 * Generate a new keypair and register it with the backend.
 * Returns { vaultId, credits, message } from the server.
 *
 * If `options.privateKeyJwk` and `options.publicKeyJwk` are supplied (e.g. a
 * deterministic keypair derived from the user's Recovery Secret), those are
 * used instead of generating fresh randomness. This lets a fresh device
 * arrive at the same Vault ID as the original simply by knowing the Secret.
 */
export async function generateKeypairAndRegister(options = {}) {
  let pubJwk, privJwk;
  if (options.privateKeyJwk && options.publicKeyJwk) {
    pubJwk = options.publicKeyJwk;
    privJwk = options.privateKeyJwk;
  } else {
    const kp = await crypto.subtle.generateKey(KEY_ALGO, true, ["sign", "verify"]);
    pubJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
    privJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  }

  // Canonicalize the public JWK so the server and client derive the same vaultId.
  // Keep only the EC public components, in a stable key order.
  const canonicalPub = {
    kty: pubJwk.kty,
    crv: pubJwk.crv,
    x: pubJwk.x,
    y: pubJwk.y,
    ext: true,
    key_ops: ["verify"],
  };
  const publicKeyString = JSON.stringify(canonicalPub);

  // Register with backend
  const resp = await fetch("/api/vault/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ publicKey: publicKeyString }),
  });
  const result = await resp.json();
  if (!resp.ok || !result.ok) {
    throw new Error(`register failed: ${result.error || resp.status}`);
  }

  // Persist. We store the private JWK and vault metadata together.
  const identity = {
    vaultId: result.vaultId,
    publicKeyJwk: canonicalPub,
    privateKeyJwk: privJwk,
    createdAt: new Date().toISOString(),
  };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(identity));
  return result;
}

/**
 * Restore the client identity deterministically from a Recovery Secret.
 *
 * On a fresh device, the user enters their Recovery Secret and we regenerate
 * the same ECDSA keypair (and therefore the same Vault ID) as the original
 * device. No server registration call — the server already knows this vault
 * id + public key from the original registration, and signatures will verify
 * against it.
 *
 * Returns { vaultId, alreadyRegistered } where alreadyRegistered is a best-
 * effort hint (we ping the server, but a 404/missing response doesn't block
 * us from installing the identity locally).
 */
export async function restoreIdentityFromRecovery(recoveryString) {
  const { deriveIdentityKeypair, deriveVaultIdFromPublicJwk } =
    await import("./vault-crypto.js");
  const { privateKeyJwk, publicKeyJwk } = await deriveIdentityKeypair(recoveryString);

  const canonicalPub = {
    kty: publicKeyJwk.kty,
    crv: publicKeyJwk.crv,
    x: publicKeyJwk.x,
    y: publicKeyJwk.y,
    ext: true,
    key_ops: ["verify"],
  };
  const vaultId = await deriveVaultIdFromPublicJwk(canonicalPub);

  // Check whether the server already has this vault-id registered.
  let alreadyRegistered = false;
  try {
    const r = await fetch(`/api/vault/${encodeURIComponent(vaultId)}`);
    if (r.ok) {
      const j = await r.json();
      alreadyRegistered = !!j.ok;
    }
  } catch {}

  if (!alreadyRegistered) {
    // First time this vault is seen by the server — register it with the
    // deterministic public key.
    const publicKeyString = JSON.stringify(canonicalPub);
    const resp = await fetch("/api/vault/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ publicKey: publicKeyString }),
    });
    const result = await resp.json();
    if (!resp.ok || !result.ok) {
      throw new Error(`register failed: ${result.error || resp.status}`);
    }
    if (result.vaultId !== vaultId) {
      throw new Error(`server returned unexpected vault-id: ${result.vaultId} vs expected ${vaultId}`);
    }
  }

  const identity = {
    vaultId,
    publicKeyJwk: canonicalPub,
    privateKeyJwk,
    createdAt: new Date().toISOString(),
    restoredFromRecovery: true,
  };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(identity));
  return { vaultId, alreadyRegistered };
}

/**
 * Fetch the current state of the vault (credits, totals, etc.).
 */
export async function fetchVaultStatus() {
  const identity = readClientIdentity();
  if (!identity) throw new Error("No client identity — call generateKeypairAndRegister first");
  const resp = await fetch(`/api/vault/${encodeURIComponent(identity.vaultId)}`);
  return resp.json();
}

/**
 * Read an Arweave item with fallback to the Arpass bundler's pending queue.
 *
 * arweave.net serves items only after the bundle lands on-chain (mempool or
 * mined). In the gap between "user wrote" and "bundle landed", the item only
 * exists on the self-hosted bundler. This helper tries arweave.net first and
 * falls back to `<bundlerBase>/items/<txid>` on 404.
 *
 * Discover `bundlerBase` from `GET /api/status` → `bundler_read_base`.
 *
 * @returns {Promise<{source: "arweave"|"bundler-pending", body: string, contentType: string}>}
 */
export async function readWithFallback(txid, options = {}) {
  const gateway = options.gateway ?? "https://arweave.net";
  // Turbo's own AR.IO gateway serves Turbo-bundled data items the moment
  // they're accepted, well before the bundle confirms on Arweave L1
  // (where arweave.net would have it). For Arpass — which writes via
  // BUNDLER_BACKEND=turbo in production — this is the fastest path for
  // anything written in the last few minutes.
  const turboGateway = options.turboGateway ?? "https://turbo-gateway.com";
  const bundlerBase = options.bundlerBase ?? null;

  // Race both gateways in parallel — first 200 wins. Was sequential
  // (Turbo → arweave.net on 404), which doubled wall-clock time when
  // Turbo was a cache miss or just slow. Now whichever responds first
  // wins; the loser's response is harmlessly discarded.
  const candidates = [
    { name: "turbo", url: `${turboGateway}/${txid}` },
    { name: "arweave", url: `${gateway}/${txid}` },
  ];

  // 8s per-gateway timeout. Without this, one stalled gateway can hang the
  // entire unlock for 20+ seconds when the other returned 404 instantly.
  const GATEWAY_TIMEOUT_MS = 8000;
  const winner = await new Promise((resolve, reject) => {
    let pending = candidates.length;
    const errors = [];
    const settle = (msg) => {
      errors.push(msg);
      if (--pending === 0) reject(new Error(errors.join("; ")));
    };
    for (const { name, url } of candidates) {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), GATEWAY_TIMEOUT_MS);
      fetch(url, { cache: "no-store", signal: ctrl.signal })
        .then(async (r) => {
          clearTimeout(timer);
          if (r.ok) {
            resolve({
              source: name,
              body: await r.text(),
              contentType: r.headers.get("content-type") ?? "application/octet-stream",
            });
          } else {
            if (r.status !== 404) console.warn(`${name} returned HTTP ${r.status} for ${txid}`);
            settle(`${name}: HTTP ${r.status}`);
          }
        })
        .catch((e) => {
          clearTimeout(timer);
          const msg = e?.name === "AbortError" ? `timeout >${GATEWAY_TIMEOUT_MS}ms` : (e?.message ?? String(e));
          console.warn(`${name} read failed for ${txid}:`, msg);
          settle(`${name}: ${msg}`);
        });
    }
  }).catch(() => null);

  if (winner) return winner;

  // Final fallback: self-hosted bundler pending queue (if configured).
  if (bundlerBase) {
    try {
      const r = await fetch(`${bundlerBase}/items/${txid}`, { cache: "no-store" });
      if (r.ok) {
        return {
          source: "bundler-pending",
          body: await r.text(),
          contentType: r.headers.get("content-type") ?? "application/octet-stream",
        };
      }
    } catch (e) {
      console.warn("bundler read failed:", e?.message);
    }
  }

  throw new Error(
    "Item not available on Turbo gateway, arweave.net, " +
      (bundlerBase ? "or the bundler's pending queue. " : "and no bundler fallback configured. ") +
      "It may still be propagating — retry in a few minutes.",
  );
}

/**
 * Perform an authenticated fetch. Adds X-Vault-Id, X-Timestamp, X-Signature.
 * Body must be a JSON-serializable object; we stringify it and sign the
 * timestamp + "." + body.
 *
 * @returns the parsed JSON response
 */
export async function signedFetch(url, method, bodyObject) {
  const identity = readClientIdentity();
  if (!identity) throw new Error("No client identity");

  const rawBody = bodyObject == null ? "" : JSON.stringify(bodyObject);
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const message = new TextEncoder().encode(`${timestamp}.${rawBody}`);

  const privateKey = await importPrivate(identity.privateKeyJwk);
  const sigBuf = await crypto.subtle.sign(SIG_ALGO, privateKey, message);
  const signature = b64urlFromBytes(sigBuf);

  const resp = await fetch(url, {
    method,
    headers: {
      "Content-Type": "application/json",
      "X-Vault-Id": identity.vaultId,
      "X-Timestamp": timestamp,
      "X-Signature": signature,
    },
    body: bodyObject == null ? undefined : rawBody,
  });
  return resp.json();
}
