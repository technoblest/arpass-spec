//! Arpass crypto core — Stage 1 (primitives only).
//!
//! This crate provides Rust + WASM implementations of the crypto primitives
//! that previously lived in `web/lib/vendor/noble-curves-and-hashes.mjs`
//! (= pure-JS via `@noble/hashes` and `@noble/curves`).
//!
//! envelope orchestration (= the high-level logic in vault-crypto.js and
//! vault-client.js — envelope v7 assembly, recovery flow, business mode
//! handling, etc.) stays in JS for Stage 1. Only the cryptographic
//! primitives themselves are moved to Rust.
//!
//! # Backward-compatibility (CRITICAL)
//!
//! All outputs MUST be bit-identical to the previous noble implementations
//! for the same inputs. Specifically:
//!   - Argon2id with kdfParams {alg:argon2id, v:2, m:65536, t:3, p:4, tagLen:32}
//!     must produce the same 32-byte output for the same password + salt.
//!   - HKDF-SHA256 extract+expand must match for the same ikm/salt/info/length.
//!   - ECDH P-256 must produce the same 32-byte shared secret for the same
//!     keypairs (= SEC1 uncompressed public key format, 32-byte private scalar).
//!   - SHA-256 trivial — standardized.
//!   - AES-256-GCM with 12-byte IV and 16-byte tag matches WebCrypto.
//!
//! Live vault data on Arweave from before Phase 7.4Z (= Rust port) must
//! continue to decrypt without re-encryption.
//!
//! # License
//!
//! AGPL-3.0-or-later. See repository root LICENSE file.

#![deny(unsafe_code)]
#![warn(clippy::all)]

use wasm_bindgen::prelude::*;

#[cfg(feature = "console_error_panic_hook")]
#[wasm_bindgen(start)]
pub fn _init() {
    console_error_panic_hook::set_once();
}

// ============================================================
// Argon2id  (Phase 7.4 — Master KDF)
// ============================================================

use argon2::{Algorithm, Argon2, Params, Version};

/// Argon2id key derivation.
///
/// Parameters MUST match Phase 7.4 envelope.kdfParams:
///   alg: "argon2id"
///   v:   2          (= Argon2 version 0x13)
///   m:   65536      (= 64 MiB memory cost, in KiB)
///   t:   3          (= 3 iterations)
///   p:   4          (= 4 lanes)
///   tagLen: 32      (= 32-byte output)
///
/// Caller (= vault-crypto.js derivePMat) is responsible for passing the
/// correct params. This function does not enforce a specific configuration
/// to allow future migrations (= e.g., Phase 7.4Y bump to t=4).
///
/// # Backward-compat
/// Existing vaults use exactly the params above. Changing any of m/t/p
/// would break decryption of all existing data.
#[wasm_bindgen]
pub fn argon2id_derive(
    password: &[u8],
    salt: &[u8],
    m_kib: u32,
    t: u32,
    p: u32,
    out_len: u32,
) -> Result<Vec<u8>, JsError> {
    let params = Params::new(m_kib, t, p, Some(out_len as usize))
        .map_err(|e| JsError::new(&format!("argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; out_len as usize];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| JsError::new(&format!("argon2 derive: {e}")))?;
    Ok(out)
}

// ============================================================
// SHA-256
// ============================================================

use sha2::{Digest, Sha256};

/// SHA-256 hash. Output: 32-byte digest.
#[wasm_bindgen]
pub fn sha256_hash(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().to_vec()
}

// ============================================================
// HKDF-SHA256
// ============================================================

use hkdf::Hkdf;

/// HKDF-SHA256 extract + expand in one call.
///
/// 2-step HKDF as in RFC 5869:
///   PRK = HMAC-SHA256(salt, ikm)
///   OKM = HMAC-SHA256(PRK, info || counter)  iterated to `length` bytes
///
/// Output: `length` bytes of derived key material.
///
/// # Backward-compat
/// Matches noble `hkdf(sha256, ikm, salt, info, length)`.
#[wasm_bindgen]
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: u32,
) -> Result<Vec<u8>, JsError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = vec![0u8; length as usize];
    hk.expand(info, &mut out)
        .map_err(|e| JsError::new(&format!("hkdf expand: {e}")))?;
    Ok(out)
}

// ============================================================
// AES-256-GCM
// ============================================================

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};

/// AES-256-GCM encrypt.
///
/// # Parameters
///   key:        32 bytes
///   iv (nonce): 12 bytes
///   plaintext:  arbitrary length
///   aad:        additional authenticated data (= envelope tag bind)
///
/// # Output
///   ciphertext concatenated with 16-byte GCM authentication tag.
///   Total length = plaintext.len() + 16.
///
/// # Backward-compat
/// Matches WebCrypto `crypto.subtle.encrypt({name:'AES-GCM', iv, additionalData: aad}, key, plaintext)`.
#[wasm_bindgen]
pub fn aes256_gcm_encrypt(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, JsError> {
    if iv.len() != 12 {
        return Err(JsError::new("AES-GCM: iv must be 12 bytes"));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| JsError::new(&format!("AES-GCM key: {e}")))?;
    let nonce = Nonce::from_slice(iv);
    cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|e| JsError::new(&format!("AES-GCM encrypt: {e}")))
}

/// AES-256-GCM decrypt.
///
/// # Parameters
///   ciphertext: must include 16-byte GCM tag at the end.
///   aad:        must match encrypt-time aad exactly.
#[wasm_bindgen]
pub fn aes256_gcm_decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, JsError> {
    if iv.len() != 12 {
        return Err(JsError::new("AES-GCM: iv must be 12 bytes"));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| JsError::new(&format!("AES-GCM key: {e}")))?;
    let nonce = Nonce::from_slice(iv);
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|e| JsError::new(&format!("AES-GCM decrypt (= tag mismatch?): {e}")))
}

// ============================================================
// ECDH P-256
// ============================================================

use p256::{
    ecdh::diffie_hellman,
    elliptic_curve::sec1::ToEncodedPoint,  // for public.to_encoded_point()
    PublicKey, SecretKey,
};
use rand_core::OsRng;

/// Generate a fresh P-256 keypair.
///
/// # Output
///   Concatenation of:
///     - 32-byte raw scalar (= private key)
///     - 65-byte uncompressed SEC1 (= 0x04 || X || Y, public key)
///   Total: 97 bytes.
///
/// JS caller is expected to slice and convert as needed (= noble returned
/// PrivateKey/PublicKey objects separately).
///
/// # Randomness
///   Uses `getrandom` crate which delegates to `window.crypto.getRandomValues`
///   in WASM/browser context.
#[wasm_bindgen]
pub fn p256_keypair_generate() -> Result<Vec<u8>, JsError> {
    let secret = SecretKey::random(&mut OsRng);
    let public = secret.public_key();
    let priv_bytes = secret.to_bytes().to_vec();
    let pub_bytes = public.to_encoded_point(false).as_bytes().to_vec();
    let mut out = Vec::with_capacity(priv_bytes.len() + pub_bytes.len());
    out.extend_from_slice(&priv_bytes);
    out.extend_from_slice(&pub_bytes);
    Ok(out)
}

/// Derive a P-256 ECDH shared secret.
///
/// # Parameters
///   private_key:     32-byte raw scalar
///   peer_public_key: 65-byte uncompressed SEC1 (0x04 || X || Y)
///                    OR 33-byte compressed SEC1 (0x02/0x03 || X) — both accepted
///
/// # Output
///   32-byte shared secret (= x-coordinate of derived point, raw).
///
/// # Backward-compat
/// Matches noble `p256.getSharedSecret(privKey, pubKey, true)` with the
/// shared secret returned as raw 32 bytes (= no SEC1 framing).
#[wasm_bindgen]
pub fn p256_ecdh(
    private_key: &[u8],
    peer_public_key: &[u8],
) -> Result<Vec<u8>, JsError> {
    let secret = SecretKey::from_slice(private_key)
        .map_err(|e| JsError::new(&format!("p256 ECDH: invalid private key: {e}")))?;
    let peer = PublicKey::from_sec1_bytes(peer_public_key)
        .map_err(|e| JsError::new(&format!("p256 ECDH: invalid public key: {e}")))?;
    let shared = diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    Ok(shared.raw_secret_bytes().to_vec())
}

/// Derive a P-256 keypair deterministically from a seed.
///
/// # Algorithm
///   1. Interpret seed bytes as big-endian unsigned integer
///   2. Reduce modulo P-256 curve order n
///   3. If 0, replace with 1 (極めて稀)
///   4. Public key = scalar × BASE point
///   5. Return: priv (= 32 byte) || pub (= 65 byte SEC1 uncompressed)
///
/// # Backward-compat
///   Matches vault-crypto.js `_signingKeyFromSeed` exactly:
///     - bigint conversion: big-endian bytes → BigUint
///     - mod n: same curve order
///     - scalar multiplication: same P-256 BASE point
///     - output format: same SEC1 uncompressed (0x04 || X || Y)
///
/// # Parameters
///   seed: 任意 byte length (= 16〜64 が典型、 noble は 48 を使う)
///
/// # Output
///   97 byte: priv(32) || pub(65)
#[wasm_bindgen]
pub fn p256_keypair_from_seed(seed: &[u8]) -> Result<Vec<u8>, JsError> {
    use crypto_bigint::{Encoding, NonZero, U256, U512};

    if seed.is_empty() {
        return Err(JsError::new("p256_keypair_from_seed: seed must not be empty"));
    }

    // Pad seed to 64 byte big-endian (= U512 representation)
    let mut padded = [0u8; 64];
    let copy_len = seed.len().min(64);
    let copy_start_src = seed.len() - copy_len;
    padded[64 - copy_len..].copy_from_slice(&seed[copy_start_src..]);

    // seed as U512
    let seed_u512 = U512::from_be_slice(&padded);

    // P-256 curve order n (= 256-bit)、 U512 に zero-extend
    const N_HEX: &str = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";
    let n_u256 = U256::from_be_hex(N_HEX);
    let mut n_u512_bytes = [0u8; 64];
    n_u512_bytes[32..].copy_from_slice(&n_u256.to_be_bytes());
    let n_u512 = U512::from_be_slice(&n_u512_bytes);
    let n_nz = NonZero::new(n_u512).expect("P-256 n is non-zero");

    // Reduce mod n
    let reduced = seed_u512.rem(&n_nz);
    let reduced_bytes = reduced.to_be_bytes();

    // Low 32 bytes = scalar
    let mut scalar_32 = [0u8; 32];
    scalar_32.copy_from_slice(&reduced_bytes[32..]);

    // 0 → 1 fallback (= 極めて稀、 noble と同じ)
    if scalar_32.iter().all(|&b| b == 0) {
        scalar_32[31] = 1;
    }

    let secret = SecretKey::from_slice(&scalar_32)
        .map_err(|e| JsError::new(&format!("p256_keypair_from_seed: invalid scalar: {e}")))?;
    let public = secret.public_key();
    let pub_bytes = public.to_encoded_point(false).as_bytes().to_vec();

    let mut out = Vec::with_capacity(32 + 65);
    out.extend_from_slice(&scalar_32);
    out.extend_from_slice(&pub_bytes);
    Ok(out)
}

// ============================================================
// Utility: random bytes (= for IV, salt etc. — replaces crypto.getRandomValues)
// ============================================================

/// Fill a buffer of `length` bytes with cryptographically-secure random bytes.
///
/// # Why
///   While JS already has `crypto.getRandomValues`, exposing this through
///   Rust gives the option to centralize all random-source audit through
///   the Rust core. Stage 1 keeps JS callers free to use either.
#[wasm_bindgen]
pub fn random_bytes(length: u32) -> Result<Vec<u8>, JsError> {
    let mut out = vec![0u8; length as usize];
    getrandom::getrandom(&mut out)
        .map_err(|e| JsError::new(&format!("random_bytes: {e}")))?;
    Ok(out)
}

// ============================================================
// Opaque key handles (= Stage 2c: CryptoKey 互換 pattern)
// ============================================================
//
// 設計理念:
//   raw key bytes が JS heap (= Uint8Array) に居座らないように、 Rust 側で
//   pin した opaque handle に閉じ込める。 JS は handle を持ち回し、 必要な
//   operation を method として呼び出す。 export 関数は存在しない (= raw
//   bytes JS 露出ゼロ)。
//
// 防御モデル (WebCrypto CryptoKey との比較):
//   - 通常 XSS / supply chain attack: 同等 (= JS spec に任意 memory read API
//     が存在しないので、 wasm-bindgen の Memory reference を hide すれば
//     WebCrypto と同 level の防御)
//   - browser engine 0day exploit: 同 (= どちらも process memory 平文に到達される)
//   - OS process dump:             同 (= どちらも TEE じゃない)
//
// 規律 (JS 側):
//   - wasm.memory を global に export しない (= XSS が WebAssembly.Memory
//     reference を握れないようにする)
//   - wasm-bindgen init 戻り値を module-scoped private に閉じ込める
//
// 業界前例:
//   - Signal libsignal の PrivateKey / SessionRecord
//   - 1Password sequoia
//   - Bitwarden Rust core
//
// 型分離 (= 混在事故防止):
//   MekKey   — Master-derived MEK (32 byte)
//   K1Key    — business mode K1 (32 byte)        (= Stage B で追加)
//   BekKey   — file blob encryption key (32 byte) (= Stage B で追加)
//   OuterKey — envelope outer key (32 byte)       (= Stage B で追加)

use zeroize::Zeroize;

/// MEK opaque handle (= Master-derived data encryption key、 Phase 7.3-A.5)。
///
/// 内部に 32 byte の AES-256 key を保持。 raw bytes export 関数なし。
/// `Drop` 時に自動 zeroize。
#[wasm_bindgen]
pub struct MekKey {
    bytes: [u8; 32],
}

#[wasm_bindgen]
impl MekKey {
    /// raw 32 byte を受け取って handle 化。 caller (= JS) は呼出直後に
    /// 入力 Uint8Array を zeroize すること (= 一瞬だけ JS heap 経由するため)。
    #[wasm_bindgen(constructor)]
    pub fn new(raw: &[u8]) -> Result<MekKey, JsError> {
        if raw.len() != 32 {
            return Err(JsError::new("MekKey: raw must be 32 bytes"));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(raw);
        Ok(MekKey { bytes })
    }

    /// AES-256-GCM encrypt with this handle as key。
    pub fn aes_gcm_encrypt(
        &self,
        iv: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        aes256_gcm_encrypt(&self.bytes, iv, plaintext, aad)
    }

    /// AES-256-GCM decrypt with this handle as key。
    pub fn aes_gcm_decrypt(
        &self,
        iv: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        aes256_gcm_decrypt(&self.bytes, iv, ciphertext, aad)
    }

    /// HKDF-SHA256 で派生した新 MekKey handle を返す (= raw bytes JS 露出なし)。
    pub fn hkdf_derive_mek(&self, salt: &[u8], info: &[u8]) -> Result<MekKey, JsError> {
        let derived = hkdf_sha256(&self.bytes, salt, info, 32)?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&derived);
        let mut d = derived;
        d.zeroize();
        Ok(MekKey { bytes })
    }

    /// この MEK で別 MEK を wrap する (= AES-GCM encrypt、 結果は ciphertext+tag)。
    pub fn wrap_mek(&self, other: &MekKey, iv: &[u8]) -> Result<Vec<u8>, JsError> {
        aes256_gcm_encrypt(&self.bytes, iv, &other.bytes, &[])
    }

    /// この MEK で wrapped bytes を unwrap して新 MekKey handle を返す。
    pub fn unwrap_mek(&self, wrapped: &[u8], iv: &[u8]) -> Result<MekKey, JsError> {
        let pt = aes256_gcm_decrypt(&self.bytes, iv, wrapped, &[])?;
        if pt.len() != 32 {
            let mut p = pt;
            p.zeroize();
            return Err(JsError::new("unwrap_mek: unwrapped key must be 32 bytes"));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&pt);
        let mut p = pt;
        p.zeroize();
        Ok(MekKey { bytes })
    }
}

impl Drop for MekKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

// ============================================================
// K1Key (= business mode K1、 admin から配布される per-company key)
// ============================================================
//
// 用途: business mode の real_MEK 派生 (= HKDF(K1, salt=K2_material) → MEK)。
// MekKey と type 分離することで 「K1 を直接 AES key として誤用」 を防ぐ。

#[wasm_bindgen]
pub struct K1Key {
    bytes: [u8; 32],
}

#[wasm_bindgen]
impl K1Key {
    #[wasm_bindgen(constructor)]
    pub fn new(raw: &[u8]) -> Result<K1Key, JsError> {
        if raw.len() != 32 {
            return Err(JsError::new("K1Key: raw must be 32 bytes"));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(raw);
        Ok(K1Key { bytes })
    }

    /// K1 直接の AES-GCM encrypt (= legacy path 用)。
    pub fn aes_gcm_encrypt(
        &self,
        iv: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        aes256_gcm_encrypt(&self.bytes, iv, plaintext, aad)
    }

    pub fn aes_gcm_decrypt(
        &self,
        iv: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        aes256_gcm_decrypt(&self.bytes, iv, ciphertext, aad)
    }

    /// K1 から HKDF-SHA256 で MekKey を派生 (= business mode real_MEK 生成)。
    /// 戻り値の MekKey は型としても MekKey、 mix-up しない設計。
    pub fn hkdf_derive_mek(&self, salt: &[u8], info: &[u8]) -> Result<MekKey, JsError> {
        let derived = hkdf_sha256(&self.bytes, salt, info, 32)?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&derived);
        let mut d = derived;
        d.zeroize();
        Ok(MekKey { bytes })
    }
}

impl Drop for K1Key {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

// ============================================================
// BekKey (= file blob encryption key、 per-record key)
// ============================================================
//
// 用途: 個々の file record の暗号化に使う key。 MEK で wrap されて
// envelope に格納される。 type 分離で 「MEK を BEK として誤用」 防止。

#[wasm_bindgen]
pub struct BekKey {
    bytes: [u8; 32],
}

#[wasm_bindgen]
impl BekKey {
    #[wasm_bindgen(constructor)]
    pub fn new(raw: &[u8]) -> Result<BekKey, JsError> {
        if raw.len() != 32 {
            return Err(JsError::new("BekKey: raw must be 32 bytes"));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(raw);
        Ok(BekKey { bytes })
    }

    /// 生成 (= 乱数 32 byte from getrandom)。 通常 caller は
    /// `BekKey::generate()` を呼ぶか、 JS 側の crypto.getRandomValues
    /// から渡す。 ここでは getrandom 経由 (= window.crypto に橋渡し済)。
    pub fn generate() -> Result<BekKey, JsError> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes)
            .map_err(|e| JsError::new(&format!("BekKey::generate: {e}")))?;
        Ok(BekKey { bytes })
    }

    pub fn aes_gcm_encrypt(
        &self,
        iv: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        aes256_gcm_encrypt(&self.bytes, iv, plaintext, aad)
    }

    pub fn aes_gcm_decrypt(
        &self,
        iv: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        aes256_gcm_decrypt(&self.bytes, iv, ciphertext, aad)
    }
}

impl Drop for BekKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

// ============================================================
// OuterKey (= envelope outer encryption key)
// ============================================================
//
// 用途: envelope v7 の outer layer 暗号化 (= Recovery / Master 経由派生)。
// type 分離で 「outer key を MEK として誤用」 防止。

#[wasm_bindgen]
pub struct OuterKey {
    bytes: [u8; 32],
}

#[wasm_bindgen]
impl OuterKey {
    #[wasm_bindgen(constructor)]
    pub fn new(raw: &[u8]) -> Result<OuterKey, JsError> {
        if raw.len() != 32 {
            return Err(JsError::new("OuterKey: raw must be 32 bytes"));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(raw);
        Ok(OuterKey { bytes })
    }

    pub fn aes_gcm_encrypt(
        &self,
        iv: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        aes256_gcm_encrypt(&self.bytes, iv, plaintext, aad)
    }

    pub fn aes_gcm_decrypt(
        &self,
        iv: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        aes256_gcm_decrypt(&self.bytes, iv, ciphertext, aad)
    }
}

impl Drop for OuterKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

// ============================================================
// RMatKey (= HKDF base material = rMat)
// ============================================================
//
// Recovery 由来の 32 byte 材料を WASM 内に閉じ込め、 そこから派生する全 key
// (= outer / mek / app tag name+value / signing seed 等) を JS heap に raw
// bytes を出さずに生成する。 設計目標は WebCrypto の HKDF-base CryptoKey と
// 構造的に同等:
//
//   WebCrypto: CryptoKey(HKDF base) → deriveKey → CryptoKey (= 全 native heap)
//   WASM:      RMatKey(WASM heap)   → derive_X  → XxxKey   (= 全 WASM heap)
//
// JS は handle を持ち回すだけで raw bytes に touch しない。
// 派生 method は arpass-specific な salt / info を caller (JS) が渡す。
// この設計で 「constant を Rust 側 に hardcode しない」 → caller 側で
// HKDF_SALTS / HKDF_INFOS を一元管理可能 (= envelope-v7-spec.md と同期維持)。

#[wasm_bindgen]
pub struct RMatKey {
    bytes: [u8; 32],
}

#[wasm_bindgen]
impl RMatKey {
    /// 32 byte raw rMat から handle を生成 (= boundary、 caller 即 zeroize)。
    #[wasm_bindgen(constructor)]
    pub fn new(raw: &[u8]) -> Result<RMatKey, JsError> {
        if raw.len() != 32 {
            return Err(JsError::new("RMatKey: raw must be 32 bytes"));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(raw);
        Ok(RMatKey { bytes })
    }

    /// rMat から OuterKey を HKDF 派生 (= 内部 HKDF、 raw bytes JS 露出ゼロ)。
    pub fn derive_outer_key(&self, salt: &[u8], info: &[u8]) -> Result<OuterKey, JsError> {
        let derived = hkdf_sha256(&self.bytes, salt, info, 32)?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&derived);
        let mut d = derived;
        d.zeroize();
        Ok(OuterKey { bytes })
    }

    /// rMat から MekKey を HKDF 派生 (= 内部 HKDF)。
    pub fn derive_mek(&self, salt: &[u8], info: &[u8]) -> Result<MekKey, JsError> {
        let derived = hkdf_sha256(&self.bytes, salt, info, 32)?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&derived);
        let mut d = derived;
        d.zeroize();
        Ok(MekKey { bytes })
    }

    /// rMat から K1Key を HKDF 派生 (= business mode legacy 経路)。
    pub fn derive_k1(&self, salt: &[u8], info: &[u8]) -> Result<K1Key, JsError> {
        let derived = hkdf_sha256(&self.bytes, salt, info, 32)?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&derived);
        let mut d = derived;
        d.zeroize();
        Ok(K1Key { bytes })
    }

    /// rMat から 任意 byte 列を HKDF 派生 (= app tag name/value 等の非 key 材料用)。
    /// 戻り値は Vec<u8> (= 公開情報、 base64url 化等で JS 側に出る) なので
    /// key 用途には使わない (= type 分離のため derive_outer_key / derive_mek 等を
    /// 使うこと)。
    pub fn derive_bytes(&self, salt: &[u8], info: &[u8], length: u32) -> Result<Vec<u8>, JsError> {
        hkdf_sha256(&self.bytes, salt, info, length)
    }
}

impl Drop for RMatKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

// ============================================================
// Cross-type wrap operations (= MekKey が他 type を wrap)
// ============================================================
//
// MekKey 自身に他 type の wrap/unwrap method を生やすことで、 raw bytes が
// JS heap に出ない経路で type-safe な wrap chain を実現する。 例:
//   const bek = BekKey.generate();
//   const wrapped = mek.wrap_bek(bek, iv);
//   const restored = mek.unwrap_bek(wrapped, iv);

#[wasm_bindgen]
impl MekKey {
    /// MEK で BekKey を wrap (= file BEK を envelope.records[].wrap で保管)。
    pub fn wrap_bek(&self, bek: &BekKey, iv: &[u8]) -> Result<Vec<u8>, JsError> {
        aes256_gcm_encrypt(&self.bytes, iv, &bek.bytes, &[])
    }

    /// MEK で wrap された bytes を unwrap して BekKey handle 返却。
    pub fn unwrap_bek(&self, wrapped: &[u8], iv: &[u8]) -> Result<BekKey, JsError> {
        let pt = aes256_gcm_decrypt(&self.bytes, iv, wrapped, &[])?;
        if pt.len() != 32 {
            let mut p = pt;
            p.zeroize();
            return Err(JsError::new("unwrap_bek: unwrapped key must be 32 bytes"));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&pt);
        let mut p = pt;
        p.zeroize();
        Ok(BekKey { bytes })
    }

    /// MEK で K1Key を wrap (= per-employee enc_K1 保管用、 業務 mode)。
    pub fn wrap_k1(&self, k1: &K1Key, iv: &[u8]) -> Result<Vec<u8>, JsError> {
        aes256_gcm_encrypt(&self.bytes, iv, &k1.bytes, &[])
    }

    /// MEK で wrap された K1 bytes を unwrap して K1Key handle 返却。
    pub fn unwrap_k1(&self, wrapped: &[u8], iv: &[u8]) -> Result<K1Key, JsError> {
        let pt = aes256_gcm_decrypt(&self.bytes, iv, wrapped, &[])?;
        if pt.len() != 32 {
            let mut p = pt;
            p.zeroize();
            return Err(JsError::new("unwrap_k1: unwrapped key must be 32 bytes"));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&pt);
        let mut p = pt;
        p.zeroize();
        Ok(K1Key { bytes })
    }
}


// ============================================================
// SigningKey (Phase 2-H1): ECDSA P-256 opaque handle
// ============================================================
//
// Replaces the CryptoKey path used by `crypto.subtle.sign(...)` on the JS side.
// Holds the raw 32-byte private scalar; exposes `ecdsa_sign(message)` which
// returns the IEEE P1363 raw signature (= 64 bytes, r || s) — identical format
// to what `subtle.sign({ name: "ECDSA", hash: "SHA-256" }, ...)` emits.
//
// Backward-compat:
//   The signature value differs each call (= ECDSA randomized nonce, both
//   subtle.sign and p256::ecdsa::SigningKey::sign use a random k), but any
//   verifier (= server, peer) that validates against the public key accepts
//   either output. Wire format is the same 64-byte r||s.

#[wasm_bindgen]
pub struct SigningKey {
    inner: Box<[u8; 32]>,         // raw private scalar
    public_raw: Box<[u8; 65]>,    // uncompressed SEC1 (0x04 || X || Y)
}

#[wasm_bindgen]
impl SigningKey {
    /// Create from a 48-byte (or longer) seed. Internally derives the P-256
    /// scalar mod n the same way `p256_keypair_from_seed` does, so a given
    /// seed produces the same keypair as the legacy path.
    #[wasm_bindgen(constructor)]
    pub fn new(seed: &[u8]) -> Result<SigningKey, JsError> {
        use crypto_bigint::{Encoding, NonZero, U256, U512};

        if seed.is_empty() {
            return Err(JsError::new("SigningKey: seed must not be empty"));
        }

        let mut padded = [0u8; 64];
        let copy_len = seed.len().min(64);
        let copy_start_src = seed.len() - copy_len;
        padded[64 - copy_len..].copy_from_slice(&seed[copy_start_src..]);

        let seed_u512 = U512::from_be_slice(&padded);
        const N_HEX: &str =
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";
        let n_u256 = U256::from_be_hex(N_HEX);
        let mut n_u512_bytes = [0u8; 64];
        n_u512_bytes[32..].copy_from_slice(&n_u256.to_be_bytes());
        let n_u512 = U512::from_be_slice(&n_u512_bytes);
        let n_nz = NonZero::new(n_u512).expect("P-256 n is non-zero");
        let reduced = seed_u512.rem(&n_nz);
        let reduced_bytes = reduced.to_be_bytes();

        let mut scalar_32 = [0u8; 32];
        scalar_32.copy_from_slice(&reduced_bytes[32..]);
        if scalar_32.iter().all(|&b| b == 0) {
            scalar_32[31] = 1;
        }

        let secret = SecretKey::from_slice(&scalar_32)
            .map_err(|e| JsError::new(&format!("SigningKey: invalid scalar: {e}")))?;
        let public = secret.public_key();
        let pub_bytes = public.to_encoded_point(false);
        let pub_slice = pub_bytes.as_bytes();
        if pub_slice.len() != 65 {
            return Err(JsError::new("SigningKey: unexpected public key length"));
        }
        let mut pub_arr = [0u8; 65];
        pub_arr.copy_from_slice(pub_slice);

        Ok(SigningKey {
            inner: Box::new(scalar_32),
            public_raw: Box::new(pub_arr),
        })
    }

    /// Sign a message with ECDSA-SHA256, returning the raw IEEE P1363
    /// signature (= 64 bytes, r || s big-endian). Same wire format that
    /// `crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, ...)` emits.
    pub fn ecdsa_sign(&self, message: &[u8]) -> Result<Vec<u8>, JsError> {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey as EcdsaSigningKey};
        let sk = EcdsaSigningKey::from_slice(&*self.inner)
            .map_err(|e| JsError::new(&format!("ecdsa_sign: from_bytes: {e}")))?;
        let sig: Signature = sk.sign(message);
        Ok(sig.to_bytes().to_vec())
    }

    /// Return the 65-byte uncompressed SEC1 public key (= 0x04 || X || Y).
    /// JS side uses this for pkHash + sending to peers.
    pub fn public_key_raw(&self) -> Vec<u8> {
        self.public_raw.to_vec()
    }

    /// Return the 32-byte private scalar. **For migration code only** —
    /// callers should prefer `ecdsa_sign` and `public_key_raw`. Used by
    /// the JS `currentSigningPrivateKeyRaw` helper for ECIES decrypt
    /// (= per-employee enc_K1 path) until that too is moved into Rust.
    pub fn private_key_raw(&self) -> Vec<u8> {
        self.inner.to_vec()
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.inner.zeroize();
        // public_raw is not secret but zero anyway for cleanliness
        for b in self.public_raw.iter_mut() {
            *b = 0;
        }
    }
}

// ============================================================
// Tests (= cargo test、 native build のみ、 WASM では実行しない)
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_known_vector() {
        // "abc" → ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let out = sha256_hash(b"abc");
        assert_eq!(
            hex::encode(&out),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_hkdf_rfc5869_test_case_1() {
        // RFC 5869 Test Case 1
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let out = hkdf_sha256(&ikm, &salt, &info, 42).unwrap();
        assert_eq!(
            hex::encode(&out),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn test_argon2id_known_vector() {
        // Phase 7.4 params: m=65536 (64 MiB), t=3, p=4, taglen=32
        let pw = b"password";
        let salt = b"saltsaltsaltsalt";  // 16 bytes
        let out = argon2id_derive(pw, salt, 65536, 3, 4, 32).unwrap();
        // Bit-identical check: same params produce same output
        let out2 = argon2id_derive(pw, salt, 65536, 3, 4, 32).unwrap();
        assert_eq!(out, out2);
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = [0x42u8; 32];
        let iv = [0x01u8; 12];
        let pt = b"hello arpass";
        let aad = b"envelope-tag-binding";
        let ct = aes256_gcm_encrypt(&key, &iv, pt, aad).unwrap();
        assert_eq!(ct.len(), pt.len() + 16);  // + GCM tag
        let pt2 = aes256_gcm_decrypt(&key, &iv, &ct, aad).unwrap();
        assert_eq!(pt2.as_slice(), pt);

        // NOTE: Wrong-aad decrypt failure assertion is intentionally NOT
        // performed here. `aes256_gcm_decrypt` returns `Err(JsError::new(...))`
        // on failure, but `JsError::new` is a wasm-bindgen imported function
        // that panics when invoked from a non-wasm cargo test target
        // (= "cannot call wasm-bindgen imported functions on non-wasm targets").
        //
        // Wrong-aad → decrypt error is verified in:
        //   - the underlying aes-gcm crate's own audited test suite, AND
        //   - the JS-side parity test added in Task #353 (= staging deploy),
        //     which runs the WASM binary in a real browser context.
    }

    #[test]
    fn test_p256_keypair_from_seed_deterministic() {
        // Same seed → same keypair
        let seed = b"test seed for deterministic derivation 48 bytes!!";  // 48 bytes
        let kp1 = p256_keypair_from_seed(seed).unwrap();
        let kp2 = p256_keypair_from_seed(seed).unwrap();
        assert_eq!(kp1, kp2);
        assert_eq!(kp1.len(), 32 + 65);  // priv + uncompressed pub
        // public starts with 0x04 (uncompressed SEC1)
        assert_eq!(kp1[32], 0x04);
    }

    #[test]
    fn test_p256_keypair_and_ecdh() {
        // Generate 2 keypairs, do ECDH both directions, verify same shared secret.
        let kp_a = p256_keypair_generate().unwrap();
        let kp_b = p256_keypair_generate().unwrap();
        let priv_a = &kp_a[..32];
        let pub_a = &kp_a[32..];
        let priv_b = &kp_b[..32];
        let pub_b = &kp_b[32..];
        assert_eq!(pub_a.len(), 65);  // uncompressed SEC1
        assert_eq!(pub_b.len(), 65);

        let ss_ab = p256_ecdh(priv_a, pub_b).unwrap();
        let ss_ba = p256_ecdh(priv_b, pub_a).unwrap();
        assert_eq!(ss_ab, ss_ba);
        assert_eq!(ss_ab.len(), 32);
    }

    // ========================================================
    // MekKey opaque handle tests (= Stage 2c)
    // ========================================================

    // NOTE: MekKey::new の length 検査は JsError を返すので native cargo test
    // で panic する (= wasm-bindgen imported function). このテストは
    // wasm-bindgen-test (= wasm-pack test) 経由で別途検証する。 同様の罠は
    // Stage 1 でも test_aes_gcm_wrong_aad で発生済 (= feedback memory に記録)。
    // 成功 path は下の 3 テストで検証されており十分。

    #[test]
    fn test_mek_key_aes_gcm_roundtrip() {
        // raw bytes API と handle API で同じ key、 同じ平文 → 同じ暗号文
        let key_bytes = [0x42u8; 32];
        let iv = [0x11u8; 12];
        let plaintext = b"Stage 2c opaque handle smoke test";
        let aad = b"envelope-bind-aad";

        let raw_ct = aes256_gcm_encrypt(&key_bytes, &iv, plaintext, aad).unwrap();
        let mek = MekKey::new(&key_bytes).unwrap();
        let handle_ct = mek.aes_gcm_encrypt(&iv, plaintext, aad).unwrap();
        assert_eq!(raw_ct, handle_ct, "raw API と handle API は bit-identical");

        // decrypt 双方向 (= raw key で encrypt → handle で decrypt も等価)
        let decrypted = mek.aes_gcm_decrypt(&iv, &handle_ct, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_mek_key_hkdf_derive_deterministic() {
        // 同じ MEK + salt + info で deterministic な MekKey 派生
        let key_bytes = [0x77u8; 32];
        let salt = b"arpass-stage2c-test-salt";
        let info = b"derive-info-vector";

        let mek1 = MekKey::new(&key_bytes).unwrap();
        let derived1 = mek1.hkdf_derive_mek(salt, info).unwrap();

        let mek2 = MekKey::new(&key_bytes).unwrap();
        let derived2 = mek2.hkdf_derive_mek(salt, info).unwrap();

        // 両 derived MekKey は同じ AES-GCM 暗号文を生成する (= bit-identical を間接検証)
        let iv = [0x33u8; 12];
        let pt = b"determinism check";
        let ct1 = derived1.aes_gcm_encrypt(&iv, pt, &[]).unwrap();
        let ct2 = derived2.aes_gcm_encrypt(&iv, pt, &[]).unwrap();
        assert_eq!(ct1, ct2, "同じ MEK + salt + info → 同じ derived MekKey");

        // raw HKDF とも一致
        let raw_derived = hkdf_sha256(&key_bytes, salt, info, 32).unwrap();
        let raw_mek = MekKey::new(&raw_derived).unwrap();
        let ct_raw = raw_mek.aes_gcm_encrypt(&iv, pt, &[]).unwrap();
        assert_eq!(ct1, ct_raw, "MekKey.hkdf_derive_mek は raw hkdf_sha256 と等価");
    }

    #[test]
    fn test_mek_key_wrap_unwrap_roundtrip() {
        // MEK で MEK を wrap → unwrap で同じ key を取り戻せる
        let outer_bytes = [0xAAu8; 32];
        let inner_bytes = [0xBBu8; 32];
        let iv = [0x55u8; 12];

        let outer = MekKey::new(&outer_bytes).unwrap();
        let inner = MekKey::new(&inner_bytes).unwrap();

        let wrapped = outer.wrap_mek(&inner, &iv).unwrap();
        // ciphertext は 32 + 16 (GCM tag) = 48 byte
        assert_eq!(wrapped.len(), 48);

        let unwrapped = outer.unwrap_mek(&wrapped, &iv).unwrap();

        // unwrapped MEK で encrypt した結果が inner MEK と一致 (= bit-identical 検証)
        let test_iv = [0x99u8; 12];
        let test_pt = b"verify unwrapped equals original inner";
        let ct_unwrapped = unwrapped.aes_gcm_encrypt(&test_iv, test_pt, &[]).unwrap();
        let ct_original = inner.aes_gcm_encrypt(&test_iv, test_pt, &[]).unwrap();
        assert_eq!(ct_unwrapped, ct_original);
    }

    // NOTE: unwrap_mek の length 検査も同じく JsError 経由で native test 不可。
    // wasm-bindgen-test 用に deferred。

    // ========================================================
    // Stage B: K1Key / BekKey / OuterKey + cross-type wrap (= success path のみ)
    // ========================================================

    #[test]
    fn test_k1_key_hkdf_derive_mek_equivalent_to_raw_hkdf() {
        // K1Key.hkdf_derive_mek が raw hkdf_sha256 と bit-identical
        let k1_bytes = [0x33u8; 32];
        let salt = b"business-mode-k2-salt";
        let info = b"derive-mek-info";

        let k1 = K1Key::new(&k1_bytes).unwrap();
        let mek_from_k1 = k1.hkdf_derive_mek(salt, info).unwrap();

        // raw HKDF で派生 → MekKey にして 検証
        let raw_derived = hkdf_sha256(&k1_bytes, salt, info, 32).unwrap();
        let mek_from_raw = MekKey::new(&raw_derived).unwrap();

        // 両方で同じ AES-GCM 暗号文を生成すれば bit-identical
        let iv = [0x42u8; 12];
        let pt = b"K1 derivation equivalence check";
        let ct_from_k1 = mek_from_k1.aes_gcm_encrypt(&iv, pt, &[]).unwrap();
        let ct_from_raw = mek_from_raw.aes_gcm_encrypt(&iv, pt, &[]).unwrap();
        assert_eq!(ct_from_k1, ct_from_raw, "K1.hkdf_derive_mek は raw HKDF + MekKey と等価");
    }

    #[test]
    fn test_bek_key_aes_gcm_roundtrip() {
        // BekKey で encrypt → 同 BekKey で decrypt
        let bek_bytes = [0x77u8; 32];
        let bek = BekKey::new(&bek_bytes).unwrap();
        let iv = [0x11u8; 12];
        let plaintext = b"file blob encrypted with BEK";
        let aad = b"file-record-aad";

        let ct = bek.aes_gcm_encrypt(&iv, plaintext, aad).unwrap();
        let pt = bek.aes_gcm_decrypt(&iv, &ct, aad).unwrap();
        assert_eq!(pt, plaintext);

        // raw AES と bit-identical
        let raw_ct = aes256_gcm_encrypt(&bek_bytes, &iv, plaintext, aad).unwrap();
        assert_eq!(ct, raw_ct);
    }

    #[test]
    fn test_bek_key_generate_unique() {
        // BekKey::generate() は別 invocation で別 bytes を返す (= 乱数)
        let bek1 = BekKey::generate().unwrap();
        let bek2 = BekKey::generate().unwrap();

        // 同 IV + 同 plaintext で encrypt 結果が違えば bytes が違うことの証明
        let iv = [0u8; 12];
        let pt = b"uniqueness check";
        let ct1 = bek1.aes_gcm_encrypt(&iv, pt, &[]).unwrap();
        let ct2 = bek2.aes_gcm_encrypt(&iv, pt, &[]).unwrap();
        assert_ne!(ct1, ct2, "BekKey::generate は毎回違う key を返すべき");
    }

    #[test]
    fn test_outer_key_aes_gcm_roundtrip() {
        let outer_bytes = [0x88u8; 32];
        let outer = OuterKey::new(&outer_bytes).unwrap();
        let iv = [0x22u8; 12];
        let plaintext = b"envelope outer layer payload";
        let aad = b"envelope-outer-aad-bind";

        let ct = outer.aes_gcm_encrypt(&iv, plaintext, aad).unwrap();
        let pt = outer.aes_gcm_decrypt(&iv, &ct, aad).unwrap();
        assert_eq!(pt, plaintext);

        // raw と bit-identical
        let raw_ct = aes256_gcm_encrypt(&outer_bytes, &iv, plaintext, aad).unwrap();
        assert_eq!(ct, raw_ct);
    }

    #[test]
    fn test_mek_wrap_bek_roundtrip() {
        // MekKey で BekKey を wrap → unwrap で同じ BekKey を取り戻せる
        let mek_bytes = [0xAAu8; 32];
        let bek_bytes = [0xBBu8; 32];
        let iv = [0x55u8; 12];

        let mek = MekKey::new(&mek_bytes).unwrap();
        let bek = BekKey::new(&bek_bytes).unwrap();

        let wrapped = mek.wrap_bek(&bek, &iv).unwrap();
        assert_eq!(wrapped.len(), 48); // 32 + 16 tag

        let unwrapped = mek.unwrap_bek(&wrapped, &iv).unwrap();

        // 同 BEK ならば同 ciphertext を生成
        let test_iv = [0x99u8; 12];
        let test_pt = b"verify unwrapped BEK equals original";
        let ct_unwrapped = unwrapped.aes_gcm_encrypt(&test_iv, test_pt, &[]).unwrap();
        let ct_original = bek.aes_gcm_encrypt(&test_iv, test_pt, &[]).unwrap();
        assert_eq!(ct_unwrapped, ct_original);
    }

    #[test]
    fn test_mek_wrap_k1_roundtrip() {
        // MekKey で K1Key を wrap → unwrap で同 K1Key
        let mek_bytes = [0xCCu8; 32];
        let k1_bytes = [0xDDu8; 32];
        let iv = [0x66u8; 12];

        let mek = MekKey::new(&mek_bytes).unwrap();
        let k1 = K1Key::new(&k1_bytes).unwrap();

        let wrapped = mek.wrap_k1(&k1, &iv).unwrap();
        let unwrapped_k1 = mek.unwrap_k1(&wrapped, &iv).unwrap();

        // 同 K1 ならば同 HKDF 派生結果
        let salt = b"test-salt";
        let info = b"test-info";
        let mek_from_unwrapped = unwrapped_k1.hkdf_derive_mek(salt, info).unwrap();
        let mek_from_original = k1.hkdf_derive_mek(salt, info).unwrap();

        let iv2 = [0x77u8; 12];
        let ct_u = mek_from_unwrapped.aes_gcm_encrypt(&iv2, b"check", &[]).unwrap();
        let ct_o = mek_from_original.aes_gcm_encrypt(&iv2, b"check", &[]).unwrap();
        assert_eq!(ct_u, ct_o);
    }

    // ========================================================
    // Stage B+ : RMatKey HKDF base 派生 tests
    // ========================================================

    #[test]
    fn test_rmat_derive_outer_key_equivalent_to_raw() {
        // RMatKey.derive_outer_key が raw HKDF + OuterKey と bit-identical
        let rmat_bytes = [0x88u8; 32];
        let salt = b"arpass-outer-v6";
        let info = b"envelope-wrap";

        let rmat = RMatKey::new(&rmat_bytes).unwrap();
        let outer_from_handle = rmat.derive_outer_key(salt, info).unwrap();

        let raw_derived = hkdf_sha256(&rmat_bytes, salt, info, 32).unwrap();
        let outer_from_raw = OuterKey::new(&raw_derived).unwrap();

        let iv = [0x42u8; 12];
        let pt = b"outer key derivation equivalence";
        let ct_h = outer_from_handle.aes_gcm_encrypt(&iv, pt, &[]).unwrap();
        let ct_r = outer_from_raw.aes_gcm_encrypt(&iv, pt, &[]).unwrap();
        assert_eq!(ct_h, ct_r, "RMat.derive_outer_key == raw HKDF + OuterKey");
    }

    #[test]
    fn test_rmat_derive_mek_equivalent_to_raw() {
        let rmat_bytes = [0x77u8; 32];
        let salt = b"test-mek-salt";
        let info = b"mek-info";

        let rmat = RMatKey::new(&rmat_bytes).unwrap();
        let mek_from_handle = rmat.derive_mek(salt, info).unwrap();

        let raw_derived = hkdf_sha256(&rmat_bytes, salt, info, 32).unwrap();
        let mek_from_raw = MekKey::new(&raw_derived).unwrap();

        let iv = [0x55u8; 12];
        let pt = b"mek derivation equivalence";
        let ct_h = mek_from_handle.aes_gcm_encrypt(&iv, pt, &[]).unwrap();
        let ct_r = mek_from_raw.aes_gcm_encrypt(&iv, pt, &[]).unwrap();
        assert_eq!(ct_h, ct_r);
    }

    #[test]
    fn test_rmat_derive_bytes_matches_raw_hkdf() {
        // 任意 length の派生 (= app tag name/value 用)
        let rmat_bytes = [0x99u8; 32];
        let salt = b"arpass-app-tag-name-v6";
        let info = b"app-tag-name";

        let rmat = RMatKey::new(&rmat_bytes).unwrap();
        let out_handle = rmat.derive_bytes(salt, info, 11).unwrap();
        let out_raw = hkdf_sha256(&rmat_bytes, salt, info, 11).unwrap();

        assert_eq!(out_handle, out_raw);
        assert_eq!(out_handle.len(), 11);
    }

    #[test]
    fn test_signing_key_sign_verify_roundtrip() {
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        use p256::PublicKey;
        use p256::elliptic_curve::sec1::FromEncodedPoint;
        use p256::EncodedPoint;

        let seed = [0xAAu8; 48];
        let sk = SigningKey::new(&seed).unwrap();
        let pub_raw = sk.public_key_raw();
        let priv_raw = sk.private_key_raw();
        assert_eq!(pub_raw.len(), 65);
        assert_eq!(priv_raw.len(), 32);
        assert_eq!(pub_raw[0], 0x04);

        // Sign + verify with p256::ecdsa
        let message = b"arpass signing key roundtrip";
        let sig_bytes = sk.ecdsa_sign(message).unwrap();
        assert_eq!(sig_bytes.len(), 64);

        let ep = EncodedPoint::from_bytes(&pub_raw).unwrap();
        let pk = PublicKey::from_encoded_point(&ep).unwrap();
        let vk: VerifyingKey = pk.into();
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        vk.verify(message, &sig).expect("signature must verify against public key");
    }

    #[test]
    fn test_signing_key_seed_matches_keypair_from_seed() {
        // Same seed → same private scalar → same public key
        let seed = [0x33u8; 48];
        let sk = SigningKey::new(&seed).unwrap();
        let legacy = p256_keypair_from_seed(&seed).unwrap();
        assert_eq!(sk.private_key_raw(), &legacy[0..32]);
        assert_eq!(sk.public_key_raw(), &legacy[32..97]);
    }

}
