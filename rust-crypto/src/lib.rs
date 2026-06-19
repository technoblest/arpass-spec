// ====================================================================
// ⚠️ AUTO-GENERATED MIRROR — DO NOT PR HERE
//
// This file is automatically synced from the private arpass repo on every
// release. Direct edits to this file will be overwritten.
//
// Source: technoblest/arpass / rust-crypto/src/lib.rs
// Mirror generator: scripts/generate-arpass-spec-mirror.mjs
// ====================================================================

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

/// 増分2 (KEK の WASM 内派生): 2 つの factor material を concat → HKDF-SHA256 →
/// 32-byte KEK を `MekKey` opaque handle として返す。 KEK の raw bytes は JS heap に
/// 一切出ない (= JS `deriveKEK` の "B window" を閉じる)。
///
/// bit-equivalence: 旧経路 `hkdf_sha256(concat(m1,m2), salt, info, 32)` → `new MekKey(raw)`
/// と完全一致 (同一 HKDF-SHA256、 IKM = material1 || material2、 同一 salt/info)。
///
/// material1/material2 (= pMat/kMat/rMat 等) は呼出側で zeroize 推奨。
#[wasm_bindgen]
pub fn derive_kek_handle(
    material1: &[u8],
    material2: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Result<MekKey, JsError> {
    let mut ikm = Vec::with_capacity(material1.len() + material2.len());
    ikm.extend_from_slice(material1);
    ikm.extend_from_slice(material2);
    let derived = hkdf_sha256(&ikm, salt, info, 32);
    ikm.zeroize();
    let mut derived = derived?;
    if derived.len() != 32 {
        derived.zeroize();
        return Err(JsError::new("derive_kek_handle: HKDF output must be 32 bytes"));
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&derived);
    derived.zeroize();
    Ok(MekKey { bytes })
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
// AES-256-CTR  (envelope v7 user.id outer-key Master-wrap)
// ============================================================

use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};

type Aes256Ctr64BE = ctr::Ctr64BE<Aes256>;

/// AES-256-CTR keystream apply (= encrypt と decrypt は同一操作)。
///
/// # Parameters
///   key:     32 bytes
///   counter: 16-byte initial counter block (= 下位 64 bit のみ increment)
///   data:    arbitrary length (= v7 user.id wrap では 32B)
///
/// # Backward-compat (CRITICAL)
/// WebCrypto `subtle.encrypt({name:"AES-CTR", counter, length: 64}, ...)` と
/// bit-identical であること。 length=64 は counter block の下位 64 bit のみを
/// increment する指定で、 RustCrypto の `Ctr64BE` がこれに一致する。
/// 既存の v7 user.id (= Arweave 上ではなく Passkey 内に永続) を再発行なしで
/// 復号し続けるため、 この互換性は絶対に壊さないこと。
/// 検証ベクタは Node webcrypto (= WebCrypto 実装) で生成・照合済み。
///
/// # 用途
/// vault-crypto.js `_wrapOuterForUserId`:
///   KEK     = Argon2id(Master, salt=appNameTag.value, USERID_KDF_PARAMS)
///   counter = SHA-256("arpass-userid-v7-ctr" || nameB || valB)[0..16]
///   wrapped = AES-256-CTR(KEK, counter, outerKey 32B)
#[wasm_bindgen]
pub fn aes256_ctr_apply(
    key: &[u8],
    counter: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, JsError> {
    if key.len() != 32 {
        return Err(JsError::new("AES-CTR: key must be 32 bytes"));
    }
    if counter.len() != 16 {
        return Err(JsError::new("AES-CTR: counter must be 16 bytes"));
    }
    let mut cipher = Aes256Ctr64BE::new_from_slices(key, counter)
        .map_err(|e| JsError::new(&format!("AES-CTR init: {e}")))?;
    let mut out = data.to_vec();
    cipher.apply_keystream(&mut out);
    Ok(out)
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

    /// Phase 2-H4-full F3: HKDF-SHA256 で任意 length の raw bytes を派生。
    /// K2 (= MekKey 流用) を IKM として sub-key 派生 (= signing key seed 48 byte,
    /// recoveryProtect key 32 byte 等) に使う。
    /// 戻り値の Vec<u8> は短命、 caller が即消費 + zeroize すること。
    pub fn hkdf_derive_bytes(
        &self,
        salt: &[u8],
        info: &[u8],
        dk_len: u32,
    ) -> Result<Vec<u8>, JsError> {
        hkdf_sha256(&self.bytes, salt, info, dk_len)
    }

    /// Phase 2-H4-full F3: K2 から HKDF で 48-byte seed 派生 → SigningKey handle 返却。
    /// JS の `deriveSigningKeyFromHkdf` を 1 関数に統合、 seed が JS heap に出現しない。
    /// Business mode の signing identity 派生 (= K2-based) 用。
    pub fn derive_signing_key(
        &self,
        salt: &[u8],
        info: &[u8],
    ) -> Result<SigningKey, JsError> {
        let mut seed = hkdf_sha256(&self.bytes, salt, info, 48)?;
        let sk = SigningKey::new(&seed);
        seed.zeroize();
        sk
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

    /// Phase 2-H4-full F1: Business V2 MEK 派生。
    ///   IKM = K2.bytes (= MekKey 流用、 32 byte AES-GCM kdf base 互換)
    ///   salt = self.bytes (= K1)
    ///   info = caller 指定 (= "mek-business-v2" 相当)
    /// K1 raw bytes は WASM 内のみ、 K2 raw bytes も MekKey handle 内のみ。
    pub fn derive_business_mek_v2(
        &self,
        k2: &MekKey,
        info: &[u8],
    ) -> Result<MekKey, JsError> {
        let derived = hkdf_sha256(&k2.bytes, &self.bytes, info, 32)?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&derived);
        let mut d = derived;
        d.zeroize();
        Ok(MekKey { bytes })
    }

    /// Phase 2-H4-full F1: Business V2 mekHkdfKey 同等の派生。
    /// 同じ IKM/salt/info で別 length を出すなら caller が dkLen 指定可能。
    /// HKDF base CryptoKey の代替として、 raw bytes を期待する caller がある場合に使う。
    pub fn derive_business_mek_v2_bytes(
        &self,
        k2: &MekKey,
        info: &[u8],
        len: u32,
    ) -> Result<Vec<u8>, JsError> {
        hkdf_sha256(&k2.bytes, &self.bytes, info, len)
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

    /// Phase 2-H4-full F2: ECIES decrypt の結果を K1Key opaque handle として返す。
    /// JS 側で eciesDecrypt → K1 raw → new K1Key (= 並列 populate) の 3 段階を
    /// 1 つの Rust 関数に統合。 K1 raw bytes は WASM 内のみで生存、 JS heap 露出ゼロ。
    ///
    /// # 引数
    ///   ephemeral_pub: 65 byte uncompressed SEC1 (= sender 側 ephemeral 公開鍵)
    ///   iv: AES-GCM IV
    ///   ciphertext: AES-GCM 暗号文 (= K1 32B + tag 16B)
    ///   hkdf_salt: ECIES KEK 派生用 salt (= JS 側 ECIES_HKDF_SALT = "arpass-ecies-v1")
    ///   hkdf_info: ECIES KEK 派生用 info (= JS 側 ECIES_HKDF_INFO = "kek")
    ///
    /// # 中間値の取り扱い
    ///   shared_x / kek / pt は短命の Vec<u8>、 explicit zeroize で確定的破棄。
    pub fn ecies_unwrap_to_k1key(
        &self,
        ephemeral_pub: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        hkdf_salt: &[u8],
        hkdf_info: &[u8],
    ) -> Result<K1Key, JsError> {
        // 1. ECDH(self.private, ephemeral_pub) → sharedX (32 byte)
        let secret = SecretKey::from_slice(&*self.inner)
            .map_err(|e| JsError::new(&format!("ecies_unwrap_to_k1key: invalid private: {e}")))?;
        let peer = PublicKey::from_sec1_bytes(ephemeral_pub)
            .map_err(|e| JsError::new(&format!("ecies_unwrap_to_k1key: invalid peer pub: {e}")))?;
        let shared = diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
        let mut shared_x: Vec<u8> = shared.raw_secret_bytes().to_vec();

        // 2. HKDF(sharedX, hkdf_salt, hkdf_info, 32) → kek
        let mut kek = match hkdf_sha256(&shared_x, hkdf_salt, hkdf_info, 32) {
            Ok(k) => k,
            Err(e) => {
                shared_x.zeroize();
                return Err(e);
            }
        };
        shared_x.zeroize();

        // 3. AES-GCM-256 decrypt(kek, iv, ciphertext) → K1 raw 32B
        let mut pt = match aes256_gcm_decrypt(&kek, iv, ciphertext, &[]) {
            Ok(p) => p,
            Err(e) => {
                kek.zeroize();
                return Err(e);
            }
        };
        kek.zeroize();

        if pt.len() != 32 {
            pt.zeroize();
            return Err(JsError::new("ecies_unwrap_to_k1key: plaintext must be 32 bytes"));
        }

        // 4. Construct K1Key handle (= raw bytes stay in WASM)
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&pt);
        pt.zeroize();
        Ok(K1Key { bytes })
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
// EmpPrivKey opaque handle (= Phase 2-F8、 K1 raw window 消去)
// ============================================================
//
// 用途: Business V2 で member の ECDH 秘密鍵 (= w_emp 復号後の 32-byte scalar)
// を opaque handle として保持。 これで `ecies_unwrap_to_k1key` を method 化、
// 既存 standalone 関数 `ecies_unwrap_to_k1key_with_emp_priv` の wrapper として
// raw scalar が JS heap に出現しない経路を提供する。
//
// 設計:
// - 32-byte private scalar を Box<[u8;32]> で hold
// - Drop で zeroize
// - new(raw: &[u8]) constructor + ecies_unwrap_to_k1key method
// - 既存 standalone 関数とは内部的に同じ ECIES 実装を共有 (bit-equiv)

#[wasm_bindgen]
pub struct EmpPrivKey {
    inner: Box<[u8; 32]>,
}

#[wasm_bindgen]
impl EmpPrivKey {
    /// 32-byte raw P-256 private scalar から EmpPrivKey opaque handle を構築。
    /// JS heap 側で短時間 raw を持っているが、 import 後は handle 内に閉じ込められる。
    #[wasm_bindgen(constructor)]
    pub fn new(raw: &[u8]) -> Result<EmpPrivKey, JsError> {
        if raw.len() != 32 {
            return Err(JsError::new("EmpPrivKey::new: emp_priv must be 32 bytes"));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(raw);
        // Validate by attempting to construct SecretKey (= reject zero / invalid).
        SecretKey::from_slice(&bytes)
            .map_err(|e| JsError::new(&format!("EmpPrivKey::new: invalid scalar: {e}")))?;
        Ok(EmpPrivKey { inner: Box::new(bytes) })
    }

    /// PKCS#8 DER 形式の private key bytes から EmpPrivKey opaque handle を構築。
    /// JS 側で `subtle.decrypt(w_emp)` 直後の pkcs8 raw bytes をそのまま渡せる。
    /// 内部で SecretKey::from_pkcs8_der で parse、 32-byte scalar を抽出して保持。
    pub fn from_pkcs8(pkcs8_der: &[u8]) -> Result<EmpPrivKey, JsError> {
        use p256::pkcs8::DecodePrivateKey;
        let secret = SecretKey::from_pkcs8_der(pkcs8_der)
            .map_err(|e| JsError::new(&format!("EmpPrivKey::from_pkcs8: parse failed: {e}")))?;
        let scalar_bytes = secret.to_bytes();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(scalar_bytes.as_slice());
        Ok(EmpPrivKey { inner: Box::new(bytes) })
    }

    /// ECIES unwrap: ephemeral_pub + iv + ciphertext を受けて、 K1Key opaque handle を返す。
    /// 内部は standalone `ecies_unwrap_to_k1key_with_emp_priv` と同じ実装 = bit-equiv 担保。
    pub fn ecies_unwrap_to_k1key(
        &self,
        ephemeral_pub: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        hkdf_salt: &[u8],
        hkdf_info: &[u8],
    ) -> Result<K1Key, JsError> {
        ecies_unwrap_to_k1key_with_emp_priv(
            &self.inner[..],
            ephemeral_pub,
            iv,
            ciphertext,
            hkdf_salt,
            hkdf_info,
        )
    }
}

impl Drop for EmpPrivKey {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}


/// Phase 2-H4-full F6: standalone ECIES unwrap to K1Key opaque handle.
/// emp_priv_raw を取って ECIES decrypt + K1Key 構築を 1 関数で。
/// K1 raw bytes は WASM 内のみ、 emp_priv は caller (= JS) で raw 保持中だが
/// K1 の hiding が主目的。
#[wasm_bindgen]
pub fn ecies_unwrap_to_k1key_with_emp_priv(
    emp_priv_raw: &[u8],
    ephemeral_pub: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    hkdf_salt: &[u8],
    hkdf_info: &[u8],
) -> Result<K1Key, JsError> {
    use zeroize::Zeroize;
    if emp_priv_raw.len() != 32 {
        return Err(JsError::new("ecies_unwrap_to_k1key_with_emp_priv: emp_priv must be 32 bytes"));
    }
    let secret = SecretKey::from_slice(emp_priv_raw)
        .map_err(|e| JsError::new(&format!("ecies_unwrap: invalid emp_priv: {e}")))?;
    let peer = PublicKey::from_sec1_bytes(ephemeral_pub)
        .map_err(|e| JsError::new(&format!("ecies_unwrap: invalid ephemeral pub: {e}")))?;
    let shared = diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    let mut shared_x: Vec<u8> = shared.raw_secret_bytes().to_vec();
    let mut kek = match hkdf_sha256(&shared_x, hkdf_salt, hkdf_info, 32) {
        Ok(k) => k,
        Err(e) => { shared_x.zeroize(); return Err(e); }
    };
    shared_x.zeroize();
    let mut pt = match aes256_gcm_decrypt(&kek, iv, ciphertext, &[]) {
        Ok(p) => p,
        Err(e) => { kek.zeroize(); return Err(e); }
    };
    kek.zeroize();
    if pt.len() != 32 {
        pt.zeroize();
        return Err(JsError::new("ecies_unwrap_to_k1key: plaintext must be 32 bytes"));
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&pt);
    pt.zeroize();
    Ok(K1Key { bytes })
}

// ============================================================
// Tests (= cargo test、 native build のみ、 WASM では実行しない)
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_kek_handle_equals_hkdf_concat() {
        // 増分2 bit-equivalence: derive_kek_handle(m1,m2,salt,info)
        //   == hkdf_sha256(m1||m2, salt, info, 32)。 旧 deriveKEK 経路と完全一致を保証。
        let m1 = [0x11u8; 32];
        let m2 = [0x22u8; 32];
        let salt = b"arpass-kek-pr-v1";
        let info = b"kek-pr";
        let kek = derive_kek_handle(&m1, &m2, salt, info).unwrap();
        let mut ikm = Vec::new();
        ikm.extend_from_slice(&m1);
        ikm.extend_from_slice(&m2);
        let expected = hkdf_sha256(&ikm, salt, info, 32).unwrap();
        assert_eq!(&kek.bytes[..], &expected[..], "KEK handle bytes must equal HKDF(concat)");
        // concat 順序の sanity: m2||m1 とは一致しないこと
        let mut rev = Vec::new();
        rev.extend_from_slice(&m2);
        rev.extend_from_slice(&m1);
        let rev_hkdf = hkdf_sha256(&rev, salt, info, 32).unwrap();
        assert_ne!(&kek.bytes[..], &rev_hkdf[..], "concat 順序が material1||material2 であること");
    }

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

    // ========================================================
    // F7 retry: MekKey.derive_signing_key の bit-equivalence
    // ========================================================
    //
    // Phase 2-H4-full F7-B で polymorphic な `deriveSigningKeyFromHkdf` 経路は
    // MekKey 入力時に `MekKey.derive_signing_key(salt, info)` を呼ぶ。 これが
    // 既存 JS path (= deriveBits(HKDF, salt, info, 384) → p256_keypair_from_seed)
    // と bit-identical な scalar + pubkey を生成しないと admin signing identity が
    // 変わって "Caller has no company" になる。
    //
    // 等価性チェーン:
    //   F7-B path     : MekKey(mek_bytes).derive_signing_key(salt, info)
    //                 = SigningKey::new(hkdf_sha256(mek_bytes, salt, info, 48))
    //   JS legacy path: deriveBits(HKDF{salt, info}, baseKey=mek_bytes, 384)
    //                 → seed [48B]
    //                 = hkdf_sha256(mek_bytes, salt, info, 48) (WebCrypto HKDF 仕様)
    //                → p256_keypair_from_seed(seed)
    //
    // SigningKey::new == p256_keypair_from_seed は前 test で担保済。
    // 残るは F7-B path と「明示的に hkdf_sha256 + SigningKey::new」 の bit-equivalence。
    //
    // この test が通過することで、 F7-B の polymorphic 経路が JS path と 同 pubkey
    // を生成することが保証される (= "Caller has no company" 再発防止)。

    #[test]
    fn test_mek_derive_signing_key_equivalent_to_explicit_hkdf_path() {
        // 同じ MEK bytes + salt + info で、 derive_signing_key 経由と explicit な
        // hkdf_sha256 + SigningKey::new 経由が bit-identical な scalar/pubkey を生成。
        let mek_bytes = [0xa5u8; 32];
        let salt = b"signing-key-salt-test";
        let info = b"signing-key-info-test";

        let mek = MekKey::new(&mek_bytes).unwrap();
        let sk_from_mek = mek.derive_signing_key(salt, info).unwrap();

        // explicit path (= JS deriveBits + p256_keypair_from_seed 相当)
        let seed = hkdf_sha256(&mek_bytes, salt, info, 48).unwrap();
        let sk_explicit = SigningKey::new(&seed).unwrap();
        let legacy = p256_keypair_from_seed(&seed).unwrap();

        assert_eq!(
            sk_from_mek.private_key_raw(),
            sk_explicit.private_key_raw(),
            "MekKey.derive_signing_key の private scalar が explicit path と bit-identical"
        );
        assert_eq!(
            sk_from_mek.public_key_raw(),
            sk_explicit.public_key_raw(),
            "MekKey.derive_signing_key の public key が explicit path と bit-identical"
        );
        // legacy noble path (= p256_keypair_from_seed) とも一致
        assert_eq!(sk_from_mek.private_key_raw(), &legacy[0..32]);
        assert_eq!(sk_from_mek.public_key_raw(), &legacy[32..97]);
    }

    #[test]
    fn test_emppriv_handle_ecies_unwrap_bit_equivalent_to_standalone() {
        // Phase 2-F8: EmpPrivKey.ecies_unwrap_to_k1key が standalone 関数と
        // bit-identical な K1 を出すことを確認 (= F8 polymorphic 化の前提)。
        //
        // setup: 送信側 ephemeral keypair で K1 を ECIES wrap、 受信側で unwrap
        let emp_priv = [0x99u8; 32];

        // 受信側 public key (= emp_priv に対応する)
        let secret = SecretKey::from_slice(&emp_priv).unwrap();
        let recipient_pub = secret.public_key();
        let recipient_pub_sec1 = recipient_pub.to_encoded_point(false);
        let recipient_pub_bytes = recipient_pub_sec1.as_bytes();

        // 送信側: ephemeral keypair + ECDH + HKDF + AES-GCM encrypt K1
        let eph_kp = p256_keypair_generate().unwrap();
        let eph_priv = &eph_kp[0..32];
        let eph_pub_sec1 = &eph_kp[32..97];

        let shared = p256_ecdh(eph_priv, recipient_pub_bytes).unwrap();
        let hkdf_salt = b"arpass-ecies-v1";
        let hkdf_info = b"kek";
        let kek = hkdf_sha256(&shared, hkdf_salt, hkdf_info, 32).unwrap();

        let iv = [0x42u8; 12];
        let k1_plain = [0xaau8; 32];
        let ct = aes256_gcm_encrypt(&kek, &iv, &k1_plain, &[]).unwrap();

        // 受信側 standalone 関数
        let k1_standalone = ecies_unwrap_to_k1key_with_emp_priv(
            &emp_priv, eph_pub_sec1, &iv, &ct, hkdf_salt, hkdf_info,
        ).unwrap();

        // 受信側 EmpPrivKey handle method
        let emp_handle = EmpPrivKey::new(&emp_priv).unwrap();
        let k1_handle = emp_handle.ecies_unwrap_to_k1key(
            eph_pub_sec1, &iv, &ct, hkdf_salt, hkdf_info,
        ).unwrap();

        // 両者が同じ K1 (= AES-GCM 出力が同じ) を生成することを確認
        let test_iv = [0x55u8; 12];
        let test_pt = b"K1 equivalence check";
        let ct_standalone = k1_standalone.derive_business_mek_v2_bytes(
            &MekKey::new(&[0x77u8; 32]).unwrap(), b"info", 32,
        ).unwrap();
        let ct_handle = k1_handle.derive_business_mek_v2_bytes(
            &MekKey::new(&[0x77u8; 32]).unwrap(), b"info", 32,
        ).unwrap();
        let _ = (test_iv, test_pt);
        assert_eq!(ct_standalone, ct_handle, "EmpPrivKey handle と standalone は bit-identical な K1 を生成");
        // 平文との突合 (= 元 K1 と一致するはず)。
        // derive_business_mek_v2_bytes の HKDF 方向は IKM=K2 / salt=K1
        // (= production: vault-client.js の deriveBits {salt: oldK1} + k2HkdfKey base
        //    と同一)。 F8 step 1 当初のこの式は ikm/salt が逆で常に fail していた
        // (= F8 ブランチが CI trigger 外だったため未発覚)。
        assert_eq!(
            hkdf_sha256(&[0x77u8; 32], &k1_plain, b"info", 32).unwrap(),
            ct_standalone,
            "復号した K1 が元 K1 と一致 (= IKM=K2 / salt=K1 の HKDF 経由で比較)"
        );
    }

    #[test]
    fn test_business_signing_chain_bit_equivalent() {
        // Business mode の admin signing chain:
        //   K2 (raw 32B) → mekHkdfKey (= HKDF(IKM=K2, salt=K1, info="-v2", 32B))
        //                 → signing seed (= HKDF(IKM=mekHkdfKey, salt=signing_salt, info=signing_info, 48B))
        //                 → P-256 scalar (mod n)
        //
        // F6 path (CryptoKey): deriveBits + importKey + deriveBits + p256_keypair_from_seed
        // F7-A+B path (handle): K1.derive_business_mek_v2(K2) + MekKey.derive_signing_key
        //
        // 両者が bit-identical な pubkey を生成しないと、 admin pkHash が変わって
        // "Caller has no company" 再発。
        let k1_bytes = [0x11u8; 32];
        let k2_bytes = [0x22u8; 32];
        let mek_business_info = b"derive-business-mek-v2";
        let signing_salt = b"arpass-signing-key-v1";
        let signing_info = b"signing-key";

        // F7 path (= K1Key + MekKey の chain)
        let k1 = K1Key::new(&k1_bytes).unwrap();
        let k2 = MekKey::new(&k2_bytes).unwrap();
        let mek_hkdf = k1.derive_business_mek_v2(&k2, mek_business_info).unwrap();
        let sk_f7 = mek_hkdf.derive_signing_key(signing_salt, signing_info).unwrap();

        // F6 path (= 明示的に hkdf_sha256 を 2 段 + p256_keypair_from_seed)
        let mek_raw = hkdf_sha256(&k2_bytes, &k1_bytes, mek_business_info, 32).unwrap();
        let seed = hkdf_sha256(&mek_raw, signing_salt, signing_info, 48).unwrap();
        let legacy = p256_keypair_from_seed(&seed).unwrap();

        assert_eq!(
            sk_f7.private_key_raw(),
            &legacy[0..32],
            "Business chain: F7 path の private scalar が F6 path と bit-identical"
        );
        assert_eq!(
            sk_f7.public_key_raw(),
            &legacy[32..97],
            "Business chain: F7 path の public key が F6 path と bit-identical (= admin pkHash 不変)"
        );
    }


    // ── AES-256-CTR: WebCrypto (Node webcrypto, length=64) 照合済みベクタ ──

    #[test]
    fn test_aes_ctr_webcrypto_vector() {
        let key: Vec<u8> = (0u8..32).collect();
        let counter: Vec<u8> = (0u8..16).map(|i| 0xa0 + i).collect();
        let pt: Vec<u8> = (0u8..32).map(|i| 0xf0 - i).collect();
        let ct = aes256_ctr_apply(&key, &counter, &pt).unwrap();
        assert_eq!(
            hex::encode(&ct),
            "2c70ef109a5396e4e7ac0e60efe80e01010e35cca09a4ff1345d2e5fb3e3014e",
            "AES-CTR length=64: WebCrypto と bit-identical"
        );
        // 対合性: もう一度かけると元に戻る
        let back = aes256_ctr_apply(&key, &counter, &ct).unwrap();
        assert_eq!(back, pt, "AES-CTR involution");
    }

    #[test]
    fn test_aes_ctr_64bit_counter_wrap() {
        // 下位 64 bit ffffffffffffffff → wrap しても上位 64 bit 不変
        // (= WebCrypto length:64 と同一挙動、 Node webcrypto で照合済み)
        let key: Vec<u8> = (0u8..32).collect();
        let mut counter: Vec<u8> = (0u8..16).map(|i| 0xa0 + i).collect();
        for b in counter[8..].iter_mut() { *b = 0xff; }
        let pt: Vec<u8> = (0u8..32).map(|i| 0xf0 - i).collect();
        let ct = aes256_ctr_apply(&key, &counter, &pt).unwrap();
        assert_eq!(
            hex::encode(&ct),
            "0f832bde9cacd7dc0cbc829cbcbc15913ea3a598412f9ca6560ff07b136adf91",
            "AES-CTR 64-bit counter wrap が Ctr64BE と一致"
        );
    }

    #[test]
    fn wrap_mek_for_prf_handle_equals_raw() {
        // JS wrapMekForPrf の handle 経路と raw 経路がバイト一致 (Stage 2 raw-MEK elimination)。
        //   handle: MekKey(prf).hkdf_derive_mek(salt,info).wrap_mek(MekKey(mek), iv)
        //   raw:    aes256_gcm_encrypt(hkdf_sha256(prf,salt,info,32), iv, mek)
        let prf = [0x11u8; 32];
        let mek = [0x42u8; 32];
        let iv = [1u8; 12];
        let salt = b"arpass-mek-wrap-v7";
        let info = b"mek-wrap";
        let prf_h = MekKey::new(&prf).unwrap();
        let wrap_key = prf_h.hkdf_derive_mek(salt, info).unwrap();
        let ct_handle = wrap_key.wrap_mek(&MekKey::new(&mek).unwrap(), &iv).unwrap();
        let raw_key = hkdf_sha256(&prf, salt, info, 32).unwrap();
        let ct_raw = aes256_gcm_encrypt(&raw_key, &iv, &mek, &[]).unwrap();
        assert_eq!(ct_handle, ct_raw, "wrapMekForPrf handle == raw");
    }

    #[test]
    fn unwrap_mek_for_prf_handle_equals_raw() {
        // decryptVaultHwkey の handle-unwrap: wrapKey.unwrap_mek(ct, iv) が
        //   raw 経路 (unwrapMekForPrf) と同じ MEK を復元することを担保。
        let prf = [0x11u8; 32];
        let mek = [0x42u8; 32];
        let wrap_iv = [1u8; 12];
        let salt = b"arpass-mek-wrap-v7";
        let info = b"mek-wrap";
        // k[] entry を raw 経路で wrap
        let wrap_key_raw = hkdf_sha256(&prf, salt, info, 32).unwrap();
        let wrapped_ct = aes256_gcm_encrypt(&wrap_key_raw, &wrap_iv, &mek, &[]).unwrap();
        // handle 経路で unwrap → MEK handle
        let mek_handle = MekKey::new(&prf)
            .unwrap()
            .hkdf_derive_mek(salt, info)
            .unwrap()
            .unwrap_mek(&wrapped_ct, &wrap_iv)
            .unwrap();
        // 復元 handle == 元 MEK の証明: 元 MEK で暗号化した body を handle で復号できる
        let body_iv = [2u8; 12];
        let plaintext = b"hello arpass vault";
        let body_ct = aes256_gcm_encrypt(&mek, &body_iv, plaintext, &[]).unwrap();
        let decrypted = mek_handle.aes_gcm_decrypt(&body_iv, &body_ct, &[]).unwrap();
        assert_eq!(decrypted, plaintext, "unwrap_mek した handle == 元 MEK");
    }
}
