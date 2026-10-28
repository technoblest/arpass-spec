// ====================================================================
// ⚠️ AUTO-GENERATED MIRROR — DO NOT PR HERE
//
// This file is automatically synced from the private arpass repo on every
// release. Direct edits to this file will be overwritten.
//
// Source: technoblest/arpass / rust-crypto/src/totp.rs
// Mirror generator: scripts/generate-arpass-spec-mirror.mjs
// ====================================================================

//! TOTP（2段階認証コード、RFC 6238）— docs/totp-spec.md
//!
//! 秘密キーは `TotpKey` handle の中だけに置く。**生バイトを返すメソッドは作らない。**
//! 保存時は MEK から HKDF で派生した TOTP 専用鍵で AES-256-GCM で包み (wrap)、
//! AAD にエントリ ID を入れて、包んだ秘密キーを別エントリへ付け替えられないようにする。
//!
//! ```text
//! totpWrapKey = HKDF-SHA256(ikm = MEK, salt = "arpass/totp/v1", info = "totp-wrap", L = 32)
//! ct          = AES-256-GCM(totpWrapKey, iv(12), aad = "arpass/totp/v1|" + entryId, secretBytes)
//! ```
//!
//! 中身は native でテストできる純関数 (`&'static str` エラー) にし、wasm-bindgen 側は薄い包みにする
//! （`JsError` は native の `cargo test` では作れないため）。

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use crate::MekKey;

const WRAP_SALT: &[u8] = b"arpass/totp/v1";
const WRAP_INFO: &[u8] = b"totp-wrap";
const AAD_PREFIX: &[u8] = b"arpass/totp/v1|";
/// 16 Base32 文字 = 80 bit（web/lib/totp.js の下限と同じ）
const SECRET_MIN_BYTES: usize = 10;
/// 128 Base32 文字
const SECRET_MAX_BYTES: usize = 80;

/// TOTP 秘密キーの opaque handle。`Drop` で zeroize。
#[wasm_bindgen]
pub struct TotpKey {
    bytes: Vec<u8>,
}

#[wasm_bindgen]
impl TotpKey {
    /// 登録時: Base32（`A-Z2-7`、小文字可、空白・`-`・末尾の `=` は無視）をデコードして handle 化。
    pub fn from_base32(s: &str) -> Result<TotpKey, JsError> {
        base32_decode(s).map(|bytes| TotpKey { bytes }).map_err(JsError::new)
    }

    /// RFC 6238 のコード（`digits` 桁にゼロ埋めした文字列）。`unix_secs` は秒（JS の `Date.now() / 1000`）。
    pub fn code(&self, unix_secs: f64, period: u32, digits: u32, algorithm: &str) -> Result<String, JsError> {
        if !unix_secs.is_finite() || unix_secs < 0.0 {
            return Err(JsError::new("TotpKey.code: invalid time"));
        }
        totp_code(&self.bytes, unix_secs.floor() as u64, period, digits, algorithm).map_err(JsError::new)
    }
}

impl Drop for TotpKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[wasm_bindgen]
impl MekKey {
    /// この MEK から派生した TOTP 専用鍵で `totp` を包む。戻り値は ciphertext + tag。
    pub fn wrap_totp(&self, totp: &TotpKey, entry_id: &str, iv: &[u8]) -> Result<Vec<u8>, JsError> {
        wrap_secret(&self.bytes, &totp.bytes, entry_id, iv).map_err(JsError::new)
    }

    /// `wrap_totp` の逆。エントリ ID（AAD）や鍵が違えば Err。
    pub fn unwrap_totp(&self, ct: &[u8], iv: &[u8], entry_id: &str) -> Result<TotpKey, JsError> {
        unwrap_secret(&self.bytes, ct, iv, entry_id)
            .map(|bytes| TotpKey { bytes })
            .map_err(JsError::new)
    }
}

// ------------------------------------------------------------------
// 純関数（native テスト対象）
// ------------------------------------------------------------------

pub(crate) fn base32_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    let mut out: Vec<u8> = Vec::with_capacity(s.len() * 5 / 8 + 1);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    let mut chars: usize = 0;
    let mut padding = false;
    for c in s.chars() {
        let v = match c {
            ' ' | '-' | '\t' | '\r' | '\n' => continue,
            '=' => {
                padding = true;
                continue;
            }
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32,
            '2'..='7' => c as u32 - '2' as u32 + 26,
            _ => {
                out.zeroize();
                return Err("TotpKey: invalid Base32 character");
            }
        };
        if padding {
            out.zeroize();
            return Err("TotpKey: data after Base32 padding");
        }
        buf = (buf << 5) | v;
        bits += 5;
        chars += 1;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    buf.zeroize();
    if matches!(chars % 8, 1 | 3 | 6) {
        out.zeroize();
        return Err("TotpKey: invalid Base32 length");
    }
    if out.len() < SECRET_MIN_BYTES || out.len() > SECRET_MAX_BYTES {
        out.zeroize();
        return Err("TotpKey: secret must be 10..80 bytes (16..128 Base32 chars)");
    }
    Ok(out)
}

pub(crate) fn totp_code(key: &[u8], unix_secs: u64, period: u32, digits: u32, algorithm: &str) -> Result<String, &'static str> {
    if !(10..=300).contains(&period) {
        return Err("TOTP: period must be 10..300");
    }
    if !(6..=8).contains(&digits) {
        return Err("TOTP: digits must be 6..8");
    }
    let counter = (unix_secs / period as u64).to_be_bytes();
    let mut mac: Vec<u8> = match algorithm.to_ascii_uppercase().as_str() {
        "SHA1" => {
            let mut m = <Hmac<Sha1> as Mac>::new_from_slice(key).map_err(|_| "TOTP: invalid key")?;
            m.update(&counter);
            m.finalize().into_bytes().to_vec()
        }
        "SHA256" => {
            let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| "TOTP: invalid key")?;
            m.update(&counter);
            m.finalize().into_bytes().to_vec()
        }
        "SHA512" => {
            let mut m = <Hmac<Sha512> as Mac>::new_from_slice(key).map_err(|_| "TOTP: invalid key")?;
            m.update(&counter);
            m.finalize().into_bytes().to_vec()
        }
        _ => return Err("TOTP: algorithm must be SHA1, SHA256 or SHA512"),
    };
    let off = (mac[mac.len() - 1] & 0x0f) as usize;
    let bin = ((mac[off] as u32 & 0x7f) << 24)
        | ((mac[off + 1] as u32) << 16)
        | ((mac[off + 2] as u32) << 8)
        | (mac[off + 3] as u32);
    mac.zeroize();
    let code = bin % 10u32.pow(digits);
    Ok(format!("{:0width$}", code, width = digits as usize))
}

fn wrap_key(mek: &[u8; 32]) -> Result<[u8; 32], &'static str> {
    let hk = Hkdf::<Sha256>::new(Some(WRAP_SALT), mek);
    let mut k = [0u8; 32];
    hk.expand(WRAP_INFO, &mut k).map_err(|_| "TOTP: wrap key derivation failed")?;
    Ok(k)
}

fn aad_for(entry_id: &str) -> Result<Vec<u8>, &'static str> {
    if entry_id.is_empty() {
        return Err("TOTP: entry id required");
    }
    let mut aad = AAD_PREFIX.to_vec();
    aad.extend_from_slice(entry_id.as_bytes());
    Ok(aad)
}

fn cipher_for(mek: &[u8; 32]) -> Result<Aes256Gcm, &'static str> {
    let mut k = wrap_key(mek)?;
    let cipher = <Aes256Gcm as KeyInit>::new_from_slice(&k).map_err(|_| "TOTP: invalid wrap key");
    k.zeroize();
    cipher
}

pub(crate) fn wrap_secret(mek: &[u8; 32], secret: &[u8], entry_id: &str, iv: &[u8]) -> Result<Vec<u8>, &'static str> {
    if iv.len() != 12 {
        return Err("TOTP wrap: iv must be 12 bytes");
    }
    if secret.len() < SECRET_MIN_BYTES || secret.len() > SECRET_MAX_BYTES {
        return Err("TOTP wrap: secret length out of range");
    }
    let aad = aad_for(entry_id)?;
    cipher_for(mek)?
        .encrypt(Nonce::from_slice(iv), Payload { msg: secret, aad: &aad })
        .map_err(|_| "TOTP wrap: encrypt failed")
}

pub(crate) fn unwrap_secret(mek: &[u8; 32], ct: &[u8], iv: &[u8], entry_id: &str) -> Result<Vec<u8>, &'static str> {
    if iv.len() != 12 {
        return Err("TOTP unwrap: iv must be 12 bytes");
    }
    let aad = aad_for(entry_id)?;
    let mut pt = cipher_for(mek)?
        .decrypt(Nonce::from_slice(iv), Payload { msg: ct, aad: &aad })
        .map_err(|_| "TOTP unwrap: decrypt failed (wrong key or entry id)")?;
    if pt.len() < SECRET_MIN_BYTES || pt.len() > SECRET_MAX_BYTES {
        pt.zeroize();
        return Err("TOTP unwrap: secret length out of range");
    }
    Ok(pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED_SHA1: &[u8] = b"12345678901234567890";
    const SEED_SHA256: &[u8] = b"12345678901234567890123456789012";
    const SEED_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    #[test]
    fn rfc6238_appendix_b_vectors() {
        // RFC 6238 付録 B（8 桁、period 30）。docs/totp-spec.md §8 と同じ表
        let cases: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (t, s1, s256, s512) in cases {
            assert_eq!(totp_code(SEED_SHA1, t, 30, 8, "SHA1").unwrap(), s1, "SHA1 t={t}");
            assert_eq!(totp_code(SEED_SHA256, t, 30, 8, "SHA256").unwrap(), s256, "SHA256 t={t}");
            assert_eq!(totp_code(SEED_SHA512, t, 30, 8, "sha512").unwrap(), s512, "SHA512 t={t}");
        }
    }

    #[test]
    fn six_digits_and_zero_padding() {
        // 8 桁の下 6 桁と一致し、先頭ゼロを保つ
        assert_eq!(totp_code(SEED_SHA1, 59, 30, 6, "SHA1").unwrap(), "287082");
        assert_eq!(totp_code(SEED_SHA1, 1111111109, 30, 6, "SHA1").unwrap(), "081804");
        assert_eq!(totp_code(SEED_SHA1, 1111111109, 30, 7, "SHA1").unwrap(), "7081804");
    }

    #[test]
    fn rejects_bad_parameters() {
        assert!(totp_code(SEED_SHA1, 59, 5, 6, "SHA1").is_err());
        assert!(totp_code(SEED_SHA1, 59, 30, 9, "SHA1").is_err());
        assert!(totp_code(SEED_SHA1, 59, 30, 6, "MD5").is_err());
    }

    #[test]
    fn base32_decoding() {
        // "Hello!" + DE AD BE EF
        let want = [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad, 0xbe, 0xef];
        assert_eq!(base32_decode("JBSWY3DPEHPK3PXP").unwrap(), want);
        assert_eq!(base32_decode("jbsw y3dp-ehpk 3pxp").unwrap(), want);
        // RFC 4648 のテスト値に 10 byte 以上のものが無いので、SHA1 シードの Base32 で往復を確認
        assert_eq!(base32_decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(), SEED_SHA1);
        assert_eq!(base32_decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ==").unwrap(), SEED_SHA1);
        assert!(base32_decode("JBSWY3DPEHPK3PX1").is_err(), "invalid char");
        assert!(base32_decode("JBSWY3DPEHPK3PXPJ").is_err(), "invalid length (17 chars)");
        assert!(base32_decode("JBSWY3DP").is_err(), "too short (5 bytes)");
        assert!(base32_decode("JBSW=Y3DP").is_err(), "data after padding");
    }

    #[test]
    fn wrap_unwrap_roundtrip_and_binding() {
        let mek = [0x42u8; 32];
        let iv = [0x24u8; 12];
        let ct = wrap_secret(&mek, SEED_SHA1, "e_abc", &iv).unwrap();
        assert_eq!(unwrap_secret(&mek, &ct, &iv, "e_abc").unwrap(), SEED_SHA1);
        assert!(unwrap_secret(&mek, &ct, &iv, "e_other").is_err(), "entry id is bound via AAD");
        assert!(unwrap_secret(&[0x43u8; 32], &ct, &iv, "e_abc").is_err(), "wrong MEK");
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(unwrap_secret(&mek, &bad, &iv, "e_abc").is_err(), "tampered ciphertext");
        assert!(wrap_secret(&mek, SEED_SHA1, "", &iv).is_err(), "empty entry id");
        assert!(wrap_secret(&mek, b"short", "e_abc", &iv).is_err(), "secret too short");
    }

    #[test]
    fn wrap_known_answer() {
        // 形式を固定するための既知の値。WebCrypto（HKDF-SHA256 → AES-256-GCM）で独立に計算した結果と一致すること。
        // 緊急復旧ツールの pure JS 実装はこの値で照合する（docs/totp-spec.md §4）。
        let mek = [0x42u8; 32];
        let iv = [0x24u8; 12];
        let ct = wrap_secret(&mek, SEED_SHA1, "e_abc", &iv).unwrap();
        assert_eq!(hex::encode(&ct), WRAP_KAT_HEX);
    }

    // scripts で WebCrypto により計算（mek=0x42*32, iv=0x24*12, entry="e_abc", secret=SEED_SHA1）
    const WRAP_KAT_HEX: &str = "4535f82fa68394fd295ea832c094728cc64e202bdcf7fc200acd4b1f3499ec7ea248b039";
}
