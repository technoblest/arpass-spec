export class BekKey {
    static __wrap(ptr) {
        const obj = Object.create(BekKey.prototype);
        obj.__wbg_ptr = ptr;
        BekKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        BekKeyFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_bekkey_free(ptr, 0);
    }
    /**
     * @param {Uint8Array} iv
     * @param {Uint8Array} ciphertext
     * @param {Uint8Array} aad
     * @returns {Uint8Array}
     */
    aes_gcm_decrypt(iv, ciphertext, aad) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(iv, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_export3);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passArray8ToWasm0(aad, wasm.__wbindgen_export3);
            const len2 = WASM_VECTOR_LEN;
            wasm.bekkey_aes_gcm_decrypt(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v4 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export2(r0, r1 * 1, 1);
            return v4;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @param {Uint8Array} iv
     * @param {Uint8Array} plaintext
     * @param {Uint8Array} aad
     * @returns {Uint8Array}
     */
    aes_gcm_encrypt(iv, plaintext, aad) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(iv, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(plaintext, wasm.__wbindgen_export3);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passArray8ToWasm0(aad, wasm.__wbindgen_export3);
            const len2 = WASM_VECTOR_LEN;
            wasm.bekkey_aes_gcm_encrypt(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v4 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export2(r0, r1 * 1, 1);
            return v4;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * 生成 (= 乱数 32 byte from getrandom)。 通常 caller は
     * `BekKey::generate()` を呼ぶか、 JS 側の crypto.getRandomValues
     * から渡す。 ここでは getrandom 経由 (= window.crypto に橋渡し済)。
     * @returns {BekKey}
     */
    static generate() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.bekkey_generate(retptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return BekKey.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @param {Uint8Array} raw
     */
    constructor(raw) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(raw, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            wasm.bekkey_new(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            this.__wbg_ptr = r0;
            BekKeyFinalization.register(this, this.__wbg_ptr, this);
            return this;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}
if (Symbol.dispose) BekKey.prototype[Symbol.dispose] = BekKey.prototype.free;

export class EmpPrivKey {
    static __wrap(ptr) {
        const obj = Object.create(EmpPrivKey.prototype);
        obj.__wbg_ptr = ptr;
        EmpPrivKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        EmpPrivKeyFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_empprivkey_free(ptr, 0);
    }
    /**
     * ECIES unwrap: ephemeral_pub + iv + ciphertext を受けて、 K1Key opaque handle を返す。
     * 内部は standalone `ecies_unwrap_to_k1key_with_emp_priv` と同じ実装 = bit-equiv 担保。
     * @param {Uint8Array} ephemeral_pub
     * @param {Uint8Array} iv
     * @param {Uint8Array} ciphertext
     * @param {Uint8Array} hkdf_salt
     * @param {Uint8Array} hkdf_info
     * @returns {K1Key}
     */
    ecies_unwrap_to_k1key(ephemeral_pub, iv, ciphertext, hkdf_salt, hkdf_info) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(ephemeral_pub, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(iv, wasm.__wbindgen_export3);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_export3);
            const len2 = WASM_VECTOR_LEN;
            const ptr3 = passArray8ToWasm0(hkdf_salt, wasm.__wbindgen_export3);
            const len3 = WASM_VECTOR_LEN;
            const ptr4 = passArray8ToWasm0(hkdf_info, wasm.__wbindgen_export3);
            const len4 = WASM_VECTOR_LEN;
            wasm.empprivkey_ecies_unwrap_to_k1key(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return K1Key.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * PKCS#8 DER 形式の private key bytes から EmpPrivKey opaque handle を構築。
     * JS 側で `subtle.decrypt(w_emp)` 直後の pkcs8 raw bytes をそのまま渡せる。
     * 内部で SecretKey::from_pkcs8_der で parse、 32-byte scalar を抽出して保持。
     * @param {Uint8Array} pkcs8_der
     * @returns {EmpPrivKey}
     */
    static from_pkcs8(pkcs8_der) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(pkcs8_der, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            wasm.empprivkey_from_pkcs8(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return EmpPrivKey.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * 32-byte raw P-256 private scalar から EmpPrivKey opaque handle を構築。
     * JS heap 側で短時間 raw を持っているが、 import 後は handle 内に閉じ込められる。
     * @param {Uint8Array} raw
     */
    constructor(raw) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(raw, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            wasm.empprivkey_new(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            this.__wbg_ptr = r0;
            EmpPrivKeyFinalization.register(this, this.__wbg_ptr, this);
            return this;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}
if (Symbol.dispose) EmpPrivKey.prototype[Symbol.dispose] = EmpPrivKey.prototype.free;

export class K1Key {
    static __wrap(ptr) {
        const obj = Object.create(K1Key.prototype);
        obj.__wbg_ptr = ptr;
        K1KeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        K1KeyFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_k1key_free(ptr, 0);
    }
    /**
     * @param {Uint8Array} iv
     * @param {Uint8Array} ciphertext
     * @param {Uint8Array} aad
     * @returns {Uint8Array}
     */
    aes_gcm_decrypt(iv, ciphertext, aad) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(iv, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_export3);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passArray8ToWasm0(aad, wasm.__wbindgen_export3);
            const len2 = WASM_VECTOR_LEN;
            wasm.k1key_aes_gcm_decrypt(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v4 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export2(r0, r1 * 1, 1);
            return v4;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * K1 直接の AES-GCM encrypt (= legacy path 用)。
     * @param {Uint8Array} iv
     * @param {Uint8Array} plaintext
     * @param {Uint8Array} aad
     * @returns {Uint8Array}
     */
    aes_gcm_encrypt(iv, plaintext, aad) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(iv, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(plaintext, wasm.__wbindgen_export3);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passArray8ToWasm0(aad, wasm.__wbindgen_export3);
            const len2 = WASM_VECTOR_LEN;
            wasm.k1key_aes_gcm_encrypt(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v4 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export2(r0, r1 * 1, 1);
            return v4;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Phase 2-H4-full F1: Business V2 MEK 派生。
     *   IKM = K2.bytes (= MekKey 流用、 32 byte AES-GCM kdf base 互換)
     *   salt = self.bytes (= K1)
     *   info = caller 指定 (= "mek-business-v2" 相当)
     * K1 raw bytes は WASM 内のみ、 K2 raw bytes も MekKey handle 内のみ。
     * @param {MekKey} k2
     * @param {Uint8Array} info
     * @returns {MekKey}
     */
    derive_business_mek_v2(k2, info) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(k2, MekKey);
            const ptr0 = passArray8ToWasm0(info, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            wasm.k1key_derive_business_mek_v2(retptr, this.__wbg_ptr, k2.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return MekKey.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Phase 2-H4-full F1: Business V2 mekHkdfKey 同等の派生。
     * 同じ IKM/salt/info で別 length を出すなら caller が dkLen 指定可能。
     * HKDF base CryptoKey の代替として、 raw bytes を期待する caller がある場合に使う。
     * @param {MekKey} k2
     * @param {Uint8Array} info
     * @param {number} len
     * @returns {Uint8Array}
     */
    derive_business_mek_v2_bytes(k2, info, len) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(k2, MekKey);
            const ptr0 = passArray8ToWasm0(info, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            wasm.k1key_derive_business_mek_v2_bytes(retptr, this.__wbg_ptr, k2.__wbg_ptr, ptr0, len0, len);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v2 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export2(r0, r1 * 1, 1);
            return v2;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * K1 から HKDF-SHA256 で MekKey を派生 (= business mode real_MEK 生成)。
     * 戻り値の MekKey は型としても MekKey、 mix-up しない設計。
     * @param {Uint8Array} salt
     * @param {Uint8Array} info
     * @returns {MekKey}
     */
    hkdf_derive_mek(salt, info) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(salt, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(info, wasm.__wbindgen_export3);
            const len1 = WASM_VECTOR_LEN;
            wasm.k1key_hkdf_derive_mek(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return MekKey.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @param {Uint8Array} raw
     */
    constructor(raw) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(raw, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            wasm.k1key_new(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            this.__wbg_ptr = r0;
            K1KeyFinalization.register(this, this.__wbg_ptr, this);
            return this;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}
if (Symbol.dispose) K1Key.prototype[Symbol.dispose] = K1Key.prototype.free;

/**
 * MEK opaque handle (= Master-derived data encryption key、 Phase 7.3-A.5)。
 *
 * 内部に 32 byte の AES-256 key を保持。 raw bytes export 関数なし。
 * `Drop` 時に自動 zeroize。
 */
export class MekKey {
    static __wrap(ptr) {
        const obj = Object.create(MekKey.prototype);
        obj.__wbg_ptr = ptr;
        MekKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        MekKeyFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_mekkey_free(ptr, 0);
    }
    /**
     * AES-256-GCM decrypt with this handle as key。
     * @param {Uint8Array} iv
     * @param {Uint8Array} ciphertext
     * @param {Uint8Array} aad
     * @returns {Uint8Array}
     */
    aes_gcm_decrypt(iv, ciphertext, aad) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(iv, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_export3);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passArray8ToWasm0(aad, wasm.__wbindgen_export3);
            const len2 = WASM_VECTOR_LEN;
            wasm.mekkey_aes_gcm_decrypt(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v4 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export2(r0, r1 * 1, 1);
            return v4;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * AES-256-GCM encrypt with this handle as key。
     * @param {Uint8Array} iv
     * @param {Uint8Array} plaintext
     * @param {Uint8Array} aad
     * @returns {Uint8Array}
     */
    aes_gcm_encrypt(iv, plaintext, aad) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(iv, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(plaintext, wasm.__wbindgen_export3);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passArray8ToWasm0(aad, wasm.__wbindgen_export3);
            const len2 = WASM_VECTOR_LEN;
            wasm.mekkey_aes_gcm_encrypt(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v4 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export2(r0, r1 * 1, 1);
            return v4;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Phase 2-H4-full F3: K2 から HKDF で 48-byte seed 派生 → SigningKey handle 返却。
     * JS の `deriveSigningKeyFromHkdf` を 1 関数に統合、 seed が JS heap に出現しない。
     * Business mode の signing identity 派生 (= K2-based) 用。
     * @param {Uint8Array} salt
     * @param {Uint8Array} info
     * @returns {SigningKey}
     */
    derive_signing_key(salt, info) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(salt, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(info, wasm.__wbindgen_export3);
            const len1 = WASM_VECTOR_LEN;
            wasm.mekkey_derive_signing_key(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return SigningKey.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Phase 2-H4-full F3: HKDF-SHA256 で任意 length の raw bytes を派生。
     * K2 (= MekKey 流用) を IKM として sub-key 派生 (= signing key seed 48 byte,
     * recoveryProtect key 32 byte 等) に使う。
     * 戻り値の Vec<u8> は短命、 caller が即消費 + zeroize すること。
     * @param {Uint8Array} salt
     * @param {Uint8Array} info
     * @param {number} dk_len
     * @returns {Uint8Array}
     */
    hkdf_derive_bytes(salt, info, dk_len) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(salt, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(info, wasm.__wbindgen_export3);
            const len1 = WASM_VECTOR_LEN;
            wasm.mekkey_hkdf_derive_bytes(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1, dk_len);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v3 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export2(r0, r1 * 1, 1);
            return v3;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * HKDF-SHA256 で派生した新 MekKey handle を返す (= raw bytes JS 露出なし)。
     * @param {Uint8Array} salt
     * @param {Uint8Array} info
     * @returns {MekKey}
     */
    hkdf_derive_mek(salt, info) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(salt, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(info, wasm.__wbindgen_export3);
            const len1 = WASM_VECTOR_LEN;
            wasm.mekkey_hkdf_derive_mek(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return MekKey.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * raw 32 byte を受け取って handle 化。 caller (= JS) は呼出直後に
     * 入力 Uint8Array を zeroize すること (= 一瞬だけ JS heap 経由するため)。
     * @param {Uint8Array} raw
     */
    constructor(raw) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(raw, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            wasm.mekkey_new(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            this.__wbg_ptr = r0;
            MekKeyFinalization.register(this, this.__wbg_ptr, this);
            return this;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * MEK で wrap された bytes を unwrap して BekKey handle 返却。
     * @param {Uint8Array} wrapped
     * @param {Uint8Array} iv
     * @returns {BekKey}
     */
    unwrap_bek(wrapped, iv) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(wrapped, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(iv, wasm.__wbindgen_export3);
            const len1 = WASM_VECTOR_LEN;
            wasm.mekkey_unwrap_bek(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return BekKey.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * MEK で wrap された K1 bytes を unwrap して K1Key handle 返却。
     * @param {Uint8Array} wrapped
     * @param {Uint8Array} iv
     * @returns {K1Key}
     */
    unwrap_k1(wrapped, iv) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(wrapped, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(iv, wasm.__wbindgen_export3);
            const len1 = WASM_VECTOR_LEN;
            wasm.mekkey_unwrap_k1(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return K1Key.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * この MEK で wrapped bytes を unwrap して新 MekKey handle を返す。
     * @param {Uint8Array} wrapped
     * @param {Uint8Array} iv
     * @returns {MekKey}
     */
    unwrap_mek(wrapped, iv) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(wrapped, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(iv, wasm.__wbindgen_export3);
            const len1 = WASM_VECTOR_LEN;
            wasm.mekkey_unwrap_mek(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return MekKey.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * MEK で BekKey を wrap (= file BEK を envelope.records[].wrap で保管)。
     * @param {BekKey} bek
     * @param {Uint8Array} iv
     * @returns {Uint8Array}
     */
    wrap_bek(bek, iv) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(bek, BekKey);
            const ptr0 = passArray8ToWasm0(iv, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            wasm.mekkey_wrap_bek(retptr, this.__wbg_ptr, bek.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v2 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export2(r0, r1 * 1, 1);
            return v2;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * MEK で K1Key を wrap (= per-employee enc_K1 保管用、 業務 mode)。
     * @param {K1Key} k1
     * @param {Uint8Array} iv
     * @returns {Uint8Array}
     */
    wrap_k1(k1, iv) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(k1, K1Key);
            const ptr0 = passArray8ToWasm0(iv, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            wasm.mekkey_wrap_k1(retptr, this.__wbg_ptr, k1.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v2 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export2(r0, r1 * 1, 1);
            return v2;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * この MEK で別 MEK を wrap する (= AES-GCM encrypt、 結果は ciphertext+tag)。
     * @param {MekKey} other
     * @param {Uint8Array} iv
     * @returns {Uint8Array}
     */
    wrap_mek(other, iv) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(other, MekKey);
            const ptr0 = passArray8ToWasm0(iv, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            wasm.mekkey_wrap_mek(retptr, this.__wbg_ptr, other.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v2 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export2(r0, r1 * 1, 1);
            return v2;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}
if (Symbol.dispose) MekKey.prototype[Symbol.dispose] = MekKey.prototype.free;

export class OuterKey {
    static __wrap(ptr) {
        const obj = Object.create(OuterKey.prototype);
        obj.__wbg_ptr = ptr;
        OuterKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        OuterKeyFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_outerkey_free(ptr, 0);
    }
    /**
     * @param {Uint8Array} iv
     * @param {Uint8Array} ciphertext
     * @param {Uint8Array} aad
     * @returns {Uint8Array}
     */
    aes_gcm_decrypt(iv, ciphertext, aad) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(iv, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_export3);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passArray8ToWasm0(aad, wasm.__wbindgen_export3);
            const len2 = WASM_VECTOR_LEN;
            wasm.outerkey_aes_gcm_decrypt(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v4 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export2(r0, r1 * 1, 1);
            return v4;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @param {Uint8Array} iv
     * @param {Uint8Array} plaintext
     * @param {Uint8Array} aad
     * @returns {Uint8Array}
     */
    aes_gcm_encrypt(iv, plaintext, aad) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(iv, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(plaintext, wasm.__wbindgen_export3);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passArray8ToWasm0(aad, wasm.__wbindgen_export3);
            const len2 = WASM_VECTOR_LEN;
            wasm.outerkey_aes_gcm_encrypt(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v4 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export2(r0, r1 * 1, 1);
            return v4;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @param {Uint8Array} raw
     */
    constructor(raw) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(raw, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            wasm.outerkey_new(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            this.__wbg_ptr = r0;
            OuterKeyFinalization.register(this, this.__wbg_ptr, this);
            return this;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}
if (Symbol.dispose) OuterKey.prototype[Symbol.dispose] = OuterKey.prototype.free;

export class RMatKey {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        RMatKeyFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_rmatkey_free(ptr, 0);
    }
    /**
     * rMat から 任意 byte 列を HKDF 派生 (= app tag name/value 等の非 key 材料用)。
     * 戻り値は Vec<u8> (= 公開情報、 base64url 化等で JS 側に出る) なので
     * key 用途には使わない (= type 分離のため derive_outer_key / derive_mek 等を
     * 使うこと)。
     * @param {Uint8Array} salt
     * @param {Uint8Array} info
     * @param {number} length
     * @returns {Uint8Array}
     */
    derive_bytes(salt, info, length) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(salt, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(info, wasm.__wbindgen_export3);
            const len1 = WASM_VECTOR_LEN;
            wasm.rmatkey_derive_bytes(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1, length);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v3 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export2(r0, r1 * 1, 1);
            return v3;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * rMat から K1Key を HKDF 派生 (= business mode legacy 経路)。
     * @param {Uint8Array} salt
     * @param {Uint8Array} info
     * @returns {K1Key}
     */
    derive_k1(salt, info) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(salt, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(info, wasm.__wbindgen_export3);
            const len1 = WASM_VECTOR_LEN;
            wasm.rmatkey_derive_k1(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return K1Key.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * rMat から MekKey を HKDF 派生 (= 内部 HKDF)。
     * @param {Uint8Array} salt
     * @param {Uint8Array} info
     * @returns {MekKey}
     */
    derive_mek(salt, info) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(salt, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(info, wasm.__wbindgen_export3);
            const len1 = WASM_VECTOR_LEN;
            wasm.rmatkey_derive_mek(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return MekKey.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * rMat から OuterKey を HKDF 派生 (= 内部 HKDF、 raw bytes JS 露出ゼロ)。
     * @param {Uint8Array} salt
     * @param {Uint8Array} info
     * @returns {OuterKey}
     */
    derive_outer_key(salt, info) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(salt, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(info, wasm.__wbindgen_export3);
            const len1 = WASM_VECTOR_LEN;
            wasm.rmatkey_derive_outer_key(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return OuterKey.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * 32 byte raw rMat から handle を生成 (= boundary、 caller 即 zeroize)。
     * @param {Uint8Array} raw
     */
    constructor(raw) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(raw, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            wasm.rmatkey_new(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            this.__wbg_ptr = r0;
            RMatKeyFinalization.register(this, this.__wbg_ptr, this);
            return this;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}
if (Symbol.dispose) RMatKey.prototype[Symbol.dispose] = RMatKey.prototype.free;

export class SigningKey {
    static __wrap(ptr) {
        const obj = Object.create(SigningKey.prototype);
        obj.__wbg_ptr = ptr;
        SigningKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        SigningKeyFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_signingkey_free(ptr, 0);
    }
    /**
     * Sign a message with ECDSA-SHA256, returning the raw IEEE P1363
     * signature (= 64 bytes, r || s big-endian). Same wire format that
     * `crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, ...)` emits.
     * @param {Uint8Array} message
     * @returns {Uint8Array}
     */
    ecdsa_sign(message) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(message, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            wasm.signingkey_ecdsa_sign(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v2 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export2(r0, r1 * 1, 1);
            return v2;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Phase 2-H4-full F2: ECIES decrypt の結果を K1Key opaque handle として返す。
     * JS 側で eciesDecrypt → K1 raw → new K1Key (= 並列 populate) の 3 段階を
     * 1 つの Rust 関数に統合。 K1 raw bytes は WASM 内のみで生存、 JS heap 露出ゼロ。
     *
     * # 引数
     *   ephemeral_pub: 65 byte uncompressed SEC1 (= sender 側 ephemeral 公開鍵)
     *   iv: AES-GCM IV
     *   ciphertext: AES-GCM 暗号文 (= K1 32B + tag 16B)
     *   hkdf_salt: ECIES KEK 派生用 salt (= JS 側 ECIES_HKDF_SALT = "arpass-ecies-v1")
     *   hkdf_info: ECIES KEK 派生用 info (= JS 側 ECIES_HKDF_INFO = "kek")
     *
     * # 中間値の取り扱い
     *   shared_x / kek / pt は短命の Vec<u8>、 explicit zeroize で確定的破棄。
     * @param {Uint8Array} ephemeral_pub
     * @param {Uint8Array} iv
     * @param {Uint8Array} ciphertext
     * @param {Uint8Array} hkdf_salt
     * @param {Uint8Array} hkdf_info
     * @returns {K1Key}
     */
    ecies_unwrap_to_k1key(ephemeral_pub, iv, ciphertext, hkdf_salt, hkdf_info) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(ephemeral_pub, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(iv, wasm.__wbindgen_export3);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_export3);
            const len2 = WASM_VECTOR_LEN;
            const ptr3 = passArray8ToWasm0(hkdf_salt, wasm.__wbindgen_export3);
            const len3 = WASM_VECTOR_LEN;
            const ptr4 = passArray8ToWasm0(hkdf_info, wasm.__wbindgen_export3);
            const len4 = WASM_VECTOR_LEN;
            wasm.signingkey_ecies_unwrap_to_k1key(retptr, this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return K1Key.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Create from a 48-byte (or longer) seed. Internally derives the P-256
     * scalar mod n the same way `p256_keypair_from_seed` does, so a given
     * seed produces the same keypair as the legacy path.
     * @param {Uint8Array} seed
     */
    constructor(seed) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(seed, wasm.__wbindgen_export3);
            const len0 = WASM_VECTOR_LEN;
            wasm.signingkey_new(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            this.__wbg_ptr = r0;
            SigningKeyFinalization.register(this, this.__wbg_ptr, this);
            return this;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Return the 32-byte private scalar. **For migration code only** —
     * callers should prefer `ecdsa_sign` and `public_key_raw`. Used by
     * the JS `currentSigningPrivateKeyRaw` helper for ECIES decrypt
     * (= per-employee enc_K1 path) until that too is moved into Rust.
     * @returns {Uint8Array}
     */
    private_key_raw() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.signingkey_private_key_raw(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export2(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Return the 65-byte uncompressed SEC1 public key (= 0x04 || X || Y).
     * JS side uses this for pkHash + sending to peers.
     * @returns {Uint8Array}
     */
    public_key_raw() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.signingkey_public_key_raw(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export2(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}
if (Symbol.dispose) SigningKey.prototype[Symbol.dispose] = SigningKey.prototype.free;

export function _init() {
    wasm._init();
}

/**
 * AES-256-CTR keystream apply (= encrypt と decrypt は同一操作)。
 *
 * # Parameters
 *   key:     32 bytes
 *   counter: 16-byte initial counter block (= 下位 64 bit のみ increment)
 *   data:    arbitrary length (= v7 user.id wrap では 32B)
 *
 * # Backward-compat (CRITICAL)
 * WebCrypto `subtle.encrypt({name:"AES-CTR", counter, length: 64}, ...)` と
 * bit-identical であること。 length=64 は counter block の下位 64 bit のみを
 * increment する指定で、 RustCrypto の `Ctr64BE` がこれに一致する。
 * 既存の v7 user.id (= Arweave 上ではなく Passkey 内に永続) を再発行なしで
 * 復号し続けるため、 この互換性は絶対に壊さないこと。
 * 検証ベクタは Node webcrypto (= WebCrypto 実装) で生成・照合済み。
 *
 * # 用途
 * vault-crypto.js `_wrapOuterForUserId`:
 *   KEK     = Argon2id(Master, salt=appNameTag.value, USERID_KDF_PARAMS)
 *   counter = SHA-256("arpass-userid-v7-ctr" || nameB || valB)[0..16]
 *   wrapped = AES-256-CTR(KEK, counter, outerKey 32B)
 * @param {Uint8Array} key
 * @param {Uint8Array} counter
 * @param {Uint8Array} data
 * @returns {Uint8Array}
 */
export function aes256_ctr_apply(key, counter, data) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(key, wasm.__wbindgen_export3);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(counter, wasm.__wbindgen_export3);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(data, wasm.__wbindgen_export3);
        const len2 = WASM_VECTOR_LEN;
        wasm.aes256_ctr_apply(retptr, ptr0, len0, ptr1, len1, ptr2, len2);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v4 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export2(r0, r1 * 1, 1);
        return v4;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * AES-256-GCM decrypt.
 *
 * # Parameters
 *   ciphertext: must include 16-byte GCM tag at the end.
 *   aad:        must match encrypt-time aad exactly.
 * @param {Uint8Array} key
 * @param {Uint8Array} iv
 * @param {Uint8Array} ciphertext
 * @param {Uint8Array} aad
 * @returns {Uint8Array}
 */
export function aes256_gcm_decrypt(key, iv, ciphertext, aad) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(key, wasm.__wbindgen_export3);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(iv, wasm.__wbindgen_export3);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_export3);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(aad, wasm.__wbindgen_export3);
        const len3 = WASM_VECTOR_LEN;
        wasm.aes256_gcm_decrypt(retptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v5 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export2(r0, r1 * 1, 1);
        return v5;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * AES-256-GCM encrypt.
 *
 * # Parameters
 *   key:        32 bytes
 *   iv (nonce): 12 bytes
 *   plaintext:  arbitrary length
 *   aad:        additional authenticated data (= envelope tag bind)
 *
 * # Output
 *   ciphertext concatenated with 16-byte GCM authentication tag.
 *   Total length = plaintext.len() + 16.
 *
 * # Backward-compat
 * Matches WebCrypto `crypto.subtle.encrypt({name:'AES-GCM', iv, additionalData: aad}, key, plaintext)`.
 * @param {Uint8Array} key
 * @param {Uint8Array} iv
 * @param {Uint8Array} plaintext
 * @param {Uint8Array} aad
 * @returns {Uint8Array}
 */
export function aes256_gcm_encrypt(key, iv, plaintext, aad) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(key, wasm.__wbindgen_export3);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(iv, wasm.__wbindgen_export3);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(plaintext, wasm.__wbindgen_export3);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(aad, wasm.__wbindgen_export3);
        const len3 = WASM_VECTOR_LEN;
        wasm.aes256_gcm_encrypt(retptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v5 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export2(r0, r1 * 1, 1);
        return v5;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Argon2id key derivation.
 *
 * Parameters MUST match Phase 7.4 envelope.kdfParams:
 *   alg: "argon2id"
 *   v:   2          (= Argon2 version 0x13)
 *   m:   65536      (= 64 MiB memory cost, in KiB)
 *   t:   3          (= 3 iterations)
 *   p:   4          (= 4 lanes)
 *   tagLen: 32      (= 32-byte output)
 *
 * Caller (= vault-crypto.js derivePMat) is responsible for passing the
 * correct params. This function does not enforce a specific configuration
 * to allow future migrations (= e.g., Phase 7.4Y bump to t=4).
 *
 * # Backward-compat
 * Existing vaults use exactly the params above. Changing any of m/t/p
 * would break decryption of all existing data.
 * @param {Uint8Array} password
 * @param {Uint8Array} salt
 * @param {number} m_kib
 * @param {number} t
 * @param {number} p
 * @param {number} out_len
 * @returns {Uint8Array}
 */
export function argon2id_derive(password, salt, m_kib, t, p, out_len) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(password, wasm.__wbindgen_export3);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(salt, wasm.__wbindgen_export3);
        const len1 = WASM_VECTOR_LEN;
        wasm.argon2id_derive(retptr, ptr0, len0, ptr1, len1, m_kib, t, p, out_len);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v3 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export2(r0, r1 * 1, 1);
        return v3;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * 増分2 (KEK の WASM 内派生): 2 つの factor material を concat → HKDF-SHA256 →
 * 32-byte KEK を `MekKey` opaque handle として返す。 KEK の raw bytes は JS heap に
 * 一切出ない (= JS `deriveKEK` の "B window" を閉じる)。
 *
 * bit-equivalence: 旧経路 `hkdf_sha256(concat(m1,m2), salt, info, 32)` → `new MekKey(raw)`
 * と完全一致 (同一 HKDF-SHA256、 IKM = material1 || material2、 同一 salt/info)。
 *
 * material1/material2 (= pMat/kMat/rMat 等) は呼出側で zeroize 推奨。
 * @param {Uint8Array} material1
 * @param {Uint8Array} material2
 * @param {Uint8Array} salt
 * @param {Uint8Array} info
 * @returns {MekKey}
 */
export function derive_kek_handle(material1, material2, salt, info) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(material1, wasm.__wbindgen_export3);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(material2, wasm.__wbindgen_export3);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(salt, wasm.__wbindgen_export3);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(info, wasm.__wbindgen_export3);
        const len3 = WASM_VECTOR_LEN;
        wasm.derive_kek_handle(retptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return MekKey.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Phase 2-H4-full F6: standalone ECIES unwrap to K1Key opaque handle.
 * emp_priv_raw を取って ECIES decrypt + K1Key 構築を 1 関数で。
 * K1 raw bytes は WASM 内のみ、 emp_priv は caller (= JS) で raw 保持中だが
 * K1 の hiding が主目的。
 * @param {Uint8Array} emp_priv_raw
 * @param {Uint8Array} ephemeral_pub
 * @param {Uint8Array} iv
 * @param {Uint8Array} ciphertext
 * @param {Uint8Array} hkdf_salt
 * @param {Uint8Array} hkdf_info
 * @returns {K1Key}
 */
export function ecies_unwrap_to_k1key_with_emp_priv(emp_priv_raw, ephemeral_pub, iv, ciphertext, hkdf_salt, hkdf_info) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(emp_priv_raw, wasm.__wbindgen_export3);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(ephemeral_pub, wasm.__wbindgen_export3);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(iv, wasm.__wbindgen_export3);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_export3);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passArray8ToWasm0(hkdf_salt, wasm.__wbindgen_export3);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passArray8ToWasm0(hkdf_info, wasm.__wbindgen_export3);
        const len5 = WASM_VECTOR_LEN;
        wasm.ecies_unwrap_to_k1key_with_emp_priv(retptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        if (r2) {
            throw takeObject(r1);
        }
        return K1Key.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * HKDF-SHA256 extract + expand in one call.
 *
 * 2-step HKDF as in RFC 5869:
 *   PRK = HMAC-SHA256(salt, ikm)
 *   OKM = HMAC-SHA256(PRK, info || counter)  iterated to `length` bytes
 *
 * Output: `length` bytes of derived key material.
 *
 * # Backward-compat
 * Matches noble `hkdf(sha256, ikm, salt, info, length)`.
 * @param {Uint8Array} ikm
 * @param {Uint8Array} salt
 * @param {Uint8Array} info
 * @param {number} length
 * @returns {Uint8Array}
 */
export function hkdf_sha256(ikm, salt, info, length) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(ikm, wasm.__wbindgen_export3);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(salt, wasm.__wbindgen_export3);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(info, wasm.__wbindgen_export3);
        const len2 = WASM_VECTOR_LEN;
        wasm.hkdf_sha256(retptr, ptr0, len0, ptr1, len1, ptr2, len2, length);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v4 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export2(r0, r1 * 1, 1);
        return v4;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Derive a P-256 ECDH shared secret.
 *
 * # Parameters
 *   private_key:     32-byte raw scalar
 *   peer_public_key: 65-byte uncompressed SEC1 (0x04 || X || Y)
 *                    OR 33-byte compressed SEC1 (0x02/0x03 || X) — both accepted
 *
 * # Output
 *   32-byte shared secret (= x-coordinate of derived point, raw).
 *
 * # Backward-compat
 * Matches noble `p256.getSharedSecret(privKey, pubKey, true)` with the
 * shared secret returned as raw 32 bytes (= no SEC1 framing).
 * @param {Uint8Array} private_key
 * @param {Uint8Array} peer_public_key
 * @returns {Uint8Array}
 */
export function p256_ecdh(private_key, peer_public_key) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(private_key, wasm.__wbindgen_export3);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(peer_public_key, wasm.__wbindgen_export3);
        const len1 = WASM_VECTOR_LEN;
        wasm.p256_ecdh(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v3 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export2(r0, r1 * 1, 1);
        return v3;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Derive a P-256 keypair deterministically from a seed.
 *
 * # Algorithm
 *   1. Interpret seed bytes as big-endian unsigned integer
 *   2. Reduce modulo P-256 curve order n
 *   3. If 0, replace with 1 (極めて稀)
 *   4. Public key = scalar × BASE point
 *   5. Return: priv (= 32 byte) || pub (= 65 byte SEC1 uncompressed)
 *
 * # Backward-compat
 *   Matches vault-crypto.js `_signingKeyFromSeed` exactly:
 *     - bigint conversion: big-endian bytes → BigUint
 *     - mod n: same curve order
 *     - scalar multiplication: same P-256 BASE point
 *     - output format: same SEC1 uncompressed (0x04 || X || Y)
 *
 * # Parameters
 *   seed: 任意 byte length (= 16〜64 が典型、 noble は 48 を使う)
 *
 * # Output
 *   97 byte: priv(32) || pub(65)
 * @param {Uint8Array} seed
 * @returns {Uint8Array}
 */
export function p256_keypair_from_seed(seed) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(seed, wasm.__wbindgen_export3);
        const len0 = WASM_VECTOR_LEN;
        wasm.p256_keypair_from_seed(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v2 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export2(r0, r1 * 1, 1);
        return v2;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Generate a fresh P-256 keypair.
 *
 * # Output
 *   Concatenation of:
 *     - 32-byte raw scalar (= private key)
 *     - 65-byte uncompressed SEC1 (= 0x04 || X || Y, public key)
 *   Total: 97 bytes.
 *
 * JS caller is expected to slice and convert as needed (= noble returned
 * PrivateKey/PublicKey objects separately).
 *
 * # Randomness
 *   Uses `getrandom` crate which delegates to `window.crypto.getRandomValues`
 *   in WASM/browser context.
 * @returns {Uint8Array}
 */
export function p256_keypair_generate() {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        wasm.p256_keypair_generate(retptr);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v1 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export2(r0, r1 * 1, 1);
        return v1;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * Fill a buffer of `length` bytes with cryptographically-secure random bytes.
 *
 * # Why
 *   While JS already has `crypto.getRandomValues`, exposing this through
 *   Rust gives the option to centralize all random-source audit through
 *   the Rust core. Stage 1 keeps JS callers free to use either.
 * @param {number} length
 * @returns {Uint8Array}
 */
export function random_bytes(length) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        wasm.random_bytes(retptr, length);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        if (r3) {
            throw takeObject(r2);
        }
        var v1 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export2(r0, r1 * 1, 1);
        return v1;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
 * SHA-256 hash. Output: 32-byte digest.
 * @param {Uint8Array} input
 * @returns {Uint8Array}
 */
export function sha256_hash(input) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(input, wasm.__wbindgen_export3);
        const len0 = WASM_VECTOR_LEN;
        wasm.sha256_hash(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var v2 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_export2(r0, r1 * 1, 1);
        return v2;
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_fdd633d4bb5dd76a: function(arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return addHeapObject(ret);
        },
        __wbg___wbindgen_is_function_acc5528be2b923f2: function(arg0) {
            const ret = typeof(getObject(arg0)) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_object_0beba4a1980d3eea: function(arg0) {
            const val = getObject(arg0);
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_string_1fca8072260dd261: function(arg0) {
            const ret = typeof(getObject(arg0)) === 'string';
            return ret;
        },
        __wbg___wbindgen_is_undefined_721f8decd50c87a3: function(arg0) {
            const ret = getObject(arg0) === undefined;
            return ret;
        },
        __wbg___wbindgen_throw_ea4887a5f8f9a9db: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_call_5575218572ead796: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = getObject(arg0).call(getObject(arg1), getObject(arg2));
            return addHeapObject(ret);
        }, arguments); },
        __wbg_crypto_38df2bab126b63dc: function(arg0) {
            const ret = getObject(arg0).crypto;
            return addHeapObject(ret);
        },
        __wbg_error_a6fa202b58aa1cd3: function(arg0, arg1) {
            let deferred0_0;
            let deferred0_1;
            try {
                deferred0_0 = arg0;
                deferred0_1 = arg1;
                console.error(getStringFromWasm0(arg0, arg1));
            } finally {
                wasm.__wbindgen_export2(deferred0_0, deferred0_1, 1);
            }
        },
        __wbg_getRandomValues_c44a50d8cfdaebeb: function() { return handleError(function (arg0, arg1) {
            getObject(arg0).getRandomValues(getObject(arg1));
        }, arguments); },
        __wbg_length_589238bdcf171f0e: function(arg0) {
            const ret = getObject(arg0).length;
            return ret;
        },
        __wbg_msCrypto_bd5a034af96bcba6: function(arg0) {
            const ret = getObject(arg0).msCrypto;
            return addHeapObject(ret);
        },
        __wbg_new_227d7c05414eb861: function() {
            const ret = new Error();
            return addHeapObject(ret);
        },
        __wbg_new_with_length_9b650f44b5c44a4e: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return addHeapObject(ret);
        },
        __wbg_node_84ea875411254db1: function(arg0) {
            const ret = getObject(arg0).node;
            return addHeapObject(ret);
        },
        __wbg_process_44c7a14e11e9f69e: function(arg0) {
            const ret = getObject(arg0).process;
            return addHeapObject(ret);
        },
        __wbg_prototypesetcall_d721637c7ca66eb8: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), getObject(arg2));
        },
        __wbg_randomFillSync_6c25eac9869eb53c: function() { return handleError(function (arg0, arg1) {
            getObject(arg0).randomFillSync(takeObject(arg1));
        }, arguments); },
        __wbg_require_b4edbdcf3e2a1ef0: function() { return handleError(function () {
            const ret = module.require;
            return addHeapObject(ret);
        }, arguments); },
        __wbg_stack_3b0d974bbf31e44f: function(arg0, arg1) {
            const ret = getObject(arg1).stack;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_export3, wasm.__wbindgen_export4);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_static_accessor_GLOBAL_THIS_2fee5048bcca5938: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        },
        __wbg_static_accessor_GLOBAL_ce44e66a4935da8c: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        },
        __wbg_static_accessor_SELF_44f6e0cb5e67cdad: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        },
        __wbg_static_accessor_WINDOW_168f178805d978fe: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        },
        __wbg_subarray_b0e8ac4ed313fea8: function(arg0, arg1, arg2) {
            const ret = getObject(arg0).subarray(arg1 >>> 0, arg2 >>> 0);
            return addHeapObject(ret);
        },
        __wbg_versions_276b2795b1c6a219: function(arg0) {
            const ret = getObject(arg0).versions;
            return addHeapObject(ret);
        },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return addHeapObject(ret);
        },
        __wbindgen_cast_0000000000000002: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return addHeapObject(ret);
        },
        __wbindgen_object_clone_ref: function(arg0) {
            const ret = getObject(arg0);
            return addHeapObject(ret);
        },
        __wbindgen_object_drop_ref: function(arg0) {
            takeObject(arg0);
        },
    };
    return {
        __proto__: null,
        "./arpass_crypto_bg.js": import0,
    };
}

const BekKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_bekkey_free(ptr, 1));
const EmpPrivKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_empprivkey_free(ptr, 1));
const K1KeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_k1key_free(ptr, 1));
const MekKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_mekkey_free(ptr, 1));
const OuterKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_outerkey_free(ptr, 1));
const RMatKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_rmatkey_free(ptr, 1));
const SigningKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_signingkey_free(ptr, 1));

function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];

    heap[idx] = obj;
    return idx;
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
}

function dropObject(idx) {
    if (idx < 1028) return;
    heap[idx] = heap_next;
    heap_next = idx;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    return decodeText(ptr >>> 0, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function getObject(idx) { return heap[idx]; }

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        wasm.__wbindgen_export(addHeapObject(e));
    }
}

let heap = new Array(1024).fill(undefined);
heap.push(undefined, null, true, false);

let heap_next = heap.length;

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasmInstance, wasm;
function __wbg_finalize_init(instance, module) {
    wasmInstance = instance;
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = module.ok && expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('arpass_crypto_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
