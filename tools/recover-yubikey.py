#!/usr/bin/env python3
# ============================================================================
# recover-yubikey.py — Arpass hwkey (YubiKey-only) vault recovery CLI
# ----------------------------------------------------------------------------
# Recovers an Arpass "hwkey" mode vault (mode:"hwkey", envelope v5) directly
# from the PUBLIC Arweave network AFTER the Arpass service has permanently shut
# down. It talks to the YubiKey over CTAP2 (USB HID) via Yubico's python-fido2,
# obtaining the same WebAuthn PRF output the browser used — but without any
# arpass.io server and without a browser's origin binding.
#
# WHY THIS TOOL EXISTS
#   A WebAuthn/YubiKey credential is bound to an rpId (here "arpass.io"). In a
#   browser the PRF secret can only be requested from a page served on that
#   origin, so once arpass.io is gone no other web page can use the credential.
#   CTAP2 (the wire protocol the browser speaks to the key) takes rpId as an
#   explicit parameter, so a native tool can present rpId="arpass.io" itself and
#   obtain the exact same PRF output — no server, no origin lock-in. The vault
#   ciphertext already lives permanently on the public Arweave network; this
#   tool only needs the YubiKey plus public data.
#
# ZERO-KNOWLEDGE: all encrypted vault data is fetched from public Arweave
# gateways only. This tool NEVER contacts arpass.io or any /api endpoint.
#
# The crypto here is bit-compatible with the web app (web/lib/vault-crypto.js)
# and the public spec repo github.com/technoblest/arpass-spec
# (rust-crypto/src/lib.rs, lib/vault-crypto.js). Do not change the constants.
# ============================================================================

import sys
import os
import json
import argparse
import base64
import hashlib
import urllib.request
import urllib.error
import re

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Constants (bit-compatible with vault-crypto.js — do not deviate)
# ---------------------------------------------------------------------------
RP_ID = "arpass.io"
ORIGIN = "https://arpass.io"          # registrable domain must match RP_ID

# WebAuthn PRF input salt used by the web app:
#   extensions: { prf: { eval: { first: PRF_SALT } } }
PRF_SALT = b"arpass-passkey-prf-salt-v1"

USERID_HWKEY_VERSION = 8
APPTAG_NAME_LEN = 8
APPTAG_VALUE_LEN = 16
AES_IV_LEN = 12
AES_TAG_LEN = 16
WRAPPED_MEK_LEN = AES_IV_LEN + 32 + AES_TAG_LEN   # 60
PAD_TERMINATOR = 0x80
VAULT_FORMAT_V5 = 5

# HKDF-SHA256 (salt, info) pairs — UTF-8 strings, 32-byte output.
HKDF_KEYSLOT_SALT = b"arpass-keyslot-v7"
HKDF_KEYSLOT_INFO = b"keyslot-wrap"
HKDF_MEKWRAP_SALT = b"arpass-mek-wrap-v7"
HKDF_MEKWRAP_INFO = b"mek-wrap"

ARWEAVE_GATEWAYS = ["https://arweave.net", "https://turbo-gateway.com"]
GRAPHQL_ENDPOINTS = ["https://arweave.net/graphql", "https://turbo-gateway.com/graphql"]
HTTP_TIMEOUT = 30


# ---------------------------------------------------------------------------
# base64url (no padding)
# ---------------------------------------------------------------------------
def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    s = str(s)
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + ("=" * pad))


# ---------------------------------------------------------------------------
# crypto primitives
# ---------------------------------------------------------------------------
def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def aes_gcm_decrypt(key: bytes, iv: bytes, ct_with_tag: bytes) -> bytes:
    # `cryptography` AESGCM expects the 16-byte GCM tag appended to the ciphertext.
    return AESGCM(key).decrypt(iv, ct_with_tag, None)


def unpad(padded: bytes) -> bytes:
    # Scan backwards: first 0x80 is the terminator; trailing 0x00 are padding.
    for i in range(len(padded) - 1, -1, -1):
        b = padded[i]
        if b == PAD_TERMINATOR:
            return padded[:i]
        if b != 0x00:
            raise ValueError("padding terminator not found")
    raise ValueError("padding terminator not found")


# ---------------------------------------------------------------------------
# Arweave (public) fetch helpers — resilient across gateways
# ---------------------------------------------------------------------------
def _http_post_json(url: str, payload: dict) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_get_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"Accept": "application/octet-stream"})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        return resp.read()


def graphql_newest_txid(tag_name: str, tag_value: str) -> str:
    """Find the newest Arweave tx carrying tag {name: value}. PUBLIC data only."""
    query = (
        'query { transactions(tags:[{name:"%s", values:["%s"]}], '
        'sort:HEIGHT_DESC, first:5){edges{node{id}}} }' % (tag_name, tag_value)
    )
    last_err = None
    for endpoint in GRAPHQL_ENDPOINTS:
        try:
            data = _http_post_json(endpoint, {"query": query})
            edges = (data.get("data") or {}).get("transactions", {}).get("edges", [])
            if edges:
                return edges[0]["node"]["id"]
            last_err = RuntimeError("no matching transaction on %s" % endpoint)
        except (urllib.error.URLError, urllib.error.HTTPError, ValueError, KeyError) as e:
            last_err = e
    raise RuntimeError("GraphQL tag lookup failed (name=%s): %s" % (tag_name, last_err))


def fetch_blob(txid: str) -> bytes:
    """Fetch raw tx data bytes from a public Arweave gateway (with fallback)."""
    last_err = None
    for gw in ARWEAVE_GATEWAYS:
        try:
            return _http_get_bytes("%s/%s" % (gw, txid))
        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            last_err = e
    raise RuntimeError("could not fetch blob %s: %s" % (txid, last_err))


# ---------------------------------------------------------------------------
# CTAP2 / WebAuthn PRF via python-fido2
# ---------------------------------------------------------------------------
def _build_fido_client(dev, interaction):
    """Construct a Fido2Client across python-fido2 1.x and 2.x signatures.

    1.x:  Fido2Client(device, origin, user_interaction=...)
    2.x:  Fido2Client(device, client_data_collector=DefaultClientDataCollector(origin), ...)
    The PRF extension is enabled by default in both; we do NOT need raw hmac-secret.
    """
    from fido2.client import Fido2Client
    try:
        return Fido2Client(dev, ORIGIN, user_interaction=interaction)
    except TypeError:
        from fido2.client import DefaultClientDataCollector
        return Fido2Client(
            dev,
            client_data_collector=DefaultClientDataCollector(ORIGIN),
            user_interaction=interaction,
        )


def _get_attr(obj, *names):
    """Return first present attribute/key (tolerates dataclass vs dict shapes)."""
    for n in names:
        if hasattr(obj, n):
            v = getattr(obj, n)
            if v is not None:
                return v
        try:
            if n in obj:
                return obj[n]
        except (TypeError, KeyError):
            pass
    return None


def ctap2_get_prf(uv: str):
    """CTAP2 get-assertion on rpId=arpass.io, empty allowList (resident cred),
    requesting the WebAuthn PRF output. Returns (prfOutput, credentialId, userHandle).

    The high-level `prf` extension performs the WebAuthn-PRF -> hmac-secret salt
    mapping internally: hmac_salt = SHA256(b"WebAuthn PRF\\x00" + PRF_SALT). We
    therefore pass the RAW PRF_SALT as prf.eval.first, exactly like the browser.
    """
    from fido2.hid import CtapHidDevice
    from fido2.client import UserInteraction

    class CliInteraction(UserInteraction):
        def __init__(self):
            self._pin = None

        def prompt_up(self):
            print("\n>>> Touch your YubiKey now (it should be blinking)...\n", flush=True)

        def request_pin(self, permissions, rd_id):
            from getpass import getpass
            if not self._pin:
                self._pin = getpass("Enter YubiKey PIN: ")
            return self._pin

        def request_uv(self, permissions, rd_id):
            print("User Verification required (touch / biometric).", flush=True)
            return True

    devs = list(CtapHidDevice.list_devices())
    if not devs:
        raise RuntimeError("No FIDO2 USB HID authenticator found. Plug in your YubiKey.")

    interaction = CliInteraction()
    last_err = None
    for dev in devs:
        try:
            client = _build_fido_client(dev, interaction)
        except Exception as e:  # noqa: BLE001
            last_err = e
            continue

        options = {
            "rpId": RP_ID,
            "challenge": os.urandom(32),   # unused (we only want the PRF, no server verify)
            "allowCredentials": [],        # empty => discoverable/resident credential
            "userVerification": uv,
            "extensions": {"prf": {"eval": {"first": PRF_SALT}}},
        }
        try:
            selection = client.get_assertion(options)
        except Exception as e:  # noqa: BLE001
            last_err = e
            continue

        # Decrypt PRF outputs (get_response performs hmac-secret decryption).
        response = selection.get_response(0)

        # --- prfOutput ---
        prf_out = None
        ext = _get_attr(response, "extension_results", "client_extension_results")
        if ext is not None:
            try:
                prf_out = ext["prf"]["results"]["first"]
            except (TypeError, KeyError):
                prf = _get_attr(ext, "prf")
                results = _get_attr(prf, "results") if prf is not None else None
                prf_out = _get_attr(results, "first") if results is not None else None
        if prf_out is None:
            raise RuntimeError(
                "YubiKey returned no PRF output. This vault requires a key enrolled "
                "with the arpass.io PRF/hmac-secret credential."
            )
        prf_out = bytes(prf_out)

        # --- credentialId + userHandle: prefer the raw CTAP2 assertion ---
        credential_id = None
        user_handle = None
        try:
            raw = selection.get_assertions()[0]
            cred = _get_attr(raw, "credential")
            user = _get_attr(raw, "user")
            if cred is not None:
                credential_id = _get_attr(cred, "id")
            if user is not None:
                user_handle = _get_attr(user, "id")
        except Exception:  # noqa: BLE001
            pass
        if credential_id is None:
            credential_id = _get_attr(response, "credential_id")
        if user_handle is None:
            user_handle = _get_attr(response, "user_handle")

        if user_handle is None:
            raise RuntimeError(
                "Authenticator did not return a userHandle. The vault's keyslot "
                "pointer lives in the resident credential's user.id; without it "
                "recovery cannot proceed (is this the right YubiKey?)."
            )
        return prf_out, (bytes(credential_id) if credential_id else b""), bytes(user_handle)

    raise RuntimeError("CTAP2 get-assertion failed on all connected keys: %s" % last_err)


# ---------------------------------------------------------------------------
# hwkey userHandle -> keyslotTag
# ---------------------------------------------------------------------------
def decode_user_handle(user_handle: bytes) -> dict:
    if len(user_handle) != 1 + APPTAG_NAME_LEN + APPTAG_VALUE_LEN:
        raise ValueError(
            "userHandle length %d != %d (not an hwkey-mode credential?)"
            % (len(user_handle), 1 + APPTAG_NAME_LEN + APPTAG_VALUE_LEN)
        )
    if user_handle[0] != USERID_HWKEY_VERSION:
        raise ValueError(
            "userHandle version %d != %d (this tool only recovers hwkey/YubiKey-only vaults)"
            % (user_handle[0], USERID_HWKEY_VERSION)
        )
    name_b = user_handle[1:1 + APPTAG_NAME_LEN]
    value_b = user_handle[1 + APPTAG_NAME_LEN:1 + APPTAG_NAME_LEN + APPTAG_VALUE_LEN]
    return {"name": b64u_encode(name_b), "value": b64u_encode(value_b)}


# ---------------------------------------------------------------------------
# File name sanitization
# ---------------------------------------------------------------------------
def sanitize_filename(name: str) -> str:
    name = os.path.basename(str(name or "file"))
    name = re.sub(r"[^A-Za-z0-9._ \-()\[\]]", "_", name).strip()
    if not name or name in (".", ".."):
        name = "file"
    return name[:200]


# ---------------------------------------------------------------------------
# Vault pretty-print
# ---------------------------------------------------------------------------
def print_entries(vault: dict) -> int:
    entries = vault.get("entries") or []
    print("\n================ PASSWORD ENTRIES (%d) ================" % len(entries))
    for i, e in enumerate(entries, 1):
        if not isinstance(e, dict):
            continue
        print("\n[%d]" % i)
        for label, key in (("Site", "site"), ("User", "user"), ("Password", "pw"),
                           ("URL", "url"), ("Notes", "notes")):
            if e.get(key):
                print("    %-9s %s" % (label + ":", e.get(key)))
    print("\n======================================================")
    return len(entries)


# ---------------------------------------------------------------------------
# Records / attachments recovery
# ---------------------------------------------------------------------------
def recover_files(vault: dict, mek: bytes, out_dir: str) -> int:
    records = (vault.get("records") or {}).get("active") or []
    saved = 0
    for rec in records:
        if not isinstance(rec, dict):
            continue
        for att in (rec.get("attachments") or []):
            if not isinstance(att, dict):
                continue
            enc = att.get("encryption") or {}
            txid = att.get("txId")
            fname = sanitize_filename(att.get("filename"))
            if not (txid and enc.get("wrappedBEK") and enc.get("wrapIv") and enc.get("dataIv")):
                print("    ! skipping attachment (missing metadata): %s" % fname)
                continue
            try:
                # MEK and BEK are used DIRECTLY as raw AES-256 keys (no extra HKDF).
                bek = aes_gcm_decrypt(mek, b64u_decode(enc["wrapIv"]), b64u_decode(enc["wrappedBEK"]))
                blob = fetch_blob(txid)  # raw ciphertext; dataIv is separate metadata
                plain = aes_gcm_decrypt(bek, b64u_decode(enc["dataIv"]), blob)
            except Exception as e:  # noqa: BLE001
                print("    ! failed to recover file %s: %s" % (fname, e))
                continue
            path = os.path.join(out_dir, fname)
            base, ext = os.path.splitext(path)
            n = 1
            while os.path.exists(path):
                path = "%s_%d%s" % (base, n, ext)
                n += 1
            with open(path, "wb") as fh:
                fh.write(plain)
            print("    Saved file: %s (%d bytes)" % (path, len(plain)))
            saved += 1
    return saved


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(
        description="Recover an Arpass hwkey (YubiKey-only) vault from public Arweave via CTAP2.")
    ap.add_argument("--uv", default="preferred", choices=["preferred", "required", "discouraged"],
                    help="userVerification level (default: preferred, mirrors the browser).")
    ap.add_argument("--out", default=".", help="Output directory (default: current directory).")
    ap.add_argument("--no-files", action="store_true", help="Skip recovering file attachments.")
    args = ap.parse_args()

    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)

    print("Arpass YubiKey-only vault recovery")
    print("  rpId          : %s" % RP_ID)
    print("  Arweave (pub) : %s" % ", ".join(ARWEAVE_GATEWAYS))
    print("  Output dir    : %s" % out_dir)

    # Step 1: CTAP2 get-assertion -> PRF, credentialId, userHandle
    print("\n[1/8] Requesting WebAuthn PRF from your YubiKey via CTAP2...")
    prf_output, credential_id, user_handle = ctap2_get_prf(args.uv)
    print("      Got PRF output (%d bytes), userHandle (%d bytes)." % (len(prf_output), len(user_handle)))

    # Step 2: userHandle -> keyslotTag
    print("[2/8] Decoding userHandle -> keyslot locator tag...")
    keyslot_tag = decode_user_handle(user_handle)

    # Step 3: find keyslot tx on Arweave, fetch blob
    print("[3/8] Locating keyslot transaction on Arweave...")
    ks_txid = graphql_newest_txid(keyslot_tag["name"], keyslot_tag["value"])
    print("      Found keyslot tx: %s" % ks_txid)
    ks_blob = fetch_blob(ks_txid)

    # Step 4: decode keyslot
    print("[4/8] Decrypting keyslot with YubiKey PRF...")
    keyslot_key = hkdf_sha256(prf_output, HKDF_KEYSLOT_SALT, HKDF_KEYSLOT_INFO, 32)
    try:
        padded = aes_gcm_decrypt(keyslot_key, ks_blob[:AES_IV_LEN], ks_blob[AES_IV_LEN:])
    except Exception:
        raise SystemExit("ERROR: keyslot decryption failed (wrong YubiKey, or corrupt blob).")
    payload = json.loads(unpad(padded).decode("utf-8"))
    app_name_tag = payload["t"]
    outer_key = b64u_decode(payload["o"])
    if len(outer_key) != 32:
        raise SystemExit("ERROR: keyslot outer key is not 32 bytes.")

    # Step 5: find vault envelope by appNameTag
    print("[5/8] Locating vault envelope on Arweave...")
    env_txid = graphql_newest_txid(app_name_tag["name"], app_name_tag["value"])
    print("      Found envelope tx: %s" % env_txid)
    env_blob = fetch_blob(env_txid)

    # Step 6: outer-decrypt the envelope
    print("[6/8] Outer-decrypting the vault envelope...")
    try:
        env_plain = aes_gcm_decrypt(outer_key, env_blob[:AES_IV_LEN], env_blob[AES_IV_LEN:])
    except Exception:
        raise SystemExit("ERROR: envelope outer decryption failed (corrupt blob).")
    envelope = json.loads(env_plain.decode("utf-8"))
    if envelope.get("v") != VAULT_FORMAT_V5 or envelope.get("m") != "hwkey":
        raise SystemExit("ERROR: not an hwkey v5 envelope (v=%r m=%r)."
                         % (envelope.get("v"), envelope.get("m")))

    # Step 7: unwrap MEK (try each k[] entry, first success wins)
    print("[7/8] Unwrapping the master encryption key with your YubiKey...")
    wrap_key = hkdf_sha256(prf_output[:32], HKDF_MEKWRAP_SALT, HKDF_MEKWRAP_INFO, 32)
    mek = None
    for e in (envelope.get("k") or []):
        wrapped = b64u_decode(e.get("w", ""))
        if len(wrapped) != WRAPPED_MEK_LEN:
            continue
        try:
            mek = aes_gcm_decrypt(wrap_key, wrapped[:AES_IV_LEN], wrapped[AES_IV_LEN:])
            if len(mek) == 32:
                break
            mek = None
        except Exception:
            mek = None
    if mek is None:
        raise SystemExit("ERROR: could not unwrap MEK (wrong YubiKey?)")

    # Step 8: decrypt body
    print("[8/8] Decrypting vault body...")
    padded_body = aes_gcm_decrypt(mek, b64u_decode(envelope["i"]), b64u_decode(envelope["c"]))
    vault = json.loads(unpad(padded_body).decode("utf-8"))

    n = print_entries(vault)
    print("\nDecrypted %d entries." % n)

    # Write vault.json (full decrypted vault) to output dir
    vault_path = os.path.join(out_dir, "vault.json")
    with open(vault_path, "w", encoding="utf-8") as fh:
        json.dump(vault, fh, ensure_ascii=False, indent=2)
    print("Saved vault.json -> %s" % vault_path)

    # Files / attachments
    if not args.no_files:
        print("\nRecovering file attachments (if any)...")
        saved = recover_files(vault, mek, out_dir)
        print("Recovered %d file(s)." % saved)

    print("\nDone. Keep vault.json and any recovered files safe; they are plaintext.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        print("\nERROR: %s" % exc, file=sys.stderr)
        sys.exit(1)
