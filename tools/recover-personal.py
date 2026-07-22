#!/usr/bin/env python3
# ============================================================================
# recover-personal.py — Arpass personal (Master + Recovery) vault recovery CLI
# ----------------------------------------------------------------------------
# Recovers an Arpass PERSONAL vault (envelope v5, mode absent — unlocked by the
# Master password + the Recovery secret "RS1-...") directly from the PUBLIC
# Arweave network AFTER the Arpass service has permanently shut down. No server,
# no browser, no arpass.io. This is the command-line counterpart to the browser
# emergency-recovery tool, for people who prefer to run recovery with code they
# control and can audit line by line.
#
# ZERO-KNOWLEDGE: all encrypted vault data is fetched from public Arweave
# gateways only. This tool NEVER contacts arpass.io or any /api endpoint. Your
# Master password and Recovery secret are read locally (getpass / stdin) and are
# used only to derive keys in memory; they are sent nowhere.
#
# The crypto here is bit-compatible with the web app
# (web/lib/vault-crypto.js and web/lib/emergency-recover-purejs.js) and the
# public spec repo github.com/technoblest/arpass-spec. Do not change the
# constants, HKDF salt/info strings, or the Argon2id parameters.
#
#   Personal unlock (AC path):
#     rMat  = HKDF(utf8(normalize(recovery)), "arpass-recovery-v1", "recovery-material", 32)
#     outer = HKDF(rMat, "arpass-outer-v6", "envelope-wrap", 32)     -> outer AES-GCM key
#     pMat  = Argon2id(master, envelope.s, kdfParams)                -> 32B
#     kek   = HKDF(pMat || rMat, "arpass-kek-pr-v1", "kek-pr", 32)
#     MEK   = AES-GCM-decrypt(kek, envelope.w.a)                     -> 32B
#     body  = AES-GCM-decrypt(MEK, envelope.i/.c) ; vault = unpad(body)
# ============================================================================

import sys
import os
import json
import argparse
import base64
import re

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Argon2id (reference libargon2 via argon2-cffi) — bit-compatible with the
# noble/Rust Argon2id the app uses. Imported lazily in derive_pmat so that the
# pure-helper self-tests can run even without argon2-cffi installed.

# ---------------------------------------------------------------------------
# Constants (bit-compatible with vault-crypto.js — do not deviate)
# ---------------------------------------------------------------------------
AES_IV_LEN = 12
AES_TAG_LEN = 16
PAD_TERMINATOR = 0x80
VAULT_FORMAT_V5 = 5

APPTAG_NAME_LEN = 8
APPTAG_VALUE_LEN = 16

# HKDF-SHA256 (salt, info) — UTF-8 strings.
HKDF_RECOVERY_SALT = b"arpass-recovery-v1"
HKDF_RECOVERY_INFO = b"recovery-material"
HKDF_OUTER_SALT = b"arpass-outer-v6"
HKDF_OUTER_INFO = b"envelope-wrap"
HKDF_KEKPR_SALT = b"arpass-kek-pr-v1"
HKDF_KEKPR_INFO = b"kek-pr"
HKDF_APPTAG_NAME_SALT = b"arpass-app-tag-name-v6"
HKDF_APPTAG_NAME_INFO = b"app-tag-name"
HKDF_APPTAG_VALUE_SALT = b"arpass-app-tag-value-v6"
HKDF_APPTAG_VALUE_INFO = b"app-tag-value"

# Argon2id defaults (used only when envelope has no kdfParams).
ARGON2_DEFAULT_M = 65536   # KiB (== 64 MiB)
ARGON2_DEFAULT_T = 3
ARGON2_DEFAULT_P = 4
ARGON2_DEFAULT_DKLEN = 32
ARGON2_VERSION = 19        # 0x13

# Recovery-string dash normalization: any of these Unicode dashes -> ASCII "-".
# Mirrors the browser deriveRMat regex /[‐-―−－⁃‧]/ :
#   U+2010..U+2015 (range), U+2212, U+FF0D, U+2043, U+2027.
_DASH_CHARS = "".join(
    [chr(c) for c in range(0x2010, 0x2016)] + [chr(0x2212), chr(0xFF0D), chr(0x2043), chr(0x2027)]
)
_DASH_RE = re.compile("[" + re.escape(_DASH_CHARS) + "]")
_WS_RE = re.compile(r"\s+")

# The four tiers to probe when locating the vault envelope. None == no suffix.
TIERS = [None, "free", "paid", "private"]

ARWEAVE_GATEWAYS = ["https://arweave.net", "https://turbo-gateway.com"]
GRAPHQL_ENDPOINTS = ["https://arweave.net/graphql", "https://turbo-gateway.com/graphql"]
HTTP_TIMEOUT = 30

import urllib.request
import urllib.error


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


def graphql_candidates(tag_name: str, tag_value: str):
    """Return [(txid, height), ...] for tag {name:value}, MERGING both public
    GraphQL indexes (arweave.net can lag behind Turbo). Not sorted here — the
    caller merges across tiers and sorts newest-first."""
    query = (
        'query { transactions(tags:[{name:"%s", values:["%s"]}], '
        'sort:HEIGHT_DESC, first:25){edges{node{id block{height}}}} }' % (tag_name, tag_value)
    )
    found = {}
    for endpoint in GRAPHQL_ENDPOINTS:
        try:
            data = _http_post_json(endpoint, {"query": query})
            edges = (data.get("data") or {}).get("transactions", {}).get("edges", [])
            for e in edges:
                node = e.get("node", {})
                txid = node.get("id")
                h = (node.get("block") or {}).get("height")
                if not txid:
                    continue
                # Prefer a known height over an unknown one for the same txid.
                if txid not in found or (found[txid] is None and h is not None):
                    found[txid] = h
        except Exception:  # noqa: BLE001 — one gateway failing is tolerable
            pass
    return list(found.items())


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
# personal-vault key derivations (bit-compatible with vault-crypto.js)
# ---------------------------------------------------------------------------
def normalize_recovery(recovery_string: str) -> str:
    s = _DASH_RE.sub("-", recovery_string or "")
    s = _WS_RE.sub("", s)
    return s.upper()


def derive_rmat(recovery_string: str) -> bytes:
    norm = normalize_recovery(recovery_string).encode("utf-8")
    return hkdf_sha256(norm, HKDF_RECOVERY_SALT, HKDF_RECOVERY_INFO, 32)


def derive_outer_key(rmat: bytes) -> bytes:
    return hkdf_sha256(rmat, HKDF_OUTER_SALT, HKDF_OUTER_INFO, 32)


def derive_app_name_tag(rmat: bytes, tier=None) -> dict:
    suffix = ("::" + tier) if tier else ""
    name = hkdf_sha256(rmat, HKDF_APPTAG_NAME_SALT, HKDF_APPTAG_NAME_INFO + suffix.encode("utf-8"),
                       APPTAG_NAME_LEN)
    value = hkdf_sha256(rmat, HKDF_APPTAG_VALUE_SALT, HKDF_APPTAG_VALUE_INFO + suffix.encode("utf-8"),
                        APPTAG_VALUE_LEN)
    return {"name": b64u_encode(name), "value": b64u_encode(value)}


def derive_pmat(master: str, salt: bytes, kdf_params) -> bytes:
    """Argon2id via the reference libargon2 (argon2-cffi). Bit-compatible with
    noble/Rust Argon2id: same salt, memory (KiB), iterations, parallelism, and
    version 0x13. Returns the raw 32-byte derived key."""
    try:
        from argon2.low_level import hash_secret_raw, Type
    except ImportError as e:  # noqa: BLE001
        raise RuntimeError(
            "argon2-cffi is required for personal (Master) recovery. "
            "Install it with:  pip install argon2-cffi") from e

    if kdf_params:
        alg = kdf_params.get("alg")
        if alg and alg != "argon2id":
            raise RuntimeError("unsupported KDF alg %r (expected argon2id)" % alg)
        m = int(kdf_params.get("m", ARGON2_DEFAULT_M))
        t = int(kdf_params.get("t", ARGON2_DEFAULT_T))
        p = int(kdf_params.get("p", ARGON2_DEFAULT_P))
        dklen = int(kdf_params.get("dkLen", ARGON2_DEFAULT_DKLEN))
    else:
        m, t, p, dklen = ARGON2_DEFAULT_M, ARGON2_DEFAULT_T, ARGON2_DEFAULT_P, ARGON2_DEFAULT_DKLEN

    return hash_secret_raw(
        secret=master.encode("utf-8"),
        salt=salt,
        time_cost=t,
        memory_cost=m,
        parallelism=p,
        hash_len=dklen,
        type=Type.ID,
        version=ARGON2_VERSION,
    )


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
def print_entries(vault: dict, show_pw: bool = False) -> int:
    entries = vault.get("entries") or []
    print("\n================ PASSWORD ENTRIES (%d) ================" % len(entries))
    for i, e in enumerate(entries, 1):
        if not isinstance(e, dict):
            continue
        print("\n[%d]" % i)
        for label, key in (("Site", "site"), ("User", "user"), ("Password", "pw"),
                           ("URL", "url"), ("Notes", "notes")):
            val = e.get(key)
            if not val:
                continue
            if key == "pw" and not show_pw:
                val = "(hidden - see vault.json, or run with --show-passwords)"
            print("    %-9s %s" % (label + ":", val))
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
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            print("    Saved file: %s (%d bytes)" % (path, len(plain)))
            saved += 1
    return saved


# ---------------------------------------------------------------------------
# Locate the vault envelope across all tiers on the public Arweave network
# ---------------------------------------------------------------------------
def find_envelope(rmat: bytes, outer_key: bytes):
    """Probe every tier's app-name tag, gather ALL candidate txids across tiers
    and both gateways, dedupe, sort newest-first, and return the first that
    outer-decrypts to a v5 envelope. The rMat-derived outer key only decrypts
    THIS user's envelopes, so a successful decrypt is a positive match."""
    candidates = {}   # txid -> height
    tier_by_txid = {}
    for tier in TIERS:
        tag = derive_app_name_tag(rmat, tier)
        label = tier or "(no-tier)"
        try:
            found = graphql_candidates(tag["name"], tag["value"])
        except Exception:  # noqa: BLE001
            found = []
        if found:
            print("      tier %-10s: %d candidate tx" % (label, len(found)))
        for txid, h in found:
            if txid not in candidates or (candidates[txid] is None and h is not None):
                candidates[txid] = h
            tier_by_txid.setdefault(txid, label)

    if not candidates:
        return None

    # newest first (unknown heights last)
    ordered = sorted(
        candidates.items(),
        key=lambda kv: (kv[1] is not None, kv[1] if kv[1] is not None else -1),
        reverse=True,
    )
    for txid, h in ordered:
        try:
            blob = fetch_blob(txid)
            env_plain = aes_gcm_decrypt(outer_key, blob[:AES_IV_LEN], blob[AES_IV_LEN:])
            envelope = json.loads(env_plain.decode("utf-8"))
        except Exception:  # noqa: BLE001 — not ours / corrupt / not JSON
            continue
        if isinstance(envelope, dict) and envelope.get("v") == VAULT_FORMAT_V5:
            return {"envelope": envelope, "txid": txid, "height": h,
                    "tier": tier_by_txid.get(txid, "(no-tier)")}
    return None


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(
        description="Recover an Arpass personal (Master + Recovery) vault from public Arweave.")
    ap.add_argument("--out", default=".", help="Output directory (default: current directory).")
    ap.add_argument("--no-files", action="store_true", help="Skip recovering file attachments.")
    ap.add_argument("--show-passwords", action="store_true",
                    help="Print passwords in cleartext to the console (default: masked).")
    args = ap.parse_args()

    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)

    print("Arpass personal (Master + Recovery) vault recovery")
    print("  Arweave (pub) : %s" % ", ".join(ARWEAVE_GATEWAYS))
    print("  Output dir    : %s" % out_dir)

    # Inputs — read locally; sent nowhere.
    import getpass
    master = getpass.getpass("Master password: ")
    recovery = input("Recovery secret (RS1-...): ")
    if not master:
        raise RuntimeError("Master password is empty.")
    if not recovery.strip():
        raise RuntimeError("Recovery secret is empty.")

    # Step 1: derive rMat + outer key from the Recovery secret.
    print("\n[1] Deriving recovery material from the Recovery secret...")
    rmat = derive_rmat(recovery)
    outer_key = derive_outer_key(rmat)

    # Step 2: locate the vault envelope on public Arweave (probe all tiers).
    print("[2] Searching public Arweave for your vault envelope (probing all tiers)...")
    hit = find_envelope(rmat, outer_key)
    if hit is None:
        raise RuntimeError(
            "No personal vault found for this Recovery secret "
            "(check the Recovery, or this may be a YubiKey-only / business vault).")
    envelope = hit["envelope"]
    print("      Found vault envelope: tx %s (tier %s, height %s)"
          % (hit["txid"], hit["tier"], hit["height"]))

    # Step 3: reject non-personal envelopes with a helpful message.
    mode = envelope.get("m")
    if mode == "hwkey":
        raise RuntimeError(
            "This is a YubiKey-only (hwkey) vault. Use recover-yubikey.py with your YubiKey.")
    if mode == "business":
        raise RuntimeError(
            "This is a business vault. It needs the admin K1 file to decrypt; "
            "use the browser emergency-recovery tool.")
    if not (envelope.get("w") or {}).get("a"):
        raise RuntimeError(
            "Envelope has no Master+Recovery (AC) wrap; this vault cannot be opened "
            "with a Master password + Recovery secret.")

    # Step 4: derive pMat from the Master password (Argon2id).
    kdf = envelope.get("kdfParams")
    if kdf:
        print("[3] Deriving keys (Argon2id m=%s KiB t=%s p=%s, this takes a few seconds)..."
              % (kdf.get("m", ARGON2_DEFAULT_M), kdf.get("t", ARGON2_DEFAULT_T),
                 kdf.get("p", ARGON2_DEFAULT_P)))
    else:
        print("[3] Deriving keys (Argon2id m=%d KiB t=%d p=%d, this takes a few seconds)..."
              % (ARGON2_DEFAULT_M, ARGON2_DEFAULT_T, ARGON2_DEFAULT_P))
    salt = b64u_decode(envelope["s"])
    pmat = derive_pmat(master, salt, kdf)

    # Step 5: AC wrap -> MEK.
    print("[4] Unwrapping the master key (MEK)...")
    kek = hkdf_sha256(pmat + rmat, HKDF_KEKPR_SALT, HKDF_KEKPR_INFO, 32)
    wrap = envelope["w"]["a"]
    try:
        mek = aes_gcm_decrypt(kek, b64u_decode(wrap["i"]), b64u_decode(wrap["c"]))
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(
            "Decryption failed - wrong Master password "
            "(the Recovery matched the vault, so the Master is the likely mismatch).") from e
    if len(mek) != 32:
        raise RuntimeError("unwrapped MEK is not 32 bytes")

    # Step 6: decrypt the vault body.
    print("[5] Decrypting the vault body...")
    padded = aes_gcm_decrypt(mek, b64u_decode(envelope["i"]), b64u_decode(envelope["c"]))
    vault = json.loads(unpad(padded).decode("utf-8"))

    # Step 7: output.
    n = print_entries(vault, args.show_passwords)
    print("\n      Decrypted %d entries." % n)
    vpath = os.path.join(out_dir, "vault.json")
    with open(vpath, "w", encoding="utf-8") as fh:
        json.dump(vault, fh, ensure_ascii=False, indent=2)
    try:
        os.chmod(vpath, 0o600)
    except OSError:
        pass
    print("      Saved %s" % vpath)

    files = 0
    if not args.no_files:
        recs = ((vault.get("records") or {}).get("active")) or []
        if recs:
            print("\n[6] Recovering %d record(s) with file attachments..." % len(recs))
            files = recover_files(vault, mek, out_dir)
            print("      Recovered %d file(s)." % files)

    print("\n================ SECURITY NOTICE ================")
    print("  vault.json and any recovered attachments are PLAINTEXT")
    print("  (passwords/files in the clear). Handle with care:")
    print("    - Do NOT run this in a cloud-synced/backed-up folder (Dropbox, iCloud, etc.).")
    print("    - Delete these files when you are done (they were written with 0600 perms).")
    print("    - Passwords are masked on screen; use --show-passwords to reveal, or open vault.json.")
    print("  This tool only reads from public Arweave gateways; it sends your secrets nowhere.")
    print("  Your Master password and Recovery secret never leave this machine.")
    print("=================================================")
    print("\nDone.")
    return 0


# ---------------------------------------------------------------------------
# Runtime self-tests of the pure helpers (no network, no vault, no argon2 needed)
# ---------------------------------------------------------------------------
def _selftest() -> int:
    import os as _os
    # b64url roundtrip (incl. lengths that need padding)
    for raw in (b"", b"\x00", b"abc", _os.urandom(8), _os.urandom(16), _os.urandom(31)):
        assert b64u_decode(b64u_encode(raw)) == raw, "b64url roundtrip failed"
    assert "=" not in b64u_encode(_os.urandom(10)), "b64url must be unpadded"
    # hkdf length
    out = hkdf_sha256(b"ikm", b"salt", b"info", 32)
    assert len(out) == 32, "hkdf length"
    assert len(hkdf_sha256(b"ikm", b"salt", b"info", 8)) == 8, "hkdf length 8"
    # aes-gcm tag-appended roundtrip
    key = _os.urandom(32)
    iv = _os.urandom(AES_IV_LEN)
    ct = AESGCM(key).encrypt(iv, b"hello world", None)
    assert aes_gcm_decrypt(key, iv, ct) == b"hello world", "aes-gcm roundtrip"
    # unpad: valid + error path
    assert unpad(b"data\x80\x00\x00") == b"data", "unpad basic"
    assert unpad(b"data\x80") == b"data", "unpad no trailing zeros"
    assert unpad(b"\x80") == b"", "unpad empty payload"
    try:
        unpad(b"data\x00\x01")  # non-zero, non-terminator before any 0x80
        raise AssertionError("unpad should have raised")
    except ValueError:
        pass
    # recovery normalization: unicode dashes -> '-', whitespace stripped, uppercased
    assert normalize_recovery(" rs1–ab cd−ef ") == "RS1-ABCD-EF", "normalize"
    # derive_rmat / derive_outer_key are deterministic 32B
    r = derive_rmat("RS1-TESTTESTTESTTEST")
    assert len(r) == 32 and derive_rmat("rs1-testtesttesttest") == r, "rmat determinism/normalize"
    assert len(derive_outer_key(r)) == 32, "outer key length"
    tag = derive_app_name_tag(r, "paid")
    assert len(b64u_decode(tag["name"])) == APPTAG_NAME_LEN, "app tag name len"
    assert len(b64u_decode(tag["value"])) == APPTAG_VALUE_LEN, "app tag value len"
    assert derive_app_name_tag(r, None)["name"] != tag["name"], "tier suffix changes tag"
    print("selftest OK")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
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
