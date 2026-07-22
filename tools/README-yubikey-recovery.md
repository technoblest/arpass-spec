<!--
====================================================================
⚠️ AUTO-GENERATED MIRROR — DO NOT PR HERE

This file is automatically synced from the private arpass repo on every
release. Direct edits to this file will be overwritten.

Source: technoblest/arpass / tools/README-yubikey-recovery.md
Mirror generator: scripts/generate-arpass-spec-mirror.mjs
====================================================================
-->

# Arpass YubiKey-only vault recovery (`recover-yubikey.py`)

A standalone command-line tool that recovers an Arpass **hwkey (YubiKey-only)
vault** directly from the **public Arweave network**, even after the Arpass
service has permanently shut down. It talks to your YubiKey over **CTAP2**
(USB HID) using Yubico's `python-fido2`.

## Why this native tool exists

An Arpass YubiKey credential is bound to the WebAuthn `rpId` `arpass.io`. In a
browser, the PRF secret that unlocks your vault can only be requested from a
page served on that exact origin — so once `arpass.io` is gone, no other web
page can use the credential (the browser enforces origin binding). CTAP2, the
wire protocol the browser speaks to the key, takes `rpId` as an explicit
parameter, so a native tool can present `rpId="arpass.io"` itself and obtain the
**same PRF output** — no server and no origin lock-in required. Your encrypted
vault already lives permanently on the public Arweave blockchain, so this tool
needs only your YubiKey plus that public data.

This is a zero-knowledge design: the tool fetches encrypted data from public
Arweave gateways only and **never contacts `arpass.io` or any API endpoint**.
All decryption happens locally on your machine.

## What you need

- The **YubiKey** (or other FIDO2 key) you enrolled with Arpass, with its PIN if
  one is set. YubiKey-only vaults require at least two keys were enrolled; any
  **one** of them can recover the vault.
- Python 3.8+ and a USB port.

## Install

```bash
cd tools
python3 -m venv venv && source venv/bin/activate    # optional but recommended
pip install -r requirements.txt
```

## Run

1. Plug in your YubiKey.
2. Run the tool:

   ```bash
   python3 recover-yubikey.py
   ```

3. When prompted, **enter your YubiKey PIN** (only if the key has one), then
   **touch the key when it blinks**.

Options:

- `--out DIR` — where to write output (default: current directory).
- `--uv preferred|required|discouraged` — user-verification level. Default
  `preferred` mirrors the browser and adapts to whether your key has a PIN.
- `--no-files` — skip recovering file attachments (passwords only).

## What it outputs

- Prints each password entry (`site`, `user`, `pw`, `url`, `notes`).
- Writes **`vault.json`** — the full decrypted vault — to the output directory.
- Recovers and saves any **file attachments** stored in your vault, using each
  attachment's original filename (sanitized).

The tool never prints raw cryptographic keys. `vault.json` and any recovered
files are **plaintext** — store them somewhere safe and delete them when done.

## How it works (summary)

1. CTAP2 get-assertion on `rpId=arpass.io` with an empty allow-list (your
   credential is discoverable/resident) requesting the WebAuthn PRF. This yields
   the 32-byte `prfOutput`, the `credentialId`, and the `userHandle`.
2. The `userHandle` encodes a locator tag pointing at your **keyslot** object on
   Arweave. The tool finds it via the public Arweave GraphQL endpoint.
3. The keyslot is decrypted with a key derived from your PRF; it yields the
   vault's tag and the envelope's outer key.
4. The vault **envelope** is fetched from Arweave and outer-decrypted, then the
   master key is unwrapped with your PRF and the vault body is decrypted.

## Cross-verification

The cryptography implemented here is bit-compatible with the Arpass web app and
the public spec repository **`github.com/technoblest/arpass-spec`**
(`rust-crypto/src/lib.rs` and `lib/vault-crypto.js`). You can audit those
sources to confirm the constants, HKDF salts/info strings, and envelope format.


## Multiple vaults on one key

A single YubiKey can be enrolled in **several** Arpass vaults (each is a separate
resident credential). This tool recovers **all** of them in one run: it writes
`vault_0.json`, `vault_1.json`, ... (and `files_N/` for any attachments) and
prints a **SUMMARY** at the end showing how many password entries and files each
vault has. Your real vault is the one with entries. (If you truly want to remove
a vault from a key, delete its credential from the YubiKey itself.)

## Security notes

- **Passwords are masked on screen by default.** Use `--show-passwords` to print them,
  or read the written `vault_N.json`.
- **Output is plaintext.** `vault_N.json` and recovered files contain your passwords /
  documents in the clear. They are written with `0600` permissions. Do **not** run this
  in a cloud-synced or backed-up folder (Dropbox, iCloud Drive, OneDrive, ...), and
  **delete** the files when you are done.
- **This tool sends your secrets nowhere.** It only issues read requests (GraphQL tag
  lookups + blob GETs) to the public Arweave gateways. The YubiKey PIN is read via
  `getpass` and never stored or printed.
- **Get this tool only from the official source** — `github.com/technoblest/arpass-spec`
  (owner: technoblest). A recovery tool handles your most sensitive secrets; running a
  tampered copy would expose them. Verify the repository owner, and prefer a specific
  commit you have reviewed.
