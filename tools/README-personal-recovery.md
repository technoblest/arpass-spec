<!--
====================================================================
⚠️ AUTO-GENERATED MIRROR — DO NOT PR HERE

This file is automatically synced from the private arpass repo on every
release. Direct edits to this file will be overwritten.

Source: technoblest/arpass / tools/README-personal-recovery.md
Mirror generator: scripts/generate-arpass-spec-mirror.mjs
====================================================================
-->

# Arpass personal (Master + Recovery) vault recovery (`recover-personal.py`)

A standalone command-line tool that recovers an Arpass **personal vault** —
the kind unlocked with your **Master password** plus your **Recovery secret**
(`RS1-...`) — directly from the **public Arweave network**, even after the
Arpass service has permanently shut down. It is the command-line counterpart to
the browser emergency-recovery tool, for people who prefer to run recovery with
code they control and can audit line by line.

## Why this native tool exists

Your encrypted vault lives permanently on the public Arweave blockchain. All the
keys that open it are derived from two secrets **you** hold — your Master
password and your Recovery secret — never from an arpass.io server. So recovery
needs nothing but those two secrets and the public data. This tool derives the
keys locally and decrypts on your machine.

This is a zero-knowledge design: the tool fetches encrypted data from public
Arweave gateways only and **never contacts `arpass.io` or any API endpoint**.
Your Master password and Recovery secret are read locally and **sent nowhere**.

## What you need

- Your **Master password**.
- Your **Recovery secret** — the `RS1-...` string you saved when you set up the
  vault.
- Python 3.8+.

(YubiKey-only vaults use `recover-yubikey.py` instead; business vaults need the
admin K1 file and the browser emergency-recovery tool.)

## Install

```bash
cd tools
python3 -m venv venv && source venv/bin/activate    # optional but recommended
pip install cryptography argon2-cffi
# or: pip install -r requirements.txt
```

`cryptography` provides HKDF-SHA256 + AES-256-GCM; `argon2-cffi` provides the
Argon2id key derivation used for the Master password (reference libargon2,
bit-compatible with the app).

## Run

```bash
python3 recover-personal.py
```

You will be prompted for:

- **Master password** — read via `getpass` (not echoed to the screen).
- **Recovery secret (RS1-...)** — read from stdin.

Options:

- `--out DIR` — where to write output (default: current directory).
- `--no-files` — skip recovering file attachments (passwords only).
- `--show-passwords` — print passwords in cleartext (default: masked).

The Argon2id step takes a few seconds — that is expected (it is deliberately
memory-hard).

## What it outputs

- Prints each password entry (`site`, `user`, `pw`, `url`, `notes`); passwords
  are masked unless you pass `--show-passwords`.
- Writes **`vault.json`** — the full decrypted vault — to the output directory
  (with `0600` permissions).
- Recovers and saves any **file attachments** stored in your vault, using each
  attachment's original filename (sanitized).

The tool never prints raw cryptographic keys or your secrets.

## How it works (summary)

1. `rMat = HKDF(normalize(Recovery), "arpass-recovery-v1", "recovery-material")`
   and the outer envelope key `HKDF(rMat, "arpass-outer-v6", "envelope-wrap")`.
2. Probe the public Arweave GraphQL indexes for your vault's app-name tag across
   every tier, newest-first, and outer-decrypt to find your envelope. The
   rMat-derived key only decrypts *your* envelopes, so a successful decrypt is a
   positive match.
3. `pMat = Argon2id(Master, envelope.s, kdfParams)`, then
   `kek = HKDF(pMat || rMat, "arpass-kek-pr-v1", "kek-pr")` and unwrap the
   master key (MEK) from the envelope's Master+Recovery (AC) wrap.
4. Decrypt the vault body with the MEK; decrypt each attachment's per-file key
   (BEK) with the MEK, then the file with the BEK.

## Cross-verification

The cryptography implemented here is bit-compatible with the Arpass web app
(`web/lib/vault-crypto.js`, `web/lib/emergency-recover-purejs.js`) and the
public spec repository **`github.com/technoblest/arpass-spec`**. You can audit
those sources to confirm the constants, HKDF salt/info strings, Argon2id
parameters, and envelope format.

## Security notes

- **Passwords are masked on screen by default.** Use `--show-passwords` to print
  them, or read the written `vault.json`.
- **Output is plaintext.** `vault.json` and recovered files contain your
  passwords / documents in the clear. They are written with `0600` permissions.
  Do **not** run this in a cloud-synced or backed-up folder (Dropbox, iCloud
  Drive, OneDrive, ...), and **delete** the files when you are done.
- **This tool sends your secrets nowhere.** It only issues read requests
  (GraphQL tag lookups + blob GETs) to the public Arweave gateways. The Master
  password and Recovery secret are read via `getpass`/stdin and are never stored,
  printed, or transmitted.
- **Get this tool only from the official source** — `github.com/technoblest/arpass-spec`
  (owner: technoblest). A recovery tool handles your most sensitive secrets;
  running a tampered copy would expose them. Verify the repository owner, prefer
  a specific commit you have reviewed, and prefer running code you control.
