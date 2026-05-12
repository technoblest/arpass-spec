<!--
====================================================================
⚠️ AUTO-GENERATED MIRROR — DO NOT PR HERE

This file is automatically synced from the private arpass repo on every
release. Direct edits to this file will be overwritten.

Source: technoblest/arpass / BUILD-HASHES.md
Mirror generator: scripts/generate-arpass-spec-mirror.mjs
====================================================================
-->

# Build hashes

SHA-256 of every file under `web/` (the directory served by Cloudflare Pages).

**Why this exists**: see [SECURITY.md → Build verification](./SECURITY.md#build-verification).

## How to verify

✅ **Verifiable via curl** — JS / JSON / config / image files:

```bash
# Compute SHA-256 of the live file at arpass.io
curl -s https://arpass.io/lib/vault-crypto.js | sha256sum
# Compare with the entry below for the same path
```

Mismatch on these = the live deployment diverges from this commit. Open a security advisory.

## ⚠️ HTML files: hash mismatch is expected (not a tampering signal)

**HTML files** (`*.html`) **will not match** the live curl hash because Cloudflare automatically injects the following into HTML responses only:

- **Cloudflare Web Analytics beacon** (`<script defer src="https://static.cloudflareinsights.com/..."></script>`)
- **Bot Fight Mode** challenge tokens (rotating per-request)

**This is by design and does not affect security**: the cryptographic operations (key derivation, AES-GCM encrypt/decrypt, ECDSA signing, Recovery decoding) all run in JavaScript files (`lib/*.js`). HTML is purely UI structure (forms, buttons, layout) and cannot exfiltrate secrets without JS — and the JS is verifiable.

Additionally, `Content-Security-Policy: form-action 'self'` (defined in `web/_headers`) prevents an attacker from redirecting form submissions to an external domain, even if HTML were tampered.

**Practical guidance**: Run hash verification on **JS files** (`lib/*.js`), the **i18n JSON files** (`i18n/*.json`), and the **published hash list itself** (`/.well-known/build-hashes.txt`). These are the files that matter for the security boundary.

---

**Generated**: 2026-05-12T22:05:06.482Z
**Files**: 65

| SHA-256 | Bytes | Path |
|---|---|---|
| `f8dda5a14390456597f141572462eea6ae0bd77c066211da9558794f1aac5e56` | 11510 | `_headers` |
| `f90724367930c1e805dde0702768b28293d9cbd899a076bdcea8456bf0d2afc4` | 321 | `.well-known/assetlinks.json` |
| `001b55b480f8936bf4b1cd4a0400da22c07e5a797d1bc36a593bf8bd6b33d731` | 100489 | `app.html` |
| `f95e3afbf046101041abac282cb5da357b09a4599bf6efd5b25b9b54eb496326` | 403588 | `arpass-image.png` |
| `ebaa0b820a097106fe6cefd3c56b46187d051f7ddc13efbc75ba7dc781b988df` | 625 | `favicon-16.png` |
| `bb52ebe86d04fca009d38d88da2366f3e3eba013b926c0c6f9b8fa5094471a03` | 1637 | `favicon-32.png` |
| `c52ba1a98f447fb79168d3b5b6c60f2f892056fe02897eb207808e8ff0b3c240` | 15342 | `favicon.ico` |
| `5768e0f5ade986412143b5220821ba18266890fd92347727cecee7e48ef64939` | 32414 | `help.html` |
| `01e9a74be224bcce810a547d7cb6a121f1bc24428e981d17d413caafaf40b782` | 166031 | `i18n/ar.json` |
| `16df91bda15b2a98f5bb5e58ac3732d1bfdc68b68fe2bc58b3e88ddb817ddd91` | 142159 | `i18n/de.json` |
| `e8c721b04d4df21f790e050d49d088c4ad3fbf54c6f222b42f84116be34a4715` | 127654 | `i18n/en.json` |
| `e8b4db3f1a5310da1cd0e0d133e20955ceee52b19a3812d22863324e748ace0d` | 138940 | `i18n/es.json` |
| `b3e8e212b66b848e2dd65ee0d51376c7fcf9cea62d7eed64893cfae19b05c672` | 143768 | `i18n/fr.json` |
| `24a4efac683ee896b696183a69794fb9f310a5e5948946a9e7fb3ebcb5723211` | 222980 | `i18n/hi.json` |
| `c0647a988185d0bdc394a213da87efd19b5ccda3222388d8947f950a41e16d03` | 131499 | `i18n/id.json` |
| `c0b8bcf6f0cc78b8ce204f7b98310346c5b2e986be6c69c0bfe0705379da1097` | 136365 | `i18n/it.json` |
| `eac371de16c1adfa3f0b1fe05ef83d7675b5e586e3974ae25c52743894c3a5c0` | 151901 | `i18n/ja.json` |
| `361a1b6347958338993b72616dcada6458f9d40d05684f688ac81bf781747438` | 141356 | `i18n/ko.json` |
| `b28c8c284b63e59fff3343183d1f25fe79b49b633fcaff5c20a4790476f335b9` | 136205 | `i18n/pt-BR.json` |
| `1ac7e524599d01e0150eb208a6ec9aff1c88f78c12df1119fab8e63dfa779579` | 5733 | `i18n/README.md` |
| `797165acc663fabd6741537a0d683c85236b85d59bc2ff4bc43fe577ecf5a079` | 195627 | `i18n/ru.json` |
| `3ea8d726c12a5a37694395d4a2fcc3197a4f358fe633084c23cb5f218355b596` | 136251 | `i18n/tr.json` |
| `5307abaafba9efccfc1a806b5b1cca6c834f902a5378e13c01da48789c219ea5` | 147617 | `i18n/vi.json` |
| `22b5340e47a6a78e6e25035b4878e172a3626e6581ac878dce940de8c352659e` | 120497 | `i18n/zh-CN.json` |
| `2c099645204d1b5606c4cbea48135582d25f488b06ee1ed368bcc5a411f89482` | 120562 | `i18n/zh-TW.json` |
| `aea87aec25c4698322f5a7ca7f43ca2070244ddddcc4c1ba3294de9d0635a183` | 356859 | `icon-1024.png` |
| `97e38260b98141784e8a5a21971c0f97073a5805eedfb7c78affa5dd27ae1ee5` | 23939 | `icon-192.png` |
| `5136b72cc1f12355947aacf4fd7a9d98fceae3ba5209210be5826b5399c5b2dd` | 122358 | `icon-512.png` |
| `7311900454c3565c8276737e129cdf2ddfde8b24b9cfbdbe986a17dc44d3f920` | 609 | `icon.svg` |
| `a14030d9642de8502b20396b6c97480383a4d25452b0d6c5a7fb3d3c43a1bba6` | 77322 | `index.html` |
| `aa1a20ed8c3b8c3807a3e340e4ab373729647beac852b1b02a5f4efb65cf10fd` | 234167 | `lib/app-main.js` |
| `c992adb34cfd4d2605db70eb166feaf366d3078655fcacceafa7f235dcef3151` | 37253 | `lib/client-auth.js` |
| `3d317680777a403f55de8d8c89ab869aeed03d7ea9730ba3aa3ac0e7b8a7975d` | 633 | `lib/help-main.js` |
| `e85cb4b9927714c92e74727659262009567b75d5fc478489c749f7f97436b3d2` | 14774 | `lib/i18n.js` |
| `ea255434dfdb2c5365493abe25715164300b0883c64b81601ef292588ce2a2f6` | 5748 | `lib/idb-cache.js` |
| `2d299d83fcf0c8ba16df3a797d02a5fba286fd7066ea10a844f345b41ccb8312` | 5754 | `lib/image-compress.js` |
| `d7cf043cb952f094aeeff508f2aca843bdb41a109db860f643d9755262d4846b` | 737 | `lib/index-main.js` |
| `1ad0a2e45642c1b219da566fe5bd5c72e69c5146b9113ea22fc87fc24bcf80d7` | 9054 | `lib/local-cache.js` |
| `cc0c4b2fab0fb7de2ed821669be4c36c8f3e828e79ddc516ef12d8abd7660deb` | 12554 | `lib/ocr-vision.js` |
| `9af3f31ab37edb56458b220e976fad43a8f60bbfa3ee016a0282746d1e9ecc91` | 648 | `lib/pay-cancel-main.js` |
| `9dc579269ca5969de6be1544c08cc63c6ed8dced0e6902767b124c743d23c3a7` | 1076 | `lib/pay-success-main.js` |
| `890960c51e5a485fe4c1ba9f6b0b2dcbd93f8e162e64e9ce8575be2269f8ea71` | 3634 | `lib/pdf-to-image.js` |
| `ed3f30754df5b08994bda75afb9b86ec6262acc1a63fb52c3f861f420505010f` | 7377 | `lib/pricing-main.js` |
| `67bec11bfb8ec7e49b5a88b58bf84b78ae26c28d45937644ba8775ad1d2a1b4b` | 7901 | `lib/qr.js` |
| `f5fca6372b427248aa679d164d6ec97e74363d916958e7002b251d90503c6835` | 7839 | `lib/save-debounce.js` |
| `54287038203f85d533926fb5b0aec7e0f35f2372ce7f59021607c366584e8558` | 652 | `lib/security-main.js` |
| `9fc8646a2c23ad3e3853c8dfd0971e023bf48cba52b79c07362477179565642b` | 72384 | `lib/vault-client.js` |
| `01f3125cc64467e398d38714672e59f40c979a4795646b03e8d5391dd0347190` | 47642 | `lib/vault-crypto.js` |
| `bc40c8a15196236b2314db0856f72ca0b49980cd5413b8c852a7349f5fee0859` | 256885 | `lib/vendor/jsqr.js` |
| `c6596eb7be8581c18be736c846fb9173b69eccf6ef94c5135893ec56bd92ba08` | 11358 | `lib/vendor/LICENSE-jsqr` |
| `c518e8e7d6fd6add47849fe528790af26533102d1ac898882dc1df49a76f6678` | 1915 | `lib/vendor/LICENSE-noble` |
| `ed60021cc356fd6b77e4c0cddc60cfa3bbd49042e8f91c13a7149d287ce99e9e` | 70382 | `lib/vendor/noble-curves-and-hashes.mjs` |
| `0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594` | 10174 | `lib/vendor/pdfjs/LICENSE` |
| `27fc2a057a00f92a4334ad06e17dbd7259912954e9fb7f76400bcca5fd190a9c` | 352645 | `lib/vendor/pdfjs/pdf.min.mjs` |
| `1baa1844c89c80a5b2797c916e75ab29254be46d8e9cb53cb6364d7aad84be36` | 1375838 | `lib/vendor/pdfjs/pdf.worker.min.mjs` |
| `18d12d607bda7ac5cc673ab515c2ed1a706483bfbcac7b20273f93368a6db62b` | 20 | `lib/vendor/pdfjs/VERSION.txt` |
| `ea91d7118a5395289170da848b7c6758b996163bfbccf312591ab65a4911b7c0` | 51907 | `lib/vendor/qrcode-generator.mjs` |
| `22e8a0fe10eed95d3f45c10904c7dd93a8c8e077a15a8f254cb4bb5edb1c82af` | 602 | `manifest.webmanifest` |
| `6f35e5031aee4ba9e5029e9e6659e50d22a4793452cb98e7fbaf35f21bf1dba3` | 1782 | `pay-cancel.html` |
| `4bc1933a96ec1acb5b73269fd8b3c08a497fb77820fb66583e3ef118efc59d39` | 2493 | `pay-success.html` |
| `fd136fec0311561d994654f666e350047f95c1da4aa3eda4c2aa4c74b2195747` | 7801 | `pricing.html` |
| `e5ded4942d4647dd5b8f973ae9232973507ba2c15347fd6867c9f0a6957396c7` | 23051 | `privacy.html` |
| `4d5d99d56ad88346a75c1a25e03c93c7592523ae63406e0e6637d31b46a6eee4` | 23465 | `security.html` |
| `811af38d946be27c0f5126ad73195045e6ea3b81be9da496bde4018bef5f57c0` | 17797 | `terms.html` |
| `3f2c122c70a90acf1ff46a2e88a1874038d250f924bf5f00abd419f67f65b9dc` | 12478 | `tokushoho.html` |
