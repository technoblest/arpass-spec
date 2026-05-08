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

**Generated**: 2026-05-08T07:34:16.598Z
**Files**: 57

| SHA-256 | Bytes | Path |
|---|---|---|
| `82fbc9e55f8f3134b48de7b4cf3c6ef56a2a095b9bf735b08bf243184be29e82` | 9186 | `_headers` |
| `f90724367930c1e805dde0702768b28293d9cbd899a076bdcea8456bf0d2afc4` | 321 | `.well-known/assetlinks.json` |
| `9a81b0f1dbf76113809f428c25b76fe731a3c2558557585ad121119a925148e0` | 68144 | `app.html` |
| `f95e3afbf046101041abac282cb5da357b09a4599bf6efd5b25b9b54eb496326` | 403588 | `arpass-image.png` |
| `ebaa0b820a097106fe6cefd3c56b46187d051f7ddc13efbc75ba7dc781b988df` | 625 | `favicon-16.png` |
| `bb52ebe86d04fca009d38d88da2366f3e3eba013b926c0c6f9b8fa5094471a03` | 1637 | `favicon-32.png` |
| `c52ba1a98f447fb79168d3b5b6c60f2f892056fe02897eb207808e8ff0b3c240` | 15342 | `favicon.ico` |
| `d434ef7a3a56618fa536c2a7d76ecc02df19aef07c80fb77dcb0fa2a4deff9a5` | 27432 | `help.html` |
| `a06a8d5ac445d159a366f800cc3f73b9c6c23572c36555c95b0372f6826fea00` | 94586 | `i18n/ar.json` |
| `229ef81d6c5e9ec80368d1dbc4cbbfad0e2a8fa31001a6baa2c2dd5fbb6dc43f` | 81377 | `i18n/de.json` |
| `1c690430895aa8711375406b70dcd3acd61f998a3c4253473b57757e87528732` | 102741 | `i18n/en.json` |
| `477d168768f1af4ea67ec25c6c659b2292725c9104a40457336f5159388a136e` | 79475 | `i18n/es.json` |
| `65a1537923af4049bbbd9ae01a4bd4b412418e5a8502b393d3154686fdcb2293` | 82536 | `i18n/fr.json` |
| `3963dd8ea6e0987461ee64db5d960e537edc7d5a1501d523e501bebb9c4e7212` | 133018 | `i18n/hi.json` |
| `fdf1e17fd186b3b2e87d351d3b6d985b0d0136873b3d78561f7c5fee6be9dde8` | 76208 | `i18n/id.json` |
| `b9c92033a4a427d790c852c4ae4b81194300d2699b1514118cbb739e8dafcd84` | 78818 | `i18n/it.json` |
| `dc16534808761722d5f19b473414492b064dee8e9d0d584e348b458b40382fb1` | 122316 | `i18n/ja.json` |
| `b11d68bd066e0f3acbf12c45509b79b2f61a24cfb6663ee233755d95732b12f0` | 81912 | `i18n/ko.json` |
| `514d1475e0ffc27c5208004c31c9fbbbc4ecba140f6755d82d557119ed6ff32f` | 78032 | `i18n/pt-BR.json` |
| `1ac7e524599d01e0150eb208a6ec9aff1c88f78c12df1119fab8e63dfa779579` | 5733 | `i18n/README.md` |
| `6f791a294c5d4b333745d1c65ec1fb44291dd5ce964283db92a7c143618f91c0` | 111069 | `i18n/ru.json` |
| `b129d3e6a32a77756fa460e1765d9ff224ccb63f36e44ee3e0f813cf5df6bb02` | 77761 | `i18n/tr.json` |
| `9185f9159ba3c216832e2467e27c3a298a35d3ea2da2c68d99cefd186374e4d3` | 85682 | `i18n/vi.json` |
| `e235046d09906a1bf5db7e1386449b6ae82c23c49eddbc04e4b3bef3e496940a` | 69226 | `i18n/zh-CN.json` |
| `fefeaf341a6d742b5dd67139695f726769d30fea0d8f8ac4e12730f8710d5032` | 69398 | `i18n/zh-TW.json` |
| `aea87aec25c4698322f5a7ca7f43ca2070244ddddcc4c1ba3294de9d0635a183` | 356859 | `icon-1024.png` |
| `97e38260b98141784e8a5a21971c0f97073a5805eedfb7c78affa5dd27ae1ee5` | 23939 | `icon-192.png` |
| `5136b72cc1f12355947aacf4fd7a9d98fceae3ba5209210be5826b5399c5b2dd` | 122358 | `icon-512.png` |
| `7311900454c3565c8276737e129cdf2ddfde8b24b9cfbdbe986a17dc44d3f920` | 609 | `icon.svg` |
| `cfa97988d20b6bc11a7194bbab543784c89060dde43280be1042c300c2363873` | 67093 | `index.html` |
| `1952089ddab5a001a72008c171aff592518356256ef1d22e6140f26919227ad9` | 136408 | `lib/app-main.js` |
| `01097bacc66969165345b5c0cb8fe5a6be50d616b6e70171b1c880a7d7070342` | 31659 | `lib/client-auth.js` |
| `3d317680777a403f55de8d8c89ab869aeed03d7ea9730ba3aa3ac0e7b8a7975d` | 633 | `lib/help-main.js` |
| `e85cb4b9927714c92e74727659262009567b75d5fc478489c749f7f97436b3d2` | 14774 | `lib/i18n.js` |
| `d7cf043cb952f094aeeff508f2aca843bdb41a109db860f643d9755262d4846b` | 737 | `lib/index-main.js` |
| `65f84a74331d48846a9cdc081340e748b117ed170030a5bc803a4a1c55d184af` | 4253 | `lib/local-cache.js` |
| `9af3f31ab37edb56458b220e976fad43a8f60bbfa3ee016a0282746d1e9ecc91` | 648 | `lib/pay-cancel-main.js` |
| `9dc579269ca5969de6be1544c08cc63c6ed8dced0e6902767b124c743d23c3a7` | 1076 | `lib/pay-success-main.js` |
| `d69f9ed8ffa5be28e634e7a82a7a5d84a145638ca0f39fda0035f99d9e7c1a85` | 7264 | `lib/pricing-main.js` |
| `67bec11bfb8ec7e49b5a88b58bf84b78ae26c28d45937644ba8775ad1d2a1b4b` | 7901 | `lib/qr.js` |
| `f5fca6372b427248aa679d164d6ec97e74363d916958e7002b251d90503c6835` | 7839 | `lib/save-debounce.js` |
| `54287038203f85d533926fb5b0aec7e0f35f2372ce7f59021607c366584e8558` | 652 | `lib/security-main.js` |
| `9c9b4e2a330df8010d72a654377b7526512aa4c0a102362a06d9c9d7be0923f2` | 39041 | `lib/vault-client.js` |
| `5ba46de6a3dac132c16d7c00bf43d7d9ff6d19a8e40f2902f4571f8978eedfbc` | 36547 | `lib/vault-crypto.js` |
| `bc40c8a15196236b2314db0856f72ca0b49980cd5413b8c852a7349f5fee0859` | 256885 | `lib/vendor/jsqr.js` |
| `c6596eb7be8581c18be736c846fb9173b69eccf6ef94c5135893ec56bd92ba08` | 11358 | `lib/vendor/LICENSE-jsqr` |
| `c518e8e7d6fd6add47849fe528790af26533102d1ac898882dc1df49a76f6678` | 1915 | `lib/vendor/LICENSE-noble` |
| `ed60021cc356fd6b77e4c0cddc60cfa3bbd49042e8f91c13a7149d287ce99e9e` | 70382 | `lib/vendor/noble-curves-and-hashes.mjs` |
| `ea91d7118a5395289170da848b7c6758b996163bfbccf312591ab65a4911b7c0` | 51907 | `lib/vendor/qrcode-generator.mjs` |
| `22e8a0fe10eed95d3f45c10904c7dd93a8c8e077a15a8f254cb4bb5edb1c82af` | 602 | `manifest.webmanifest` |
| `4d61a485b44f754b48f5a402703182a44d302e9f23ce169ae9143f69ae634ec1` | 1771 | `pay-cancel.html` |
| `c314591adffaa9cfdf270c6120c8568c9c7bde78ee334b53ccc1f600a10cae94` | 2482 | `pay-success.html` |
| `2d8703294c7d3ed9e3b1b95008a9ffb16c3c16ad2ca9e117e042bda571879cb0` | 5975 | `pricing.html` |
| `e5ded4942d4647dd5b8f973ae9232973507ba2c15347fd6867c9f0a6957396c7` | 23051 | `privacy.html` |
| `7117b8d93e14b465d86edde864df898dc58536776dd3de52f091eb2d51c407b1` | 23454 | `security.html` |
| `811af38d946be27c0f5126ad73195045e6ea3b81be9da496bde4018bef5f57c0` | 17797 | `terms.html` |
| `3f2c122c70a90acf1ff46a2e88a1874038d250f924bf5f00abd419f67f65b9dc` | 12478 | `tokushoho.html` |
