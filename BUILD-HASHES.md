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

**Generated**: 2026-05-08T02:24:24.544Z
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
| `f6d1f350f2f5aef2cee7f096a09045990e6006deea44096bbbd6791e21c8cabf` | 94399 | `i18n/ar.json` |
| `491890874ae6a4cff1a042493a3219a486e6b605019bc6964185c4caef03c98f` | 81191 | `i18n/de.json` |
| `a470c6bcf985a9f59492db2a10a66659b269bb487082c13ad89dfef3cc57e995` | 102587 | `i18n/en.json` |
| `b73cae2ae1875f2321721126e99cec6805d1fa57df1ff7dbec7f682383993706` | 79302 | `i18n/es.json` |
| `26d683fb328b07a3fa1435a69040264786f6e7ef3eec32a355dd0c9c048cb620` | 82361 | `i18n/fr.json` |
| `f9fc06d29adf696de50c215d68f53a5437354fa5d8875a2718f3c194e1c1ecfe` | 132725 | `i18n/hi.json` |
| `2bc956ecf8c51c73363165d349d9e515cab443edb1cd8d77d07e32a8fbcf4d05` | 76046 | `i18n/id.json` |
| `f8138300d9581758b2b79d7e290ba1f3fc1e4036f987f2700e01c1e534dd7cb7` | 78643 | `i18n/it.json` |
| `477923cd35a5b27f36be1f986fea56bd7ce894017680576b6789164ded7738ab` | 122128 | `i18n/ja.json` |
| `56fe8386147677df4e3239e38d45bc390b3693f5a217910a4f8c03716d86c641` | 81738 | `i18n/ko.json` |
| `0d9fb0ba287b505c7321f9b4775959f6ba75336f58410745762d3f3050608aff` | 77861 | `i18n/pt-BR.json` |
| `1ac7e524599d01e0150eb208a6ec9aff1c88f78c12df1119fab8e63dfa779579` | 5733 | `i18n/README.md` |
| `e48a915df9a517126a423449e542334fcc7bd90ebd7951128f5f7870c49b4ac3` | 110843 | `i18n/ru.json` |
| `4dd3001998c71861ce9f50d924ffb85d6689a13839474f0def438f72968fcf28` | 77574 | `i18n/tr.json` |
| `1f51971ac72cf59124c4585996c5dbb1aa16a74945c1d5874b41719cb03297a9` | 85525 | `i18n/vi.json` |
| `ad3c71571d5cc7740079ba7cd807e46aa8c510faed03ad012de5a950798856b4` | 69079 | `i18n/zh-CN.json` |
| `4db0295d3b7365a05f43d12a1b7dc80a11fb5aa056c8f34cc58455ee8c4cee29` | 69251 | `i18n/zh-TW.json` |
| `aea87aec25c4698322f5a7ca7f43ca2070244ddddcc4c1ba3294de9d0635a183` | 356859 | `icon-1024.png` |
| `97e38260b98141784e8a5a21971c0f97073a5805eedfb7c78affa5dd27ae1ee5` | 23939 | `icon-192.png` |
| `5136b72cc1f12355947aacf4fd7a9d98fceae3ba5209210be5826b5399c5b2dd` | 122358 | `icon-512.png` |
| `7311900454c3565c8276737e129cdf2ddfde8b24b9cfbdbe986a17dc44d3f920` | 609 | `icon.svg` |
| `cfa97988d20b6bc11a7194bbab543784c89060dde43280be1042c300c2363873` | 67093 | `index.html` |
| `67ef888b6418cf1ed375e43210b16499a2095a63df180ae330f6df1a6dadff17` | 132705 | `lib/app-main.js` |
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
