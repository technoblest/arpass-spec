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

**Generated**: 2026-06-03T01:20:44.681Z
**Files**: 201

| SHA-256 | Bytes | Path |
|---|---|---|
| `f8dda5a14390456597f141572462eea6ae0bd77c066211da9558794f1aac5e56` | 11510 | `_headers` |
| `f90724367930c1e805dde0702768b28293d9cbd899a076bdcea8456bf0d2afc4` | 321 | `.well-known/assetlinks.json` |
| `4e94973c0121c0da970e803b690624ec49a5bcd9457275e009b0eaa43bf9cc03` | 155120 | `app.html` |
| `d9097ff6de63659cc571cfc74d96b05733fdf4203482eb1a50185c90a4197261` | 50519 | `ar/help.html` |
| `63efefa27061bf68ad04f22082cb74e842928e71c7716e97abd9d342f5aaefc1` | 92613 | `ar/index.html` |
| `16cd76e436a743b95e8f8b82e27f5c32411170aa834af18515c9e0d830367cde` | 10228 | `arpass-emergency-restore.html` |
| `1e852fb57a76a006193b3009c92f6b48d242ef50698f0ec217d336436c12e32e` | 66067 | `arpass-image.png` |
| `578c43b2fcee11a4ea1ddc8f3ff0b3c19cb77d819f8eb49a271a5ab42d0bf80e` | 58254 | `arpass-image.webp` |
| `5c692df273ededf21f7233d9f773e9f5b74fc6fac5129f5f5c6300e7d5e38d72` | 45142 | `de/help.html` |
| `452fbfcf0f4b565e92642bc794f1b0ff8d534287b35297f3dcb7eb2c88152dce` | 85595 | `de/index.html` |
| `992473324dbaf0397999649deca25c6475edc52f9ac38996def5eeacfb798393` | 39585 | `en/help.html` |
| `17bcf67db5ebe8c41868f84b15a335b55e3613cc528b7d6fc6c6a8c8142c69da` | 83070 | `en/index.html` |
| `266f8a9a438c447bde4f91a2a2f7475c66e24d9cb9c44445094bcaa1b43e1b64` | 43558 | `es/help.html` |
| `002d8fdc48c2bebe6976bf22967fb00c1ac048e70af2e9ada3a8281f4465041a` | 84737 | `es/index.html` |
| `ebaa0b820a097106fe6cefd3c56b46187d051f7ddc13efbc75ba7dc781b988df` | 625 | `favicon-16.png` |
| `bb52ebe86d04fca009d38d88da2366f3e3eba013b926c0c6f9b8fa5094471a03` | 1637 | `favicon-32.png` |
| `c52ba1a98f447fb79168d3b5b6c60f2f892056fe02897eb207808e8ff0b3c240` | 15342 | `favicon.ico` |
| `07c3008cf1f9e89647848da133e2289daf9f2dd2b131cef17c73c1197c2ab9db` | 44932 | `fr/help.html` |
| `4f21cadb9a07f94a5a8c9708adc030c7970e50e487f5e14a58da23cbdcfcd36a` | 86369 | `fr/index.html` |
| `30208b7752b8c89e6b7aa35baf5f094f2266b3f55f30e2f93396a2cc41949ed1` | 3712 | `guide/ar/index.html` |
| `92b6518717d1f88afa3da9a7c53c4d6602a8ca722dfa583a7be85ce965f84b78` | 12693 | `guide/ar/security-glossary.html` |
| `86deeaca1e1e440f41466874b6cd579d54655f480d2b11c374203be9c35e54f8` | 9877 | `guide/ar/yubikey-arpass.html` |
| `c745c013387e2b778bc3dd2c6eab9414ac69256226e485186dd8eea8566cac83` | 11287 | `guide/ar/yubikey-guide.html` |
| `7c5d8ac3e7e5e6bb1fe39224200ece958bc51e87810d32309452ed8e383441ac` | 8426 | `guide/ar/yubikey-price.html` |
| `1b37b1cb16d7c8b294e932f1f6525a5c9890bd7abbbfb54f08e44ea793e57fde` | 10139 | `guide/ar/yubikey-vs-passkey.html` |
| `b66cbd186dee32bfd418efc64bd2eba31e2352bf3a02a522b78f62c845edfc5c` | 3273 | `guide/de/index.html` |
| `2e4e8696cd6234a0aa025eb9a67f6aae25a62449c738650ab5dbd6d2a679d239` | 10623 | `guide/de/security-glossary.html` |
| `3fbbc1f9a75b19b929cb4463350956ed128562ace020a4fc0f2281b79cf4c312` | 8638 | `guide/de/yubikey-arpass.html` |
| `fa8f971cdb1167bf9afa290b18851d6961c5ae95d8d43ab51da2426ed8dd1efb` | 9508 | `guide/de/yubikey-guide.html` |
| `d71701436233307e9a324e103b6d19f9081272348b9fa88716e3580b72dfce13` | 7227 | `guide/de/yubikey-price.html` |
| `6f7d5c7f03de2837da7972e8450fd907451ea6219d9d67484fc8f592fb741700` | 8547 | `guide/de/yubikey-vs-passkey.html` |
| `b4fabcadb226f991a8a5571ffe2bb6f1221f9ca482d3eefefc2be431b6e98ce9` | 3103 | `guide/en/index.html` |
| `182999248fcf3d2f8781e2334d33bc4b5526266fa320c31f29d5cea8de3369de` | 9055 | `guide/en/security-glossary.html` |
| `66841a44acf657b1a9a44fb8e61849164039fbf48e274fc6f0e52135d53eae22` | 7649 | `guide/en/yubikey-arpass.html` |
| `4d3548afb0a803c564680f2d8c35715a9fe853ade4fcfca58c983e36a7e2bb85` | 8977 | `guide/en/yubikey-guide.html` |
| `d7d446bf6ca92bf03b215526ffb0de798ac62d846b5bd30c867af20995f1971b` | 6674 | `guide/en/yubikey-price.html` |
| `f74ea918caac88cb6d1d32a36925c6a723aba47c29d8845b269e5309d9747032` | 7856 | `guide/en/yubikey-vs-passkey.html` |
| `40053e43e52e01a942d0373235a80b5f0b395c53632f4059db52dbc4e5374853` | 3358 | `guide/es/index.html` |
| `495dba8c577b696583e7ede48468734488820e2b9079f7fb3331b8716883cc9b` | 10603 | `guide/es/security-glossary.html` |
| `aceda0790261cb6a33b90f63226392d18a22440ac759e1408bfb2080b0240f24` | 8111 | `guide/es/yubikey-arpass.html` |
| `440fd982d23fdfde2aeb69354b90eb993251954ecaca3b5ebe7f36778c98d445` | 9669 | `guide/es/yubikey-guide.html` |
| `c325ae6d98d7b8e3da312e5f5906f3e4e0b3ad13f4463a38d652f7f15651dfe6` | 7176 | `guide/es/yubikey-price.html` |
| `0332387957ca35786a4be6d46db00d5d9bf08d912ac17a83d192201f4b2d914e` | 8534 | `guide/es/yubikey-vs-passkey.html` |
| `ce5077ecb936ab40714d483e992ebbe53400bbcb7d0fd55cea28479bb9edb0dd` | 3378 | `guide/fr/index.html` |
| `3182cc75fb7c79cbc3bc0465d98fae62df85faa7a3523ae9a2e3840984f6e7e8` | 10975 | `guide/fr/security-glossary.html` |
| `b1a547e04e9f271c4acffc75ddea316512a3007b26f3e3ec19d1cb6f52e8d62f` | 8650 | `guide/fr/yubikey-arpass.html` |
| `cd03c95cdd1d14564372fbd46f139a33b3206bbf4adc278b58758ff4898e9c67` | 9932 | `guide/fr/yubikey-guide.html` |
| `bc94ec65eb64bc5186dbc47fd99b7b1bcaf5dc3d69a790e2a0f8eb3fae65de86` | 7507 | `guide/fr/yubikey-price.html` |
| `549952b067a2a4140aac634642aec4fe3bd82d79b8ee32cad4ccad1ab2edf827` | 8827 | `guide/fr/yubikey-vs-passkey.html` |
| `1576fc3367e246c0daf24a3bc6e8b7aa00a671f50ff919ca39053f966e4c8b74` | 5452 | `guide/guide.css` |
| `f197dab5106e1d38c1b6d1fce942128ff0c85e55af3535522aca8cb7cbeadcf7` | 4605 | `guide/hi/index.html` |
| `f37956087474b075ef39dc3a60a1f474ea6e228f4168698bddd4813543246628` | 19767 | `guide/hi/security-glossary.html` |
| `f8ae9edc5039f414fc20950116f81e684743c561632bf5c13f5044b027525352` | 14113 | `guide/hi/yubikey-arpass.html` |
| `df1717c8d3b58ed8237ac74e74a632c73eaca39d6157223fd8ea76aaac0c0371` | 14580 | `guide/hi/yubikey-guide.html` |
| `78919e8f3fc655caeadde998d3bf3e5be8930cc481cb21859cecce43c4047059` | 10556 | `guide/hi/yubikey-price.html` |
| `62e00a2d58b9b95cbafed3eadc6a4ac6c2773ce094c6a14df6eed6b91cca695a` | 13768 | `guide/hi/yubikey-vs-passkey.html` |
| `d44a0157d160d55bf54f657631f62d637a6d1008bc464896a1998b379837b863` | 3207 | `guide/id/index.html` |
| `2261140218a730eedb47ef165f0bce1322bbe428a0d85192879657b72c2a4df5` | 9927 | `guide/id/security-glossary.html` |
| `e4ebde167cf7cf88fe22a382a7f75df492b77a5f16a052c6ced149418982e9e8` | 7840 | `guide/id/yubikey-arpass.html` |
| `2e42f44f9b842935b3b8982a5b5239a723bee46f46c8b904116413c05fc456e9` | 9073 | `guide/id/yubikey-guide.html` |
| `bbca9aef3916a718a3c57fb75c34ff022062b94faa35c92784c32c44bea8b615` | 6752 | `guide/id/yubikey-price.html` |
| `27a90c245326d64435c54d35146c93cbb466ad1e94957350f4388efc33a400c7` | 7995 | `guide/id/yubikey-vs-passkey.html` |
| `9119fe1f7b1bce56003d5d0dee27b683215e616051e55a1f044c3a21c6323edb` | 4365 | `guide/index.html` |
| `129eae3782ae0da251ca5f09c0cbe4197e157af4460fab53151919e752976d94` | 3225 | `guide/it/index.html` |
| `6ab0c319ce48cfd247d5474efcbfd05589c241d3724f43cfcf28ea448ca132f7` | 10103 | `guide/it/security-glossary.html` |
| `5df7ca28ce56f530a310dc902f523cd0cf8c60b27c2f928b4077e520c7305784` | 8054 | `guide/it/yubikey-arpass.html` |
| `80137fd0d833188c09269bf079353ec4746c870b5898a90a4c0e224e515daf70` | 9384 | `guide/it/yubikey-guide.html` |
| `6ab081274d3aba092ac4ecd605d33687c20fa312f40b54c7f53287078aaf916b` | 7035 | `guide/it/yubikey-price.html` |
| `95acec70b323e375614032c3d2f4c89ab07c699b3692f9614c10330c2a2b3977` | 8381 | `guide/it/yubikey-vs-passkey.html` |
| `07113d47c145cc94f931ee7760431231165c9e00d26f1ca4cda42d2548c04cb6` | 3231 | `guide/ko/index.html` |
| `cb6f94bd5483c656162bc7fbc83c3ed8af3b1a7b1b277819a0138ef75efb6834` | 10049 | `guide/ko/security-glossary.html` |
| `1b419cdf2338e6914e68ab7cff5f2f2bc303c893cb981ef7b47ccc4654f2cb4e` | 8304 | `guide/ko/yubikey-arpass.html` |
| `9f0a0b2e7a79422729a147cd77e3138ca12cb07826d6ee9ad687fbc82d27bf80` | 9663 | `guide/ko/yubikey-guide.html` |
| `bb0a3f61a28d7ca10ba68c7294bc11c200b4bacff9c727a941e726780f77f2a6` | 7171 | `guide/ko/yubikey-price.html` |
| `923eb620dec198715522a5a7bec67e96f1a46b221411c4c90e46e5d806c914a5` | 8480 | `guide/ko/yubikey-vs-passkey.html` |
| `0ea0998a50c7efb955e58b99dc9731d61424c15478867756b9c02a94938df5ce` | 3306 | `guide/pt-BR/index.html` |
| `a491e1ef9ae8ae073854e9bf24c8e87d2fe6b1c021222effd7128c121814ddce` | 10320 | `guide/pt-BR/security-glossary.html` |
| `81a65f7816c20045f852a0b979724be13d658438b500b184399746b31b5ba809` | 8107 | `guide/pt-BR/yubikey-arpass.html` |
| `21af5e7096fdb09f4ea6a2699000263ffb81c4d74ba385f291ceda0f987a0efc` | 9538 | `guide/pt-BR/yubikey-guide.html` |
| `94846490add371fd155bc2ece0db5a079a43bea263c8bc91a777a2a0efe7914e` | 7146 | `guide/pt-BR/yubikey-price.html` |
| `74d8d715c23d4e08b36441951582ea6933942824662178085e34d344a33847b5` | 8382 | `guide/pt-BR/yubikey-vs-passkey.html` |
| `d324b399eb736469c4fc5526836fd848fd5b4aae9bf28ef8135e3e876ec8a213` | 4080 | `guide/ru/index.html` |
| `458e904e575c1d4ed2c6a927a15ed0ee7b5ba5ea3b5616b6811b08fafe233155` | 15135 | `guide/ru/security-glossary.html` |
| `6c48f002adee17ecfb77bb0e258af1c2e0d011c6bf72cae54d2806c725d0fbe0` | 11592 | `guide/ru/yubikey-arpass.html` |
| `c1cc6816d38029c44e14a2f438ac498094f7e8def62cae5da006d47ce999d584` | 12410 | `guide/ru/yubikey-guide.html` |
| `3babd187f6bc0d9ec99824a4bf31b1cd3b4314a82b42caa48ebbed559e06e78a` | 8889 | `guide/ru/yubikey-price.html` |
| `a57276185faf21a0b9ac8879b972e806598a583fdcd66607e4cf3355203e122a` | 11273 | `guide/ru/yubikey-vs-passkey.html` |
| `19c46138b2f7fa2c5798f26927e607c67d13462ab2f9e64112a6cf7d3470e83f` | 11734 | `guide/security-glossary.html` |
| `ad8582a06a77a87b82e5b29d5bb53726608d2818997e74502bfba313bb64fcab` | 3285 | `guide/tr/index.html` |
| `f70507d646a76f49a01718765f1357c91b60209cfd37211480d6b3cae7bfc8f3` | 10452 | `guide/tr/security-glossary.html` |
| `bcc5e8c051307bbcaafc0ca56184d0cabb1e48d131f60691192d345b27d72514` | 8031 | `guide/tr/yubikey-arpass.html` |
| `40895a54ad24c23f0160a4f145647ce8399887ea57ddbe2e7eda2275facd1c22` | 9286 | `guide/tr/yubikey-guide.html` |
| `9607289c5bb9644b6390c273d74c76a6aa181ea0a0a7f86d15a98197efa08232` | 6846 | `guide/tr/yubikey-price.html` |
| `7c5857e05d7f2b6f240a742cd86396850e3d1ce3bb6e795dca2f23a38498e63b` | 8150 | `guide/tr/yubikey-vs-passkey.html` |
| `2626c536ddf9315e5c67c88859b5b7bb329f9bfc3c6c87f1908eb83ff9b41b9e` | 3568 | `guide/vi/index.html` |
| `2cd3a67a1b1fa3d701f8a7807bfd3ab8e6ef9fdc85762b4e5ab4cca30a5a68db` | 11189 | `guide/vi/security-glossary.html` |
| `7eb8f9bbd94cb29adb9e971a23bbb2d460be9e4d663571851a0e4a8baba2ddab` | 8884 | `guide/vi/yubikey-arpass.html` |
| `3af05bd3f0b5baf9e56321cfb1ebbfaddae85d88b36a330aad4773426b2c24ce` | 10078 | `guide/vi/yubikey-guide.html` |
| `6c9f16d19fa4e225e50a4c4d723c3a2a27afac627e12c85ed563dd0f703494d1` | 7387 | `guide/vi/yubikey-price.html` |
| `4fd05111cce12df4c4010d7049ac484647123ee4b791096920c33f0cf60dbba2` | 9050 | `guide/vi/yubikey-vs-passkey.html` |
| `ea142ce66bb5e8d8d27e7d897d65f2324770272d59de50793c9b5019a25666ea` | 9438 | `guide/yubikey-arpass.html` |
| `9d48551e50fd9b5327ae8b07a9213927f0c4b5675a968cdc68ad845adff477c8` | 10779 | `guide/yubikey-guide.html` |
| `f7bef11ebf3762821fbd03a6d2914d31b181fcda6c1783fed65b0095eb14fddb` | 7990 | `guide/yubikey-price.html` |
| `b38df1467c3acca31f12cc286d87de636ecefa9c6f22b179c9b24be557351ed7` | 9263 | `guide/yubikey-vs-passkey.html` |
| `a840cc277dde330193276fdd10c4857d97bf625abccd907d24b9d3fa6420bcbe` | 3145 | `guide/zh-CN/index.html` |
| `38b608231730c4baa126a65f9706ded870f4839c52220ffa4ee789b15194e4a9` | 8785 | `guide/zh-CN/security-glossary.html` |
| `9b335db7de20b85aca785dd31670cd010744b22c40eb870b839c317c1ce1bf78` | 7316 | `guide/zh-CN/yubikey-arpass.html` |
| `38dd931e3e995551bcaae7f8f6718fb616882bdf7bb3df58af420682299a680b` | 8939 | `guide/zh-CN/yubikey-guide.html` |
| `2d6ea47e607f22c9c08d4cddb7e5fbad1866d75722ea7b39aca26ce4a5098f52` | 6592 | `guide/zh-CN/yubikey-price.html` |
| `2a189873eb42721162f5252fa53452c6c7c9021769675d40b98b296fe40eccf5` | 7443 | `guide/zh-CN/yubikey-vs-passkey.html` |
| `ace2adce591906f8a8311b9c6ea45998e8041bb66b170b121394904c35aa3f26` | 3127 | `guide/zh-TW/index.html` |
| `01bf76891574bfbb80f97973442e7b88890492268acaa725050b7e46d09aee8a` | 8940 | `guide/zh-TW/security-glossary.html` |
| `b813ee4bd78ebc7668515124a59a2127c454a4cf44fdea8cae1e29757d9d2d2d` | 7317 | `guide/zh-TW/yubikey-arpass.html` |
| `e8e7685b16bbcf1a456626326bd249dfceb71d3e4141d4d3c8fd3759477447e2` | 8893 | `guide/zh-TW/yubikey-guide.html` |
| `e9ce1291e6ebf0e8514ea9fc36d79c6c63a1c33a55407d4dcca16d80fa8b412d` | 6605 | `guide/zh-TW/yubikey-price.html` |
| `035350732aaa18939e0edce26c3167e03fac7b01afdef5d1e08dc974cbe89e90` | 7469 | `guide/zh-TW/yubikey-vs-passkey.html` |
| `a31de5c8a9fd4d3b2c3a81f141e0c824a4bdd940799a222c081c836ab3dc031f` | 46354 | `help.html` |
| `3a51f70098bf8f756c4e87cce6f592b3bf1bb1f918de61a6830f4629604b1af7` | 60331 | `hi/help.html` |
| `125986a807ff15b80ba2b7a341154401130a0f755d2f351ca5bba7ad7da67c4e` | 112283 | `hi/index.html` |
| `cee520e6ab6d4f002415c679c634d2dd24db7cfba847224c2f1420bc165abc08` | 217192 | `i18n/ar.json` |
| `6fe8fd3dd5c1715b8993865c699c7fde0c33d414a295dcb1d3d417efde03f406` | 187620 | `i18n/de.json` |
| `1424869fe9d6277665a5f333eeee3ca694f4690e356c8b0a9eaceb1da44244ec` | 168192 | `i18n/en.json` |
| `d9be8cee9c01d61593ac311a3abe24a42ae2fc8d8be001fc7041055dc103f859` | 182775 | `i18n/es.json` |
| `af37e69444fe49fb960a3d37798bbc513384ebc096cdea1825d41c10c6efc5f4` | 189079 | `i18n/fr.json` |
| `883564b0f759ff796f3b859a1030a4da07766f4740716f33942edc96ebad59c3` | 290517 | `i18n/hi.json` |
| `37c7e616d55422c4b465ba45b96a1a6d55852e3ee8a538bb67ebc5ecd0a11e34` | 173772 | `i18n/id.json` |
| `7ae8fb131182a8cfd8dfc395e41da5bd5d96ea700ebcab39da44215193ebf026` | 179994 | `i18n/it.json` |
| `fef4d920803b8e4dbba839cc22fe4d0f78b5fa1c3db93373e565452687ef8a72` | 200319 | `i18n/ja.json` |
| `b75b744bf98e04df691455ecad8a81bb3398b3196512a4576fe42314058c8703` | 186507 | `i18n/ko.json` |
| `ed973130e657f5456d24ea06da493c39d0cd6df556a220b07023d637a475458b` | 180017 | `i18n/pt-BR.json` |
| `1ac7e524599d01e0150eb208a6ec9aff1c88f78c12df1119fab8e63dfa779579` | 5733 | `i18n/README.md` |
| `9a2516f71321d1c87dea95195b33669c0cbfc6c16b5caecd8b802993d2dfe3ec` | 253345 | `i18n/ru.json` |
| `3ad5777a46131ffd5926c8148d77bb2e436d9e4fac9973900cb433290189ce23` | 179618 | `i18n/tr.json` |
| `a4329da71b1960b086d1b99d5ca9aedb7831123468abafdb59d42581f74e2f61` | 193455 | `i18n/vi.json` |
| `0c750caf52f4b4efc3e2d1661744dec5c1062a6bcc8a93b6d934855708ffc2db` | 160786 | `i18n/zh-CN.json` |
| `6ce41ac2c095f9ce7bc25f2000a86f31e65e15c82c46c81dcb239722d0790170` | 160887 | `i18n/zh-TW.json` |
| `aea87aec25c4698322f5a7ca7f43ca2070244ddddcc4c1ba3294de9d0635a183` | 356859 | `icon-1024.png` |
| `97e38260b98141784e8a5a21971c0f97073a5805eedfb7c78affa5dd27ae1ee5` | 23939 | `icon-192.png` |
| `5136b72cc1f12355947aacf4fd7a9d98fceae3ba5209210be5826b5399c5b2dd` | 122358 | `icon-512.png` |
| `7311900454c3565c8276737e129cdf2ddfde8b24b9cfbdbe986a17dc44d3f920` | 609 | `icon.svg` |
| `8d290e07dc72555f71eea5d7a62a530af14d2b489a0dbdb1c49e2338c4cee6fe` | 41125 | `id/help.html` |
| `89f8a8a22c564a87770556eb9544d52ec9da5904d4cec63ce382581cae0c88fc` | 83214 | `id/index.html` |
| `c0feae88337f9f80b9b89791f548eb09d02f6e6cd8f135b9b6ec88b2d5b6eea4` | 90113 | `index.html` |
| `ec48567949e07d918a8b48dcc7eaedcf6677549068e6bef2027a3868221970c6` | 42417 | `it/help.html` |
| `9979faa0dc74987ca4855df4262dda1370f0c959e9c250d4e9f5ccf6c9ce3eaf` | 84345 | `it/index.html` |
| `583e39c7920ac461a3fee812abc20802598f87636e39c8af63e64d0d75b00e77` | 43909 | `ko/help.html` |
| `e3bd829c1a7502efc30952271f68dcdbc314b8a5c972f3f3105f3beb8d9f0e4f` | 85402 | `ko/index.html` |
| `f00aa9d80cbc5664c68c0c182a31d5852aa78d02a2ba8136e1243957f0a7d973` | 413273 | `lib/app-main.js` |
| `776e3254f21a5a1ddcd6730a6a586a507317071ee69e896e8d6c313c8fe99db2` | 44749 | `lib/client-auth.js` |
| `9a1f8d6a7d3c7cd46679fa04f2af4219fa5a3c4c5bb6f140a03eb45d04e6ebe4` | 19883 | `lib/emergency-restore-main.js` |
| `928ee43fb3d1aa1ed8ff3df21efc3ffb0983c535277a47df681303fbfef91033` | 644 | `lib/help-main.js` |
| `912ad9c9c45493c90658960fc158f9ce4992434789ab84ea76f687966c2e4b23` | 17230 | `lib/i18n.js` |
| `ea255434dfdb2c5365493abe25715164300b0883c64b81601ef292588ce2a2f6` | 5748 | `lib/idb-cache.js` |
| `2d299d83fcf0c8ba16df3a797d02a5fba286fd7066ea10a844f345b41ccb8312` | 5754 | `lib/image-compress.js` |
| `5424f6e36f8e26b0398ff983ee06900029950ca71bf0172703ffdd78b5fe976b` | 2008 | `lib/index-main.js` |
| `d1a16bde114faddd1a81827dfee00545a02d05385074a32ed7b47394cc2fc36a` | 10097 | `lib/local-cache.js` |
| `08f6235eee2b83d01cc9e419fb644d8ce7710ded5d21d210e802c7c3f3e4898b` | 12565 | `lib/ocr-vision.js` |
| `23b9c7faa3d5191064bd54d9dbbae95713bba72f3d76ac4d517acf08725091be` | 659 | `lib/pay-cancel-main.js` |
| `9519cbb27cabcb782db0bbaf5c73ae04133d2871cd47289ecdb9807d7ef851fa` | 1087 | `lib/pay-success-main.js` |
| `890960c51e5a485fe4c1ba9f6b0b2dcbd93f8e162e64e9ce8575be2269f8ea71` | 3634 | `lib/pdf-to-image.js` |
| `a742e878779649e6f71fde216b3870b018211091da23d7ab39e2efe206b25301` | 7421 | `lib/pricing-main.js` |
| `5ef6de241c86bdb9ec03129add6101fa613ad2d66f5dac08a17494581093efb4` | 5923 | `lib/profiles.js` |
| `6b9d08f4238b267c159c8ce1da1e9da18abdb8892db1b70e4c95da2d98f0aafa` | 9112 | `lib/pwa-install.js` |
| `10f0a55e3cbea59890d8fad01959056e80643ad31ae8fbf65b5e12c5f7152a07` | 9127 | `lib/qr.js` |
| `0b10245be4c9eb6c964dd333f23d9c2c6f0978baf37982e10182fca73e401673` | 10551 | `lib/save-debounce.js` |
| `f3bd4764af87af155e7b54996233026d2adbc5b8096dc4872c308bb4fe17ecbd` | 663 | `lib/security-main.js` |
| `bfaf7e76c1f784e93a89b1c9dc736fb8671727d9391ec352855f5ff4ed12de2b` | 219787 | `lib/vault-client.js` |
| `31123a489d42ef1058f784392c27b17aad7d839e21e954e2704a7af1167755d8` | 125532 | `lib/vault-crypto.js` |
| `bc40c8a15196236b2314db0856f72ca0b49980cd5413b8c852a7349f5fee0859` | 256885 | `lib/vendor/jsqr.js` |
| `c6596eb7be8581c18be736c846fb9173b69eccf6ef94c5135893ec56bd92ba08` | 11358 | `lib/vendor/LICENSE-jsqr` |
| `c518e8e7d6fd6add47849fe528790af26533102d1ac898882dc1df49a76f6678` | 1915 | `lib/vendor/LICENSE-noble` |
| `640b215ddbf52e1b9f698d24f645e11db72ec64573d4dba0695af8be3783f3f5` | 107010 | `lib/vendor/noble-curves-and-hashes.mjs` |
| `0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594` | 10174 | `lib/vendor/pdfjs/LICENSE` |
| `27fc2a057a00f92a4334ad06e17dbd7259912954e9fb7f76400bcca5fd190a9c` | 352645 | `lib/vendor/pdfjs/pdf.min.mjs` |
| `1baa1844c89c80a5b2797c916e75ab29254be46d8e9cb53cb6364d7aad84be36` | 1375838 | `lib/vendor/pdfjs/pdf.worker.min.mjs` |
| `18d12d607bda7ac5cc673ab515c2ed1a706483bfbcac7b20273f93368a6db62b` | 20 | `lib/vendor/pdfjs/VERSION.txt` |
| `ea91d7118a5395289170da848b7c6758b996163bfbccf312591ab65a4911b7c0` | 51907 | `lib/vendor/qrcode-generator.mjs` |
| `b69a59d3b42af0c03e8951a872c2085b23fcf76728a9f1b21c50b595a1f43ceb` | 805 | `manifest.webmanifest` |
| `9822e3ab29bee4f1690c49157ce2e66c2f652ad43404abb07b4cea32ccc8a24a` | 83577 | `og-card.png` |
| `d50644fdadf579b7ad19453e151ff4a4e2e19c634fbefc0486948657ea08b0b6` | 1782 | `pay-cancel.html` |
| `79a249c448d90e12fa11a0a545946cd18fedc649fd67b0519ad440fa3b45a80a` | 2493 | `pay-success.html` |
| `9f938765abf8ce554b8bac4956df29781a66ebe3bf58074f59a98d48f11e4cdc` | 8645 | `pricing.html` |
| `e1ad706e32aeae6a1b4b4bc6e9127732c902f5fb207d24d8dff4fccd1944ca04` | 22993 | `privacy.html` |
| `b8762831e7e97b0bf69c79eb64c33082d67d6334a482753cc615d3a610ab8c14` | 42813 | `pt-BR/help.html` |
| `1d3c3952afff113530817454d497dbc605fd7c5edbff6971134891614059b53f` | 84242 | `pt-BR/index.html` |
| `0b95164f3e0a89a1885ffeea7c5556a9730d364048a397e8e5585978c74dde7d` | 328 | `robots.txt` |
| `2e3832c6e0ab75957c50a0cf5b6ea00ffdfa6b71e641edda15eb1440c63014af` | 58975 | `ru/help.html` |
| `3ac5ae6053690faa30b5d43213974d1d18d4bcf017e58069f2944a1dbc44e105` | 100393 | `ru/index.html` |
| `8189db2e8a399a2c4ed5571c885c9dfb76b2b55dc87a8e3b812e7030c83939cf` | 25076 | `security.html` |
| `5934c6aa8b2698729a13d82310771d8ec74c9a1fec9ccaef116c8e9cd747357b` | 234812 | `sitemap.xml` |
| `e484c2c99400fd064c40bbacb7802521a749943954d3e101ee61e3a67c3dd258` | 6838 | `sw.js` |
| `811af38d946be27c0f5126ad73195045e6ea3b81be9da496bde4018bef5f57c0` | 17797 | `terms.html` |
| `3f2c122c70a90acf1ff46a2e88a1874038d250f924bf5f00abd419f67f65b9dc` | 12478 | `tokushoho.html` |
| `5d1a3994dc32b345360911d407267b8da796fa4fb0f374e3ede7c0adf77b604b` | 42892 | `tr/help.html` |
| `cc19d71742bfc8b6db5e0528ee7d1fa474d4fe3d9ba4bcb2ac48f099077722f4` | 84174 | `tr/index.html` |
| `d11215a42b64441b53aabd804e6613981a2a19cd922afa94f1b655221682dab4` | 44871 | `vi/help.html` |
| `675d796f54ebcb2c99f44e94dcda252832ba21899f60ec9723f7024a4c52153a` | 88409 | `vi/index.html` |
| `dd5a6600ee5b510006760ee8f33f3ce8886c037cb1e6b8a4c35bd543aa9f5267` | 39189 | `zh-CN/help.html` |
| `6434dbed23f8e00f53549e43c8db5adeac63eabaccbe46911660949997daf7a5` | 79988 | `zh-CN/index.html` |
| `3ca7e2ac780aded56a7a7017f2e91307f86383cfdb6eb2d221f4665ade7eb149` | 39020 | `zh-TW/help.html` |
| `d686a94633c821100222313918879f5643ca0f4e29be251105eb5c195a3b846f` | 80038 | `zh-TW/index.html` |
