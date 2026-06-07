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

**Generated**: 2026-06-07T01:58:33.931Z
**Files**: 204

| SHA-256 | Bytes | Path |
|---|---|---|
| `03453e1ee53652ca807da1b07587c599bedcd8d73d7008a458e3ac5062514f1d` | 12218 | `_headers` |
| `f90724367930c1e805dde0702768b28293d9cbd899a076bdcea8456bf0d2afc4` | 321 | `.well-known/assetlinks.json` |
| `7bb2417062ae1f06c8d75c22489f4e1c7e22d970057ea7f0825825561e57c2fd` | 160467 | `app.html` |
| `0040923fd145a61649ecb6c59df0b81dbe75125c6d41368e194f49e9844298a6` | 53717 | `ar/help.html` |
| `6d9b5dd81675ca0d8083ae22d4d4b6d2d0a0838ef22e3eeccc020ecaf7496805` | 93160 | `ar/index.html` |
| `6d1faa0183fd0a04a14feed4b4a836af5af262cb842e15c48e702a604a787814` | 10228 | `arpass-emergency-restore.html` |
| `1e852fb57a76a006193b3009c92f6b48d242ef50698f0ec217d336436c12e32e` | 66067 | `arpass-image.png` |
| `578c43b2fcee11a4ea1ddc8f3ff0b3c19cb77d819f8eb49a271a5ab42d0bf80e` | 58254 | `arpass-image.webp` |
| `5dc667475d2b23bc065edc6f068aaa5591d4e20e3b63349fa3538ce66bc04e26` | 48632 | `de/help.html` |
| `58f4fce1f84c851cf391331c7553e850638c1dde193ba78b1b5fe4615edf94b8` | 86065 | `de/index.html` |
| `bc82a12352c1b3715dfcdceba353147fd7c511d355d27b0c9d464b4497ea3d3e` | 43286 | `en/help.html` |
| `cf8cec5950be39d6e632ad316cd6eb90599fd61411677637394bf95bb72aeb4c` | 83334 | `en/index.html` |
| `c1446584b638f4874af97693f0f5aa212263ea623e65fe33de2e2273440edbba` | 46970 | `es/help.html` |
| `82815e5ce2ca8b9d156b2bd44bfc16fa92e74e1dc487dd31eb6ae8bec99712e2` | 85392 | `es/index.html` |
| `ebaa0b820a097106fe6cefd3c56b46187d051f7ddc13efbc75ba7dc781b988df` | 625 | `favicon-16.png` |
| `bb52ebe86d04fca009d38d88da2366f3e3eba013b926c0c6f9b8fa5094471a03` | 1637 | `favicon-32.png` |
| `c52ba1a98f447fb79168d3b5b6c60f2f892056fe02897eb207808e8ff0b3c240` | 15342 | `favicon.ico` |
| `8f136945e5dde8af7743bd22fdc19642efa990b873e53714c88aeeb3cf406437` | 48369 | `fr/help.html` |
| `911870480b524fc849f21fd25f8bf44b9bd6a045f2209fe092d0e69d756e165a` | 86983 | `fr/index.html` |
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
| `c740b3d5c4416f38dfaf628cf9744b9669254fa290f98807886bdf8fb6b5f7e6` | 52524 | `help.html` |
| `f382f318f70b51cb7289ec933d381197789d57708694e3be26e9e12e88312ea7` | 63391 | `hi/help.html` |
| `b22369f7cdf81b5edd5fcc8eadfc7eedcdde70446ee92efba4b03d2b2de4f55e` | 112994 | `hi/index.html` |
| `294b0642b464fdfe70b19bc2e4b23151c9f6c94f938704c6db5e763fd69dcb2f` | 226322 | `i18n/ar.json` |
| `83815c0c81d5443b40ddd91d236307e579235bef36f51c3a141a9d1f890a58c1` | 196145 | `i18n/de.json` |
| `4e82a9593eafd0f449195c6c43d285ea97620d58a540f2f083c59e27989bb499` | 176405 | `i18n/en.json` |
| `353a3c1265ef9e1c900602910a536ce575de4b44e0fa682855e511fb5c7e5f75` | 191423 | `i18n/es.json` |
| `cf6c8127ff55295287e590dc18f3a64d4dfb78acab686835ac3f82c36c8065a9` | 197853 | `i18n/fr.json` |
| `be56830630b4dc5ec8a17e064e95e63e284329d1a70e017025a988df4af9f98b` | 301165 | `i18n/hi.json` |
| `9d0080baf52f1e731883bdbf58ac6c021316f5fba589b326ff42e953985eaa04` | 182197 | `i18n/id.json` |
| `ad91ab515a812de492bd552b93087e76d5f202538449c831daad4b50fec96721` | 188670 | `i18n/it.json` |
| `1c0ab8d726e7624bf7bee79c95e6d2c92d7688dbb46bf77eabe4b902d7bd5689` | 210528 | `i18n/ja.json` |
| `f6928473354e537fea08db8d210a5025f572df39356f6fc338f22a1947cf642e` | 195268 | `i18n/ko.json` |
| `8b0174e7c625502182cc954bf64fd3c9fbf01c52d1e0bcb2369fd09f64b05241` | 188732 | `i18n/pt-BR.json` |
| `1ac7e524599d01e0150eb208a6ec9aff1c88f78c12df1119fab8e63dfa779579` | 5733 | `i18n/README.md` |
| `f42a1d3821c0d13bb21ca7a167277f4fd2788512817f5218c6f8e6409d7f870d` | 262751 | `i18n/ru.json` |
| `3575031685dca28ea040493cd845a346d1c1c7645e9e10bd0df36dde5fb29138` | 188418 | `i18n/tr.json` |
| `99223c74693f62e4db8c9fd8dfecfaf5a2393c04caa73f81ce6ce9c069699d82` | 202047 | `i18n/vi.json` |
| `78a150089a92d1d3dde40131bc6fbb6d024b244d248a7828f6d6644c865293ab` | 169409 | `i18n/zh-CN.json` |
| `d700682aa46e38f0cbacad438242327372783091ece29cf51ea2ebb16e9ff97b` | 169513 | `i18n/zh-TW.json` |
| `aea87aec25c4698322f5a7ca7f43ca2070244ddddcc4c1ba3294de9d0635a183` | 356859 | `icon-1024.png` |
| `97e38260b98141784e8a5a21971c0f97073a5805eedfb7c78affa5dd27ae1ee5` | 23939 | `icon-192.png` |
| `5136b72cc1f12355947aacf4fd7a9d98fceae3ba5209210be5826b5399c5b2dd` | 122358 | `icon-512.png` |
| `7311900454c3565c8276737e129cdf2ddfde8b24b9cfbdbe986a17dc44d3f920` | 609 | `icon.svg` |
| `f208b60c354bf9f8c8052a6241a3ff1159dc836fc68c402b5db99f978ebcc869` | 44713 | `id/help.html` |
| `657675f40722e1b3a1637dfbfc4b8942bb1f00a3fd8d2a2baf16805197e720f2` | 83758 | `id/index.html` |
| `617c61a0b52f1372aaa0a41e89d4ff6b475c3c2fee7a977851b617f5fb891a44` | 90569 | `index.html` |
| `4a1a501a5d52abb4f0c433bcc02d4ad4940b4a260bb3049a0a33878e59a9b8c7` | 45986 | `it/help.html` |
| `8bd3ae77ea811fba1de73c97dc1f8d46cc89e8f4193ebeb68085564d5a18162d` | 84905 | `it/index.html` |
| `facf27c6708ae0dfac20cd7616783ad7cfc0bf551a9764cf7a0c48f198f11eea` | 47387 | `ko/help.html` |
| `c0c29c7d065c7bdfede05ad5f7289a4fa5769a2f9d9e3d16a3ead80ded45ba56` | 86206 | `ko/index.html` |
| `d9836877557d83d93d8e1924a20ed8b354fd81571f3cfb40f7e0a29e28d0d681` | 428519 | `lib/app-main.js` |
| `3f7b48ec060e8104b774090a9c10d61bb4a02d5843573c387ca6a21b61a89ef7` | 46445 | `lib/client-auth.js` |
| `0850c462f8032b84cd6eebb9aab0fc7bcfce88983b15bb6effdbab403f90e6e2` | 19883 | `lib/emergency-restore-main.js` |
| `b70c5332ebcc7b662cad84db49a036c6dac78fe55223fad40d11030e7271d5fd` | 644 | `lib/help-main.js` |
| `409d637c33f55d65cd19ed4484116289c0e711175686fa0c87fe50edf5c3d099` | 17483 | `lib/i18n.js` |
| `ea255434dfdb2c5365493abe25715164300b0883c64b81601ef292588ce2a2f6` | 5748 | `lib/idb-cache.js` |
| `2d299d83fcf0c8ba16df3a797d02a5fba286fd7066ea10a844f345b41ccb8312` | 5754 | `lib/image-compress.js` |
| `734a7784335b690cbd747f1cafc0834ded9a4cfcabc2ce4a8e2e687064c9dbba` | 2189 | `lib/index-main.js` |
| `d1a16bde114faddd1a81827dfee00545a02d05385074a32ed7b47394cc2fc36a` | 10097 | `lib/local-cache.js` |
| `e4fbb0a9d8de10d063ede9d774242881b75a322c51c47adbc775f9674d86e7c6` | 7126 | `lib/lp-pricing.js` |
| `08f6235eee2b83d01cc9e419fb644d8ce7710ded5d21d210e802c7c3f3e4898b` | 12565 | `lib/ocr-vision.js` |
| `c7a41aa1ccd74fb814ee4cf79414e57e6c1f58281183b59d35cf7519d3d2f8b5` | 659 | `lib/pay-cancel-main.js` |
| `fd3393f258f93d7a33ee0299327ef1f1777bcf1cd5c190098a3f27cfb6685195` | 1087 | `lib/pay-success-main.js` |
| `890960c51e5a485fe4c1ba9f6b0b2dcbd93f8e162e64e9ce8575be2269f8ea71` | 3634 | `lib/pdf-to-image.js` |
| `9eeb2dae06750bb0c57eece7eef8eaf2b71e51bea1ffb8e8f4a9d22f38833ba0` | 7477 | `lib/pricing-main.js` |
| `5ef6de241c86bdb9ec03129add6101fa613ad2d66f5dac08a17494581093efb4` | 5923 | `lib/profiles.js` |
| `6b9d08f4238b267c159c8ce1da1e9da18abdb8892db1b70e4c95da2d98f0aafa` | 9112 | `lib/pwa-install.js` |
| `89be3e9f146de5dee22b08a84fe7764f651fccd797ceb47c70d1aaee2ffd7b22` | 11808 | `lib/qr.js` |
| `6821ac53f8ed4ca7c7107fd50863cc478bacfe72cbc2f383fed0cd3bed4b12a7` | 159671 | `lib/rust-crypto/arpass_crypto_bg.wasm` |
| `6aa89037d34827cada9daf74bf78b6ac88d6a000efa324e6be032f4a5462c188` | 73436 | `lib/rust-crypto/arpass_crypto.js` |
| `0b10245be4c9eb6c964dd333f23d9c2c6f0978baf37982e10182fca73e401673` | 10551 | `lib/save-debounce.js` |
| `7f4d0f676453e68f9954be5ef1728871da5c4faa2f8a00ab34f56039f3aad399` | 663 | `lib/security-main.js` |
| `b2442b6ecb372e504974f3f7cdc696e5143861945799aecfaf677b9ebf8b72ed` | 234174 | `lib/vault-client.js` |
| `7b09ae9b94ca6071a2b45fea6816ce90f83d3bfc6eb3e10c03f55bdccf6f3c26` | 151476 | `lib/vault-crypto.js` |
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
| `8d343685065105b53e56fc0a9fc0fa8acdd3e8338e415774efe3a196547b9a45` | 1782 | `pay-cancel.html` |
| `bedfa7b0a30c79cb9d1381e2547a0c747fa6172026cde9ea6344a3a51127028b` | 2493 | `pay-success.html` |
| `532601f53ea269afa6dfb769b472799004dc228258350c5c05a6244467d370b4` | 8645 | `pricing.html` |
| `e1ad706e32aeae6a1b4b4bc6e9127732c902f5fb207d24d8dff4fccd1944ca04` | 22993 | `privacy.html` |
| `3605066e7190ba9382fcc57dfcb2c0476919d9d29ca8ffb4ea0a255edea9dac7` | 46341 | `pt-BR/help.html` |
| `3e6e1dff9db38329eff28cffb729373061afabe07cfc4fc85e84e44f434d84ba` | 84864 | `pt-BR/index.html` |
| `0b95164f3e0a89a1885ffeea7c5556a9730d364048a397e8e5585978c74dde7d` | 328 | `robots.txt` |
| `c65ddb19775e439c1c500a94d856a1d5935423a6a13191423c080545bae79dae` | 61783 | `ru/help.html` |
| `84f396976729bf00624cfa0543943519d520b6d0ab3257ade33b032b7d9c9c24` | 101019 | `ru/index.html` |
| `57f833398642d569474dec4ba85058a6cd72e124927a16af643709bd951bf976` | 25076 | `security.html` |
| `5934c6aa8b2698729a13d82310771d8ec74c9a1fec9ccaef116c8e9cd747357b` | 234812 | `sitemap.xml` |
| `32b895be53b5d97c3958769f3d3ed428906c5884a9e8671437b45153e8eb7285` | 6838 | `sw.js` |
| `811af38d946be27c0f5126ad73195045e6ea3b81be9da496bde4018bef5f57c0` | 17797 | `terms.html` |
| `3f2c122c70a90acf1ff46a2e88a1874038d250f924bf5f00abd419f67f65b9dc` | 12478 | `tokushoho.html` |
| `8d2f9e3eff36c5d2cff4f96ba6fdb20cebd8bb2686a8f0bf01edde1107c0c0c3` | 46417 | `tr/help.html` |
| `046c9b2a36ebdbe893bc42149e494f5b47fd8d116c567a6ed859f8fc98cf728c` | 84880 | `tr/index.html` |
| `ead5013a7f631a1d5f4b33f89191d9757a9d94560f9164466855ba0280a5e1e9` | 48368 | `vi/help.html` |
| `7317be021eca5487e1d8c19faf943f83dff8fbee4f686909174265f59aae8b00` | 88969 | `vi/index.html` |
| `0fbb1660ccbe53ac8af57f81d4af6cde1c34744274288b37b47aa8d89fbd27ac` | 42879 | `zh-CN/help.html` |
| `90f06d3d2a43439d2f321cab1e865680fe99b008f0692b9b359187d7c4b11d0b` | 80749 | `zh-CN/index.html` |
| `810c0a1ec78a81b3cd2983aae2ad6414e2fa426fab5e181cb6e19c07e9b70a3e` | 42737 | `zh-TW/help.html` |
| `11bbd157df402002427fbaa41f41a37f4a0a4fa93fe9910446d4010e818cb5a9` | 80802 | `zh-TW/index.html` |
