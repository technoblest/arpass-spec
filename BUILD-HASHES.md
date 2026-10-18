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

**Generated**: 2026-09-17T16:49:51.362Z
**Files**: 237

| SHA-256 | Bytes | Path |
|---|---|---|
| `53f3d8402e3f5e7bc465c45febfe59701879c66f22afec421f9939c07c4c5b29` | 14019 | `_headers` |
| `322bb043cefecf44444d22ece3c08932f9b7af3f5e5a72321867df46770262c9` | 124 | `.well-known/apple-app-site-association` |
| `3f8beb570b36974b4562f475aa49a29b5b3525faaa65961358d16fd790eb7a9c` | 881 | `.well-known/assetlinks.json` |
| `978fa78812d00a1b16159a21658da01a4a701454a4028089b2fd2ca3a7254582` | 505 | `.well-known/security.txt` |
| `a768cd9b9f2d8b7b364cddb7afd570469aec557ed2ba653040e512b91fbcb7b0` | 166078 | `app.html` |
| `88eb1c4fdfce0634e504c9c3568b8bced4ff28cfe4c5a7d885c21a02e4dd6b78` | 6643 | `ar/download.html` |
| `5c76dab2ef7a7768e5639d6418b3e282a7f94b4fee7c770351234f6ffb5c682d` | 58584 | `ar/help.html` |
| `e9e59bb5baf70ecedfd3aecc77b5180661eb83b7618ffe14cddc4c2dabaddccf` | 95083 | `ar/index.html` |
| `abd2457893ba790b352d232af02c6085e926f2c761262ca4495e93edf0751fbb` | 14315 | `arpass-emergency-restore.html` |
| `1e852fb57a76a006193b3009c92f6b48d242ef50698f0ec217d336436c12e32e` | 66067 | `arpass-image.png` |
| `578c43b2fcee11a4ea1ddc8f3ff0b3c19cb77d819f8eb49a271a5ab42d0bf80e` | 58254 | `arpass-image.webp` |
| `2fb8efc284390b3e2cef614d10d07a055e70d81ed423d5bcb35998cd61c59eb9` | 6322 | `de/download.html` |
| `211a5873105605611edb45b137e082d7cbeedf37999db98109710503de5661d0` | 52551 | `de/help.html` |
| `82c1a2a6368d2cc40965b31bfaf9f552c6443592b5056de0eaf9b100612973d6` | 88803 | `de/index.html` |
| `7329551e8f2573fc41960ae4992fa96949fbbf2f01a854cf45155e549f935289` | 1585 | `demo/demo.js` |
| `4d52541fc8c6bfefff05a7de6192c77cce4cad6a828728dd94301d8d9ecb554c` | 1612 | `demo/index.html` |
| `96771777e77cd463747bf5c18103bdd18c809e5c631f5b32f1e8fa885ac2f2f3` | 4620 | `demo/login-en.html` |
| `b2d8cf92b9f6a125c6eca8d22e104f37497dde0d6f499dcc57601467e523473d` | 4913 | `demo/login-ja.html` |
| `834a15c9174f05580ccfbda2469d7b10a3f38b2f404f0850d7353decd44f21ef` | 4585 | `demo/nav-en.html` |
| `7d3292a72c04fb53aedc19ba77d17f41d75d17ad528914672eff29e38af0e590` | 4877 | `demo/nav-ja.html` |
| `85baae7a3694e3dce37614033e3c16c8d747a9675edebfad0d5ddc5aa3124904` | 6250 | `download.html` |
| `98f6058bf008cd61d03b00af3fd348932f3ad0bc87d1fc882da7ca788a22cdd9` | 1320982 | `download/arpass-for-safari-mac.dmg` |
| `e3fedc2ab36d297dfa3a7d58a997e4e962f8b607ffdc0e4772ffe4d1403ac43c` | 260 | `download/README.txt` |
| `ac8d62e188769302fc5af4b6b1460c354faf289777ce95d7bb99c48300a2529c` | 6015 | `en/download.html` |
| `75a50117097bf844242af440bf2593d14685695c91ef4d875791e1d883ee0390` | 47077 | `en/help.html` |
| `f96774e662a7b596a6f2b790b2a0d92d48fc48822d225f2bad21370b6c2c6ce5` | 86374 | `en/index.html` |
| `70c1d2b968982f30472d871d8e3a1ffc8f8a2f02c9cec40c82f0e7b9656899a9` | 6171 | `es/download.html` |
| `97503a1ad1586355814c6eeaf66e20f5c4fbb394043c08c22a7c63083f9de43e` | 50728 | `es/help.html` |
| `f0b8109c6109d58783305639f717b271d1be3fc8b895104cf7bfc1e846dae904` | 87896 | `es/index.html` |
| `ebaa0b820a097106fe6cefd3c56b46187d051f7ddc13efbc75ba7dc781b988df` | 625 | `favicon-16.png` |
| `bb52ebe86d04fca009d38d88da2366f3e3eba013b926c0c6f9b8fa5094471a03` | 1637 | `favicon-32.png` |
| `c52ba1a98f447fb79168d3b5b6c60f2f892056fe02897eb207808e8ff0b3c240` | 15342 | `favicon.ico` |
| `d973602e20a967c9b47a4c9988660989a52699e3094160d899555c7e6ab3c94b` | 6365 | `fr/download.html` |
| `a6bcf13db7ce06de7a8328bc294d57ce0e33a9922a9196be2bb3c7aae3f32833` | 52489 | `fr/help.html` |
| `68302b1f0f2554fb06c001d9d2aaf746d1f47a687434bf9a8abf5367a6783042` | 89704 | `fr/index.html` |
| `ece6e7b94f51a3af8fa02ffa96bd354c6dbbb3f1c8be18d78312371f56fffc47` | 5052 | `guide/ar/index.html` |
| `8197399cab569a587740ab34ca2adc294f7f1c4b99059d1b2114a69248b82d80` | 14339 | `guide/ar/security-glossary.html` |
| `c254b603c315d20cec205b3f161f702339d6146ea897c4e6559d6f500352f06a` | 11469 | `guide/ar/yubikey-arpass.html` |
| `f23acfda2cfd1e01df9f9212db6a58846f5fd9e5e92aa6094dc3fc09d5bede8d` | 12861 | `guide/ar/yubikey-guide.html` |
| `d77d0a5ac3b2a6334288ce59a4d2ac995edb284be69ff4458923de91d1e2caa6` | 10000 | `guide/ar/yubikey-price.html` |
| `e02b029fc3f2d91205fcc0c55c95ce0853464162d27dd75734bd9cb1f046a273` | 11803 | `guide/ar/yubikey-vs-passkey.html` |
| `ef5263ef1054dd5d1be9e130512f59564e42560022d6caba009b1415fe177892` | 4613 | `guide/de/index.html` |
| `51d1a5712712547dae90152a06b751da206a73ec81316ff216bfb451cede82ab` | 12269 | `guide/de/security-glossary.html` |
| `de54af06f8f4fcc764c2c13a1f6496c024a12f71c49e87245bab535958986e70` | 10230 | `guide/de/yubikey-arpass.html` |
| `aa6cecbdf828aab9da67e8f88a0f73fc8328abb5568868925a8b87d390a3e786` | 11082 | `guide/de/yubikey-guide.html` |
| `7ae20827996bf4f4572464ab8788c25d1b94017b9155defce43014707b57720b` | 8801 | `guide/de/yubikey-price.html` |
| `ac78d6da892839469bd48d96d9fe42dc56bb98bd199e25050f40e3dbf6343e5a` | 10211 | `guide/de/yubikey-vs-passkey.html` |
| `c54412c8b17abd8f7f1c9b46a76127dc28e2a5ed68012376ab2123ca2f4e579c` | 4443 | `guide/en/index.html` |
| `4410dc493cbbde684c9cafad94f56d9e5b411d28eb84b9b3bf3ec9663b3cb6ec` | 10701 | `guide/en/security-glossary.html` |
| `5fce45849aded4f139333de372f094fc7d3abb52555e820ab432887c237e9098` | 9241 | `guide/en/yubikey-arpass.html` |
| `25b06352a30d766c6d5d0d9b9a2a131c123c49a1dae2f9819c9aa86a19c42290` | 10551 | `guide/en/yubikey-guide.html` |
| `01b92d006ddbc1d90184db7aa90f62c57fb49c9fab220227ced7e8587cbc8b32` | 8248 | `guide/en/yubikey-price.html` |
| `ae32625ef2d23d616cc7bd18f5be18184b8c2c856149e7dec3af075af4c89733` | 9520 | `guide/en/yubikey-vs-passkey.html` |
| `9f04c1fb44aa7d49500be7301cfaac42619565615657087431af8878c2e05c8d` | 4698 | `guide/es/index.html` |
| `f260fc14130dc47216144a4b5bb4a3f28fb770e8d701cdb758f728c8b4758c1f` | 12249 | `guide/es/security-glossary.html` |
| `f9210310b8273f1bd80415374ffea1265b25bb0174f0674e0dadb57a6ef7a829` | 9703 | `guide/es/yubikey-arpass.html` |
| `f846df75b0110f3e0a5b71b98fd1cd4649221717604a7d3930bb220917f2dec1` | 11243 | `guide/es/yubikey-guide.html` |
| `1552cdfc1a5a93a59305836921760ea11582ae2b408aa47f7227daa83bd227cd` | 8750 | `guide/es/yubikey-price.html` |
| `75c0cf0452cab6493dbde06faefcc9e6a20faeb8b79c108297db28799a9cc6f6` | 10198 | `guide/es/yubikey-vs-passkey.html` |
| `0630266ec521fa243db2fdb7dd3df2754ddf618237a08786749386ccfa3e3075` | 4718 | `guide/fr/index.html` |
| `be49d2409396f3b5b375028b14d40d3842d474db725b2a2d5fc4be5ec1eccc3c` | 12621 | `guide/fr/security-glossary.html` |
| `a3b04c20b5cb525e48d34b8f250cebaac710c192a5e8a2d83cea0b38d5a37fdb` | 10242 | `guide/fr/yubikey-arpass.html` |
| `af1cb44ae5f7adfd0c69ee9da7fedd6f0ee3d8ce472dbf01252e8658a7d602e0` | 11506 | `guide/fr/yubikey-guide.html` |
| `c6d7bfa5599748ce02ff56b116dbdab594f07af8b6f144108395070326acaa59` | 9081 | `guide/fr/yubikey-price.html` |
| `94ebbff13185b63dc6d849386661a32929a44f2b169cec7dff4b936146616d48` | 10491 | `guide/fr/yubikey-vs-passkey.html` |
| `1576fc3367e246c0daf24a3bc6e8b7aa00a671f50ff919ca39053f966e4c8b74` | 5452 | `guide/guide.css` |
| `a5fa5724be8c0421be1c1b127fe541b3e58235e9e449221968a40d0ee5b9c5a8` | 5945 | `guide/hi/index.html` |
| `20a054e7aa01e85bf94a0baaadb7532d52fc73392c74d9596622813a1f23390a` | 21413 | `guide/hi/security-glossary.html` |
| `4ee428f3782dc86df886a3953e1752c5bfc9c709a43e33e8aaf07177fbb0d77c` | 15705 | `guide/hi/yubikey-arpass.html` |
| `ef1c9535b1bd960a4fb53c2000472a7acaa7c908fbd91403cde828647cc2af72` | 16154 | `guide/hi/yubikey-guide.html` |
| `7ee906e8057b9ce4ea749350bc6d51edd3bc40b5b1a1a47a050fe47250438086` | 12130 | `guide/hi/yubikey-price.html` |
| `a6761d087c9f824e592745821269a7e09eaaf668f2a7fa9424bfb8bc94652a95` | 15432 | `guide/hi/yubikey-vs-passkey.html` |
| `b169ce49108940749534ab9213fd58f619c9b05d72232f1a346efb46ab8dcdae` | 4547 | `guide/id/index.html` |
| `4265410514db2b586a78997e4f8b963843d92fad8dc308b52ef88748ca677d8d` | 11573 | `guide/id/security-glossary.html` |
| `ab37f517912a65d4ce1ff79593eccc2108480988ca6803174e3cead188978683` | 9432 | `guide/id/yubikey-arpass.html` |
| `4a08e88d14d53f31b0a9fc801611309a823b6adf3f36954b39daace33e702505` | 10647 | `guide/id/yubikey-guide.html` |
| `13e886587a3782cb8a7e269c25a92547e5354287db45f049edde538be1ce8ef6` | 8326 | `guide/id/yubikey-price.html` |
| `90b3550bc7eccbe143a57ecd58999624ff8be9b8a58ff0049229bc369a0dbbd7` | 9659 | `guide/id/yubikey-vs-passkey.html` |
| `5d173002fa3a39230e7a9af3435ad2e6e8b34b9d90b0d0097b514794d538b98f` | 5645 | `guide/index.html` |
| `842769097e65402801f739b80ef81aa33d1f4cdf77f298aa4ccb03523a05a76c` | 4565 | `guide/it/index.html` |
| `e392c6c4459946054fc7461f9c43f92a49ebe25d58a46815073da554777d0e73` | 11749 | `guide/it/security-glossary.html` |
| `b5ebbd330f8c21783aa24ed11e38ed7d9cc81a87c70449bb821380c28db22e83` | 9646 | `guide/it/yubikey-arpass.html` |
| `f14fb5dbc94885f390ffa37250407076ab41923a8538fd8f7f13b6a23d76a96c` | 10958 | `guide/it/yubikey-guide.html` |
| `f1373a16cdb8ea649f0cc09fcd85d69f117986c4350f02ac3162b5167345767b` | 8609 | `guide/it/yubikey-price.html` |
| `12bfe47830300a92acc39287cb90c0eb5a83d842a8a52ef006144d3ed723b0a9` | 10045 | `guide/it/yubikey-vs-passkey.html` |
| `cad998679fa5180d1f063c8959ec9035c4e4f9d9f96fd16594a88767dde36fbe` | 4571 | `guide/ko/index.html` |
| `1129b8efd3627ef1385f0d447bef13b5149baca7265ccec1601199564beae2cd` | 11695 | `guide/ko/security-glossary.html` |
| `e831c2ecd898f3779c5c0ae7f40b574f62450d7751ecab848d8cbff6d3c4bc70` | 9896 | `guide/ko/yubikey-arpass.html` |
| `fa417f4a68523554419f3834bd21839c04d6d150274a2f49cfd90460eb1a4b1a` | 11237 | `guide/ko/yubikey-guide.html` |
| `57b732369f1aaa8b8cf9b5d8969b2a784fd2ebe95557bd18689bbaf798bf2014` | 8745 | `guide/ko/yubikey-price.html` |
| `2081c44eea53456bc73423c0e914d2cb9bb60750f3cf55502537b234694c26d7` | 10144 | `guide/ko/yubikey-vs-passkey.html` |
| `8d89889cdbd36786324499a0df921aa74752ec3e6c49f470ce7aff6746536ff7` | 4649 | `guide/pt-BR/index.html` |
| `f1f974fd5f828f509fc9a3d474f0052894aa18e515e02358b1b84f7f622dfb79` | 11969 | `guide/pt-BR/security-glossary.html` |
| `2417b962e78bff28cec4285af7c75aa11c4751b1896b6789e27ff3c8ee2df68c` | 9702 | `guide/pt-BR/yubikey-arpass.html` |
| `2e098bf1a4fd7b2dae2a39f1449de3b089dc22e32b66aec0a00741dc9def1bd0` | 11115 | `guide/pt-BR/yubikey-guide.html` |
| `2c47b19ec4b79b69080f4eec91b171f232a305b015600e6cbcdf159663a43049` | 8723 | `guide/pt-BR/yubikey-price.html` |
| `d6da177944adecc28bd44a36c3b2daeba0ef1f619041adc045a5515603a1c51d` | 10049 | `guide/pt-BR/yubikey-vs-passkey.html` |
| `4fec79ee4551317ff99caca7d51ec859c360f31dc31f0c585240687f65145944` | 5420 | `guide/ru/index.html` |
| `99444c48ae9b0a9777c12854ab4d0a683fdb30b66587149ac04a7a9d9a2caa2b` | 16781 | `guide/ru/security-glossary.html` |
| `433869cb0d10cfbf535aef4289494536d5988b2b45747f83920976fe39d36359` | 13184 | `guide/ru/yubikey-arpass.html` |
| `edf204f55b064dbd170d7378d83b066b02cc8c0903e7d768efdeabf4efec5a70` | 13984 | `guide/ru/yubikey-guide.html` |
| `63d035ab1886c491c9526c967f4d944d26c2636aaee65748abab040d1d50ae2c` | 10463 | `guide/ru/yubikey-price.html` |
| `b45daaa68bebce66395a17dd9dcf3f1e4cc9c409852a38d78a20df0b036b8749` | 12937 | `guide/ru/yubikey-vs-passkey.html` |
| `d351b666cd974c2ea1e1f40f64f6fd028f2de485e600c4f6f680caf3c084db17` | 13377 | `guide/security-glossary.html` |
| `a63e9216051dde00faad5c8152103e826db7b009d11657e07f50b5263f935f6f` | 4625 | `guide/tr/index.html` |
| `538a3b663dbebb9a006f678710c49d5b673861bfa723c51261e4ad1ffb2092f8` | 12098 | `guide/tr/security-glossary.html` |
| `02cb52825304ea5af34f82c61c2b919ea4e88dc09c6582ef838a9d286911c22d` | 9623 | `guide/tr/yubikey-arpass.html` |
| `8e11117d03048a38797e4e94705d2f923f80883a525915fb28d9ca6d3f7297d1` | 10860 | `guide/tr/yubikey-guide.html` |
| `eac471dbcf27f002f7e497dde55719676fcb3ed3fa1b44402b951e6c5001435f` | 8420 | `guide/tr/yubikey-price.html` |
| `0d3172672c8b777c55d0f02143d245643918f53a74758ff4435e71faf06da0d1` | 9814 | `guide/tr/yubikey-vs-passkey.html` |
| `39c685ffac5289b03c9029805ad1cf791d3fae8e0eea5414d60f6a56e9484a51` | 4908 | `guide/vi/index.html` |
| `88e93071a8f8c2d9721239c791f9e9f8209655f9c0d1f4b7ca24bbae18ee6a09` | 12835 | `guide/vi/security-glossary.html` |
| `f3d7f4c53e4086b2a4a398fc63195869b4de6edb162497928bb43680d3ea6d1d` | 10476 | `guide/vi/yubikey-arpass.html` |
| `083fc6bc4221d4df39efbadd0d3cb13410e6161eec1c62559dbd2b1bdb779b3d` | 11652 | `guide/vi/yubikey-guide.html` |
| `c940ea057e2b8c1821d4938d3e43807e8b77f8b9bbe89f6b199700dff1a0bf55` | 8961 | `guide/vi/yubikey-price.html` |
| `a250cc1eda149cc8b1b129c96f229eaa7d4c69c99a35d2e690baacda5af66df1` | 10714 | `guide/vi/yubikey-vs-passkey.html` |
| `249cde865b2628a83abe4a3c1f131d141a94199ce77648b8a2e2c1be3d53d42d` | 11027 | `guide/yubikey-arpass.html` |
| `9ac59c7e18d6f72786119a551d47e64e040ee3744b60a3d873b703817abd254a` | 12350 | `guide/yubikey-guide.html` |
| `ac7246aa2673fe2f8bebdc74c36d1c013937517d445c0fbc70110b6ba0619143` | 9561 | `guide/yubikey-price.html` |
| `bce1bc79442fffca2d7ec1863fd5e5e82650694914c4f873ec335481825a7625` | 10924 | `guide/yubikey-vs-passkey.html` |
| `e2d98a836ab84272bf3155732b34d7b8bf34b9bb77cb521f0bfe7215ce8409aa` | 4488 | `guide/zh-CN/index.html` |
| `2b1901b10b47e3777836b87a519935e0fe9a99ed6798452f5f25f652e225acd7` | 10434 | `guide/zh-CN/security-glossary.html` |
| `2a20f0957c1f2a69dab982f22f2534e64fef2eed5b1abb9fc35c7f8a89604ce0` | 8911 | `guide/zh-CN/yubikey-arpass.html` |
| `9345495c581ea2e48ed5701e7167f861c410f08c97978b27fe3fa18dffd04d9b` | 10516 | `guide/zh-CN/yubikey-guide.html` |
| `3564de74da49c6473c2721e2eafb98b35268c21c7b3982edf344266206a2bd1b` | 8169 | `guide/zh-CN/yubikey-price.html` |
| `167f96eb210f37419c2298b3d4a8408b859c204799f16f2e4fb04056129d1b0c` | 9110 | `guide/zh-CN/yubikey-vs-passkey.html` |
| `4ef8702991a2d0aff1378e19d59125861fb20fa4039818a423543a1c506225dc` | 4470 | `guide/zh-TW/index.html` |
| `fbdd499594ce5153e15dcd483d04e6ef596ad631210c120418061a753a8dbd32` | 10589 | `guide/zh-TW/security-glossary.html` |
| `bf6a447a4de5707c6444fd2dd7705a5e9b24d414f199352859f3b26e83aad577` | 8912 | `guide/zh-TW/yubikey-arpass.html` |
| `add80e16de903d40f28ff3ec1f1f029f2898b33bd18f72129825014ad445be30` | 10470 | `guide/zh-TW/yubikey-guide.html` |
| `eb06e0eb1abd147ae3b026e33a5e2332bea3a0f12f55f2d6fbc858f66e25656f` | 8182 | `guide/zh-TW/yubikey-price.html` |
| `d582ed7036cba3bac4b329bded0813ff2e06dfbcc44106f1e0b81e24d6c3a505` | 9136 | `guide/zh-TW/yubikey-vs-passkey.html` |
| `ee7f67e8a94084d49af9b8d5c8e52bdc6dc75928fbabc93001239d5ae5142676` | 54459 | `help.html` |
| `b0d60cc87a3fa498c8c8691f815074504a12c63927c764db6591a8146d71992a` | 7479 | `hi/download.html` |
| `03cbf57332e1998d1c9e17594feacdd990c2a854761b20411121103927840b43` | 69891 | `hi/help.html` |
| `ce537ff60591a4902dec7596836fc6d3ef86e65c4f3a82c284b75aa9ce5d47d7` | 113628 | `hi/index.html` |
| `58485daee809a505fa6032dc38ed90c1ed13f62284733c936d6419285f9f1766` | 238862 | `i18n/ar.json` |
| `5dc5938bea86e08d8f5955c2aab894c9d1abbac2dacf9572afc508cc33055519` | 207071 | `i18n/de.json` |
| `fa7ae4faf69acbdf44d9990fe2f9b5ba9ce95daf5b8601e8c20dc53c0517ef10` | 187134 | `i18n/en.json` |
| `3e76746213b0c0bcd3cda9500e017827f2599529aa770bd1e4eeddf9488ef39d` | 201499 | `i18n/es.json` |
| `1de1e308e3debda00f8c1a09fbb3afdeeebe867fe871e2b06933694b9f978827` | 209255 | `i18n/fr.json` |
| `443035d6a8d1c06f33af510d42825c73556eccd69e466aceed65b9dfbad8f371` | 318520 | `i18n/hi.json` |
| `b9f1ac9db874768cc0f4667633f249653473659374e17b68a7aa08d491a7099a` | 192176 | `i18n/id.json` |
| `0b0eee3f46fd5af8296e80632dc076cc4a0ff40a0efef3b7a9b1bb6023ab32aa` | 199141 | `i18n/it.json` |
| `a1f86df4da77a379bf04da927694740fa34d720bbee71f632c8944d36c80f7a1` | 223881 | `i18n/ja.json` |
| `056410fd993a490970161debe576e0391e0c3c8ae578e4d5ad3878bb86a3a16c` | 206430 | `i18n/ko.json` |
| `d25483e95ba84489cd84023224e6d11ff655cbf281154c3f85970d47dd60b3c4` | 198915 | `i18n/pt-BR.json` |
| `1ac7e524599d01e0150eb208a6ec9aff1c88f78c12df1119fab8e63dfa779579` | 5733 | `i18n/README.md` |
| `1cd90e45083f53f85c943ed98a2631f12c536e60e348955066160c140a5e0744` | 277967 | `i18n/ru.json` |
| `3e6df7c884fdcd453200917a0dcb36334cba18dba3f47760d0f0255af0d34bdd` | 198940 | `i18n/tr.json` |
| `24e5219855faede0caede4774734d79c5503a32c6141c65fddbe858008c42383` | 213742 | `i18n/vi.json` |
| `f4aa56cb4549d3d1962bc160d0028da80f9c2e69b10fcd4580fd721520be1b65` | 179179 | `i18n/zh-CN.json` |
| `28edfdf3902aba046b611e0569672ff167817ddd0e2b7274f656133b6819d6ca` | 179330 | `i18n/zh-TW.json` |
| `aea87aec25c4698322f5a7ca7f43ca2070244ddddcc4c1ba3294de9d0635a183` | 356859 | `icon-1024.png` |
| `97e38260b98141784e8a5a21971c0f97073a5805eedfb7c78affa5dd27ae1ee5` | 23939 | `icon-192.png` |
| `5136b72cc1f12355947aacf4fd7a9d98fceae3ba5209210be5826b5399c5b2dd` | 122358 | `icon-512.png` |
| `7e4f63befaed9ec8301ad0838b6cab453f236f857d5defce9edcd6c647e81eec` | 6081 | `id/download.html` |
| `c0494ae4ff6dd1cbdd7493106b8e4989b9849f18cf5e334e502e17a3558614ba` | 48377 | `id/help.html` |
| `7f39e2a0e11b9fc6e6127cea8a5d18bd74f558d15507d8ce23a6ac6740f08cb2` | 86639 | `id/index.html` |
| `cb2fcd992f534f15f835528b34b839706369e7c0ce855af1d21c9077ac22ecea` | 13617 | `img/lock-icon-gold.png` |
| `f3269cd98338a5a35e4a85ab36f7fb42383c25c7d5677588b1641f5c0266db05` | 93916 | `index.html` |
| `f55716b86d40e46d71d095cc258538ae5c42cae99f7be84fff9ce0e1c4815812` | 6163 | `it/download.html` |
| `aafee58bedca6288a2595fe52ccf8e53fc93a46a43615196da1661602780fb2a` | 49850 | `it/help.html` |
| `6477f7ef055b485c419054cd7ecad0e867d7abe38f2604f423634f88654c189a` | 87573 | `it/index.html` |
| `ae42940432b0b374c60ca0c6edb1e3681a18f2fec1df242923b2c46fe612ab16` | 6323 | `ko/download.html` |
| `d693ff9f1a8c6e3f08db294a4fb7f916de7b4ce1d0cd2c51b1d10f493ce0d072` | 51422 | `ko/help.html` |
| `a7e5c3cc5823ba116214eaeba15213973b5f93fde92d574f98c1e7539c6f7e25` | 88893 | `ko/index.html` |
| `691e5b2bf27333e6f6fc06189e7e40d5afe1da146bf176f4341edbc9c762f0dc` | 488430 | `lib/app-main.js` |
| `5d3f1f4f023a939fb7f1264415d424c61a86fcb5136ea9b88d55bdaa4654714c` | 51756 | `lib/client-auth.js` |
| `27e8e013e3811c736d29967631b642c5ad12ae4511e1e063822e7388b9a6aed6` | 626 | `lib/download-main.js` |
| `f5603e48421566881f6161c55aa0659e88b1566c11d2a0204069113210623dd5` | 7948 | `lib/emergency-recover-purejs.js` |
| `e7487b3b3790356a624eebb77f51a195b79acbf3b4a680129c46652a06ffbd93` | 32098 | `lib/emergency-restore-main.js` |
| `f99e09354cdf5cc975a42a745574a6512ecdb41a4672c35ed0301e47a16c741b` | 1636 | `lib/help-main.js` |
| `a97271a39a44c6cee6d7fa2c9a136401f23eb1ab54fc6877adabd64efa4e3f95` | 17769 | `lib/i18n.js` |
| `ea255434dfdb2c5365493abe25715164300b0883c64b81601ef292588ce2a2f6` | 5748 | `lib/idb-cache.js` |
| `2d299d83fcf0c8ba16df3a797d02a5fba286fd7066ea10a844f345b41ccb8312` | 5754 | `lib/image-compress.js` |
| `67b695d8b6f191ab883188cf7170ce9a4a07d3f9c5959381646bb4f32d985557` | 2189 | `lib/index-main.js` |
| `c964c72ffb41c3ebab34f15778d9b406725a2b912dcf09e34b63cc6d8e7e3c65` | 10097 | `lib/local-cache.js` |
| `47fccc702b0a074ea1699a47d5176f47d4e73aa5adc939b27d8ee81004133936` | 7126 | `lib/lp-pricing.js` |
| `08f6235eee2b83d01cc9e419fb644d8ce7710ded5d21d210e802c7c3f3e4898b` | 12565 | `lib/ocr-vision.js` |
| `c64dd5aa0f7ffc19fc5c8cdf2747e2b43cf3cd2dad6a7ddf362e7481c1c3dfbf` | 659 | `lib/pay-cancel-main.js` |
| `60ea2e2cd0087a7befeb40eb5a26dcb2f1088d6a94601876483de3696d0474c6` | 1087 | `lib/pay-success-main.js` |
| `890960c51e5a485fe4c1ba9f6b0b2dcbd93f8e162e64e9ce8575be2269f8ea71` | 3634 | `lib/pdf-to-image.js` |
| `1a4af1a72dad06288e6df86db26875cb6ec1b6377c477f2a3637d312bde3ed90` | 4513 | `lib/pricing-main.js` |
| `69cb395de7c0e027f66de7cac0ed4d21ddddd870075a136eda118b3d3a97dbd2` | 14371 | `lib/profiles.js` |
| `310ff450ee8fc3bc7ac946987d4532ccc6c8d6d91184dee5e4097801f916ed13` | 10626 | `lib/pwa-install.js` |
| `89be3e9f146de5dee22b08a84fe7764f651fccd797ceb47c70d1aaee2ffd7b22` | 11808 | `lib/qr.js` |
| `46cccff04b577ecdd894479fe5b949b2e86fc7007f09d79d4f5c14ee8f03a468` | 197381 | `lib/rust-crypto/arpass_crypto_bg.wasm` |
| `864a584ee0509b7fd11295e1f89c73c361c3d51e40c86730c3a8a210ea99005c` | 82126 | `lib/rust-crypto/arpass_crypto.js` |
| `0b10245be4c9eb6c964dd333f23d9c2c6f0978baf37982e10182fca73e401673` | 10551 | `lib/save-debounce.js` |
| `9691e2298d0db956374e835c805e155f5fd99e4c992707ae673a3fb10fc6757b` | 663 | `lib/security-main.js` |
| `adb3cd178f75e7070b291911b0e671eb0e226feee8e337b9b32b3a4d9c2e93d3` | 271356 | `lib/vault-client.js` |
| `6bb1e228d0977d90f8c53d004cc121a049d90cc0063b80be8829da97b2a4e96d` | 150890 | `lib/vault-crypto.js` |
| `bc40c8a15196236b2314db0856f72ca0b49980cd5413b8c852a7349f5fee0859` | 256885 | `lib/vendor/jsqr.js` |
| `c6596eb7be8581c18be736c846fb9173b69eccf6ef94c5135893ec56bd92ba08` | 11358 | `lib/vendor/LICENSE-jsqr` |
| `c518e8e7d6fd6add47849fe528790af26533102d1ac898882dc1df49a76f6678` | 1915 | `lib/vendor/LICENSE-noble` |
| `640b215ddbf52e1b9f698d24f645e11db72ec64573d4dba0695af8be3783f3f5` | 107010 | `lib/vendor/noble-curves-and-hashes.mjs` |
| `0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594` | 10174 | `lib/vendor/pdfjs/LICENSE` |
| `27fc2a057a00f92a4334ad06e17dbd7259912954e9fb7f76400bcca5fd190a9c` | 352645 | `lib/vendor/pdfjs/pdf.min.mjs` |
| `1baa1844c89c80a5b2797c916e75ab29254be46d8e9cb53cb6364d7aad84be36` | 1375838 | `lib/vendor/pdfjs/pdf.worker.min.mjs` |
| `18d12d607bda7ac5cc673ab515c2ed1a706483bfbcac7b20273f93368a6db62b` | 20 | `lib/vendor/pdfjs/VERSION.txt` |
| `ea91d7118a5395289170da848b7c6758b996163bfbccf312591ab65a4911b7c0` | 51907 | `lib/vendor/qrcode-generator.mjs` |
| `dcdc26553d3a34270818f51d550c9bdbfbf28b2677acb37dce02e8cb7485ff68` | 4565 | `login/en.html` |
| `35f190bae4b1ca1d6ac3b93030e07a7b57d623ebfe0291fc984f6cd1a5da2c08` | 4857 | `login/ja.html` |
| `b69a59d3b42af0c03e8951a872c2085b23fcf76728a9f1b21c50b595a1f43ceb` | 805 | `manifest.webmanifest` |
| `aebe74828186038610ba39deff04c40351898037edab875197300a4fac2e0923` | 12249378 | `media/arpass-intro-en.mp4` |
| `2864dbe81a5ddc72bd8bcabf7de7610148e3e40800be42169d9e978a254b3f6b` | 95306 | `media/arpass-intro-poster.jpg` |
| `ba95cad5a674dd073dbf2994c322b45a62afccbe1e324b151e59224dec32a352` | 12646967 | `media/arpass-intro.mp4` |
| `9822e3ab29bee4f1690c49157ce2e66c2f652ad43404abb07b4cea32ccc8a24a` | 83577 | `og-card.png` |
| `792b1b19d01c3488f46c7f209056db6dc8563229aeb29d57e50d078856195a40` | 1782 | `pay-cancel.html` |
| `3dc198b27999a309285697053bd4560b6654ff4af9cd781f8e88c18b31639bbc` | 2493 | `pay-success.html` |
| `36d0e7a09a041572041c107c685ce77836431805f1dbfa7c06b2c333c506f604` | 8641 | `pricing.html` |
| `bc658d1ab408772167316f230af3f1e1a3e624f95de9f4a137a65636bfaed177` | 26337 | `privacy.html` |
| `5c272b9b1f8817dec1a5edc5b046c9052ddad3cac384b8dfb6c8c36f0a0aaa75` | 6146 | `pt-BR/download.html` |
| `e8c20f56cc797306383c5b0c6b25521a8399432e1278464c7c0f426396f0d9c2` | 50174 | `pt-BR/help.html` |
| `5f8ea45b6b9aacd6e92ffb645fa0eabaa8183677a5a9086fcac94ae1a41c6eba` | 87489 | `pt-BR/index.html` |
| `4d99cb71b68b5371a8b9b562cd5d108cdeedddad07347c71f38aceac97849c48` | 364 | `robots.txt` |
| `b28936dc048e733ae3f96b37f7dce333c8bdacf1db542610ec342fcd9c70a427` | 6779 | `ru/download.html` |
| `dc4d0cfbb35768962e79c2fe0f216a8c8d9366280e96dd61f9149b1306feddb0` | 67209 | `ru/help.html` |
| `362d3cea096afee724aae40c8670a05e801ad2696b07a6415aceb724e2e276cc` | 103006 | `ru/index.html` |
| `5b4406ef1087060328fd4e17cfd70d8145aac26a0896a2cd713a7e0b04117c63` | 30292 | `security.html` |
| `7d442b6357bcf026f66e112025e912f79d98b3302690e39e4455e5c91cc4232e` | 249314 | `sitemap.xml` |
| `f818b40ae2d435af516ceccf4e09f222a1829692306b0345ce62ae3d21f3824b` | 7427 | `sw.js` |
| `33f6731adcb76de32e27d75df1cf954b32cc062b8ef411fb896553bfd8feb0ad` | 19037 | `terms.html` |
| `ed8d9d2782dabb39f15fafe78789507c6e60067f2103d0b0ee58a532b3b4d193` | 12930 | `tokushoho.html` |
| `c0056ec4f28b02c66cbbf88592a64fa559638931f42d99e462c9da2ba35aff2b` | 6290 | `tr/download.html` |
| `bb083954d68622068b0e679be9abba752aa2397fdb754a65c9844b04db76d7ae` | 50299 | `tr/help.html` |
| `126ac9d8d9882bf939c3bf2039d451ea189f338d545b1c5870d18b97c9ad4eb4` | 87544 | `tr/index.html` |
| `779797db42c72dad221456de6553ba037e8878182a034b3140f7ff17abdf5a70` | 6342 | `vi/download.html` |
| `0376ad215dd3c141ecbfb37766693d606770546abd9f972dd53fb5beac761400` | 52573 | `vi/help.html` |
| `0634a98205c833545f83903206b8d2aa540488192b5b767cff46177c10bed18d` | 91351 | `vi/index.html` |
| `e6c267b80b1d7b98715b323f25766e291b59a6a77351097aefa3001b54317256` | 6108 | `zh-CN/download.html` |
| `c953cea0b59e957200690145f94c5b7cddca33401841c95f48cb2e02c0b22cd0` | 46416 | `zh-CN/help.html` |
| `31b406fda768e8b789dda7638daaa73410d42e5ed000866657673e9f79981f5d` | 83829 | `zh-CN/index.html` |
| `6c7e7b8587751365bda41fbb71a606aadf55c6699dc2ebd3098c47683463bda9` | 6132 | `zh-TW/download.html` |
| `cc5297f03e9c76435ef0e6c73ca01d76cc95c4a50b020c248e13fb60d2637af2` | 46282 | `zh-TW/help.html` |
| `58c1508cd43881269be1f8c63a413f79389a94e33e9f37b2669fb34a1e335935` | 83879 | `zh-TW/index.html` |
