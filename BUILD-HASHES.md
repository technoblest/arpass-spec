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

**Generated**: 2026-07-22T11:32:56.991Z
**Files**: 235

| SHA-256 | Bytes | Path |
|---|---|---|
| `283040bbb57645a10a37c0211b2b6ae418de50fc109dbbe3f3789591e6fe787b` | 13844 | `_headers` |
| `322bb043cefecf44444d22ece3c08932f9b7af3f5e5a72321867df46770262c9` | 124 | `.well-known/apple-app-site-association` |
| `3f8beb570b36974b4562f475aa49a29b5b3525faaa65961358d16fd790eb7a9c` | 881 | `.well-known/assetlinks.json` |
| `978fa78812d00a1b16159a21658da01a4a701454a4028089b2fd2ca3a7254582` | 505 | `.well-known/security.txt` |
| `f4d4d1f2b3fbde5d15db91d9544b95778f4aac8e184d5cfa011c0696b8290790` | 166072 | `app.html` |
| `504c7d9670728fbb09a402c16c2fbb203b1381d2fa70509ea998139f7333d887` | 6514 | `ar/download.html` |
| `d518a6ecbab145441ed711918f8eeb6af41215f22f57ec30b7e05ffc2012e35e` | 53794 | `ar/help.html` |
| `eb25462a1eb3beabee1a48e51a93a0844ecc9e834c796e7cbbc4d6a1ff1212ba` | 91991 | `ar/index.html` |
| `bc23347d3d949fc7af2495c7a8b3be155c64aa212716620705856c1546110516` | 12637 | `arpass-emergency-restore.html` |
| `1e852fb57a76a006193b3009c92f6b48d242ef50698f0ec217d336436c12e32e` | 66067 | `arpass-image.png` |
| `578c43b2fcee11a4ea1ddc8f3ff0b3c19cb77d819f8eb49a271a5ab42d0bf80e` | 58254 | `arpass-image.webp` |
| `3d96eabe5e26209f3b9f20a0d9c05960515a0b345c12985285bbd73ea53e23d8` | 6161 | `de/download.html` |
| `360d95b45467dd5389a4bc9e719c98a4c16fa6826d0ff9eddb0f99b8c3066633` | 48703 | `de/help.html` |
| `b385db9a9954bc2b21484782b05f2cb91c47ec89b5e31823bcc3bcb1e54ec54c` | 85319 | `de/index.html` |
| `7329551e8f2573fc41960ae4992fa96949fbbf2f01a854cf45155e549f935289` | 1585 | `demo/demo.js` |
| `4d52541fc8c6bfefff05a7de6192c77cce4cad6a828728dd94301d8d9ecb554c` | 1612 | `demo/index.html` |
| `96771777e77cd463747bf5c18103bdd18c809e5c631f5b32f1e8fa885ac2f2f3` | 4620 | `demo/login-en.html` |
| `b2d8cf92b9f6a125c6eca8d22e104f37497dde0d6f499dcc57601467e523473d` | 4913 | `demo/login-ja.html` |
| `834a15c9174f05580ccfbda2469d7b10a3f38b2f404f0850d7353decd44f21ef` | 4585 | `demo/nav-en.html` |
| `7d3292a72c04fb53aedc19ba77d17f41d75d17ad528914672eff29e38af0e590` | 4877 | `demo/nav-ja.html` |
| `ec4cbffaa8597bcde83132189d1fd05de570f09f0cf409b7af3d11ae02c3d7f6` | 6189 | `download.html` |
| `98f6058bf008cd61d03b00af3fd348932f3ad0bc87d1fc882da7ca788a22cdd9` | 1320982 | `download/arpass-for-safari-mac.dmg` |
| `e3fedc2ab36d297dfa3a7d58a997e4e962f8b607ffdc0e4772ffe4d1403ac43c` | 260 | `download/README.txt` |
| `543c9f915f048d03ea8e1ced8fd7e5b8163b5989691ac862ea090da671f40b55` | 5850 | `en/download.html` |
| `28e1b5e76252f3900034dcff2d0b174e8ba18a31367828f0bd1bf1bff7ea2b87` | 43334 | `en/help.html` |
| `c78a31e5b2a2c3d47b1255010e9f7eba3001e52a4e0ed30f839b94536a2effeb` | 82798 | `en/index.html` |
| `6d888a90430e76f90be82ef09c54079684ad572c9350295ad091c009086ba93e` | 6011 | `es/download.html` |
| `11d358a313bc33a0e0a4545338a453bf03fe4c4d2c51af00b7416b47dc771ea0` | 46987 | `es/help.html` |
| `a2ece5ec29372da77f647ff00a544ab8b6da3b390e5820a8f6bbcf711a07901b` | 84483 | `es/index.html` |
| `ebaa0b820a097106fe6cefd3c56b46187d051f7ddc13efbc75ba7dc781b988df` | 625 | `favicon-16.png` |
| `bb52ebe86d04fca009d38d88da2366f3e3eba013b926c0c6f9b8fa5094471a03` | 1637 | `favicon-32.png` |
| `c52ba1a98f447fb79168d3b5b6c60f2f892056fe02897eb207808e8ff0b3c240` | 15342 | `favicon.ico` |
| `194b53c057046f9a481f4efd825c072e0bf6bdabf95063eeffb39ca940989a79` | 6227 | `fr/download.html` |
| `ac42a642c070d3fc40cfab5cc4d586a15df3452f4fca62e87a526b03a5f55ca0` | 48411 | `fr/help.html` |
| `1efc19c7bc8f3eca5240a84bb68f019e92dc7d9ab9d4a827a6bc82432464e887` | 86160 | `fr/index.html` |
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
| `ea714c1b70545bfbbba3a64c16a6471e655d96ecb03b5e9f0d3ec0b755de2d5c` | 7441 | `hi/download.html` |
| `12113f1f011a899345893b67e9daf42d173d0d8e1151f777e6a90eb5991b3c61` | 63526 | `hi/help.html` |
| `e531e643004f68a739426aa7c677e265dca60f84b20e75d19ed9e7c75fc3d9ad` | 111421 | `hi/index.html` |
| `60e5640584dad87ff7c33e9e447f8e7318ef28e5cbb574ab5f46aa9926433d71` | 237368 | `i18n/ar.json` |
| `26208611b61a4ee148ce3c95029113b2be4513d4e4917882ce0023108cac4cc5` | 205738 | `i18n/de.json` |
| `f3391edd40ceb87c9cd019462006f480a818e40d72ffaa873a8683ed563520c2` | 185943 | `i18n/en.json` |
| `3581c17be2eaf08c01889cac5ae28a091a7ab6a07e1384b464ee2372688fef06` | 200221 | `i18n/es.json` |
| `2ca138388067858d5c56cc60537818d8be51efafac2dc68f388ecd82cd292b15` | 207847 | `i18n/fr.json` |
| `e2643e07a1ce0e262a05b889eb04a0c4c64f6d950bff544d02c90c02b626936a` | 315959 | `i18n/hi.json` |
| `fb52a22d802a1abbfe25e7341a7c3c31f93e8b5430bb9e558b7e06ddcee84aa0` | 190861 | `i18n/id.json` |
| `a7636776533d76268cd39b1a45e42bc90405fe3b648f7614091273690ddf5dce` | 197813 | `i18n/it.json` |
| `892b5e0bcb6d80b92656c4de1095aa34d05eb69e94f194203f8c855ba8db2dcd` | 222413 | `i18n/ja.json` |
| `96089c2643882749f19787eda793f5d1ac8705b01e0841db9877db1e1a35b890` | 205058 | `i18n/ko.json` |
| `48c8e60aeb5f23f325a8afcdb9699618a8e785e52b901a7f42552eba828a9390` | 197621 | `i18n/pt-BR.json` |
| `1ac7e524599d01e0150eb208a6ec9aff1c88f78c12df1119fab8e63dfa779579` | 5733 | `i18n/README.md` |
| `4d5c12dd5019a56204201e7f8a942cdd3a4f40e0ce3f9659d7895be33bcf3666` | 275923 | `i18n/ru.json` |
| `8918deffb2233ca04d4989638ea14e4fc0bda4af87a2d55c5ad8f1f302f8a979` | 197643 | `i18n/tr.json` |
| `d6c6b3a40903a48be23ce08fe9e42c69d2e9e307adffac1de0980dc62b4ac30b` | 212249 | `i18n/vi.json` |
| `b3f7ac47ba0a72c0bea9a2b5d7e31d8dd41c63406664e070262ea7cc21d256b7` | 178065 | `i18n/zh-CN.json` |
| `c7a3b4b13fc0740ee319f4cb78b613a1b2cd781cfff802b6708506bf38b3dd1d` | 178219 | `i18n/zh-TW.json` |
| `aea87aec25c4698322f5a7ca7f43ca2070244ddddcc4c1ba3294de9d0635a183` | 356859 | `icon-1024.png` |
| `97e38260b98141784e8a5a21971c0f97073a5805eedfb7c78affa5dd27ae1ee5` | 23939 | `icon-192.png` |
| `5136b72cc1f12355947aacf4fd7a9d98fceae3ba5209210be5826b5399c5b2dd` | 122358 | `icon-512.png` |
| `7311900454c3565c8276737e129cdf2ddfde8b24b9cfbdbe986a17dc44d3f920` | 609 | `icon.svg` |
| `57ca5292f63fe91fff6c2d68f3824cf900e3fd879c8373d30bc9ee1203a53d47` | 5912 | `id/download.html` |
| `4efeda6a8daa15104580586baba156f96cd6da5aab329459715780e34ae36485` | 44745 | `id/help.html` |
| `77071122bb291a01aa45d7c60b0d345779b17aa515fbf23a8c4e0011486c87a9` | 82959 | `id/index.html` |
| `cb2fcd992f534f15f835528b34b839706369e7c0ce855af1d21c9077ac22ecea` | 13617 | `img/lock-icon-gold.png` |
| `37790a4a281686ecccd256bc3390477e5cdc73c0a780552f446cf752c4dc8a30` | 90369 | `index.html` |
| `b51f99ffad185191793750b44dfc0f6a86654c88bb3e05b291d537aaec253c86` | 5996 | `it/download.html` |
| `f5c55a93b7c85e09e8436cb621104bfb1b764449821648e7a4e90ba53b0e8273` | 46036 | `it/help.html` |
| `7fae2ac1d05697ba79059af8bad796adc8bd3b7dc39d2b5127f083edc8831c3e` | 84001 | `it/index.html` |
| `d1275b8910d4f41734c7416db2154906cfe7792c5fcc723245151a79cdb123c9` | 6155 | `ko/download.html` |
| `e55c9c8d4d9acf40f05ab71e736267588f24b4b10dd3811e5ca6d1c336bf9a83` | 47485 | `ko/help.html` |
| `04376a6f42e9226c31ba1fb1b71529eca0333bd5b82f32fceb5017d163ccb662` | 85402 | `ko/index.html` |
| `691e5b2bf27333e6f6fc06189e7e40d5afe1da146bf176f4341edbc9c762f0dc` | 488430 | `lib/app-main.js` |
| `5d3f1f4f023a939fb7f1264415d424c61a86fcb5136ea9b88d55bdaa4654714c` | 51756 | `lib/client-auth.js` |
| `27e8e013e3811c736d29967631b642c5ad12ae4511e1e063822e7388b9a6aed6` | 626 | `lib/download-main.js` |
| `f5603e48421566881f6161c55aa0659e88b1566c11d2a0204069113210623dd5` | 7948 | `lib/emergency-recover-purejs.js` |
| `21fd6b4cd8271526ce78113bef9747b9dee478e84757d4fd7bc191c58ecc1326` | 32026 | `lib/emergency-restore-main.js` |
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
| `9822e3ab29bee4f1690c49157ce2e66c2f652ad43404abb07b4cea32ccc8a24a` | 83577 | `og-card.png` |
| `792b1b19d01c3488f46c7f209056db6dc8563229aeb29d57e50d078856195a40` | 1782 | `pay-cancel.html` |
| `3dc198b27999a309285697053bd4560b6654ff4af9cd781f8e88c18b31639bbc` | 2493 | `pay-success.html` |
| `9760766eef34772b9b74400f01603db469a9c2840cba1997382e5418b2fe0d3c` | 8635 | `pricing.html` |
| `0caad175b0833db22d2ec6046954d2d1e4db883637c68a4af9848048f7d7ae65` | 26325 | `privacy.html` |
| `353f0eba70152871459bc9a8d2cce92d351990049153790b213b82c863dd1403` | 5984 | `pt-BR/download.html` |
| `365fa336be34f4db62a4fa693bd66a99cd940c7a4311c496b7babb7dc2d351ef` | 46339 | `pt-BR/help.html` |
| `1eaac709a447224e3fba56f462b16df03802fe8e6d1743ccb8bd72ea91860cd2` | 83954 | `pt-BR/index.html` |
| `4d99cb71b68b5371a8b9b562cd5d108cdeedddad07347c71f38aceac97849c48` | 364 | `robots.txt` |
| `9a4b34826624c833eb103cf9e4006366f06a737cc75cf0ae66c6e7a4c9fe2627` | 6678 | `ru/download.html` |
| `16ff4cedfbed3237d0b00c3cfe215ff5b63b5ff6eab87439f6d47783cd9b5de0` | 61884 | `ru/help.html` |
| `aaa919d4fc8258f89d3eac83a211086cdb96944f4c23aa4eaf4cd05b78066da1` | 99964 | `ru/index.html` |
| `11850e18aafdead19184ba8688a095d601b5712265930979b72d86206e67b916` | 25057 | `security.html` |
| `7d442b6357bcf026f66e112025e912f79d98b3302690e39e4455e5c91cc4232e` | 249314 | `sitemap.xml` |
| `22589118f20a1db1d46fd85d41870215c3773eadae3d904944409e468da284a3` | 7427 | `sw.js` |
| `5454dd0d445d7518a5650139248d6935c9c49e17539386dcdf33a463b1e95c37` | 19025 | `terms.html` |
| `39423e97d9d05639f8ea4f0458bbe60b520a0f3586ff0bbaea0b9f46beb2e62e` | 12918 | `tokushoho.html` |
| `5604f1b6545c08e416ee87669af796003ce242e9abad3953427b177d917ac65f` | 6113 | `tr/download.html` |
| `d059896e8abac422d82757ed81e37c2c549e317ad7045651e3f94acba4b1175c` | 46480 | `tr/help.html` |
| `5a2a9784bf4db7fb96985f07288be62b46abd71c87b12b4ce1114d5984423836` | 84064 | `tr/index.html` |
| `dbe18e15a752f67d4e9d7b80ede8d6900dfb85d2718938dae0be3c9d31517913` | 6204 | `vi/download.html` |
| `45620a605d575a8e9d1affb851806109a80c01dda1d2ac050c94ce106631851c` | 48429 | `vi/help.html` |
| `25289653e8a68cee6ccc43c7e8414b0f2bbf480216946117dc7b3204e2c015ce` | 87969 | `vi/index.html` |
| `483d40d676b1b837e71b9ca3298e1c902bf617c3c187b93b7215a1d78f821b6d` | 5911 | `zh-CN/download.html` |
| `21a704b51a5fe7898c8e888f7f1f3fc4db45865f714057457694e26e966ea2b0` | 42923 | `zh-CN/help.html` |
| `39cffb07f031a4dc738bd432ddd6a10a46133abfac156e8cb2f4c425634355b1` | 80098 | `zh-CN/index.html` |
| `f69a6bf4e8fc4d5377f2da9865288efb47d6c5099a88580f1cccce390b17a215` | 5935 | `zh-TW/download.html` |
| `d7641f82efd609b5bb9ac3febd17bf01a5bcf3b4647190aa59412833b3e3968f` | 42793 | `zh-TW/help.html` |
| `05515e1121bf3e42d409d1de7000882117213ce24eb3a286730d34c83a10e7bd` | 80151 | `zh-TW/index.html` |
