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

**Generated**: 2026-11-05T16:07:02.078Z
**Files**: 239

| SHA-256 | Bytes | Path |
|---|---|---|
| `53f3d8402e3f5e7bc465c45febfe59701879c66f22afec421f9939c07c4c5b29` | 14019 | `_headers` |
| `322bb043cefecf44444d22ece3c08932f9b7af3f5e5a72321867df46770262c9` | 124 | `.well-known/apple-app-site-association` |
| `3f8beb570b36974b4562f475aa49a29b5b3525faaa65961358d16fd790eb7a9c` | 881 | `.well-known/assetlinks.json` |
| `978fa78812d00a1b16159a21658da01a4a701454a4028089b2fd2ca3a7254582` | 505 | `.well-known/security.txt` |
| `3ccd5a83ff421f5137b8d496bdf20f66fb34e9657f686c9e84bc8f6a29589c96` | 182413 | `app.html` |
| `414bacdb4b69cf837f3696b142ccffd64bb58441ac31f4596c72c7fd6b87ed70` | 6643 | `ar/download.html` |
| `8c2a7c5f83dcc9e1065d69b05c24190e070405bf4a734b48509adfc8973a56b6` | 64908 | `ar/help.html` |
| `c241b6b7a88fca85848bfc054f8d9e4512b00725683954468dfaabcedfcf7374` | 98138 | `ar/index.html` |
| `041c5bf2d8fa03448a18095a38fa0f9dc9777194f5497823ad6edfb13c413286` | 14991 | `arpass-emergency-restore.html` |
| `1e852fb57a76a006193b3009c92f6b48d242ef50698f0ec217d336436c12e32e` | 66067 | `arpass-image.png` |
| `578c43b2fcee11a4ea1ddc8f3ff0b3c19cb77d819f8eb49a271a5ab42d0bf80e` | 58254 | `arpass-image.webp` |
| `f47c46f51fe6630f11e1287763f31092ced8c5642a53c822dcfc98535120817d` | 6322 | `de/download.html` |
| `e3a37f5d3969141691654fa218c49307326678ef50d3f956abd40b731556a02e` | 57436 | `de/help.html` |
| `e3ef3114f618013e7b99be4f99b1246d43ee83bcc9236ad2203b77c63ed5ee88` | 91473 | `de/index.html` |
| `7329551e8f2573fc41960ae4992fa96949fbbf2f01a854cf45155e549f935289` | 1585 | `demo/demo.js` |
| `4d52541fc8c6bfefff05a7de6192c77cce4cad6a828728dd94301d8d9ecb554c` | 1612 | `demo/index.html` |
| `96771777e77cd463747bf5c18103bdd18c809e5c631f5b32f1e8fa885ac2f2f3` | 4620 | `demo/login-en.html` |
| `b2d8cf92b9f6a125c6eca8d22e104f37497dde0d6f499dcc57601467e523473d` | 4913 | `demo/login-ja.html` |
| `834a15c9174f05580ccfbda2469d7b10a3f38b2f404f0850d7353decd44f21ef` | 4585 | `demo/nav-en.html` |
| `7d3292a72c04fb53aedc19ba77d17f41d75d17ad528914672eff29e38af0e590` | 4877 | `demo/nav-ja.html` |
| `3efbd049a8e42e34c60999ea4b6fc5a2c04f871c3a43e358f40cabb11d910280` | 6250 | `download.html` |
| `98f6058bf008cd61d03b00af3fd348932f3ad0bc87d1fc882da7ca788a22cdd9` | 1320982 | `download/arpass-for-safari-mac.dmg` |
| `e3fedc2ab36d297dfa3a7d58a997e4e962f8b607ffdc0e4772ffe4d1403ac43c` | 260 | `download/README.txt` |
| `0c39aecd2bdad3da24bdbf177c68cc9d8b4dffe16e84f35bf4708d8947f8b48a` | 6015 | `en/download.html` |
| `86542ff3a973ada301369cbb64de70681aaa3e60a2149f9d883e10887b69b3d8` | 50887 | `en/help.html` |
| `12de90f2727835c81e56e254df1c50af879435dddff843d40b3c9d1c23190d92` | 88604 | `en/index.html` |
| `29b6f1bf523308b9a80a1f8b6d3a1c457293f28c0ff8333e0dfe3802abc146ad` | 6171 | `es/download.html` |
| `7ec1a648e87829da5fc045e267663c281e7cc824153c8b1323de32bf09b07839` | 55319 | `es/help.html` |
| `677d8eb2786cf5c1dbf8dfb9ef9e98b0c560a42f29f5d7b9a96749cf0486577e` | 90396 | `es/index.html` |
| `ebaa0b820a097106fe6cefd3c56b46187d051f7ddc13efbc75ba7dc781b988df` | 625 | `favicon-16.png` |
| `bb52ebe86d04fca009d38d88da2366f3e3eba013b926c0c6f9b8fa5094471a03` | 1637 | `favicon-32.png` |
| `c52ba1a98f447fb79168d3b5b6c60f2f892056fe02897eb207808e8ff0b3c240` | 15342 | `favicon.ico` |
| `8a4e6badc50ad4e203e14b396827a8723a9740412ffeb3e9d9bdd037fcbd35af` | 6365 | `fr/download.html` |
| `f72e3a1a71e9da77e2d88a0b04da02b694c1452a2a12a0fd9c38ac90af284f7a` | 57572 | `fr/help.html` |
| `83481a1cdf2afe803748b5521c1bc4d6dc2e752f60f20191ec9d147b73fd5cf5` | 92467 | `fr/index.html` |
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
| `62941e05a30a0052dd347d0e700e93488e4d29ae4830d61840d42c99bf243c0b` | 6515 | `guide/guide.css` |
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
| `cf0f03febc29f478fee959acd8629ec23b198bb6b93d1392c928a390e43dc6b2` | 13217 | `guide/yubikey-guide.html` |
| `2b72adbe1c4bb03bd6a71d16586c090d8f8c78bc18c9dabe79bd09ef73a0913d` | 10529 | `guide/yubikey-price.html` |
| `4a7c9347dd39552014437f63f8e63565001fd15e3420104e492daad6f358b606` | 11536 | `guide/yubikey-vs-passkey.html` |
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
| `c05ccb1039c794323ecf88c6d192df32a0ff4c72c029d35cc83dd3fda2daa7a1` | 59664 | `help.html` |
| `473e43994df05b1fd0517cc91e30e38d4017c16cb7da81ff0c029fc9f4a763bf` | 7479 | `hi/download.html` |
| `e287cf8b357dce6d3dc1f2f44490b2531e4bb6bf44848ec850e017c685463b97` | 80405 | `hi/help.html` |
| `9c20c5f1b4013a054837e588eb2891c8643b480d7be9e848e1497e3e22d2e4d9` | 118263 | `hi/index.html` |
| `57571767682b1017e6ebbb15ab49d5f3dc73d0aacd06644e6dbab63e7ea88258` | 264725 | `i18n/ar.json` |
| `b63b298f5d2e22ffcf888d4260541b8adf6790c283516c76f4ad15f01d939cae` | 228568 | `i18n/de.json` |
| `6eeefba989dd3c92fe1ab7306aee79bd6a93386387e16d178b5f7eae500130dc` | 204971 | `i18n/en.json` |
| `e893c45003783ff5c8ee622bc318d559fb2e9040ebae1c7bb90cdd87c24c1a4d` | 221508 | `i18n/es.json` |
| `0ab09d8a39db91dbdd2f7b80a2d7e0ebb51d239e3a558496fc40c01dc8f08b1a` | 230716 | `i18n/fr.json` |
| `9971d43247f514b118ea4080b20eb70325f95e55b01be1120548043a46582dbf` | 356927 | `i18n/hi.json` |
| `d9124b77bf3d5886e5a1cc82c8994cbfc1e0cab214cdfe2660ff5a01559571c1` | 211087 | `i18n/id.json` |
| `c617a5ddf5587ec54da0c9b822a0908491a2fb0abab037369c859d661507235e` | 219031 | `i18n/it.json` |
| `dfe20045c58dbf1036bb8bc141465939488db5fe7021cfc3fbde92081c4826cb` | 245503 | `i18n/ja.json` |
| `f7b2bd0564f5557f050aa0a8b9083fa128995490b9bab8099c152866b6724120` | 227642 | `i18n/ko.json` |
| `cd51a0838dfd8eb3ba57a4f4eed2e14d413e1f53916b4aa265220c9c42344f15` | 218479 | `i18n/pt-BR.json` |
| `1ac7e524599d01e0150eb208a6ec9aff1c88f78c12df1119fab8e63dfa779579` | 5733 | `i18n/README.md` |
| `9b557cfc976be3df519db82c7422c1ab55eddd4503c7780b8727c0a1b0e5ffb0` | 308705 | `i18n/ru.json` |
| `663773f4504f5e8a990ca238f8320f7f037250811900ef47f3a8b7a198eeb6e8` | 218807 | `i18n/tr.json` |
| `44d40252e98f7821c360c744f0ec6a75998751ff6c94151fa358a543d4a1093d` | 235228 | `i18n/vi.json` |
| `1ead60b195c6e173d89a9ee72b4ea3e9b44e20a06560c79443a8c1128c9b7008` | 196465 | `i18n/zh-CN.json` |
| `42622af0e5293bc31ca397f6355e32cd3f84a3fffae1b8deea8eb69ed0348c30` | 196808 | `i18n/zh-TW.json` |
| `aea87aec25c4698322f5a7ca7f43ca2070244ddddcc4c1ba3294de9d0635a183` | 356859 | `icon-1024.png` |
| `97e38260b98141784e8a5a21971c0f97073a5805eedfb7c78affa5dd27ae1ee5` | 23939 | `icon-192.png` |
| `5136b72cc1f12355947aacf4fd7a9d98fceae3ba5209210be5826b5399c5b2dd` | 122358 | `icon-512.png` |
| `a31dc49b53cd022f7b81f5507d0884ebd63b45cb29b9abb482bc31f929b2eaf4` | 6081 | `id/download.html` |
| `802fe63477851c89d10c7480774be0cb129bd0f7a3e20e149db128ef5c700b1a` | 52521 | `id/help.html` |
| `64dd430f151c4b6f9a0ae5d1a9f0c70c3a7608f768b4ea99305e5c0091aac3e8` | 89189 | `id/index.html` |
| `cb2fcd992f534f15f835528b34b839706369e7c0ce855af1d21c9077ac22ecea` | 13617 | `img/lock-icon-gold.png` |
| `8c3da1621f8e6a032240f2e44428397aeb3c48edce4e72d5b455e5dea06ae36e` | 96615 | `index.html` |
| `3577082dc5179414ed3764d621f323026544c761f2b7fe79e441bb33b3cdce5d` | 6163 | `it/download.html` |
| `e5f1521ec243359c1e3722247e515dd86abfad286ec226978a2a26b642b67cd2` | 54332 | `it/help.html` |
| `21893c4e1e0ef61815924eb01464d3d0f113f20809334792b60b4440c0b3ac39` | 90029 | `it/index.html` |
| `34b5bf9788ee78e0c583a3f928f28a4c0acbf240a7166bc678f25a828ceb60ef` | 6323 | `ko/download.html` |
| `8d35e1961849537ba106ace5f20c788113cb93446024f88f7b19b4ac10dc7310` | 56048 | `ko/help.html` |
| `11ab4df48ba999ec75c4e6689e23430032887908a99d1c996bf73048616330ed` | 91405 | `ko/index.html` |
| `3cc05342aa620ebd9992039e30717a651a69cd72213ebf918ef92afe7aba48ae` | 553589 | `lib/app-main.js` |
| `4d7bac3bca987b2f718393ea47446a456a289404ecfeaa916bb2ed97ca959d29` | 51977 | `lib/client-auth.js` |
| `b99b7097f89f1978fdb158b005654286e66ba0734aad6f80fe0db9efa676843b` | 18046 | `lib/csv-import.js` |
| `54b0d6fdeb01bb8bfb35285f8809fddae1b441bb8f269b97614d2dc45f0d6b67` | 626 | `lib/download-main.js` |
| `d44eb2a8b45e132405ef9ed38fa8f697ab3b30a72bd90ce3b27049a54e558343` | 12100 | `lib/emergency-recover-purejs.js` |
| `ca977b5e9bda4aca83cc1677e67b089568ccea4bb1d1986da379f85d75c512f4` | 38255 | `lib/emergency-restore-main.js` |
| `1a1f069ce210e29a8d7e3288ec70a1716c0d138ff0f61a2278f6b38b49b4c648` | 2657 | `lib/help-main.js` |
| `e28daf5a58671268fc966355ba5c082dfafb1c932db361996bdaefd05d000e49` | 17941 | `lib/i18n.js` |
| `ea255434dfdb2c5365493abe25715164300b0883c64b81601ef292588ce2a2f6` | 5748 | `lib/idb-cache.js` |
| `2d299d83fcf0c8ba16df3a797d02a5fba286fd7066ea10a844f345b41ccb8312` | 5754 | `lib/image-compress.js` |
| `5b9e18b45f7e4134253b1376f20d7fb2ebff07c339a2b9883114a9d9fa886ff2` | 2189 | `lib/index-main.js` |
| `d713a5429233d4489a3edd9f795189b54229cc3f93e8435d41daebf11ec2a594` | 10097 | `lib/local-cache.js` |
| `c632a26949e09216ea5d9f21aafac78f0ec6c551a2e8bde216f72251bb62352f` | 9940 | `lib/lp-pricing.js` |
| `08f6235eee2b83d01cc9e419fb644d8ce7710ded5d21d210e802c7c3f3e4898b` | 12565 | `lib/ocr-vision.js` |
| `2edd7410d86986f0658251500473e07cc5ba22cfe5bad6f40cc12c4fe38b24ee` | 659 | `lib/pay-cancel-main.js` |
| `d5b80baa47b7993fe395a6752933e2f6364657054c88f9483928357cfdaf7fc3` | 1087 | `lib/pay-success-main.js` |
| `890960c51e5a485fe4c1ba9f6b0b2dcbd93f8e162e64e9ce8575be2269f8ea71` | 3634 | `lib/pdf-to-image.js` |
| `73e12e71111012336eb730543e1e2ffdbadf376206609b9c0db6c481844a23a7` | 5683 | `lib/pricing-main.js` |
| `7762257ba6c0896c3f15beac10993d52c48c0b51b88d6034c2a3b2fb11a0d3b6` | 14371 | `lib/profiles.js` |
| `310ff450ee8fc3bc7ac946987d4532ccc6c8d6d91184dee5e4097801f916ed13` | 10626 | `lib/pwa-install.js` |
| `6177d9899940fa5f1a81ff6095b0eea7e2204248629c562ca16b394ee81a2fd0` | 12592 | `lib/qr.js` |
| `bf994dc6269a79ca87e78002e45fe1155880839a0ea0ff4cdba83e17f97218e5` | 234483 | `lib/rust-crypto/arpass_crypto_bg.wasm` |
| `1b722eb7a53f0608f5424decd892e1258bdfd9db72691baea45c5f40e00ee2ab` | 102630 | `lib/rust-crypto/arpass_crypto.js` |
| `0700d8a98ce4cd75f7f51653ee0fc519b660d38d9e1d662bba64e6ae46aff04d` | 15267 | `lib/save-debounce.js` |
| `907f5ce3bf5908037010821d9973e66ce607b62ab86a2cad3f1a1ea2147bfb28` | 663 | `lib/security-main.js` |
| `3c789b7feb40a662640a5fe78e32e78f3acca61d3de339ed9ee374b7a3740fa4` | 14530 | `lib/totp.js` |
| `de6113e98c1f24438f07099a5252ab86c8b0827025eee4d2b8280bd299b85721` | 282341 | `lib/vault-client.js` |
| `f026329961112f1d6d846d1022987855c2217eda4120aff9673aef3d6e330e58` | 158555 | `lib/vault-crypto.js` |
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
| `a0307310f3788643759c524e162b1e662d282c3c925abedc0285197aaa487523` | 1782 | `pay-cancel.html` |
| `c5c4d08fdafaf7416dc0643a1d4754af99dd4938fd46c951089f69ddf1357378` | 2493 | `pay-success.html` |
| `d1cc77468baf9fa1bccfbdb7ce065fea472afa9c8be81e7c8c3b3100c32fd12b` | 8751 | `pricing.html` |
| `bc658d1ab408772167316f230af3f1e1a3e624f95de9f4a137a65636bfaed177` | 26337 | `privacy.html` |
| `2019d633684c2fbb2482b92ce08a39bd1f35d448100aba39ee3450c0f1899191` | 6146 | `pt-BR/download.html` |
| `9b673d4627f064bab5edc1e7dee05184ad03eaed0b78a3998a5000e17edd1db2` | 54477 | `pt-BR/help.html` |
| `ada657c5d0d2d5f00b0f122949bbbc2f9d11fd0ef054254a81d842a9959ceca4` | 89957 | `pt-BR/index.html` |
| `4d99cb71b68b5371a8b9b562cd5d108cdeedddad07347c71f38aceac97849c48` | 364 | `robots.txt` |
| `79db34b8a4e278b93eb8aeca5bfe0dc8ea71d419cb94f3ff1b69ae5651502cec` | 6779 | `ru/download.html` |
| `96cd05c08278752a3a839da3645daee8fc6ec68a20f3803924bd07bc3bbfceba` | 75509 | `ru/help.html` |
| `ffe14084804574932ea6da1f0c8f1f2cae47afc169f6e5831bad9f7384167008` | 106891 | `ru/index.html` |
| `1d41ba64363d7d83e4615ecbc4cd93364190342ecd6b62555d22b5f7a10a4052` | 30679 | `security.html` |
| `7d442b6357bcf026f66e112025e912f79d98b3302690e39e4455e5c91cc4232e` | 249314 | `sitemap.xml` |
| `80500583c39c6876a042808f2e0616c0c5af2876e79f59a4abb6bdf70847a9e0` | 7427 | `sw.js` |
| `33f6731adcb76de32e27d75df1cf954b32cc062b8ef411fb896553bfd8feb0ad` | 19037 | `terms.html` |
| `ed8d9d2782dabb39f15fafe78789507c6e60067f2103d0b0ee58a532b3b4d193` | 12930 | `tokushoho.html` |
| `ebe9b8e778eb0a447c4cc495845a7604e690302b40f1d052ff4e3f770cf9dc5e` | 6290 | `tr/download.html` |
| `66d2095e43f11b2c9dd9d670ecb1f4f3c51998e92836da1dadb0ee213bf8bc83` | 54841 | `tr/help.html` |
| `3a92cfc44d3aa53657530d4c546ba4392c7022afa13bbfdcce6ed606c0c36cd2` | 90080 | `tr/index.html` |
| `4a1c5561d2df761f43ced428b084bca1e1de916f4f7b61b59dde88641d8bb713` | 6342 | `vi/download.html` |
| `979c7f22719b2b3fd63667d43e8f97035e9ea5f0cc92c4b8b57efe3ca73ff15c` | 57642 | `vi/help.html` |
| `459486a7bf82378c1cf81b0b2a2c3e41b51b084046f51f764374f8e663fb74f3` | 94313 | `vi/index.html` |
| `794f19682eeee2f9ff2a52bcddf420ca1219c3fdd6e2ae68190efd6ec640e58e` | 6108 | `zh-CN/download.html` |
| `733d885488c3b1ecbcdfc055d531a252c471e69e729825f072266c462e48d258` | 50065 | `zh-CN/help.html` |
| `290ab4e208257691665eb0994c9990d7fc3ddcd604e0ca84ebd2b81d879052ca` | 86030 | `zh-CN/index.html` |
| `eda081e7318cd51df9aea81626c4d95b9ec17eaec1506e5ff154ecd1122a7f5f` | 6132 | `zh-TW/download.html` |
| `bfe868b236604ff62f06d6593279ee86d4aedbf9b6c908bb2a4e39756f8c0f60` | 49966 | `zh-TW/help.html` |
| `5c88ff940f07d7321d3dada99a46315b83f3f0dc4bc57563eb64565448e2831e` | 86133 | `zh-TW/index.html` |
