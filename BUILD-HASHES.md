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

**Generated**: 2026-11-14T01:51:07.703Z
**Files**: 259

| SHA-256 | Bytes | Path |
|---|---|---|
| `53f3d8402e3f5e7bc465c45febfe59701879c66f22afec421f9939c07c4c5b29` | 14019 | `_headers` |
| `322bb043cefecf44444d22ece3c08932f9b7af3f5e5a72321867df46770262c9` | 124 | `.well-known/apple-app-site-association` |
| `3f8beb570b36974b4562f475aa49a29b5b3525faaa65961358d16fd790eb7a9c` | 881 | `.well-known/assetlinks.json` |
| `978fa78812d00a1b16159a21658da01a4a701454a4028089b2fd2ca3a7254582` | 505 | `.well-known/security.txt` |
| `3c47ad7f24b20a825b93cacd0acee0173ca32f68d19be94dc92b12d16f78b552` | 188260 | `app.html` |
| `414bacdb4b69cf837f3696b142ccffd64bb58441ac31f4596c72c7fd6b87ed70` | 6643 | `ar/download.html` |
| `d243a21a16206fc3a79131d9a3ea4987a3b248b9142130af164133fb8fc30aad` | 87309 | `ar/help.html` |
| `c241b6b7a88fca85848bfc054f8d9e4512b00725683954468dfaabcedfcf7374` | 98138 | `ar/index.html` |
| `5322537b42635f30e70027de2ad832cf786b6d0cf8bc9500ac1528ff165bf5e9` | 14991 | `arpass-emergency-restore.html` |
| `1e852fb57a76a006193b3009c92f6b48d242ef50698f0ec217d336436c12e32e` | 66067 | `arpass-image.png` |
| `578c43b2fcee11a4ea1ddc8f3ff0b3c19cb77d819f8eb49a271a5ab42d0bf80e` | 58254 | `arpass-image.webp` |
| `f47c46f51fe6630f11e1287763f31092ced8c5642a53c822dcfc98535120817d` | 6322 | `de/download.html` |
| `1d9eb5d01b7ee819dabb21a33370dc8b348f3088dc7130938997bcf3cfb8f53b` | 74864 | `de/help.html` |
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
| `d3cf64353dd7977f50b53c78464607469fa306267f1420fe859e669c7bec8843` | 64869 | `en/help.html` |
| `12de90f2727835c81e56e254df1c50af879435dddff843d40b3c9d1c23190d92` | 88604 | `en/index.html` |
| `29b6f1bf523308b9a80a1f8b6d3a1c457293f28c0ff8333e0dfe3802abc146ad` | 6171 | `es/download.html` |
| `5767df985f716fcfba79ad61119d7966f15aa613884d13c91531d790c46cdbad` | 71513 | `es/help.html` |
| `677d8eb2786cf5c1dbf8dfb9ef9e98b0c560a42f29f5d7b9a96749cf0486577e` | 90396 | `es/index.html` |
| `ebaa0b820a097106fe6cefd3c56b46187d051f7ddc13efbc75ba7dc781b988df` | 625 | `favicon-16.png` |
| `bb52ebe86d04fca009d38d88da2366f3e3eba013b926c0c6f9b8fa5094471a03` | 1637 | `favicon-32.png` |
| `c52ba1a98f447fb79168d3b5b6c60f2f892056fe02897eb207808e8ff0b3c240` | 15342 | `favicon.ico` |
| `8a4e6badc50ad4e203e14b396827a8723a9740412ffeb3e9d9bdd037fcbd35af` | 6365 | `fr/download.html` |
| `36ed6a4376397d8052671eed6e5f4923ab54d0eb13c4ac6d235cf0b634fc32ba` | 74678 | `fr/help.html` |
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
| `b2e6beb6e6f25be63a5164f58cf99f205d1e3a42c14567f6fa11bb7fc595066e` | 76279 | `help.html` |
| `473e43994df05b1fd0517cc91e30e38d4017c16cb7da81ff0c029fc9f4a763bf` | 7479 | `hi/download.html` |
| `52275c1cd0728028488b0843a1715a28724b81b050b1c2cf31ee8f33cf87cde8` | 113844 | `hi/help.html` |
| `9c20c5f1b4013a054837e588eb2891c8643b480d7be9e848e1497e3e22d2e4d9` | 118263 | `hi/index.html` |
| `51f3163e7b3736d952034157484bbf3cb5ec6e5fed3a5fa442ae5874958fb9d8` | 310817 | `i18n/ar.json` |
| `274ad7d54476e52eaa39c05995aa827369e2edfa0195a3ec627306d8cf760076` | 265025 | `i18n/de.json` |
| `191cf1cafe8af77c411a4334692e31a96e5c0c1614feae5dda0471a327854570` | 234753 | `i18n/en.json` |
| `411b736bf815f1531fc32b3493cd93b4b6a0e5282dd6fad308dbf064f5aa6805` | 255914 | `i18n/es.json` |
| `b359377adff59ddc65a252297a0eff914c4c2441625dfcebc9476073b6179b3d` | 266657 | `i18n/fr.json` |
| `31e1facabaf8729d058d2e2f7a5024121301978f9bbcb000e2948e55093a207a` | 422387 | `i18n/hi.json` |
| `fa88e6e37fbe9d259fd8a424bd327ca8efe73094f615c178973b10343442548c` | 244658 | `i18n/id.json` |
| `ef2a32e0b8826e648d0f6c0497c8fd7c6cfd45bf5c18682cce27a4f69d2188e6` | 253618 | `i18n/it.json` |
| `492a14d4f5d7073f4d916c82b8f8968a92a4604ab36345be85c7f7599c645441` | 281147 | `i18n/ja.json` |
| `50e1fcbd82fb0f8243a5660a83f97d0a722c89021f160dddebf1817a666d452a` | 262386 | `i18n/ko.json` |
| `89ec786b85c1d84dee484ff94a633b820989cd086108d37e243955ae8d323c4b` | 252022 | `i18n/pt-BR.json` |
| `1ac7e524599d01e0150eb208a6ec9aff1c88f78c12df1119fab8e63dfa779579` | 5733 | `i18n/README.md` |
| `cd2d0d9f8ee3d4bfdc375ae14fc98e19ad7b8c4abf756fffaf75a235e9e889e7` | 361633 | `i18n/ru.json` |
| `540fb640d29582e7cfe3f869868f6c47db7b9c6a6cf25ba0722c8a37e339b4de` | 252846 | `i18n/tr.json` |
| `01f4f6374ad7caac652b8d624b1d32cfce1b0bb4b4e3108eed3c86b1e4acb910` | 272859 | `i18n/vi.json` |
| `73468d910cba2deb7ca85d50cbcc8086408377c2851d0f5fbcd59a82f7ec91f4` | 225719 | `i18n/zh-CN.json` |
| `bfdfc6e943acb66bb74546b2341fdd02784e9ca4abc0a0ae2b1dddd9ae147c2b` | 226116 | `i18n/zh-TW.json` |
| `aea87aec25c4698322f5a7ca7f43ca2070244ddddcc4c1ba3294de9d0635a183` | 356859 | `icon-1024.png` |
| `97e38260b98141784e8a5a21971c0f97073a5805eedfb7c78affa5dd27ae1ee5` | 23939 | `icon-192.png` |
| `5136b72cc1f12355947aacf4fd7a9d98fceae3ba5209210be5826b5399c5b2dd` | 122358 | `icon-512.png` |
| `a31dc49b53cd022f7b81f5507d0884ebd63b45cb29b9abb482bc31f929b2eaf4` | 6081 | `id/download.html` |
| `95fc91c8d2730d5168dac62d649fe45f1e4b47158449de97dcbb173b7793d7b5` | 68704 | `id/help.html` |
| `64dd430f151c4b6f9a0ae5d1a9f0c70c3a7608f768b4ea99305e5c0091aac3e8` | 89189 | `id/index.html` |
| `cb2fcd992f534f15f835528b34b839706369e7c0ce855af1d21c9077ac22ecea` | 13617 | `img/lock-icon-gold.png` |
| `8c3da1621f8e6a032240f2e44428397aeb3c48edce4e72d5b455e5dea06ae36e` | 96615 | `index.html` |
| `3577082dc5179414ed3764d621f323026544c761f2b7fe79e441bb33b3cdce5d` | 6163 | `it/download.html` |
| `0d5aaf7e96f4e5d52b6c34d3dbacb1a6d97ad3958d65c7741f70db204c43b106` | 70599 | `it/help.html` |
| `21893c4e1e0ef61815924eb01464d3d0f113f20809334792b60b4440c0b3ac39` | 90029 | `it/index.html` |
| `34b5bf9788ee78e0c583a3f928f28a4c0acbf240a7166bc678f25a828ceb60ef` | 6323 | `ko/download.html` |
| `db687b7f5dc7682aca4297795c97a22e541ec87aab408826bcc42aaf0808fc25` | 72404 | `ko/help.html` |
| `11ab4df48ba999ec75c4e6689e23430032887908a99d1c996bf73048616330ed` | 91405 | `ko/index.html` |
| `2cacebce1437c3c168f3f1d46869693245178b40777e09928a3c9469949ceeb7` | 12790 | `lib/android-autofill-setup.js` |
| `2d88e0519ab0a183a768eac3c985f0780110ca62765bfcaf155df2bdba70afdd` | 586849 | `lib/app-main.js` |
| `352862bc86e6f8a0ad30814f946a51166bd8683bf18e2f7d5a2452a19d1eba83` | 53246 | `lib/client-auth.js` |
| `b99b7097f89f1978fdb158b005654286e66ba0734aad6f80fe0db9efa676843b` | 18046 | `lib/csv-import.js` |
| `5783e5e5eed847a7b0ef3c261c6a41711957d1fc54068c7952ef42200753c261` | 56046 | `lib/dicewords-ui.js` |
| `2b44ba4654b9516804890899dbc0c996826715d9cd3980fb01470614c7c12a34` | 23833 | `lib/dicewords.js` |
| `54b0d6fdeb01bb8bfb35285f8809fddae1b441bb8f269b97614d2dc45f0d6b67` | 626 | `lib/download-main.js` |
| `d44eb2a8b45e132405ef9ed38fa8f697ab3b30a72bd90ce3b27049a54e558343` | 12100 | `lib/emergency-recover-purejs.js` |
| `6735b3c0a4ddbad6d251cab619891cfaa0d4aaeb88d0d8257483dbc3463e27bb` | 41104 | `lib/emergency-restore-main.js` |
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
| `2de91e0a78cf2161b90a50b21a44b5aa4d3002e8a6c2d6048e60477465a4a901` | 5683 | `lib/pricing-main.js` |
| `7762257ba6c0896c3f15beac10993d52c48c0b51b88d6034c2a3b2fb11a0d3b6` | 14371 | `lib/profiles.js` |
| `310ff450ee8fc3bc7ac946987d4532ccc6c8d6d91184dee5e4097801f916ed13` | 10626 | `lib/pwa-install.js` |
| `6177d9899940fa5f1a81ff6095b0eea7e2204248629c562ca16b394ee81a2fd0` | 12592 | `lib/qr.js` |
| `4864deb5935325e0dcf765cd885f6a83046568bb616a5d4a4f6185b86f4d79fe` | 7688 | `lib/quick-unlock.js` |
| `52adceae7b6538f7c55d5e3f74199fe4baf8b27562a742f8894983197e65d7c8` | 243785 | `lib/rust-crypto/arpass_crypto_bg.wasm` |
| `0b284f90859585f5d431bb76cd1f477fadb9ce5e5223565055fda04bd0ac2ab9` | 112104 | `lib/rust-crypto/arpass_crypto.js` |
| `0700d8a98ce4cd75f7f51653ee0fc519b660d38d9e1d662bba64e6ae46aff04d` | 15267 | `lib/save-debounce.js` |
| `907f5ce3bf5908037010821d9973e66ce607b62ab86a2cad3f1a1ea2147bfb28` | 663 | `lib/security-main.js` |
| `3c789b7feb40a662640a5fe78e32e78f3acca61d3de339ed9ee374b7a3740fa4` | 14530 | `lib/totp.js` |
| `d231ea2681c5ff736464a153e72120331fb0b81a2cdfaec084cd6be0009cc813` | 332365 | `lib/vault-client.js` |
| `550aefc3f32cb93c3414eb528c415752d1c2fe0525c14866fa371ecabaacbd82` | 166697 | `lib/vault-crypto.js` |
| `bc40c8a15196236b2314db0856f72ca0b49980cd5413b8c852a7349f5fee0859` | 256885 | `lib/vendor/jsqr.js` |
| `c6596eb7be8581c18be736c846fb9173b69eccf6ef94c5135893ec56bd92ba08` | 11358 | `lib/vendor/LICENSE-jsqr` |
| `c518e8e7d6fd6add47849fe528790af26533102d1ac898882dc1df49a76f6678` | 1915 | `lib/vendor/LICENSE-noble` |
| `640b215ddbf52e1b9f698d24f645e11db72ec64573d4dba0695af8be3783f3f5` | 107010 | `lib/vendor/noble-curves-and-hashes.mjs` |
| `0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594` | 10174 | `lib/vendor/pdfjs/LICENSE` |
| `27fc2a057a00f92a4334ad06e17dbd7259912954e9fb7f76400bcca5fd190a9c` | 352645 | `lib/vendor/pdfjs/pdf.min.mjs` |
| `1baa1844c89c80a5b2797c916e75ab29254be46d8e9cb53cb6364d7aad84be36` | 1375838 | `lib/vendor/pdfjs/pdf.worker.min.mjs` |
| `18d12d607bda7ac5cc673ab515c2ed1a706483bfbcac7b20273f93368a6db62b` | 20 | `lib/vendor/pdfjs/VERSION.txt` |
| `ea91d7118a5395289170da848b7c6758b996163bfbccf312591ab65a4911b7c0` | 51907 | `lib/vendor/qrcode-generator.mjs` |
| `08c94a8c8c8778cc1c643a7bb7d3a8aab93f2ccbdf78a6ea2f85a721ff0eeb34` | 27572 | `lib/wordlist/ar.json` |
| `18832db4d9a83b08c11d760badb3b8a904a9ccc8684624012bcbab79abafb27c` | 22546 | `lib/wordlist/de.json` |
| `cfd641621d8112dc09406e9f21708f0bf84b791bdc86ccbeac198ba4cd7b3116` | 18340 | `lib/wordlist/en.json` |
| `7570ae0388f05cf79b4182fd85c804b2686d680b467d51e014440107aeab44f4` | 23732 | `lib/wordlist/es.json` |
| `ac1d9eadd4e0eb5bfcf3b6eab2adb5ab2b46dea0edf77f22b49b7b0d420c221e` | 22035 | `lib/wordlist/fr.json` |
| `2f83eb3f9c2e2cbc667be85e87aeb2adc980d84937fc24acd84ba5f8e0601497` | 36369 | `lib/wordlist/hi.json` |
| `5d37919369dc4c0cd94fdae4fdb81c9534d9584d7a41cc1b0329c44866687f8c` | 22226 | `lib/wordlist/id.json` |
| `b783bfea0797f3db489a199f4978399550242bd49bd0ebc82566c41334745f4e` | 22159 | `lib/wordlist/it.json` |
| `c4d7f4d898bd4f4a9e2c7cf9b2f1450ea0b71e3fbfcf9286ab83b6aef3604456` | 35652 | `lib/wordlist/ja.json` |
| `b04065d8cfbe81eeea2c4f2ac2c74e36519340e5336f3c77e3f9f119a5178ef1` | 23968 | `lib/wordlist/ko.json` |
| `c5ee805b2e1cc8e40f48e7bff4a119b0893b0cda15e7d25029a1b58885b8ad32` | 22484 | `lib/wordlist/pt-BR.json` |
| `ac94c8e5ab7bf84c0100e2a01ebeaff56ef7021e52063b955a9efb48a9231e0a` | 29169 | `lib/wordlist/ru.json` |
| `750284d60f02c7d73f3cf70b9e57e59ceef74143b52dc83dc79a16bf2d8dadd4` | 492896 | `lib/wordlist/test-vectors.json` |
| `aa9077422188aaa8ed19cfcf0c3ac76b0982b5a2ed34c063378bc0c3026c641c` | 22342 | `lib/wordlist/tr.json` |
| `66e5e1e4dfbd89abf8a7540f47111efa7e3ae83b304ce0207469f0e3ddd43781` | 27768 | `lib/wordlist/vi.json` |
| `1ed284299b82b04e4568b65722a56b75645a613dd5fa93cd029504b23e90bb5b` | 94453 | `lib/wordlist/zh.json` |
| `dcdc26553d3a34270818f51d550c9bdbfbf28b2677acb37dce02e8cb7485ff68` | 4565 | `login/en.html` |
| `35f190bae4b1ca1d6ac3b93030e07a7b57d623ebfe0291fc984f6cd1a5da2c08` | 4857 | `login/ja.html` |
| `b69a59d3b42af0c03e8951a872c2085b23fcf76728a9f1b21c50b595a1f43ceb` | 805 | `manifest.webmanifest` |
| `aebe74828186038610ba39deff04c40351898037edab875197300a4fac2e0923` | 12249378 | `media/arpass-intro-en.mp4` |
| `2864dbe81a5ddc72bd8bcabf7de7610148e3e40800be42169d9e978a254b3f6b` | 95306 | `media/arpass-intro-poster.jpg` |
| `ba95cad5a674dd073dbf2994c322b45a62afccbe1e324b151e59224dec32a352` | 12646967 | `media/arpass-intro.mp4` |
| `9822e3ab29bee4f1690c49157ce2e66c2f652ad43404abb07b4cea32ccc8a24a` | 83577 | `og-card.png` |
| `a0307310f3788643759c524e162b1e662d282c3c925abedc0285197aaa487523` | 1782 | `pay-cancel.html` |
| `c5c4d08fdafaf7416dc0643a1d4754af99dd4938fd46c951089f69ddf1357378` | 2493 | `pay-success.html` |
| `6c2cd4b5b8d00181ca9d6ff3a206752d9810844ffa2b55be362f94af79e57984` | 8751 | `pricing.html` |
| `4884ede3f87492ef3e1beca81f64a75248b9446591181f89eef9171b1a9d2f17` | 28323 | `privacy.html` |
| `2019d633684c2fbb2482b92ce08a39bd1f35d448100aba39ee3450c0f1899191` | 6146 | `pt-BR/download.html` |
| `7b8eb1bc17332335d429bb9de9bf05b5b2d6de50ea746455936200cfe9416dee` | 70252 | `pt-BR/help.html` |
| `ada657c5d0d2d5f00b0f122949bbbc2f9d11fd0ef054254a81d842a9959ceca4` | 89957 | `pt-BR/index.html` |
| `4d99cb71b68b5371a8b9b562cd5d108cdeedddad07347c71f38aceac97849c48` | 364 | `robots.txt` |
| `79db34b8a4e278b93eb8aeca5bfe0dc8ea71d419cb94f3ff1b69ae5651502cec` | 6779 | `ru/download.html` |
| `fd902a3623c6067636923ef2896542e16bc9f0e536d60e576094bea7ba7455b5` | 101323 | `ru/help.html` |
| `ffe14084804574932ea6da1f0c8f1f2cae47afc169f6e5831bad9f7384167008` | 106891 | `ru/index.html` |
| `32787760776d3417ed68d69b1c91bac499ce3236bc53b14e1a844e76270bb3c3` | 31810 | `security.html` |
| `7d442b6357bcf026f66e112025e912f79d98b3302690e39e4455e5c91cc4232e` | 249314 | `sitemap.xml` |
| `5260493abde30e5b8f9a1114298d08e85841787a605516d51c9dd1fdcd6a0038` | 7427 | `sw.js` |
| `33f6731adcb76de32e27d75df1cf954b32cc062b8ef411fb896553bfd8feb0ad` | 19037 | `terms.html` |
| `ed8d9d2782dabb39f15fafe78789507c6e60067f2103d0b0ee58a532b3b4d193` | 12930 | `tokushoho.html` |
| `ebe9b8e778eb0a447c4cc495845a7604e690302b40f1d052ff4e3f770cf9dc5e` | 6290 | `tr/download.html` |
| `eba12eaea030c44c8e8287bd4becfcaf97c1d6c4dc7fea760f48e8fdc54829b0` | 71196 | `tr/help.html` |
| `3a92cfc44d3aa53657530d4c546ba4392c7022afa13bbfdcce6ed606c0c36cd2` | 90080 | `tr/index.html` |
| `4a1c5561d2df761f43ced428b084bca1e1de916f4f7b61b59dde88641d8bb713` | 6342 | `vi/download.html` |
| `f132c171b5cc4dd49e03b7fc386a3f4edcc6e4ad924e50d939a6c13f4830b7b1` | 75810 | `vi/help.html` |
| `459486a7bf82378c1cf81b0b2a2c3e41b51b084046f51f764374f8e663fb74f3` | 94313 | `vi/index.html` |
| `794f19682eeee2f9ff2a52bcddf420ca1219c3fdd6e2ae68190efd6ec640e58e` | 6108 | `zh-CN/download.html` |
| `c161c7a86ea9eb2a3ff33258baa408e4988dcbd3adf345272b0833cd8f72d752` | 63679 | `zh-CN/help.html` |
| `290ab4e208257691665eb0994c9990d7fc3ddcd604e0ca84ebd2b81d879052ca` | 86030 | `zh-CN/index.html` |
| `eda081e7318cd51df9aea81626c4d95b9ec17eaec1506e5ff154ecd1122a7f5f` | 6132 | `zh-TW/download.html` |
| `4a761608606b6a99884f34af65478a7ba70d03e9fbc396f6bc2b27f355138b87` | 63603 | `zh-TW/help.html` |
| `5c88ff940f07d7321d3dada99a46315b83f3f0dc4bc57563eb64565448e2831e` | 86133 | `zh-TW/index.html` |
