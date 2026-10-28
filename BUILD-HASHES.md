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

**Generated**: 2026-10-26T21:11:58.001Z
**Files**: 237

| SHA-256 | Bytes | Path |
|---|---|---|
| `53f3d8402e3f5e7bc465c45febfe59701879c66f22afec421f9939c07c4c5b29` | 14019 | `_headers` |
| `322bb043cefecf44444d22ece3c08932f9b7af3f5e5a72321867df46770262c9` | 124 | `.well-known/apple-app-site-association` |
| `3f8beb570b36974b4562f475aa49a29b5b3525faaa65961358d16fd790eb7a9c` | 881 | `.well-known/assetlinks.json` |
| `978fa78812d00a1b16159a21658da01a4a701454a4028089b2fd2ca3a7254582` | 505 | `.well-known/security.txt` |
| `f88b52306deb2487581cc8abdcc0d16bcf3b178293bcc57b4c57db3ead3758a0` | 166775 | `app.html` |
| `414bacdb4b69cf837f3696b142ccffd64bb58441ac31f4596c72c7fd6b87ed70` | 6643 | `ar/download.html` |
| `159c7ea492f30fdf8371d60ee57a5572cdabd186161b2ab695b183b34351b8a9` | 59152 | `ar/help.html` |
| `1da5d1fa4d3bceb0e97308f6f4a7304484e66e2f4cc1e68cc5e31d62ab3e3adf` | 96120 | `ar/index.html` |
| `529bc9567d6af04352fc108719d18d2e8d8031cc28363593e0c9f13cc2f906c1` | 14315 | `arpass-emergency-restore.html` |
| `1e852fb57a76a006193b3009c92f6b48d242ef50698f0ec217d336436c12e32e` | 66067 | `arpass-image.png` |
| `578c43b2fcee11a4ea1ddc8f3ff0b3c19cb77d819f8eb49a271a5ab42d0bf80e` | 58254 | `arpass-image.webp` |
| `f47c46f51fe6630f11e1287763f31092ced8c5642a53c822dcfc98535120817d` | 6322 | `de/download.html` |
| `2df06d16294a7579b732ce8430f87fda9bb1e876eb3f5b8b99e6ed48a2016ddf` | 52979 | `de/help.html` |
| `0ad1a0a95a1df565f37dd3f29d2dbc266e1d51823f3dd24347f6545f25bab6b6` | 89770 | `de/index.html` |
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
| `62f90778c953eab26eb46760e0d57e884695715fbee75a107525b43fb0c44a02` | 47407 | `en/help.html` |
| `49151b19dd4f898d57fdf163c71b2db2e1e1327ff047f5bbebff3a23b98d7352` | 87317 | `en/index.html` |
| `29b6f1bf523308b9a80a1f8b6d3a1c457293f28c0ff8333e0dfe3802abc146ad` | 6171 | `es/download.html` |
| `80e7e6196f0bb4293346544d2f165a28c3123d0fef652ce354fe1dc8188d5176` | 51158 | `es/help.html` |
| `ee028dd8ee45bd81d6c94a6a955b62bd72b8093659af94058fdbaecb22d8a747` | 88868 | `es/index.html` |
| `ebaa0b820a097106fe6cefd3c56b46187d051f7ddc13efbc75ba7dc781b988df` | 625 | `favicon-16.png` |
| `bb52ebe86d04fca009d38d88da2366f3e3eba013b926c0c6f9b8fa5094471a03` | 1637 | `favicon-32.png` |
| `c52ba1a98f447fb79168d3b5b6c60f2f892056fe02897eb207808e8ff0b3c240` | 15342 | `favicon.ico` |
| `8a4e6badc50ad4e203e14b396827a8723a9740412ffeb3e9d9bdd037fcbd35af` | 6365 | `fr/download.html` |
| `100d6de2b4e0e5def9d791e156e398186b27f129f766f24db92cfc8a1ad6ca67` | 52979 | `fr/help.html` |
| `aad4d5ec7a582a2e16e62350c95bc3d4956d0b77f941c7f48b3338cc8e99bd83` | 90668 | `fr/index.html` |
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
| `464ad562bd94d7db10db7ddd7f6dc9978bbd9a43bad7425501a221932ef6a730` | 55954 | `help.html` |
| `473e43994df05b1fd0517cc91e30e38d4017c16cb7da81ff0c029fc9f4a763bf` | 7479 | `hi/download.html` |
| `b9de135b45ea69cc3d3e2d7a1e3778738c08f7bc1c523b131a95f821475a0878` | 70727 | `hi/help.html` |
| `04196fffbce5af8f65c714803b1e41e86fab1ef2d74e808caa028005e0930280` | 114837 | `hi/index.html` |
| `0d55f03d75e34d13a53cea66e4c56e9be030bf5bd46e5ebacac1a66797559d28` | 239331 | `i18n/ar.json` |
| `e45d43ec371e322cc7a28df481b72772c4fab4ccbe3edb6f209d413dac09300c` | 207473 | `i18n/de.json` |
| `fcd97a997dd2b2938988f1b3bc23594bcfabe9d991456095a718ec042a83c271` | 187442 | `i18n/en.json` |
| `69b8f125e1d4e953c3374d94c430b2716a3d96285ce4e8c7846133938dad2eca` | 201846 | `i18n/es.json` |
| `1add006f001ff27cc793d24112f9352ee15b45cea7b995d46f643bd8f181a192` | 209604 | `i18n/fr.json` |
| `864c7db048623594f6360394e3ea0c4759c05928e89c5f9b595a5f76f14601ca` | 319147 | `i18n/hi.json` |
| `90b23b61e66d8be1e8e33b83d87ad55f6439a19715d1b905cd2b83ca03d0230a` | 192494 | `i18n/id.json` |
| `fe98b522bd4299a3e3d0bbadbc9a7e063371715360329ee67787794d2b5a2330` | 199501 | `i18n/it.json` |
| `0593a68ff74551951bba635cd5a52006cb1c206bbb8ca5e0a3650477ce47b938` | 224331 | `i18n/ja.json` |
| `20f4fbf81d11d9674e7841e0ae4de16915423a6febe4b1f2042f8ce40d8b891c` | 206856 | `i18n/ko.json` |
| `af37abab0f526b448e2f80c1e5a1a7b1bf4cb91a472facb54c3dde4c1a6c5f00` | 199258 | `i18n/pt-BR.json` |
| `1ac7e524599d01e0150eb208a6ec9aff1c88f78c12df1119fab8e63dfa779579` | 5733 | `i18n/README.md` |
| `2c0bb3128dae1bc4a9c1e0b1657e3d99e0c066e2e8b7eb34d1373802ea407ef1` | 278452 | `i18n/ru.json` |
| `3cfce8a155be17fdfa21612b3b2f823dda8c4e17d0e7dab7f8e2a831d29e9383` | 199281 | `i18n/tr.json` |
| `2ff56a68a3dddfbe138a80687a3a7fe14a60b13f0cc1e1ef22bf8d59852772b2` | 214091 | `i18n/vi.json` |
| `7ec847f10f173809c292fcb332d8499c81829d8bf2f42199834390050b39368d` | 179469 | `i18n/zh-CN.json` |
| `f328de281a64acf0f8b0b91eb76a1dbf98da66141922819d144a3e8c04379e12` | 179620 | `i18n/zh-TW.json` |
| `aea87aec25c4698322f5a7ca7f43ca2070244ddddcc4c1ba3294de9d0635a183` | 356859 | `icon-1024.png` |
| `97e38260b98141784e8a5a21971c0f97073a5805eedfb7c78affa5dd27ae1ee5` | 23939 | `icon-192.png` |
| `5136b72cc1f12355947aacf4fd7a9d98fceae3ba5209210be5826b5399c5b2dd` | 122358 | `icon-512.png` |
| `a31dc49b53cd022f7b81f5507d0884ebd63b45cb29b9abb482bc31f929b2eaf4` | 6081 | `id/download.html` |
| `4022ad1933bb6e507a3563d49514fa35a7989d59f6cff7552d93cfa231a9c87e` | 48753 | `id/help.html` |
| `090b1103399a30302e6567b33a4717865066cd9716bd13c6f6ad2cc5e6acfe47` | 87600 | `id/index.html` |
| `cb2fcd992f534f15f835528b34b839706369e7c0ce855af1d21c9077ac22ecea` | 13617 | `img/lock-icon-gold.png` |
| `bf0d59f3ee2a0e2f36ef312c2fe6e20c0c89618564c1e165fb45cce4094347cd` | 95071 | `index.html` |
| `3577082dc5179414ed3764d621f323026544c761f2b7fe79e441bb33b3cdce5d` | 6163 | `it/download.html` |
| `35932af608f982516161c0b2e6e88cf323a69b1300270d8b811d8e1569fa8964` | 50260 | `it/help.html` |
| `bb62d736f62f92e2de382d1be08bb92edb294001fa3c01bfc039660069dd71a0` | 88526 | `it/index.html` |
| `34b5bf9788ee78e0c583a3f928f28a4c0acbf240a7166bc678f25a828ceb60ef` | 6323 | `ko/download.html` |
| `8a1443173cad721ddbd9acccc35992af89973913ca654c7e97727a19f572ff24` | 51754 | `ko/help.html` |
| `89364a1d892ca4ddb5a321c862f7323eda5146a5f759129c8ba6e3aea494bfef` | 89881 | `ko/index.html` |
| `b8659eefa06e88c644aa7968440c65577154523ec6a1f518442512fffa48b0be` | 490384 | `lib/app-main.js` |
| `d3f506d50b2513f514c36473737582d309e2d06a3f1986d2a225be250b02661c` | 51756 | `lib/client-auth.js` |
| `54b0d6fdeb01bb8bfb35285f8809fddae1b441bb8f269b97614d2dc45f0d6b67` | 626 | `lib/download-main.js` |
| `f5603e48421566881f6161c55aa0659e88b1566c11d2a0204069113210623dd5` | 7948 | `lib/emergency-recover-purejs.js` |
| `6068cbcc8706a094edb3d0969bf735c5a5ab2098ddf488e29fd3b04f5a2cfa2f` | 32098 | `lib/emergency-restore-main.js` |
| `4d8740f86028f05c1590e46936cd6122183f95af654e70dc237cee46ead14db4` | 1862 | `lib/help-main.js` |
| `e28daf5a58671268fc966355ba5c082dfafb1c932db361996bdaefd05d000e49` | 17941 | `lib/i18n.js` |
| `ea255434dfdb2c5365493abe25715164300b0883c64b81601ef292588ce2a2f6` | 5748 | `lib/idb-cache.js` |
| `2d299d83fcf0c8ba16df3a797d02a5fba286fd7066ea10a844f345b41ccb8312` | 5754 | `lib/image-compress.js` |
| `5955f2e88e7666af6c2a8552f36ce8559dad890298de594f6ed419846e2f1908` | 2189 | `lib/index-main.js` |
| `d713a5429233d4489a3edd9f795189b54229cc3f93e8435d41daebf11ec2a594` | 10097 | `lib/local-cache.js` |
| `090e0c3b414ebd6cfdd345812ada4345d3e52415ec5b872f1164032fd55e5a8a` | 9049 | `lib/lp-pricing.js` |
| `08f6235eee2b83d01cc9e419fb644d8ce7710ded5d21d210e802c7c3f3e4898b` | 12565 | `lib/ocr-vision.js` |
| `2edd7410d86986f0658251500473e07cc5ba22cfe5bad6f40cc12c4fe38b24ee` | 659 | `lib/pay-cancel-main.js` |
| `d5b80baa47b7993fe395a6752933e2f6364657054c88f9483928357cfdaf7fc3` | 1087 | `lib/pay-success-main.js` |
| `890960c51e5a485fe4c1ba9f6b0b2dcbd93f8e162e64e9ce8575be2269f8ea71` | 3634 | `lib/pdf-to-image.js` |
| `f5c6e4b297a018b083276be275abac78a8c986b9baac756a115f97368df8a4ed` | 4698 | `lib/pricing-main.js` |
| `7762257ba6c0896c3f15beac10993d52c48c0b51b88d6034c2a3b2fb11a0d3b6` | 14371 | `lib/profiles.js` |
| `310ff450ee8fc3bc7ac946987d4532ccc6c8d6d91184dee5e4097801f916ed13` | 10626 | `lib/pwa-install.js` |
| `89be3e9f146de5dee22b08a84fe7764f651fccd797ceb47c70d1aaee2ffd7b22` | 11808 | `lib/qr.js` |
| `46cccff04b577ecdd894479fe5b949b2e86fc7007f09d79d4f5c14ee8f03a468` | 197381 | `lib/rust-crypto/arpass_crypto_bg.wasm` |
| `864a584ee0509b7fd11295e1f89c73c361c3d51e40c86730c3a8a210ea99005c` | 82126 | `lib/rust-crypto/arpass_crypto.js` |
| `0b10245be4c9eb6c964dd333f23d9c2c6f0978baf37982e10182fca73e401673` | 10551 | `lib/save-debounce.js` |
| `907f5ce3bf5908037010821d9973e66ce607b62ab86a2cad3f1a1ea2147bfb28` | 663 | `lib/security-main.js` |
| `d38b76893c339368412f6ef97c211afac212496ab24b92930a6a30bf98d8f24b` | 271356 | `lib/vault-client.js` |
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
| `a0307310f3788643759c524e162b1e662d282c3c925abedc0285197aaa487523` | 1782 | `pay-cancel.html` |
| `c5c4d08fdafaf7416dc0643a1d4754af99dd4938fd46c951089f69ddf1357378` | 2493 | `pay-success.html` |
| `c0881628c95679f23062f242c1098a984302dda46a29c7e6846ac2a749a8f033` | 8641 | `pricing.html` |
| `bc658d1ab408772167316f230af3f1e1a3e624f95de9f4a137a65636bfaed177` | 26337 | `privacy.html` |
| `2019d633684c2fbb2482b92ce08a39bd1f35d448100aba39ee3450c0f1899191` | 6146 | `pt-BR/download.html` |
| `6f8441cc98552da16097cf7dc1e010197779741d4fd4984381f60eecb88d796e` | 50562 | `pt-BR/help.html` |
| `1ac1ca4082be64bf27a1d2d71a391b67b4ea5b89518464cd48baaa78a4fbfda1` | 88437 | `pt-BR/index.html` |
| `4d99cb71b68b5371a8b9b562cd5d108cdeedddad07347c71f38aceac97849c48` | 364 | `robots.txt` |
| `79db34b8a4e278b93eb8aeca5bfe0dc8ea71d419cb94f3ff1b69ae5651502cec` | 6779 | `ru/download.html` |
| `da23388a8b51bf4feaea4a9768fb46b574c56d11716b60803ac37cb23a782200` | 68001 | `ru/help.html` |
| `0df8ddd51f80444a7ae11fa97480f9e6599ab8ec76f2c112b14f253073491537` | 104108 | `ru/index.html` |
| `1d41ba64363d7d83e4615ecbc4cd93364190342ecd6b62555d22b5f7a10a4052` | 30679 | `security.html` |
| `7d442b6357bcf026f66e112025e912f79d98b3302690e39e4455e5c91cc4232e` | 249314 | `sitemap.xml` |
| `9df1dd7eed177cb6a73258b04448889833c9f30648022f3029adefc0e2312aa1` | 7427 | `sw.js` |
| `33f6731adcb76de32e27d75df1cf954b32cc062b8ef411fb896553bfd8feb0ad` | 19037 | `terms.html` |
| `ed8d9d2782dabb39f15fafe78789507c6e60067f2103d0b0ee58a532b3b4d193` | 12930 | `tokushoho.html` |
| `ebe9b8e778eb0a447c4cc495845a7604e690302b40f1d052ff4e3f770cf9dc5e` | 6290 | `tr/download.html` |
| `ebe4691a3972b898eece1a7896c0ae508331e0056ba3742ee9377f11868b3670` | 50715 | `tr/help.html` |
| `cf16acbb040209198892ec5cfc5bdf8fbdc105ce4c1527b7e5a864cd615488a2` | 88495 | `tr/index.html` |
| `4a1c5561d2df761f43ced428b084bca1e1de916f4f7b61b59dde88641d8bb713` | 6342 | `vi/download.html` |
| `7a9e4ffd4808532762272efe3ffdbcd7ddd1f47d6632888fb6848664ab1dc492` | 53031 | `vi/help.html` |
| `0f276f897f2d95e1082894710e9c0db83e5997dfd703c22c1ebbb4132129706e` | 92367 | `vi/index.html` |
| `794f19682eeee2f9ff2a52bcddf420ca1219c3fdd6e2ae68190efd6ec640e58e` | 6108 | `zh-CN/download.html` |
| `2a3ff6f4b5efdc8df02206b9dc0afa12ebb2b9ff710e34c0e535aa99deb4c0d2` | 46732 | `zh-CN/help.html` |
| `1f29bbe4d660bec7b0ddc27056641c05625e0d70da4159d2985fc14900008cd0` | 84794 | `zh-CN/index.html` |
| `eda081e7318cd51df9aea81626c4d95b9ec17eaec1506e5ff154ecd1122a7f5f` | 6132 | `zh-TW/download.html` |
| `2cddfd4b510dc02c44a268348e600825bfc6303d7e5aed300a1afe09d4e697c8` | 46604 | `zh-TW/help.html` |
| `6fcbfe481d18c3492c31d59a1ec85ed0c192b89d005563c20a73db9cf0ae265c` | 84844 | `zh-TW/index.html` |
