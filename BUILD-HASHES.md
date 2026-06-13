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

**Generated**: 2026-06-13T09:17:17.980Z
**Files**: 206

| SHA-256 | Bytes | Path |
|---|---|---|
| `f149be8dfb35f30e5162700a1db6629443fc88e0b6dc8600ff331776254c8317` | 12435 | `_headers` |
| `322bb043cefecf44444d22ece3c08932f9b7af3f5e5a72321867df46770262c9` | 124 | `.well-known/apple-app-site-association` |
| `6debf89e472f412e4abef956637a70deb96820e055e39daf9682b752cfffb5d6` | 774 | `.well-known/assetlinks.json` |
| `ef01439f203c358638978bcfdc3c8c3716080778de476d5b3dfa823401b5f093` | 160862 | `app.html` |
| `3a341896827c94d8c0500c5a35cc5ba61ba3b33dc3db0ca1b8cadb49d63e363e` | 53707 | `ar/help.html` |
| `f85f972d075b670725ea506b7d52600fe51fbdeec424073834f3cef05a5ea749` | 92970 | `ar/index.html` |
| `c9cb527d2d4e1a62f7f2e83b0943532c8b3976875674f0b396ade6b20686d59d` | 10228 | `arpass-emergency-restore.html` |
| `1e852fb57a76a006193b3009c92f6b48d242ef50698f0ec217d336436c12e32e` | 66067 | `arpass-image.png` |
| `578c43b2fcee11a4ea1ddc8f3ff0b3c19cb77d819f8eb49a271a5ab42d0bf80e` | 58254 | `arpass-image.webp` |
| `6d651e2c23d53eadc09d61c3377e302392595dbfabc72f10eaf0f4cb0d24c116` | 48622 | `de/help.html` |
| `65fffe052bc94a02c06f1e0e37ad1bb043fa141c92b0f9395eeeabec0124f6e1` | 85875 | `de/index.html` |
| `257d8553479bda6d56d05a0e0232ae4eee0158169f0fa2e8660f21f5da0eb4a4` | 43276 | `en/help.html` |
| `f7d0b305449319bf3a3b769cfcde3cb30f402a6d473bda62d065d9e501a04c50` | 83144 | `en/index.html` |
| `430e9311c95275a84896cdd04eb60b47e395e2237f7ce886ae5cf753e1179ec8` | 46960 | `es/help.html` |
| `a2be64d4b038a846f6a220a42563466c273966801b79cb39c5035f0bef6ff75f` | 85202 | `es/index.html` |
| `ebaa0b820a097106fe6cefd3c56b46187d051f7ddc13efbc75ba7dc781b988df` | 625 | `favicon-16.png` |
| `bb52ebe86d04fca009d38d88da2366f3e3eba013b926c0c6f9b8fa5094471a03` | 1637 | `favicon-32.png` |
| `c52ba1a98f447fb79168d3b5b6c60f2f892056fe02897eb207808e8ff0b3c240` | 15342 | `favicon.ico` |
| `3c13c27b2c25941485bef324ba29f842f4b4eb8157b0e74f408000ef5becc34a` | 48359 | `fr/help.html` |
| `1f27032e09a8c5bb67e8c7906b967efafdf5387cba379f41128577415d50a466` | 86793 | `fr/index.html` |
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
| `1048810e50719fa6273f44b55d9b62cc0da9f80b85f66a6c30567ce6dd896837` | 52514 | `help.html` |
| `1ea5e4c995eb9869fac65854b17c9d21df459987fc4abdb822b192f68d9f3e16` | 63381 | `hi/help.html` |
| `aa10841468057da0a195a1b8513c1c6351f54063742a1288283dc5e36a79c942` | 112804 | `hi/index.html` |
| `0e0fe977709b6de8169d80af87f420340e3d4afe91732d6d840328978bff9bc4` | 226779 | `i18n/ar.json` |
| `6137866e5b1a4672344830b9a625a9f616c5e37d9838e6ab47803ece1aa12a0d` | 196531 | `i18n/de.json` |
| `281ddda4340baaeda3e03dbfa6291c58eb1256f50ea871a2a9535bd356691faf` | 176775 | `i18n/en.json` |
| `26e7a6f34bf5b6fc41ce3934b09035eb13f14b8552ffd26dc306a460dc0f303f` | 191827 | `i18n/es.json` |
| `66b55f5a2366bbd6091cc873eeb29e0da7b14123af2f379743edc7197621bc6f` | 198272 | `i18n/fr.json` |
| `494fb549de35942a198dfbbf16b967a0cde9c39481bd7827c90f36f75df5dfc5` | 301711 | `i18n/hi.json` |
| `7e9f0fc61a2ea6117bd05f24e2c64cce92a457e6aa5f6217932fca3fdcacb921` | 182586 | `i18n/id.json` |
| `e80bd3e30c05aa2668a5da99c3d8761b15ee507f435855390121fc4acf157557` | 189081 | `i18n/it.json` |
| `cbacc3410b42167f6b1378293ee78e599a76114bd1b339c08cf67b922fdbc7dd` | 210976 | `i18n/ja.json` |
| `c759649876c26c6735ba878b9202b985c7a5a416a88b658b80db44ff4f20959f` | 195651 | `i18n/ko.json` |
| `895a6691b46ad0d1882f6dfed7794ff65ce0e293b2fa596d40e3ae1ba5f010ef` | 189138 | `i18n/pt-BR.json` |
| `1ac7e524599d01e0150eb208a6ec9aff1c88f78c12df1119fab8e63dfa779579` | 5733 | `i18n/README.md` |
| `e1ec5bcbd561dc12910c21fa488dcf23de55e7d052573a6297a840108fd10d3e` | 263277 | `i18n/ru.json` |
| `6624c07aa0dbe124c04ead82beca15e8fc57151c3436ea66e4d385f98278cd47` | 188794 | `i18n/tr.json` |
| `25fa6ea77f4d9c1f44889315be0081d2580c20e525647398bcf9c7658124a924` | 202457 | `i18n/vi.json` |
| `712b1128b4103176c5bd286c45391e599b5f7220509baaa6a57a221a7e06c890` | 169757 | `i18n/zh-CN.json` |
| `36ce3a59b0183d07d7fe59b991e5d5909b0d3cc8f5bfa1ac430c482885f503fe` | 169867 | `i18n/zh-TW.json` |
| `aea87aec25c4698322f5a7ca7f43ca2070244ddddcc4c1ba3294de9d0635a183` | 356859 | `icon-1024.png` |
| `97e38260b98141784e8a5a21971c0f97073a5805eedfb7c78affa5dd27ae1ee5` | 23939 | `icon-192.png` |
| `5136b72cc1f12355947aacf4fd7a9d98fceae3ba5209210be5826b5399c5b2dd` | 122358 | `icon-512.png` |
| `7311900454c3565c8276737e129cdf2ddfde8b24b9cfbdbe986a17dc44d3f920` | 609 | `icon.svg` |
| `d81b0e33e454de57ca90cf9efc7b6c65bfc17ab9837e07af7b8f55a1daa02033` | 44703 | `id/help.html` |
| `7a82da9f19d1dc683797207c66a6c8b098f6d5c2cf28749dbc203ca8ee6ec41f` | 83568 | `id/index.html` |
| `cb2fcd992f534f15f835528b34b839706369e7c0ce855af1d21c9077ac22ecea` | 13617 | `img/lock-icon-gold.png` |
| `617c61a0b52f1372aaa0a41e89d4ff6b475c3c2fee7a977851b617f5fb891a44` | 90569 | `index.html` |
| `48c04e89c41c7e00de51305511eb9501b0b33d2fb7c57ab3168167abbe0a8354` | 45976 | `it/help.html` |
| `db1c99c3ad844b65309ba5ae0264575378fb9a5d18ed44ca902081bbc82c5457` | 84715 | `it/index.html` |
| `a9c5cb2ccbcfa696de7447811224cdb5a3f8fee2389c2e627ad6b8b8c4975cf8` | 47377 | `ko/help.html` |
| `973ffe4ad4835050c2b244685c3bb91547b00a7de271874c6423e16ef695aa31` | 86016 | `ko/index.html` |
| `bfde3f6dda33674ef1891e1c63cdda9728ac70bf65e892318892d25df1c3b296` | 437319 | `lib/app-main.js` |
| `7f7807a9301c5cc791146ad2c2024e511e0d9aafdcb769f18717543147f002aa` | 46652 | `lib/client-auth.js` |
| `93ae8b535e8caef3b0cdeefa31ca4ff67cdc57cff6455306e924d801acc50490` | 19883 | `lib/emergency-restore-main.js` |
| `b70c5332ebcc7b662cad84db49a036c6dac78fe55223fad40d11030e7271d5fd` | 644 | `lib/help-main.js` |
| `409d637c33f55d65cd19ed4484116289c0e711175686fa0c87fe50edf5c3d099` | 17483 | `lib/i18n.js` |
| `ea255434dfdb2c5365493abe25715164300b0883c64b81601ef292588ce2a2f6` | 5748 | `lib/idb-cache.js` |
| `2d299d83fcf0c8ba16df3a797d02a5fba286fd7066ea10a844f345b41ccb8312` | 5754 | `lib/image-compress.js` |
| `734a7784335b690cbd747f1cafc0834ded9a4cfcabc2ce4a8e2e687064c9dbba` | 2189 | `lib/index-main.js` |
| `101375584cda9d44718fc34939b884b27a7f73b525106321ed75393f3535b49c` | 10097 | `lib/local-cache.js` |
| `e4fbb0a9d8de10d063ede9d774242881b75a322c51c47adbc775f9674d86e7c6` | 7126 | `lib/lp-pricing.js` |
| `08f6235eee2b83d01cc9e419fb644d8ce7710ded5d21d210e802c7c3f3e4898b` | 12565 | `lib/ocr-vision.js` |
| `c7a41aa1ccd74fb814ee4cf79414e57e6c1f58281183b59d35cf7519d3d2f8b5` | 659 | `lib/pay-cancel-main.js` |
| `fd3393f258f93d7a33ee0299327ef1f1777bcf1cd5c190098a3f27cfb6685195` | 1087 | `lib/pay-success-main.js` |
| `890960c51e5a485fe4c1ba9f6b0b2dcbd93f8e162e64e9ce8575be2269f8ea71` | 3634 | `lib/pdf-to-image.js` |
| `6967514866099b88ff182ee6d2dea7bb6a3af5038c44c775170d3ff5b94c1db9` | 7477 | `lib/pricing-main.js` |
| `17f9039b865e98318078812084ef3850976746b65304aab46410f5da81d11855` | 12156 | `lib/profiles.js` |
| `6b9d08f4238b267c159c8ce1da1e9da18abdb8892db1b70e4c95da2d98f0aafa` | 9112 | `lib/pwa-install.js` |
| `89be3e9f146de5dee22b08a84fe7764f651fccd797ceb47c70d1aaee2ffd7b22` | 11808 | `lib/qr.js` |
| `e5f928081ff1f842ec02f09410ba29497e531cd1d2823542c3845492fd527243` | 196231 | `lib/rust-crypto/arpass_crypto_bg.wasm` |
| `3bccf3980eba7084f34ba0fd602e2f9d70d21a6e26e1e40d580fba207d0d0662` | 80379 | `lib/rust-crypto/arpass_crypto.js` |
| `0b10245be4c9eb6c964dd333f23d9c2c6f0978baf37982e10182fca73e401673` | 10551 | `lib/save-debounce.js` |
| `7f4d0f676453e68f9954be5ef1728871da5c4faa2f8a00ab34f56039f3aad399` | 663 | `lib/security-main.js` |
| `1d00444183fc75c6b32b49e7e19655184e8f57619d91e27155ec343e9e968025` | 238505 | `lib/vault-client.js` |
| `3be7676c6c0eb11c74b826845b99896c837ccf9f741000be476d4f9cd593c615` | 157281 | `lib/vault-crypto.js` |
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
| `e8c2fd28e763016863d33bfc17b057515a82192fb4aeac5e6d887a6b934f2112` | 8635 | `pricing.html` |
| `e1ad706e32aeae6a1b4b4bc6e9127732c902f5fb207d24d8dff4fccd1944ca04` | 22993 | `privacy.html` |
| `4baf885a934ac6e090e5574007684efd009123c9d421a35d0de7418d856368ca` | 46331 | `pt-BR/help.html` |
| `bb2f9f7899ef7d6c5df00409b808ab48f9d09b61ab86b4477f9f75f88c2f9717` | 84674 | `pt-BR/index.html` |
| `4d99cb71b68b5371a8b9b562cd5d108cdeedddad07347c71f38aceac97849c48` | 364 | `robots.txt` |
| `2913ffe89420d9a2d61af610d6d9e4cc1cda940aa0fe3d3e836b3ce3ce4d3c21` | 61773 | `ru/help.html` |
| `3c0b919238f4803fd1ac5524b5a14a4caa7b49338d61f6af9ab157d0a824c116` | 100829 | `ru/index.html` |
| `7f67d842c84dee6a41e054a72bbcc9b9b019818e8551e1961cea7eb953598a34` | 25066 | `security.html` |
| `13354874a4ba70f2f8ccfe0aa0ae8a4db8adf3072a868d88d5f618478f391c95` | 223292 | `sitemap.xml` |
| `67bc89a1e92a9bb7a72cc342e7a4744d921566ea933cfaf010dd3ec90d85afd7` | 6838 | `sw.js` |
| `811af38d946be27c0f5126ad73195045e6ea3b81be9da496bde4018bef5f57c0` | 17797 | `terms.html` |
| `3f2c122c70a90acf1ff46a2e88a1874038d250f924bf5f00abd419f67f65b9dc` | 12478 | `tokushoho.html` |
| `0a227300b27ba52569178247d5177f87f858ca8786be9081d372963a75e2f438` | 46407 | `tr/help.html` |
| `e70f8c361a27c71e23c85ad039d2c90b5e3e8a93398cbe1bd1e6c046d3d85b7e` | 84690 | `tr/index.html` |
| `34a3c59830caffa88faeb78ea67253c0bc7b555ac98299db7ab4857377a4d425` | 48358 | `vi/help.html` |
| `c5ea6145af55a7984476a26dc359f68015259fa86a0603baf16deece17e5674f` | 88779 | `vi/index.html` |
| `118e97cb3fdde3a68fa4555ca863b783b873b1176ba41686c48cadb24f465d27` | 42869 | `zh-CN/help.html` |
| `ae5d2e76424ca61c25bcae8b9d8490d6eb03c7907b3727c4460613065224f139` | 80559 | `zh-CN/index.html` |
| `8c5da297ab2d5b27b983911a547886d247408b139a6c09e3e72c14b28fdfec1b` | 42727 | `zh-TW/help.html` |
| `5d893db20bab45167fbd0e7269d46c6717616645185188a30319862158ec9038` | 80612 | `zh-TW/index.html` |
