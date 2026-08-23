# Glossary / 术语表

> 🌐 **Language / 语言:** This page is intentionally bilingual — it is the single source of truth for terminology used in both [the English guide](using-gmcrypto-core.md) and [中文指南](using-gmcrypto-core.zh-CN.md).

Rule: when an English term appears in this table, use the corresponding Chinese term in `.zh-CN.md`. Do not coin alternative translations. If a term is missing, add it here first, then use it in prose.

API names, crate names, commands, filenames, feature flags, error messages, and format names (`DER`, `PEM`, `PKCS#8`, `SEC1`, `SPKI`) stay in backticks and are **not** translated in either language.

| English | 中文 | Notes / 备注 |
|---|---|---|
| signature | 签名 | |
| sign / verify | 签名 / 验证 | |
| encrypt / decrypt | 加密 / 解密 | |
| ciphertext / plaintext | 密文 / 明文 | |
| key | 密钥 | |
| public key / private key | 公钥 / 私钥 | |
| key agreement | 密钥协商 | generic term; for the SM2 protocol see "key exchange" |
| key exchange | 密钥交换 | the GM/T 0003.3 (≡ GB/T 32918.3) SM2 protocol, per the standard's own naming |
| key confirmation | 密钥确认 | the `S_A` / `S_B` tag-verification step in SM2 key exchange |
| key derivation | 密钥派生 | |
| TLCP | TLCP | the Transport Layer Cryptography Protocol (GB/T 38636-2020); acronym kept English |
| key schedule | 密钥编排 | two senses: TLCP's PRF-based derivation of session keys from the pre-master secret (GB/T 38636 §6.5), and a block cipher's expansion of a key into round keys (SM4) |
| master secret / pre-master secret | 主密钥 / 预主密钥 | TLCP key-schedule inputs/outputs (GB/T 38636 §6.5) |
| record protection | 记录层保护 | TLCP's per-record protect/deprotect (GB/T 38636 §6.3): MAC-then-encrypt SM4-CBC or SM4-GCM, with `seq` / `type` / `version` bound into the MAC/AAD |
| key encapsulation | 密钥封装 | |
| MAC | MAC | acronym kept English |
| HMAC | HMAC | acronym kept English |
| AEAD | AEAD | gloss: 认证加密 (authenticated encryption) |
| authentication tag | 认证标签 | also "tag" alone → 标签 |
| postfix tag / detached tag | 后置标签 / 分离标签 | postfix = appended as `ciphertext ‖ tag` in one buffer; detached = returned separately from the ciphertext |
| nonce | nonce | acronym kept English; gloss: 一次性数 |
| IV | IV | acronym kept English; gloss: 初始化向量 (initialization vector) |
| counter | 计数器 | for CTR mode |
| salt | 盐值 | |
| iteration count | 迭代次数 | |
| signer ID | 签名者 ID | SM2 Z-value input; ID kept English |
| Z value | Z 值 | SM2 user-identity hash |
| hash / digest | 哈希 / 摘要 | "hash" for the operation, "digest" for the output |
| randomness / RNG | 随机性 / RNG | RNG acronym kept English |
| sector / data unit | 扇区 / 数据单元 | for XTS |
| tweak | tweak | XTS-specific; keep English |
| feature flag | 特性开关 / feature | "feature" alone also acceptable |
| crate | crate | Rust ecosystem term; keep English |
| trait | trait | Rust ecosystem term; keep English (as with "crate") |
| sealed trait | 密封 trait | a trait only the defining crate can implement; used to fix a closed set (CCM's legal tag/nonce sizes) |
| RustCrypto | RustCrypto | the Rust cryptography organisation and its trait ecosystem (`aead`, `digest`, `cipher`); proper noun, not translated |
| companion crate | 配套 crate | a separate crate the caller must add themselves because the primary crate does not re-export it (`aead`, `digest`, `cipher` — one per trait fit) |
| UFCS / fully-qualified syntax | 完全限定语法 | `<T as Trait>::method(..)`; required where an inherent method of the same name would win instead (`Sm3`, `HmacSm3`, `Sm4Cipher`) |
| ECB | ECB(电码本模式) | enciphering each block independently under one key, so equal plaintext blocks give equal ciphertext blocks; keep the acronym English |
| round-trip | 往返 | as in "encrypt-then-decrypt round-trip" |
| constant-time comparison | 恒定时间比较 | |
| side channel | 侧信道 | |
| sample / fixture | 示例 / 测试用例 | "demo fixture" → 演示用样例 |
| production-safe | 生产安全 | "not production-safe" → 非生产安全 |
| catastrophic | 灾难性 | as in "nonce reuse in GCM is catastrophic" |
| scalar | 标量 | as in "32-byte big-endian scalar" for SM2 private keys |
| cross-cutting | 横向 | as in "cross-cutting review" → 横向回顾 |
| password | 口令 | preferred over 密码 to avoid ambiguity with "cipher" (密码 also means cipher in Chinese) |
| authenticated encryption | 认证加密 | full form of AEAD |
| non-repudiation | 不可抵赖性 | core property of digital signatures |
| hybrid (encryption pattern) | 混合加密 | as in "SM2-wraps-SM4-GCM hybrid pattern" |
| smoke test | 冒烟测试 | as in "downstream smoke-test demo" |
| downstream | 下游 | as in "downstream consumer of the published crate" |
| tour | 演示巡览 | the CLI walkthrough; the `tour` subcommand name itself stays English in backticks |
| wire format | 线上字节格式 | the on-the-wire byte representation of signatures / ciphertexts / SM4 mode outputs; frozen as of `gmcrypto-core 1.0.0` and identical to the prior 0.16.0 line |
| thin wrapper | 薄封装 | a type that delegates to an existing API and adds no logic of its own |
| compile time / run time | 编译期 / 运行期 | as in "CCM's tag/nonce sizes are checked at compile time, not at run time" |
| opaque error | 不透明错误 | an error type carrying no distinguishing detail, e.g. `aead::Error` |
| in-place | 原地 | operating on the caller's buffer; note it does **not** imply "without allocating" |
