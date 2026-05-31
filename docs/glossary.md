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
| key agreement | 密钥协商 | |
| key derivation | 密钥派生 | |
| key encapsulation | 密钥封装 | |
| MAC | MAC | acronym kept English |
| HMAC | HMAC | acronym kept English |
| AEAD | AEAD | gloss: 认证加密 (authenticated encryption) |
| authentication tag | 认证标签 | also "tag" alone → 标签 |
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
