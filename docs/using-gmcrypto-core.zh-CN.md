# 正确使用 `gmcrypto-core` —— 一份实战指南

> 🌐 **Language / 语言:** [English](using-gmcrypto-core.md) | **简体中文**

> 📖 **术语表:** 本文档术语翻译以 [`glossary.md`](glossary.md) 为准。

本文从下游使用者的视角出发,讲解如何**正确**使用已发布的
[`gmcrypto-core`](https://crates.io/crates/gmcrypto-core) crate(GM/T
**SM2 / SM3 / SM4**)。文中所有片段都来自 [`examples/`](../examples/) 目录下
可直接运行、可自我校验的示例程序。

**面向读者:** 想要第一次就把 SDK 调对、避开常见密码学陷阱(重复使用 nonce、
KDF 参数过弱、密文未认证、密钥材料泄露等)的 Rust 开发者。

**每个章节的结构:**

- **是什么** —— 用一两句话介绍该原语。
- **正确用法** —— 列出关键调用,并附可运行片段。
- **该做 / 不该做** —— 生产环境中真正重要的规则。
- **对应示例** —— `examples/` 下的文件以及运行命令。

> ⚠️ **本演示(以及本指南)中出现的所有密钥、IV、nonce、盐值和口令都是
> 固定的_公开样例_。** 它们的存在只是为了让片段可复现,**切勿**在真实数据
> 上复用;生产环境务必生成新的随机秘密。

<a id="the-golden-rules"></a>
## 黄金法则

1. **使用真正的 CSPRNG。** 从操作系统获取随机性(`getrandom::SysRng`),
   绝不要使用固定或低熵的种子。→ [§0](#0-getting-started-setup-rng-and-helpers)
2. **同一密钥下,绝不复用 nonce / IV / 计数器。** 这会以不同但同样致命的方式
   破坏 CTR、GCM 和 CBC。
   → [§6](#6-sm4-symmetric-encryption-cbc-and-ctr)–[§8](#8-sm4-xts-disk-and-sector-encryption)
3. **优先选择认证加密。** 默认使用 SM4-GCM;CBC / CTR / XTS 只提供机密性,
   **不**提供完整性。
   → [§7](#7-sm4-authenticated-encryption-gcm-and-ccm)
4. **调好你的 KDF。** 示例中的 PBKDF2 迭代次数为了速度刻意调得很低,
   生产环境需要远远更高的取值(OWASP 建议 ≥ 600,000)。
   → [§2](#2-message-authentication-and-key-derivation-hmac-sm3-pbkdf2)
5. **保护静态私钥。** 使用加密的 `PKCS#8`,并把口令排除在源码之外。
   → [§5](#5-sm2-key-management-and-serialization)
6. **以恒定时间比较秘密。** 使用 SDK 提供的 `verify(...)` 辅助函数,
   不要对标签使用 `==`。
   → [§2](#2-message-authentication-and-key-derivation-hmac-sm3-pbkdf2)

<a id="how-to-read-this-guide"></a>
## 如何阅读本指南

请把本指南当作一条引导式路径,而不是一组松散的笔记。先从环境搭建开始,
再依次走过 原语 → 密钥 / 签名 / 加密 → 对称模式 → 最终回顾。

| 阶段 | 阅读 | 你能获得 |
|---|---|---|
| 基础 | [§0](#0-getting-started-setup-rng-and-helpers) | 依赖配置、操作系统 RNG、共享辅助函数 |
| 哈希与密钥 | [§1](#1-sm3-hashing) → [§2](#2-message-authentication-and-key-derivation-hmac-sm3-pbkdf2) | SM3、HMAC-SM3、PBKDF2、恒定时间验证 |
| SM2 公钥密码 | [§3](#3-sm2-digital-signatures) → [§5](#5-sm2-key-management-and-serialization) | 签名、加密、密钥格式、加密的 `PKCS#8` |
| SM4 对称密码 | [§6](#6-sm4-symmetric-encryption-cbc-and-ctr) → [§8](#8-sm4-xts-disk-and-sector-encryption) | CBC、CTR、GCM、CCM、XTS,以及各模式特有的陷阱 |
| 回顾 | [§9](#9-doing-crypto-correctly-cross-cutting-review) | 跨章节规则:如何安全地选择并组合各原语 |

<a id="table-of-contents"></a>
## 目录

0. [起步:环境、RNG 与辅助函数](#0-getting-started-setup-rng-and-helpers)
1. [SM3 哈希](#1-sm3-hashing)
2. [消息认证与密钥派生(HMAC-SM3、PBKDF2)](#2-message-authentication-and-key-derivation-hmac-sm3-pbkdf2)
3. [SM2 数字签名](#3-sm2-digital-signatures)
4. [SM2 公钥加密](#4-sm2-public-key-encryption)
5. [SM2 密钥管理与序列化](#5-sm2-key-management-and-serialization)
6. [SM4 对称加密:CBC 与 CTR](#6-sm4-symmetric-encryption-cbc-and-ctr)
7. [SM4 认证加密:GCM 与 CCM](#7-sm4-authenticated-encryption-gcm-and-ccm)
8. [SM4-XTS 磁盘与扇区加密](#8-sm4-xts-disk-and-sector-encryption)
9. [正确地做密码学(跨章节回顾)](#9-doing-crypto-correctly-cross-cutting-review)

---

<a id="0-getting-started-setup-rng-and-helpers"></a>
## §0 起步:环境、RNG 与辅助函数

其他所有章节都建立在这一节的基础之上:如何添加 crate、如何获得高质量的
随机性,以及本演示用到的少量共享辅助函数。

<a id="add-the-dependency"></a>
### 添加依赖

本演示像外部用户那样,**严格精确地**钉住已发布的 crate ——
绝不使用 path / workspace / git 依赖:

```toml
[dependencies]
gmcrypto-core = "=0.16.0"
getrandom = { version = "0.4.2", features = ["sys_rng"], default-features = false }
rand_core = "0.10.1"
```

可选 feature 用于开启受门控的 SM4 模式(默认构建保持精简):

```toml
[features]
sm4-aead = ["gmcrypto-core/sm4-aead"]   # SM4-GCM / SM4-CCM
sm4-xts  = ["gmcrypto-core/sm4-xts"]     # SM4-XTS
```

<a id="get-randomness-right"></a>
### 正确使用随机性

SM2 的签名和加密都需要密码学安全的 RNG,而操作系统的 CSPRNG 正是合适的
来源。`getrandom::SysRng` 实现的是*可失败*的 `TryRngCore`;SM2 的 API 需要
*不可失败*的 `RngCore`,因此用 `UnwrapErr` 适配一次即可:

```rust
use getrandom::SysRng;
use rand_core::UnwrapErr;

/// OS CSPRNG, adapted to the infallible RngCore the SDK expects.
pub fn os_rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}
```

> - ✅ **该做:** 每次运行都从操作系统创建 RNG。
> - ⚠️ **不该做:** 在真实签名 / 密文场景下,把带种子或确定性的 RNG
>   (或任何固定值)交给 SDK —— 随机化的 SM2 每次调用都依赖新鲜熵。

<a id="load-the-sample-key"></a>
### 加载示例密钥

本指南重复使用一把固定的 GB/T 32918.2 示例私钥。在 0.16 版本中,推荐的
构造函数是 `from_bytes_be`,接受 32 字节大端标量:

```rust
use gmcrypto_core::sm2::{Sm2PrivateKey, Sm2PublicKey};

let bytes: [u8; 32] = /* decode "3945208F...4DF7C5B8" */;
let key = Sm2PrivateKey::from_bytes_be(&bytes).expect("valid scalar");
let public = Sm2PublicKey::from_point(key.public_key());
```

> ⚠️ 这个标量是一份**公开的**标准样例。任何真实用途都请自行生成私钥。

**对应代码:** [`src/lib.rs`](../src/lib.rs) —— `os_rng()`、
`sample_private_key()`、`sample_public_key()`、`encode_hex()` / `decode_hex()`。

---
