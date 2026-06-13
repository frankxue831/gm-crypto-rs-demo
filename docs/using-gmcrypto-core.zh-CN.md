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

> 🛡️ **SDK 稳定性(1.0 起):** 自 `gmcrypto-core 1.0.0`(2026-06-01 发布)起,
> 该 SDK 进入 SemVer 稳定阶段。SM2 签名、SM2 密文与 SM4 各模式输出的
> **线上字节格式已冻结**,与 0.16.0 完全一致(上游已用 KAT 与 gmssl 互通
> 11/11 验证);破坏性的 *API 形态* 变更须经主版本号变更,上游由
> `cargo-semver-checks` 把关。在 0.16.0 下序列化得到的输出,在这里依然可读取
> 与验证。

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
gmcrypto-core = "=1.6.0"
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

<a id="1-sm3-hashing"></a>
## §1 SM3 哈希

**是什么:** SM3 是 GM/T 标准定义的 256 位密码学哈希(GB/T 32905-2016)——
SM 家族中对应于 SHA-256 的成员。

<a id="what-its-for"></a>
### 用途

完整性校验与指纹标识:校验和、去重键、内容寻址,以及作为 HMAC、PBKDF2
和 SM2 签名内部的构建模块。哈希提供的是一份防篡改指纹 —— **不**提供保密性,
也**不**提供身份认证。

<a id="correct-usage"></a>
### 正确用法

一次性调用:

```rust
use gmcrypto_core::sm3;
let digest = sm3::hash(b"abc"); // [u8; 32]
```

流式调用,适用于数据不能一次性全部拿到的场景:

```rust
use gmcrypto_core::sm3::Sm3;
let mut hasher = Sm3::new();
hasher.update(b"a");
hasher.update(b"bc");
let digest = hasher.finalize(); // identical to sm3::hash(b"abc")
```

<a id="do--dont"></a>
### Do / Don't

> - ✅ **该做:** 对于大数据,用 `update()` 流式喂入,而不是先在内存里拼接。
> - ✅ **该做:** 把 SM3 用于完整性校验,以及作为 HMAC / 签名的输入。
> - ⚠️ **不该做:** 用 SM3 直接对裸口令做哈希再存储 —— 请改用 PBKDF2-HMAC-SM3([§2](#2-message-authentication-and-key-derivation-hmac-sm3-pbkdf2))。
> - ⚠️ **不该做:** 把哈希当作身份认证 —— 任何人都能重新计算出来。要证明来源请使用 HMAC 或签名。

**对应示例:** `cargo run --example sm3_hashing`

---

<a id="2-message-authentication-and-key-derivation-hmac-sm3-pbkdf2"></a>
## §2 消息认证与密钥派生(HMAC-SM3, PBKDF2)

**是什么:** 两个建立在 SM3 之上的带密钥构造。HMAC-SM3 用于证明消息出自
持有共享密钥的一方;PBKDF2-HMAC-SM3 则把口令拉伸成密钥材料。

<a id="hmac-sm3--authenticate-a-message"></a>
### HMAC-SM3 — 消息认证

```rust
use gmcrypto_core::hmac::{hmac_sm3, HmacSm3};

let tag = hmac_sm3(key, msg);        // one-shot -> [u8; 32]

let mut mac = HmacSm3::new(key);     // streaming
mac.update(b"authenticated ");
mac.update(b"message");
let tag = mac.finalize();
```

使用内建的**恒定时间**校验来验证 —— 绝不要用 `==`:

```rust
let mut mac = HmacSm3::new(key);
mac.update(msg);
assert!(mac.verify(&tag));            // constant-time comparison
```

> ⚠️ **不该做:** 用 `tag == expected` 比较认证标签 —— 逐字节 `==` 会泄露
> 时间信息,从而被用于伪造。请使用 `verify()`。

<a id="pbkdf2-hmac-sm3--derive-a-key-from-a-password"></a>
### PBKDF2-HMAC-SM3 — 从密码派生密钥

```rust
use gmcrypto_core::kdf::pbkdf2_hmac_sm3;
let mut derived = [0u8; 32];
pbkdf2_hmac_sm3(password, salt, 600_000, &mut derived).expect("kdf");
```

相同口令 + 相同盐值始终派生出相同的密钥;盐值不同则结果发散。

<a id="do--dont-1"></a>
### Do / Don't

> - ✅ **该做:** 为每个口令使用唯一的随机盐值(≥ 16 字节)。
> - ✅ **该做:** 选择较高的迭代次数 —— OWASP 建议 **≥ 600,000**。(示例中使用 10,000 仅是为了运行得快。)
> - ⚠️ **不该做:** 在多个用户之间复用同一盐值,或把盐值硬编码。
> - ⚠️ **不该做:** 用裸的 SM3 哈希做口令存储。

**对应示例:** `cargo run --example hmac_and_kdf`

---

<a id="3-sm2-digital-signatures"></a>
## §3 SM2 数字签名

**它是什么:** SM2 是 GM/T 椭圆曲线密码体系(GB/T 32918)。签名带来**真实性**与**不可抵赖性**:私钥持有者进行签名,任何拥有公钥的人都可以验证。

<a id="the-signer-id-and-z"></a>
### 签名者 ID 与 Z 值

SM2 会把签名者身份哈希(`Z`)折入消息哈希。除非协议另有规定,否则使用 `DEFAULT_SIGNER_ID` —— 而且签名方与验证方**必须**使用同一个。

```rust
use gmcrypto_core::sm2::{sign_with_id, verify_with_id, DEFAULT_SIGNER_ID};

let mut rng = os_rng();
let sig = sign_with_id(&key, DEFAULT_SIGNER_ID, msg, &mut rng).expect("sign");
let ok  = verify_with_id(&public, DEFAULT_SIGNER_ID, msg, &sig); // -> bool
```

SM2 签名是**随机化**的:对同一条消息签两次会得到两个不同(但都有效)的签名。这是预期行为,不是 bug。

<a id="do--dont-2"></a>
### Do / Don't

> - ✅ **该做:** 用与签名时*相同*的签名者 ID 进行验证。
> - ✅ **该做:** 给签名传入一个新的 OS RNG([§0](#0-getting-started-setup-rng-and-helpers))。
> - ⚠️ **不该做:** 假设签名是确定性的,或按相等性比较签名。
> - ⚠️ **不该做:** 把签名(真实性)与加密(机密性)混为一谈 —— 它们解决的是不同的问题。

**对应示例:** `cargo run --example sm2_sign_verify`

---

<a id="4-sm2-public-key-encryption"></a>
## §4 SM2 公钥加密

**它是什么:** SM2 可以用接收者的公钥进行加密(GB/T 32918.4)。只有持有对应私钥的人才能解密。

<a id="correct-usage-1"></a>
### 正确用法

```rust
use gmcrypto_core::sm2::{encrypt, decrypt};

let mut rng = os_rng();
let ciphertext = encrypt(&public, plaintext, &mut rng).expect("encrypt"); // DER bytes
let recovered  = decrypt(&key, &ciphertext).expect("decrypt");
```

加密是随机化的 —— 每次调用产生的密文都不同。解密会校验内嵌的 `C3` 哈希,因此被破坏的密文会被**拒绝**(返回 `Err`),而不是被悄悄地解出错误内容。

<a id="when-to-use-it"></a>
### 何时使用

SM2 加密适用于**小**载荷 —— 通常是封装一个对称密钥或一段较短的秘密。批量数据请使用**混合加密**方案:生成一个随机的 SM4 密钥,用 SM4-GCM([§7](#7-sm4-authenticated-encryption-gcm-and-ccm))加密数据,再用 SM2 加密这个 SM4 密钥。

<a id="do--dont-3"></a>
### Do / Don't

> - ✅ **该做:** 用 SM2 封装一个对称密钥,再用 SM4 加密载荷。
> - ✅ **该做:** 把解密返回的 `Err` 当作"拒绝此消息",而不是"重试"。
> - ⚠️ **不该做:** 用 SM2 直接加密大块数据 —— 它很慢,也并非为此设计。

**对应示例:** `cargo run --example sm2_encrypt_decrypt`

---

<a id="5-sm2-key-management-and-serialization"></a>
## §5 SM2 密钥管理与序列化

**它是什么:** 如何以标准格式存储、加载和交换 SM2 密钥 —— 以及如何在静态存储时保护私钥。

<a id="the-formats"></a>
### 编码格式

- **`PKCS#8`** —— 标准的私钥容器(`DER`)。
- **`SEC1`** —— EC 私钥编码。
- **`SPKI`** —— 标准的公钥容器(`DER`)。
- **`PEM`** —— 包裹上述任一种的 base64 文本封装。
- **`加密的 PKCS#8`** —— 用口令加密后的私钥。

```rust
use gmcrypto_core::{pem, pkcs8, sec1, spki};

// Private key -> PKCS#8 DER -> PEM and back
let der = pkcs8::encode(&key);
let pem_str = pem::encode("PRIVATE KEY", &der);
let der2 = pem::decode(&pem_str, "PRIVATE KEY").expect("pem");
let key2 = pkcs8::decode(&der2).expect("pkcs8");

// Public key -> SPKI DER
let spki_der = spki::encode(&key.public_key());

// Private key at rest -> encrypted PKCS#8 (a wrong password is rejected)
let enc = pkcs8::encrypt(&key, password, salt, 600_000, &iv).expect("encrypt");
let key3 = pkcs8::decrypt(&enc, password).expect("decrypt");
```

<a id="do--dont-4"></a>
### Do / Don't

> - ✅ **该做:** 把私钥以**加密的** `PKCS#8` 形式存储,使用随机的盐值 + IV 以及较高的迭代次数。
> - ✅ **该做:** 以 `SPKI` / `PEM` 形式分发公钥,便于互通。
> - ⚠️ **不该做:** 把私钥(无论是否加密)或其口令提交到源码仓库。
> - ⚠️ **不该做:** 在多个密钥之间复用同一个加密盐值或 IV。

**对应示例:** `cargo run --example sm2_key_encoding`

---

<a id="6-sm4-symmetric-encryption-cbc-and-ctr"></a>
## §6 SM4 对称加密：CBC 与 CTR

**它是什么:** SM4 是 GM/T 的 128 位分组密码(GB/T 32907-2016),是 SM 家族中
对应 AES 的算法。CBC 和 CTR 是经典的工作模式,**仅提供机密性**。

<a id="correct-usage-2"></a>
### 正确用法

```rust
use gmcrypto_core::sm4::{mode_cbc, mode_ctr};

// CBC needs a 16-byte IV
let ct = mode_cbc::encrypt(&key, &iv, plaintext);
let pt = mode_cbc::decrypt(&key, &iv, &ct).expect("cbc");

// CTR needs a 16-byte initial counter block
let ct = mode_ctr::encrypt(&key, &counter, plaintext);
let pt = mode_ctr::decrypt(&key, &counter, &ct);
```

原始的单块原语(`Sm4Cipher::new(&key).encrypt_block(&mut block)`)也可使用,
但你几乎总是需要某种工作模式,而不是裸的分组操作。

<a id="the-one-rule-that-matters-never-reuse-the-iv--counter-under-a-key"></a>
### 唯一重要的规则：同一密钥下绝不重用 IV / 计数器

> - ⚠️ **CTR:** 重用 `(key, counter)` 对会泄漏两段明文的 XOR —— 后果是灾难性的。
> - ⚠️ **CBC:** 可预测或被重用的 IV 会使其遭受选择明文攻击。
> - ✅ **该做:** 为每条消息生成全新的随机 IV / 计数器,并与密文一起存储或发送(它本身不是秘密)。

<a id="bigger-caveat-these-are-unauthenticated"></a>
### 更大的注意事项：这些模式不带认证

CBC 和 CTR 无法检测篡改 —— 攻击者可以翻转比特,而解密不会报错。

> ✅ **该做:** 优先使用 **SM4-GCM**([§7](#7-sm4-authenticated-encryption-gcm-and-ccm))。
> 如果必须使用 CBC / CTR,请在密文之上叠加一层 HMAC-SM3(先加密后 MAC)。

**对应示例:** `cargo run --example sm4_cbc_ctr`

---

<a id="7-sm4-authenticated-encryption-gcm-and-ccm"></a>
## §7 SM4 认证加密：GCM 与 CCM

**它是什么:** SM4-GCM 是**带关联数据的认证加密(AEAD)**:它在一步内同时
完成加密*与*认证,因此解密时能检测出篡改。这应是你做对称加密时的默认选择。

> 🧩 **需要开启特性:** `gmcrypto-core = { version = "=1.6.0", features = ["sm4-aead"] }`。
> SM4-CCM 位于同一特性之下,通过 `sm4::mode_ccm` 使用。

<a id="correct-usage-3"></a>
### 正确用法

```rust
use gmcrypto_core::sm4::mode_gcm;

let nonce = /* 12 random bytes, unique per key */;
let (ciphertext, tag) = mode_gcm::encrypt(&key, &nonce, aad, plaintext);

// decrypt returns None if the ciphertext, tag, OR aad was altered
let pt = mode_gcm::decrypt(&key, &nonce, aad, &ciphertext, &tag).expect("auth ok");
```

`aad`(关联数据)会被认证但**不会**被加密 —— 用它承载那些必须与密文绑定、
但可以明文传输的头部 / 元数据。

<a id="do--dont-5"></a>
### Do / Don't

> - ⚠️ **不该做:绝不重用 `(key, nonce)` 对。** GCM 中重用 nonce 是灾难性的 —— 会泄漏认证密钥。每条消息都应使用全新的 96 位 nonce。
> - ✅ **该做:** 把 `decrypt` 返回的 `None` 视为"拒绝" —— 绝不退而求其次地使用那些字节。
> - ✅ **该做:** 把你必须信任的元数据(版本、头部、接收方)放进 `aad`。

**对应示例:** `cargo run --features sm4-aead --example sm4_aead`

**另见:** `cargo run --features sm4-aead --example sm4_ccm`(SM4-CCM),以及 `cargo run --features sm4-aead --example sm4_streaming`(分块流式 SM4-GCM,使用 Sm4GcmEncryptor / Sm4GcmDecryptor)。

---

<a id="8-sm4-xts-disk-and-sector-encryption"></a>
## §8 SM4-XTS 磁盘/扇区加密

**它是什么:** SM4-XTS 是为块存储上的**静态存储**数据设计的模式 ——
全盘加密、扇区、文件 —— 在这些场景中,密文长度不能增长。每个数据单元
都用一个 **tweak**(通常是其扇区号)进行加密。

> 🧩 **需要开启特性:** `features = ["sm4-xts"]`。

<a id="correct-usage-4"></a>
### 正确用法

```rust
use gmcrypto_core::sm4::mode_xts;

// 32-byte key = TWO distinct 16-byte subkeys; identical halves are rejected (GB/T 17964)
let ct = mode_xts::encrypt(&key32, &tweak, sector).expect("xts");   // data unit >= 16 bytes
let pt = mode_xts::decrypt(&key32, &tweak, &ct).expect("xts");
```

<a id="do--dont-6"></a>
### Do / Don't

> - ⚠️ **XTS 不带认证。** 用错误的 tweak(或被篡改的密文)解密只会返回*乱码*,不会报错。它在磁盘上保护机密性,而不是完整性。
> - ✅ **该做:** 使用存储位置(扇区索引)作为 tweak。
> - ✅ **该做:** 确保两个密钥半部互不相同。
> - ⚠️ **不该做:** 不要用 XTS 加密传输中的消息 —— 当你需要篡改检测时,请使用 SM4-GCM([§7](#7-sm4-authenticated-encryption-gcm-and-ccm))。

**对应示例:** `cargo run --features sm4-xts --example sm4_xts`

---

<a id="9-doing-crypto-correctly-cross-cutting-review"></a>
## §9 正确做加密（横向回顾）

贯穿每个原语的原则。如果本指南其他内容你都忘了,请记住这些。

<a id="1-randomness"></a>
### 1. 随机性

密钥、nonce、IV、盐值始终从操作系统的 CSPRNG 取得。在本 SDK 中,这就是用
`rand_core::UnwrapErr` 包装的 `getrandom::SysRng`
([§0](#0-getting-started-setup-rng-and-helpers))。绝不能用常量,也不能用低熵种子。

<a id="2-uniqueness-of-nonces--ivs--counters"></a>
### 2. nonce / IV / 计数器的唯一性

| Mode | 需要唯一的值 | 重用的代价 |
|---|---|---|
| SM4-CTR | 初始计数器 | 泄漏两段明文的 XOR |
| SM4-CBC | IV | 容易遭受选择明文攻击 |
| SM4-GCM | 96 位 nonce | **灾难性** —— 可能泄漏认证密钥 |
| SM4-XTS | tweak(每扇区一个) | 相同明文块在跨扇区时会泄漏 |

每条消息都重新生成;nonce 或 IV 与密文一起传输 / 存储 —— 它们不是秘密。

<a id="3-authentication"></a>
### 3. 认证

加密 ≠ 完整性。CBC、CTR、XTS 都不带认证。默认选用 **SM4-GCM**;否则先加密后用
HMAC-SM3 做 MAC。任何认证失败(`Err` / `None` / `false`)都必须视为“拒绝”,绝
不能“反正用这些字节”。

<a id="4-key-derivation-and-passwords"></a>
### 4. 密钥派生与口令

绝不要对口令做原始哈希存储。使用 PBKDF2-HMAC-SM3,配合唯一的随机盐值和较高的
迭代次数(OWASP 建议 ≥ 600,000)。演示中的 10,000 仅为提速所用。

<a id="5-constant-time-comparison"></a>
### 5. 恒定时间比较

比较 MAC / 标签时使用所提供的 `verify()`(恒定时间),而不是 `==`。

<a id="6-key-management"></a>
### 6. 密钥管理

私钥保存为加密的 `PKCS#8`,口令置于源码控制之外。公钥以 `SPKI` / `PEM` 形式
分享。轮换密钥;不要把同一把密钥用于互不相关的用途。

<a id="7-pick-the-right-tool"></a>
### 7. 选用合适的工具

| Goal | Use |
|---|---|
| 指纹 / 完整性校验 | SM3 |
| 证明消息出处(共享密钥) | HMAC-SM3 |
| 证明出处(可公开验证) | SM2 signature |
| 向某人加密一段小数据 | SM2 encryption |
| 批量加密(带完整性) | SM4-GCM |
| 加密磁盘上的静态数据 | SM4-XTS |
| 把口令转换为密钥 | PBKDF2-HMAC-SM3 |

> ⚠️ **请牢记:** 本演示中的每一把密钥、nonce、盐值和口令都是公开的演示样例。
> 生产代码必须自行生成。
