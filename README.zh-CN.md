# gm-crypto-rs-demo

> 🌐 [English](README.md) · [简体中文](README.zh-CN.md) · [📚 Guide](docs/using-gmcrypto-core.md) · [📚 中文指南](docs/using-gmcrypto-core.zh-CN.md)

已发布 crate [`gmcrypto-core`](https://crates.io/crates/gmcrypto-core)(GM/T
**SM2 / SM3 / SM4**)的可运行示例食谱。克隆、跑巡览、复制一段代码即可。

本仓库刻意精确钉住 crates.io 上的发布版本 —— 绝不用 path 或 workspace
检出 —— 因此也能冒烟测试外部用户实际拿到的内容:

```toml
gmcrypto-core = "=1.11.2"
```

本仓库中所有的示例密钥、IV、口令、签名者 ID 与输出均为公开演示素材,请勿用于真实数据。

<a id="start-here"></a>
## 从这里开始

```bash
cargo run -- tour
```

<a id="try-the-cli"></a>
## 试几个命令

下面的 CLI 子命令都是 `cargo run -- <subcommand>`。

用 SM3 对消息进行哈希:

```bash
cargo run -- hash abc
```

使用自定义 SM2 签名者 ID 进行签名与验证:

```bash
sig=$(cargo run --quiet -- sign hello --id alice@example)
cargo run -- verify hello "$sig" --id alice@example
```

用 SM2 进行加密与解密:

```bash
ct=$(cargo run --quiet -- encrypt "secret message")
cargo run -- decrypt "$ct"
```

用 SM4-CBC 进行加密与解密:

```bash
sm4=$(cargo run --quiet -- sm4-encrypt "bulk data")
cargo run -- sm4-decrypt "$sm4"
```

计算 HMAC-SM3:

```bash
cargo run -- hmac 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b "Hi There"
```

使用 PBKDF2-HMAC-SM3 派生密钥材料:

```bash
cargo run -- pbkdf2 password 73616c74 10000 32
```

<a id="capability-map"></a>
## 能力速查表

本演示暴露的能力,按「怎么用到」分组。门控行需要 `--features`(见示例食谱)。
横切检查清单在[指南 §9](docs/using-gmcrypto-core.zh-CN.md#9-doing-crypto-correctly-cross-cutting-review),不是单独的示例。

<a id="default-capabilities"></a>
### 默认能力

无需特性开关。这些是 SDK 固有 API,并且带 CLI 命令。

| 使用场景 | CLI | 示例 | 指南 |
| --- | --- | --- | --- |
| SM3 哈希(GB/T 32905) | `hash <msg>` | `sm3_hashing` | `§1` |
| HMAC-SM3 消息认证 | `hmac <key-hex> <msg>` | `hmac_and_kdf` | `§2` |
| PBKDF2-HMAC-SM3 口令拉伸 | `pbkdf2 <pw> <salt-hex> <iter> <len>` | `hmac_and_kdf` | `§2` |
| SM2 数字签名(GB/T 32918.2) | `sign` / `verify` | `sm2_sign_verify` | `§3` |
| SM2 公钥加密(GB/T 32918.4) | `encrypt` / `decrypt` | `sm2_encrypt_decrypt` | `§4` |
| SM2 密钥编码(PKCS#8 / SEC1 / SPKI / PEM) | `key-info` | `sm2_key_encoding` | `§5` |
| SM4-CBC / CTR 对称加密 | `sm4-encrypt` / `sm4-decrypt` | `sm4_cbc_ctr` | `§6` |

<a id="feature-gated-modes"></a>
### 门控模式

| 使用场景 | 示例 | 特性 | 指南 |
| --- | --- | --- | --- |
| SM4-GCM 认证加密(AEAD) | `sm4_aead` | `sm4-aead` | `§7` |
| SM4-CCM 认证加密(受限场景 AEAD) | `sm4_ccm` | `sm4-aead` | `§7` |
| SM4-GCM 流式加解密(分块 AEAD) | `sm4_streaming` | `sm4-aead` | `§7` |
| SM2 密钥交换(GB/T 32918.3,带确认 + 免确认) | `sm2_key_exchange` | `sm2-key-exchange` | — |
| TLCP 密钥编排(GB/T 38636 PRF) | `tlcp_key_schedule` | `tlcp` | — |
| TLCP 记录层保护(GB/T 38636 §6.3) | `tlcp_record` | `tlcp` | — |
| SM4-XTS 扇区/磁盘加密 | `sm4_xts` | `sm4-xts` | `§8` |

<a id="ecosystem-traits"></a>
### 生态 trait

除非你已经在写 RustCrypto 泛型代码(`D: Digest`、`BlockCipherEncrypt`、
`Aead`),否则跳过本组。上面的固有 API 才是默认路径。

| 使用场景 | 示例 | 特性 | 指南 |
| --- | --- | --- | --- |
| SM3 / HMAC-SM3 的 `digest` 0.11 形态(`Sm3` / `HmacSm3`) | `sm3_digest_traits` | `digest-traits` | `§1`、`§2` |
| SM4 分组原语的 `cipher` 0.5 形态(`Sm4Cipher`) | `sm4_cipher_traits` | `cipher-traits` | `§6` |
| SM4-GCM / CCM 的 `aead` 0.6 形态(`Sm4Gcm` / `Sm4Ccm`) | `sm4_aead_traits` | `aead-traits` | `§7` |

<a id="cookbook-examples"></a>
## 示例食谱

[`examples/`](examples/) 目录下的每个文件都是独立小程序,会说明自己在做什么
并自校验往返结果。CI 会运行全部示例。

<a id="default-examples"></a>
### 默认示例

| 示例 | 演示内容 | 运行命令 |
|---|---|---|
| `sm3_hashing` | SM3 单次哈希与流式哈希器 | `cargo run --example sm3_hashing` |
| `hmac_and_kdf` | HMAC-SM3(单次/流式/验证)与 PBKDF2-HMAC-SM3 | `cargo run --example hmac_and_kdf` |
| `sm2_sign_verify` | SM2 签名/验证、签名者 ID 的 `Z` 值、篡改拒绝 | `cargo run --example sm2_sign_verify` |
| `sm2_encrypt_decrypt` | SM2 公钥加密 | `cargo run --example sm2_encrypt_decrypt` |
| `sm2_key_encoding` | PKCS#8 / SEC1 / SPKI / PEM 与加密 PKCS#8 | `cargo run --example sm2_key_encoding` |
| `sm4_cbc_ctr` | SM4 CBC + CTR 与原始分组 | `cargo run --example sm4_cbc_ctr` |

<a id="feature-gated-examples"></a>
### 门控示例

| 示例 | 演示内容 | 运行命令 |
|---|---|---|
| `sm4_aead` | SM4-GCM 认证加密 | `cargo run --features sm4-aead --example sm4_aead` |
| `sm4_ccm` | SM4-CCM 的两种 nonce/标签形态(12+16、13+8) | `cargo run --features sm4-aead --example sm4_ccm` |
| `sm4_streaming` | SM4-GCM 流式加解密(分块处理) | `cargo run --features sm4-aead --example sm4_streaming` |
| `sm2_key_exchange` | SM2 密钥交换 —— 带确认与免确认(TLCP)两种形态 | `cargo run --features sm2-key-exchange --example sm2_key_exchange` |
| `tlcp_key_schedule` | TLCP PRF:主密钥、密钥块、Finished `verify_data` | `cargo run --features tlcp --example tlcp_key_schedule` |
| `tlcp_record` | TLCP 记录层保护/解保护:SM4-CBC(+ GCM)往返与拒绝 | `cargo run --features tlcp --example tlcp_record` |
| `sm4_xts` | SM4-XTS 扇区加密 | `cargo run --features sm4-xts --example sm4_xts` |

<a id="ecosystem-trait-examples"></a>
### 生态 trait 示例

| 示例 | 演示内容 | 运行命令 |
|---|---|---|
| `sm3_digest_traits` | SM3 / HMAC-SM3 的 RustCrypto `digest` 0.11 形态 —— 与 `sm3::hash`/`hmac_sm3` 逐字节一致 | `cargo run --features digest-traits --example sm3_digest_traits` |
| `sm4_cipher_traits` | `Sm4Cipher` 的 RustCrypto `cipher` 0.5 形态 —— 逐字节一致,以及多分组为何就是 ECB | `cargo run --features cipher-traits --example sm4_cipher_traits` |
| `sm4_aead_traits` | SM4-GCM/CCM 的 RustCrypto `aead` 0.6 形态 —— 与 `mode_gcm`/`mode_ccm` 逐字节一致 | `cargo run --features aead-traits --example sm4_aead_traits` |

<a id="guide"></a>
## 指南

各原语的该做/不该做 —— RNG、nonce 唯一性、认证与非认证模式、PBKDF2 迭代次数、
密钥存储,以及[选对工具速查表(§9)](docs/using-gmcrypto-core.zh-CN.md#9-doing-crypto-correctly-cross-cutting-review):
[`docs/using-gmcrypto-core.zh-CN.md`](docs/using-gmcrypto-core.zh-CN.md)
(英文版:[`docs/using-gmcrypto-core.md`](docs/using-gmcrypto-core.md))。

指南有两条轨道:**SDK 用法**是各节正文;**RustCrypto trait 形态**是 §1、§2、§6、
§7 末尾的可选 H3。

<a id="test"></a>
## 测试

```bash
cargo test
```
