# gm-crypto-rs-demo

> 🌐 [English](README.md) · [简体中文](README.zh-CN.md) · [📚 Guide](docs/using-gmcrypto-core.md) · [📚 中文指南](docs/using-gmcrypto-core.zh-CN.md)

已发布 crate [`gmcrypto-core`](https://crates.io/crates/gmcrypto-core)(GM/T
**SM2 / SM3 / SM4**)的可运行示例食谱。克隆仓库、运行演示巡览,再复制所需代码即可。

本仓库将依赖固定为 crates.io 上的精确发布版本,不使用 path 或 workspace
依赖,因此也能冒烟测试外部用户实际拿到的内容:

```toml
gmcrypto-core = "=1.13.0"
```

本仓库中所有的示例密钥、IV、口令、签名者 ID 与输出均为公开演示素材,请勿用于真实数据。

<a id="start-here"></a>
## 从这里开始

请先安装 Git 和 Rust 1.85 或更新版本(含 Cargo)。下文的 shell 示例使用
Bash/Zsh 语法。克隆仓库并运行演示巡览:

```bash
git clone https://github.com/frankxue831/gm-crypto-rs-demo.git
cd gm-crypto-rs-demo
cargo run -- tour
```

后续命令均在此目录中运行。首次运行会下载并编译依赖。

<a id="try-the-cli"></a>
## 试几个命令

下面的 CLI 子命令都是 `cargo run -- <subcommand>`。

SM2 命令使用仓库自带的示例密钥对,SM4 命令使用自带的示例密钥和 IV。
这些命令不接受用户自己的密钥;示例代码展示了如何显式传入密钥来调用 SDK。

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

本演示提供的能力,按使用方式分组。需要启用特性的条目使用 `--features`
(见[示例食谱](#cookbook-examples))。横向检查清单在[指南 §9](docs/using-gmcrypto-core.zh-CN.md#9-doing-crypto-correctly-cross-cutting-review),不是单独的示例。

<a id="default-capabilities"></a>
### 默认能力

无需特性开关。CLI 支持下表注明的操作,示例代码则展示更完整的 SDK API。

| 使用场景 | CLI | 示例 | 指南 |
| --- | --- | --- | --- |
| SM3 哈希(GB/T 32905) | `hash <msg>` | [`sm3_hashing`](examples/sm3_hashing.rs) | [§1](docs/using-gmcrypto-core.zh-CN.md#1-sm3-hashing) |
| HMAC-SM3 消息认证 | `hmac <key-hex> <msg>` | [`hmac_and_kdf`](examples/hmac_and_kdf.rs) | [§2](docs/using-gmcrypto-core.zh-CN.md#2-message-authentication-and-key-derivation-hmac-sm3-pbkdf2) |
| PBKDF2-HMAC-SM3 口令拉伸 | `pbkdf2 <pw> <salt-hex> <iter> <len>` | [`hmac_and_kdf`](examples/hmac_and_kdf.rs) | [§2](docs/using-gmcrypto-core.zh-CN.md#2-message-authentication-and-key-derivation-hmac-sm3-pbkdf2) |
| SM2 数字签名(GB/T 32918.2) | `sign` / `verify` | [`sm2_sign_verify`](examples/sm2_sign_verify.rs) | [§3](docs/using-gmcrypto-core.zh-CN.md#3-sm2-digital-signatures) |
| SM2 公钥加密(GB/T 32918.4) | `encrypt` / `decrypt` | [`sm2_encrypt_decrypt`](examples/sm2_encrypt_decrypt.rs) | [§4](docs/using-gmcrypto-core.zh-CN.md#4-sm2-public-key-encryption) |
| SM2 密钥编码(PKCS#8 / SEC1 / SPKI / PEM) | `key-info`(SEC1/SPKI 公钥,含 PEM;PKCS#8 仅在示例中) | [`sm2_key_encoding`](examples/sm2_key_encoding.rs) | [§5](docs/using-gmcrypto-core.zh-CN.md#5-sm2-key-management-and-serialization) |
| SM4-CBC / CTR 对称加密 | `sm4-encrypt` / `sm4-decrypt`(仅 CBC;CTR 仅在示例中) | [`sm4_cbc_ctr`](examples/sm4_cbc_ctr.rs) | [§6](docs/using-gmcrypto-core.zh-CN.md#6-sm4-symmetric-encryption-cbc-and-ctr) |

<a id="feature-gated-modes"></a>
### 需要启用特性的模式

| 使用场景 | 示例 | 特性 | 指南 |
| --- | --- | --- | --- |
| SM4-GCM 认证加密(AEAD) | [`sm4_aead`](examples/sm4_aead.rs) | `sm4-aead` | [§7](docs/using-gmcrypto-core.zh-CN.md#7-sm4-authenticated-encryption-gcm-and-ccm) |
| SM4-CCM 认证加密(受限场景 AEAD) | [`sm4_ccm`](examples/sm4_ccm.rs) | `sm4-aead` | [§7](docs/using-gmcrypto-core.zh-CN.md#7-sm4-authenticated-encryption-gcm-and-ccm) |
| SM4-GCM 流式加解密(分块 AEAD) | [`sm4_streaming`](examples/sm4_streaming.rs) | `sm4-aead` | [§7](docs/using-gmcrypto-core.zh-CN.md#7-sm4-authenticated-encryption-gcm-and-ccm) |
| SM4-CCM 流式加解密(长度提交的 AEAD) | [`sm4_ccm_streaming`](examples/sm4_ccm_streaming.rs) | `sm4-aead` | [§7](docs/using-gmcrypto-core.zh-CN.md#7-sm4-authenticated-encryption-gcm-and-ccm) |
| SM2 密钥交换(GB/T 32918.3,带确认 + 免确认) | [`sm2_key_exchange`](examples/sm2_key_exchange.rs) | `sm2-key-exchange` | [§11](docs/using-gmcrypto-core.zh-CN.md#11-sm2-key-exchange) |
| TLCP 密钥编排(GB/T 38636 PRF) | [`tlcp_key_schedule`](examples/tlcp_key_schedule.rs) | `tlcp` | [§12](docs/using-gmcrypto-core.zh-CN.md#12-tlcp-toolkit) |
| TLCP 记录层保护(GB/T 38636 §6.3) | [`tlcp_record`](examples/tlcp_record.rs) | `tlcp` | [§12](docs/using-gmcrypto-core.zh-CN.md#12-tlcp-toolkit) |
| TLCP 证书对(GB/T 38636 §4) | [`tlcp_chain`](examples/tlcp_chain.rs) | `tlcp`, `x509` | [§12](docs/using-gmcrypto-core.zh-CN.md#12-tlcp-toolkit) |
| X.509-with-SM2 叶子证书解析 / 签名校验 | [`x509_sm2`](examples/x509_sm2.rs) | `x509` | [§10](docs/using-gmcrypto-core.zh-CN.md#10-x509-with-sm2-certificates) |
| SM4-XTS 扇区/磁盘加密 | [`sm4_xts`](examples/sm4_xts.rs) | `sm4-xts` | [§8](docs/using-gmcrypto-core.zh-CN.md#8-sm4-xts-disk-and-sector-encryption) |

<a id="ecosystem-traits"></a>
### 生态 trait

除非你已经在写 RustCrypto 泛型代码(`D: Digest`、`BlockCipherEncrypt`、
`Aead`),否则跳过本组。上面的固有 API 才是默认路径。

| 使用场景 | 示例 | 特性 | 指南 |
| --- | --- | --- | --- |
| SM3 / HMAC-SM3 的 `digest` 0.11 形态(`Sm3` / `HmacSm3`) | [`sm3_digest_traits`](examples/sm3_digest_traits.rs) | `digest-traits` | [§1](docs/using-gmcrypto-core.zh-CN.md#1-sm3-hashing)、[§2](docs/using-gmcrypto-core.zh-CN.md#2-message-authentication-and-key-derivation-hmac-sm3-pbkdf2) |
| SM4 分组原语的 `cipher` 0.5 形态(`Sm4Cipher`) | [`sm4_cipher_traits`](examples/sm4_cipher_traits.rs) | `cipher-traits` | [§6](docs/using-gmcrypto-core.zh-CN.md#6-sm4-symmetric-encryption-cbc-and-ctr) |
| SM4-GCM / CCM 的 `aead` 0.6 形态(`Sm4Gcm` / `Sm4Ccm`) | [`sm4_aead_traits`](examples/sm4_aead_traits.rs) | `aead-traits` | [§7](docs/using-gmcrypto-core.zh-CN.md#7-sm4-authenticated-encryption-gcm-and-ccm) |

<a id="cookbook-examples"></a>
## 示例食谱

[`examples/`](examples/) 目录下的每个文件都是独立小程序,会说明自己在做什么
并自校验往返结果。CI 会运行全部示例。

<a id="default-examples"></a>
### 默认示例

| 示例 | 演示内容 | 运行命令 |
|---|---|---|
| [`sm3_hashing`](examples/sm3_hashing.rs) | SM3 单次哈希与流式哈希器 | `cargo run --example sm3_hashing` |
| [`hmac_and_kdf`](examples/hmac_and_kdf.rs) | HMAC-SM3(单次/流式/验证)与 PBKDF2-HMAC-SM3 | `cargo run --example hmac_and_kdf` |
| [`sm2_sign_verify`](examples/sm2_sign_verify.rs) | SM2 签名/验证、签名者 ID 的 `Z` 值、篡改拒绝 | `cargo run --example sm2_sign_verify` |
| [`sm2_encrypt_decrypt`](examples/sm2_encrypt_decrypt.rs) | SM2 公钥加密 | `cargo run --example sm2_encrypt_decrypt` |
| [`sm2_key_encoding`](examples/sm2_key_encoding.rs) | PKCS#8 / SEC1 / SPKI / PEM 与加密 PKCS#8 | `cargo run --example sm2_key_encoding` |
| [`sm4_cbc_ctr`](examples/sm4_cbc_ctr.rs) | SM4 CBC + CTR 与原始分组 | `cargo run --example sm4_cbc_ctr` |

<a id="feature-gated-examples"></a>
### 需要启用特性的示例

| 示例 | 演示内容 | 运行命令 |
|---|---|---|
| [`sm4_aead`](examples/sm4_aead.rs) | SM4-GCM 认证加密 | `cargo run --features sm4-aead --example sm4_aead` |
| [`sm4_ccm`](examples/sm4_ccm.rs) | SM4-CCM 的两种 nonce/标签形态(12+16、13+8) | `cargo run --features sm4-aead --example sm4_ccm` |
| [`sm4_streaming`](examples/sm4_streaming.rs) | SM4-GCM 流式加解密(分块处理) | `cargo run --features sm4-aead --example sm4_streaming` |
| [`sm4_ccm_streaming`](examples/sm4_ccm_streaming.rs) | SM4-CCM 流式加解密(长度提交的加密 / 缓冲解密) | `cargo run --features sm4-aead --example sm4_ccm_streaming` |
| [`sm2_key_exchange`](examples/sm2_key_exchange.rs) | SM2 密钥交换 —— 带确认与免确认(TLCP)两种形态 | `cargo run --features sm2-key-exchange --example sm2_key_exchange` |
| [`tlcp_key_schedule`](examples/tlcp_key_schedule.rs) | TLCP PRF:主密钥、密钥块、Finished `verify_data` | `cargo run --features tlcp --example tlcp_key_schedule` |
| [`tlcp_record`](examples/tlcp_record.rs) | TLCP 记录层保护/解保护:SM4-CBC(+ GCM)往返与拒绝 | `cargo run --features tlcp --example tlcp_record` |
| [`tlcp_chain`](examples/tlcp_chain.rs) | TLCP [签名,加密]证书对验证(叶子优先的证书链) | `cargo run --features tlcp,x509 --example tlcp_chain` |
| [`x509_sm2`](examples/x509_sm2.rs) | X.509-with-SM2 叶子证书解析 + 签名验证(解析不是信任判定) | `cargo run --features x509 --example x509_sm2` |
| [`sm4_xts`](examples/sm4_xts.rs) | SM4-XTS 扇区加密 | `cargo run --features sm4-xts --example sm4_xts` |

<a id="ecosystem-trait-examples"></a>
### 生态 trait 示例

| 示例 | 演示内容 | 运行命令 |
|---|---|---|
| [`sm3_digest_traits`](examples/sm3_digest_traits.rs) | SM3 / HMAC-SM3 的 RustCrypto `digest` 0.11 形态 —— 与 `sm3::hash`/`hmac_sm3` 逐字节一致 | `cargo run --features digest-traits --example sm3_digest_traits` |
| [`sm4_cipher_traits`](examples/sm4_cipher_traits.rs) | `Sm4Cipher` 的 RustCrypto `cipher` 0.5 形态 —— 逐字节一致,以及多分组为何就是 ECB | `cargo run --features cipher-traits --example sm4_cipher_traits` |
| [`sm4_aead_traits`](examples/sm4_aead_traits.rs) | SM4-GCM/CCM 的 RustCrypto `aead` 0.6 形态 —— 与 `mode_gcm`/`mode_ccm` 逐字节一致 | `cargo run --features aead-traits --example sm4_aead_traits` |

<a id="guide"></a>
## 指南

各原语的该做/不该做 —— RNG、nonce 唯一性、认证与非认证模式、PBKDF2 迭代次数、
密钥存储,以及[选对工具速查表(§9)](docs/using-gmcrypto-core.zh-CN.md#9-doing-crypto-correctly-cross-cutting-review):
[`docs/using-gmcrypto-core.zh-CN.md`](docs/using-gmcrypto-core.zh-CN.md)
(英文版:[`docs/using-gmcrypto-core.md`](docs/using-gmcrypto-core.md))。

指南有两条轨道:**SDK 用法**是各节正文;**RustCrypto trait 形态**是 §1、§2、§6、
§7 末尾的可选 H3。结尾的[工具箱各节(§10–§12)](docs/using-gmcrypto-core.zh-CN.md#10-x509-with-sm2-certificates)
覆盖 X.509-with-SM2、SM2 密钥交换与 TLCP 原语。

<a id="test"></a>
## 测试

先运行默认测试,再运行启用全部可选特性的测试:

```bash
cargo test
cargo test --all-features
```

编译全部示例:

```bash
cargo test --examples --all-features
```

这会检查示例能否构建,但不会执行 `main` 函数中的断言。请使用
[示例表格](#cookbook-examples)中的 `cargo run --example …` 命令运行示例;
CI 会运行表中的全部示例。
