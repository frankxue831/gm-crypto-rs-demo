# gm-crypto-rs-demo

> 🌐 [English](README.md) · [简体中文](README.zh-CN.md) · [📚 Guide](docs/using-gmcrypto-core.md) · [📚 中文指南](docs/using-gmcrypto-core.zh-CN.md)

已发布 crate [`gmcrypto-core`](https://crates.io/crates/gmcrypto-core) 的下游 SDK 演示巡览。

本仓库刻意依赖 crates.io 上的发布版本:

```toml
gmcrypto-core = "=1.6.0"
```

它没有 path / workspace 依赖,不引用本地 `gm-crypto-rs` 检出。因此本仓库可作为冒烟测试,验证外部用户从已发布 crate 实际拿到的内容。

本仓库中所有的示例密钥、IV、口令、签名者 ID 与输出均为公开演示素材,请勿用于真实数据。

<a id="quick-tour"></a>
## 快速巡览

运行完整演示巡览:

```bash
cargo run -- tour
```

<a id="commands"></a>
## 命令

| 类别 | 命令 | 展示内容 |
| --- | --- | --- |
| SM3 | `hash <message>` | SM3 单次哈希摘要 |
| SM2 | `sign <message> [--id <signer-id>]` | SM2 签名(可使用默认或自定义签名者 ID) |
| SM2 | `verify <message> <der-signature-hex> [--id <signer-id>]` | SM2 签名验证 |
| SM2 | `key-info` | SEC1、SPKI DER 与 SPKI PEM 公钥导出 |
| SM2 | `encrypt <message>` | SM2 公钥加密,输出 DER 密文十六进制 |
| SM2 | `decrypt <der-ciphertext-hex>` | SM2 私钥解密 |
| SM4 | `sm4-encrypt <message>` | SM4-CBC 加密(使用固定演示密钥与 IV) |
| SM4 | `sm4-decrypt <ciphertext-hex>` | SM4-CBC 解密(使用同一组演示密钥与 IV) |
| MAC | `hmac <key-hex> <message>` | HMAC-SM3 |
| KDF | `pbkdf2 <password> <salt-hex> <iterations> <out-len>` | PBKDF2-HMAC-SM3 |

<a id="examples"></a>
## 示例

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

<a id="cookbook-examples"></a>
## 示例食谱

[`examples/`](examples/) 目录下的每个示例都是一个独立的小程序,会说明自己在做什么并自校验往返结果,因此也兼作冒烟测试(CI 会运行其中每一个):

| 示例 | 演示内容 | 运行命令 |
|---|---|---|
| `sm3_hashing` | SM3 单次哈希与流式哈希器 | `cargo run --example sm3_hashing` |
| `hmac_and_kdf` | HMAC-SM3(单次/流式/验证)与 PBKDF2-HMAC-SM3 | `cargo run --example hmac_and_kdf` |
| `sm2_sign_verify` | SM2 签名/验证、签名者 ID 的 `Z` 值、篡改拒绝 | `cargo run --example sm2_sign_verify` |
| `sm2_encrypt_decrypt` | SM2 公钥加密 | `cargo run --example sm2_encrypt_decrypt` |
| `sm2_key_encoding` | PKCS#8 / SEC1 / SPKI / PEM 与加密 PKCS#8 | `cargo run --example sm2_key_encoding` |
| `sm4_cbc_ctr` | SM4 CBC + CTR 与原始分组 | `cargo run --example sm4_cbc_ctr` |
| `sm4_aead` | SM4-GCM 认证加密 | `cargo run --features sm4-aead --example sm4_aead` |
| `sm4_ccm` | SM4-CCM 的两种 nonce/标签形态(12+16、13+8) | `cargo run --features sm4-aead --example sm4_ccm` |
| `sm4_streaming` | SM4-GCM 流式加解密(分块处理) | `cargo run --features sm4-aead --example sm4_streaming` |
| `sm2_key_exchange` | 带密钥确认的 SM2 密钥交换 | `cargo run --features sm2-key-exchange --example sm2_key_exchange` |
| `sm4_xts` | SM4-XTS 扇区加密 | `cargo run --features sm4-xts --example sm4_xts` |

上表中运行命令带 `--features …` 的示例即由对应特性开关控制;默认构建运行其余示例。

<a id="capability-map"></a>
## 能力速查表

本演示从 `gmcrypto-core` 中暴露的每项能力,对应到 CLI 子命令、示例食谱与指南章节。

| 使用场景 | CLI | 示例 | 指南 § |
| --- | --- | --- | --- |
| SM3 哈希(GB/T 32905) | `cargo run -- hash <msg>` | `examples/sm3_hashing.rs` | `§1` |
| HMAC-SM3 消息认证 | `cargo run -- hmac <key-hex> <msg>` | `examples/hmac_and_kdf.rs` | `§2` |
| PBKDF2-HMAC-SM3 口令拉伸 | `cargo run -- pbkdf2 <pw> <salt-hex> <iter> <len>` | `examples/hmac_and_kdf.rs` | `§2` |
| SM2 数字签名(GB/T 32918.2) | `cargo run -- sign` / `verify` | `examples/sm2_sign_verify.rs` | `§3` |
| SM2 公钥加密(GB/T 32918.4) | `cargo run -- encrypt` / `decrypt` | `examples/sm2_encrypt_decrypt.rs` | `§4` |
| SM2 密钥编码(PKCS#8 / SEC1 / SPKI / PEM) | `cargo run -- key-info` | `examples/sm2_key_encoding.rs` | `§5` |
| SM4-CBC / CTR 对称加密 | `cargo run -- sm4-encrypt` / `sm4-decrypt` | `examples/sm4_cbc_ctr.rs` | `§6` |
| SM4-GCM 认证加密(AEAD) | — | `examples/sm4_aead.rs`(特性 `sm4-aead`) | `§7` |
| SM4-CCM 认证加密(受限场景 AEAD) | — | `examples/sm4_ccm.rs`(特性 `sm4-aead`) | `§7` |
| SM4-GCM 流式加解密(分块 AEAD) | — | `examples/sm4_streaming.rs`(特性 `sm4-aead`) | `§7` |
| SM2 密钥交换(GB/T 32918.3) | — | `examples/sm2_key_exchange.rs`(特性 `sm2-key-exchange`) | — |
| SM4-XTS 扇区/磁盘加密 | — | `examples/sm4_xts.rs`(特性 `sm4-xts`) | `§8` |
| 横切正确性检查清单 | — | — | `§9` |
| 覆盖所有原语的端到端巡览 | `cargo run -- tour` | — | `§0`–`§9` |

<a id="guide"></a>
## 指南

若需要一份更深入的 do/don't 指南,逐个讲解如何正确使用每个原语 —— RNG 处理、nonce/IV 唯一性、认证加密与非认证模式、PBKDF2 迭代次数、密钥存储,以及一份"选对工具"速查表 —— 请见 [`docs/using-gmcrypto-core.zh-CN.md`](docs/using-gmcrypto-core.zh-CN.md)(英文版:[`docs/using-gmcrypto-core.md`](docs/using-gmcrypto-core.md))。

<a id="test"></a>
## 测试

```bash
cargo test
```
