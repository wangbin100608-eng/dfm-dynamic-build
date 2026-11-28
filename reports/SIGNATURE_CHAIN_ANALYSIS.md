# 签名链路静态分析报告（阶段2 · 离线可验证部分）

> 作者：ProtoSig · 生成时间：2026-11-28（UTC）
> 样本：`/root/三角洲/dfm-apk/so-analysis/libUE4.so`，561,598,448 字节，arm64-v8a。
> 工具：`tools/emu/analyze_signature_chain.py`、`capstone 5.0.7`、`find_xrefs.py`；结构化证据见 `reports/signature-chain-static.json`。
> 边界：本报告只做本机静态分析，不发包、不改目标、不写生产实例；所有"算法判断"均附证据，缺证据处明确标注未知。

## 1. 给定"函数偏移"的实测性质

任务给定 7 个符号偏移，全部落在 PT_LOAD 可执行段（flags=5），但**字节内容不是可反汇编的函数序言**：

| 符号 | 给定偏移 | 明文/XOR-0x10 命中 | capstone 线性反汇编首指令 | 实测字节形态 |
|---|---|---|---|---|
| SendTssData | 0x5c32655 | XOR×3 | `udf` | `55 71 08 08` + 大量 0x10 对齐表项 → protobuf descriptor 表 |
| TssSDKOnRecvSignature | 0x4d7c3de | 明文×1（在 ELF 头部，非代码） | `stxr` | `44 0b 2c 00` + `10 9e 02 9d 04` varint 序列 → descriptor 数据 |
| InitTss | 0x592d059 | XOR×3 | `strb` | `0c 1d 10 9e 02 9d 04` → descriptor 数据 |
| EVP_DigestSignInit | 0x4d7699f | 0/0 | 无有效指令 | `00 9c f8 cb 04` + varint 序列 |
| EVP_PKEY_sign | 0x4fbb9e5 | XOR×2 | 无有效指令 | varint 序列 |
| RSA_sign | 0x4fbba6b | XOR×2 | `adr` (乱码入口) | 长度/指针表项 |
| sha256WithRSAEncryption | 0x5e91ffd | XOR×1 | 无有效指令 | 指针表项 |

**结论**：这 7 个偏移是符号/字符串在 descriptor 表中的位置或名称池位置，不是函数入口。
`find_xrefs.py` 对这些字符串做 ADRP+ADD / LDR-literal 反查，均**未命中**（结果见 `reports/sig-symbol-xrefs.json`、`reports/xref-sha256rsa.json`、`reports/xref-md5rsa.json`）；说明这些字符串通过间接表/自定义寻址引用，纯静态拿不到调用点。

因此：**阶段2 不产出"从反汇编恢复出的签名算法实现"**——那需要真机 hook 拿运行时函数地址与参数（见第 4 节）。本阶段产出的是可验证的栈存在性、算法候选与运行时输入清单。

## 2. so 中密码学栈的字符串证据

关键符号在 so 里几乎全部以 **XOR-0x10** 编码存储（字节级验证：解码后为 NUL 终止 ASCII 串）；`.dynsym` 动态符号表未导出这些 OpenSSL 函数（静态链接 OpenSSL）。

| 类别 | 符号 | 证据（XOR-0x10 文件偏移） |
|---|---|---|
| TSS 入口 | `SendTssData` | 0x188cc71、0x27c797a、0x2860eb8 |
| TSS 入口 | `InitTss` | 0x1cce45e、0x1ea042e、0x24b713e |
| TSS 回调 | `TssSDKOnRecvSignature` | 明文 @0xc082（字符串池） |
| RSA 签名 | `RSA_sign` | 0x244c24e、0x27f9c25 |
| RSA 签名 | `RSA_private_encrypt` | 0x21dae4c |
| EVP 签名 | `EVP_PKEY_sign` / `EVP_PKEY_sign_init` | 0x1b2ef3f（两串相邻） |
| EVP 签名 | `EVP_SignFinal` | 0x18bf328 |
| 哈希 OID 名 | `sha256WithRSAEncryption` | 0x1f7006f |
| 哈希 OID 名 | `md5WithRSAEncryption` | 0x1d9ac64 |
| 哈希 OID 名 | `sha1WithRSAEncryption` | 0x26c0908 |
| 密钥加载 | `d2i_PrivateKey` | 0x24e949e |
| 验签 | `RSA_verify` / `EVP_PKEY_verify` | 0x1787088 / 0x164eae2 等 |
| 安全协议 | `cscpp_security.pb.cpp` / `cscpp_tss.pb.cpp` | 0x21dae4c 附近 / 0x244c24e 附近 |

邻近上下文（`annotate_configs.py` 输出的 XOR 解码窗口）显示这些名字位于 OpenSSL 字符串池：`RSA_sign` 旁有 `RSA_NULL_PRIVATE_ENCRYPT`、`unsupported signature type`；`sha256WithRSAEncryption` 旁有 `RSA-SHA384`、`hmac-sha1`、`CAMELLIA-128-ECB`；`EVP_SignFinal` 旁有 `jni/../../openssl/crypto/evp/evp_lib.c`。说明这是**静态链接的 OpenSSL**。

## 3. 算法判断（附证据强度）

| 问题 | 判断 | 证据 / 可信度 |
|---|---|---|
| 是否 RSA 非对称签名？ | **是**（栈存在性 high） | `RSA_sign`、`RSA_private_encrypt`、`EVP_PKEY_sign`、`d2i_PrivateKey` 全部命中；mid |
| padding 是否 PKCS#1 v1.5？ | **很可能**（medium） | `RSA_sign(type, ...)` 与 `md5/sha256WithRSAEncryption` OID 名存在，对应 PKCS#1 v1.5 的 DigestInfo 封装；`EVP_PKEY_sign` 默认 padding 即 PKCS#1 v1.5，除非显式设 PSS；未见 `RSA_PKCS1_PSS_PADDING` 字符串 |
| 哈希是 SHA-256 还是 MD5？ | **未定**（unknown） | 三种 OID 名同时存在：`sha256WithRSAEncryption`、`md5WithRSAEncryption`、`sha1WithRSAEncryption`。静态无法把某一个绑定到 TSS 调用路径；历史 DEX 报告 `SIGNING_NOTES.md` 有 `get md5 form native` 日志字符串（不同层），但不证明网关签名用 MD5 |
| 是否 HMAC/AES 参与？ | **存在栈，角色未定** | `HMAC` 明文×1 + XOR×12，`AES_cbc_encrypt` XOR 0 次（但 `AES_cbc_encrypt` 的历史偏移 0x4fbe54c 处为 descriptor，不能据此否认；AESNI_INIT_KEY / AES-192-CFB8 等字符串存在） |
| 能否静态提取私钥？ | **否** | `d2i_PrivateKey` 只是函数字符串；so 中无 PEM/PKCS#8 blob 证据；TSS SDK 密钥由运行时下发/设备绑定 |

**综合**：签名链路形态 = 客户端调用 TSS SDK → SDK 内用静态链接 OpenSSL 做 RSA 签名（大概率 PKCS#1 v1.5，摘要算法需在真机确认）。**这不是可以离线复刻的确定性函数**——输入摘要与密钥都在运行时。

## 4. 复现签名需要的运行时输入清单（缺一不可）

1. **待签名字节范围**：frame 中 `len`/`cmd_id`/`seq_id`/`body` 哪几段进入摘要；从 `dump_traffic.js` 的 `socket_send-*.bin` + hook 入参确定。
2. **摘要算法与 padding**：hook `RSA_sign` 的第一个参数 `type`（NID_sha256=672 等）和 `EVP_PKEY_sign` 的 `RSA_PKCS1_PSS_PADDING` 设置；或 hook `sha256WithRSAEncryption`/`md5WithRSAEncryption` 对应 EVP MD ctx。
3. **私钥/密钥句柄**：TSS SDK 内部，真机运行时持有；离线不可得。可通过 Frida 调 SDK 的 `sign(payload)` RPC 现算（probe_gateway.py 的 `--signature-mode frida` 已预留接口）。
4. **设备指纹**：qimei / oaid / 设备 ID，TSS 风控强相关。
5. **会话参数**：`cmd_id`、`seq_id`、uin、时间戳、session key / seed（若二次加密）。
6. **签名帧布局**：签名字节在帧中的偏移和长度（`frame.order` 默认把 `signature` 设为 `enabled:false`，必须抓包校准后启用）。

## 5. 与阶段1结论的一致性

阶段1 `GATEWAY_KEY_ANALYSIS.md` 已证明网关地址、cmd_id、签名、会话密钥四把钥匙均无法从静态/模拟获得；本阶段用 XOR-0x10 全量扫描和符号反查再次确认：**签名算法栈可见，签名输入不可见**。阶段2的可交付价值是把"不知道"收敛成"知道具体要抓哪些参数、hook 哪些函数"。

---

*证据文件：`reports/signature-chain-static.json`、`reports/sig-symbol-xrefs.json`、`reports/xref-sha256rsa.json`、`reports/xref-md5rsa.json`、`reports/xor-protobuf-messages.txt`。*
