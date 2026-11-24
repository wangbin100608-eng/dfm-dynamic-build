# tools/probe — UE4 私有网关 CS 消息探针（原型）

基于 `repo/reports/HAVAL_PURCHASE_API.md` 的静态逆向结论，本目录提供一个**可运行的原型**：在拿到真实客户端运行时的字段号/会话/签名后，直接构造并发送 `CSMallBuyReq` / `CSGetCurrencyReq` 等 CS 消息，读取商品信息/弹药价格并模拟购买。

## 0. 先说清楚：为什么纯静态无法凭空生成合法请求

这是设计前提，不是免责声明：

1. **字段号未静态确定**。so 里有 911 条 `pb.CS*` 消息名和大量字段名字符串（`buy_currency_id`@0x5992bb9、`goods_id`@0x5e3462d 等），但序列化 `FileDescriptorProto`（如 `cs_mall.proto`）在 so 中不存在。字段名与字段号分处不同字符串池，无法静态一一对应。`field_map.example.json` 中所有 `number` 都是 `null`，必须由 `find_descriptor.js` 在运行期导出后填入。
2. **签名走 TSS 安全 SDK**。`UDFMGameTss::SendTssData`@0x5c32655、`TssSDKOnRecvSignature`@0x4d7c3de、`cscpp_security.pb.cpp`@0x5f21052，加上完整的 OpenSSL 签名栈（EVP/RSA/MD5/SHA256）。签名依赖真实客户端的设备指纹、会话密钥、时间戳等运行时数据，静态二进制里没有可直接重放的固定签名。
3. **会话与网关参数未知**。HOST/PORT、`cmd_id`、`seq_id`、session key、设备指纹（qimei/oaid）都必须从真实客户端抓包或 Frida hook 获取。so 中唯一 URL 字面量 `http://10.32.75.192:9093/app`@0x15f9d8c4 是内网测试地址，**不可当生产端点**。
4. **帧格式是假设**。`frame.order` 默认布局（length + cmd + seq + body）来自"UE4 私有网关常见形态"，可信度 **medium**，须以 `dump_traffic.js` 抓到的真实字节校准。

本原型的所有未知量都做成配置项/外部注入，程序在缺字段号、缺会话、缺网关地址时会明确拒绝发送，不会假装成功。

## 1. 文件清单

| 文件 | 作用 | 依赖 |
|---|---|---|
| `probe_gateway.py` | 主程序：手写 protobuf wire 编解码 + 可配置帧 + 会话/签名注入 + decode_raw 风格响应解析 | Python 3.6+ 标准库；frida 模式需 `pip install frida` |
| `field_map.example.json` | 字段号/帧格式/网关配置模板，含每条结论的可信度与 so 偏移证据 | 复制为 `field_map.json` 后填写 |
| `capture.example.json` | 会话/签名抓包注入模板（cmd_id/seq_id/signature_hex/...） | 复制为 `capture.json` 后填写 |
| `find_descriptor.js` | Frida 脚本：从 protobuf DescriptorPool 导出 `cs_mall.proto` 的 FileDescriptorProto（字段名+字段号+类型） | Frida + 目标进程 |
| `dump_traffic.js` | Frida 脚本：hook `SendTssData`/`TssSDKOnRecvSignature`/libc send-recv，dump 出站/入站二进制到 `/data/local/tmp/dfm_dump/` | Frida + 目标进程 |

## 2. 完整工作流

### 步骤 A — 准备 Frida 环境

在已 root/越狱的 arm64 Android 设备（或 emulator）上：

```bash
# PC 端
pip install frida frida-tools

# 设备上运行 frida-server（版本与 PC 端 frida 一致），然后：
adb shell 'mkdir -p /data/local/tmp/dfm_dump && chmod 777 /data/local/tmp/dfm_dump'
adb forward tcp:27042 tcp:27042
```

### 步骤 B — 抓真实流量，确定帧格式与参数

```bash
# 游戏运行中，另开终端
frida -U -f com.tencent.tmgp.dfm -l dump_traffic.js --no-pause
```

在 UI 上执行一次"商城购买弹药/战备"操作，然后查看：

```bash
adb pull /data/local/tmp/dfm_dump/ ./dumps/
```

从 dump 文件中确定：

- **真实网关 HOST/PORT**：用 `tcpdump -i any -nn -s0 port not 53 -w /sdcard/dfm.pcap` 抓包后 wireshark/tshark 查看；或 `cat /proc/<pid>/net/tcp` 结合 Frida hook `connect()`。
- **cmd_id / seq_id**：`dump_traffic.js` 的帧级 dump（`socket_send`）+ `fields` 日志；静态证据 `cmd_id`@0x15f9c5cc / `seq_id`@0x15f9c5c5。也可 hook `requestCallback` 附近（JS 数据区 0x15f9c594，只能间接观察）。
- **签名字节**：`Signature_arg*.bin`（`TssSDKOnRecvSignature`@0x4d7c3de）与 `SendTssData_arg*.bin`（0x5c32655）。注意 dump 长度是猜测值，需手工裁剪。
- **帧布局**：`socket_send-*.bin` 是完整帧。按字节比对 protobuf body（用 `protoc --decode_raw < body.bin` 验证哪一段是 protobuf），然后调整 `field_map.json` 中 `frame.order`。

可信度：帧级 dump 的**字节内容**是 high（真实流量）；对其**语义解释**（哪 4 字节是 cmd_id 等）初始为 medium，校准后升为 high。

### 步骤 C — 导出 protobuf 字段号（关键）

```bash
frida -U -f com.tencent.tmgp.dfm -l find_descriptor.js --no-pause
# 在 Frida console 中：
rpc.exports.dump('cs_mall.proto')
rpc.exports.dump('cs_currency.proto')
rpc.exports.listFiles()
```

`find_descriptor.js` 的策略：

- **策略 A（high）**：调用 `google::protobuf::DescriptorPool::generated_pool()->FindFileByName()`，要求 so 动态符号表保留对应 C++ 符号且可按 NDK ABI 构造 `std::string`。脚本会检测符号是否存在；若存在但 `std::string` ABI 构造复杂，脚本明确提示而不硬来。
- **策略 C（medium/兜底）**：hook protobuf `CodedInputStream::ReadTag`，记录运行时实际解析到的 field number。它只能看到客户端实际发送的字段，看不到未发送的字段——脚本会明确标注此限制。

把导出结果填入 `field_map.json` 的 `messages.<msg>.fields[].number`，**不要猜字段号**。

### 步骤 D — 填入配置

```bash
cd /root/dfm_dynamic_build/repo/tools/probe
cp field_map.example.json field_map.json
cp capture.example.json capture.json
# 编辑：
#   field_map.json: gateway.host/port, messages.*.fields[].number, frame.order（按真实帧校准）
#   capture.json:   cmd_id, seq_id, signature_hex, session_key_hex, device_fingerprint, uin
```

### 步骤 E — 离线构造预览（不联网）

```bash
python3 probe_gateway.py --config field_map.json --capture capture.json \
  --message CSMallBuyReq --set goods_id=12345 --set buy_num=1 --mode build
```

输出包含：`body_hex`、逐字段编码报告（含 `BLOCKED` 与证据可信度）、组装后的帧 hex。字段号没填时会打印 `BLOCKED ... field number 未确定`，帧仍可生成用于离线测试，但**不代表合法请求**。

查看消息/字段证据表：

```bash
python3 probe_gateway.py --config field_map.json --summary
```

### 步骤 F — 离线解码响应/抓包 body

```bash
python3 probe_gateway.py --mode decode --raw-file ../dumps/socket_recv-xxx.bin
python3 probe_gateway.py --mode decode --raw-hex '080110012a03123456'
```

输出为 `field N wire=... value=...` 的 decode_raw 风格列表；嵌套消息用启发式递归解析并标注 `confidence low`。

### 步骤 G — 发包（仅在参数齐备后）

```bash
python3 probe_gateway.py --config field_map.json --capture capture.json \
  --message CSGetCurrencyReq --set currency_id=1 --mode send
```

程序会在以下任一情况**拒绝发送并返回码 2**：`gateway.host/port` 为 null、`cmd_id`/`seq_id` 为空、签名模式为 file 但 `signature_hex` 为空。这是刻意设计——防止在不具备合法会话时产生误导性结果。

若签名由 Frida 实时提供（不写入文件）：

```bash
# sign.js 需导出 rpc.exports.sign(payloadHex) -> signatureHex
python3 probe_gateway.py --config field_map.json --capture capture.json \
  --signature-mode frida --frida-sign-script sign.js \
  --message CSMallBuyReq --set goods_id=12345 --set buy_num=1 --mode send
```

## 3. 静态结论与可信度速查

| 项目 | 值 / 候选 | 可信度 | 来源 |
|---|---|---|---|
| 接口形态 | UE4 私有网关 + protobuf CS 消息 + cmd_id | high | DEX 无 REST 购买端点；so 中 911 条 `pb.CS*` + 网关字符串 |
| 购买消息 | `CSMallBuyReq` / `CSMallBuyRes` | high | `pb.CSMallBuyReq`@0x5b6cd50；`cs_mall.pb.cpp`@0x5e33b45 |
| 弹药/市场购买 | `CSMarketBuyTRes`@0x58a3277 | medium | 仅 Res 名明文；Req 名未找到 |
| 货币消息 | `CSGetCurrencyReq`@0x57eebf3 / `Res`@0x5af6f6c、`CSCurrencyExchangeReq`@0x5b6cc25 | high | so 明文 + `cs_currency.pb.cpp`@0x5b6cbd8 |
| 字段存在性 | `buy_currency_id`@0x5992bb9、`goods_id`@0x5e3462d、`buy_num`@0x5a476ad、`currency_id`@0x5c203f2、`bullet_gid`@0x5be2c9c、`equip_price`@0x5af78f9 | high（存在性）/ medium（归属具体消息） | so 字符串池 |
| 字段号 | 未确定，配置中全为 `null` | unknown | 无序列化 descriptor；需运行期导出 |
| 网关地址 | 未确定，配置中 `null` | unknown | so 仅有内网字面量，不作生产端点 |
| 帧格式 | length+cmd+seq+body（默认假设） | medium | 需以真实抓包校准 |
| 签名 | TSS SDK：`SendTssData`@0x5c32655、`TssSDKOnRecvSignature`@0x4d7c3de、`cscpp_security.pb.cpp`@0x5f21052 | high（链路存在）/ unknown（算法细节） | so 明文符号 |
| 历史字段 | `buy_item_id`/`buy_currency_itemid`/`equip_item_id`/`bullet_id` | 当前版本 NOT_FOUND | 直接字节检索；不可照搬旧报告 |

## 4. 合规说明（工程事实，非价值判断）

本目录是**本地 sandbox 原型**：所有网关地址、会话、签名字段均为占位符或需你从自己控制的客户端运行时注入。程序不会、也没有内置绕过去签名/会话的逻辑；缺参数时直接拒绝发送。把它变成可用探针的前提，是你自己掌握合法的客户端运行环境与抓包数据。
