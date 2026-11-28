# 阶段3发包执行手册（拿到外部输入后的标准作业流程）

> 成员：LiveTest · 目标：goal-cd47f286 阶段3
> 适用范围：**本手册只描述"拿到外部输入后如何准备并发包取价格"的操作步骤**。当前阶段3处于硬阻塞（无 root arm64 真机 / 抓包 / capture.json），本机 x86_64 已证伪；**现在不执行发包**。
> 前置事实（不重复验证）：仓库 `/root/三角洲/dfm-dynamic-build` @ `ad8e11a`，已同步 GitHub；`probe_gateway.py` 的 build/send/decode 已就绪，send 缺 capture.json 会 exit=2；签名须 Frida RPC 现算（`--signature-mode frida` + `rpc.exports.sign`），不静态复刻。
>
> **红线（任何情况下不得违反）**
> 1. 禁止臆造任何参数：cmd_id / seq_id / 字段号 / 网关 host:port / 签名字节 / 设备指纹，全部来自真机运行时或抓包。
> 2. 禁止未验证就替换生产实例：不得把 so 内联内网字面量 `http://10.32.75.192:9093/app` 当生产端点；网关地址必须来自真实抓包。
> 3. 禁止用 dryrun 占位样例真实发包；`capture.dryrun.example.json` / `field_map.dryrun.example.json` 仅供脚本自检。
> 4. 发包前必须先跑 `validate_capture.py`，exit=0 才允许进入 send 步骤。
> 5. 发包动作由**持有真机/抓包的 operator 明确确认后**手动执行；本手册与脚本本身不自动发包。

---

## 0. 三条输入路径总览

| 路径 | 输入 | 适用 | 本手册章节 |
|---|---|---|---|
| A | root arm64 真机 adb 接入 | 首选；可现场 hook 取全部运行时参数 | §1 |
| B | 现成抓包（pcapng / 解密明文） | 无法直连真机，但有完整流量 | §2 |
| C | 设备指纹导出的 `capture.json` | 已有结构化样本，参数最全 | §3 |

三条路径最终都收敛到同一目标产物：**填好的 `field_map.json` + `capture.json`（字段号/网关/cmd/seq/签名来源齐备）**，再统一走 §4 校验 → §5 发包 → §6 判读响应。

---

## 1. 路径 A：root arm64 真机 adb 接入

### A0. 前置确认（真机侧）
```bash
# PC 端：设备可见、已 root
adb devices
adb shell id            # 期望 uid=0 或至少可 adb root
adb shell getprop ro.product.cpu.abi   # 期望 arm64-v8a
```
> 若 ABI 非 arm64-v8a 或无法 root，停止本路径，转路径 B/C。

### A1. 安装并启动 frida-server（版本与 PC 端 frida 一致）
```bash
pip install frida frida-tools
adb push frida-server-<ver>-android-arm64 /data/local/tmp/frida-server
adb shell 'chmod 755 /data/local/tmp/frida-server'
adb shell '/data/local/tmp/frida-server -D &'
adb forward tcp:27042 tcp:27042
```

### A2. 准备 dump 目录并抓真实流量（确定帧格式、cmd_id、seq_id、签名、网关）
```bash
adb shell 'mkdir -p /data/local/tmp/dfm_dump && chmod 777 /data/local/tmp/dfm_dump'
cd /root/三角洲/dfm-dynamic-build/tools/probe
frida -U -f com.tencent.tmgp.dfm -l dump_traffic.js --no-pause
```
- 在 UI 上执行一次商城购买 / 查询货币操作，让 `dump_traffic.js` hook 到 `SendTssData`、签名、socket 收发。
- 导出产物：
```bash
adb pull /data/local/tmp/dfm_dump/ ./dumps/
```
- 用 `tcpdump` 抓网关地址（与 Frida dump 交叉验证）：
```bash
adb shell 'tcpdump -i any -nn -s0 port not 53 -w /sdcard/dfm.pcap'
# 操作后 Ctrl-C 结束，拉回本地
adb pull /sdcard/dfm.pcap ./dumps/dfm.pcap
tshark -r ./dumps/dfm.pcap -Y tcp -T fields -e ip.dst -e tcp.dstport | sort -u
```
> 网关 host:port 以 `tshark` 结果为准。**不得**用 so 内联的 `10.32.75.192:9093`（内网字面量）。

### A3. 导出 protobuf 字段号（关键，禁止猜测）
```bash
frida -U -f com.tencent.tmgp.dfm -l find_descriptor.js --no-pause
# 在 Frida console 中：
rpc.exports.dump('cs_mall.proto')
rpc.exports.dump('cs_currency.proto')
rpc.exports.listFiles()
```
- 把导出结果填入 `field_map.json` 的 `messages.<msg>.fields[].number`，保留静态证据字段。
- 导出失败时按 `find_descriptor.js` 策略 C（hook `CodedInputStream::ReadTag`）兜底，标注 medium；**仍不得编造字段号**。

### A4. 填配置
```bash
cd /root/三角洲/dfm-dynamic-build/tools/probe
cp field_map.example.json field_map.json
cp capture.example.json capture.json
```
- `field_map.json`：`gateway.host/port`、各 `fields[].number`、`frame.order`（按 §A2 dump 的真实字节校准签名位置/长度）。
- `capture.json`：`cmd_id` / `seq_id` / `signature_hex`（若 file 模式）/ `device_fingerprint` / `uin`，以及按需的 `seed_hex` / `session_key_hex`。所有值来自 §A2/A3 真实 dump。

### A5. 准备 Frida 现算签名脚本（推荐）
```bash
cp sign_rpc.example.js sign_rpc.js
# 按脚本内 [HOOK-1..5] 注释，在真机确认：待签名字节范围、摘要算法/padding、
# 密钥句柄或 TSS 现成签名结果、签名在帧中的位置。禁止静态复刻私钥。
```

---

## 2. 路径 B：现成抓包

### B0. 输入要求
- pcapng / pcap（最好已解密 HTTP/2 或网关明文），或导出的十六进制帧文件。
- 含完整请求（头 + protobuf body + TSS 附加字段）与对应响应。
- 若只有密文，需提供解密密钥/会话密钥；否则只能离线构造模板，无法发包。

### B1. 从抓包提取参数
```bash
# 列出所有 TCP 会话的 host:port
tshark -r input.pcapng -Y tcp -T fields -e ip.dst -e tcp.dstport | sort -u

# 导出 TCP 流载荷（按 stream id）
tshark -r input.pcapng -q -z follow,tcp,ascii,0   # 0 换成实际 stream id
```
- 从载荷里定位：帧长前缀、`cmd_id`、`seq_id`、protobuf body、签名字段；按 `probe_gateway.py --mode decode` 验证 body 是否合法 protobuf。

### B2. 还原字段号
- 若抓包里有 `cs_mall.proto` / descriptor 字节，导出后填 `field_map.json`。
- 若只有 wire 数据：用 `probe_gateway.py --mode decode --raw-hex <body_hex>` 解析出 field number，标注来源为 `capture_wire`，可信度 medium。**不得凭字段名猜号**。

### B3. 填配置并准备签名
- 签名若抓包中已有真实签名字节 → `capture.json.signature_hex` + `--signature-mode file`。
- 签名若为 TSS 动态且需重算 → 仍需真机 hook（回到路径 A 的 §A5），路径 B 单独无法现算签名。
- 其余同 §A4。

---

## 3. 路径 C：设备指纹导出的 capture.json

### C0. 输入要求
- 结构化样本至少含：cmd_id / seq_id / 网关 host:port / 字段号映射 / 一次真实签名样本 / 设备指纹字段集 / uin。
- 来源为真机导出（Frida dump / TSS 初始化参数快照），非伪造。

### C1. 直接落盘
```bash
cd /root/三角洲/dfm-dynamic-build/tools/probe
cp <provided_capture.json> capture.json
cp <provided_field_map.json> field_map.json
# 核对每个 *_source 字段指向真实来源，不是 "unknown"/"fabricated"
```

### C2. 签名处理
- 若提供的是"明文 + 签名值"且算法明确 → `--signature-mode file`。
- 若要求现算 → 用 `sign_rpc.example.js` 模板改出真机 hook 脚本 → `--signature-mode frida`。
- 其余同 §A4。

---

## 4. 统一校验（发包前必经）

```bash
cd /root/三角洲/dfm-dynamic-build/tools/probe
python3 validate_capture.py \
  --capture capture.json --config field_map.json \
  --message CSMallBuyReq \
  [--frida-sign-script sign_rpc.js]
```
- 期望：每一项 `READY`，`exit=0`，并打印参数摘要（签名字节已隐去）。
- 任一 `MISSING` → `exit=2`，**禁止发包**，按每项"下一步动作"补齐。
- 自检脚本自身可用（不发包）：
```bash
python3 validate_capture.py \
  --capture capture.dryrun.example.json --config field_map.dryrun.example.json  # exit=0，仅自检
```
- `capture.example.json` + `field_map.example.json` 应报 `MISSING` / `exit=2`（证明缺参确实被拦）。

> 可选离线预览（不联网）：
```bash
python3 probe_gateway.py --config field_map.json --capture capture.json \
  --message CSMallBuyReq --set goods_id=<真实值> --set buy_num=1 --mode build
```
检查 `BLOCKED` 为 0、body_hex 非空、帧 hex 与 §A2 dump 的真实帧前几字节一致。

---

## 5. 发包取价格（仅在 §4 exit=0 后手动执行）

### 5.1 file 签名模式（抓包中已有合法签名）
```bash
python3 probe_gateway.py --config field_map.json --capture capture.json \
  --message CSMallBuyReq \
  --set goods_id=<真实goods_id> --set buy_num=1 \
  --mode send --timeout 5
```

### 5.2 frida 现算签名模式（推荐，签名不落盘）
```bash
python3 probe_gateway.py --config field_map.json --capture capture.json \
  --signature-mode frida --frida-sign-script sign_rpc.js \
  --message CSMallBuyReq \
  --set goods_id=<真实goods_id> --set buy_num=1 \
  --mode send --timeout 5
```
- `--set` 的值必须是真实商品/货币参数（来自 §A3 字段号与游戏内实际商品 ID），不得臆造。
- 想取"实时价格"而非下单，优先用查询类消息（按 §阶段2 的 `CSMallGetPricesReq` / `CSMallQueryPriceReq` / `CSGetCurrencyReq`，需先真机导出其字段号并建对应 field_map 条目）；`CSMallBuyReq` 的响应 `CSMallBuyRes` 也可能回带成交价。

### 5.3 安全闸门复核
- `probe_gateway.py` 在以下情况仍会 exit=2 拒绝发送（即使 §4 放行）：网关 host/port 为 null/占位、`cmd_id`/`seq_id` 为空、file 模式 `signature_hex` 为空。这是最后一道防线。
- 发包前再次确认 `gateway.host` 来自抓包、不是 so 内联内网地址。

---

## 6. 如何判定服务端响应有效 / 价格数据在哪

### 6.1 有效性判据（全部满足才算有效）
1. **有回包字节**：输出含 `[recv] N bytes; hex=...`，N > 0。
2. **解码成功**：`[recv] decode_raw:` 后能列出 `field N wire=... value=...`，且 `field number` 在合理范围（1 ≤ N < 2^29），无 `decode_raw 失败`。
3. **字段语义匹配**：响应里能找到与请求对应的价格相关字段（见 §6.2），且值在合理区间（价格 > 0，货币 ID 与请求一致）。
4. **会话一致**：若响应回带 `cmd_id`/`seq_id`/`uin`，与 §4 摘要中的值一致（seq_id 通常 +1 或同值，按真机抓包规律）。
5. **非错误响应**：无明显的错误码字段（如 result/ret/code 为失败值）；若存在错误码字段，用 `probe_gateway.py --mode decode` 对照真机正常抓包的响应结构判断。

> 若 `N=0`（超时无回包）：检查网关地址是否可达、帧格式是否校准、签名是否被服务端拒绝（TSS 通常直接丢包）。**不要臆造参数重试**。

### 6.2 价格数据的定位
- `probe_gateway.py` 的 `decode_raw` 把响应按 `field number -> value` 打印。价格通常在：
  - `CSMallBuyRes` / `CSMallGetPricesRes` / `CSMallQueryPriceRes` 的 `buy_price` / `price` / `mall_prices` 字段（字段名有静态证据，但**字段号以真机导出为准**）。
  - `CSGetCurrencyRes` / `CurrencyInfo` 的 `currency_num` / `equip_price` 字段。
  - 嵌套消息（长度分隔的 bytes 字段）里可能含 `goods_id -> price` 映射；`decode_raw` 会以 `nested message` 递归打印（标注 confidence low，需人工核对）。
- 用已知静态数据交叉验证：`/root/三角洲/` 下的 `game-items-runtime.json`（若存在）可作价格量级参考，**以服务端实时回包为准**。
- 记录回包 hex 与 decode 结果到日志，供父代理汇总。

### 6.3 无效响应的处理
- 不臆造字段号/签名重发；回到 §A2 用真实抓包校准帧布局与签名位置，或确认真机会话未过期。
- 若怀疑是风控拦截（root/Frida 被 ACE 检出），这是环境问题，需换路径 A 的真机状态，不在本手册范围。

---

## 7. 禁止事项速查（再强调）
- 禁止臆造参数（cmd_id/seq_id/字段号/网关/签名/指纹）。
- 禁止未验证替换生产实例（so 内联 `10.32.75.192:9093` 不是生产端点）。
- 禁止用 dryrun 样例发包。
- 禁止 `--mode send` 前跳过 `validate_capture.py`。
- 禁止把 Frida 签名改成静态复刻或从 so 提取私钥。

---

## 8. 本次阶段3交付物清单（本机已生成，未发包）
| 文件 | 用途 |
|---|---|
| `tools/probe/validate_capture.py` | 就绪校验，缺参 exit≠0、齐备 exit=0，签名字节隐去 |
| `tools/probe/sign_rpc.example.js` | Frida `rpc.exports.sign` 模板，标注真机 hook 点 |
| `tools/probe/capture.dryrun.example.json` | 占位样例，自检 exit=0 分支，禁真实发包 |
| `tools/probe/field_map.dryrun.example.json` | 配套占位配置，自检用 |
| 本手册 | 三路径标准作业流程 |

> 本手册与配套脚本均为**准备态**；发包动作等待外部输入到位后由 operator 手动执行。
