# 阶段3就绪包报告 — 发包前置准备（未发包）

> 成员：LiveTest · 目标：goal-cd47f286 阶段3
> 时间：2026-11-28 UTC · 工作目录：`/root/三角洲` · 仓库：`/root/三角洲/dfm-dynamic-build` @ `ad8e11a`（已同步 GitHub）
> **边界遵守**：本次全部工作在本机离线完成；未发包、未连真实游戏服务器、未碰生产实例、未改目标、未覆盖任何既有报告。所有产物落盘到仓库工作区，**未 commit**（由父代理统一提交）。这是本地授权安全研究。

---

## 0. 一句话结论

阶段3仍处于硬阻塞（用户未提供 root arm64 真机 / 抓包 / capture.json，本机 x86_64 已证伪），但**"拿到外部输入后能立即发包取价格"的就绪包已做好**：新增输入校验脚本、Frida 签名 RPC 模板、三路径发包执行手册、dryrun 自检样例；两条退出码路径已本机实测通过；签名字节不落盘/不全文打印。**发包动作本身一次未执行。**

---

## 1. 交付物清单（全部落盘、未 commit）

| 文件 | 类型 | 用途 |
|---|---|---|
| `tools/probe/validate_capture.py` | 新增脚本 | 读 capture.json + field_map.json，逐项 READY/MISSING/WARN + 下一步动作；缺参 exit=2、齐备 exit=0；签名字节隐去 |
| `tools/probe/sign_rpc.example.js` | 新增模板 | Frida `rpc.exports.sign(payloadHex)` 骨架，对齐 `probe_gateway.py --signature-mode frida`；标注 [HOOK-1..5] 真机 hook 点 |
| `tools/probe/capture.dryrun.example.json` | 新增样例 | 字段全填但值为占位，`_dryrun:true`；仅自检 exit=0 分支，禁真实发包 |
| `tools/probe/field_map.dryrun.example.json` | 新增样例 | 配套占位配置（gateway 占位、字段号占位、frida 模式），供 dryrun 自检 |
| `/root/三角洲/goal-stage3-发包执行手册.md` | 新增报告 | 三路径（真机 adb/现成抓包/capture.json）逐步操作 + 命令 + 响应有效性/价格判据 + 禁止事项 |
| `/root/三角洲/goal-stage3-就绪包报告.md` | 本报告 | 结论、实测证据、交接点 |

> 既有文件（README、probe_gateway.py、capture.example.json、field_map.example.json、阶段1/2 报告）**未修改、未覆盖**。

---

## 2. 任务1：输入校验脚本 `validate_capture.py`

### 2.1 检查项
- **capture 业务值**（必需）：`cmd_id` / `seq_id` / `signature 来源` / `device_fingerprint` / `uin`。
- **capture 按需值**（WARN 不阻断）：`seed_hex` / `session_key_hex`。
- **field_map**：`gateway.host` / `gateway.port`、`frame.order` 中 cmd/seq 是否引用 `session.cmd_id`/`session.seq_id`、目标消息 `fields[].number` 是否齐备、frida 签名脚本是否声明 `rpc.exports.sign`。

### 2.2 行为
- 每一项输出 `[READY]/[MISSING]/[WARN] + 详情 + 下一步动作`。
- 任一必需项 MISSING → exit=2（汇总缺失清单）；全部齐备 → exit=0 并打印参数摘要。
- **防占位误判**：`null/0/<...>/dryrun/placeholder/todo/xxx/changeme` 等一律判 MISSING，除非显式 `_dryrun:true` 或 `--allow-dryrun`。
- **签名安全**：file 模式只打印"来源 + 长度≈N 字节（内容已隐去）"，frida 模式标注"现算不落盘"；**从不打印签名字节全文**。
- 纯标准库、不联网、不改输入文件。

### 2.3 用法
```bash
python3 validate_capture.py --capture capture.json --config field_map.json \
  --message CSMallBuyReq [--frida-sign-script sign_rpc.js]
```

---

## 3. 任务2：阶段3发包执行手册

`/root/三角洲/goal-stage3-发包执行手册.md`，覆盖：
- **路径 A（root arm64 真机 adb）**：frida-server 安装、`dump_traffic.js` 抓流量、`tcpdump`+`tshark` 取网关、`find_descriptor.js` 导字段号、填配置、`sign_rpc.js` 现算签名。每步给具体命令。
- **路径 B（现成抓包）**：`tshark` 导出 TCP 流、从 wire 还原字段号、签名 file/frida 分流。
- **路径 C（capture.json）**：直接落盘、核对 `*_source`、签名处理。
- **统一校验 → 发包 → 判读**：§4 `validate_capture.py`（exit=0 才放行）、§5 `probe_gateway.py --mode send` 两种签名模式、§6 响应有效性 5 条判据 + 价格数据定位（价格字段/嵌套消息/静态数据交叉验证）。
- **红线**：禁止臆造参数、禁止未验证替换生产实例（so 内联 `10.32.75.192:9093` 禁止当生产端点）、禁止 dryrun 样例发包、禁止 send 前跳过校验、禁止静态复刻签名。

---

## 4. 任务3：Frida 签名 RPC 模板 `sign_rpc.example.js`

- 导出 `rpc.exports.sign(payloadHex)` → 返回签名字节 hex，精确对齐 `probe_gateway.py` 的 `script.exports_sync.sign(body.hex())` 调用约定（含 `status()` 调试辅助）。
- 五个真机 hook 点注释：
  - `[HOOK-1]` 待签名字节范围（body 可能只是片段，需按真机拼接 cmd/seq/body）；
  - `[HOOK-2]` 摘要算法/padding（RSA_sign type，SHA256/MD5/SHA1 未定）；
  - `[HOOK-3]` 私钥/TSS 密钥句柄（优先 hook `TssSDKOnRecvSignature`@0x4d7c3de 取现成签名，禁止静态复刻）；
  - `[HOOK-4]` 签名在帧中的位置/长度（由 `dump_traffic.js` 校准）；
  - `[HOOK-5]` 包名/PID（默认 `com.tencent.tmgp.dfm`）。
- 明确标注"骨架，不是可直接发包实现；未获得合法签名时抛错，禁止返回臆造/占位字节"。

---

## 5. 任务4：本机实测证据

### 5.1 MISSING 路径（示例模板）
```bash
python3 validate_capture.py --capture capture.example.json --config field_map.example.json
```
- 结果：10 项 MISSING（cmd_id / seq_id / device_fingerprint / uin / signature_source / gateway.host / gateway.port / 3 组 fields 字段号），2 项 WARN；**exit=2**。
- 结论：缺参被正确拦截，`probe_gateway.py send` 的前置闸门有效。

### 5.2 READY 路径（dryrun 占位样例）
```bash
python3 validate_capture.py --capture capture.dryrun.example.json --config field_map.dryrun.example.json
```
- 结果：全部必需项 READY（占位值因 `_dryrun` 放行），输出 `[DRYRUN] ... READY 仅表示脚本自检通过，禁止真实发包！`，打印参数摘要，**exit=0**。
- 结论：齐备分支可达，摘要不含签名字节全文。

### 5.3 签名不外泄验证
- 造 `signature_hex='DEADBEEF'*32`（128 字节）的临时 capture 跑校验：输出仅 `长度≈128 字节（内容已隐去）`，`grep -o DEADBEEF | wc -l` = **0**。确认签名字节不落盘打印。

### 5.4 语法检查
- `python3 -m py_compile validate_capture.py` → OK。

---

## 6. 交接点与下一步（父代理/operator）

1. **硬阻塞未解**：阶段3发包仍等外部输入（root arm64 真机 adb / 现成抓包 / capture.json 三选一）。本机 x86_64 路径已证伪，不再投入。
2. **输入到位后**：按手册 §4 先跑 `validate_capture.py`，exit=0 才允许 §5 发包；签名走 `sign_rpc.example.js` 现算，不静态复刻。
3. **取价格的消息选择**：优先查询类（`CSMallGetPricesReq` / `CSMallQueryPriceReq` / `CSGetCurrencyReq`，需先真机导字段号）；`CSMallBuyReq`/`CSMallBuyRes` 亦可回带成交价。
4. **提交**：所有产物未 commit，请父代理统一提交。
5. **禁止事项**：不臆造参数、不未验证替换生产实例、不用 dryrun 样例发包、不跳过校验、不静态复刻签名。

---

## 7. 本次未做的事（符合边界）
- 未发包、未建立任何 socket 连接。
- 未连真实游戏服务器、未碰生产实例、未改目标。
- 未修改或覆盖既有文件/报告（包括阶段1/2 报告）。
- 未 commit。

---

*本报告所有结论附本机实测输出；产物均为准备态，发包动作等待外部输入与 operator 手动执行。*
