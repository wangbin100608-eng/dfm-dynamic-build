# 阶段2 成果独立复核报告（Verifier）

> 复核对象：goal-cd47f286 阶段2 · `/root/三角洲/goal-stage2-协议与签名完备.md` · 仓库 `dfm-dynamic-build`
> 复核人：Verifier（独立复核，非执行者 ProtoSig）
> 时间：2026-11-28 UTC · 全程只读 + 离线验证；未修改任何源文件/配置/样本，未发包，未连接任何网络端点。
> 样本：`/root/三角洲/dfm-apk/so-analysis/libUE4.so`，561,598,448 字节，ARM64 aarch64 stripped（file/readelf 确认）。
> 仓库状态：HEAD=`a0ccc3a4a4926056cd16d7bfe8545fef703c8277`（阶段2 提交，题目中的 `1df478d` 为其祖先；工作区干净，阶段2 改动已提交而非未提交——与题面描述略有出入，不影响内容复核）。

## 一、逐项结论总表

| # | 复核项 | 结论 | 一句话依据 |
|---|---|---|---|
| 1 | 5 条随机消息 XOR-0x10 编码与偏移；明文 0 条 | **PASS** | 随机 5/5 字节级解码命中；全量明文正则独立扫描 0 条，4844 条消息全部 `source=XOR-0x10-decode` |
| 2 | field_map/capture 标注完整性；null 字段；无臆造字段号 | **PASS** | 29 字段逐项含 `_source/confidence/runtime_required`；7 个 null 全标 unknown + runtime_required=true；候选字段 0 个带 number |
| 3 | 签名偏移"给定值是字符串/描述表非函数入口"断言 | **PASS（附方法学瑕疵 OBS-2）** | 7 个给定偏移 mod4≠0，ARM64 函数入口必须 4 字节对齐；明文字串 @0xc082 实测存在；JSON 字节哈希逐条吻合 |
| 4 | probe build 成功 / send 缺参拒绝且无 socket | **PASS（附描述歧义 OBS-1）** | 用 `field_map.stage2-verify.json` 复跑 4/4 build exit=0（body 16/34/14/0）；decode 正确；send exit=2，strace network 系统调用为空 |
| 5 | 新增脚本逻辑只读审查 | **PASS（附小瑕疵 OBS-3）** | 三脚本无伪造字段号、无联网、无写样本；发现注释与实现的小出入及一处反汇编对齐瑕疵 |
| 6 | 报告统计数字与精选偏移 | **PASS** | 4844 / 633 / 4980 / 159 行全部复算一致；抽查 8 个精选偏移全部在 harvest JSON 且字节解码吻合 |

**总评：PASS。** 阶段2 五项核心结论均可独立复现，未发现臆造字段号、未发现发包行为。以下三条为不影响结论的观察项。

## 二、详细复核记录

### 1. XOR-0x10 编码与"明文 0 条"（PASS）

- 以固定种子（20261128）从 `reports/pb-messages-harvest.json` 的 4844 条消息中随机抽取 5 条，按各自 `xor_offsets[0]` 从 so 读取等长字节并 XOR-0x10：
  - `pb.MapInfo` @0x15df27b → 解码 `pb.MapInfo` ✔
  - `pb.CSBattlePassReceiveArchiveRewardReq` @0x1bf709e → ✔
  - `pb.CSActivitySOCSendCardRes` @0x2036350 → ✔
  - `pb.ActivityJumpPair` @0x2652d21 → ✔
  - `pb.DsStat` @0x2653a2d → ✔
  - 5/5 全命中，raw 字节均以 `60 72 3e 5d 71 62 7b 75...` 开头（即 "pb." XOR 0x10）。
- 独立做全文件明文正则 `pb\.[A-Za-z]...` 扫描：distinct 明文字符串 **0 条**；harvest JSON 中 `offsets`（明文）非空的消息 **0 条**，`xor_offsets` 非空 **4844 条**。`source` 分布 100% 为 `XOR-0x10-decode`。
- 报告 1.2 节列出的 8 个精选偏移（CSMallBuyReq@0x1a24a2f 等）逐一核对：均在 harvest JSON 中且字节解码与该消息名完全一致。
- **结论：当前样本"pb.* 消息名全部 XOR-0x10 编码、明文 0 条"成立。** 旧"明文"结论适用历史版本这一点，报告已明确标注（字典头部注明 + 不删旧报告），证据冲突处理正确。

### 2. 配置文件标注完整性（PASS）

- `reports/field_map.inferred.json`：顶层 `_stage2_annotations` 齐备；`frame.order` 5 项全部带 `_source`/`confidence`（len=local_calculation/medium，cmd/seq/signature=capture_runtime/unknown/runtime_required=true，body=local_protobuf_builder/high）；4 类消息共 **29 个字段**逐项带 `_source`/`confidence`/`runtime_required`，缺失 0 项。
- **7 个 `number:null` 字段**全部为 `_source=inferred_from_struct_offset_order_failed`、`confidence=unknown`、`runtime_required=true`，并附"必须 find_descriptor.js 或抓包提供、禁止猜测"的 `_comment_stage2`。清单：LimitBuyReq.last_update_time、MarketTradeReq.sale_lists、BulletOpReq 的 5 个字段。
- `tools/probe/capture.example.json`：7 个业务值（cmd_id/seq_id/signature_hex/seed_hex/session_key_hex/device_fingerprint/uin）全部为 null，且每个都有 `<key>_source=capture_runtime`、`_confidence=unknown`、`_runtime_required=true`；`_captured_from/_captured_at` 标为 capture_metadata/high。无臆造业务值。
- `tools/probe/field_map.example.json`：3 类消息全部字段 number=null，逐项 `_source=runtime_descriptor_required`/`unknown`/`runtime_required=true`。
- "有无臆造字段号"：唯一带数字字段号的是 `field_map.inferred.json`（medium 结构偏移推断值，明确标注非 DescriptorPool、不可当服务端真实字段号）和 `field_map.stage2-verify.json`（专用离线验证配置，报告已声明绝不外发）。`pb-field-candidates.json` 的 4980 条候选 **0 条含 number 键**，纯字符串存在性证据。无 high 字段号混入。
- **结论：标注完整，边界清晰，无臆造字段号。**

### 3. 签名链路偏移断言（PASS，附 OBS-2）

- readelf 确认 so 仅两段 R E：0x0–0x1baacf30 与 0x204c4000 附近的补充段；给定偏移全部落在第一段地址范围，但：
  - 7 个给定偏移 mod 4 分别为 1/2/1/3/1/3/1，**全部非 4 字节对齐**。ARM64 指令固定 4 字节、函数入口必须对齐，这是比反汇编更强的独立证据，主结论"这些偏移不是函数入口"成立。
  - 用 dd/xxd 抽查 7 个偏移处 32 字节，与 `signature-chain-static.json` 的 `bytes_at_offset` 逐条十六进制完全一致；`plain_count`/`xor10_count` 用 `data.count()` 独立复算也逐条一致。
  - 对"给定偏移是字符串"的断言抽查：`TssSDKOnRecvSignature` 的 `plain_offset=0xc082`，实测该处字节为 `TssSDKOnRecvSignature\x00CreateDolphin\x00ReleaseDolph...`，确为 NUL 终止字符串；`SendTssData` 的 XOR 串 @0x188cc71 解码为 `SendTssData_ES\x00UDFMGameUdpMgr::S...`；`EVP_PKEY_sign` @0x1b2ef3f 解码为 `EVP_PKEY_sign_init\x00`；`RSA_sign` @0x244c24e 解码为 `RSA_sign\x00unsupported version\x00PKC...`；`sha256WithRSAEncryption` @0x1f7006f 解码为完整字符串。符号存在性结论真实。
- OBS-2：`analyze_signature_chain.py` 第 58 行以 `off-16` 为起点调用 capstone，起点普遍未对齐（mod4=1/2/3），输出的 `udf`/`stxr`/`strb` 等"首指令"是非对齐解码产物，其 `disasm_valid_heuristic` 判据在方法学上不严谨。但主结论有上述对齐性 + 字节内容 + 字符串位置三重独立证据支撑，结论不受影响。
- **结论：签名符号结论与"给定偏移不是函数入口"断言成立。**

### 4. probe_gateway 实跑验证（PASS，附 OBS-1）

- 4 类消息用 `tools/probe/field_map.stage2-verify.json` + `capture.example.json` 复跑 build，全部 exit=0、未联网：
  - LimitBuyReq body_len=16（8 ENCODED + 1 BLOCKED last_update_time）
  - MallOrderReq body_len=34（7 ENCODED，0 BLOCKED）
  - MarketTradeReq body_len=14（7 ENCODED + 1 BLOCKED sale_lists）
  - BulletOpReq body_len=0（5 BLOCKED，空 body）
  - 与报告 4.1 表格完全一致。
- decode：`--raw-hex 1801280130013801420a746573745f6f7264657210010a0a746573745f6f72646572` 正确还原 field 3/5/6/7/8(len,"test_order")/2/1，exit=0。
- send：`--mode send` 输出 `[send] 网关 host/port 未填（占位符）...本原型拒绝臆造地址`，**exit=2**；`strace -f -e trace=network` 捕获到的唯一行是进程退出，**无任何 socket/connect 调用**。无发包。
- OBS-1：复核任务书与报告"一句话结论"表述为"用 `reports/field_map.inferred.json` 做 build 验证"，但实际复跑该文件时 4 类消息全部 `body_len=0`、字段报告为空——因为它是字典（所有字段无 `value`），不是带测试值的 build 配置。报告第 4 节正文与命令示例使用的是 `tools/probe/field_map.stage2-verify.json`，该配置复跑全部通过。**结论本身正确，仅"用哪个配置文件验证"的表述有歧义**，建议父代理在最终汇总中明确以 stage2-verify 为准。
- **结论：build/decode 通过，send 缺参拒绝且零网络连接，符合边界。**

### 5. 新增脚本只读审查（PASS，附 OBS-3）

- `harvest_pb_messages.py`：正则 + XOR-0x10 交叉验证逻辑正确（`PB_RE` 允许可选 `.field`，消息/字段区分靠 `name[3:]` 是否含点）；buy_related_count=633 与报告一致；字段候选由 ±0x1000 窗口 snake_case 共现提取，明确只做存在性证据、不赋字段号，符合边界。
- `annotate_configs.py`：只追加标注字段，`setdefault` 不覆盖既有 number/evidence，逻辑正确；三份配置实际内容与脚本预期一致。
- `analyze_signature_chain.py`：见 OBS-2；无联网、无写样本、无伪造算法结论，算法候选标注 unknown 与报告一致。
- OBS-3：`harvest_pb_messages.py` 文档字符串称"mmap 全文件"，实现为 `open().read()` 全量读入（561MB 常驻内存）；功能正确但与注释不符，属小瑕疵。
- **结论：三脚本无明显逻辑错误。**

### 6. 统计数字复算（PASS）

| 指标 | 报告值 | 复核实测 |
|---|---|---|
| pb.* 消息总数 | 4844 | 4844 ✔ |
| buy_related 消息 | 633 | 633 ✔ |
| 字段候选 | 4980 | 4980 ✔ |
| 消息字典行数 | 159 | 159 ✔ |
| 消息置信度分布 | medium/low | medium 4252 / low 592，high 0 ✔ |
| 字段候选置信度 | medium/low | medium 4480 / low 500 ✔ |

## 三、发现的问题汇总

1. **OBS-1（文档歧义，建议修正）**：报告"结论"段与复核任务书称用 `reports/field_map.inferred.json` 做 build 验证，实测该字典无字段 value，直接用它 build 会得到空 body；4/4 通过的实测配置是 `tools/probe/field_map.stage2-verify.json`（报告第 4 节正文/命令示例已用它）。核心结论不受影响。
2. **OBS-2（方法学瑕疵，不影响结论）**：`analyze_signature_chain.py` 反汇编起点 `off-16` 未做 4 字节对齐，capstone 首指令为错对齐解码产物；"非函数入口"结论应由偏移 mod4≠0 + 字节内容 + 字符串位置三项独立证据支撑，而非该反汇编启发式。
3. **OBS-3（注释与实现不符）**：`harvest_pb_messages.py` 注释称 mmap，实际为整文件读入内存。
4. **补充事实（非问题）**：仓库 HEAD 为 `a0ccc3a`（阶段2 提交，工作区干净），`1df478d` 是其祖先；题面"1df478d 基础上有未提交改动"的描述与当前磁盘状态不符，阶段2 内容已完整提交。

## 四、总评

阶段2 的六项关键结论全部经独立复核成立：XOR-0x10 编码与明文 0 条、4844/4980 全量清单与 159 行字典、配置逐项标注与 null 字段不猜测、签名偏移非函数入口且算法密钥仅运行时可得、build/decode 稳定且 send 缺参拒绝零联网、脚本无明显错误。三条观察项均为文档/方法学层面的小瑕疵，**不影响 PASS 结论**。

---
*Verifier·独立复核·只读验证·未发包·未改任何目标文件（本报告为本次复核唯一新建文件）。*
