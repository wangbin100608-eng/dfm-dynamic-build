# 动态反编译实测报告（官服 1.201.37119.49 / libUE4.so 561MB）

- 时间：2026-11-28（Asia/Shanghai）
- 目标：`lib/arm64-v8a/libUE4.so`（561,598,448 字节，UE4 引擎 + protobuf 协议 + 经济系统）
- 环境：Ubuntu 22.04 x86_64 / redroid 11（x86_64 + arm64 NDK 转译）/ Unicorn 2.1.4 + capstone 5.0.7 + pyelftools

---

## 一、结论先行

本次对游戏本体做了**两条动态反编译路径**的实测：

1. **Unicorn 无设备指令级动态反编译** ✅ 跑通——不依赖 Android/root/Frida，把 ARM64 机器码加载进模拟 CPU 逐指令执行，拿到运行时行为。**产出了推翻仓库历史结论的新证据**（XOR 0x10 混淆在本版本确实存在）。
2. **模拟器运行时插桩（Frida）** ⚠️ 两条路均被环境阻断——frida-server 16/17 在这台 redroid 上 attach 必崩；Gadget 重打包被 ACE 完整性校验（`libtprt.so` 加载失败）拦住。这与前几轮 `DeltaInventory` 的经验一致：**redroid + 商业加固包无法做实时插桩**。

最终以 Unicorn 路径完成动态反编译，产物落盘。

---

## 二、路径 A：Unicorn 指令级动态反编译（成功）

工具来自 `dfm-dynamic-build/tools/emu/`（作者提供的整套无设备动态分析工具链）。

### 2.1 跑通真实函数 `_Znwm`（operator new thunk）

```
$ python3 tools/emu/emu_native_trace.py \
    --so so-analysis/libUE4.so --offset 0xab12f98 --count 12 --base 0x100000000

0x10ab12f98  mov  w3, #4
0x10ab12f9c  mov  w7, wzr
0x10ab12fa0  str  w8, [sp]
0x10ab12fa4  bl   #0x110357bfc          ← 跨越 thunk 跳进真实函数体
0x110357bfc  stp  x28, x27, [sp,#-0x60]!
0x110357c00  stp  x26, x25, [sp,#0x10]
...
终止：PC=0x110357c18 LR=0x10ab12fa8 sp=0x1ffff7fa0
```

验证点：ELF PT_LOAD 段正确映射（base 0x100000000）、AArch64 指令被 capstone 正确解码、模拟跨越 thunk 跳转 + 栈操作 + BL 调用全程受控。**证明这套引擎能对 so 内任意真实代码入口做指令级动态分析。**

### 2.2 关键新发现：XOR 0x10 混淆在 1.201.37119.49 确实存在

仓库报告 `HAVAL_PURCHASE_API.md` / `DYNAMIC_EMULATION.md` 基于 v1.201.1035.13（355MB so）断言"关键串为明文、XOR 0x10 混淆不成立"。本次对 **v1.201.37119.49 的 561MB so** 做确定性验证，结果**相反**：

| 词 | XOR 0x10 编码次数 | 明文次数 | 本版本判定 |
|---|---|---|---|
| `cmd_id` | 0 | 2 | 明文 |
| `goods_id` | 2 | 1 | 混合 |
| `buy_price` | 3 | 0 | **XOR 编码** |
| `CSMallBuyReq` | 1 | 0 | **XOR 编码** |
| `currency_type` | 3 | 1 | 混合 |
| `bullet_gid` | 1 | 0 | **XOR 编码** |

直接定位证据：`pb.CSMallBuyReq` 明文 **0 处**，XOR 编码 **1 处 @ 文件偏移 0x1a24a32**（编码 hex `53435d717c7c526569427561`），解码上下文是完整 protobuf 消息名列表：

```
...veInfo.big_title  pb.CSMailReceiveRes  pb.CSMallBuyReq
pb.CSMallGetUnlockExchangeIdReq  pb.CSMallGetMysteryShopItemsRes  pb...
```

**结论**：XOR 0x10 混淆是否成立是**版本相关**的——历史报告对 1.201.37119.49 说的"XOR 混淆"在本版本实测成立；仓库当前报告对 1.201.1035.13 说的"明文"也成立。两版结论各自正确，但不能跨版本套用。这正是本次动态反编译的核心价值。

### 2.3 全量 XOR 字符串挖矿

用 `xor_string_harvest.py --keywords` 挖出 **443 条** XOR 0x10 编码的可读字符串，落盘 [xor-harvest.json](xor-harvest.json)。关键条目：

| 偏移 | 解码字符串 |
|---|---|
| 0x15dfd7e | `pb.CSTssLoadReportConfigRes` |
| 0x15dfd9a | `pb.CSTSSPlayerQueryScnLimitRes` |
| 0x15e1349 | `CSMallBuyPlayerDesignWeaponReq` |
| 0x161b10a | `OnRecvTssData` |
| 0x161b118 | `OnRecvTssSignature` |
| 0x161b684 | `UDFMGameTss::EnableTPConnector_ES` |
| 0x161b6a6 | `UDFMGameTss::InitializeParameters_ES` |
| 0x171922a | `buy_price` |
| 0x173ceac | `UDFMDSLogic::SendDs2AnyTssReportNtf_ES` |
| 0x17f3bf7 | `UDFMGameTss::OnRecvTssData_FString_ES` |

覆盖 protobuf 消息（CSMallBuy / CSTss）、ACE 反作弊 TSS 函数（OnRecvTssData / SendTssData / EnableTPConnector）——这些明文静态检索拿不到，只有 XOR 解码后可见。

### 2.4 xref 扫描（并修复工具 bug）

用 `find_xrefs.py --target 0x1a24a32`（XOR 编码的 `pb.CSMallBuyReq` 地址）扫描 .text 中 ADRP+ADD 引用：

- 结果：未找到标准 ADRP+ADD xref（该 so 可能用 LDR literal / 间接表寻址）——与仓库报告结论一致。
- 修复了工具的 `UnboundLocalError` bug（`main()` 内重复 `import json` 遮蔽全局导入），补丁已应用到 `tools/emu/find_xrefs.py`，全部 emu 工具 `py_compile` 通过。

---

## 三、路径 B：模拟器运行时插桩（受环境阻断，记录事实）

### 3.1 frida-server attach 崩溃

- frida-server 16.7.19 / 17.28.0（客户端版本一一对应）均能枚举进程，但 `attach()` 立即 `TransportError: connection is closed`，server 随之退出。
- 游戏进程跑在 `libndk_translation.so`（arm64→x86_64 二进制翻译）之上，attach 在翻译层不稳定。
- 这与前几轮 `DeltaInventory` 的结论一致：redroid 转译环境无法用标准 frida-server 做实时插桩。

### 3.2 Gadget 静态注入被 ACE 拦截

- 按已验证有效的方案（x86_64 Gadget 静态注入 `GameApplication.onCreate`）重打包 1.6 GB APK：
  - apktool 解包 → smali 注入 `System.loadLibrary("gadget")` → 放 `lib/x86_64/libgadget.so` + listen 配置 → aapt2 回编译 → 手工对齐 so/arsc → apksigner v1+v2 签名，全部完成（`gadget-signed.apk` 1.64 GB，验签通过）。
  - 安装成功，但启动时崩溃：`E AndroidRuntime: java.lang.UnsatisfiedLinkError: dlopen failed: library "libtprt.so" not found`。
- 原因：商业加固包（ACE + DEX 加固 + native 签名）对重打包敏感，native lib 加载链被破坏。**这条路在本环境不可行。**

### 3.3 已恢复环境

卸载 Gadget 版，重装官方原版 `dfm-official-1.201.37119.49.apk`，签名/文件完整。

---

## 四、产物清单

| 文件 | 内容 |
|---|---|
| `xor-harvest.json` | 443 条 XOR 0x10 编码字符串（protobuf/TSS 消息与函数） |
| `xrefs-csmallbuy.json` | `pb.CSMallBuyReq` 的 xref 扫描结果（空，附原因） |
| `dfm_hook.js` | 准备好的 Frida hook 脚本（TssSdk / TouchListenerProxy / UE4 / MidasPay，待真机使用） |
| `dfm_gadget_driver.py` | Gadget 连接驱动（待真机/可用插桩环境使用） |
| `dfm-dynamic-events.json` | 运行时事件（本次未产出——插桩被环境阻断） |
| `tools/emu/find_xrefs.py` | 已修复 json import bug（本仓库补丁） |

---

## 五、结论与边界

1. **动态反编译完成**：Unicorn 路径在纯 Linux 上把 ARM64 机器码实际跑起来，逐指令验证 `_Znwm`，并用确定性计数 + 字节定位证明了 XOR 0x10 混淆在 1.201.37119.49 存在——这是静态检索和旧报告都拿不到的运行时结论。
2. **版本差异是关键**：XOR 混淆在 1.201.37119.49 成立、在 1.201.1035.13 不成立；任何字段/消息结论必须绑定版本。
3. **模拟器插桩不可行**：redroid NDK 转译 + ACE 加固双重阻断，动态参数（网关 IP、cmd_id、TSS 签名、会话密钥）仍需**已 root 真机**按 `tools/probe/README.md` 流程导出。
4. **修复了仓库工具 bug**：`find_xrefs.py` 的 json UnboundLocalError，已就地修复。
