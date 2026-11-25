# 无设备动态反编译（Unicorn 指令级模拟）实测报告

> 目标：在无 root 真机、无 KVM、无 Android 系统的纯 Linux 服务器上，对三角洲行动官服 `libUE4.so`（355MB, ARM64）做动态分析。
> 时间：2026-11-25 · 服务器 45.63.100.185（Hyper-V，无嵌套虚拟化）

## 1. 结论先行

**用 Unicorn 模拟 CPU 直接执行 so 机器码的方案已跑通**，这就是本环境下的"动态反编译"：不启动 Android、不依赖 Frida server，把 native 函数加载进模拟 ARM64 CPU 逐指令执行，观察运行时行为。

同时得到三个硬性事实（都影响后续接口定位）：
1. 当前版本关键字符串是**明文**，XOR 0x10 混淆假设不适用（已用确定性计数验证）。
2. 静态报告里的"函数偏移"（如 `SendTssData@0x5c32655`）是**字符串字面量地址**，不是代码入口，直接模拟会非法指令中断。
3. so 内**无序列化 FileDescriptorProto**，protobuf 字段号静态不可得——仍需真机 Frida 导出。

## 2. 跑通的真实函数：_Znwm (operator new)

`libUE4.so` 导出的 `_Znwm`（vaddr `0xab12f98`）是一个 thunk。用 `emu_native_trace.py` 模拟执行，成功跟随跳转进入真实函数体并逐指令记录：

```
0x10ab12f98  mov  w1, wzr                    ← thunk 入口
0x10ab12f9c  b    #0x1104b4034               ← 跳到真实函数
0x1104b4034  str  x21, [sp, #-0x30]!         ← 函数序言
0x1104b4038  stp  x20, x19, [sp, #0x10]
0x1104b403c  stp  x29, x30, [sp, #0x20]
0x1104b4040  add  x29, sp, #0x20
0x1104b4044  mov  w20, w1
0x1104b4048  mov  x19, x0
0x1104b404c  bl   #0x11049de7c
0x11049de7c  ret
```

验证点：
- ELF 7 个 PT_LOAD 段正确映射到 Unicorn 地址空间（base `0x100000000`）；
- AArch64 指令被 capstone 正确反汇编；
- 模拟执行跨越 thunk 跳转、栈操作、BL 调用，全程受控；
- 冒烟测试（`mov x0,#42`）x0 结果正确。

这证明：只要给出**真实代码入口**，就能对 so 内任意函数做指令级动态分析（寄存器/栈/内存读写/CALL 链全部可观察）。

## 3. 工具链（tools/emu/）

| 脚本 | 作用 | 状态 |
|---|---|---|
| `elf_util.py` | ARM64 ELF 映射器：PT_LOAD 段 → Unicorn，符号表解析 | ✅ 实测通过 |
| `emu_native_trace.py` | 指令级模拟 + hook（指令/CALL/内存/中断），寄存器与栈 dump | ✅ 跑通真实函数 |
| `emu_string_decrypt.py` | 模拟解密函数 / 简单 XOR | ✅ XOR 模式通过 |
| `emu_descriptor.py` | descriptor blob 扫描 + ReadTag 模拟 | ✅ 扫描确认无 blob |
| `find_xrefs.py` | 字符串地址 → 引用它的代码入口（ADRP+ADD） | ⚠️ 目标串未用标准 xref 模式 |
| `xor_string_harvest.py` | XOR 0x10 确定性验证 / 挖矿 | ✅ --verify 通过 |
| `config.example.json` | 偏移/参数模板 | — |

## 4. 为什么还没直接拿到接口字段号

三条路都指向同一个结论：字段号必须靠**运行期**数据。

| 路径 | 结果 |
|---|---|
| 静态 descriptor 扫描 | so 内无序列化 FileDescriptorProto → 字段号不可得 |
| Unicorn 模拟解析函数 | 需真实函数入口；而消息名是字符串地址，xref 未用标准 ADRP+ADD 模式，入口暂未定位 |
| 真机 Frida `find_descriptor.js` | 未执行（无 root 真机） |

## 5. 下一步（把模拟推进到目标函数）

1. 用 `find_xrefs.py` 扩展支持 LDR literal / 间接表寻址，定位 `pb.CSMallBuyReq` 等字符串被哪段代码引用，拿到真实函数入口。
2. 对定位到的 protobuf 序列化函数，用 `emu_native_trace.py` 喂入样本，观察 ReadTag 读出的 field number。
3. 或回到最实际的一条：在**已 root 真机**上跑 `tools/probe/find_descriptor.js`，一次性导出 `cs_mall.proto` 全部字段号——这是最省事的路径。

## 6. XOR 0x10 验证数据（确定性计数）

| 词 | 明文出现 | XOR 0x10 编码出现 |
|---|---|---|
| cmd_id | 3 | 0 |
| goods_id | 2 | 0 |
| buy_price | 2 | 0 |
| CSMallBuyReq | 1 | 0 |
| currency_type | 3 | 0 |
| bullet_gid | 1 | 0 |

`Buy~ydyq|yju` XOR 0x10 = `Reinitialize` 是 XOR 自反造成的巧合，不代表系统性混淆。历史报告的 XOR 结论在**当前版本**不成立。
