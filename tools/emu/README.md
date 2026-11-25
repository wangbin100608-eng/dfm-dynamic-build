# tools/emu — 无设备动态反编译（Unicorn CPU 指令级模拟）

## 为什么要这个

没有 root 真机、没有 KVM、REDroid/AVD 都起不来时，仍然可以做「动态」分析：**用 Unicorn 把 ARM64 机器码加载进模拟 CPU 直接执行**，观察运行时行为。它不依赖 Android 系统、不依赖 Frida server、不需要设备——在纯 Linux 服务器上就能跑 native 函数。

与静态反汇编（capstone/IDA）的区别：静态只看指令，模拟执行能拿到**运行时计算出的值**（解密字符串、protobuf 字段号、签名中间结果），这正是静态逆向 `libUE4.so` 时的最大缺口。

## 工具清单

| 脚本 | 作用 | 解决的问题 |
|---|---|---|
| `emu_native_trace.py` | 加载 libUE4.so 到 Unicorn，从指定偏移模拟执行，hook 指令/CALL/内存访问，dump 寄存器与栈 | 动态观察 native 函数行为，替代 Frida 的指令级 hook |
| `xor_string_harvest.py` | 确定性验证/挖矿 XOR 0x10 字符串 | 验证混淆假设（实测结论：当前版本关键串为明文） |
| `find_xrefs.py` | 从字符串地址反查引用它的代码位置（AArch64 ADRP+ADD） | 静态报告的"函数偏移"实为字符串地址，需 xref 找真实代码入口 |
| `emu_descriptor.py` | 模拟 protobuf 序列化路径，从 `CodedInputStream::ReadTag` / DescriptorPool 动态提取字段号 | 补齐 `CSMallBuyReq` 等消息的字段号（静态无法映射） |
| `elf_util.py` | ELF 加载器：解析 PT_LOAD、映射段到 Unicorn、解析动态符号表 | 让 .so 能在模拟地址空间正确运行 |
| `config.example.json` | so 路径、函数偏移、模拟参数模板 | 集中配置，避免硬编码 |

## 实测结论（2026-11-25，真实 libUE4.so 355MB）

1. **XOR 0x10 混淆假设在当前版本不成立**：对 `cmd_id`/`goods_id`/`buy_price`/`CSMallBuyReq`/`currency_type` 等关键术语，XOR 编码出现次数全为 0，明文大量存在。`Buy~ydyq|yju` XOR 0x10 = `Reinitialize` 只是巧合（XOR 自反）。历史报告的混淆结论不适用于当前版本。
2. **静态报告的"函数偏移"是字符串地址**：`0x5c32655` 处字节是 ASCII `"UDFMGameTss::SendTssData\0"`，直接模拟触发非法指令中断。真实代码入口需先用 `find_xrefs.py` 反查 ADRP+ADD 引用。当前 so 对这些字符串的 xref 未用标准 ADRP+ADD 模式（可能用 LDR literal/间接表），需进一步定位。
3. **descriptor blob 不存在**：扫描确认 so 内无序列化 FileDescriptorProto，字段号静态不可得——与 `reports/HAVAL_PURCHASE_API.md` 一致，必须靠真机 Frida `find_descriptor.js` 导出。
4. **Unicorn 引擎本身工作正常**：冒烟测试（mov x0,#42）通过；ELF 7 个 PT_LOAD 段映射成功。这是"无设备动态执行"的能力基础，但要把 so 内真实函数跑起来，仍需先解决上述 xref/函数入口问题。

## 前提与局限（工程事实）

1. **需要真实函数入口和调用约定**。Unicorn 不做符号解析自动调用，需给出函数文件偏移、参数（寄存器/栈）、返回地址。偏移来自静态逆向（`reports/HAVAL_PURCHASE_API.md` 已有大量候选）。
2. **不能跨 so 自动解析依赖调用**。函数内部调用其他 so（libc/其他 SDK）时，需要在 hook 里 stub 掉或手动实现（脚本提供 `stubs` 配置）。
3. **C++ ABI / TLS / JNI 复杂调用难模拟**。纯算法函数（解密、hash、protobuf 编解码）成功率高；涉及 JNIEnv、线程、网络的函数不适合。
4. **这是辅助手段，不替代真机抓包**。网关地址、cmd_id、会话密钥、TSS 签名这类依赖真实运行环境的值，模拟拿不到；但**字段号、解密算法、字符串明文**这类纯计算问题，模拟能解决。

## 用法

```bash
# 1) 提取 libUE4.so（从已下载 APK）
unzip -j /root/dfm_dynamic_build/apk/dfm.apk \
  lib/arm64-v8a/libUE4.so -d /root/dfm_dynamic_build/reports/

# 2) 配置
cp config.example.json config.json
# 编辑 so_path / function_offset / args

# 3) 动态跟踪真实函数（已验证：_Znwm @ 0xab12f98）
python3 emu_native_trace.py --so libUE4.so --offset 0xab12f98 --count 10

# 4) 确定性验证某词是否被 XOR 0x10 混淆
python3 xor_string_harvest.py --so libUE4.so --verify "cmd_id,goods_id,CSMallBuyReq"

# 5) 动态字符串解密（简单 XOR / 模拟 so 函数）
python3 emu_string_decrypt.py --input-hex <密文> --xor 0x10

# 6) 动态导出 protobuf 字段号（路径B，需 ReadTag 偏移）
python3 emu_descriptor.py --so libUE4.so --readtag-off 0x... --sample-hex 0801...
```

依赖：`pip3 install unicorn pyelftools capstone`（纯 Python + C 扩展，无需 Android/设备）。
