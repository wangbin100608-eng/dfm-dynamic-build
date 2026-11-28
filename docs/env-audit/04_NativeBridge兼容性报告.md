# Native Bridge 兼容性报告（任务4）

- 测试时间：2026-11-28
- 核心发现：**Undefined instruction 死循环是人为 patch 的转译器引入，不是目标 APP 或转译器原生缺陷**

## 4.1 Native Bridge 审计

| 实例 | 转译器来源 | 大小 | BuildID | md5 |
|---|---|---|---|---|
| 生产 `redroid11` | bind mount `/root/盘点/libndk_translation.so` | 1,654,288 | `8d5bb5dd...` | `0afc37ea...` |
| 测试 `redroid-x86-test` | 镜像原生 `/system/lib64/libndk_translation.so`（2021-10-06） | 1,654,288 | `8d5bb5dd...` | `ae34fb02...` |

两者 BuildID 相同、大小相同，但**二进制有 11 字节差异**。

## 4.2 版本与来源

- 原生版：redroid 11.0.0 镜像内置，日期 2021-10-06，是 Android 11 官方 NDK Translation (libnb.so)。
- 生产版：宿主机 `/root/盘点/libndk_translation.so`，未记录来源，通过 Docker bind mount 覆盖。

## 4.3-4.4 Undefined instruction 分析

错误日志：
```
E/ndk_translation: Undefined instruction 0x5ea1b801 at 0x0000739b6dd78748
E/ndk_translation: Undefined instruction 0x5ea1b842 at 0x0000739b75b94ac0
```

- 二进制位：`0101 1110 1010 0001 1011 1000 0000 0001`
- 属 ARM64 Advanced SIMD/FP data-processing 空间（`0x5E00_0000-0x5FFF_FFFF`），是 FP16/半精度 SIMD 指令族（`fmov`/`fadd` H 变体）。
- **关键**：`0x5ea1b801` 在 `libUE4.so` 静态内容中**出现 0 次**——错误地址 `0x739b...` 是运行时 JIT/解密生成的代码，不是 so 静态指令。
- ANR trace 铁证（生产实例）：
  ```
  GameActivity.onCreate → System.loadLibrary → Runtime.nativeLoad
    → libndk_translation.so::ExecuteGuest
    → DecodeSimdScalarTwoRegMisc → DecodeDataProcessingSimdAndFp
    → __android_log_print("Undefined instruction ...")
  ```
- 生产实例死循环：同一地址 **44,933 次 / 3 秒**，CPU 100%，3 秒刷 10 万行日志。
- capstone 5.0.7 亦无法解码该指令（属较新 ARMv8.2+ 扩展）。

## 4.5 11 字节 patch 定位（决定性证据）

两处差异，均为 NOP (`0x90`) 替换：

| 偏移 | 所在函数 | 原生字节 | 生产字节 |
|---|---|---|---|
| `0x14639e` | `InitInterpreter` | `e8 ed 45 03 00` (CALL) | `90 90 90 90 90` (5×NOP) |
| `0x16d2cc` | `intrinsics::Umaal` | `0f 85 95 00 00 00` (JNE) | `90 90 90 90 90 90` (6×NOP) |

**这两个 patch 破坏了转译器初始化/内建函数逻辑，是死循环的直接原因。**

## 4.6 独立实例对照验证（三实例因果闭环）

| 指标 | 生产 `redroid11`（patched） | 测试 `redroid-x86-test`（原生 2021） | 验证 `redroid-patched-test`（patched） |
|---|---|---|---|
| 转译器 md5 | `0afc37ea...` | `ae34fb02...` | `0afc37ea...`（与生产一致） |
| 错误频率 | 44,933 次/3秒（死循环） | **1 次/4秒** | **109 次/累计采样，持续上升** |
| CPU | 104%（单核满载） | 0.74%（空闲） | **184-330%（多核）** |
| 错误地址低 12 位 | `...748` | `...748` | `...748`（完全一致） |

**因果闭环**：把 patched 转译器挂到全新独立实例后，死循环精确复现（同一错误地址、CPU 飙升、错误刷屏）；原生转译器实例则在进入 GameActivity 后触发 **`Fatal signal 4 (SIGILL), code -6`** 崩溃（native 无法翻译该指令 → 非法指令信号 → 进程死亡）。**证明死循环由 patched 转译器（11 字节 NOP）直接导致，而非生产实例其它因素。**

**两种失败模式**：
- 原生转译器：`Undefined instruction` 1 次 → SIGILL → 进程崩溃
- patched 转译器：`Undefined instruction` 持续刷屏 → 死循环 → CPU 满载不崩溃

**结论**：无论哪个版本，目标 APP 在 x86_64 + Native Bridge 上都无法运行。patch 只是把"快速崩溃"变成"永久卡死"，起到反效果。

## 4.7 其他兼容方案评估

| 方案 | 评估 |
|---|---|
| 换新版转译器（如 Android 14 的 libnb） | 需匹配 redroid 11 的 ART/NDK ABI，未验证；不可直接替换生产实例 |
| 禁用 ARM Bridge 只跑原生 x86_64 | 目标 APK 无 x86_64 库（见任务2），无法运行 |
| 静态 patch 掉 UE4 的 FP16 指令 | 561MB so，指令在运行时生成，无法静态 patch |
| Waydroid + 软件渲染 | 见环境专项总报告：SurfaceFlinger present 死锁 |
| 真机 arm64 | 唯一可靠路径，需 root 用于 Frida |

## 4.8 生产实例安全

- 所有测试在独立实例 `redroid-x86-test`（端口 5556）完成。
- **未替换生产实例 `redroid11` 的任何组件**。
- 生产实例当前仍挂载 patched 转译器——建议恢复为原生版（去掉 bind mount）以消除死循环。

## 禁止行为遵守

- 未在未经验证的情况下替换生产实例组件。
- patch 版本仅在独立实例对照测试，生产实例保持原状。
