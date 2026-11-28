# APK ABI 分析报告（任务2）

- APK：`/root/三角洲/dfm-apk/dfm-official-1.201.37119.49.apk`
- 大小：1,625,586,573 字节
- 包名：`com.tencent.tmgp.dfm`（三角洲行动国服官服）
- 分析方式：Python zipfile 遍历全部条目 + ANR trace 的 Libraries 段 + readelf

## 2.1-2.4 lib 目录与 split 检查

| ABI | SO 数量 | 存在 |
|---|---|---|
| arm64-v8a | **90** | ✅ |
| x86_64 | 0 | ❌ |
| x86 | 0 | ❌ |
| armeabi-v7a | 0 | ❌ |
| armeabi | 0 | ❌ |

- **单 APK，无 split APK**（zip 内无 `split` 相关条目、无嵌套 `.apk`）
- 90 个 arm64 SO 按大小 Top：
  - `libUE4.so` 561,598,448 字节（UE4 引擎主库）
  - `libgcloud.so` 11.6MB、`libtersafe.so` 5.7MB（ACE 反作弊）、`libPcdnTegTransSdk.so`、`libMSDKPIXCore.so` 等

## 2.5 实际加载的 Native SO

从 ANR trace `/data/anr/anr_2026-11-28-11-16-50-298` 的 `Libraries:` 段（游戏进程实际加载，14 个）：

```
libCrashSightPlugin.so   libGCloudVoice.so    libGPM.so
libHttpDnsPlugin.so      libMSDKPIXCore.so    libPcdnTegTransSdk.so
libPluginCrosCurl.so     libTDataMaster.so    libgcloud.so
libgcloudcore.so         libmagt_sdk.so       libtersafe.so
libtgpa.so               libtprt.so
```

另有 `libUE4.so`/`libPixUI*`/`libAk*`/`libopencv*` 等在游戏初始化后期按需加载（进程 RSS 从 330MB 涨到 1GB 证实）。

## 2.6 ABI 依赖报告结论

**应用是纯 arm64-v8a，无任何 x86/x86_64 native 库。** 在 x86_64 宿主上只能通过 Native Bridge（arm64→x86_64 二进制翻译）运行，这是任务4 存在的前提。

`libUE4.so` 的 ELF 头：
```
Class: ELF64   Type: DYN   Machine: AArch64
```

## 关键推论

- EGL 初始化正常（SwiftShader）**不等于** APP 兼容性正常——APP 的核心逻辑在 arm64 native 库里。
- 任务3 的"原生 x86_64 基准"因 APK 无 x86_64 库而无法直接跑通目标 APP，只能作为平台能力基准。
