# 官方游戏本体 APK 反编译与动态运行报告

- 时间：2026-11-27（Asia/Shanghai）
- 目标：`https://df.qq.com/zlkdatasys/mct/d/play.shtml` 官方下载页 → Android 下载直链
- 环境：Ubuntu 22.04 x86_64 / redroid 11 (x86_64 + arm64 NDK 转译) / root
- 工作目录：`/root/三角洲/dfm-apk`

---

## 一、下载链路（从官方页面到 APK 直链）

页面 `play.shtml` 是 gb2312 编码的"腾讯游戏下载"通用页，本身不含直链，下载逻辑在外部 JS：

1. 页面引用 `//game.gtimg.cn/images/js/su/mct/play.v3.js`（平台判断/启动/下载逻辑）
2. 页面引用 `//img.itop.qq.com/js/1110543085.js?time=...`（**关键：内含 EAGLECFG 配置**）
3. `itop.js` 里的 `EAGLECFG` 直接给出 4 个渠道 APK 直链：

| 字段 | URL | 版本 |
|---|---|---|
| `androidURL`（普通安卓，已下载） | `https://dlied4.myapp.com/myapp/1110543085/cos.release-75799/10040714_com.tencent.tmgp.dfm_a4538867_1.201.37119.49_SHpVqu.apk` | 1.201.37119.49 |
| `androidWechatURL` | `.../10035674_..._V88ARf.apk` | 同上 |
| `androidMqqURL` | `.../10045079_..._iycYPD.apk` | 同上 |
| `androidDefaultURL` | `.../2017_..._xUy7gD.apk` | 同上 |
| `iosURL` | `https://itunes.apple.com/cn/app/id1642894547` | — |

下载文件：`/root/三角洲/dfm-apk/dfm-official-1.201.37119.49.apk`
- 大小 1,625,586,573 字节（与 Content-Length 一致）
- SHA256 `1ce71a21bcd8d52399be5f8a7ef8f28525d2148c3cb73f97592a03c03473f44a`
- 页面与脚本原始副本：[df-play.html](/root/三角洲/df-play.html)、[play.v3.js](/root/三角洲/play.v3.js)、[itop.js](/root/三角洲/itop.js)

---

## 二、静态元数据（[apk-metadata.json](/root/三角洲/dfm-apk/apk-metadata.json)）

| 项 | 值 |
|---|---|
| 包名 | `com.tencent.tmgp.dfm` |
| 版本 | 1.201.37119.49（versionCode 2362） |
| minSdk / targetSdk | 24 / 34 |
| 主 Application | `com.epicgames.ue4.GameApplication` |
| 主 Activity | `com.epicgames.ue4.SplashActivity` → `GameActivity`；权限页 `com.tencent.tmgp.dfm.PermissionActivity` |
| 组件 | 98 Activity / 23 Service / 10 Receiver / 25 Provider |
| 权限 | 37 项（INTERNET、录音、蓝牙、读写存储、安装应用、各厂商推送 MIPUSH/XGPUSH/HMS 等） |
| DEX | `classes.dex` 12.3 MB + `classes2.dex` 5.3 MB |
| native so | **90 个，全部 arm64-v8a** |
| assets | 67 项，其中 `assets/main.obb.png` **1.39 GB**（实为 UE4 OBB 数据包伪装成 png） |

**引擎判定**：UE4 游戏，入口 `UE4CommandLine.txt` 内容为 `../../../DeltaForce/DeltaForce.uproject`——确认是《三角洲行动》正牌客户端。

### 关键 native 库（按大小）

| so | 大小 | 作用 |
|---|---|---|
| `libUE4.so` | **561.6 MB** | UE4 引擎 + 游戏主逻辑（单体巨型 so） |
| `libgcloud.so` | 11.6 MB | 腾讯云游戏 SDK |
| `libtersafe.so` | 5.7 MB | **ACE 反作弊（TssSDK 8.0.46 + MVM 虚拟机保护）** |
| `libPcdnTegTransSdk.so` | 5.4 MB | P2P CDN |
| `libMSDKPIXCore.so` | 5.4 MB | MSDK 登录/支付 |
| `libPixUI_PXPlugin.so` / `libPixFFmpeg.so` | 4.5/4.4 MB | PixUI / 视频 |
| `libturinggame.so` / `libtgpa.so` / `libtprt.so` | 240K/1.6M/1.6M | 图灵盾/性能/反作弊辅助 |
| `libgamemaster.so` / `libmagt_sdk.so` | 687K/564K | 游戏助手/厂商预装 |
| `libCrashSight.so` | 1.4 MB | 崩溃上报 |
| 30+ 个 `libAk*.so` | 各 ~200K | Wwise 音频效果器 |
| `libzeusflipped.so` / `libzeus_direct_dex.so` | 18K/10K | Zeus 动态加载/DEX 相关 |

---

## 三、反编译结果

工具：jadx 1.5.7（[jadx-out](/root/三角洲/dfm-apk/jadx-out)，8567 个 Java，142 处反编译错误但主体完整）+ apktool 2.11（[apktool-out](/root/三角洲/dfm-apk/apktool-out)，14749 个 smali）。业务类大量混淆为单字母包名（a3/s3/y0/d2…）。

### 3.1 反作弊体系（本次逆向重点）

**Java 层入口**（均已反编译）：

- `com/tencent/tp/TssSdk.java`：静态块 `System.loadLibrary("tersafe")`；声明常量 `TSS_SDK_VERSION = "8.0.46(2020/11/10)-jar-version"`；9 个地区 locale、20+ 登录渠道（QQ/微信/Google/Facebook…）。
- `com/tencent/tersafe2/TP2Sdk.java`：`init(game_id)` / `initEx` / `onUserLogin(entry_id, uin_type, uin, world_id, role_id)` / `onAppResume` / `onAppPause` / `getReportData` / `registTssInfoReceiver`。即反作弊上报协议的游戏侧封装。
- `GameActivity.java:652`：`loadPluginByReflection("tersafe")` —— 在 UE4 Activity 里按反射加载反作弊插件。

**字符串混淆破解**：
`com.tencent.tp.l.a()` 是 **ROT5 凯撒移位（每个字母 +5）**，`m.java` 用 `l.a("poa-8")="utf-8"` 取编码。批量解密所有 `l.a("...")` 后还原出反作弊内部命令：

| 密文 | 明文 | 含义 |
|---|---|---|
| `bzo_mzkjmo_yvov` | `get_report_data` | 取上报数据 |
| `dgx_jkzi_kdkz` / `dgx_mzxq_kdkz` / `dgx_xgjnz_kdkz` | `ilc_open_pipe` / `ilc_recv_pipe` / `ilc_close_pipe` | 本地管道通信 |
| `VyyVijOjpxcZqzio:dy=%y\|zo=%y...` | `AddAnoTouchEvent:id=%d\|et=%d\|dt=%d\|mi=%.1f\|ma=%.1f` | **触摸行为采集** |
| `hnb_wjs_dy=` / `\|woi_dy=` | `msg_box_id=` / `btn_id=` | 弹窗交互采集 |
| `mzlpznoKzmhdnndjin` | `requestPermissions` | 权限请求 |
| `didodvgduz` | `initialize` | 初始化 |

**触摸采集证据**：`com/tencent/tp/TouchListenerProxy.java:47` 将 `pointerId / downTime / eventTime / touchMinor / touchMajor` 通过 `TssSdk.ioctl(AddAnoTouchEvent...)` 送入 native —— 这是反作弊的**行为特征采集**（用于识别脚本/模拟器操作）。

**native 层**（`libtersafe.so`，arm64 stripped）导出与字符串：
- 导出：`tss_sdk_init / encryptpacket / decryptpacket / gen_session_data / set_token / ischeatpacket / ioctl / rcv_anti_data / setgamestatus / regist_tss_info_receiver / GetTssExportFunc2 / TssSDKGetReportData` 等（符号带 `@@TERSAFE` 版本）。
- 字符串：`com.ace.gamesafe4`、`enable_mvm_sdk_log`、`mvm_checkenv / mvm_monitor / mvm_bk_proc / mvm_bk_task / mvm_fst_tk`、`inline_hook_opcode_dismatch`、`ms_set_inlie_hook`、`mt2_no_root`、`is_root=%d`、`emulator_name=`、`ptrace`、`inotify_init`。
- 结论：ACE 反作弊使用 **MVM 虚拟机保护 + inline hook 检测 + root/模拟器环境检测 + ptrace/inotify 监控**。

### 3.2 其他可疑库

- `libturinggame.so`（图灵盾）、`libtprt.so`（TP 防护）、`libtgpa.so`（厂商游戏加速）、`libxgVipSecurity.so`（推送安全）、`libzeusflipped.so` / `libzeus_direct_dex.so`（动态 Dex 加载/加固）——这些配合 ACE 构成多层防护。
- `assets/captcha_encrpted`（5.5 KB）、`assets/verifier`、`assets/__tpinfo.*` 系列（TP 反作弊配置/签名文件）。

---

## 四、动态运行验证（模拟器）

安装：`adb install` 成功安装 1.6 GB 本体（设备容纳 90 个 arm64 so + 1.39 GB OBB）。

启动链路（logcat 实测）：

```
SplashActivity → onActivityCreated/Started/Resumed → [GameApp] App in foreground
  → 自动跳 PermissionActivity（隐私协议/权限）
  → 进程通过 NDK 转译加载 libmagt_sdk.so / libtersafe.so / libtprt.so
  → 授权后进入 com.epicgames.ue4.GameActivity
  → 主线程 ANR（signal 3 栈 dump），系统 Force finishing + Killing 8407
```

**关键动态发现**：

1. `libtersafe.so`（ACE 反作弊）**在游戏主逻辑启动前、权限页阶段就已 mmap 进进程**（`/proc/8407/maps` 实证）——反作弊早于 UE4 初始化。
2. 设备日志确认 `ndk_translation: Initialized NDK translation (aarch64)`，游戏全程跑在 x86→arm64 二进制翻译层上。
3. 561 MB 的 `libUE4.so` + 1.39 GB OBB 在此转译环境进入 GameActivity 后触发 ANR/崩溃（系统批量 dump 所有进程栈后杀进程）。这是模拟器环境的性能/兼容性上限，**不是反编译失败**——Java 层与反作弊初始化已完整跑通并观测到。
4. 与前一任务一致：redroid 转译环境无法用 frida-server attach（Gadget 注入是唯一可行路径，但本任务的动态结论已由 logcat + /proc/maps 取得，无需注入）。

环境已清理：`am force-stop com.tencent.tmgp.dfm`，`DeltaInventory` 与游戏本体均保留安装。

---

## 五、产物清单（`/root/三角洲/dfm-apk/`）

| 文件 | 内容 |
|---|---|
| `dfm-official-1.201.37119.49.apk` | 官方游戏本体（1.6 GB） |
| `apk-metadata.json` | 包名/版本/权限/组件/90 so/67 assets 完整元数据 |
| `jadx-out/`（2.0 GB） | 8567 个反编译 Java 文件 |
| `apktool-out/`（2.1 GB） | 14749 个 smali + 解码资源 |
| `so-analysis/` | 解压出的 `libtersafe.so` / `libUE4.so` / `libturinggame.so` / `libgamemaster.so` 等关键库 |
| `dfm-screen.png` / `dfm-screen2.png` | 模拟器运行截图（隐私协议/权限页） |
| `analyze_metadata.py` | 元数据解析脚本 |

上游页面副本在 `/root/三角洲/`：`df-play.html`、`play.v3.js`、`itop.js`。

---

## 六、结论

1. 从腾讯官方下载页一路追到 APK 直链并完整下载，《三角洲行动》官方客户端 v1.201.37119.49 已落盘。
2. 静态反编译（jadx + apktool）完成，确认 UE4 引擎 + ACE（TssSDK 8.0.46 / MVM）反作弊体系。
3. **破解了反作弊 SDK 的 ROT5 字符串混淆**，还原出 `get_report_data`、`ilc_*_pipe`、`AddAnoTouchEvent` 等内部命令，并定位到触摸行为采集代码 `TouchListenerProxy.java`。
4. 动态运行实证：游戏可安装、可启动到权限页，`libtersafe.so` 早于主逻辑加载；561 MB `libUE4.so` 在 x86_64+NDK 转译模拟器上最终 ANR，属于环境限制。
