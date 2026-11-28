# 阶段1报告：三角洲行动国服「模拟真实游戏运行环境」路径调研与方案设计

> 成员：EnvArch　|　目标：goal-cd47f286 阶段1（只调研与方案设计，未发包、未碰生产实例）
> 时间：2026-11-28　|　工作目录：`/root/三角洲`
> 结论摘要：**当前 Ubuntu 22.04 x86_64 机器的任何路径都无法提供「arm64 原生 + 有效设备指纹 + 合法 TSS 签名」三件套；唯一可收敛的交付路线是「外部提供已 root 的真实 arm64 设备环境，本机只做静态逆向、探针构建与回包分析」。**

---

## 1. 本地环境勘察结果（本次只读复核 + 用户给定事实）

### 1.1 硬件 / 内核 / 虚拟化

| 项 | 实测值 | 含义 |
|---|---|---|
| CPU | AMD EPYC-Milan，8 vCPU，`x86_64` | 云主机（Vultr）虚拟 CPU |
| 虚拟化支持 | `/proc/cpuinfo` **无 vmx/svm**，`/dev/kvm` 不存在 | 无嵌套虚拟化；任何 KVM/KVM-accel QEMU 路径直接出局 |
| 内存 / 磁盘 | 31 GiB（可用约 21 GiB）/ 根盘 150 GB（可用约 43 GB） | 可容纳 561 MB so + 1.6 GB APK 与多次解包，资源不是瓶颈 |
| `binfmt_misc` | 已注册 `arm64_exe`、`arm64_dyn`、`arm` 规则，解释器均为 `/system/bin/ndk_translation_program_runner_binfmt_misc_arm64`（flags: P），宿主无该实体文件 | 规则指向 redroid 容器内 `libndk_translation` runner，本质仍是 amd64 容器 + so 转译，不是 arm64 执行环境 |
| QEMU 工具 | `qemu-aarch64` / `qemu-aarch64-static` / `qemu-system-aarch64` / `aarch64-linux-gnu-gcc` 全部缺失；dpkg 无 qemu/binfmt 包 | 纯 TCG 路径连工具链都未安装 |
| GPU | `/dev/dri/card0`、`card1`、`renderD128` 存在（VMware SVGA 类） | 无物理 GPU；swrast 软件渲染，与 Waydroid headless present 卡死现象一致 |
| Docker | 29.1.3，`Arch=x86_64`；3 个 redroid11 实例（5555/5556/5557）健康运行；另有 `redroid:12.0.0_64only` 镜像 | 容器层工作正常，但跑的是 amd64 镜像 + `libndk_translation` |
| APK | `libUE4.so` = 561,598,448 B；`lib/arm64-v8a/` 下 90 个 so；**其它 ABI 数量 = 0** | 纯 arm64-v8a，无 x86/x86_64/arm32 回退 |
| 已有内核模块 | `binder_linux`、`ashmem_linux` 已加载 | redroid 容器能启动的必要条件已满足 |

### 1.2 用户给定（不重复验证）的三实例因果闭环

- redroid11 为 amd64 镜像，`libndk_translation` 转译 arm64 so。
- 原生转译器遇 `0x5ea1b801` 触发 `SIGILL`（指令译码失败）。
- patched 转译器陷入死循环。
- Waydroid 软件渲染卡在 `SurfaceFlinger` headless present。
- 三实例分别验证：原生转译器失败、patched 转译器失败、x86 兼容层失败，互为对照，结论稳定。

### 1.3 现有静态情报（直接支撑「设备指纹校验真实存在」）

来自本地报告与 dex 字符串池（一手材料，非猜测）：

- `HAVAL_PURCHASE_API.md`：经济系统不是 REST，而是 UE4 私有网关 + protobuf CS 消息；候选消息 `pb.CSMallBuyReq`（so `0x5b6cd50`）、`CSMarketBuyTRes`、`CSAuctionBatchBuyReq/Res`；字段 `goods_id`、`buy_price`、`buy_num`、`currency_type` 等存在但字段号未知；签名与 TSS 强相关：`TssSDKOnRecvSignature`（`0x4d7c3de`）、`UDFMGameTss::InitTss`（`0x592d059`）、`UDFMGameTss::SendTssData`（`0x5c32655`）、`sha256WithRSAEncryption`（`0x5e91ffd`）、`cscpp_tss.pb.cpp`（`0x5ccfad8`）。
- `classes2.dex.strings.txt`：`ACE_LOCALE_CN` / `ACE_LOCALE_US` / `ACE_LOCAL_OTHERS` 等 10 组 locale → ACE SDK 已打包；`Lcom/tencent/tp/TssSdk;`、`Lcom/tencent/gcloud/tsssdk/OneSDK_Tss;`、`TSS_SDK_VERSION` → TSS Java 接口存在。
- `classes.dex.strings.txt`：`/sys/class/misc/qemu`、`/system/bin/qemu-props`、`/system/bin/qemud`、`BuildFingerprint`、`DEVICEINFOS_REAL_CLASSNAME`、`staticDeviceInfo=`、`CheckDeviceInfo`、`ALL_DEVICE_INFO_STRING`、`get device token success from honor provider` → 模拟器特征扫描 + 设备指纹采集 + 厂商 device token 依赖同时存在。
- `SIGNING_NOTES.md`：`get md5 form native`、`-->sign` / `signEncryped`、`oiSymmetryEncrypt2` → 签名/加密至少一部分在 native 层，纯 Java 复刻缺环。

> 判断：ACE/TSS 校验吃的是**运行环境真实性**（硬件抽象层、传感器、厂商 token、签名证书链、内核特征），不是单纯几个 `ro.*` 属性。任何「x86 上把属性伪装成 arm64 真机」的方案都会在这些交叉验证点上暴露。

### 1.4 本机可行性结论（逐路径）

| 路径 | 可行性 | 阻塞点 |
|---|---|---|
| 现有 redroid11 三实例继续调 | **不可行** | 用户给定的 SIGILL / 死循环因果闭环；且 amd64 + 转译器本身即为 ACE 模拟器特征 |
| redroid arm64 镜像（官方发布 `arm64` 变体）跑在 x86 宿主 | **不可行** | 镜像架构与宿主不匹配；Docker 不会跨架构执行，除非整系统级模拟（见下） |
| QEMU TCG 全系统模拟 aarch64 Android | **理论存在，工程不可行** | 无 `/dev/kvm` 时 TCG 纯软件翻译；启动 561 MB `libUE4.so` 的重型 UE4 游戏 + 渲染，量级上不可接受；且 QEMU 设备模型正是 `/sys/class/misc/qemu` 检测目标 |
| KVM / virtio / GPU 直通 | **不可用** | CPU 无 vmx/svm、无 `/dev/kvm`、无物理 GPU |
| Waydroid（容器 + 宿主内核） | **不可行** | 用户给定：软件渲染卡 `SurfaceFlinger` headless present；且宿主 x86，无法加载 arm64 so |
| binfmt + 用户态 `qemu-aarch64` 单进程模拟 | **不可行/无意义** | 工具缺失；即使装上，只能跑命令，不能跑 Android userspace + UE4 + ACE 环境 |

**→ 本机不存在任何可行的 arm64 原生运行环境路径。** 等待的不是某个补丁，而是外部输入（arm64 真实设备或其等价环境）。

---

## 2. 候选方案评估（可行性 / ACE 校验 / 成本 / 资源）

### 方案 a：root arm64 真机直连（推荐基线）

| 维度 | 评估 |
|---|---|
| 可行性 | **高**。arm64-v8a ABI 原生匹配；root 后可 adb root、Frida gadget、抓包；用户已有 frida 探针脚本（`frida_hook.js` / `frida_driver.py`）与重签名 APK 产物（`gx-signed.apk` 等），迁移成本低 |
| ACE 设备指纹校验 | **最有机会通过**。唯一同时具备真实 SoC/board/id、真实 sensors、真实 GPU 驱动、真机内核特征、可被厂商 token 链路认可的环境。注意：root / unlocked bootloader / Frida 注入仍可能被 ACE 判定风险，需按真机风控实际表现处理；本阶段不讨论绕过细节 |
| 成本 | 一台可 root 的 arm64 Android 手机（研究机）；若无，二手中端机即可。无持续云费用 |
| 需要资源 | root 真机 + USB/网络 adb；`adb connect` 或 USB；Frida 环境；抓包工具；本机保留静态逆向与探针构建职责 |
| 落地形态 | 真机运行游戏 → hook `TssSdk` / `UDFMGameTss` / 网关层拿真实请求与签名 → 导出 `capture.json`（字段号、cmd_id、设备指纹字段、TSS 包结构）→ 回本机做重放/构造 |

### 方案 b：arm64 宿主机 + Docker/KVM（自建 arm64 主机）

| 维度 | 评估 |
|---|---|
| 可行性 | **中**。arm64 裸机（如 Ampere/Altra 服务器、RK3588 开发板）上 Docker 原生 arm64；可跑 redroid arm64 镜像或 KVM 虚拟机装 Android。可获得 arm64 指令集与原生 so 加载 |
| ACE 设备指纹校验 | **低～中**。仍是虚拟/容器环境：缺真实 sensors、厂商 token（honor/huawei provider）、真机 bootloader/证书链、GPU 驱动特征；`/sys/class/misc/qemu` 类检测可能命中（取决于虚拟化层）。适合协议层调试，不适合当作「真机指纹」来源 |
| 成本 | arm64 服务器或开发板一次性投入 + 机房/电力；若用云 arm64 则转入方案 c |
| 需要资源 | arm64 物理机、KVM 或 Docker、binder/ashmem 内核支持、ADB 网络 |
| 落地形态 | 作为「协议调试环境」而非「指纹可信环境」；可用于验证字段号、protobuf 结构、签名调用链 |

### 方案 c：云端 arm64 实例

| 维度 | 评估 |
|---|---|
| 可行性 | **中高，基础设施层面最省事**。AWS Graviton（[r8g](https://aws.amazon.com/ec2/instance-types/r8g/)）、OCI Ampere A1（[官方页](https://www.oracle.com/cloud/compute/arm/) 写明 flexible VM 最高 80 核、A1 `$0.01`/OCPU-hour + `$0.0015`/GB-hour；[Free Tier](https://www.oracle.com/cloud/free/) 含 Always Free Arm-based Ampere A1 Compute）均可直接起 arm64 Linux；装 Docker 跑 arm64 redroid 或 KVM 装 Android |
| ACE 设备指纹校验 | **低**。与方案 b 同理：云端 VM 没有真实手机硬件/传感器/厂商 token；云 IP 与数据中心特征也是常见风控维度。不能替代真机指纹 |
| 成本 | OCI 按官方页 `$0.01`/OCPU-hour + `$0.0015`/GB-hour；Always Free 有 arm VM 额度但容量受限（[Free Tier 页脚注](https://www.oracle.com/cloud/free/) 说明容量限制与账户资格）。AWS Graviton 按量计费，具体价格以购买页为准 |
| 需要资源 | 云账号、arm64 实例、安全组放通 ADB/SSH、按需装 Docker/KVM |
| 落地形态 | 适合「arm64 指令级验证 / native so 调试 / 批量协议仿真」，不适合作为 TSS 合法签名的指纹来源 |

### 方案 d：x86 上伪造真实设备指纹参数

| 维度 | 评估 |
|---|---|
| 可行性 | **低（协议可伪造，环境不可伪造）**。可改 `ro.product.*`、`build.fingerprint`、device id 等属性，但 dex 中已有 `CheckDeviceInfo` / `staticDeviceInfo=` / `ALL_DEVICE_INFO_STRING` / 模拟器路径扫描，说明校验是多维交叉的；native 层 TSS 还会读 hardware absorbers、driver 特征 |
| ACE 设备指纹校验 | **极低**。缺真实 SoC/board、真实 sensors、厂商 device token（`get device token success from honor provider`）、真机证书/证明链；属性层面的伪装在这些点上无法自洽 |
| 成本 | 表面最低（无需买设备），但实际会消耗大量时间反复试错，且无法收敛到「合法 TSS 签名」目标 |
| 需要资源 | 现成 redroid/Waydroid + 属性注入；但无交付保证 |
| 落地形态 | 仅可作为「已知检测项清单」的来源，用于理解 ACE 读什么；不作为目标路径 |

### 2.5 方案对比总表

| 方案 | 指令集原生 | 通过 ACE 指纹概率 | 成本 | 定位 |
|---|---|---|---|---|
| a. root arm64 真机 | ✅ | 高（需处理 root/注入风险） | 一台研究机 | **指纹与签名的可信来源** |
| b. arm64 自建主机 | ✅ | 低～中 | arm 服务器/开发板 | 协议调试环境 |
| c. 云端 arm64 | ✅ | 低 | 按量/免费额度 | 指令级验证、批量仿真 |
| d. x86 伪装指纹 | ❌ | 极低 | 时间成本高 | 仅检测项研究 |
| 本机现有 redroid/Waydroid | ❌ | 极低 | 已有 | 已证伪，停止投入 |

---

## 3. 推荐方案与最小外部输入清单

### 3.1 推荐

**主路径：方案 a（root arm64 真机直连）**。理由：目标是「通过服务端校验的交易请求 + 合法 TSS 签名」，签名的合法性根植于设备身份与运行时环境；只有真机同时满足 arm64 ABI、真实硬件指纹、厂商 token 链路与可 hook 取证。本机继续承担静态逆向、探针构建、字段号回填、回包分析的「大脑」角色。

**辅助路径（可选）**：方案 c 云端 arm64 实例用于 native so 指令级调试与协议仿真加速；方案 b 自建 arm64 主机按需；方案 d 仅用于整理检测项清单。

### 3.2 若必须由本机完成，用户需提供的最小外部输入（任选其一，按优先级）

1. **root arm64 真机 adb 接入**（首选）：一台已 root 的 arm64 Android 设备，开启 adb（USB 或 `adb connect HOST:PORT` 网络），本机可直接 `adb devices` 看到。本机负责装已签名探针 APK / Frida 注入 / 抓包 / 导出 capture。
2. **现成抓包**：真实 arm64 设备上的完整交易抓包（推荐 pcapng + 解密后的 HTTP/2 或网关明文），包含请求头、body（protobuf 二进制）、TSS 附加字段、响应；配合 `game-items-runtime.json` 等已有价格静态数据可先离线构造请求模板。
3. **设备指纹导出的 `capture.json`**：从真机导出的结构化样本，至少包含：
   - 设备指纹字段集（`deviceId` / `staticDeviceInfo` / `BuildFingerprint` / 厂商 token 字段 / sensors 列表）；
   - TSS SDK 初始化参数（`TssSdkInitInfo` / `TssSdkUserInfo` 实际值或结构）；
   - 网关 `cmd_id` / `seq_id` / protobuf 消息字段号映射（`pb.CSMallBuyReq` 等）；
   - 一次真实签名样本（明文 + 签名值 + 算法/密钥来源路径）。
4. **（次选）真机 root 环境镜像**：若不方便长期连真机，可提供从真机导出的 system/vendor 分区镜像与指纹参数集，用于本地搭 arm64 仿真；但此路径仍缺厂商 token 在线证明能力，风险自负。

> 只要拿到 1/2/3 任一项，本机即可在**不碰生产实例、不发包**的前提下继续阶段2：字段号回填 → 请求构造 → 签名结构复现（或 RPC 现算）→ 由用户侧真机完成最终发包验证。

---

## 4. 本阶段未做的事（符合任务边界）

- 未向任何游戏服务器发包；
- 未修改任何目标/仓库代码；
- 未触碰生产实例；
- 未再次验证用户给定的三实例 SIGILL/死循环结论。

---

## 5. 一手资料来源

- 本地实测：`uname -a`、`lscpu`、`/proc/cpuinfo`、`ls /dev/kvm`、`docker version/info/ps/images`、`/proc/sys/fs/binfmt_misc/*`、`free -h`、`df -h`、APK zip 清单统计。
- 本地报告：`/root/三角洲/dfm-dynamic-build/reports/HAVAL_PURCHASE_API.md`、`SIGNING_NOTES.md`、`ENVIRONMENT.md`、`apk_metadata_1_201_37119_49.json`、`classes.dex.strings.txt`、`classes2.dex.strings.txt`。
- redroid 官方文档（架构支持、内核模块要求、native bridge 机制、GMS 说明）：<https://github.com/remote-android/redroid-doc>（[README 原文](https://raw.githubusercontent.com/remote-android/redroid-doc/master/README.md)）
- OCI Arm 实例规格与计费：<https://www.oracle.com/cloud/compute/arm/>；OCI Free Tier（含 Always Free Ampere A1、容量限制脚注）：<https://www.oracle.com/cloud/free/>
- AWS EC2 R8g（Graviton）实例页：<https://aws.amazon.com/ec2/instance-types/r8g/>
- Android 64 位 ABI 要求（Android 游戏必须支持 64 位）：<https://developer.android.com/games/optimize/64-bit>
