# DFM 国服官服 APK 动态编译 / 分析工具链

> 面向《三角洲行动》手游**国服官服**（`com.tencent.tmgp.dfm`）的高效动态逆向与重编译研究工具链。
> 目标 APK 来源：腾讯官网 `df.qq.com` 移动端页面给出的应用宝官方分发直链，当前抓取版本 `1.201.1035.13`（约 1.3GB）。
>
> **版本说明**：仓库同时保留一份历史深度分析报告（`reports/REPORT.md`），对应官服版本 `1.201.37119.49`（versionCode 2362，1.51GiB，SHA256 `1ce71a21…f44a`）。该报告已定位 UE4 字符串 XOR 0x10 混淆、protobuf 消息/字段、哈弗币优惠券接口（`/api/v2/%s/users/%s/coupons/%s`）等关键结论；当前抓取版本用于复现与交叉验证。

---

## 1. 这个项目是什么

本仓库保存对**三角洲行动国服官服 APK**做「动态编译 / 动态分析」的一整套可复现工具链与产物，包括：

- 官服 APK 抓取脚本（官网直链 → 本地归档，带 SHA256 校验）
- 反编译辅助封装（apktool / jadx / SDK 自带 apksigner / aapt / dexdump）
- **非侵入式**动态分析框架（Frida + mitmproxy，附 SSL Pinning bypass、native libcurl hook、签名 RPC）
- 签名算法还原与请求重放（Python `requests`）
- 一键编排脚本 `run_all.sh`，全流程可重复执行
- 产物目录约定与报告模板

### 重要边界（请先读）

本项目是**学术研究 / 安全研究用途**的本地工具链。目标 APK 是商业加固包（腾讯 ACE 反作弊 + DEX 加固 + native 签名 + 风控）。因此：

| 动作 | 可行性 | 说明 |
|---|---|---|
| 下载官服 APK | ✅ | 官网公开分发渠道 |
| 提取 Manifest / 签名证书 / dex / so 清单 | ✅ | 静态元信息，无需运行 APP |
| dexdump / jadx 反编译 | ✅ | 得到 java/smali 源码用于分析 |
| 动态 hook（Frida） | ✅ | **需要真机 / root 模拟器**，APP 实际运行时 |
| 重签名 / 重打包 | ✅ | apksigner + zipalign，**产物仅用于本地分析** |
| 让改包通过 ACE 反作弊登录官服 | ❌ | 服务端风控 + 完整性校验，不在本项目范围 |

> 「动态编译」在这里指：**反编译 → hook 运行时 → 还原签名/接口 → 重放验证 → 重签名打包**的完整动态分析闭环，不是把官服客户端改造成可用的第三方客户端。

---

## 2. 目录结构

```
dfm-dynamic-build/
├── README.md                  本文件
├── LICENSE                    研究用途声明
├── env.example                环境变量模板
├── apk/
│   └── dfm_official_cn.apk    官服 APK（1.3GB，因体积通常不入 git，见 .gitignore）
├── scripts/
│   ├── 00_fetch_apk.sh        从官网直链下载 APK + SHA256
│   ├── 01_meta.sh             aapt/apksigner 提取 Manifest、签名、证书
│   ├── 02_decompile.sh        apktool decode + jadx 反编译
│   ├── 03_hook_ssl.js         Frida: OkHttp/Conscrypt/TrustManager SSL Pinning bypass
│   ├── 04_hook_libcurl.js     Frida: native curl_easy_setopt URL/BODY/HDR 明文
│   ├── 05_hook_midas.js       Frida: MidasPay 支付字段观察
│   ├── 06_sign_rpc.js         Frida: 导出 APP 内签名函数为 RPC（类名/方法名占位）
│   ├── 07_replay.py           本地重放：RPC 现算签名 → 发请求 → 打印响应
│   ├── 08_capture.sh          mitmdump 抓包
│   ├── 09_rebuild.sh          zipalign + apksigner 重签名打包
│   └── run_all.sh             一键编排（只跑不依赖真机的静态部分）
├── tools/probe/               哈弗币购买接口探针（见 §7）
│   ├── probe_gateway.py       protobuf CS 消息构造/发送/解码
│   ├── find_descriptor.js     Frida 导出运行期 protobuf 字段号
│   ├── dump_traffic.js        Frida dump 网关收发二进制
│   ├── field_map.example.json 字段号/帧格式/网关配置模板
│   ├── capture.example.json   会话/签名注入模板
│   └── README.md              探针使用说明
├── reports/
│   ├── apk_meta.txt           当前版本 APK 元信息（自动生成）
│   ├── signature_cert.txt     当前版本签名证书（自动生成）
│   ├── manifest.xml           反编译 Manifest（自动生成）
│   ├── dex_urls.txt           源码中提取的 URL
│   ├── HAVAL_PURCHASE_API.md  哈弗币购买接口静态逆向结论（核心）
│   ├── REPORT.md              历史版本深度逆向分析报告
│   ├── HOOK_TARGETS.md        动态 hook 目标定位（实证类名）
│   ├── SIGNING_NOTES.md       DEX 层签名/加密线索
│   ├── dex_paths.txt          /api 接口路径清单
│   ├── manifest_strings.txt   Manifest 字符串池
│   └── RESEARCH_LOG.md        研究日志模板
└── .gitignore
```

---

## 3. 环境要求

- Linux（测试环境 Ubuntu 26.10，4 核 / 15G 内存 / 200G 磁盘）
- JDK 17+
- Android SDK build-tools 34（提供 `aapt` / `apksigner` / `zipalign` / `dexdump`）
- Python 3.10+，安装依赖：`pip install requests frida-tools mitmproxy`
- 动态部分需要：已 root 的真机或模拟器 + frida-server（见第 6 节）

环境变量见 `env.example`：

```bash
export APK_URL="https://dlied4.myapp.com/myapp/1110543085/cos.release-75799/89900051_com.tencent.tmgp.dfm_h3275935_1.201.1035.13_Rmt4f0.apk"
export ANDROID_BUILD_TOOLS="/opt/android-sdk/build-tools/34.0.0"
export TARGET_PKG="com.tencent.tmgp.dfm"
export FRIDA_HOST="127.0.0.1:5555"   # 模拟器；真机用 -U
```

---

## 4. 快速开始（静态部分，无需设备）

```bash
cd dfm-dynamic-build
cp env.example .env && source .env

# 1) 下载官服 APK（1.3GB，断点续传 + SHA256）
bash scripts/00_fetch_apk.sh

# 2) 提取元信息 / 签名证书 / Manifest
bash scripts/01_meta.sh

# 3) 反编译（apktool + jadx，耗时较长）
bash scripts/02_decompile.sh

# 或：一键跑静态全流程
bash scripts/run_all.sh
```

产物：
- `reports/apk_meta.txt` —— 包名、版本、SDK、权限、组件
- `reports/signature_cert.txt` —— 官服签名证书（用于对比重签名）
- `reports/manifest.xml` —— 反编译后的 Manifest
- `build/apktool/` —— smali + 资源
- `build/jadx/` —— java 源码（jadx 输出）

---

## 5. 动态分析部分（需要 root 设备）

> 这一部分是「动态编译」的核心：让 APP 真正跑起来，在运行时 hook 出明文请求与签名函数。

### 5.1 准备设备

```bash
# 已 root 模拟器（REDroid 示例）
docker run -itd --privileged -p 5555:5555 redroid/redroid:11.0.0-latest
adb connect 127.0.0.1:5555

# 推送并启动 frida-server
adb push frida-server /data/local/tmp/ && adb shell "chmod +x /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
frida-ps -H 127.0.0.1:5555 | grep dfm
```

### 5.2 抓包 + 绕 SSL Pinning

```bash
# 终端 A：抓包
bash scripts/08_capture.sh

# 终端 B：Frida 绕 SSL + 启动 APP
frida -H 127.0.0.1:5555 -f com.tencent.tmgp.dfm \
  -l scripts/03_hook_ssl.js --no-pause
```

在 APP 内触发目标接口 → mitmproxy 里拿到真实 URL / Header / body → 存入 `reports/capture/`。

### 5.3 密文 body？用 native hook

若抓到的 body 是密文（游戏常用 native 层加密），用 libcurl hook 捞明文：

```bash
frida -H 127.0.0.1:5555 -f com.tencent.tmgp.dfm \
  -l scripts/04_hook_libcurl.js --no-pause
```

脚本会多符号探测 `curl_easy_setopt` / `curl_easy_perform`，覆盖静态链接 libcurl 的场景；拿不到导出时明确打印「未导出」，不静默失败。

### 5.4 签名函数定位与 RPC

```bash
# 先跑 findSign 扫描真实签名函数（类名/方法名为占位，需按实际替换）
frida -H 127.0.0.1:5555 -f com.tencent.tmgp.dfm \
  -l scripts/06_sign_rpc.js --no-pause
# 观察输出中的真实类名/方法名 → 回填脚本顶部 TARGET_CLASS / TARGET_METHOD
```

### 5.5 重放验证

```bash
# 终端 A：签名 RPC 常驻
frida -H 127.0.0.1:5555 -f com.tencent.tmgp.dfm \
  -l scripts/06_sign_rpc.js --no-pause

# 终端 B：用现算签名重放
python3 scripts/07_replay.py '<抓到的URL>' '{"goods_id":"..."}'
```

返回 200 + 合理数据即表示签名算法还原成功。

### 5.6 重签名打包（本地验证用）

```bash
bash scripts/09_rebuild.sh
# 产物：build/rebuilt/dfm_rebuilt_signed.apk
# 注意：重签名包无法通过官服 ACE 完整性校验，仅用于本地分析
```

---

## 6. 常见坑

| 现象 | 原因 | 处理 |
|---|---|---|
| 抓不到 HTTPS 包 | SSL Pinning | 用 `03_hook_ssl.js`；仍失败加 `objection -g ... sslpinning disable` |
| body 是密文 | native 层加密 | 用 `04_hook_libcurl.js` |
| RPC 签名对不上 | 类名/方法名占位未替换 | 先 `findSign` 扫描再回填 |
| 重签包登录失败 | ACE 完整性校验 | 预期内；本工具链不绕过服务端风控 |
| APK 下载慢 | 1.3GB 单连接 | `00_fetch_apk.sh` 已带断点续传，可重复执行 |

---

## 7. 哈弗币购买战备/弹药接口定位（核心成果）

静态逆向（`libUE4.so` 明文字符串池 + 偏移定位）已定位接口结构，详见 `reports/HAVAL_PURCHASE_API.md`：

- **接口形态**：不是 REST URL，而是 **UE4 私有网关 + protobuf CS 消息 + cmd_id**。DEX 的 17 条 `/api` 端点里没有哈弗币购买端点。
- **购买消息**：`pb.CSMallBuyReq` / `CSMallBuyRes`（`cs_mall.pb.cpp`），可信度高；弹药/市场购买候选 `CSMarketBuyTRes`。
- **货币消息**：`CSGetCurrencyReq/Res`、`CSCurrencyExchangeReq/Res`、`CSCurrencyChangeNtf`（`cs_currency.pb.cpp`）。
- **字段**：`buy_currency_id` / `buy_price` / `buy_num` / `goods_id` / `currency_id` / `bullet_gid` 等已证实存在；**字段号未静态确定**，需运行期导出 descriptor。
- **签名**：走 TSS 安全 SDK（`UDFMGameTss::SendTssData` + OpenSSL EVP/RSA），依赖设备指纹+会话+时间戳，**无法静态重放**。
- **版本修正**：历史报告称 so 字符串用 XOR 0x10 混淆，实测当前版本为明文（XOR 方向写反），已按明文重新提取。

**"不进游戏调接口"的可行性**：静态只能拿到消息结构；字段号、网关地址、cmd_id/seq_id、会话密钥、设备指纹、TSS 签名全部依赖真实客户端运行时。因此提供了 `tools/probe/` 原型：

| 文件 | 作用 |
|---|---|
| `tools/probe/probe_gateway.py` | 手写 protobuf wire 编解码 + 可配置帧 + 会话/签名注入；缺参时明确拒绝发送 |
| `tools/probe/find_descriptor.js` | Frida：运行期从 DescriptorPool 导出 `cs_mall.proto` 字段号（补齐静态缺口） |
| `tools/probe/dump_traffic.js` | Frida：hook `SendTssData`/签名函数，dump 出站/入站二进制 |
| `tools/probe/field_map.example.json` | 字段号/帧格式/网关配置模板（带可信度与 so 偏移） |
| `tools/probe/capture.example.json` | 会话/签名抓包注入模板 |

工作流：真机跑一次客户端 → `dump_traffic.js` 抓参数 → `find_descriptor.js` 导出字段号 → 填配置 → `probe_gateway.py --mode send` 发包。详见 `tools/probe/README.md`。

> 关于模拟器：在 Vultr 服务器上尝试 REDroid（缺 ashmem 模块）和 QEMU/KVM + Android x86（boot 卡在动画）均未成功起完整环境；且 DFM 有 ACE 反作弊与设备指纹，模拟器登录官服本身也不可行。因此动态参数导出需在**已 root 的真机**上完成。

## 8. 本次已完成的静态编译产出（实证）

在本机 Ubuntu 服务器上已完成「非侵入式」的高效静态编译/反编译全流程（独立目录，**未干扰任何正在运行的程序**）：

| 产物 | 结果 |
|---|---|
| 官服 APK 抓取 | ✅ 1.4GB，SHA256 `2f82c451…f144` |
| 元信息提取 | ✅ versionName `1.201.1035.13`，versionCode 19 |
| 签名证书 | ✅ `CN=DFM, OU=J3, O=TIMI`（DSA 1024，v1+v2） |
| apktool decode | ✅ 11,866 个 smali + 72 个 so |
| Hook 目标定位 | ✅ `reports/HOOK_TARGETS.md`（MidasPay 真实类名/方法名） |
| 签名函数判断 | ✅ Java 层无独立签名方法，签名在 native 层 → 走 RPC 现算 |

重点结论（见 `reports/HOOK_TARGETS.md`）：
- MidasPay 支付链路在 `com/pay/` 包，`APMidasCommMethod.MaptoString()` 是签名前的参数拼接点。
- 签名/加密在 native 层（dex 字符串池出现 `-->get md5 form native`），故 hook 策略为**直接调 native 函数现算**，而非复刻算法。
- `05_hook_midas.js` 的占位符已按实证类名回填，开箱可用。

## 8. 研究边界

本仓库仅用于**个人安全研究与逆向工程学习**。请勿将产物用于任何违反游戏服务条款、破坏线上服务或侵害他人权益的行为。所有接口调用应控制在研究必要的最小化范围内。

---

*生成时间：2026-11-24 · 目标版本：三角洲行动国服官服 1.201.1035.13 · 编译服务器：Ubuntu 26.10 (Vultr)*
