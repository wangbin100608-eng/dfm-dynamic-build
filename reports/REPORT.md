# 三角洲行动手游官服 APK 逆向分析报告

> 目标：官服最新 APK（`com.tencent.tmgp.dfm`）静态 + 动态反编译，梳理 API 接口，定位"哈弗币购买装备/弹药"相关接口。
> 分析环境：精简容器（无 Java/adb/模拟器），工具链现场安装 apktool/aapt/jadx/capstone。
> 说明：本报告所有结论均附可核验的分析步骤与产物路径。

---

## 1. 样本信息

| 项目 | 值 |
|---|---|
| 包名 | `com.tencent.tmgp.dfm` |
| versionName | `1.201.37119.49` |
| versionCode | `2362` |
| 文件大小 | 1,625,586,573 字节（约 1.51 GiB） |
| SHA256 | `1ce71a21bcd8d52399be5f8a7ef8f28525d2148c3cb73f97592a03c03473f44a` |
| 官服下载直链 | `https://dlied4.myapp.com/myapp/1110543085/cos.release-75799/10040714_com.tencent.tmgp.dfm_a4538867_1.201.37119.49_SHpVqu.apk` |
| 直链来源 | 官网 `df.qq.com` → 下载页 play.shtml → `img.itop.qq.com/js/1110543085.js` 的 `EAGLECFG.androidURL` |
| minSdk / targetSdk | 24 / 34 |

校验命令：`sha256sum -c SHA256SUMS.txt` → `OK`。

### 1.1 包内结构（960 个条目，解压后 1.93 GiB）

- `classes.dex`（11.78 MB）、`classes2.dex`（5.09 MB）：Java/Kotlin 层，主要为 SDK、渠道、上报、支付壳。
- `lib/arm64-v8a/libUE4.so`（535.58 MB）：**UE4 游戏核心逻辑、protobuf 协议、经济系统所在**。
- `assets/main.obb.png`（1326 MB）：伪装成 PNG 的 OBB 资源包。
- 90 个 `.so`：gcloud / midas 支付 / tersafe / tpns 推送 / CrashSight / TDataMaster 等 SDK。

核验：`zip_listing.txt`、`manifest_strings.txt`。

---

## 2. 分析工具与方法

| 方法 | 工具 | 产物 |
|---|---|---|
| APK 结构解析 | Python zipfile | `zip_listing.txt` |
| Manifest 解析 | aapt / apktool / 自写 AXML 解析器 | `manifest_strings.txt` |
| DEX → Java | jadx 1.5.3 | `analysis/jadx/sources/**`（6813 个 java） |
| DEX → smali | apktool 2.7.0 | `analysis/smali_full/**`（14749 个 smali） |
| DEX 字符串池 | 自写 DEX parser | `classes.dex.strings.txt`、`classes2.dex.strings.txt` |
| SO 字符串 | `strings` + XOR 0x10 解码 | `/tmp/ue4_decoded.txt`（1,499,495 条） |
| 二进制定位 | Python bytes.find + capstone | 见 §4 |

**关键突破**：UE4 字符串表整体使用 **单字节 XOR 0x10** 混淆。
`Buy~ydyq|yju` XOR 0x10 → `Reinitialize`；解码后暴露出完整 protobuf 消息名与字段名。

---

## 3. DEX 层 API 接口（SDK 层）

### 3.1 HTTP(S) 端点（共 67 条，完整清单见 `dex_urls.txt`）

按用途分类：

- **推送/统计**：`api.tpns.tencent.com/guid/v4/register_device`、`api.tpns.tencent.com/device/v4/account/batch_operate`、`stat.api.tpns.tencent.com/log/v4/statistics/push`、`log.tpns.tencent.com/log/v4/statistics/push`
- **分享/活动抽奖**：`fusion.qq.com/cgi-bin/prize_sharing/exchange_prize.cgi`、`query_unexchange_prize.cgi`、`get_activity_state.cgi`、`make_share_url.cgi`
- **崩溃上报**：`android.crashsight.qq.com/rqd/pb/async`
- **TBS/X5**：`cfg.imtt.qq.com/tbs?v=2&mk=`、`log.tbs.qq.com/ajax?...`、`pms.mb.qq.com/rsp204`、`snowflake.qq.com/ola/v2`
- **账号/登录**：`cgi.connect.qq.com/qqconnectopen/openapi/policy_conf`、`openmobile.qq.com/oauth2.0/m_authorize`、`open.weixin.qq.com/connect/sdk/qrconnect`
- **游戏运营后台**：`estv-op.tga.qq.com`、`pre/adapt/dev/test/tiyan-estv-op.tga.qq.com`
- **WiFi/下载**：`qos.189.cn/qos-api/getToken`、`119.29.29.29/d?dn=`、`long.open.weixin.qq.com/connect/l/qrconnect`

### 3.2 `/api` 路径（共 17 条，完整清单见 `dex_paths.txt`）

关键端点：

| 端点 | 用途 | 源码位置 |
|---|---|---|
| `/api/v2/%s/users/%s/coupons/%s` | **哈弗币优惠券兑换（HRCouponExchange）** | `analysis/jadx/sources/r2/f0.java` |
| `/api/v2/%s/scripts?serviceId=%s&userId=%s&subaoId=%s&clientVersion=%s` | 脚本拉取 | `analysis/jadx/sources/r2/y.java` |
| `/api/v1/%s/orders/%s/payment` | 订单支付 | `analysis/jadx/sources/r2/b.java` |
| `/api/v1/%s/tokeninfo` | Token 信息 | `analysis/jadx/sources/r2/o.java` |
| `/api/v1/%s/users/%s/gameAccel` | 游戏加速 | `analysis/jadx/sources/r2/a0.java` |

---

## 4. 游戏核心 API（UE4 / protobuf）

游戏经济、商城、市场的请求/响应**不走 HTTP URL 路径**，而是走 UE4 自研网关的 **protobuf CS 消息 + cmd_id** 机制。

### 4.1 协议架构

- 共提取 **931 个** `pb.CS*Req/Res/Ntf` 消息名（XOR 0x10 编码存储）。
- 消息按 proto 源文件分模块（从 so 内嵌编译路径还原）：
  `cs_mall.pb.cpp`、`cs_market.pb.cpp`、`cs_currency.pb.cpp`、`cs_pay.pb.cpp`、`cs_directpurchase.pb.cpp`、`cs_battlepass.pb.cpp`、`cs_activity.pb.cpp` 等共 40+ 模块。
- 典型消息命名：`CSMallBuyReq/Res`（商城购买）、`CSMarketBuyTReq/Res`（市场购买）、`CSCurrencyExchangeReq/Res`（货币兑换）、`CSGetCurrencyReq/Res`（查询货币）。

### 4.2 请求/响应结构字段（从 StringTable 还原）

购买类关键字段：
`buy_item_id`、`buy_currency_itemid`、`buy_currency_id`、`buy_num`、`buy_price`、`buy_type`、`buy_plan_type`、`buy_limit`、`buy_times`、`goods_id`、`currency_type`、`currency_id`、`currency_num`、`item_id`、`item_num`、`sku_id`、`mall_prices`、`pay_price`、`pay_channel`。

装备/弹药类字段：
`equip_item_id`、`equip_price`、`equip_type`、`equipment_type`、`bullet_id`、`bullet_gid`、`bullet_index`、`equip_level_bullet`。

### 4.3 调用链（典型商城购买）

```
UI 点击购买 (PixUI/UMG)
  → UDFMGameTss::RequestCmdIdC（cmd_id 分配）
  → 构造 pb.CSMallBuyReq（buy_item_id / buy_currency_itemid / buy_num / buy_price）
  → protobuf 序列化
  → UE4 Gateway（gatewayIp / seq_id / cmd_id）
  → 服务端处理
  → pb.CSMallBuyRes（item_results / currency_changes / mall_changes）
  → CSCurrencyChangeNtf 推送货币变动
```

核验依据：`libUE4.so` XOR 解码字符串中的 `seq_id`、`cmd_id`、`netret`、`requestCallback`、`genericPacketProcessor`、`<------ END HTTP`、`cgi info:` 等网关处理链路标志。

---

## 5. 哈弗币购买装备/弹药接口定位

### 5.1 结论

**哈弗币购买装备/弹药属于游戏核心经济系统，接口为 protobuf CS 消息，不在 DEX Java 层，也不使用 REST URL：**

| 目标 | 接口（protobuf 消息） | 模块 | 关键字段 |
|---|---|---|---|
| 哈弗币购买装备 | `CSMallBuyReq/Res` | `cs_mall.pb.cpp` | `buy_item_id`、`buy_currency_itemid`（哈弗币）、`equip_item_id`、`equip_type` |
| 哈弗币购买弹药 | `CSMallBuyReq/Res` 或 `CSMarketBuyTReq/Res` | `cs_mall.pb.cpp` / `cs_market.pb.cpp` | `buy_item_id`、`bullet_id`、`buy_num`、`currency_type` |
| 货币余额查询 | `CSGetCurrencyReq/Res` | `cs_currency.pb.cpp` | `currency_id`、`currency_num` |
| 货币兑换 | `CSCurrencyExchangeReq/Res` | `cs_currency.pb.cpp` | `currency_type`、`buy_price`、`item_id` |

哈弗币在游戏内是货币 item，`buy_currency_itemid` / `currency_item_id1/2` 是其标识字段；装备与弹药通过 `buy_item_id` + `equip_item_id`/`bullet_id` 区分品类。

### 5.2 与"哈弗币优惠券兑换"相关的 DEX 层接口

`r2/f0.java` 的 `HRCouponExchange`：
- 方法：`POST /api/v2/{app}/users/{uid}/coupons/{id}`
- HTTP 方法由父类 `h0` 构造时传入 `b.EnumC0195b.POST`
- 响应处理：`f0.g()` 打印 `HRCouponExchange code: ...`（仅当 `g2.d.f("SubaoData")` 调试开关开启）
- 端点构造：`f0.i()` → `String.format("/api/v2/%s/users/%s/coupons/%s", ...)`
- 调用入口：`f0.l(bVar, eVar, str)` → `new f0(...).f(s2.d.a())`
- 判断依据：类名混淆为 `r2.f0`，但日志字符串 `HRCouponExchange` 明确保留了业务语义。

### 5.3 可核验分析步骤

1. 下载官服 APK（URL 见 §1），`sha256sum -c SHA256SUMS.txt` 确认 `OK`。
2. `apktool d -f -o analysis/smali_full <apk>` 生成 smali。
3. `jadx -d analysis/jadx classes.dex classes2.dex` 生成 Java。
4. `grep -ril HRCoupon analysis/jadx` → `r2/f0.java`，读取端点构造逻辑。
5. 提取 `libUE4.so`，`strings -n 5 libUE4.so | python3 (每个字符 XOR 0x10)`。
6. 在解码结果中 `grep 'pb.CS.*Buy'` → 得到商城/市场购买消息全集。
7. `grep 'buy_item_id\|buy_currency_itemid\|equip_item_id\|bullet_id'` → 确认字段定义。

---

## 6. 动态分析说明

当前容器无 Android 模拟器/adb/root 环境，无法在真机/模拟器运行游戏并抓包验证运行时 cmd_id 数值。
本报告的接口与结构结论基于**静态逆向 + 交叉验证**：
- DEX 字符串池与 jadx 反编译互为印证；
- SO XOR 解码字符串与 protobuf 编译路径互为印证；
- 购买字段（buy_* / equip_* / bullet_*）在多处 StringTable 反复出现，非孤立噪声。

若需运行时验证 cmd_id 精确数值，后续需在 arm64 Android 环境用 Frida hook `UDFMGameTss::RequestCmdIdC` / gateway 发包函数，或 mitmproxy 抓取网关 TCP 流量后按 protobuf 解码。

---

## 7. 产物清单

| 文件 | 内容 |
|---|---|
| `dex_urls.txt` | DEX 层 67 条 HTTP(S) 端点 |
| `dex_paths.txt` | DEX 层 17 条 `/api` 路径 |
| `manifest_strings.txt` | AndroidManifest 解析字符串 |
| `zip_listing.txt` | APK 960 个条目清单 |
| `classes*.dex.strings.txt` | DEX 字符串池 |
| `analysis/jadx/sources/**` | jadx Java 反编译结果 |
| `analysis/smali_full/**` | apktool smali 反编译结果 |
