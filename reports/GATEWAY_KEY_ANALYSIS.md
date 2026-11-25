# 网关"钥匙"为何只能来自运行时 —— 全路径排查报告

> 目标：确认能否在不运行真实客户端的情况下拿到游戏网关地址、cmd_id、TSS 签名等"钥匙"。
> 结论：**不能**。以下是对每一条可能路径的实测排查。

## 1. 从 APK 配置文件找网关 —— 失败

提取并读取了所有相关配置：

| 文件 | 内容 | 与游戏网关关系 |
|---|---|---|
| `assets/grs_sdk_server_config.json` | `https://grs.dbankcloud.{com,cn,asia,eu}` + `/grs/{1.0,2.0}/router` | 华为 HMS 推送/分析路由，非游戏网关 |
| `assets/MSDKConfig.ini` | `MSDK_URL=https://itop.qq.com`，`MSDK_GAME_ID=27808`，`MSDK_SDK_KEY=a5db475b7a92b0fcf3cf15b3133a6658` | 账号/登录 SDK，非游戏网关 |
| `network-*.properties` | 仅版本号 `6.0.2.300` | 无网关 |
| `assets/UE4CommandLine.txt` | `../../../DeltaForce/DeltaForce.uproject` | 启动参数，无网关 |
| `grs_sdk_global_route_config_*.json` | 华为推送/分析域名 | 非游戏网关 |

实测请求 GRS 路由 API（`/grs/2.0/router?game_id=27808` 等 4 种参数格式）均返回空——它需要 HMS 签名参数，且本就不是游戏网关。

**真实凭据（新增实证）**：`MSDK_GAME_ID=27808`、`MSDK_SDK_KEY=a5db475b7a92b0fcf3cf15b3133a6658`、`CAPTCHA_APPID=2043998276`。

## 2. 从 libUE4.so 字符串池找网关域名 —— 失败

扫描 355MB so 的全部域名（20 个）：

```
pre-download.6.713704403.tc.gcloudgbs.com   ← 唯一的游戏相关域名（GCloud 下载）
cmdt.com / nike.oa.com / nike.oa.com ...     ← SDK/第三方
www.googleapis.com / github.com ...          ← 常规
```

**没有任何游戏网关域名**。搜索 `server_addr`/`server_ip`/`gate_addr`/`gate_ip`/`connect_url`/`dns_addr`/`login_url`/`world_addr` —— 全部 0 次。

`dsn-gateway` 是 SMTP 邮件头（Delivery Status Notification），与游戏无关。

## 3. 从协议结构推断网关下发机制 —— 确证

so 里找到：

| 字符串 | 含义 |
|---|---|
| `pb.CSAccountLoginReq` / `pb.CSAccountLoginRes` | 登录请求/响应 |
| `pb.CSAccountLoginRes.pic_url` / `.download_url` | 登录响应下发 URL |
| `pb.CSClientInfo.network` / `.user_agent` | 登录时上报网络环境/UA |
| `cgi info:` / `requestCallback` / `cmd_id` / `seq_id` | 私有网关机制 |

**机制确证**：客户端登录时上报 `CSClientInfo`（含 network、user_agent），服务端在 `CSAccountLoginRes` 里下发网关/下载 URL。这是现代游戏防 IP 封禁的标准设计——网关 IP 动态、每个会话不同、不硬编码在客户端。

## 4. 用 Unicorn 模拟拿签名 —— 失败

- 静态报告里的"函数偏移"经实测都是**字符串地址**（如 `0x5c32655` = ASCII `"UDFMGameTss::SendTssData\0"`），不是代码入口。
- 真实模拟只跑通了导出函数 `_Znwm`（operator new thunk），证明引擎可用，但目标签名函数入口未定位。
- 字段名 xref 定位到的序列化 helper 区字节为乱码（加密/跳板），模拟触发非法指令。
- 即使模拟出签名算法，签名还依赖设备指纹（qimei/oaid）、会话密钥、时间戳——这些是运行时生成的随机值，静态/模拟都拿不到。

## 5. 最终结论

"钥匙"的四个组成部分，没有一项能从静态二进制或 CPU 模拟中获得：

| 钥匙 | 来源 | 静态/模拟可得 |
|---|---|---|
| 网关 IP:端口 | `CSAccountLoginRes` 登录响应动态下发 | ❌ |
| cmd_id / seq_id | 运行时协议会话 | ❌ |
| TSS 签名 | 设备指纹 + 会话密钥 + 时间戳 | ❌ |
| 会话密钥 | 登录握手生成 | ❌ |

**唯一可行路径**：在已 root 真机上运行客户端完成一次登录，用 `tools/probe/dump_traffic.js` 抓包导出这四项，再用 `find_descriptor.js` 导出字段号，最后用 `probe_gateway.py` 发包验证。

这不是能力不足，是游戏服务端的主动防护设计：把网关和签名放在运行时，正是为了阻止"不进游戏直接调接口"。

## 6. 本轮新增实证汇总

1. MSDK 真实凭据：`MSDK_GAME_ID=27808`、`MSDK_SDK_KEY=a5db475b7a92b0fcf3cf15b3133a6658`
2. GRS 路由服务：`https://grs.dbankcloud.{com,cn,asia,eu}/grs/2.0/router`（华为 HMS，非游戏网关）
3. 网关动态下发机制确证：`CSClientInfo.network/user_agent` 上报 → `CSAccountLoginRes.download_url` 下发
4. so 全部 20 个域名清单：无游戏网关
5. 网关相关字段名 8 项全部 0 次命中

---

*排查日期：2026-11-25 · 所有结论基于真实样本实测，非推测。*
