# 哈弗币购买战备/弹药接口 —— 静态逆向结论

> 目标：定位「用哈弗币购买战备/弹药」的游戏服务器接口。
> 样本：三角洲行动国服官服 `com.tencent.tmgp.dfm`，版本 `1.201.1035.13`，`lib/arm64-v8a/libUE4.so`（535MB）。
> 方法：apktool 反编译 11,866 个 smali + 72 个 so；libUE4.so 字符串池字节检索 + 偏移定位；DEX 字符串池过滤。
> 所有结论均附 so 偏移或字符串证据；找不到即标注 NOT_FOUND，不臆造。

---

## 0. 重要修正：XOR 0x10 假设不成立（当前版本）

历史报告（版本 1.201.37119.49）称 UE4 字符串表整体用单字节 XOR 0x10 混淆。本轮对当前版本实测：

| 测试 | raw | XOR 0x10 后 | 结论 |
|---|---|---|---|
| `raw@0x5bff70a` | `ReinitializeInstances`（可读） | 乱码 | raw 本身就是明文 |
| `pb.CS` 出现次数 | 911 次 | 0 次 | 明文直接提取即可 |

**结论**：当前 APK 的 so 字符串是明文，直接检索 raw 即可。

2026-11-25 在服务器上用确定性方法复核（对每个词计算 XOR 0x10 编码后在 355MB so 中精确计数）：`cmd_id`(明文3/XOR0)、`goods_id`(2/0)、`buy_price`(2/0)、`CSMallBuyReq`(1/0)、`currency_type`(3/0)、`bullet_gid`(1/0) —— XOR 编码全部 0 次。`Buy~ydyq|yju` XOR 0x10 = `Reinitialize` 只是 XOR 自反造成的巧合，不代表系统性混淆。已确认无 XOR 编码的 protobuf 名/字段残留。

---

## 1. 接口形态：不是 REST，是 UE4 私有网关 + protobuf CS 消息

DEX 层 `/api` 全集 17 条中，只有两条与"购买"沾边：
- `/api/v2/%s/users/%s/coupons/%s` — HRCouponExchange（历史版本的哈弗币优惠券兑换，**当前 smali 中已无此字符串**）
- `/api/v1/%s/orders/%s/payment` — 米大师支付（真实货币，非哈弗币）

**没有找到任何"哈弗币购买战备/弹药"的 REST URL。** 游戏经济走 UE4 自研网关的 protobuf CS 消息 + cmd_id 机制：

| 网关证据 | so 偏移 |
|---|---|
| `cgi info:` | 0x15f9c476 |
| `requestCallback` | 0x15f9c594 |
| `seq_id` | 0x15f9c5c5 |
| `cmd_id` | 0x15f9c5cc / 0x5c46d09 |
| `sub_cmd_id` | 0x15f9e216 |
| `cs_gateway.pb.cpp` | 0x5c1fa9c |

> `http://10.32.75.192:9093/app`@0x15f9d8c4 是内网测试字面量，**不是生产端点**。

---

## 2. protobuf 消息候选（按可信度）

| 消息 | so 偏移 | 归属 | 可信度 | 用途推测 |
|---|---|---|---|---|
| `pb.CSMallBuyReq` | 0x5b6cd50 | `cs_mall.pb.cpp`@0x5e33b45 | **high** | 商城/战备购买主候选 |
| `pb.CSMallBuyRes` | 0x5abd4ec | 同上 | **high** | 商城购买响应 |
| `CSMarketBuyTRes` | 0x58a3277 / 0x5f219a1 | `cs_market.pb.cpp`@0x5d8048c | medium | 弹药/玩家市场购买 |
| `CSAuctionBatchBuyReq/Res` | — | — | medium | 拍卖批量购买 |
| `CSAuctionBuyTReq/Res` | — | — | medium | 拍卖购买 |
| `CSCheapBuyReq/Res` | — | — | medium | 廉价购买 |
| `CSShopBuyReq/Res` | — | — | medium | 商店购买 |
| `CSGetCurrencyReq` | 0x57eebf3 | `cs_currency.pb.cpp`@0x5b6cbd8 | **high** | 查询货币（辅助） |
| `CSGetCurrencyRes` | 0x5af6f6c | 同上 | **high** | 货币查询响应 |
| `CSCurrencyExchangeReq` | 0x5b6cc25 | 同上 | **high** | 货币兑换 |
| `CSCurrencyChangeNtf` | 0x5953f6a | 同上 | **high** | 货币变动通知 |
| `pb.CSBuyGoodsReq` | 0x5d8053c | `cs_pay.pb.cpp`@0x57eecdf | **high** | 米大师支付（真实货币，非哈弗币） |

> `CSMarketBuyTReq` 明文 NOT_FOUND；历史字段 `buy_item_id`/`buy_currency_itemid`/`equip_item_id`/`bullet_id` 当前版本全部 NOT_FOUND —— 字段集发生版本演进，不可照搬旧报告。

---

## 3. 请求参数字段（存在性已证实，字段号未找到）

so 明文字符串池中的相关字段：

| 字段 | so 偏移 | 字段 | so 偏移 |
|---|---|---|---|
| `buy_currency_id` | 0x5992bb9 | `goods_id` | 0x5e3462d / 0x15f9d3a4 |
| `buy_price` | 0x5b6d48d / 0x5af7b07 | `goods_num` | 0x5b6d5be |
| `buy_num` | 0x5a476ad | `goods_type` | 0x5c206c1 |
| `buy_type` | 0x5ee3b80 | `mall_prices` | 0x5b3358d |
| `currency_type` | 0x5a83012 / 0x15f9d450 | `currency_id` | 0x5c203f2 |
| `currency_num` | 0x5df6326 | `currency_changes` | 0x5d80b27 |
| `bullet_gid` | 0x5be2c9c | `bullet_op_num` | 0x5a477cf |
| `has_ammo` | 0x5a47700 | `equip_price` | 0x5af78f9 |
| `equip_type` | 0x5ee3b97 | `equipment_price` | 0x58de6cd |
| `is_cash` | 0x5be2ddc | `shop_id` | 0x5d80c1c |

**字段号（tag number）本轮未找到**：`cs_mall.proto` 等序列化 descriptor 字符串 NOT_FOUND，消息名与字段名分处不同字符串池，无法静态建立唯一映射。需运行期从 protobuf DescriptorPool 导出（见 `tools/probe/find_descriptor.js`）。

---

## 4. "哈弗币"字面量

`Haval` / `haval` / `HRCoupon` 在 so 和 dex 字符串池均 **NOT_FOUND**。
DEX 只有米大师优惠券相关（`hfCouponsRollBack`@classes.dex.strings.txt:53879 等）。
哈弗币在协议里应以内部 `currency_id` / `currency_type` 表达，静态无法确定具体 item id。

---

## 5. 签名线索

native 符号与密码学栈（so 明文）：

| 符号 | 偏移 |
|---|---|
| `TssSDKOnRecvSignature` | 0x4d7c3de |
| `UDFMGameTss::SendTssData` | 0x5c32655 |
| `UDFMGameTss::EnableTPConnector` | 0x592d03a |
| `UDFMGameTss::InitTss` | 0x592d059 |
| `UDFMGameTss::SetUserInfo` | 0x5acf28c |
| `EVP_DigestSignInit` | 0x4d7699f |
| `EVP_PKEY_sign` | 0x4fbb9e5 |
| `RSA_sign` | 0x4fbba6b |
| `md5WithRSAEncryption` | 0x58c7314 |
| `sha256WithRSAEncryption` | 0x5e91ffd |
| `AES_cbc_encrypt` | 0x4fbe54c |
| `cscpp_security.pb.cpp` | 0x5f21052 |
| `cscpp_tss.pb.cpp` | 0x5ccfad8 |

未找到明确命名的游戏自定义签名函数（MakeSign/calcSign）。历史报告的 `UDFMGameTss::RequestCmdIdC` 当前版本 NOT_FOUND，但 cmd_id 机制字符串仍在。
**判断**：游戏侧包签名/风控与 TSS 安全 SDK 强相关，区别于 MidasPay 支付签名。

---

## 6. 可行性评估：能否"不进游戏"用接口读商品信息/模拟购买？

| 环节 | 静态能否完成 | 说明 |
|---|---|---|
| 找到消息名/字段名 | ✅ | 本已定位 `CSMallBuyReq` 等 |
| 拿到字段号 | ❌ | 需运行期导出 descriptor（`find_descriptor.js`） |
| 拿到网关 HOST/PORT | ❌ | 需抓包；so 只有内网字面量 |
| 拿到 cmd_id/seq_id | ❌ | 需 hook 运行时 |
| 拿到会话密钥/设备指纹 | ❌ | TSS SDK 运行时生成 |
| 生成合法签名 | ❌ | 依赖设备指纹+会话+时间戳，非固定值 |
| 构造并发送消息 | ⚠️ 原型可构造，缺合法参数时拒绝发送 | 见 `tools/probe/probe_gateway.py` |

**结论**：静态逆向能定位消息结构，但**无法凭空生成合法请求**——字段号、网关、会话、设备指纹、TSS 签名全部依赖真实客户端运行时。要实现"不进游戏调接口"，必须先在真机/模拟器上跑一次客户端，用 Frida 把上述运行时参数导出，之后才可能离线复现。原型程序已按此约束设计（缺参拒绝发送，不假装成功）。

---

## 7. 下一步动态验证（需 root 设备）

1. Frida hook `UDFMGameTss::SendTssData`/`requestCallback`，点击商城购买时 dump 出站 protobuf 与 cmd_id/seq_id（`tools/probe/dump_traffic.js`）。
2. 运行期从 protobuf DescriptorPool 导出 `cs_mall.proto` 的 FileDescriptorProto，补齐字段号（`tools/probe/find_descriptor.js`）。
3. 抓网关 TCP 包用 `protoc --decode_raw` 初步解码，校准帧格式。
4. hook `CSGetCurrencyRes`/`CSCurrencyChangeNtf` 对照 UI 确定哈弗币 currency_id。
5. hook `TssSDKOnRecvSignature`/`EVP_SignFinal`/`RSA_sign` 确认签名算法与数据。
6. 用 descriptor 精确映射字段号→字段名，填入 `field_map.json`，再用 `probe_gateway.py` 发包验证。

---

*所有结论可复核：偏移来自 libUE4.so 直接字节检索，计数来自字符串池过滤。*
