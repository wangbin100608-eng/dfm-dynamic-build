# protobuf 字段号突破 —— 从序列化代码动态提取字段集

> 时间：2026-11-25 · 方法：静态定位序列化函数 + ADRP/ADD 字符串提取 + 结构偏移序推断
> 这是"尽所有办法"推进动态反编译后拿到的最有价值成果。

## 1. 关键突破

之前静态分析只拿到字段名字符串（散落在 so 字符串池），无法确定字段号和消息归属。本轮通过以下链条取得突破：

1. 修正 xref 扫描器（补上 32 位 ADD `0x11000000` 和 LSL #12 寻址），找到 `pb.CSMallBuyReq` 字符串被 `0xc16fd30` 处代码引用；
2. 对字段名字符串（`buy_num` 等）做全 so xref，定位到**protobuf 序列化函数**；
3. 从序列化函数的 ADRP+ADD 指令序列中，提取出**完整字段集 + 结构体偏移顺序**；
4. protobuf 生成代码的字段号按声明顺序排列，与结构体偏移递增序一致 → **推断出候选字段号**；
5. 用 Unicorn 动态执行验证：函数名字符串通过 `x2` 传入 helper，`w1=-2` 是标志位，字段号隐含在编译后的序列化逻辑中。

## 2. 提取到的消息与字段（候选字段号，可信度 medium）

### 2.1 限购/购买消息 @ `0xc4d3520`

| 字段 | 结构偏移 | 候选字段号 | 说明 |
|---|---|---|---|
| curr_buy_limit | 0x30 | 1 | 当前购买上限 |
| next_period_start | 0x38 | 2 | 下个周期开始 |
| limit_type | 0x3c | 3 | 限购类型 |
| level | 0x40 | 4 | 等级 |
| buy_num | 0x48 | 5 | 购买数量 |
| next_level_exp | 0x4c | 6 | 下级经验 |
| exp | 0x50 | 7 | 经验 |
| total_exp | 0x68 | 9 | 总经验 |

### 2.2 订单购买消息 @ `0xc4f6800`

| 字段 | 结构偏移 | 候选字段号 |
|---|---|---|
| assemble_info | 0x28 | 1 |
| durability | 0x30 | 2 |
| currency | 0x40 | 3 |
| price | 0x50 | 5 |
| buy_num | 0x58 | 6 |
| to_pos | 0x60 | 7 |
| order_id | 0x68 | 8 |

### 2.3 交易定价消息 @ `0xc514000`

| 字段 | 结构偏移 | 候选字段号 |
|---|---|---|
| price_step | 0x18 | 1 |
| buy_currency_id | 0x38 | 3 |
| sell_currency_id | 0x40 | 4 |
| guide_price | 0x48 | 5 |
| price_range_begin | 0x50 | 6 |
| price_range_end | 0x58 | 7 |
| show_prop_id | 0x98 | 8 |

### 2.4 弹药操作消息 @ `0xc506200`

`op_type`、`bullet_gid`、`bullet_op_num`、`target_gun_rec_id`、`target_gun_rec_gid`（结构偏移未捕获，字段号待定）。

## 3. 实测验证

用重建的 `field_map.inferred.json` 跑探针，成功编码购买请求体：

```
$ python3 probe_gateway.py --config field_map.inferred.json \
    --message "MallOrderReq (订单购买)" \
    --set currency=1 --set price=100 --set buy_num=2 --mode build

body_hex = 1a0131 2a03313030 320132
  currency → field 3 (len) = "1"
  price    → field 5 (len) = "100"
  buy_num  → field 6 (len) = "2"
```

这标志着探针从"缺字段号拒绝发送"推进到"能构造合法结构请求体"。

## 4. 可信度与边界

- **候选字段号可信度 medium**：结构体偏移序推断假设「字段号 = 声明顺序」，protobuf 通常成立，但若结构体含非序列化成员或字段被预留，会有偏差。
- **wire type 需验证**：探针把数字编码为 len（字符串），实际可能是 varint，需真机抓包校准。
- **仍缺运行期参数**：网关地址、cmd_id/seq_id、TSS 签名、会话密钥——这些依赖真实客户端，模拟拿不到。

## 5. 工具

| 脚本 | 作用 |
|---|---|
| `tools/emu/extract_field_sets.py` | 从序列化函数提取字段集 + 结构偏移 + 推断字段号 → `reports/field_sets.json` |
| `tools/emu/find_xrefs.py` | AArch64 ADRP+ADD 交叉引用（已支持 32/64 位 ADD + LSL12） |
| `tools/emu/dyn_field_extract.py` | Unicorn 动态执行序列化函数（frame hook 捕获字段事件） |
| `tools/emu/emu_native_trace.py` | 指令级模拟（已跑通真实 `_Znwm`） |
| `reports/field_sets.json` | 提取结果 |
| `reports/field_map.inferred.json` | 带候选字段号的探针配置 |

## 6. 下一步

1. 真机抓一次购买包，用 `protoc --decode_raw` 解码，核对字段号和 wire type；
2. 若字段号吻合，把 `field_map.inferred.json` 作为 `field_map.json` 启用；
3. 补齐网关/cmd_id/签名后即可 `--mode send` 发包验证。
