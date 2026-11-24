# DEX 层签名 / 加密线索（来自历史版本字符串池）

> 数据源：`classes.dex.strings.txt`（73,378 条）、`classes2.dex.strings.txt`（34,470 条）。
> 方法：自写 DEX parser 提取字符串池后按 sign/md5/hmac/encrypt/secret 等关键字过滤。
> 结论用于指导动态 hook 目标定位，具体算法需运行时验证。

## 1. 观察到的签名/加密关键字

| 字符串 | 含义推测 | 动态 hook 建议 |
|---|---|---|
| `checkSignature = ` / `is v3 signature : ` / `packageSign=` | APK 签名校验日志（渠道/加固 SDK） | 关注 `PackageManager.getPackageInfo` / signature 比对 |
| `secretKey='` / `, md5='` / `, md5Str:` | 请求参数签名拼接痕迹 | hook 对应 `StringBuilder.append` 或 `md5()` 方法 |
| `-->sign: ` / `-->signEncryped: ` | 签名生成日志（Midas/支付相关） | hook 打印该日志的类方法，取 sign 前后值 |
| `-->get md5 form native` / `-->getMD5FromNative, MD5= ` | **MD5 在 native 层计算** | Java 层拿不到算法，需 hook .so 或 Frida RPC 直接调 native 函数 |
| `oiSymmetryEncrypt2` / `oiSymmetryDecrypt2` | 对称加密封装（Oi 系列，常见于 Midas/SDK） | hook 这两个方法取明文 |
| `AESdecrypt` / `AES_ENCRYPTION_PADDINGS` / `cbc encrypt/decrypt data error` | AES-CBC 加解密 | hook `Cipher.doFinal` |
| `AGC_FixedDecrypt` / `AGC_FlexibleDecrypt` | 上报数据加解密 | 低优先级 |
| `/client/client_secret` | OAuth client_secret 路径 | 账号 SDK 相关 |

## 2. 关键判断

1. **签名算法跨 Java/native 两层**：日志 `get md5 form native` 表明至少一部分 MD5/签名在 native 层完成，纯 Java 复刻会缺环。
2. **MidasPay 支付壳独立**：`midasCallBack:`、`exist in midasplugins!`、`-->signEncryped:` 说明支付字段签名由 Midas SDK 处理，适合用 `05_hook_midas.js` 观察真实参数。
3. **`oiSymmetryEncrypt2` 是高价值 hook 点**：对称加密封装方法名固定，可直接定位。

## 3. 建议的动态验证顺序

```
05_hook_midas.js  → 观察 -->sign / -->signEncryped 真实调用（拿参数结构）
      ↓
06_sign_rpc.js(findSign) → 扫描真实签名类/方法名，回填占位
      ↓
若签名落 native → 用 Frida RPC 直接调 native 函数现算（不复刻算法）
      ↓
04_hook_libcurl.js → 若 body 密文，捞 native 层明文
      ↓
07_replay.py → 现算签名重放验证
```

## 4. 备注

本报告只记录**可观测线索**，不臆造密钥或算法实现。所有结论需以运行时 hook 输出为准。
