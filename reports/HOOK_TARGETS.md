# 动态 Hook 目标定位（基于当前版本 smali 实证）

> 数据源：apktool decode 产物 `build/apktool/smali*/`（11,866 个 smali 文件，72 个 so）。
> 方法：grep 方法定义 + native 声明 + 字符串常量交叉定位。
> 这些是**从当前抓取版本实际反编译得到**的类名，用于替换 hook 脚本里的占位符。

## 1. MidasPay 支付链路（com/pay 包）

| 类 | 关键方法 | Hook 价值 |
|---|---|---|
| `com/pay/tool/APMidasCommMethod` | `MaptoString(HashMap)` / `MaptoString(HashMap,String)` | ⭐⭐⭐ 参数拼接成 URL 串，签名前的原始参数 |
| `com/pay/tool/APMidasTools` | `map2UrlParams(HashMap)` / `getUrlParamsValue` | ⭐⭐ 参数编码（含 urlEncode） |
| `com/pay/api/APPayGameService` | `LaunchMp(...)` / `setCommParams(...)` / `startMpNetWork(...)` | ⭐⭐⭐ 支付入口 + 公共参数（goods_id 等） |
| `com/pay/api/APPayOpenService` | `setCommParams(...)` | ⭐⭐ 支付开放接口参数 |
| `com/pay/http/APHttpHandle` | 网络通信 | ⭐⭐ 请求发送点 |
| `com/pay/http/APNetworkManager` | `dataReport(...)` / `cancelRequest(...)` | ⭐ 数据上报 |
| `com/pay/http/APPluginUrlConf` | 接口地址配置 | ⭐ 找真实支付域名 |

## 2. Native 交互（JNIAdapter）

`com/tencent/midas/comm/jni/JNIAdapter` 声明了 5 个 native 回调方法：

```
NeedLogin()V                        登录态失效回调
NetError(String, int, String)       网络错误回调
NetFinish(String, String)           网络完成回调（含返回数据）
NetStop(String)                     网络停止回调
PayCallBack(Object)                 支付结果回调
```

> 这些是 native → Java 的回调，hook 它们可观察支付结果和返回数据。

## 3. 签名函数的判断

- Java 层 **未找到** 独立的 `getSign` / `doSign` 方法定义（排除 SDK 自带的 Google/Huawei 登录组件）。
- 结合 dex 字符串池中的 `-->get md5 form native`、`-->signEncryped:`，判断**签名计算在 native 层**（.so）。
- 因此策略是：**不在 Java 层复刻算法，改用 `06_sign_rpc.js` 通过 Frida 直接调用 native 签名函数现算**。

## 4. 推荐的 hook 脚本占位符回填

`05_hook_midas.js` 中：
```
TARGET_CLASS = "com.tencent.midas.comm.APUtil"   → 改为 "com.pay.api.APPayGameService"
TARGET_METHODS = ["getSign","sign","createSign"]  → 改为 ["LaunchMp","setCommParams","startMpNetWork"]
```

补充 hook（新增，观察支付参数拼接）：
```javascript
Java.perform(function () {
  var C = Java.use("com.pay.tool.APMidasCommMethod");
  C.MaptoString.overload("java.util.HashMap").implementation = function (m) {
    var r = this.MaptoString(m);
    console.log("[Midas] MaptoString -> " + r);
    return r;
  };
  var J = Java.use("com.tencent.midas.comm.jni.JNIAdapter");
  J.NetFinish.implementation = function (a, b) {
    console.log("[Midas] NetFinish -> " + a + " | " + b);
    return this.NetFinish(a, b);
  };
});
```

## 5. 下一步（需真机）

1. 用 `03_hook_ssl.js` 绕 SSL + `08_capture.sh` 抓包，拿到真实支付接口 URL。
2. 挂上述 hook，进入游戏触发支付，观察 `MaptoString` 打印的**签名前原始参数**。
3. 用 `06_sign_rpc.js` 的 `findSign` 扫描 native 侧签名导出，或直接在 `libmidas`/`libUE4.so` hook `curl_easy_setopt`。
4. `07_replay.py` 现算签名重放验证。

---

*所有类名均来自 `build/apktool/` 实际反编译产物，非臆测。*
