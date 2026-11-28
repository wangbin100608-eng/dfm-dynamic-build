# decompiled_samples/ — 关键 Java 类反编译样本

从官服 `1.201.37119.49`（SHA256 `1ce71a21…f44a`）的 jadx 输出中摘录的关键类，供复核报告结论：

| 文件 | 关键结论 |
|---|---|
| `com/tencent/tp/TssSdk.java` | 静态块 `System.loadLibrary("tersafe")`；`TSS_SDK_VERSION = 8.0.46`；`l.a()` 混淆命令入口 |
| `com/tencent/tp/l.java` | **ROT5 凯撒移位（字母 +5）** —— 破解反作弊字符串混淆的关键 |
| `com/tencent/tp/TouchListenerProxy.java` | `AddAnoTouchEvent` 触摸行为采集（pointerId/downTime/eventTime/touchMinor/touchMajor 送 native） |
| `com/tencent/tersafe2/TP2Sdk.java` | ACE 反作弊 Java 封装：init / onUserLogin / onAppResume / getReportData |

完整 jadx 输出（8567 个 Java）见 `reports/DECOMPILE_RESULTS.md`；本目录只入库与结论直接相关的 4 个类。

解密命令示例（`l.a()` 是 +5 加密，故密文 `bzo_mzkjmo_yvov` → 明文 `get_report_data`）：

```python
def rot5(s):
    out = ''
    for c in s:
        if 'a' <= c <= 'z': out += chr((ord(c) - 97 + 5) % 26 + 97)
        elif 'A' <= c <= 'Z': out += chr((ord(c) - 65 + 5) % 26 + 65)
        else: out += c
    return out

print(rot5('bzo_mzkjmo_yvov'))  # get_report_data
print(rot5('VyyVijOjpxcZqzio')) # AddAnoTouchEvent
```
