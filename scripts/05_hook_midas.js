/*
 * 05_hook_midas.js — MidasPay 支付字段观察
 * hook 常见 MidasPay 入口，打印 goods_id / currency_type / token / 支付参数
 * 类名/方法名为占位，需按实际 jadx 结果替换（findClass 扫描辅助）
 * 用法: frida -U -f com.tencent.tmgp.dfm -l 05_hook_midas.js --no-pause
 */
Java.perform(function () {
    console.log("[*] MidasPay hook 加载中...");

    // 扫描含 midas / pay 的类
    function findMidasClasses() {
        Java.enumerateLoadedClasses({
            onMatch: function (name) {
                if (/midas|pay/i.test(name)) {
                    console.log("[class] " + name);
                }
            },
            onComplete: function () { console.log("[*] 类扫描完成"); }
        });
    }
    findMidasClasses();

    // 占位：按实际替换
    var TARGET_CLASS = "com.pay.api.APPayGameService"; // 实证类名（当前版本 smali）
    var TARGET_METHODS = ["LaunchMp", "setCommParams", "startMpNetWork"]; // 实证方法

    TARGET_METHODS.forEach(function (m) {
        try {
            var cls = Java.use(TARGET_CLASS);
            if (cls[m]) {
                cls[m].overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        var args = [];
                        for (var i = 0; i < arguments.length; i++) args.push(String(arguments[i]));
                        console.log("[MidasPay] " + TARGET_CLASS + "." + m + "(" + args.join(", ") + ")");
                        var ret = ov.apply(this, arguments);
                        console.log("[MidasPay]   -> " + ret);
                        return ret;
                    };
                });
                console.log("[+] hooked " + TARGET_CLASS + "." + m);
            }
        } catch (e) { console.log("[-] " + m + " hook 失败: " + e); }
    });

    console.log("[*] MidasPay hook 注入完成（占位类需按扫描结果替换）");
});
