/*
 * 06_sign_rpc.js — 把 APP 内签名函数导出为 Frida RPC
 * rpc.exports.sign(params) 供主机侧 07_replay.py 调用现算签名
 * 类名/方法名为占位，先用 findSign 扫描真实函数再回填
 * 用法: frida -H 127.0.0.1:5555 -f com.tencent.tmgp.dfm -l 06_sign_rpc.js --no-pause
 */
'use strict';

var TARGET_CLASS = "com.tencent.midas.comm.APUtil"; // ← 按实际替换
var TARGET_METHOD = "getSign";                       // ← 按实际替换

rpc.exports = {
    // 扫描候选签名函数（打印类名，帮助定位占位符）
    findSign: function () {
        var hits = [];
        Java.perform(function () {
            Java.enumerateLoadedClasses({
                onMatch: function (name) {
                    if (/sign|crypto|signutil|aputil|security|signhelper/i.test(name)) {
                        hits.push(name);
                    }
                },
                onComplete: function () {}
            });
        });
        return hits;
    },

    // 现算签名：params 为字符串（通常 JSON），返回签名字符串
    sign: function (params) {
        var result = null;
        Java.perform(function () {
            try {
                var cls = Java.use(TARGET_CLASS);
                var method = cls[TARGET_METHOD];
                var ret = method.call(cls, params);
                result = String(ret);
                console.log("[RPC] sign(" + params + ") -> " + result);
            } catch (e) {
                console.log("[RPC] sign 失败: " + e);
                result = "ERROR: " + e;
            }
        });
        return result;
    },

    version: function () { return "sign_rpc 1.0"; }
};

console.log("[*] 签名 RPC 已导出: findSign / sign / version");
console.log("[*] 当前占位: " + TARGET_CLASS + "." + TARGET_METHOD + "（请用 findSign 结果回填）");
