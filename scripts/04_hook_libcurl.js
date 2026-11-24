/*
 * 04_hook_libcurl.js — native 层明文 body 还原
 * hook curl_easy_setopt / curl_easy_perform，打印 URL / POSTFIELDS / HTTPHEADER
 * UE4 静态链接 libcurl 时导出名可能不在 libUE4.so，脚本做多模块探测 + 延迟轮询
 * 用法: frida -U -f com.tencent.tmgp.dfm -l 04_hook_libcurl.js --no-pause
 */
'use strict';

var CURL_OPT_URL = 10002;      // CURLOPT_URL
var CURL_OPT_POSTFIELDS = 10015; // CURLOPT_POSTFIELDS
var CURL_OPT_HTTPHEADER = 10023; // CURLOPT_HTTPHEADER
var CURL_OPT_POSTFIELDSIZE = 60; // CURLOPT_POSTFIELDSIZE

var seen = {};

function hook_setopt(addr, modName) {
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                var opt = args[1].toInt32();
                if (opt === CURL_OPT_URL) {
                    var url = args[2].readCString();
                    console.log("[libcurl][" + modName + "] URL: " + url);
                } else if (opt === CURL_OPT_POSTFIELDS || opt === CURL_OPT_POSTFIELDSIZE) {
                    var body = args[2].readCString();
                    if (body) console.log("[libcurl][" + modName + "] BODY: " + body.substring(0, 2000));
                } else if (opt === CURL_OPT_HTTPHEADER) {
                    console.log("[libcurl][" + modName + "] HTTPHEADER set");
                }
            }
        });
        console.log("[+] hooked curl_easy_setopt @ " + addr + " (" + modName + ")");
    } catch (e) { console.log("[-] hook_setopt 失败: " + e); }
}

function scanModule(mod) {
    ['curl_easy_setopt', '_curl_easy_setopt', 'curl_easy_setopt@'].forEach(function (sym) {
        var addr = Module.findExportByName ? Module.findExportByName(mod.name, sym) : null;
        if (!addr && mod.findExportByName) addr = mod.findExportByName(sym);
        if (addr && !seen[addr.toString()]) {
            seen[addr.toString()] = 1;
            hook_setopt(addr, mod.name);
        }
    });
}

function scan_all() {
    Process.enumerateModules().forEach(function (m) {
        if (/UE4|libcurl|gamemaster|tapsdk|curl/i.test(m.name)) scanModule(m);
    });
}

console.log("[*] 扫描 libcurl 导出...");
scan_all();
// 延迟轮询：so 可能还没加载
var tries = 0;
var timer = setInterval(function () {
    tries++;
    scan_all();
    if (tries > 30) clearInterval(timer);
}, 1000);
console.log("[*] 延迟轮询已启动（30 次）");
