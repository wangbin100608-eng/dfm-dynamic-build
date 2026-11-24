/*
 * 03_hook_ssl.js — Frida SSL Pinning bypass
 * 覆盖 OkHttp / Conscrypt / TrustManager / TrustManagerFactory
 * 用法: frida -U -f com.tencent.tmgp.dfm -l 03_hook_ssl.js --no-pause
 */
Java.perform(function () {
    console.log("[*] SSL Pinning bypass 加载中...");

    function bypassTrustManager() {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        try {
            TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                console.log("[+] bypass verifyChain: " + host);
                return untrustedChain;
            };
        } catch (e) { console.log("[-] TrustManagerImpl hook 失败: " + e); }

        var tm = Java.registerClass({
            name: "com.dfm.bypass.TM",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        try {
            var SSLContext = Java.use("javax.net.ssl.SSLContext");
            SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function (km, tmArr, sr) {
                console.log("[+] SSLContext.init bypass");
                return this.init(km, [tm.$new()], sr);
            };
        } catch (e) { console.log("[-] SSLContext hook 失败: " + e); }
    }

    function bypassOkHttp() {
        try {
            var CertificatePinner = Java.use("okhttp3.CertificatePinner");
            CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (host, peers) {
                console.log("[+] OkHttp CertificatePinner.check bypass: " + host);
            };
            CertificatePinner.check$okhttp.implementation = function (host, peers) {
                console.log("[+] OkHttp check$okhttp bypass: " + host);
            };
        } catch (e) { console.log("[-] OkHttp pinner hook 失败（可能版本不同）: " + e); }
    }

    function bypassWebView() {
        try {
            var WebViewClient = Java.use("android.webkit.WebViewClient");
            WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
                console.log("[+] WebView SSL error bypass");
                handler.proceed();
            };
        } catch (e) {}
    }

    try { bypassTrustManager(); } catch (e) { console.log(e); }
    try { bypassOkHttp(); } catch (e) { console.log(e); }
    try { bypassWebView(); } catch (e) { console.log(e); }
    console.log("[*] SSL Pinning bypass 注入完成");
});
