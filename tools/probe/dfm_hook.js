'use strict';
// 游戏本体动态反编译 hook：ACE 反作弊 + UE4 入口 + protobuf 网关 + native so 加载
var TAG = 'DFM_DYN';
function log(o) { try { send(Object.assign({ tag: TAG, ts: Date.now() }, o)); } catch (e) {} }

log({ type: 'start', arch: Process.arch, pid: Process.id });

// 1) 已加载模块（native so 清单）
try {
  var mods = Process.enumerateModules();
  log({ type: 'modules_total', count: mods.length });
  mods.forEach(function (m) {
    if (/UE4|tersafe|tss|turing|tgpa|tprt|gcloud|midas|gamemaster|magt|zeus|dex|curl|crash/i.test(m.name))
      log({ type: 'module', name: m.name, base: String(m.base), size: m.size });
  });
} catch (e) { log({ type: 'err', where: 'modules', msg: String(e) }); }

// 2) dlopen 监控（so 动态加载时序）
try {
  var dlopen = Module.findExportByName(null, 'dlopen');
  if (dlopen) {
    Interceptor.attach(dlopen, {
      onEnter: function (a) { try { this.p = a[0].readCString(); } catch (e) { this.p = null; } },
      onLeave: function (r) {
        if (this.p && /UE4|tersafe|turing|tgpa|tprt|tss|midas|gcloud|dex|zeus|crash/i.test(this.p))
          log({ type: 'dlopen', path: this.p, ok: !r.isNull() });
      }
    });
    log({ type: 'hooked_dlopen' });
  } else log({ type: 'warn', msg: 'dlopen not found' });
} catch (e) { log({ type: 'err', where: 'dlopen', msg: String(e) }); }

// 3) Java 层：枚举关键类 + hook 关键方法
setTimeout(function () {
  try {
    Java.perform(function () {
      var INTEREST = /com\.tencent\.(tp|tersafe2|tmgp\.dfm)|com\.epicgames\.ue4|com\.pay\./;
      Java.enumerateLoadedClasses({
        onMatch: function (n) { if (INTEREST.test(n)) log({ type: 'class', name: n }); },
        onComplete: function () { log({ type: 'classes_done' }); }
      });

      var HOOKS = [
        ['com.tencent.tp.TssSdk', ['init', 'ioctl', 'getsdkantidata', 'getReportData', 'enableGameReport']],
        ['com.tencent.tp.TouchListenerProxy', ['onTouch']],
        ['com.tencent.tersafe2.TP2Sdk', ['init', 'initEx', 'onUserLogin', 'onAppResume', 'onAppPause', 'getReportData', 'ioctl']],
        ['com.epicgames.ue4.GameActivity', ['onCreate', 'nativeSetGlobalActivity', 'nativeResumeMainInit']],
        ['com.pay.tool.APMidasCommMethod', ['MaptoString']],
        ['com.pay.api.APPayGameService', ['LaunchMp', 'setCommParams']]
      ];
      HOOKS.forEach(function (t) {
        var C;
        try { C = Java.use(t[0]); } catch (e) { log({ type: 'miss', cls: t[0] }); return; }
        t[1].forEach(function (mn) {
          try {
            var m = C[mn];
            if (!m || !m.overloads) return;
            m.overloads.forEach(function (ov, i) {
              ov.implementation = function () {
                var a = [];
                for (var k = 0; k < arguments.length; k++) {
                  try { var v = arguments[k]; a.push(v === null ? 'null' : String(v).slice(0, 120)); }
                  catch (e) { a.push('<obj>'); }
                }
                log({ type: 'call', cls: t[0], method: mn, ov: i, args: a });
                return ov.apply(this, arguments);
              };
              log({ type: 'hooked', cls: t[0], method: mn, ov: i, sig: ov.toString().slice(0, 220) });
            });
          } catch (e) { log({ type: 'err', where: t[0] + '.' + mn, msg: String(e) }); }
        });
      });

      // ROT5 混淆函数 l.a() 直接调用验证
      try {
        var L = Java.use('com.tencent.tp.l');
        ['bzo_mzkjmo_yvov', 'poa-8', 'dgx_jkzi_kdkz', 'didodvgduz'].forEach(function (x) {
          try { log({ type: 'rot5', cipher: x, plain: L.a(x) }); } catch (e) {}
        });
      } catch (e) { log({ type: 'err', where: 'l.a', msg: String(e) }); }
    });
  } catch (e) { log({ type: 'err', where: 'java', msg: String(e) }); }
}, 1500);
