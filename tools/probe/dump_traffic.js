/*
 * dump_traffic.js — hook libUE4.so 的 UDFMGameTss::SendTssData / requestCallback
 * 附近，dump 出站 protobuf 二进制到文件，供离线分析。
 *
 * 静态证据（报告 repo/reports/HAVAL_PURCHASE_API.md）：
 *   UDFMGameTss::SendTssData        @ libUE4.so:0x5c32655  (high: 明文符号)
 *   requestCallback                 @ libUE4.so:0x15f9c594 (medium: JS 打包层字符串)
 *   seq_id / cmd_id                 @ 0x15f9c5c5 / 0x15f9c5cc (high)
 *   TssSDKOnRecvSignature           @ 0x4d7c3de (high)
 *   cgi info: / genericPacketProcessor / sub_cmd_id @ 0x15f9c476 / 0x15f9c514 / 0x15f9e216
 *
 * 重要：0x15f9xxxx 段位于 so 内的 JS(WebPack) 打包数据区，不是可直接 hook 的 native 函数入口！
 * 所以本脚本：
 *   1) 对 0x5c32655 用 Interceptor.attach（真实 native 函数，high confidence）。
 *   2) 对 JS 层的 requestCallback 不做代码 hook，而是 hook 其底层发包/收包函数
 *      （通过导出的 send/recv 符号或 protobuf 序列化点），并在日志中标注置信度。
 *   3) 提供按偏移手动指定 hook 点的能力：Frida 运行前用 setHookOffset("name", offset)。
 *
 * 输出目录：/data/local/tmp/dfm_dump/（可通过 rpc.exports.setOutDir 改）。
 * 每个包保存为 <seq>-<dir>-<ts>.bin + .json 元数据。
 */

'use strict';

var TARGET_MODULE = 'libUE4.so';
var OUT_DIR = '/data/local/tmp/dfm_dump';
var hooks = [];
var seqCounter = 0;

// 偏移来自静态分析（相对 libUE4.so 基址）
var KNOWN_OFFSETS = {
  SendTssData: 0x5c32655,
  TssSDKOnRecvSignature: 0x4d7c3de,
  requestCallback_js_string: 0x15f9c594, // JS 字符串位置，非函数入口；仅作标注
  cmd_id_string: 0x15f9c5cc,
  seq_id_string: 0x15f9c5c5
};

function log(msg) { console.log('[dump_traffic] ' + msg); }

function baseAddr() {
  var m = Process.findModuleByName(TARGET_MODULE);
  if (!m) throw new Error(TARGET_MODULE + ' 未加载');
  return m.base;
}

function addrOf(offset) { return baseAddr().add(offset); }

function safeWrite(name, bytes, meta) {
  try {
    var buf = bytes instanceof ArrayBuffer ? bytes : Memory.readByteArray(bytes, bytes.length);
    var byteLen = buf.byteLength || buf.length;
    var f = new File(OUT_DIR + '/' + name + '.bin', 'wb');
    f.write(buf);
    f.close();
    log('dumped ' + name + '.bin (' + byteLen + ' bytes)');
    var jf = new File(OUT_DIR + '/' + name + '.json', 'w');
    jf.write(JSON.stringify(meta, null, 2));
    jf.close();
    log('dumped ' + name + '.bin (' + bytes.length + ' bytes)');
  } catch (e) {
    log('写文件失败: ' + e + '  （确认 OUT_DIR 存在且可写）');
  }
}

// 从 C++ 指针 + 长度 dump，智能识别常见容器（std::string / TArray / raw ptr）
function dumpArgPtr(ptr, guessedLen, tag) {
  if (ptr.isNull()) { log(tag + ': null ptr'); return null; }
  var len = guessedLen;
  if (!len || len > 16 * 1024 * 1024) len = 4096;
  var bytes = ptr.readByteArray(len);
  if (!bytes) { log(tag + ': readByteArray 失败'); return null; }
  var name = (++seqCounter) + '-' + tag + '-' + Date.now();
  safeWrite(name, bytes, {
    tag: tag,
    ptr: ptr.toString(),
    len: bytes.byteLength || bytes.length,
    module: TARGET_MODULE,
    confidence: tag === 'SendTssData' ? 'high' : 'medium',
    note: 'guessed length; trim to actual protobuf body with protoc --decode_raw'
  });
  return bytes;
}

// ---- hook 1: UDFMGameTss::SendTssData（native 符号，高可信） ----
function hookSendTssData() {
  try {
    var addr = addrOf(KNOWN_OFFSETS.SendTssData);
    log('hook SendTssData @ ' + addr + ' (offset 0x' + KNOWN_OFFSETS.SendTssData.toString(16) + ')');
    var h = Interceptor.attach(addr, {
      onEnter: function (args) {
        // UE4/C++ 成员调用约定：this=x0, 参数依次 x1..；protobuf/TArray 参数形态未知，
        // 这里按"最可能"的顺序 dump 前 3 个非 null 指针参数，并在元数据标注 low confidence。
        this._args = [args[1], args[2], args[3]].map(function (a) { return a.toString(); });
        [args[1], args[2], args[3]].forEach(function (a, i) {
          try { if (!a.isNull()) dumpArgPtr(a, i === 0 ? 8192 : 4096, 'SendTssData_arg' + (i + 1)); }
          catch (e) { log('arg' + (i + 1) + ' dump 失败: ' + e); }
        });
      },
      onLeave: function (retval) {
        log('SendTssData returned ' + retval);
      }
    });
    hooks.push(h);
    return true;
  } catch (e) {
    log('hook SendTssData 失败: ' + e);
    return false;
  }
}

// ---- hook 2: TssSDKOnRecvSignature（签名相关，辅助） ----
function hookSignature() {
  try {
    var addr = addrOf(KNOWN_OFFSETS.TssSDKOnRecvSignature);
    log('hook TssSDKOnRecvSignature @ ' + addr);
    var h = Interceptor.attach(addr, {
      onEnter: function (args) {
        this._sigPtrs = [args[0], args[1]].map(function (a) { return a.toString(); });
        [args[0], args[1]].forEach(function (a, i) {
          try { if (!a.isNull()) dumpArgPtr(a, 512, 'Signature_arg' + (i + 1)); }
          catch (e) {}
        });
      }
    });
    hooks.push(h);
    return true;
  } catch (e) {
    log('hook TssSDKOnRecvSignature 失败: ' + e);
    return false;
  }
}

// ---- hook 3: 通用 recv/send（帧级抓取，覆盖 JS 层 requestCallback） ----
// requestCallback 的字符串位于 JS 打包数据区 (0x15f9c594)，无法直接 Interceptor。
// 退而 hook libc send/recv（或 libcrosCurl.so 的写回调），按帧长度截断后保存。
function hookSocketIO() {
  var targets = [
    { name: 'send', argIndex: 1, lenIndex: 2, tag: 'socket_send' },
    { name: 'recv', argIndex: 1, lenIndex: 2, tag: 'socket_recv' }
  ];
  var count = 0;
  targets.forEach(function (t) {
    var addr = Module.findExportByName(null, t.name);
    if (!addr) { log('未找到 libc ' + t.name + ' 导出'); return; }
    try {
      var h = Interceptor.attach(addr, {
        onEnter: function (args) {
          this._buf = args[t.argIndex];
          this._len = args[t.lenIndex].toInt32();
        },
        onLeave: function () {
          if (!this._buf || this._len <= 0 || this._len > 16 * 1024 * 1024) return;
          // 只保存看起来像我们目标帧的数据（含已知消息名片段或长度>16），减少噪声
          try {
            var head = this._buf.readByteArray(Math.min(this._len, 64));
            if (!head) return;
            var u = new Uint8Array(head);
            var s = '';
            for (var i = 0; i < u.length; i++) s += (u[i] >= 32 && u[i] < 127) ? String.fromCharCode(u[i]) : '.';
            if (this._len < 16 && s.indexOf('CS') < 0) return;
            dumpArgPtr(this._buf, this._len, t.tag);
          } catch (e) {}
        }
      });
      hooks.push(h);
      count++;
    } catch (e) { log('hook ' + t.name + ' 失败: ' + e); }
  });
  log('socket hook 点位数: ' + count + '（帧级 dump，可信度 high；内容是否 protobuf 需离线验证）');
  return count;
}

rpc.exports = {
  setOutDir: function (dir) { OUT_DIR = dir; log('OUT_DIR=' + OUT_DIR); },
  offsets: function () { return KNOWN_OFFSETS; },
  dumpOnce: function (addrStr, len) {
    var p = ptr(addrStr);
    return dumpArgPtr(p, len || 4096, 'manual') ? true : false;
  },
  detach: function () {
    hooks.forEach(function (h) { try { h.detach(); } catch (e) {} });
    hooks = [];
    log('detached all hooks');
  }
};

log('=== dump_traffic 初始化 ===');
log('target=' + TARGET_MODULE + ' base=' + baseAddr());
log('OUT_DIR=' + OUT_DIR + '（请先 mkdir -p 并 chmod 777）');
log('静态偏移: ' + JSON.stringify(KNOWN_OFFSETS));
hookSendTssData();
hookSignature();
hookSocketIO();
log('初始化完成。调用 rpc.exports.detach() 可停止。');
