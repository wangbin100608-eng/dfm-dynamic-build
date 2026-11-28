/*
 * sign_rpc.example.js — Frida 签名 RPC 模板（阶段3，真机现算签名）
 *
 * 对齐 probe_gateway.py:
 *   python3 probe_gateway.py ... \
 *     --signature-mode frida --frida-sign-script sign_rpc.example.js \
 *     --message CSMallBuyReq --set goods_id=... --mode send
 *   probe_gateway.py 会 attach 目标、加载本脚本、调用
 *     script.exports_sync.sign(bodyHex)   // payloadHex = protobuf body 的十六进制串
 *   期望返回: 签名字节的 hex 字符串（或字节数组）。probe_gateway.py 把返回值
 *   塞进 session["signature_hex"]，再由 frame.order 里的 signature 元素注入帧。
 *
 * ============================================================================
 * 重要：这是"骨架"，不是可直接发包的实现。以下点必须在真机上 hook/确认后填写，
 *       禁止从 libUE4.so 静态复刻签名、禁止臆造密钥/算法/padding。
 * ============================================================================
 *   [HOOK-1] 待签名字节范围：probe_gateway.py 传进来的是 protobuf body。真实 TSS
 *            签名可能覆盖 cmd_id+seq_id+body+时间戳 等拼接串，不一定是 body 本身。
 *            必须在真机 hook 签名函数入参，确认实际被签名的字节范围，然后在
 *            buildPayload() 里按真实规则拼接（当前为占位：原样返回 body）。
 *   [HOOK-2] 摘要算法与 padding：阶段2 静态分析显示 RSA_sign + SHA256/MD5/SHA1
 *            OID 并存，padding 大概率 PKCS#1 v1.5（medium）。真机 hook
 *            RSA_sign(type, ...) / EVP_PKEY_sign 的 type 参数确定；
 *            本模板默认调 OpenSSL RSA_sign(NID_sha256=0x40, ...)，需实测修正。
 *   [HOOK-3] 私钥 / TSS 密钥句柄：私钥运行时持有，so 中无 PEM/PKCS#8 blob。
 *            本模板的 PRIVATE_KEY_PEM 是占位符；真机应从 TSS SDK / keystore
 *            取签名能力，或 hook TssSDKOnRecvSignature 的现成签名结果，
 *            而不是把私钥写死在脚本里。
 *   [HOOK-4] 签名在帧中的位置/长度：由 dump_traffic.js 真实字节校准 frame.order
 *            中 signature 元素的 enabled/size；本脚本只产出签名字节。
 *   [HOOK-5] 包名/PID：默认 com.tencent.tmgp.dfm；多开/改包名时改 probe_gateway.py
 *            的 field_map.json.signature.package_or_pid 或本脚本 TARGET。
 */

'use strict';

var TARGET_MODULE = 'libUE4.so';
var NID_SHA256 = 0x40;  // [HOOK-2] 真机确认后修正（NID_sha1=0x20, NID_md5=0x21）

// ---------------------------------------------------------------------------
// 工具函数
// ---------------------------------------------------------------------------
function log(msg) { console.log('[sign_rpc] ' + msg); }

function modBase() {
  var m = Process.findModuleByName(TARGET_MODULE);
  if (!m) throw new Error(TARGET_MODULE + ' 未加载（游戏未启动？）');
  return m.base;
}

// 把 hex 字符串读成 ArrayBuffer
function hexToBytes(hex) {
  var clean = hex.replace(/ /g, '');
  if (clean.length % 2 !== 0) throw new Error('payloadHex 长度为奇数');
  var out = new Uint8Array(clean.length / 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}

// 把字节数组转回 hex 字符串（probe_gateway.py 期望的返回格式）
function bytesToHex(bytes) {
  var out = '';
  for (var i = 0; i < bytes.length; i++) {
    out += ('0' + (bytes[i] & 0xff).toString(16)).slice(-2);
  }
  return out;
}

// ---------------------------------------------------------------------------
// [HOOK-1] 构造真实待签名字节
//   probe_gateway.py 传入的是 protobuf body 的 hex。真实签名输入需按真机 hook
//   结果拼接（cmd_id/seq_id/body/timestamp/session key... 的顺序与分隔符）。
//   当前实现是"占位：原样返回 body"，只用于跑通 RPC 链路，不代表合法签名。
// ---------------------------------------------------------------------------
function buildPayload(bodyHex) {
  var body = hexToBytes(bodyHex);
  log('body bytes=' + body.length + ' [HOOK-1] 待签名字节范围待真机确认');
  // TODO(真机): 按 dump_traffic.js / hook RSA_sign 入参结果拼接真实 payload：
  //   var cmd = <从 session 注入或从 probe 侧传>;
  //   return concat(cmdBytes, seqBytes, body, ...);
  return body;
}

// ---------------------------------------------------------------------------
// [HOOK-3] 取私钥 / 调用签名能力
//   3 种真机可行路径（按推荐顺序）：
//   A. hook TssSDKOnRecvSignature @ libUE4.so:0x4d7c3de，直接读取现成签名字节
//      （最省事：让客户端自己签，RPC 只负责把结果回传）；
//   B. hook RSA_sign / EVP_PKEY_sign，用 Interceptor.replace 在真机进程内调真实
//      密钥句柄对 payload 签名；
//   C. [占位] 用外部私钥在 PC 侧签 —— 仅当真机能导出合法私钥/密钥句柄时使用，
//      私钥不可从 so 静态提取（阶段2 结论）。
//   下面给出 A 与 C 的骨架，B 留给真机按实际 ABI 补充。
// ---------------------------------------------------------------------------

// 路径 A 骨架：从 hook 到的签名结果读取（需要在脚本加载时先 Interceptor.attach）
var lastSignature = null;
function hookTssSignature() {
  try {
    var addr = modBase().add(0x4d7c3de);  // TssSDKOnRecvSignature @ 0x4d7c3de
    Interceptor.attach(addr, {
      onEnter: function (args) {
        // TODO(真机): 根据真实函数签名确定哪个参数指向签名字节、长度在哪。
        // 示例（需实测修正）：
        //   var p = args[1]; var len = args[2].toInt32();
        //   if (len > 0 && len < 4096) lastSignature = Memory.readByteArray(p, len);
        log('TssSDKOnRecvSignature hit; 参数需真机确认后读取签名');
      }
    });
    log('hook TssSDKOnRecvSignature @ 0x4d7c3de 已安装');
  } catch (e) {
    log('hook TssSDKOnRecvSignature 失败: ' + e);
  }
}

// 路径 C 骨架：PC 侧私钥签名（占位，禁止用臆造密钥发包）
// var PRIVATE_KEY_PEM = '<从真机安全导出或 TSS keystore 获取，禁止硬编码臆造值>';
function signWithPrivateKey(payload) {
  // Frida JS 无内置 RSA。可用 frida 的 Module/NativeFunction 调 libcrypto 的
  // RSA_sign，或用 Python 侧（probe_gateway.py --signature-mode file）替代。
  // 这里仅占位：
  throw new Error('[HOOK-3] 未实现：请在真机 hook TSS/RSA_sign 现算，或提供合法私钥后实现本函数。');
}

// ---------------------------------------------------------------------------
// rpc.exports.sign —— probe_gateway.py 调用的入口
// ---------------------------------------------------------------------------
rpc.exports = {
  sign: function (payloadHex) {
    log('sign() called, payloadHex len=' + String(payloadHex).length);

    // 1) 构造待签名字节（HOOK-1）
    var payload = buildPayload(payloadHex);

    // 2) 取签名（HOOK-2/3）：优先用真机 hook 到的现成结果
    if (lastSignature) {
      var sig = new Uint8Array(lastSignature);
      log('返回 hook 到的签名字节 len=' + sig.length);
      return bytesToHex(sig);
    }

    // 3) 否则走私钥/密钥句柄路径（需真机补齐）
    // var sigBytes = signWithPrivateKey(payload);
    // return bytesToHex(sigBytes);

    throw new Error('[HOOK-3] 未获得签名：必须在真机 hook TSS/RSA_sign 或提供合法密钥句柄；'
      + '禁止返回臆造/占位签名字节。');
  },
  // 调试辅助：让调用方确认脚本已加载、hook 是否就位
  status: function () {
    return {
      ready: !!lastSignature,
      module: TARGET_MODULE,
      hooked_signature: true,  // hookTssSignature 已在加载时调用
      hookpoints: {
        TssSDKOnRecvSignature: '0x4d7c3de',
        SendTssData: '0x5c32655',
        RSA_sign: '[HOOK-2] 真机定位后填偏移'
      }
    };
  }
};

// 脚本加载即安装 hook（真机运行时）
hookTssSignature();
log('sign_rpc.example.js 加载完成。调用 rpc.exports.sign(payloadHex) 获取签名。');
log('注意：这是模板，需按 [HOOK-1..5] 在真机补齐后才能产出合法签名。');
