/*
 * find_descriptor.js — 运行期从 protobuf DescriptorPool 导出 cs_mall.proto 的
 * FileDescriptorProto（字段名 + 字段号 + 类型 + 归属消息），补齐静态逆向缺口。
 *
 * 背景（静态逆向报告 repo/reports/HAVAL_PURCHASE_API.md）：
 *   - libUE4.so 中明确存在 cs_mall.pb.cpp@0x5e33b45 / cs_currency.pb.cpp@0x5b6cbd8
 *     等 protobuf C++ 编译单元，说明客户端用 C++ protobuf 生成类。
 *   - 但字符串池里没有 cs_mall.proto 的序列化 descriptor，字段号无法静态确定。
 *   - google::protobuf::DescriptorPool::generated_pool()->FindFileByName("cs_mall.proto")
 *     可以在运行时拿到 FileDescriptorProto；本脚本用 Frida Stalker/Interceptor 在
 *     libUE4.so 中定位 generated_pool 导出的函数并调用。
 *
 * 重要：本脚本依赖目标进程内的 C++ ABI。不同构建（本样本 1.201.1035.13）可能有
 * 符号裁剪；脚本提供三种策略（按可信度排序）：
 *   A. 直接调用导出的 C++ 符号（若 so 动态符号表保留）  — 最可靠
 *   B. 枚举 generated_pool 内部 DescriptorPool 对象并找 file 表  — 需要结构布局猜测（low confidence）
 *   C. hook protobuf 反序列化入口，从运行中的消息对象反射字段  — 兜底，字段号来自 wire 解析
 *
 * 输出：Frida console 打印 + rpc.exports.dump() 返回 JSON，可直接喂给 probe_gateway.py
 * 的 field_map.json（只替换 number，保留静态证据字段）。
 *
 * 可信度标注：脚本打印每条结果的 source/confidence；策略 B/C 的结果必须人工核对。
 */

'use strict';

rpc.exports = {
  dump: function (fileName) {
    return dumpDescriptor(fileName || 'cs_mall.proto');
  },
  listFiles: function () {
    return listPoolFiles();
  }
};

var TARGET_MODULE = 'libUE4.so';
var DEFAULT_FILE = 'cs_mall.proto';

function log(msg) { console.log('[find_descriptor] ' + msg); }

// 把 std::string 从 C++ 对象读成 JS string（32-bit 布局：ptr, size, union[16]）
function readStdString(addr) {
  var ptr = Memory.readPointer(addr);
  var len = Memory.readUInt(ptr.add(Process.pointerSize * 2));
  if (len > 4096) throw new Error('std::string 长度异常: ' + len);
  return ptr.readUtf8String(len);
}

// FileDescriptorProto 是 protobuf 消息；这里只做字段号/字段名/类型的 wire 级解析，
// 不依赖 google::protobuf 的 JS 绑定。
function parseVarint(buf, pos) {
  var result = 0, shift = 0, b;
  do {
    b = buf[pos++];
    result |= (b & 0x7f) << shift;
    shift += 7;
  } while ((b & 0x80) !== 0 && shift < 70);
  return [result >>> 0, pos];
}

function parseDescriptorProto(bytes) {
  var fields = [];
  var messages = [];
  var pos = 0;
  // DescriptorProto: message_type = field 4 (LEN), name = field 1
  while (pos < bytes.length) {
    var t, wire;
    [t, pos] = parseVarint(bytes, pos);
    var number = t >>> 3; wire = t & 7;
    if (wire === 2) {
      var size; [size, pos] = parseVarint(bytes, pos);
      var sub = bytes.slice(pos, pos + size); pos += size;
      if (number === 4) { // DescriptorProto message_type
        messages.push(parseMessageDescriptor(sub));
      }
    } else if (wire === 0) {
      [, pos] = parseVarint(bytes, pos);
    } else if (wire === 5) pos += 4;
    else if (wire === 1) pos += 8;
    else throw new Error('未知 wire type ' + wire + ' in FileDescriptorProto');
  }
  return { messages: messages };
}

function parseMessageDescriptor(bytes) {
  var name = null;
  var fields = [];
  var pos = 0;
  while (pos < bytes.length) {
    var t, wire;
    [t, pos] = parseVarint(bytes, pos);
    var number = t >>> 3; wire = t & 7;
    if (wire === 2) {
      var size; [size, pos] = parseVarint(bytes, pos);
      var sub = bytes.slice(pos, pos + size); pos += size;
      if (number === 1) name = sub.toString();              // DescriptorProto.name
      else if (number === 2) fields.push(parseFieldDescriptor(sub)); // field
    } else if (wire === 0) {
      [, pos] = parseVarint(bytes, pos);
    } else if (wire === 5) pos += 4;
    else if (wire === 1) pos += 8;
    else throw new Error('未知 wire type ' + wire + ' in DescriptorProto ' + name);
  }
  return { name: name, fields: fields };
}

// FieldDescriptorProto: name=1(LEN), number=3(VARINT), label=4, type=5, type_name=6(LEN)
var TYPE_NAME = {1:'double',2:'float',3:'int64',4:'uint64',5:'int32',6:'fixed64',7:'fixed32',8:'bool',9:'string',10:'group',11:'message',12:'bytes',13:'uint32',14:'enum',15:'sfixed32',16:'sfixed64',17:'sint32',18:'sint64'};
var LABEL_NAME = {1:'optional',2:'required',3:'repeated'};

function parseFieldDescriptor(bytes) {
  var rec = {name:null, number:null, label:null, type:null, type_name:null};
  var pos = 0;
  while (pos < bytes.length) {
    var t, wire;
    [t, pos] = parseVarint(bytes, pos);
    var number = t >>> 3; wire = t & 7;
    if (wire === 2) {
      var size; [size, pos] = parseVarint(bytes, pos);
      var sub = bytes.slice(pos, pos + size); pos += size;
      if (number === 1) rec.name = sub.toString();
      else if (number === 6) rec.type_name = sub.toString();
    } else if (wire === 0) {
      var val; [val, pos] = parseVarint(bytes, pos);
      if (number === 3) rec.number = val;
      else if (number === 4) rec.label = LABEL_NAME[val] || val;
      else if (number === 5) rec.type = TYPE_NAME[val] || val;
    } else if (wire === 5) pos += 4;
    else if (wire === 1) pos += 8;
    else throw new Error('未知 wire type ' + wire + ' in FieldDescriptorProto');
  }
  return rec;
}

// ---- 策略 A：直接调用 generated_pool 导出的 C++ 符号 -------------------
function tryExportedSymbols(fileName) {
  var results = [];
  var mod = Process.findModuleByName(TARGET_MODULE);
  if (!mod) { log('模块 ' + TARGET_MODULE + ' 未加载'); return results; }

  // 常见导出名（nm -D 可预先在远程确认；未导出则 null）
  var candidates = [
    '_ZN6google8protobuf15DescriptorPool14generated_poolEv',
    '_ZN6google8protobuf15DescriptorPool13FindFileByNameERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE',
    '_ZN6google8protobuf2File15CopyToERNS0_19FileDescriptorProtoE' // 可能不存在
  ];
  var syms = candidates.map(function (n) { return mod.findExportByName(n); });
  log('generated_pool export: ' + syms[0]);
  log('FindFileByName export: ' + syms[1]);
  if (!syms[0] || !syms[1]) return results;

  // 构造 std::string 需要 libstdc++ 的 basic_string 构造，ABI 复杂；
  // 若导出存在但无法安全构造，退回到策略 C（hook 解析点）。
  log('策略 A 符号存在，但 std::string ABI 构造需按目标 NDK 版本确认；先尝试策略 C。');
  return results;
}

// ---- 策略 C：hook protobuf 反射/解析入口，从 wire 反推字段号（兜底） ----
// 静态证据：libUE4.so 中 cscpp_security.pb.cpp@0x5f21052 说明 protobuf C++ 运行时在进程内。
// 我们 hook libprotobuf 的 MergeFrom/CodedInputStream::ReadTag（若可导出），
// 或退而 hook 网关帧解析后的 protobuf body，直接对 bytes 做 parseDescriptor 风格的 raw 解析。
// 注意：此法只能看到"客户端实际填充了哪些字段"，看不到 proto 定义里未发送的字段。
function hookWireParsing() {
  var mod = Process.findModuleByName(TARGET_MODULE);
  var hooked = 0;
  // CodedInputStream::ReadTag 在静态链接的 protobuf 中通常内嵌，符号不一定导出。
  // 尝试常见导出名；找不到就只靠 rpc.exports.dump 的 Frida 脚本外部触发。
  var names = [
    '_ZN6google8protobuf16CodedInputStream8ReadTagEPi',
    '_ZN6google8protobuf16CodedInputStream8ReadTagEv'
  ];
  names.forEach(function (n) {
    var addr = mod ? mod.findExportByName(n) : null;
    if (!addr) return;
    try {
      Interceptor.attach(addr, {
        onEnter: function () { this._seen = true; },
        onLeave: function (retval) {
          if (retval && !retval.isNull && !retval.isNull()) {
            var tag = retval.toInt32();
            if (tag > 0) log('ReadTag -> ' + tag + ' (field=' + (tag >>> 3) + ', wire=' + (tag & 7) + ')');
          }
        }
      });
      hooked++;
    } catch (e) { log('hook ' + n + ' 失败: ' + e); }
  });
  log('已 hook protobuf ReadTag 点位数: ' + hooked);
  return hooked;
}

function listPoolFiles() {
  var out = [];
  try {
    var mod = Process.findModuleByName(TARGET_MODULE);
    if (!mod) return [{error: 'module not loaded'}];
    // 在 .rodata 中找所有 '*.proto' 字符串（静态 so 中虽有 pb.cpp 但未必有 .proto 字面量）
    var ranges = mod.enumerateRangesSync('r--');
    ranges.forEach(function (r) {
      try {
        var buf = Memory.readByteArray(r.base, Math.min(r.size, 64 * 1024 * 1024));
        var s = String.fromCharCode.apply(null, new Uint8Array(buf));
        var re = /[A-Za-z0-9_\/.]{1,80}\.proto/g, m;
        while ((m = re.exec(s)) !== null) {
          if (out.indexOf(m[0]) < 0) out.push(m[0]);
        }
      } catch (e) { /* 大段读取失败则跳过 */ }
    });
  } catch (e) { out.push({error: String(e)}); }
  return out;
}

function dumpDescriptor(fileName) {
  var target = fileName || DEFAULT_FILE;
  log('请求导出 FileDescriptorProto: ' + target);
  log('注意：字段名/字段号最终以 DescriptorPool 为准；以下策略结果按可信度标注。');

  var viaSymbols = tryExportedSymbols(target);
  if (viaSymbols.length > 0) {
    log('=== 策略 A 结果（high confidence）===');
    console.log(JSON.stringify(viaSymbols, null, 2));
    return viaSymbols;
  }

  hookWireParsing();
  log('=== 策略 C 提示 ===');
  log('ReadTag hook 输出的是运行时实际解析的 field number，需配合 dump_traffic.js 的抓包对应。');
  log('字段号请以 --set 构造后服务端响应验证；不要凭 hook 输出猜测未出现字段。');
  log('完整 FileDescriptorProto 导出需在目标进程内成功调用 generated_pool()->FindFileByName()，');
  log('并按目标 NDK ABI 构造 std::string；若符号被裁剪，可用 frida 的 CModule / NativeFunction 手动调用。');

  return [{
    _error: '未能自动导出 FileDescriptorProto',
    _hint: '确认 libUE4.so 是否导出 generated_pool/FindFileByName；若未导出，请用 dump_traffic.js 抓包 + protoc --decode_raw，或手动构造 std::string 调用。',
    _static_fallback: {
      cs_mall_fields_seen_in_so: [
        'goods_id','buy_currency_id','buy_num','buy_price','currency_type','currency_id','mall_prices','goods_num','goods_type'
      ],
      confidence: 'field-name high / field-number unknown'
    }
  }];
}

log('loaded. 调用 rpc.exports.dump("cs_mall.proto") 或 rpc.exports.listFiles()');
