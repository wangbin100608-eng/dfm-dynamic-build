#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
probe_gateway.py — 三角洲行动 UE4 私有网关 CS 消息原型探针（纯标准库，无 .proto 依赖）

定位（来自已完成的静态逆向，报告见 repo/reports/HAVAL_PURCHASE_API.md）：
  - 游戏经济接口不是 REST URL，而是 UE4 私有网关 + protobuf CS 消息 + cmd_id/seq_id。
  - 最强候选消息：pb.CSMallBuyReq / CSMallBuyRes（cs_mall.pb.cpp），
     aux: CSGetCurrencyReq/Res、CSCurrencyExchangeReq/Res（cs_currency.pb.cpp）。
  - 字段名有静态证据，字段号(field number)未静态确定 —— 必须由 find_descriptor.js
    在运行期从 protobuf DescriptorPool 导出后填入 field_map.json。
  - 网关 HOST/PORT、cmd_id、seq_id、签名、session/设备指纹均未知，
    本程序一律从配置文件/抓包注入，绝不内置臆造值。

设计原则：
  1. 可插拔消息构造：手写 protobuf wire varint/length-delimited 编解码器，
     字段号从 field_map.json 读取；字段号未填时拒绝构造并明确报错。
  2. 帧格式完全配置化（长度前缀 + cmd_id + seq_id + 可选签名 + protobuf body）。
  3. 会话/签名外部注入：file 模式读 capture.json；frida 模式调用外部 JS 的
     rpc.exports.sign(payloadHex)。哪些参数必须来自真实客户端运行时，见 README.md。
  4. 响应按 decode_raw 风格打印 field_number -> value。

可信度标注约定（贯穿配置与输出）：
  high    = 静态字符串 + proto 编译路径双重证据
  medium  = 仅字符串池证据 / 历史版本推断
  unknown = 静态无法确认，必须抓包或 descriptor 导出

用法见同目录 README.md。
"""
from __future__ import annotations

import argparse
import binascii
import json
import os
import socket
import struct
import sys
from dataclasses import dataclass, field as dc_field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# 1. protobuf wire 层（手写，零依赖）
# ---------------------------------------------------------------------------

WIRE_VARINT = 0      # int32/int64/uint32/uint64/bool/enum
WIRE_FIXED64 = 1     # double/fixed64/sfixed64
WIRE_LEN = 2         # string/bytes/embedded message
WIRE_FIXED32 = 5     # float/fixed32/sfixed32

WIRE_NAME = {
    WIRE_VARINT: "varint",
    WIRE_FIXED64: "fixed64",
    WIRE_LEN: "len",
    WIRE_FIXED32: "fixed32",
}


class WireError(ValueError):
    pass


class ConfigError(ValueError):
    pass


def encode_varint(value: int) -> bytes:
    """标准 protobuf base-128 varint 编码（非 zigzag）。"""
    if value < 0:
        # protobuf 负 int 以 10 字节补码 varint 表示
        value &= (1 << 64) - 1
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def decode_varint(buf: bytes, pos: int = 0) -> Tuple[int, int]:
    result = 0
    shift = 0
    n = len(buf)
    while pos < n and shift < 70:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
    raise WireError("varint 在缓冲区结尾前未终止")


def zigzag_encode(n: int) -> int:
    return (n << 1) ^ (n >> 63)


def zigzag_decode(n: int) -> int:
    return (n >> 1) ^ -(n & 1)


def _validate_field_number(number: Optional[int], where: str) -> int:
    if number is None:
        raise ConfigError(
            f"{where}: field number 未确定（null）。先用 find_descriptor.js 导出 "
            f"FileDescriptorProto 并填入 field_map.json，不要猜字段号。"
        )
    if not isinstance(number, int) or not (1 <= number <= (1 << 29) - 1):
        raise ConfigError(f"{where}: 非法 field number {number!r}")
    return number


def encode_field(number: int, wire: int, value: Any, *, zigzag: bool = False) -> bytes:
    """把一个 (field_number, wire_type, value) 编码成 protobuf 字节。"""
    number = _validate_field_number(number, "encode_field")
    tag = encode_varint((number << 3) | wire)
    if wire == WIRE_VARINT:
        if isinstance(value, bool):
            ivalue = int(value)
        elif isinstance(value, int):
            ivalue = zigzag_encode(value) if zigzag else value
        elif isinstance(value, str):
            ivalue = int(value, 0)
        else:
            raise WireError(f"field {number}: varint 需要整数，得到 {type(value).__name__}")
        return tag + encode_varint(ivalue)
    if wire == WIRE_FIXED64:
        if isinstance(value, float):
            return tag + struct.pack("<d", value)
        ivalue = int(value, 0) if isinstance(value, str) else int(value)
        return tag + struct.pack("<Q", ivalue & ((1 << 64) - 1))
    if wire == WIRE_FIXED32:
        if isinstance(value, float):
            return tag + struct.pack("<f", value)
        ivalue = int(value, 0) if isinstance(value, str) else int(value)
        return tag + struct.pack("<I", ivalue & ((1 << 32) - 1))
    if wire == WIRE_LEN:
        if isinstance(value, str):
            payload = value.encode("utf-8")
        elif isinstance(value, (bytes, bytearray)):
            payload = bytes(value)
        elif isinstance(value, (dict, list)):
            payload = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        else:
            raise WireError(f"field {number}: len 需要 str/bytes/dict/list，得到 {type(value).__name__}")
        return tag + encode_varint(len(payload)) + payload
    raise WireError(f"field {number}: 不支持的 wire type {wire}")


def decode_raw(buf: bytes) -> List[Dict[str, Any]]:
    """decode_raw 风格：返回 [{field, wire, value, hex, confidence_hint}, ...]。"""
    out: List[Dict[str, Any]] = []
    pos = 0
    while pos < len(buf):
        tag, pos = decode_varint(buf, pos)
        number, wire = tag >> 3, tag & 0x07
        if number == 0:
            raise WireError("遇到 field number 0")
        if wire == WIRE_VARINT:
            val, pos = decode_varint(buf, pos)
            out.append({"field": number, "wire": wire, "value": val, "hex": hex(val)})
        elif wire == WIRE_FIXED64:
            if pos + 8 > len(buf):
                raise WireError(f"field {number}: fixed64 截断")
            raw = buf[pos:pos + 8]
            pos += 8
            out.append({"field": number, "wire": wire,
                        "value": struct.unpack("<Q", raw)[0],
                        "double": struct.unpack("<d", raw)[0],
                        "hex": raw.hex()})
        elif wire == WIRE_LEN:
            size, pos = decode_varint(buf, pos)
            if pos + size > len(buf):
                raise WireError(f"field {number}: len={size} 超出缓冲区")
            raw = buf[pos:pos + size]
            pos += size
            rec: Dict[str, Any] = {"field": number, "wire": wire, "value": raw, "hex": raw.hex()}
            try:
                text = raw.decode("utf-8")
                if text and all(ch.isprintable() for ch in text):
                    rec["utf8"] = text
            except UnicodeDecodeError:
                pass
            # 嵌套消息启发式：尝试再解一层，失败则保留原始字节（不臆造结构）
            if size >= 2:
                try:
                    nested = decode_raw(raw)
                    if nested and all(1 <= r["field"] <= (1 << 29) - 1 for r in nested):
                        rec["nested"] = nested
                except Exception:
                    pass
            out.append(rec)
        elif wire == WIRE_FIXED32:
            if pos + 4 > len(buf):
                raise WireError(f"field {number}: fixed32 截断")
            raw = buf[pos:pos + 4]
            pos += 4
            out.append({"field": number, "wire": wire,
                        "value": struct.unpack("<I", raw)[0],
                        "float": struct.unpack("<f", raw)[0],
                        "hex": raw.hex()})
        else:
            raise WireError(
                f"field {number}: wire type {wire}（group/未知）在本原型中未实现；"
                f"原始剩余字节: {buf[pos:].hex()}"
            )
    return out


def print_decoded(records: List[Dict[str, Any]], indent: int = 0) -> None:
    pad = "  " * indent
    for rec in records:
        line = f"{pad}field {rec['field']:<5} wire={WIRE_NAME.get(rec['wire'], rec['wire']):<8}"
        if "value" in rec and isinstance(rec["value"], bytes):
            line += f" len={len(rec['value']):<5} hex={rec['hex'][:96]}"
            if "utf8" in rec:
                line += f' utf8="{rec["utf8"][:80]}"'
            print(line)
            if "nested" in rec:
                print(f"{pad}  └─ nested message (启发式解析，字段号可信度 low):")
                print_decoded(rec["nested"], indent + 2)
        else:
            line += f" value={rec.get('value')!r} hex={rec.get('hex')}"
            if "double" in rec:
                line += f" double={rec['double']}"
            if "float" in rec:
                line += f" float={rec['float']}"
            print(line)


# ---------------------------------------------------------------------------
# 2. 可插拔消息构造器
# ---------------------------------------------------------------------------

@dataclass
class FieldSpec:
    name: str
    number: Optional[int]
    wire: int
    value: Any = None
    confidence: str = "unknown"
    evidence: str = ""
    zigzag: bool = False

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "FieldSpec":
        wire = d.get("wire", WIRE_LEN)
        if isinstance(wire, str):
            wire = {"varint": 0, "fixed64": 1, "len": 2, "fixed32": 5}.get(wire.lower(), 2)
        return cls(
            name=str(d["name"]),
            number=d.get("number"),
            wire=int(wire),
            value=d.get("value"),
            confidence=d.get("confidence", "unknown"),
            evidence=d.get("evidence", ""),
            zigzag=bool(d.get("zigzag", False)),
        )


class MessageBuilder:
    """字段号来自配置；缺字段号时拒绝构造，避免'凭空生成合法请求'的错觉。"""

    def __init__(self, name: str, specs: List[FieldSpec], meta: Optional[Dict[str, Any]] = None):
        self.name = name
        self.specs = specs
        self.meta = meta or {}

    @classmethod
    def from_config(cls, config: Dict[str, Any], name: str) -> "MessageBuilder":
        msgs = config.get("messages", {})
        if name not in msgs:
            raise ConfigError(
                f"field_map.json 中没有消息 {name!r}；可用: {', '.join(msgs) or '(空)'}"
            )
        entry = msgs[name]
        return cls(name, [FieldSpec.from_dict(f) for f in entry.get("fields", [])],
                   {k: v for k, v in entry.items() if k != "fields"})

    def build(self, overrides: Optional[Dict[str, Any]] = None) -> Tuple[bytes, List[Dict[str, Any]]]:
        overrides = overrides or {}
        parts: List[bytes] = []
        report: List[Dict[str, Any]] = []
        for spec in self.specs:
            value = overrides.get(spec.name, spec.value)
            if value is None:
                continue  # 未设置的字段不编码（protobuf 默认行为）
            try:
                _validate_field_number(spec.number, f"{self.name}.{spec.name}")
            except ConfigError as exc:
                report.append({"field": spec.name, "status": "BLOCKED", "reason": str(exc),
                               "confidence": spec.confidence, "evidence": spec.evidence})
                continue
            if spec.wire not in (WIRE_VARINT, WIRE_FIXED64, WIRE_LEN, WIRE_FIXED32):
                raise WireError(f"{self.name}.{spec.name}: 不支持 wire={spec.wire}")
            parts.append(encode_field(spec.number, spec.wire, value, zigzag=spec.zigzag))
            report.append({"field": spec.name, "number": spec.number, "wire": WIRE_NAME[spec.wire],
                           "value": value, "status": "ENCODED", "confidence": spec.confidence,
                           "evidence": spec.evidence})
        return b"".join(parts), report

    def summary(self) -> str:
        lines = [f"消息 {self.name}  证据: {self.meta.get('evidence', 'N/A')}",
                 f"消息名可信度: {self.meta.get('confidence', 'unknown')}",
                 f"{'字段':<24}{'号':<8}{'wire':<10}{'可信度':<10}证据"]
        for s in self.specs:
            lines.append(f"{s.name:<24}{str(s.number):<8}{WIRE_NAME.get(s.wire, s.wire):<10}"
                         f"{s.confidence:<10}{s.evidence}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# 3. 帧编解码（完全由配置驱动）
# ---------------------------------------------------------------------------

def _resolve_source(source: str, ctx: Dict[str, Any]) -> Any:
    """支持 @body / session.key / config.key / literal:<value>。"""
    if source == "@body":
        return ctx.get("body", b"")
    if source.startswith("session."):
        key = source.split(".", 1)[1]
        val = ctx.get("session", {}).get(key)
        if val is None:
            raise ConfigError(
                f"会话参数 {key} 为空。该参数必须由真实客户端运行时提供"
                f"（抓包/Frida），见 capture.example.json 与 README.md。"
            )
        return val
    if source.startswith("config."):
        return ctx.get("config", {}).get(source.split(".", 1)[1])
    if source.startswith("literal:"):
        return source.split(":", 1)[1]
    raise ConfigError(f"未知 source 表达式 {source!r}")


def build_frame(body: bytes, frame_cfg: Dict[str, Any], session: Dict[str, Any],
                config: Dict[str, Any]) -> bytes:
    """
    frame_cfg["order"] 为元素列表，例如：
      {"id":"len", "kind":"length", "size":4, "endian":"little", "covers":"rest"}
      {"id":"cmd", "kind":"int", "size":4, "endian":"little", "source":"session.cmd_id"}
      {"id":"seq", "kind":"int", "size":4, "endian":"little", "source":"session.seq_id"}
      {"id":"body", "kind":"bytes", "source":"@body"}
    kind: int | bytes | length。length 元素在其余元素构造完后回填。
    """
    order = frame_cfg.get("order")
    if not order:
        raise ConfigError("配置缺少 frame.order")
    ctx = {"body": body, "session": session, "config": config}
    pieces: Dict[str, bytes] = {}
    for el in order:
        eid = el["id"]
        kind = el.get("kind", "bytes")
        if not el.get("enabled", True):
            pieces[eid] = b""
            continue
        if kind == "length":
            continue  # 第二遍处理
        if kind == "int":
            val = _resolve_source(el["source"], ctx)
            ivalue = int(val, 0) if isinstance(val, str) else int(val)
            size = int(el.get("size", 4))
            endian = "<" if el.get("endian", "little") == "little" else ">"
            fmt = {1: "B", 2: "H", 4: "I", 8: "Q"}.get(size)
            if not fmt:
                raise ConfigError(f"frame.{eid}: 不支持 int size={size}")
            pieces[eid] = struct.pack(endian + fmt, ivalue)
        elif kind == "bytes":
            val = _resolve_source(el["source"], ctx)
            if isinstance(val, str):
                val = bytes.fromhex(val.replace(" ", "")) if el.get("hex", False) else val.encode("utf-8")
            pieces[eid] = bytes(val)
        else:
            raise ConfigError(f"frame.{eid}: 未知 kind={kind!r}")

    for el in order:
        if el.get("kind") != "length" or not el.get("enabled", True):
            continue
        eid = el["id"]
        size = int(el.get("size", 4))
        endian = "<" if el.get("endian", "little") == "little" else ">"
        fmt = {1: "B", 2: "H", 4: "I", 8: "Q"}.get(size)
        if not fmt:
            raise ConfigError(f"frame.{eid}: 不支持 length size={size}")
        covers = el.get("covers", "rest")
        if covers == "rest":
            idx = order.index(el)
            covered = b"".join(pieces.get(x["id"], b"") for x in order[idx + 1:])
        elif covers in pieces:
            covered = pieces[covers]
        else:
            raise ConfigError(f"frame.{eid}: covers={covers!r} 无法解析")
        pieces[eid] = struct.pack(endian + fmt, len(covered))

    return b"".join(pieces.get(x["id"], b"") for x in order if x.get("enabled", True))


def recv_response(sock: socket.socket, cfg: Dict[str, Any]) -> bytes:
    rcfg = cfg.get("response", {})
    prefix_size = int(rcfg.get("length_prefix_size", 0))
    if prefix_size:
        header = b""
        while len(header) < prefix_size:
            chunk = sock.recv(prefix_size - len(header))
            if not chunk:
                break
            header += chunk
        if len(header) < prefix_size:
            raise WireError("响应长度前缀不完整")
        size = int.from_bytes(header, "little" if rcfg.get("endian", "little") == "little" else "big")
        size = min(size, int(rcfg.get("max_bytes", 16 * 1024 * 1024)))
        data = b""
        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk:
                break
            data += chunk
        return data
    sock.settimeout(float(rcfg.get("read_timeout", 2.0)))
    chunks: List[bytes] = []
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    except socket.timeout:
        pass
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# 4. 签名/会话外部注入
# ---------------------------------------------------------------------------

REQUIRED_SESSION_KEYS = ("cmd_id", "seq_id")


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def validate_session(session: Dict[str, Any], need_signature: bool) -> List[str]:
    warnings: List[str] = []
    for key in REQUIRED_SESSION_KEYS:
        if session.get(key) is None:
            warnings.append(f"session.{key} 为空 —— 必须由真实客户端抓包/Frida 提供")
    if need_signature and not session.get("signature_hex"):
        warnings.append("session.signature_hex 为空 —— 需要 TSS 签名，见 README")
    for key in ("seed_hex", "session_key_hex", "device_fingerprint", "uin"):
        if not session.get(key):
            warnings.append(f"session.{key} 未提供（仅提示；部分网关可能不强校验）")
    return warnings


def obtain_signature(body: bytes, session: Dict[str, Any], sig_cfg: Dict[str, Any],
                     script_path: Optional[str]) -> Optional[bytes]:
    """签名只从外部拿：file 模式读 capture；frida 模式调用 JS rpc.exports.sign。"""
    mode = sig_cfg.get("mode", "file")
    if mode == "file":
        hexsig = session.get("signature_hex")
        if not hexsig:
            return None
        return bytes.fromhex(str(hexsig).replace(" ", ""))
    if mode == "frida":
        if not script_path:
            raise ConfigError("signature.mode=frida 时必须提供 --frida-sign-script")
        try:
            import frida  # type: ignore
        except ImportError as exc:
            raise ConfigError(
                "未安装 frida Python 包（pip install frida）。也可改用 --signature-mode file 从抓包注入。"
            ) from exc
        target = sig_cfg.get("package_or_pid", "com.tencent.tmgp.dfm")
        device = frida.get_usb_device() if sig_cfg.get("usb", True) else frida.get_local_device()
        pid = device.attach(target)
        js = Path(script_path).read_text(encoding="utf-8")
        script = pid.create_script(js)
        script.load()
        try:
            result = script.exports_sync.sign(body.hex())
        except AttributeError:
            result = script.exports.sign(body.hex())
        pid.detach()
        if isinstance(result, str):
            return bytes.fromhex(result.replace(" ", ""))
        if isinstance(result, list):
            return bytes(result)
        raise ConfigError(f"Frida sign() 返回类型无法识别: {type(result).__name__}")
    raise ConfigError(f"未知 signature.mode={mode!r}")


# ---------------------------------------------------------------------------
# 5. CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="UE4 私有网关 CS 消息原型探针（字段号/会话/签名全部外部注入）"
    )
    parser.add_argument("--config", default="field_map.example.json", help="字段映射配置")
    parser.add_argument("--capture", default="capture.example.json", help="会话/签名抓包注入文件")
    parser.add_argument("--message", default="CSMallBuyReq",
                        help="要构造的消息名（CSMallBuyReq / CSGetCurrencyReq ...）")
    parser.add_argument("--set", action="append", default=[], metavar="NAME=VALUE",
                        help="覆盖字段值，可重复，例如 --set goods_id=12345 --set buy_num=1")
    parser.add_argument("--mode", choices=["build", "send", "decode"], default="build",
                        help="build=只打印不联网；send=发包收包；decode=离线解码")
    parser.add_argument("--raw-hex", help="decode 模式：protobuf 十六进制串")
    parser.add_argument("--raw-file", help="decode 模式：protobuf 二进制文件路径")
    parser.add_argument("--frida-sign-script", help="frida 签名 JS（需导出 rpc.exports.sign）")
    parser.add_argument("--signature-mode", choices=["file", "frida"], help="覆盖配置中的签名模式")
    parser.add_argument("--timeout", type=float, default=5.0, help="连接超时秒")
    parser.add_argument("--summary", action="store_true", help="打印消息/字段证据表后退出")
    args = parser.parse_args(argv)

    cfg = load_json(args.config)
    if args.summary:
        for name in cfg.get("messages", {}):
            print(MessageBuilder.from_config(cfg, name).summary())
            print("-" * 78)
        return 0

    if args.mode == "decode":
        if args.raw_hex:
            raw = bytes.fromhex(args.raw_hex.replace(" ", ""))
        elif args.raw_file:
            raw = Path(args.raw_file).read_bytes()
        else:
            parser.error("decode 模式需要 --raw-hex 或 --raw-file")
        print(f"[decode_raw] {len(raw)} bytes")
        print_decoded(decode_raw(raw))
        return 0

    builder = MessageBuilder.from_config(cfg, args.message)
    overrides: Dict[str, Any] = {}
    for item in args.set:
        if "=" not in item:
            parser.error(f"--set 需要 NAME=VALUE 形式: {item!r}")
        k, v = item.split("=", 1)
        overrides[k] = v

    body, report = builder.build(overrides)
    print(f"[build] message={args.message} body_len={len(body)}")
    print(f"[build] body_hex={body.hex() or '(empty)'}")
    print("[build] 字段编码报告:")
    for rec in report:
        if rec["status"] == "BLOCKED":
            print(f"  BLOCKED {rec['field']}: {rec['reason']}")
        else:
            print(f"  {rec['status']:7} {rec['field']} -> field {rec['number']} "
                  f"wire={rec['wire']} value={rec['value']!r} conf={rec['confidence']}")
    unresolved = [r for r in report if r["status"] == "BLOCKED"]
    if unresolved:
        print(f"[build] 有 {len(unresolved)} 个字段无字段号；帧仍可构造用于离线测试，但"
              f"绝不代表合法请求。")

    session = load_json(args.capture)
    sig_cfg = dict(cfg.get("signature", {}))
    if args.signature_mode:
        sig_cfg["mode"] = args.signature_mode
    frame_cfg = cfg.get("frame", {})
    signature_enabled = any(
        el.get("id") == "signature" and el.get("enabled", True) for el in frame_cfg.get("order", [])
    )
    warnings = validate_session(session, need_signature=signature_enabled and sig_cfg.get("mode") == "file")
    for w in warnings:
        print(f"[session WARN] {w}")

    if signature_enabled:
        sig = obtain_signature(body, session, sig_cfg, args.frida_sign_script)
        if sig:
            session["signature_hex"] = sig.hex()
            print(f"[signature] 注入 {len(sig)} 字节签名（来源: {sig_cfg.get('mode')}）")
        else:
            print("[signature WARN] 未获得签名；帧中签名字段为空")

    # 离线 dry-run / 占位预览：即使 session 为空也要能构造帧用于检查格式。
    # send 模式在真正 socket 连接前有严格校验（return 2），不存在误发风险。
    session_for_frame = dict(session)
    for _k in REQUIRED_SESSION_KEYS:
        if session_for_frame.get(_k) is None:
            session_for_frame[_k] = 0  # 仅供占位预览
    if session_for_frame.get("signature_hex") is None:
        session_for_frame["signature_hex"] = ""

    frame = build_frame(body, frame_cfg, session_for_frame, cfg)
    print(f"[frame] len={len(frame)} hex={frame.hex()[:256]}{'...' if len(frame) > 128 else ''}")

    if args.mode == "build":
        print("[build] dry-run 完成，未联网。")
        return 0

    host = cfg.get("gateway", {}).get("host")
    port = cfg.get("gateway", {}).get("port")
    if not host or not port or str(host).startswith("<") or int(port) == 0:
        print("[send] 网关 host/port 未填（占位符）。请先从抓包填入真实值；本原型拒绝臆造地址。")
        return 2
    if warnings:
        print("[send] 会话参数不完整，拒绝发送。请先补齐 capture.json / Frida 注入。")
        return 2

    print(f"[send] connecting {host}:{port}")
    with socket.create_connection((host, int(port)), timeout=args.timeout) as sock:
        sock.sendall(frame)
        raw = recv_response(sock, cfg)
    print(f"[recv] {len(raw)} bytes; hex={raw.hex()[:256]}")
    if raw:
        try:
            print("[recv] decode_raw:")
            print_decoded(decode_raw(raw))
        except WireError as exc:
            print(f"[recv] decode_raw 失败: {exc}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ConfigError, WireError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
