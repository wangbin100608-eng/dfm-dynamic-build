#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
validate_capture.py — 阶段3发包前"就绪检查"（本机离线，不联网、不发包）。

读取 capture.json + field_map.json，检查发包所需参数是否齐备：
  - capture 业务值:  cmd_id / seq_id / signature 来源 / device_fingerprint / uin
                     （seed_hex / session_key_hex 为按需项，单独标注）
  - field_map:       gateway.host / gateway.port / 帧内 cmd/seq 引用 /
                     各消息 fields[].number（字段号）/ 签名模式与脚本对齐

每一项输出 READY / MISSING / WARN(按需) 与"下一步动作"。
  - 任一必需项 MISSING -> exit != 0（默认 2），并汇总缺失清单。
  - 全部齐备           -> exit 0，并打印将使用的参数摘要。

安全约束：
  - 绝不打印签名字节全文；只打印签名"来源/长度/是否已设置"。
  - 不建立任何 socket 连接；不修改任何输入文件。
  - 对占位值（DRYRUN / <PLACEHOLDER> / null）一律判 MISSING，防止占位样例被误判为可发包。

用法:
  python3 validate_capture.py \
      --capture capture.json --config field_map.json [--message CSMallBuyReq]

  # 干跑自检（把占位样例当作"允许占位"来校验脚本自身的 exit=0 分支）：
  python3 validate_capture.py \
      --capture capture.dryrun.example.json --config field_map.example.json --allow-dryrun
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

# 这些值即使填了也视为"占位"，不能进入真实发包判定。
PLACEHOLDER_TOKENS = (
    "dryrun", "dry_run", "placeholder", "todo", "fillme", "tbd", "xxx", "changeme",
)
PLACEHOLDER_HOST_RE = re.compile(r"^<.*>$")

# 必需的业务值（没有它们 probe_gateway.py --mode send 会 exit=2 或产生无效请求）。
REQUIRED_CAPTURE_FIELDS = ("cmd_id", "seq_id", "device_fingerprint", "uin")
# 按需项：缺失只 WARN，不阻断（部分网关不强校验）。
OPTIONAL_CAPTURE_FIELDS = ("seed_hex", "session_key_hex")

READY = "READY"
MISSING = "MISSING"
WARN = "WARN"

EXIT_OK = 0
EXIT_MISSING = 2
EXIT_ERROR = 1


def _is_placeholder(value: Any) -> bool:
    """识别常见的占位/哨兵值（大小写不敏感）。"""
    if value is None:
        return True
    if isinstance(value, bool):
        return False  # True/False 是真实布尔值
    if isinstance(value, (int, float)):
        return value == 0
    text = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    if not text or text == "null" or text == "none":
        return True
    if PLACEHOLDER_HOST_RE.match(text):
        return True
    return any(tok in text for tok in PLACEHOLDER_TOKENS)


def _has_real_value(value: Any) -> bool:
    return not _is_placeholder(value)


def _load_json(path: str) -> Dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"文件不存在: {p}")
    with p.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"顶层必须是 JSON 对象: {p}")
    return data


def _source_of(cfg: Dict[str, Any], key: str) -> str:
    """返回 <key>_source，缺省视为 unknown。"""
    return str(cfg.get(key + "_source", "unknown"))


def _signature_status(capture: Dict[str, Any], cfg: Dict[str, Any],
                      allow_dryrun: bool) -> Tuple[str, str, str]:
    """判定签名来源是否就绪。返回 (status, detail, next_action)。"""
    sig_cfg = cfg.get("signature", {}) or {}
    mode = str(sig_cfg.get("mode", "file"))
    hexsig = capture.get("signature_hex")
    source = _source_of(capture, "signature_hex")

    # frida 模式：签名由 rpc.exports.sign 现算，capture 里不需要静态签名字节。
    if mode == "frida":
        if source == "frida_rpc" or _has_real_value(hexsig):
            return (READY, f"mode=frida, 来源={source}（现算，不落盘静态字节）",
                    "确认 sign_rpc.js 的 rpc.exports.sign 已 hook 真机 TSS/RSA_sign，"
                    "并用 --signature-mode frida --frida-sign-script 指向它。")
        return (MISSING, f"mode=frida 但 signature_hex_source={source!r}",
                "把 sign_rpc.js 挂到真机 TSS/RSA_sign，确认可返回签名字节；"
                "再用 --signature-mode frida 调用，禁止从 so 静态复刻。")

    # file 模式：必须有来自真实运行时的签名字节。
    if not _has_real_value(hexsig):
        if allow_dryrun and _is_placeholder(hexsig) and source == "capture_runtime":
            return (READY, "DRYRUN: mode=file, signature_hex 为占位（--allow-dryrun 放行）",
                    "真实发包前必须用真机 TSS 抓包替换；禁止用此占位值发包。")
        return (MISSING, f"mode=file 但 signature_hex 为空/占位，来源={source!r}",
                "从真机 TSS SDK（SendTssData/TssSDKOnRecvSignature）抓签名字节填入 capture.json；"
                "或改用 --signature-mode frida 现算。")
    # 签名有值：不打印全文，只给长度与来源。
    try:
        nbytes = len(str(hexsig).replace(" ", "")) // 2
    except Exception:
        nbytes = -1
    return (READY, f"mode=file, 来源={source}, 长度≈{nbytes} 字节（内容已隐去）",
            "确认该签名来自本次会话的真实请求，且帧内签名位置/长度已按 dump_traffic.js 校准。")


def _check_gateway(cfg: Dict[str, Any], allow_dryrun: bool) -> List[Tuple[str, str, str, str]]:
    """返回 [(item, status, detail, next_action), ...]。"""
    gw = cfg.get("gateway", {}) or {}
    host, port = gw.get("host"), gw.get("port")
    out: List[Tuple[str, str, str, str]] = []
    if _has_real_value(host) and not PLACEHOLDER_HOST_RE.match(str(host)):
        out.append(("gateway.host", READY, f"host={host}",
                    "确认该 host 来自真机抓包（tcpdump/connect hook），非 so 内联内网字面量。"))
    elif allow_dryrun and _is_placeholder(host):
        out.append(("gateway.host", READY, f"DRYRUN: host 为占位 {host!r}（--allow-dryrun 放行）",
                    "真实发包前必须用抓包得到的真实网关地址替换。"))
    else:
        out.append(("gateway.host", MISSING, f"host={host!r} 未填或为占位",
                    "用 tcpdump 抓包 / Frida hook connect() 取得真实网关 host，填入 field_map.json。"))

    if isinstance(port, int) and 0 < port < 65536:
        out.append(("gateway.port", READY, f"port={port}",
                    "确认端口与抓包一致（注意 TLS 与非 TLS 端口区别）。"))
    elif allow_dryrun and _is_placeholder(port):
        out.append(("gateway.port", READY, f"DRYRUN: port 为占位 {port!r}（--allow-dryrun 放行）",
                    "真实发包前必须用抓包得到的真实端口替换。"))
    else:
        out.append(("gateway.port", MISSING, f"port={port!r} 未填/非法",
                    "从抓包取得真实端口填入 field_map.json；so 内联 10.32.75.192:9093 是内网字面量，禁止使用。"))
    return out


def _check_frame_refs(cfg: Dict[str, Any]) -> List[Tuple[str, str, str, str]]:
    """检查 frame.order 中的 cmd/seq source 是否指向 session 里的捕获值。"""
    out: List[Tuple[str, str, str, str]] = []
    order = (cfg.get("frame", {}) or {}).get("order", []) or []
    cmd_ok = any(el.get("source") == "session.cmd_id" and el.get("enabled", True)
                 for el in order if isinstance(el, dict))
    seq_ok = any(el.get("source") == "session.seq_id" and el.get("enabled", True)
                 for el in order if isinstance(el, dict))
    out.append(("frame.cmd_ref",
                READY if cmd_ok else MISSING,
                "frame.order 含 session.cmd_id" if cmd_ok else "frame.order 未引用 session.cmd_id",
                "用 dump_traffic.js 校准帧布局后，确保 cmd 元素 source=session.cmd_id。" if not cmd_ok else "无需操作。"))
    out.append(("frame.seq_ref",
                READY if seq_ok else MISSING,
                "frame.order 含 session.seq_id" if seq_ok else "frame.order 未引用 session.seq_id",
                "用 dump_traffic.js 校准帧布局后，确保 seq 元素 source=session.seq_id。" if not seq_ok else "无需操作。"))
    return out


def _check_field_numbers(cfg: Dict[str, Any], message: Optional[str]) -> List[Tuple[str, str, str, str]]:
    """检查目标消息（或全部消息）的 field number 是否已从 descriptor 导出。"""
    out: List[Tuple[str, str, str, str]] = []
    msgs = cfg.get("messages", {}) or {}
    if message:
        if message not in msgs:
            out.append((f"message:{message}", MISSING,
                        f"field_map.json 中无此消息；可用: {', '.join(msgs) or '(空)'}",
                        "确认 --message 名称与 field_map.json 的 messages 键一致。"))
            return out
        targets = {message: msgs[message]}
    else:
        targets = msgs
    if not targets:
        out.append(("messages", MISSING, "field_map.json 无任何消息定义",
                    "从 find_descriptor.js 导出 descriptor 后填入 messages。"))
        return out
    for name, entry in targets.items():
        fields = (entry or {}).get("fields", []) or []
        missing = [f.get("name", "?") for f in fields
                   if isinstance(f, dict) and f.get("number") is None]
        if missing:
            out.append((f"fields:{name}", MISSING,
                        f"{len(missing)}/{len(fields)} 个字段号未填: {', '.join(missing)}",
                        "真机跑 find_descriptor.js，rpc.exports.dump('*.proto') 导出字段号后填入 field_map.json；禁止猜测。"))
        else:
            out.append((f"fields:{name}", READY, f"{len(fields)} 个字段号齐备",
                        "确认字段号来自 DescriptorPool 导出而非 medium 推断。"))
    return out


def _check_signature_script(cfg: Dict[str, Any], script: Optional[str],
                            allow_dryrun: bool) -> List[Tuple[str, str, str, str]]:
    """frida 签名模式下检查 --frida-sign-script 是否存在。"""
    out: List[Tuple[str, str, str, str]] = []
    mode = str((cfg.get("signature", {}) or {}).get("mode", "file"))
    if mode != "frida":
        return out
    if script and Path(script).is_file():
        text = Path(script).read_text(encoding="utf-8", errors="replace")
        has_rpc = "rpc.exports" in text and "sign" in text
        out.append(("frida.sign_script",
                    READY if has_rpc else MISSING,
                    f"{script} 存在；rpc.exports.sign {'已声明' if has_rpc else '未找到'}",
                    "在 sign_rpc.js 中实现 rpc.exports.sign(payloadHex) 并 hook 真机签名函数。" if not has_rpc else "无需操作。"))
    elif allow_dryrun:
        out.append(("frida.sign_script", READY, "DRYRUN: 未指定签名脚本（--allow-dryrun 放行）",
                    "真实发包前必须提供含 rpc.exports.sign 的脚本。"))
    else:
        out.append(("frida.sign_script", MISSING,
                    f"mode=frida 但 --frida-sign-script 未提供/文件不存在: {script!r}",
                    "用 --frida-sign-script sign_rpc.js 指向真机签名脚本。"))
    return out


def build_report(capture: Dict[str, Any], cfg: Dict[str, Any], message: Optional[str],
                 sign_script: Optional[str], allow_dryrun: bool) -> Tuple[List[Tuple[str, str, str, str]], bool]:
    """返回 ([(item,status,detail,next_action)], is_dryrun)。"""
    checks: List[Tuple[str, str, str, str]] = []
    # 文件内的 _dryrun 标记或 CLI 开关都会启用"占位放行"自检分支。
    effective_dryrun = bool(allow_dryrun or capture.get("_dryrun") or cfg.get("_dryrun"))
    is_dryrun = effective_dryrun

    # 1) capture 业务值
    for key in REQUIRED_CAPTURE_FIELDS:
        val = capture.get(key)
        if _has_real_value(val) and not effective_dryrun:
            src = _source_of(capture, key)
            checks.append((f"capture.{key}", READY,
                           f"已填（来源={src}）" + ("" if key in ("device_fingerprint", "uin") else f" 值={val}"),
                           "确认来自本次会话真机运行时，非臆造。"))
        elif effective_dryrun and _is_placeholder(val):
            checks.append((f"capture.{key}", READY,
                           f"DRYRUN: 占位值 {val!r}（_dryrun/--allow-dryrun 放行）",
                           "真实发包前必须用真机抓包值替换；禁止用占位发包。"))
        elif _has_real_value(val):
            # 非 dryrun 但填了真实值
            src = _source_of(capture, key)
            checks.append((f"capture.{key}", READY,
                           f"已填（来源={src}）" + ("" if key in ("device_fingerprint", "uin") else f" 值={val}"),
                           "确认来自本次会话真机运行时，非臆造。"))
        else:
            checks.append((f"capture.{key}", MISSING,
                           f"值为 {val!r}，来源={_source_of(capture, key)!r}",
                           {
                               "cmd_id": "hook 请求构造点 / dump_traffic.js 帧级 dump 取 cmd_id。",
                               "seq_id": "同上，通常递增；确认与响应配对。",
                               "device_fingerprint": "真机 Frida dump qimei/oaid 等设备指纹字段。",
                               "uin": "从真机登录态取游戏账号 uid。",
                           }[key]))

    # 2) 签名来源
    sig_status, sig_detail, sig_action = _signature_status(capture, cfg, effective_dryrun)
    checks.append(("capture.signature_source", sig_status, sig_detail, sig_action))

    # 3) 按需项（WARN，不阻断）
    for key in OPTIONAL_CAPTURE_FIELDS:
        val = capture.get(key)
        if _has_real_value(val):
            checks.append((f"capture.{key}(可选)", READY, "已填",
                           "确认来源与会话一致。"))
        else:
            checks.append((f"capture.{key}(可选)", WARN,
                           f"未填（来源={_source_of(capture, key)!r}）",
                           "若网关在 TLS 内二次加密或校验会话种子，需从 Frida dump 补齐。"))

    # 4) 网关
    checks.extend(_check_gateway(cfg, effective_dryrun))
    # 5) 帧内 cmd/seq 引用
    checks.extend(_check_frame_refs(cfg))
    # 6) 字段号
    checks.extend(_check_field_numbers(cfg, message))
    # 7) frida 签名脚本
    checks.extend(_check_signature_script(cfg, sign_script, effective_dryrun))

    return checks, is_dryrun


def print_report(checks: List[Tuple[str, str, str, str]], is_dryrun: bool,
                 capture: Dict[str, Any], cfg: Dict[str, Any], message: Optional[str],
                 sign_script: Optional[str]) -> int:
    print("=" * 72)
    print("阶段3 发包就绪校验 (validate_capture.py) — 本机离线，不联网不发包")
    print("=" * 72)
    if is_dryrun:
        print("[DRYRUN] 占位样例/--allow-dryrun 已启用：READY 仅表示脚本自检通过，禁止真实发包！")
    for item, status, detail, action in checks:
        print(f"[{status:>7}] {item}: {detail}")
        if status != READY:
            print(f"         下一步: {action}")
    print("-" * 72)

    missing = [item for item, st, _, _ in checks if st == MISSING]
    if missing:
        print(f"结论: NOT READY — {len(missing)} 项缺失: {', '.join(missing)}")
        print("补齐后重新运行本脚本；exit=2。")
        return EXIT_MISSING

    # 参数摘要（不含签名字节全文）
    gw = cfg.get("gateway", {}) or {}
    mode = str((cfg.get("signature", {}) or {}).get("mode", "file"))
    print("结论: READY — 所有必需项齐备。参数摘要如下（签名字节已隐去）:")
    print(f"  gateway    : {gw.get('host')}:{gw.get('port')}")
    print(f"  message    : {message or '(未指定 --message；字段号按全部消息检查)'}")
    print(f"  cmd_id     : {capture.get('cmd_id')}")
    print(f"  seq_id     : {capture.get('seq_id')}")
    print(f"  uin        : {capture.get('uin')}")
    print(f"  fingerprint: {str(capture.get('device_fingerprint'))[:64]}")
    print(f"  signature  : 来源={_source_of(capture, 'signature_hex')}, mode={mode}"
          + ("（frida 现算，不落盘）" if mode == "frida" else "（字节内容已隐去）"))
    print(f"  sign script: {sign_script or '(未指定)'}")
    print("发包命令（手动执行，本脚本不执行）:")
    print("  python3 probe_gateway.py --config <field_map.json> --capture <capture.json> \\")
    print("    --message <MSG> --set <k=v> --mode send \\")
    print("    --signature-mode %s [--frida-sign-script %s]" %
          (mode, sign_script or "<sign_rpc.js>"))
    print("exit=0")
    return EXIT_OK


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="阶段3发包前就绪校验：检查 capture.json + field_map.json，缺参 exit≠0"
    )
    parser.add_argument("--capture", default="capture.json", help="会话/签名抓包注入文件")
    parser.add_argument("--config", default="field_map.json", help="字段映射配置")
    parser.add_argument("--message", default=None,
                        help="目标消息名；指定后只检查该消息字段号，缺省检查全部")
    parser.add_argument("--frida-sign-script", default=None,
                        help="frida 签名脚本路径（frida 模式下检查）")
    parser.add_argument("--allow-dryrun", action="store_true",
                        help="自检用：允许占位样例通过 exit=0 分支（禁止用于真实发包）")
    args = parser.parse_args(argv)

    try:
        capture = _load_json(args.capture)
        cfg = _load_json(args.config)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: 读取配置失败: {exc}", file=sys.stderr)
        return EXIT_ERROR

    checks, is_dryrun = build_report(
        capture, cfg, args.message, args.frida_sign_script, args.allow_dryrun
    )
    return print_report(checks, is_dryrun, capture, cfg, args.message, args.frida_sign_script)


if __name__ == "__main__":
    sys.exit(main())
