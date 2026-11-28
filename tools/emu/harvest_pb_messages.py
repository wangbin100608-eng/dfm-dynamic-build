#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
harvest_pb_messages.py — 阶段2：从 libUE4.so 全量挖掘 protobuf 消息名与购买/货币/价格字段。

方法（全部离线，不发包、不改目标）：
  1) mmap 全文件，正则提取 `pb.<Message>` / `pb.<Message>.<field>` 形式的 ASCII NUL 终止字符串，
     记录精确文件偏移（= so 内字符串地址，因首段 vaddr≈offset）。
  2) 关键词过滤购买/货币/价格/交易/弹药/订单相关消息；保留全部 pb.CS* 作为字典。
  3) 在每个命中消息名的 ±RADIUS 字节窗口内提取 snake_case 标识符（字段名候选），
     标注为 "邻近字符串池"（medium/low 可信度，不臆造字段号）。
  4) 与 XOR 0x10 解码结果交叉验证：若明文存在则来源标 "so-明文(ASCII)"，
     若仅 XOR 解码命中则标 "XOR-0x10-decode"。

结论边界：本脚本只输出"字符串存在性 + 偏移 + 归属候选"，
不输出字段号。字段号仍需运行时 FileDescriptorProto 导出。
"""
from __future__ import annotations

import argparse
import json
import mmap
import re
import collections
import sys

PB_RE = re.compile(rb"pb\.[A-Za-z][A-Za-z0-9_]{1,79}(?:\.[A-Za-z_][A-Za-z0-9_]{1,63})?")
FIELD_RE = re.compile(rb"(?<![A-Za-z0-9_])[a-z][a-z0-9_]{2,47}(?![A-Za-z0-9_])")
BUY_KEYS = (
    "buy", "mall", "currency", "price", "trade", "market", "bullet", "ammo",
    "order", "limit", "goods", "sell", "exchange", "purchase", "pay", "ticket",
    "shop", "store", "cost", "credit", "fund", "wallet", "coupon",
)
RADIUS = 0x1000


def xor10(buf: bytes) -> bytes:
    return bytes(b ^ 0x10 for b in buf)


def main() -> int:
    ap = argparse.ArgumentParser(description="挖掘 libUE4.so 中的 protobuf 消息与字段字符串")
    ap.add_argument("--so", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--fields-out", help="字段候选 JSON 输出")
    ap.add_argument("--radius", type=int, default=RADIUS)
    a = ap.parse_args()

    data = open(a.so, "rb").read()
    n = len(data)
    # 明文扫描
    plain = {}
    for m in PB_RE.finditer(data):
        s = m.group().decode("ascii", "ignore")
        plain.setdefault(s, []).append(m.start())
    # XOR 0x10 解码扫描（对整块做一次异或代价 ~0.5s，内存足够）
    enc = xor10(data)
    dec = {}
    for m in PB_RE.finditer(enc):
        s = m.group().decode("ascii", "ignore")
        dec.setdefault(s, []).append(m.start())

    all_names = sorted(set(plain) | set(dec))
    messages = []
    for name in all_names:
        offs = plain.get(name, [])
        doffs = dec.get(name, [])
        source = "so-明文(ASCII)" if offs else "XOR-0x10-decode"
        is_buy = any(k in name.lower() for k in BUY_KEYS)
        # 当前样本结论：关键 pb.* 消息名只在 XOR-0x10 解码池命中（明文池 0 条）。
        # 明文命中 = high；仅 XOR 解码 = medium（已验证字节级 XOR 可逆）；
        # 带 .field 后缀的条目 = medium（归属是名称拼接推断）。
        conf = "high" if offs else ("medium" if "." not in name[3:] else "low")
        messages.append({
            "name": name,
            "offsets": ["0x%x" % o for o in offs[:8]],
            "xor_offsets": ["0x%x" % o for o in doffs[:8]],
            "source": source,
            "confidence": conf,
            "buy_related": is_buy,
        })

    # 字段候选：XOR 解码后的字符串池里也在消息名附近共现 snake_case 标识符。
    # 注意：这些是"邻近字符串池候选"，没有 wire 证据，不赋字段号。
    field_hits = collections.defaultdict(lambda: {"count": 0, "offsets": [], "near": []})
    for rec in messages:
        if not rec["buy_related"]:
            continue
        o = int((rec["xor_offsets"] or rec["offsets"])[0], 16)
        lo = max(0, o - a.radius)
        hi = min(n, o + a.radius)
        win = enc[lo:hi]
        seen = set()
        for fm in FIELD_RE.finditer(win):
            s = fm.group().decode("ascii")
            if s in seen:
                continue
            seen.add(s)
            if s not in field_hits:
                field_hits[s] = {"count": 0, "offsets": [], "near": []}
            fh = field_hits[s]
            fh["count"] += 1
            if len(fh["offsets"]) < 5:
                fh["offsets"].append("0x%x" % (lo + fm.start()))
            if len(fh["near"]) < 5:
                fh["near"].append(rec["name"])

    payload = {
        "_meta": {
            "so": a.so,
            "size": n,
            "method": "mmap ASCII regex pb.<Name>[.<field>] + XOR-0x10 cross-check; field candidates from +/-0x%x window" % a.radius,
            "note": "本脚本只给字符串存在性与偏移；字段号仍须运行时 DescriptorPool 导出。",
        },
        "messages": messages,
        "buy_related_count": sum(1 for r in messages if r["buy_related"]),
    }
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)

    fpayload = {
        "_meta": {"note": "邻近字符串池字段候选，非字段号证据；confidence=low/medium"},
        "fields": [
            {"name": k, "count": v["count"], "offsets": v["offsets"], "near_messages": v["near"],
             "confidence": "medium" if v["count"] >= 2 else "low",
             "source": "near-message-string-pool"}
            for k, v in sorted(field_hits.items(), key=lambda kv: (-kv[1]["count"], kv[0]))
        ],
    }
    if a.fields_out:
        with open(a.fields_out, "w", encoding="utf-8") as fh:
            json.dump(fpayload, fh, ensure_ascii=False, indent=2)

    print("[+] pb-like strings: %d (buy-related: %d)" % (len(messages), payload["buy_related_count"]))
    for r in messages:
        if r["buy_related"]:
            print("  %-70s %-16s %s %s" % (r["name"], r["offsets"][0] if r["offsets"] else r["xor_offsets"][0], r["source"], r["confidence"]))
    print("[+] field candidates: %d" % len(field_hits))
    return 0


if __name__ == "__main__":
    sys.exit(main())
