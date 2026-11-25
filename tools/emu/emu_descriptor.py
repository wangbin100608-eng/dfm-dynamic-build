#!/usr/bin/env python3
"""
emu_descriptor.py — 无设备动态提取 protobuf 消息的字段号（字段号→字段名→类型）。

原理：
  静态逆向已知 libUE4.so 里有 CS 消息名（pb.CSMallBuyReq 等）与字段名字符串，
  但缺序列化 FileDescriptorProto（字段号映射）。本脚本用两条路互补：

  路径 A（descriptor blob 扫描 + 模拟解析）：
    在 so 里扫描符合 protobuf wire 格式的 descriptor blob（含消息名 + 字段名 + field number），
    用自实现的 wire parser 解析；若发现可疑 blob，可用 Unicorn 模拟 so 内解析函数验证。

  路径 B（ReadTag 动态模拟）：
    若 so 里有 CodedInputStream::ReadTag 导出符号（或静态给出偏移），
    用 Unicorn 模拟执行，喂入目标消息序列化样本，记录运行时读到的 field number 序列。

  路径 A 纯 Python 可跑，路径 B 需要 so + Unicorn。两者输出统一为字段号表，
  可直接填入 probe/field_map.json 的 messages.<msg>.fields[].number。

用法:
  python3 emu_descriptor.py --so libUE4.so --scan             # 路径A：扫描 descriptor blob
  python3 emu_descriptor.py --so libUE4.so --msg CSMallBuyReq # 针对特定消息扫描
  python3 emu_descriptor.py --so libUE4.so --readtag-off 0x... --sample-hex 0801...  # 路径B
"""
import argparse
import json
import re
import struct
import sys

from elf_util import ELFMapper


# ---------- protobuf wire 基础 ----------
def read_varint(buf, pos):
    v = 0
    shift = 0
    while pos < len(buf) and shift < 64:
        b = buf[pos]
        pos += 1
        v |= (b & 0x7f) << shift
        if not (b & 0x80):
            return v, pos
        shift += 7
    return None, pos


def parse_fields(buf, limit=100000):
    """把一段 bytes 当 protobuf 消息解析为 [(field_no, wire_type, value)]"""
    out = []
    pos = 0
    while pos < len(buf) and len(out) < limit:
        key, pos2 = read_varint(buf, pos)
        if key is None or key == 0:
            break
        field_no, wire = key >> 3, key & 7
        if field_no == 0:
            break
        pos = pos2
        if wire == 0:
            val, pos = read_varint(buf, pos)
        elif wire == 1:
            val = buf[pos:pos+8]; pos += 8
        elif wire == 2:
            ln, pos = read_varint(buf, pos)
            if ln is None or ln > len(buf) - pos or ln < 0:
                break
            val = buf[pos:pos+ln]; pos += ln
        elif wire == 5:
            val = buf[pos:pos+4]; pos += 4
        else:
            break
        out.append((field_no, wire, val))
    return out


# descriptor.proto 里的关键 field number:
# FileDescriptorProto: name=1, package=2, message_type=4
# DescriptorProto: name=1, field=2
# FieldDescriptorProto: name=1, number=3, label=4, type=5
FDP_NAME, FDP_NUMBER, FDP_LABEL, FDP_TYPE = 1, 3, 4, 5
DP_NAME, DP_FIELD = 1, 2
FILE_NAME, FILE_MSG = 1, 4


def is_printable(s):
    try:
        t = s.decode("utf-8")
    except Exception:
        return False
    return all(c.isalnum() or c in "._-" for c in t) and len(t) >= 2


def try_descriptor_blob(blob):
    """尝试把 blob 当 FileDescriptorProto 解析，返回 [(msg, [(name,number,type)])]"""
    try:
        top = parse_fields(blob)
    except Exception:
        return []
    results = []
    for fno, wire, val in top:
        if fno != FILE_MSG or wire != 2:
            continue
        msg_fields = parse_fields(val)
        msg_name = None
        fds = []
        for mfno, mwire, mval in msg_fields:
            if mfno == DP_NAME and mwire == 2 and is_printable(mval):
                msg_name = mval.decode("utf-8")
            elif mfno == DP_FIELD and mwire == 2:
                fd = parse_fields(mval)
                fmap = {}
                for ffno, fwire, fval in fd:
                    if ffno == FDP_NAME and fwire == 2 and is_printable(fval):
                        fmap["name"] = fval.decode("utf-8")
                    elif ffno == FDP_NUMBER and fwire == 0:
                        fmap["number"] = fval
                    elif ffno == FDP_TYPE and fwire == 0:
                        fmap["type"] = fval
                if "name" in fmap and "number" in fmap:
                    fds.append((fmap["name"], fmap["number"], fmap.get("type")))
        if msg_name and fds:
            results.append((msg_name, fds))
    return results


def scan_blobs(data, pattern, max_hits=50):
    """在 so 字节里找消息名附近的可疑 descriptor blob"""
    hits = []
    for m in re.finditer(re.escape(pattern), data):
        pos = m.start()
        # 从名字前 8KB / 后 8KB 里尝试各种起点解析
        lo = max(0, pos - 8192)
        hi = min(len(data), pos + 8192)
        region = data[lo:hi]
        found = []
        for delta in range(0, min(len(region), 4096)):
            blob = region[delta:]
            res = try_descriptor_blob(blob)
            if res:
                found = res
                break
        if found:
            hits.append((pos, found))
            if len(hits) >= max_hits:
                break
    return hits


# ---------- 路径 B：Unicorn 模拟 ReadTag ----------
def simulate_readtag(so_path, offset, sample_hex, base=0x100000000, steps=200):
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UcError
    from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_SP
    mapper = ELFMapper(so_path, base=base)
    uc = mapper.create_uc()
    start = mapper.va(offset)
    sample = bytes.fromhex(sample_hex.replace(" ", ""))
    # 把样本写到栈，x0=样本地址
    buf_va = mapper.stack_base - 0x1000
    uc.mem_write(buf_va, sample)
    uc.reg_write(UC_ARM64_REG_X0, buf_va)
    uc.reg_write(UC_ARM64_REG_SP, mapper.stack_base - 0x8000)
    tags = []
    seen_x0 = []
    def hook(uc2, addr, size, user):
        seen_x0.append(uc2.reg_read(UC_ARM64_REG_X0))
        if len(seen_x0) >= steps:
            uc2.emu_stop()
    uc.hook_add(1, hook)
    try:
        uc.emu_start(start, 0xdead0000, count=steps)
    except UcError as e:
        pass
    # ReadTag 的返回值通常是 key varint；从 x0 序列反推 field number
    for v in seen_x0:
        if 0 < v < 0x100000:
            fn, wt = v >> 3, v & 7
            if fn > 0:
                tags.append((fn, wt))
    return tags, seen_x0[:50]


def main():
    p = argparse.ArgumentParser(description="动态提取 protobuf 字段号（无设备）")
    p.add_argument("--so", help="libUE4.so 路径")
    p.add_argument("--scan", action="store_true", help="路径A：扫描 descriptor blob")
    p.add_argument("--msg", default="CSMallBuyReq", help="目标消息名（去掉 pb. 前缀）")
    p.add_argument("--readtag-off", help="路径B：CodedInputStream::ReadTag 文件偏移")
    p.add_argument("--sample-hex", help="路径B：目标消息序列化样本 hex")
    p.add_argument("--out", help="结果 JSON 输出路径")
    args = p.parse_args()

    result = {"message": args.msg, "source": None, "fields": [], "confidence": None}

    if args.readtag_off and args.sample_hex and args.so:
        print("[*] 路径B：Unicorn 模拟 ReadTag @ %s" % args.readtag_off)
        tags, raw = simulate_readtag(args.so, int(args.readtag_off, 0), args.sample_hex)
        result["source"] = "unicorn-readtag-simulation"
        result["confidence"] = "medium (需确认偏移确为 ReadTag)"
        result["raw_x0"] = [hex(x) for x in raw]
        seen = set()
        for fn, wt in tags:
            if fn not in seen:
                seen.add(fn)
                result["fields"].append({"number": fn, "wire": wt, "name": None})
        print("[+] 观察到 field number:", [f["number"] for f in result["fields"]])

    elif args.so and args.scan:
        print("[*] 路径A：扫描 descriptor blob（消息 %s）" % args.msg)
        data = open(args.so, "rb").read()
        for pat in (args.msg, "pb." + args.msg, args.msg.lower()):
            hits = scan_blobs(data, pat.encode(), max_hits=10)
            if hits:
                print("[+] 命中 %d 处 descriptor blob（pattern=%s）" % (len(hits), pat))
                for off, found in hits[:3]:
                    print("    @ 0x%x:" % off)
                    for msg_name, fds in found:
                        print("      message %s:" % msg_name)
                        for name, num, typ in fds[:30]:
                            print("        %-28s = %s (type=%s)" % (name, num, typ))
                        # 记录目标消息
                        if args.msg.lower() in msg_name.lower():
                            result["fields"] = [{"name": n, "number": num, "type": t} for n, num, t in fds]
                result["source"] = "descriptor-blob-scan@" + pat
                result["confidence"] = "high" if result["fields"] else "low (命中但非目标消息)"
                break
        if not result["fields"]:
            print("[-] 未找到序列化的 FileDescriptorProto blob（与静态结论一致）")
            print("    当前 so 很可能不含 descriptor，需走路径B或真机 Frida find_descriptor.js")
            result["confidence"] = "not-found-static"
    else:
        p.print_help()
        sys.exit(1)

    if args.out:
        json.dump(result, open(args.out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        print("[*] 结果写入", args.out)
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
