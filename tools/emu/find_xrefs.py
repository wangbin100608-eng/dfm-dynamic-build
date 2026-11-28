#!/usr/bin/env python3
"""
find_xrefs.py — 从字符串字面量地址反查引用它的代码位置（AArch64 ADRP+ADD xref）。

背景：libUE4.so 的字符串在 .rodata，代码通过 ADRP（取页基址）+ ADD（页内偏移）引用。
静态报告给出的偏移（如 SendTssData@0x5c32655）是字符串本身，直接模拟会触发非法指令。
本工具扫描 .text 找出引用该字符串的代码地址，得到真实函数入口供 emu_native_trace.py 使用。

纯 Python 位运算筛选 ADRP 候选，速度快，无需反汇编整个 500MB so。

用法:
  python3 find_xrefs.py --so libUE4.so --target 0x5c32655
  python3 find_xrefs.py --so libUE4.so --strings SendTssData,CSMallBuyReq --batch
"""
import argparse
import struct
import sys
import json

from elftools.elf.elffile import ELFFile


PAGE_SHIFT = 12


def decode_adrp(insn, pc):
    """解码 ADRP 指令，返回目标页基址；非 ADRP 返回 None"""
    if (insn & 0x9F000000) != 0x90000000:
        return None
    immlo = (insn >> 29) & 0x3
    immhi = (insn >> 5) & 0x7FFFF
    imm = ((immhi << 2) | immlo)
    if imm & (1 << 20):
        imm -= (1 << 21)
    page = (pc & ~0xFFF) + (imm << PAGE_SHIFT)
    return page & 0xFFFFFFFFFFFFFFFF


def decode_add_imm(insn):
    """解码 ADD Xd, Xn, #imm（无移位），返回 (Rd, Rn, imm)；非 ADD 返回 None"""
    if (insn & 0x7FC00000) != 0x91000000:
        return None
    rd = insn & 0x1F
    rn = (insn >> 5) & 0x1F
    imm = (insn >> 10) & 0xFFF
    if (insn >> 22) & 1:
        imm |= 0x1000
    return rd, rn, imm


def decode_ldr_literal(insn, pc):
    """解码 LDR Xt, label（literal 加载），返回 (Rt, target_va)。

    编码: 01 0 0 0 0 0 imm19 Rt  → 0x58000000 mask 0x7F000000
    V=0,opc=00 = 64-bit LDR literal；target = pc + sign_extend(imm19<<2)
    """
    if (insn & 0x7F000000) != 0x58000000:
        return None
    rt = insn & 0x1F
    imm19 = (insn >> 5) & 0x7FFFF
    imm = imm19 << 2
    if imm & (1 << 21):
        imm -= (1 << 22)
    target = (pc + imm) & 0xFFFFFFFFFFFFFFFF
    return rt, target


def find_ldr_literal_refs(data, segs, target_va):
    """找所有 LDR literal 直接从 GOT/pointer slot 读到 target_va 的引用。

    两遍法：先扫所有数据区找到值 == target_va 的 8 字节 slot（pointer pool），
    再在 .text 里找 LDR literal 读取该 slot 的地址。
    """
    results = []
    # 第一遍：定位所有内容等于 target_va 的 8 字节槽（文件全局扫描）
    slots = []
    tgt = struct.pack("<Q", target_va)
    pos = data.find(tgt)
    while pos >= 0 and len(slots) < 64:
        if pos % 8 == 0:
            slots.append(pos)
        pos = data.find(tgt, pos + 1)
    if not slots:
        return results
    # 把 slot 文件偏移映射到 vaddr
    slot_vas = {}
    for s in segs:
        off, va, sz = s["offset"], s["vaddr"], s["filesz"]
        for sp in slots:
            if off <= sp < off + sz - 8 and sp not in slot_vas:
                slot_vas[sp] = va + (sp - off)
    if not slot_vas:
        return results
    target_slot_vas = set(slot_vas.values())
    # 第二遍：扫 .text 找 LDR literal 目标落在这些 slot
    for off, va, insn in iter_text(data, segs):
        lr = decode_ldr_literal(insn, va)
        if lr and lr[1] in target_slot_vas:
            results.append({
                "ldr_off": off, "ldr_va": va,
                "slot_va": lr[1], "slot_off": slot_vas.get(lr[1]),
                "reg": lr[0], "target_va": target_va,
                "kind": "LDR-literal",
            })
    return results


def iter_text(data, segs):
    """产出 (file_offset, vaddr, insn) 遍历所有可执行 PT_LOAD"""
    for s in segs:
        if not (s["flags"] & 0x1):  # PF_X
            continue
        off, va, sz = s["offset"], s["vaddr"], s["filesz"]
        for o in range(off, off + sz - 3, 4):
            insn = struct.unpack_from("<I", data, o)[0]
            yield o, va + (o - off), insn


def find_xrefs(data, segs, target_va, window=16):
    """找所有引用 target_va 的 ADRP+ADD 指令对"""
    target_page = target_va & ~0xFFF
    target_lo = target_va & 0xFFF
    results = []
    # 第一遍：找 ADRP 到目标页的指令，记录 (pc, Rd)
    adrp_hits = []
    for off, va, insn in iter_text(data, segs):
        page = decode_adrp(insn, va)
        if page == target_page:
            rd = insn & 0x1F
            adrp_hits.append((off, va, rd))
    if not adrp_hits:
        return results
    # 第二遍：对每个 ADRP，在后续 window 条里找 ADD Rd'==Rn 且 imm==target_lo
    # 建立 va->(off,insn) 的邻接表（只扫 ADRP 附近）
    for aoff, ava, rd in adrp_hits:
        end = aoff + window * 4
        for o in range(aoff + 4, min(end, len(data) - 3), 4):
            insn = struct.unpack_from("<I", data, o)[0]
            add = decode_add_imm(insn)
            if add and add[1] == rd and add[2] == target_lo:
                va_add = ava + (o - aoff)
                # 再往前找函数入口：最近的 RET 之后的第一个指令（stub 风格）
                results.append({
                    "adrp_off": aoff, "adrp_va": ava,
                    "add_off": o, "add_va": va_add,
                    "target_va": target_va,
                    "reg": rd,
                })
                break
    return results


def find_strings(data, names):
    """找字符串字面量的文件偏移"""
    out = {}
    for name in names:
        pat = name.encode()
        pos = data.find(pat)
        if pos >= 0:
            out[name] = pos
    return out


def main():
    p = argparse.ArgumentParser(description="AArch64 字符串交叉引用扫描")
    p.add_argument("--so", required=True, help="libUE4.so 路径")
    p.add_argument("--target", help="单个目标字符串地址（文件偏移，so 基址从0算）")
    p.add_argument("--strings", help="逗号分隔的字符串名，如 SendTssData,CSMallBuyReq")
    p.add_argument("--window", type=int, default=16, help="ADRP 后搜索 ADD 的指令窗口")
    p.add_argument("--out", help="JSON 输出")
    args = p.parse_args()

    data = open(args.so, "rb").read()
    with open(args.so, "rb") as f:
        elf = ELFFile(f)
        segs = []
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_LOAD":
                segs.append({
                    "offset": seg["p_offset"], "vaddr": seg["p_vaddr"],
                    "filesz": seg["p_filesz"], "flags": seg["p_flags"],
                })

    targets = {}
    if args.target:
        targets["0x%x" % int(args.target, 0)] = int(args.target, 0)
    if args.strings:
        found = find_strings(data, [s.strip() for s in args.strings.split(",")])
        for name, off in found.items():
            targets["%s@0x%x" % (name, off)] = off

    if not targets:
        p.print_help()
        sys.exit(1)

    print("[*] 目标数: %d，扫描可执行段..." % len(targets))
    all_res = {}
    for label, tva in targets.items():
        print("[*] xref: %s (va=0x%x)" % (label, tva))
        res = find_xrefs(data, segs, tva, window=args.window)
        # 补充 LDR literal / pointer-pool 寻址
        res += find_ldr_literal_refs(data, segs, tva)
        all_res[label] = res
        if res:
            for r in res[:8]:
                if r.get("kind") == "LDR-literal":
                    print("    LDR@0x%x (slot@0x%x, reg x%d) → 候选代码入口" % (
                        r["ldr_off"], r["slot_va"], r["reg"]))
                else:
                    print("    ADRP@0x%x  ADD@0x%x (reg x%d) → 候选代码入口" % (
                        r["adrp_off"], r["add_off"], r["reg"]))
        else:
            print("    未找到 ADRP+ADD / LDR-literal xref")

    if args.out:
        json.dump(all_res, open(args.out, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
        print("[*] 写入", args.out)
    else:
        print(json.dumps(all_res, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
