#!/usr/bin/env python3
"""
emu_native_trace.py — 用 Unicorn 模拟 ARM64 指令执行，动态跟踪 native 函数。
不需要 Android / 设备 / Frida server；直接把 libUE4.so 的函数加载进模拟 CPU 跑。

用法:
  python3 emu_native_trace.py --so libUE4.so --offset 0x5c32655 --count 2000
  python3 emu_native_trace.py --config config.json

输出：每条指令的地址/汇编/关键寄存器变化，CALL 目标，内存读写，最终寄存器与栈。
"""
import argparse
import json
import struct
import sys

from elf_util import ELFMapper
from unicorn import (
    Uc, UC_ARCH_ARM64, UC_MODE_ARM, UcError,
    UC_HOOK_CODE, UC_HOOK_MEM_INVALID,
)
from unicorn.arm64_const import (
    UC_ARM64_REG_SP, UC_ARM64_REG_PC, UC_ARM64_REG_LR,
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X8, UC_ARM64_REG_X19, UC_ARM64_REG_X20,
)
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

REGS = {
    "x0": UC_ARM64_REG_X0, "x1": UC_ARM64_REG_X1, "x2": UC_ARM64_REG_X2,
    "x3": UC_ARM64_REG_X3, "x8": UC_ARM64_REG_X8, "x19": UC_ARM64_REG_X19,
    "x20": UC_ARM64_REG_X20, "sp": UC_ARM64_REG_SP, "lr": UC_ARM64_REG_LR,
}


def parse_args():
    p = argparse.ArgumentParser(description="Unicorn ARM64 native function tracer")
    p.add_argument("--config", help="config.json（可覆盖其他参数）")
    p.add_argument("--so", help="libUE4.so 路径")
    p.add_argument("--offset", help="函数文件偏移，如 0x5c32655")
    p.add_argument("--count", type=int, default=1000, help="最多模拟指令数")
    p.add_argument("--base", default=hex(0x100000000), help="映射基址")
    p.add_argument("--args", nargs="*", default=[], help="初始寄存器 x0=val x1=val ...")
    p.add_argument("--stack", nargs="*", default=[], help="初始栈值 hex 列表")
    p.add_argument("--stubs", help="stub 配置文件：外部函数地址 → 返回值")
    p.add_argument("--dump-stack", type=int, default=64, help="结束时 dump 栈字节数")
    return p.parse_args()


def load_cfg(args):
    cfg = {}
    if args.config:
        cfg = json.load(open(args.config, encoding="utf-8"))
    for k in ("so", "offset", "base", "stubs"):
        v = getattr(args, k, None)
        if v is not None:
            cfg[k] = v
    if cfg.get("count") is None:
        cfg["count"] = args.count
    return cfg


def main():
    args = parse_args()
    cfg = load_cfg(args)
    so_path = cfg.get("so")
    off = cfg.get("offset")
    if not so_path or not off:
        print("[!] 需要 --so 和 --offset（或 config.json）")
        sys.exit(1)
    off = int(off, 0) if isinstance(off, str) else off
    base = int(cfg.get("base", hex(0x100000000)), 0) if isinstance(cfg.get("base", str), str) else cfg["base"]
    count = int(cfg.get("count", args.count))

    mapper = ELFMapper(so_path, base=base)
    uc = mapper.create_uc()
    start = mapper.va(off)
    end = start + count * 8  # 上限保护

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    stubs = {}
    if cfg.get("stubs"):
        stubs = json.load(open(cfg["stubs"], encoding="utf-8"))

    trace = []

    def hook_code(uc2, addr, size, user):
        code = uc2.mem_read(addr, size)
        insn = next(md.disasm(bytes(code), addr), None)
        if insn:
            x0 = uc2.reg_read(UC_ARM64_REG_X0)
            trace.append("%s  %-8s %-30s x0=%s" % (
                hex(addr), insn.mnemonic, insn.op_str, hex(x0)))
        if len(trace) >= count:
            uc2.emu_stop()

    def hook_mem_invalid(uc2, access, addr, size, value, user):
        print("[mem-invalid] access=%s @ %s size=%d" % (access, hex(addr), size))
        return False

    def hook_intr(uc2, intno, user):
        # 遇到未实现的系统调用/中断时停止，避免无限执行
        print("[intr] 中断号 %d @ PC=%s，停止模拟" % (intno, hex(uc2.reg_read(UC_ARM64_REG_PC))))
        uc2.emu_stop()

    uc.hook_add(UC_HOOK_CODE, hook_code)
    uc.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)
    from unicorn import UC_HOOK_INTR
    uc.hook_add(UC_HOOK_INTR, hook_intr)

    # 设置初始寄存器
    for a in args.args:
        if "=" in a:
            k, v = a.split("=", 1)
            if k.lower() in REGS:
                uc.reg_write(REGS[k.lower()], int(v, 0))
    sp = mapper.stack_base - 0x8000
    uc.reg_write(UC_ARM64_REG_SP, sp)
    uc.reg_write(UC_ARM64_REG_LR, 0xdead0000)  # 哨兵返回地址
    for i, v in enumerate(args.stack):
        uc.mem_write(sp + i * 8, struct.pack("<Q", int(v, 0)))

    print("[*] so=%s" % so_path)
    print("[*] offset=%s → va=%s" % (hex(off), hex(start)))
    print("[*] 模拟最多 %d 条指令" % count)
    try:
        uc.emu_start(start, end, count=count)
    except UcError as e:
        print("[*] 模拟停止: %s" % e)

    print("\n===== 指令跟踪（前 %d 条）=====" % min(len(trace), count))
    for line in trace[:count]:
        print(line)

    print("\n===== 终止状态 =====")
    print("PC =", hex(uc.reg_read(UC_ARM64_REG_PC)))
    print("LR =", hex(uc.reg_read(UC_ARM64_REG_LR)))
    for k in ("x0", "x1", "x2", "x8", "sp"):
        print("%-3s= %s" % (k, hex(uc.reg_read(REGS[k]))))
    try:
        stack = bytes(uc.mem_read(sp, args.dump_stack))
        print("stack[%d] = %s" % (args.dump_stack, stack.hex()))
    except Exception:
        pass


if __name__ == "__main__":
    main()
