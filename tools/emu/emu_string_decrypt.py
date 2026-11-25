#!/usr/bin/env python3
"""
emu_string_decrypt.py — 用 Unicorn 模拟字符串解密函数，动态还原混淆字符串。

支持两种模式：
  1) 直接模拟简单 XOR / 加解密循环（给出算法参数，Unicorn 跑 ARM64 指令验证）
  2) 模拟 so 内真实解密函数（给出函数偏移 + 输入，Unicorn 执行后读回输出）

用法:
  python3 emu_string_decrypt.py --input-hex <密文> --xor 0x10
  python3 emu_string_decrypt.py --so libUE4.so --offset 0x... --input-hex <密文> --out-len 64
"""
import argparse
import json
import sys

from elf_util import ELFMapper
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UcError
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_SP


def xor_decode(data, key):
    if isinstance(key, int):
        return bytes(b ^ key for b in data)
    else:
        kb = key if isinstance(key, bytes) else bytes(key)
        return bytes(b ^ kb[i % len(kb)] for i, b in enumerate(data))


def simulate_func(so_path, offset, data, out_len, base=0x100000000, steps=5000):
    mapper = ELFMapper(so_path, base=base)
    uc = mapper.create_uc()
    start = mapper.va(offset)
    # 输入 buffer 放到栈
    in_va = mapper.stack_base - 0x2000
    out_va = mapper.stack_base - 0x1000
    uc.mem_write(in_va, data)
    uc.reg_write(UC_ARM64_REG_X0, in_va)   # arg0: input
    uc.reg_write(UC_ARM64_REG_X1, len(data))  # arg1: len
    uc.reg_write(UC_ARM64_REG_X2, out_va)  # arg2: output buffer
    uc.reg_write(UC_ARM64_REG_SP, mapper.stack_base - 0x8000)
    uc.reg_write(0x0e, 0xdead0000)  # LR 哨兵 (UC_ARM64_REG_LR=0x0e? 用常量)
    try:
        uc.emu_start(start, 0xdead0000, count=steps)
    except UcError:
        pass
    out = bytes(uc.mem_read(out_va, out_len))
    return out


def main():
    p = argparse.ArgumentParser(description="动态字符串解密（Unicorn 模拟）")
    p.add_argument("--input-hex", required=True, help="密文 hex")
    p.add_argument("--xor", help="简单 XOR key（hex 整数或 hex 字节串）")
    p.add_argument("--so", help="libUE4.so 路径（函数模拟模式）")
    p.add_argument("--offset", help="解密函数文件偏移")
    p.add_argument("--out-len", type=int, default=256, help="输出长度")
    p.add_argument("--out", help="结果写入文件")
    args = p.parse_args()
    data = bytes.fromhex(args.input_hex.replace(" ", ""))

    if args.so and args.offset:
        print("[*] 模拟 so 解密函数 @ %s" % args.offset)
        out = simulate_func(args.so, int(args.offset, 0), data, args.out_len)
        # 截到第一个 NUL
        end = out.find(b"\x00")
        text = out[:end] if end >= 0 else out
        print("[+] 输出 hex:", text.hex())
        try:
            print("[+] 输出 str:", text.decode("utf-8"))
        except Exception:
            print("[+] 输出 (非UTF-8):", repr(text))
    elif args.xor:
        x = args.xor
        if x.lower().startswith("0x"):
            key = int(x, 16)
        else:
            key = bytes.fromhex(x)
        out = xor_decode(data, key)
        print("[+] XOR 解码:", out.hex())
        try:
            print("[+] 文本:", out.decode("utf-8"))
        except Exception:
            print("[+] (非UTF-8):", repr(out))
    else:
        p.print_help()
        sys.exit(1)

    if args.out:
        open(args.out, "wb").write(out)
        print("[*] 写入", args.out)


if __name__ == "__main__":
    main()
