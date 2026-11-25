#!/usr/bin/env python3
"""
dyn_field_extract.py — 用 Unicorn 动态执行 protobuf 序列化函数，抓字段名字符串 + 字段号。

原理：
  静态找到引用字段名字符串的序列化函数（如 goods_id/buy_num 的 xref 在 0xc4d35a4）。
  这些函数序言里会把字段号编码进指令（mov wN,#field_number），
  然后调用 helper（如 0x8f98cb0）时通过寄存器传入。
  本脚本从函数入口开始模拟，hook BL 之前的寄存器，并把 x2 指向的内存读成字符串（字段名），
  同时记录 w1（可疑字段号），从而动态建立 字段名 → 字段号 映射。
"""
import sys, struct, argparse
from elf_util import ELFMapper
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UcError, UC_HOOK_CODE, UC_HOOK_INTR
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X19,UC_ARM64_REG_SP,UC_ARM64_REG_LR
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

def cstr(uc, addr, n=64):
    try:
        b=bytes(uc.mem_read(addr,n))
        return b.split(b"\x00")[0].decode("utf-8","ignore")
    except: return ""

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--so",required=True)
    p.add_argument("--func",required=True,help="序列化函数入口文件偏移")
    p.add_argument("--steps",type=int,default=400)
    p.add_argument("--base",default="0x100000000")
    a=p.parse_args()
    base=int(a.base,16); func=int(a.func,0)
    m=ELFMapper(a.so,base=base); uc=m.create_uc()
    start=m.va(func)
    md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
    uc.reg_write(UC_ARM64_REG_SP,m.stack_base-0x8000)
    uc.reg_write(UC_ARM64_REG_LR,0xdead0000)
    # x19/x20 作为对象指针，给个可写区
    obj=m.stack_base-0x4000
    uc.reg_write(UC_ARM64_REG_X19,obj)
    events=[]
    def hook(uc2,addr,size,ud):
        code=bytes(uc2.mem_read(addr,size))
        ins=next(md.disasm(code,addr),None)
        if not ins: return
        # 检查 mov 立即数（字段号候选）
        if ins.mnemonic in ("mov","movz") and "#" in ins.op_str:
            try:
                imm=int(ins.op_str.split("#")[1].strip().replace("0x",""),0) if "0x" in ins.op_str else int(ins.op_str.split("#")[1].strip())
                if 0 < imm < 1000:
                    events.append(("IMM",hex(addr),imm))
            except: pass
        # BL 前：记录 x2 字符串 + w1
        if ins.mnemonic=="bl":
            x2=uc2.reg_read(UC_ARM64_REG_X2)
            w1=uc2.reg_read(UC_ARM64_REG_X1)&0xffffffff
            s=cstr(uc2,x2)
            if s and s.isprintable() and 2<len(s)<64:
                events.append(("FIELD",hex(addr),s,w1))
        if len(events)>2000: uc2.emu_stop()
    def onintr(uc2,intno,ud): uc2.emu_stop()
    uc.hook_add(UC_HOOK_CODE,hook)
    uc.hook_add(UC_HOOK_INTR,onintr)
    try: uc.emu_start(start,0xdead0000,count=a.steps)
    except UcError: pass
    print("[*] func=%#x va=%#x steps=%d"%(func,start,a.steps))
    print("=== 字段事件（字符串 + 当时 w1）===")
    seen=set()
    for e in events:
        if e[0]=="FIELD":
            key=(e[2],e[3])
            if key not in seen:
                seen.add(key)
                print("  %s  field=%s  w1=%d (0x%x)"%(e[1],e[2],e[3],e[3]))
    print("=== 立即数（前40，可能含字段号）===")
    imms=[e for e in events if e[0]=="IMM"]
    for e in imms[:40]: print("  %s imm=%d"%(e[1],e[2]))

if __name__=="__main__": main()
