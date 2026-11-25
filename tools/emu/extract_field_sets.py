#!/usr/bin/env python3
"""
extract_field_sets.py — 从 protobuf 序列化函数静态提取消息字段集 + 结构偏移。

已定位的序列化函数（本工具发现）：
  0xc4d3520 限购购买: curr_buy_limit,next_period_start,limit_type,buy_num
  0xc4f6800 订单购买: currency,price,buy_num,to_pos,order_id,durability
  0xc514000 交易定价: show_prop_id,buy_currency_id,sell_currency_id,guide_price,price_range_begin
  0xc506200 弹药操作: op_type,bullet_gid

原理：序列化函数用 ADRP+ADD 加载字段名字符串，随后 ldr x1,[x20,#struct_off] 取值。
字段号未在代码里以立即数出现（传给 helper 的 w1=-2 是标志位），
protobuf 生成代码字段号按声明顺序 = 结构偏移递增顺序，可据此推断候选字段号。

用法: python3 extract_field_sets.py --so libUE4.so [--func 0xc4d3520]
"""
import argparse,re
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN

def cstr(data,fo,n=48):
    return data[fo:fo+n].split(b"\x00")[0].decode("utf8","ignore")

def analyze(data,start,end):
    md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
    cur=None; fields=[]; pending=None
    for insn in md.disasm(data[start:end],start):
        if insn.mnemonic=="adrp":
            m=re.search(r"#\s*(0x[0-9a-f]+)",insn.op_str)
            if m: cur=int(m.group(1),16)
        elif insn.mnemonic=="add" and cur is not None:
            m=re.search(r"#\s*(0x[0-9a-f]+)",insn.op_str)
            if m:
                fo=cur+int(m.group(1),16)
                s=cstr(data,fo)
                if s and all(32<=ord(c)<127 for c in s) and 2<len(s)<50:
                    pending=s; fields.append({"name":s,"struct_off":None,"code_addr":hex(insn.address)})
            cur=None
        if pending and insn.mnemonic in ("ldr","ldrsw") and "x20" in insn.op_str:
            m=re.search(r"\[x20,\s*#(0x[0-9a-f]+)\]",insn.op_str)
            if m:
                fields[-1]["struct_off"]=m.group(1); pending=None
    # 按结构偏移排序，推断候选字段号
    known=[f for f in fields if f["struct_off"]]
    known.sort(key=lambda f:int(f["struct_off"],16))
    for i,f in enumerate(known,1):
        f["inferred_field_no"]=i
    return fields

FUNCS={0xc4d3520:"限购/购买 (curr_buy_limit...)",0xc4f6800:"订单购买 (currency,price...)",
       0xc514000:"交易定价 (buy_currency_id...)",0xc506200:"弹药操作 (bullet_gid...)"}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--so",required=True); p.add_argument("--func",help="单个函数偏移")
    a=p.parse_args(); data=open(a.so,"rb").read()
    funcs={int(a.func,0):"custom"} if a.func else FUNCS
    import json
    out={}
    for f,label in funcs.items():
        fs=analyze(data,f,f+0x180)
        print("\n=== %s @ %#x ==="%(label,f))
        for x in fs:
            if x["name"].startswith("_"): continue
            print("  %-24s off=%-6s field_no≈%s  @%s"%(x["name"],x["struct_off"],x.get("inferred_field_no","?"),x["code_addr"]))
        out[hex(f)]={"label":label,"fields":fs}
    if not a.func:
        json.dump(out,open("/root/dfm_dynamic_build/reports/field_sets.json","w"),indent=2)
        print("\n[+] 写入 reports/field_sets.json")
if __name__=="__main__": main()
