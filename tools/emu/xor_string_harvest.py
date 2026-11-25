#!/usr/bin/env python3
"""
xor_string_harvest.py — 从 libUE4.so 挖出 XOR 0x10 混淆的字符串明文（验证工具）。

背景与实测结论（重要）：
  历史报告声称 UE4 字符串整体用 XOR 0x10 混淆。本工具在新版本样本上做了确定性验证：
    - "Buy~ydyq|yju" XOR 0x10 = "Reinitialize"（单个巧合，XOR 自反导致双向都成立）
    - 但对所有关键术语（cmd_id/goods_id/buy_price/CSMallBuyReq/currency_type/...），
      XOR 0x10 编码在 so 中出现次数全为 0，明文大量存在。
    - 扫描出的 512 条"XOR 后可读"字符串均为噪声，无一条是 protobuf 消息名/字段名。
  结论：当前版本（1.201.1035.13）关键字符串是明文，无需 XOR 解码。
  本工具保留作验证/排除用途：若你想确认某个词是否被 XOR 混淆，用 --verify 模式。

用法:
  python3 xor_string_harvest.py --so libUE4.so --verify Reinitialize,cmd_id,CSMallBuyReq
  python3 xor_string_harvest.py --so libUE4.so --keywords Buy,Ammo --out xor_strings.txt
"""
import argparse
import re
import string
import sys

PRINTABLE = set(bytes(string.printable[:95], "ascii"))  # 0x20-0x7e
MIN_LEN = 5


def score_readable(data):
    """判断 bytes 是否像可读文本：字母数字占比 + 常见模式"""
    if not data or len(data) < MIN_LEN:
        return 0.0
    letters = sum(1 for c in data if chr(c).isalnum() or chr(c) in "._:/-= ")
    ratio = letters / len(data)
    # 常见英文片段加权
    txt = data.decode("ascii", "ignore")
    bonus = 0.0
    for w in ("tion", "ment", "ence", "able", "ing", "Req", "Res", "Info", "Data", "Name", "Get", "Set", "Buy", "Price", "Type", "id", "Num"):
        if w in txt:
            bonus += 0.1
    return ratio + bonus


def xor10(buf):
    return bytes(b ^ 0x10 for b in buf)


def scan(data, keywords, min_len=MIN_LEN, max_out=5000):
    """滑动窗口扫描：对每个位置，XOR 0x10 后判断是否可读"""
    out = []
    n = len(data)
    # 先快速定位：XOR 后可打印的连续字节段
    i = 0
    while i < n:
        # 从当前位置开始，尽可能长的连续 (xor后可打印) 段
        j = i
        while j < n and j - i < 512:
            c = data[j] ^ 0x10
            if 0x20 <= c <= 0x7e:
                j += 1
            else:
                break
        seg_len = j - i
        if seg_len >= min_len:
            decoded = xor10(data[i:j])
            sc = score_readable(decoded)
            if sc >= 0.75:
                txt = decoded.decode("ascii", "ignore")
                # 关键词过滤
                if not keywords or any(k.lower() in txt.lower() for k in keywords):
                    out.append((i, txt, round(sc, 2)))
                    if len(out) >= max_out:
                        break
        i = j + 1 if j > i else i + 1
    return out


def main():
    p = argparse.ArgumentParser(description="XOR 0x10 混淆字符串挖矿")
    p.add_argument("--so", required=True, help="libUE4.so 路径")
    p.add_argument("--verify", help="逗号分隔的词：确定性检查是否存在 XOR 0x10 编码")
    p.add_argument("--keywords", help="逗号分隔关键词（大小写无关）")
    p.add_argument("--all", action="store_true", help="不做关键词过滤（输出可能很多）")
    p.add_argument("--min-len", type=int, default=MIN_LEN)
    p.add_argument("--out", help="输出文件")
    p.add_argument("--max", type=int, default=5000)
    args = p.parse_args()

    data = open(args.so, "rb").read()
    if args.verify:
        print("[*] 确定性 XOR 0x10 验证:")
        print("%-24s %-12s %-12s %s" % ("词", "XOR编码次数", "明文次数", "判定"))
        for w in [x.strip() for x in args.verify.split(",")]:
            enc = bytes(b ^ 0x10 for b in w.encode())
            ce, cp = data.count(enc), data.count(w.encode())
            verdict = "XOR编码存在" if ce > 0 and cp == 0 else ("明文" if cp > 0 else "均未找到")
            print("%-24s %-12d %-12d %s" % (w, ce, cp, verdict))
        return
    kws = [] if args.all else [k.strip() for k in (args.keywords or "Buy,Ammo,Price,Mall,Currency,cmd_id,CSMall,proto,equipment,bullet").split(",")]
    print("[*] 扫描 %d 字节，关键词: %s" % (len(data), kws or "all"))
    res = scan(data, kws, min_len=args.min_len, max_out=args.max)
    print("[+] 找到 %d 条可读 XOR 字符串" % len(res))
    lines = []
    for off, txt, sc in res:
        line = "0x%08x  score=%.2f  %s" % (off, sc, txt)
        lines.append(line)
        print(line)
    if args.out:
        open(args.out, "w", encoding="utf-8").write("\n".join(lines) + "\n")
        print("[*] 写入", args.out)


if __name__ == "__main__":
    main()
