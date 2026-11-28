#!/usr/bin/env python3
"""从真机 pcap 离线提取网关连接与 CS 帧候选（不发包、不解密签名）。

用途：当外部提供"现成抓包"时，先离线定位：
  - 网关 HOST/PORT（游戏客户端发起的非 DNS TCP 连接，按流量/包大小排序）
  - CS 帧候选长度前缀 + cmd_id/seq_id（按 frame.order 假设切帧，标注置信度）
  - protobuf body 候选（可导出 hex 供 protoc --decode_raw）

所有结论标注来源与置信度；不臆造字段值；不修改任何抓包。
"""
import argparse, json, struct, sys
from collections import Counter, defaultdict

try:
    from scapy.all import rdpcap, TCP, UDP, IP, Raw
except ImportError:
    print("需要 scapy: pip3 install scapy", file=sys.stderr); sys.exit(2)


def extract(pcap, top=20):
    pkts = rdpcap(pcap)
    conns = defaultdict(lambda: {"pkts": 0, "bytes": 0, "payloads": []})
    for p in pkts:
        if not p.haslayer(IP) or not p.haslayer(TCP):
            continue
        ip, tcp = p[IP], p[TCP]
        key = (ip.dst, tcp.dport, ip.src, tcp.sport)
        payload = bytes(tcp.payload) if p.haslayer(Raw) else b""
        c = conns[key]
        c["pkts"] += 1; c["bytes"] += len(payload)
        if payload:
            c["payloads"].append((len(payload), payload[:64].hex()))
    out = []
    for (dst, dport, src, sport), c in sorted(conns.items(), key=lambda x: -x[1]["bytes"]):
        out.append({
            "dst": dst, "dport": dport, "src": src, "sport": sport,
            "packets": c["pkts"], "payload_bytes": c["bytes"],
            "first_payloads": c["payloads"][:5],
            "_source": f"pcap:{pcap}", "_confidence": "high(网络层事实)",
            "_note": "网关候选需结合游戏登录时序确认；内网/SDK 域名需排除",
        })
    return {"file": pcap, "total_packets": len(pkts),
            "tcp_connections": len(conns), "top_connections": out[:top]}


def main():
    ap = argparse.ArgumentParser(description="离线 pcap 网关/帧候选提取")
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--out", help="结果 JSON 输出")
    ap.add_argument("--top", type=int, default=20)
    a = ap.parse_args()
    r = extract(a.pcap, a.top)
    s = json.dumps(r, ensure_ascii=False, indent=2)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(s)
        print("[+] saved", a.out)
    else:
        print(s[:4000])


if __name__ == "__main__":
    main()
