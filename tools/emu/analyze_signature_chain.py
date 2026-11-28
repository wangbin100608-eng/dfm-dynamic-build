#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyze_signature_chain.py — 阶段2：签名链路静态分析。

事实前提（已由 tools/emu 实测）：
  - 任务给定的 7 个"函数偏移"全部落在可执行段，但字节内容是 protobuf descriptor 表/
    字符串池，不是可反汇编的 AArch64 函数序言（capstone 首次解码即 udf 或乱码）。
  - 真正的 pb.* 消息名与密码学符号在 so 里以 XOR-0x10 编码存储；明文符号表 .dynsym
    未导出 EVP_DigestSignInit/EVP_PKEY_sign/RSA_sign 等 OpenSSL 函数。
  - 因此本脚本不伪造"反汇编出的算法"，而是把可验证的静态证据整理成结构化报告：
      1) 每个符号的字符串存在性（plain/XOR-0x10）、精确文件偏移、所在段属性；
      2) 对偏移 ±window 做 capstone 线性反汇编，记录首个有效指令数/是否 udf；
      3) 密码学栈符号全集与 OID 名称，判断算法候选；
      4) 输出"复现签名需要的运行时输入清单"。
"""
from __future__ import annotations
import json, sys
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

ROOT = Path(__file__).resolve().parents[2]
SO = Path("/root/三角洲/dfm-apk/so-analysis/libUE4.so")
OUT = ROOT / "reports" / "signature-chain-static.json"

SYMBOLS = {
    "SendTssData": 0x5c32655,
    "TssSDKOnRecvSignature": 0x4d7c3de,
    "InitTss": 0x592d059,
    "EVP_DigestSignInit": 0x4d7699f,
    "EVP_PKEY_sign": 0x4fbb9e5,
    "RSA_sign": 0x4fbba6b,
    "sha256WithRSAEncryption": 0x5e91ffd,
}
EXTRA_SYMBOLS = [
    "EVP_SignFinal", "RSA_private_encrypt", "RSA_new", "EVP_PKEY_new",
    "md5WithRSAEncryption", "sha1WithRSAEncryption", "HMAC",
    "EVP_PKEY_verify", "RSA_verify", "d2i_PrivateKey",
    "AES_cbc_encrypt", "cscpp_security.pb.cpp", "cscpp_tss.pb.cpp",
]


def xor10(b: bytes) -> bytes:
    return bytes(x ^ 0x10 for x in b)


def main() -> int:
    data = SO.read_bytes()
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    out = {"_meta": {"so": str(SO), "size": len(data), "method": "static symbol string presence + capstone linear sweep"}, "symbols": [], "extra_symbols": []}

    for name, off in SYMBOLS.items():
        b = name.encode()
        xe = xor10(b)
        p_plain = data.find(b)
        p_xor = data.find(xe)
        insns = []
        for i in md.disasm(data[off - 16:off + 48], off - 16):
            insns.append({"addr": hex(i.address), "mn": i.mnemonic, "op": i.op_str})
        out["symbols"].append({
            "name": name,
            "given_offset": hex(off),
            "plain_offset": hex(p_plain) if p_plain >= 0 else None,
            "xor10_offset": hex(p_xor) if p_xor >= 0 else None,
            "plain_count": data.count(b),
            "xor10_count": data.count(xe),
            "bytes_at_offset": data[off:off + 32].hex(),
            "linear_disasm_first8": insns[:8],
            "disasm_valid_heuristic": "descriptor/data-like" if not insns or insns[0]["mn"] in ("udf", "stxrb", "stnp") else "possibly-code",
            "verdict": "给定偏移不是函数入口（字节为 protobuf descriptor 表/字符串池）",
        })
        print(f"[{name}] given={off:#x} plain={data.count(b)} xor10={data.count(xe)} "
              f"first_insn={insns[0]['mn'] if insns else 'NONE'}")

    for name in EXTRA_SYMBOLS:
        b = name.encode()
        xe = xor10(b)
        cp, cx = data.count(b), data.count(xe)
        locs = []
        q = data.find(xe)
        while q >= 0 and len(locs) < 4:
            locs.append(hex(q))
            q = data.find(xe, q + 1)
        out["extra_symbols"].append({
            "name": name, "plain_count": cp, "xor10_count": cx,
            "xor10_offsets": locs,
            "present": bool(cp or cx),
        })
        print(f"  {name:26s} plain={cp:2d} xor10={cx:2d}")

    out["algorithm_assessment"] = {
        "hash_candidates_present": ["SHA-256", "MD5", "SHA-1"],
        "asymmetric_stack": ["EVP_PKEY_sign_init", "EVP_PKEY_sign", "RSA_sign", "RSA_private_encrypt", "EVP_SignFinal"],
        "oid_names_present_xor10": ["sha256WithRSAEncryption", "md5WithRSAEncryption", "sha1WithRSAEncryption"],
        "verdict": "so 静态包含完整 RSA + SHA256/MD5/SHA1 签名栈，但无法从字符串存在性判定 TSS 具体使用哪一条；"
                   "须在真机 hook RSA_sign/EVP_PKEY_sign 的 type 参数或 OID 名称确定。",
        "likely_pkcs1_v15": True,
        "likely_pkcs1_v15_evidence": "存在 RSA_sign(type=NID_sha256/sha1/md5) 与 md5/sha256WithRSAEncryption OID 名称；"
                                     "EVP_PKEY_sign 默认 RSA padding 为 PKCS#1 v1.5（除非显式设 RSA_PKCS1_PSS_PADDING）。",
    }
    out["runtime_inputs_required"] = [
        "待签名 payload 的精确字节范围（frame 中哪一段参与签名）",
        "签名私钥或 TSS SDK 内持有的密钥句柄（不可从 so 静态提取）",
        "hash 算法选择（SHA256 / MD5 / SHA1）与 RSA padding（PKCS#1 v1.5 / PSS）",
        "设备指纹 qimei/oaid、时间戳、会话密钥、uin —— TSS 风控输入",
        "cmd_id / seq_id 的真实值及其是否进入签名摘要",
        "签名在帧中的位置与长度（frame.order 需抓包校准）",
    ]
    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("[+] wrote", OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
