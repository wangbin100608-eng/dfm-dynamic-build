#!/usr/bin/env python3
"""
07_replay.py — 本地重放：调用 Frida RPC 现算签名 → 发请求 → 打印响应
用法: python3 07_replay.py '<url>' '<json body>'
"""
import sys
import json
import time
import requests

try:
    import frida
except ImportError:
    frida = None


def rpc_sign(params: str, device: str = "127.0.0.1:5555") -> str:
    """通过 Frida RPC 调用 APP 内的签名函数"""
    if frida is None:
        raise RuntimeError("需要 frida 模块: pip install frida-tools")
    dev = frida.get_device_manager().attach(device) if ":" in device else frida.get_usb_device()
    session = dev.attach("com.tencent.tmgp.dfm")
    with session.create_script(open("scripts/06_sign_rpc.js", encoding="utf-8").read()) as script:
        script.load()
        return script.exports.sign(params)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    url = sys.argv[1]
    body = sys.argv[2]

    print("[*] 调用 RPC 现算签名...")
    sign = rpc_sign(body)
    print(f"[*] sign = {sign}")

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "okhttp/4.9.3",
        "sign": sign,
        "ts": str(int(time.time())),
        "nonce": "dfmresearch123",
    }

    print(f"[*] POST {url}")
    r = requests.post(url, data=body.encode(), headers=headers, timeout=30)
    print(f"[*] status = {r.status_code}")
    print(r.text[:4000])


if __name__ == "__main__":
    main()
