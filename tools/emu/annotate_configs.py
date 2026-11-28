#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
annotate_configs.py — 阶段2：给 field_map.inferred.json / capture.example.json 每条加
_source + confidence 标注，明确"已推断"和"必须真机提供"的边界。只追加字段，不改既有 number/evidence。
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FM = ROOT / "reports" / "field_map.inferred.json"
FME = ROOT / "tools" / "probe" / "field_map.example.json"
CAP = ROOT / "tools" / "probe" / "capture.example.json"

fm = json.loads(FM.read_text(encoding="utf-8"))

# 顶层证据说明升级（追加，不覆盖旧键）
fm["_evidence_legend"]["field_number_inferred"] = (
    "number 由 struct offset 顺序推断（推导规则见 tools/emu/extract_field_sets.py），"
    "非 DescriptorPool 导出；用于离线构造测试，不能当服务端接受的真实字段号。"
)
fm["_evidence_legend"]["must_capture_runtime"] = (
    "标记为 runtime-required 的字段/参数：静态不可得，必须由真机 Frida/dump 提供。"
)
fm["_stage2_annotations"] = {
    "generated_by": "阶段2 ProtoSig",
    "so": "/root/三角洲/dfm-apk/so-analysis/libUE4.so",
    "message_names_source": "全文件 XOR-0x10 解码扫描（tools/emu/harvest_pb_messages.py）；"
                            "4 个核心消息名均在 XOR 池命中，明文池 0 条",
    "field_numbers": "所有 number 均为 medium 推断或 null；无一来自 DescriptorPool；"
                     "真机 find_descriptor.js 导出前不得升级为 high",
    "gateway": "host/port 为 runtime-required，so 中仅内网字面量不可当生产端点",
}

# 给 frame 元素加 _source / confidence
for el in fm.get("frame", {}).get("order", []):
    src = el.get("source")
    if el.get("kind") == "length":
        el["_source"] = "local_calculation"
        el["confidence"] = "medium"
    elif src and src.startswith("session."):
        el["_source"] = "capture_runtime"
        el["confidence"] = "unknown"
        el["runtime_required"] = True
    elif src == "@body":
        el["_source"] = "local_protobuf_builder"
        el["confidence"] = "high"
    else:
        el["_source"] = "config"
        el["confidence"] = "unknown"
    el.setdefault("_comment_stage2", "帧布局为 UE4 私有网关常见形态假设，需用 dump_traffic.js 真实字节校准")

# 每条消息字段：补齐 _source / confidence；明确 null 字段必须抓包
for mname, m in fm.get("messages", {}).items():
    m.setdefault("_source", "tools/emu/extract_field_sets.py struct-offset ordering")
    m.setdefault("confidence", "medium")
    m.setdefault("runtime_required_for_field_numbers", True)
    for f in m.get("fields", []):
        num = f.get("number")
        if num is None:
            f["_source"] = "inferred_from_struct_offset_order_failed"
            f["confidence"] = "unknown"
            f["runtime_required"] = True
            f["_comment_stage2"] = "字段号未能从结构偏移推断；必须由 find_descriptor.js 或抓包提供，禁止猜测"
        else:
            f["_source"] = f.get("number_source", "inferred_from_struct_offset_order")
            f["confidence"] = "medium"
            f["runtime_required"] = False
            f["_comment_stage2"] = "字段号是结构偏移顺序推断值（medium），需 DescriptorPool 导出确认后才能升级 high"

FM.write_text(json.dumps(fm, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print("[+] annotated", FM)

# field_map.example.json 同步标注（probe_gateway.py 默认读它）
fme = json.loads(FME.read_text(encoding="utf-8"))
fme["_stage2_annotations"] = {
    "generated_by": "阶段2 ProtoSig",
    "field_numbers": "全部 number=null：静态不可得，必须真机 DescriptorPool 导出；禁止猜测。",
    "runtime_required": ["gateway.host", "gateway.port", "frame.session.cmd_id",
                         "frame.session.seq_id", "session.signature_hex"],
}
for el in fme.get("frame", {}).get("order", []):
    if el.get("kind") == "length":
        el["_source"] = "local_calculation"; el["confidence"] = "medium"
    elif str(el.get("source", "")).startswith("session."):
        el["_source"] = "capture_runtime"; el["confidence"] = "unknown"; el["runtime_required"] = True
    else:
        el["_source"] = "local_protobuf_builder"; el["confidence"] = "high"
for m in fme.get("messages", {}).values():
    m.setdefault("_source", "so-XOR-0x10-string + cs_*.pb.cpp")
    m.setdefault("runtime_required_for_field_numbers", True)
    for f in m.get("fields", []):
        f["_source"] = "runtime_descriptor_required"
        f["confidence"] = "unknown"
        f["runtime_required"] = True
        f.setdefault("_comment_stage2", "字段号必须真机导出，禁止猜测")
FME.write_text(json.dumps(fme, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print("[+] annotated", FME)

cap = json.loads(CAP.read_text(encoding="utf-8"))
cap["_stage2_annotations"] = {
    "generated_by": "阶段2 ProtoSig",
    "boundary": "本文件所有业务值均为 null；发送前必须由真实客户端运行时填充。",
    "sources": {
        "cmd_id": "runtime-required: dump_traffic.js 帧级 dump / requestCallback hook",
        "seq_id": "runtime-required: 同上，通常递增",
        "signature_hex": "runtime-required: TSS SDK SendTssData/TssSDKOnRecvSignature 入参",
        "seed_hex": "runtime-required: 若存在会话种子",
        "session_key_hex": "runtime-required: 登录握手/Frida dump",
        "device_fingerprint": "runtime-required: qimei/oaid 等设备指纹",
        "uin": "runtime-required: 游戏账号 uid",
    },
}
for k in ("cmd_id", "seq_id", "signature_hex", "seed_hex", "session_key_hex",
          "device_fingerprint", "uin"):
    cap[k + "_source"] = "capture_runtime"
    cap[k + "_confidence"] = "unknown"
    cap[k + "_runtime_required"] = True
for k in ("_captured_from", "_captured_at"):
    cap[k + "_source"] = "capture_metadata"
    cap[k + "_confidence"] = "high"

CAP.write_text(json.dumps(cap, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print("[+] annotated", CAP)
