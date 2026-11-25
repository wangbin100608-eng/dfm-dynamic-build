# 运行环境记录

## 当前工作站（2026-11-25 起）

| 项目 | 值 |
|---|---|
| 主机 | 45.63.100.185（Vultr，Ubuntu 26.10） |
| 规格 | 8 核 / 30G 内存 / 132G 可用磁盘 |
| 虚拟化 | Microsoft Hyper-V 全虚拟化（**无嵌套虚拟化，无 `/dev/kvm`**） |
| 内核 | 7.3.0-10-generic，`CONFIG_ANDROID_BINDER_IPC=m`，无 ashmem |
| adb | 1.0.41 |
| JDK | OpenJDK 25.0.5.1 |
| QEMU | 11.0.3（无 KVM 加速，仅能软模拟） |
| frida | 17.27.5（Python 模块 + CLI） |
| Python | 3.14.8，requests 2.34.2 |
| 工作目录 | `/root/dfm_dynamic_build/repo`（完整成果 + .git） |

## 前一台机器

| 项目 | 值 |
|---|---|
| 主机 | 139.180.197.211（已宕机，2026-11-24 16:16 起 ICMP 100% 丢包、SSH 22 超时） |
| 用途 | 完成 APK 下载、元信息提取、apktool decode、静态逆向 |
| 关键产出 | libUE4.so 字符串分析 → `reports/HAVAL_PURCHASE_API.md` |

## 模拟器可行性结论

两台机器均为 Vultr Hyper-V 环境，共同缺陷：
- **无 `/dev/kvm`**（无嵌套虚拟化）→ QEMU 只能 TCG 软模拟，跑完整 Android + UE4 游戏不现实；
- **内核无 ashmem** → REDroid 容器无法完成 boot（实测卡在 Android 动画）；
- binder 需手动 `mknod`，设备功能不完整。

即使模拟器起得来，三角洲行动有 ACE 反作弊 + 设备指纹 + GMS 依赖，模拟器登录官服本身也不可行。

**结论**：动态参数导出必须在**已 root 的物理真机**上完成。当前 Linux 工作站的定位是：
1. 静态逆向 / 接口定义维护；
2. 探针程序的 build / decode / 离线分析；
3. 真机抓包数据回来后的字段号填充与请求构造。

## 探针程序自测结果（本机器，2026-11-25）

```
python3 -m py_compile probe_gateway.py    → OK
probe_gateway.py --summary                → 正常打印消息/字段证据表
probe_gateway.py --mode build             → 缺字段号显示 BLOCKED，dry-run 未联网
probe_gateway.py --mode decode --raw-hex  → 正确解出 field 1=1 / field 2=1 / field 5=len3
probe_gateway.py --mode send（占位配置）  → 返回码 2，拒绝臆造网关地址
```
