"""
elf_util.py — ARM64 ELF 加载器：把 .so 映射到 Unicorn 模拟地址空间。
纯 pyelftools，无设备依赖。
"""
import struct
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_E_TYPE

# Unicorn 常量（延迟导入，避免没装时 import 报错）
def _uc():
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_ALL, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
    return Uc, UC_ARCH_ARM64, UC_MODE_ARM

DEFAULT_BASE = 0x100000000
PAGE = 0x1000


def align_up(x, a=PAGE):
    return (x + a - 1) & ~(a - 1)


def align_down(x, a=PAGE):
    return x & ~(a - 1)


class ELFMapper:
    def __init__(self, so_path, base=DEFAULT_BASE):
        self.path = so_path
        self.base = base
        self.f = open(so_path, "rb")
        self.elf = ELFFile(self.f)
        if self.elf.header["e_machine"] != "EM_AARCH64":
            raise ValueError("只支持 ARM64 (AARCH64) ELF，当前: %s" % self.elf.header["e_machine"])
        self.segments = []
        self.symbols = {}
        self._parse_segments()
        self._parse_dynamic_symbols()

    def _parse_segments(self):
        for seg in self.elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            vaddr = seg["p_vaddr"]
            memsz = seg["p_memsz"]
            filesz = seg["p_filesz"]
            off = seg["p_offset"]
            flags = seg["p_flags"]
            self.segments.append({
                "vaddr": vaddr, "memsz": memsz, "filesz": filesz,
                "offset": off, "flags": flags, "data": seg.data(),
            })

    def _parse_dynamic_symbols(self):
        try:
            dynsym = self.elf.get_section_by_name(".dynsym")
            if dynsym is None:
                return
            for sym in dynsym.iter_symbols():
                if sym["st_value"]:
                    self.symbols[sym.name] = sym["st_value"]
        except Exception:
            pass

    def va(self, file_offset):
        """文件偏移 → 虚拟地址（基于第一个包含该 offset 的 PT_LOAD）"""
        for s in self.segments:
            if s["offset"] <= file_offset < s["offset"] + s["filesz"]:
                return self.base + s["vaddr"] + (file_offset - s["offset"])
        # fallback: 直接 base + offset
        return self.base + file_offset

    def offset_to_va(self, file_offset):
        return self.va(file_offset)

    def create_uc(self):
        Uc, arch, mode = _uc()
        uc = Uc(arch, mode)
        self.map_into(uc)
        return uc

    def map_into(self, uc):
        from unicorn import UC_PROT_ALL, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
        for s in self.segments:
            start = self.base + align_down(s["vaddr"])
            size = align_up(s["vaddr"] + s["memsz"]) - align_down(s["vaddr"])
            try:
                uc.mem_map(start, size)
            except Exception:
                # 段重叠时忽略已映射部分
                pass
            # 写入文件数据（bss 部分保持 0）
            data_start = self.base + s["vaddr"]
            if s["filesz"]:
                uc.mem_write(data_start, bytes(s["data"][:s["filesz"]]))
        # 栈
        self.stack_base = 0x200000000
        uc.mem_map(self.stack_base - 0x100000, 0x200000)  # 2MB 栈
        # 仅映射 PT_LOAD，避免无开销；stub 由调用方注册

    def find_symbol(self, name):
        return self.symbols.get(name)

    def close(self):
        self.f.close()


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("用法: elf_util.py <libUE4.so>")
        sys.exit(1)
    m = ELFMapper(sys.argv[1])
    print("base     :", hex(m.base))
    print("segments :", len(m.segments))
    for s in m.segments:
        print("  PT_LOAD vaddr=%s filesz=%s memsz=%s flags=%s" % (
            hex(s["vaddr"]), hex(s["filesz"]), hex(s["memsz"]), s["flags"]))
    print("symbols  :", len(m.symbols))
    for k in list(m.symbols)[:20]:
        print(" ", k, hex(m.symbols[k]))
