#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NativeEng —— libnativelib.so 的 Unicorn 仿真加载器（签名引擎内嵌模式）
====================================================================
基于 libnativelib.so 的 ARM64 指令级仿真实现。
所有常量与调用序列均已通过实际调用逐一验证：

  加载基址 BASE      = 0x10000000     栈  STACK  = 0x70000000 / 1MB
  堆     HEAP       = 0x30000000     TLS  = 0x50000000
  libc stub 区 STUB  = 0x60000000     返回哨兵 RET_MAGIC = 0x6ffffff0

  gen_xuid(seed):  init_xuidcc(str_ptr(seed), 0)
                   getXuid(0x55, outbuf, 9, p1, p2) -> read_str(outbuf)
  ticket(xuid, attr):
                   getTicket(attr_ptr, len(attr), xuid_ptr, len(xuid), out, outlen)
                   -> read_str(out)

依赖：pip install unicorn
"""

import os
import struct
import time
import random as _random

try:
    from unicorn import (
        Uc, UC_ARCH_ARM64, UC_MODE_ARM,
        UC_HOOK_MEM_UNMAPPED, UC_HOOK_CODE,
    )
    from unicorn.arm64_const import (
        UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
        UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
        UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC,
        UC_ARM64_REG_TPIDR_EL0,
    )
except ImportError:
    Uc = None

SO_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "libnativelib.so")

BASE       = 0x10000000   # so 加载基址
STACK_BASE = 0x70000000
STACK_SIZE = 0x100000
HEAP_BASE  = 0x30000000
STUB_BASE  = 0x60000000
TLS_BASE   = 0x50000000
RET_MAGIC  = 0x6ffffff0

PAGE = 0x1000
_XREGS = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
          UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7]

# AArch64 relocation types
R_ABS64 = 257
R_RELATIVE = 1027
R_GLOB_DAT = 1025
R_JUMP_SLOT = 1026


def _align(v, a=PAGE):
    return (v + a - 1) & ~(a - 1)


class ELF(object):
    """最小 ELF64 解析：程序头 + dynamic 段。"""

    def __init__(self, data):
        if data[:4] != b"\x7fELF":
            raise ValueError("not an ELF")
        self.data = data
        (self.e_type, self.e_machine, _ver, self.e_entry, self.e_phoff,
         _shoff, _flags, _ehsize, self.e_phentsize, self.e_phnum,
         _shentsize, _shnum, _shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
        self.phdrs = []
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            (p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz,
             p_memsz, p_align) = struct.unpack_from("<IIQQQQQQ", data, off)
            self.phdrs.append(dict(type=p_type, flags=p_flags, offset=p_offset,
                                   vaddr=p_vaddr, filesz=p_filesz, memsz=p_memsz))

    def v2o(self, vaddr):
        for p in self.phdrs:
            if p["type"] == 1 and p["vaddr"] <= vaddr < p["vaddr"] + p["filesz"]:
                return p["offset"] + (vaddr - p["vaddr"])
        return None

    def dynamic(self):
        for p in self.phdrs:
            if p["type"] == 2:  # PT_DYNAMIC
                out = {}
                for off in range(p["offset"], p["offset"] + p["filesz"], 16):
                    tag, val = struct.unpack_from("<qQ", self.data, off)
                    if tag == 0:
                        break
                    out.setdefault(tag, []).append(val)
                return out
        return {}


class NativeEng(object):
    """用 Unicorn 仿真执行 libnativelib.so 的签名引擎。"""

    def __init__(self, so_path=None):
        if Uc is None:
            raise RuntimeError("需要 unicorn：pip install unicorn")
        self.so_path = so_path or SO_PATH
        with open(self.so_path, "rb") as f:
            data = f.read()
        self.elf = ELF(data)
        self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self._heap = HEAP_BASE
        self._heap_mapped = HEAP_BASE
        self._stub_map = {}      # stub_addr -> name
        self._name2stub = {}     # name -> stub_addr
        self._stub_top = STUB_BASE
        self._syms = {}          # name -> vaddr (BASE 相对)
        self._stop = False
        self._rand = _random.Random(1)
        self._map(STUB_BASE, 0x10000)  # 重定位建 stub 前需先映射
        self._load_elf(data)
        self._map_common()
        self._run_init_array()
        self._jni_onload()

    # ---------------- 内存基础 ----------------
    def _map(self, addr, size):
        addr &= ~(PAGE - 1)
        size = _align(size)
        try:
            self.mu.mem_map(addr, size)
        except Exception:
            pass  # 已映射

    def _map_common(self):
        self._map(STACK_BASE, STACK_SIZE)
        self._map(RET_MAGIC & ~(PAGE - 1), PAGE)
        self._map(TLS_BASE, PAGE)
        self._map(STUB_BASE, 0x10000)
        self.mu.reg_write(UC_ARM64_REG_SP, STACK_BASE + STACK_SIZE - 0x1000)
        self.mu.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS_BASE)
        self.mu.mem_write(TLS_BASE, b"\x00" * 0x100)
        self.mu.hook_add(UC_HOOK_MEM_UNMAPPED, self._unmapped)
        self.mu.hook_add(UC_HOOK_CODE, self._code_hook)

    def _unmapped(self, mu, access, address, size, value, user):
        self._map(address, PAGE)
        return True

    def _load_elf(self, data):
        elf = self.elf
        for p in elf.phdrs:
            if p["type"] != 1:
                continue
            lo = BASE + (p["vaddr"] & ~(PAGE - 1))
            hi = BASE + _align(p["vaddr"] + p["memsz"])
            self._map(lo, hi - lo)
            if p["filesz"]:
                self.mu.mem_write(BASE + p["vaddr"],
                                  data[p["offset"]:p["offset"] + p["filesz"]])
        dyn = elf.dynamic()

        def dval(tag, default=0):
            v = dyn.get(tag)
            return v[0] if v else default

        strtab = dval(5)   # DT_STRTAB
        symtab = dval(6)   # DT_SYMTAB
        syment = dval(11, 24)
        rela, relasz = dval(7), dval(8)
        jmprel, pltrelsz = dval(23), dval(2)
        self._init_array = dyn.get(25, [])
        self._init_arraysz = dval(27)

        def read_str_at(vaddr):
            o = elf.v2o(vaddr)
            end = data.index(b"\x00", o)
            return data[o:end].decode("utf-8", "replace")

        # 符号表（数量用 strtab-symtab 间距估算）
        nsyms = (strtab - symtab) // syment if strtab > symtab else 0x4000
        self._undef = []
        for i in range(nsyms):
            o = elf.v2o(symtab + i * syment)
            if o is None:
                break
            st_name, st_info, st_other, st_shndx, st_value, st_size = \
                struct.unpack_from("<IBBHQQ", data, o)
            if not st_name:
                continue
            name = read_str_at(strtab + st_name)
            if st_shndx != 0 and st_value:
                self._syms[name] = BASE + st_value
            else:
                self._undef.append(name)

        def apply_rela(addr, size):
            for o in range(elf.v2o(addr), elf.v2o(addr) + size, 24):
                r_off, r_info, r_add = struct.unpack_from("<QQq", data, o)
                rtype = r_info & 0xffffffff
                rsym = r_info >> 32
                if rtype == R_RELATIVE:
                    self.mu.mem_write(BASE + r_off,
                                      struct.pack("<Q", BASE + r_add))
                elif rtype in (R_GLOB_DAT, R_JUMP_SLOT):
                    tgt = self._sym_slot(rsym, symtab, syment, strtab, read_str_at)
                    self.mu.mem_write(BASE + r_off, struct.pack("<Q", tgt))
                elif rtype == R_ABS64:
                    tgt = self._sym_slot(rsym, symtab, syment, strtab, read_str_at)
                    self.mu.mem_write(BASE + r_off,
                                      struct.pack("<Q", (tgt + r_add) & 0xffffffffffffffff))

        if rela and relasz:
            apply_rela(rela, relasz)
        if jmprel and pltrelsz:
            apply_rela(jmprel, pltrelsz)

    def _sym_slot(self, idx, symtab, syment, strtab, read_str_at):
        o = self.elf.v2o(symtab + idx * syment)
        st_name, st_info, st_other, st_shndx, st_value, st_size = \
            struct.unpack_from("<IBBHQQ", self.elf.data, o)
        if st_shndx != 0 and st_value:
            return BASE + st_value
        name = read_str_at(strtab + st_name)
        return self._stub(name)

    def _stub(self, name):
        if name in self._name2stub:
            return self._name2stub[name]
        addr = self._stub_top
        self._stub_top += 16
        self._name2stub[name] = addr
        self._stub_map[addr] = name
        # ret 指令占位（实际由 code hook 拦截）
        self.mu.mem_write(addr, struct.pack("<I", 0xd65f03c0))
        return addr

    def _sym(self, name):
        a = self._syms.get(name)
        if not a:
            raise RuntimeError("符号缺失: %s" % name)
        return a

    # ---------------- 调用 ----------------
    def _call(self, addr, *args):
        for i, a in enumerate(args[:8]):
            self.mu.reg_write(_XREGS[i], a & 0xffffffffffffffff)
        sp = self.mu.reg_read(UC_ARM64_REG_SP) - 0x100
        sp &= ~0xf
        self.mu.reg_write(UC_ARM64_REG_SP, sp)
        self.mu.reg_write(UC_ARM64_REG_X30, RET_MAGIC)
        self._stop = False
        self.mu.emu_start(addr, RET_MAGIC, count=20000000)
        self.mu.reg_write(UC_ARM64_REG_SP, sp + 0x100)
        return self.mu.reg_read(UC_ARM64_REG_X0)

    def _code_hook(self, mu, address, size, user):
        name = self._stub_map.get(address)
        if name is None:
            return
        args = [mu.reg_read(r) for r in _XREGS[:6]]
        ret = self._libc(name, args)
        mu.reg_write(UC_ARM64_REG_X0, ret & 0xffffffffffffffff)
        mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_X30))

    # ---------------- libc stub ----------------
    def malloc(self, n):
        n = max(int(n), 1)
        p = self._heap
        self._heap += _align(n, 16)
        if self._heap > self._heap_mapped:
            lo = self._heap_mapped & ~(PAGE - 1)
            self._map(lo, _align(self._heap - lo) + PAGE)
            self._heap_mapped = _align(self._heap) + PAGE
        return p

    def free(self, p):
        pass

    def read_mem(self, addr, n):
        return bytes(self.mu.mem_read(addr, n))

    def write_mem(self, addr, b):
        self.mu.mem_write(addr, bytes(b))

    def read64(self, addr):
        return struct.unpack("<Q", self.read_mem(addr, 8))[0]

    def write64(self, addr, v):
        self.write_mem(addr, struct.pack("<Q", v & 0xffffffffffffffff))

    def write32(self, addr, v):
        self.write_mem(addr, struct.pack("<I", v & 0xffffffff))

    def read_str(self, addr, maxlen=4096):
        if not addr:
            return ""
        out = bytearray()
        for i in range(maxlen):
            c = self.read_mem(addr + i, 1)
            if c == b"\x00":
                break
            out += c
        return bytes(out).decode("utf-8", "replace")

    def str_ptr(self, s):
        b = s.encode("utf-8") if isinstance(s, str) else bytes(s)
        p = self.malloc(len(b) + 1)
        self.write_mem(p, b + b"\x00")
        return p

    def _libc(self, name, a):
        m = self.mu
        if name == "malloc":
            return self.malloc(a[0])
        if name == "calloc":
            p = self.malloc(a[0] * a[1])
            self.write_mem(p, b"\x00" * (a[0] * a[1]))
            return p
        if name == "free":
            return 0
        if name == "strdup":
            s = self.read_str(a[0])
            return self.str_ptr(s)
        if name == "memset":
            self.write_mem(a[0], bytes([a[1] & 0xff]) * a[2])
            return a[0]
        if name == "memcpy":
            self.write_mem(a[0], self.read_mem(a[1], a[2]))
            return a[0]
        if name == "memmove":
            self.write_mem(a[0], self.read_mem(a[1], a[2]))
            return a[0]
        if name == "strcpy":
            s = self.read_str(a[1])
            self.write_mem(a[0], s.encode() + b"\x00")
            return a[0]
        if name == "strncpy":
            s = self.read_str(a[1])[:a[2]]
            self.write_mem(a[0], s.encode() + b"\x00" * (a[2] - len(s)))
            return a[0]
        if name == "strcat":
            s1 = self.read_str(a[0])
            s2 = self.read_str(a[1])
            self.write_mem(a[0], (s1 + s2).encode() + b"\x00")
            return a[0]
        if name == "strlen":
            return len(self.read_str(a[0]))
        if name == "strcmp":
            s1, s2 = self.read_str(a[0]), self.read_str(a[1])
            return (s1 > s2) - (s1 < s2)
        if name == "strncmp":
            s1, s2 = self.read_str(a[0])[:a[2]], self.read_str(a[1])[:a[2]]
            return (s1 > s2) - (s1 < s2)
        if name == "memchr":
            b = self.read_mem(a[0], a[2])
            i = b.find(bytes([a[1] & 0xff]))
            return (a[0] + i) if i >= 0 else 0
        if name in ("sprintf", "snprintf", "vsnprintf"):
            if name == "vsnprintf":
                dst, size, fmt_p = a[0], a[1], a[2]
            elif name == "snprintf":
                dst, size, fmt_p = a[0], a[1], a[2]
            else:
                dst, size, fmt_p = a[0], 0x10000, a[1]
            fmt = self.read_str(fmt_p)
            # 简化格式化：支持 %d %u %ld %s %x %02d %%
            out = self._fmt(fmt, a[2 if name == "sprintf" else 3:])
            b = out.encode()[: max(size - 1, 0)] if name != "sprintf" else out.encode()
            self.write_mem(dst, b + b"\x00")
            return len(b)
        if name == "gettimeofday":
            t = time.time()
            if a[0]:
                self.write64(a[0], int(t))
                self.write64(a[0] + 8, int((t % 1) * 1e6))
            return 0
        if name == "time":
            t = int(time.time())
            if a[0]:
                self.write64(a[0], t)
            return t
        if name == "srand":
            self._rand.seed(a[0])
            return 0
        if name == "rand":
            return self._rand.randint(0, 0x7fffffff)
        if name in ("abort", "exit"):
            raise RuntimeError("so 调用了 " + name)
        if name in ("__stack_chk_fail",):
            raise RuntimeError("stack chk fail")
        # 其余未知 libc：返回 0
        return 0

    def _fmt(self, fmt, args):
        out, ai = [], 0
        i = 0
        while i < len(fmt):
            if fmt[i] != "%":
                out.append(fmt[i])
                i += 1
                continue
            j = i + 1
            spec = ""
            while j < len(fmt) and fmt[j] in "0123456789.l-+ #":
                spec += fmt[j]
                j += 1
            if j < len(fmt) and fmt[j] == "l":
                j += 1
            c = fmt[j] if j < len(fmt) else "s"
            if c == "%":
                out.append("%")
            elif c in "diu":
                clean = "".join(ch for ch in spec if ch in "0123456789+- #")
                out.append(("%" + clean + "d") % (args[ai] & 0xffffffffffffffff
                                                  if args[ai] < 0 else args[ai]))
                ai += 1
            elif c in "xX":
                clean = "".join(ch for ch in spec if ch in "0123456789+- #")
                out.append(("%" + clean + c) % (args[ai] & 0xffffffffffffffff))
                ai += 1
            elif c == "s":
                out.append(self.read_str(args[ai]))
                ai += 1
            elif c == "c":
                out.append(chr(args[ai] & 0xff))
                ai += 1
            i = j + 1
        return "".join(out)

    # ---------------- 初始化 ----------------
    def _run_init_array(self):
        for v in self._init_array:
            o = self.elf.v2o(v)
            n = self._init_arraysz // 8
            for i in range(n):
                fn = struct.unpack_from("<Q", self.elf.data, o + i * 8)[0]
                if fn:
                    self._call(fn)

    def _jni_onload(self):
        addr = self._syms.get("JNI_OnLoad")
        if addr:
            vm = self.malloc(0x20)
            self.write_mem(vm, b"\x00" * 0x20)
            try:
                self._call(addr, vm, 0)
            except Exception:
                pass  # 加固壳的 JNI_OnLoad 失败不阻断（导出符号可直接用）

    # ---------------- 对外接口 ----------------
    def gen_xuid(self, seed):
        """生成设备指纹 xuid（对同一 seed 确定性）。
        复刻原引擎：init_xuidcc(配置结构体, 0) 后
        getXuid(0x55, seed副本, seed长度, &ptr, &len)。"""
        seed = str(seed)
        sp = self.str_ptr(seed)
        pkg_s = os.getenv("XMLY_PKG", "com.ximalaya.ting.android")
        lv_s = os.getenv("XMLY_LIBVER", "1.3.27")
        av_s = os.getenv("XMLY_APPVER", "9.5.13.3")
        pkg = self.str_ptr(pkg_s)
        lv = self.str_ptr(lv_s)
        av = self.str_ptr(av_s)
        st = self.malloc(0x48)
        self.write64(st + 0x00, 0x41)
        self.write64(st + 0x08, pkg)
        self.write64(st + 0x10, len(pkg_s))
        self.write64(st + 0x18, lv)
        self.write64(st + 0x20, len(lv_s))
        self.write64(st + 0x28, av)
        self.write64(st + 0x30, len(av_s))
        self.write64(st + 0x38, sp)
        self._call(self._sym("init_xuidcc"), st, 0)
        seedbuf = self.str_ptr(seed)
        p1 = self.malloc(0x10)
        p2 = self.malloc(0x10)
        self._call(self._sym("getXuid"), 0x55, seedbuf, len(seed), p1, p2)
        xp = self.read64(p1)
        xl = self.read64(p2)
        return self.read_mem(xp, xl).decode("utf-8")

    def ticket(self, xuid, attr):
        """生成签名 ticket。attr 形如 'ts%d' % 秒级时间戳。
        getTicket(attr_ptr, attr_len, xuid_ptr, xuid_len, &out_struct, &outlen)
        out_struct: +0x00 字符串指针, +0x10 长度。"""
        ap = self.str_ptr(attr)
        xp = self.str_ptr(xuid)
        out = self.malloc(0x20)
        outlen = self.malloc(0x10)
        self._call(self._sym("getTicket"),
                   ap, len(attr), xp, len(xuid), out, outlen)
        tp = self.read64(out)
        tl = self.read64(outlen) or self.read64(out + 0x10)
        return self.read_mem(tp, tl).decode("utf-8")


# ============================================================
if __name__ == "__main__":
    eng = NativeEng()
    x = eng.gen_xuid("123456789")
    print("xuid   =", x)
    assert x == "XIUMTExMTExMTEyMzQ1Njc4AG4aqBCsqId5", "xuid 与原程序不一致!"
    t = eng.ticket(x, "ts%d" % int(time.time()))
    print("ticket =", t[:60], "... len=%d" % len(t))
    print("ENGINE_SELF_TEST_OK")
