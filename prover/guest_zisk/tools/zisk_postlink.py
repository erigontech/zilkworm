#!/usr/bin/env python3
# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0
"""ZisK post-link step for the guest ELF (edits it in place, idempotent).

1. Rewrites every ebreak in executable segments to the ZisK halt word.
2. Checks the ISA, segment layout, memory-map symbols and TLS.

Exits 1 on any violation and renames the ELF to <ELF>.rejected.
Usage: zisk_postlink.py ELF
"""

import os
import struct
import sys

EBREAK = 0x00100073
HALT = 0xFFFFFFFF  # CHalt: halt with error

ROM = (0x8000_0000, 0x87F0_0000)  # excludes the float-lib ROM
RAM = (0xA000_0000, 0xC000_0000)

EXPECTED_SYMBOLS = {
    "_init_stack_top": 0xA040_0000,
    "_general_registers_data_start": 0xA040_0000,
    "_output_data_start": 0xA041_0000,
    "_heap_top": 0xBFFF_0000,
}

FORBIDDEN_OPCODES = {
    0x2F: "A (amo/lr/sc)",
    0x07: "F/D load",
    0x27: "F/D store",
    0x43: "fmadd",
    0x47: "fmsub",
    0x4B: "fnmsub",
    0x4F: "fnmadd",
    0x53: "op-fp",
}

ET_EXEC = 2
EM_RISCV = 243
EF_RISCV_RVC = 0x1
EF_RISCV_FLOAT_ABI = 0x6
PT_LOAD = 1
PT_TLS = 7
PF_X, PF_W = 0x1, 0x2
SHT_SYMTAB = 2
SHF_TLS = 0x400

EHDR = struct.Struct("<HHIQQQIHHHHHH")
PHDR = struct.Struct("<IIQQQQQQ")
SHDR = struct.Struct("<IIQQQQIIQQ")
SYM = struct.Struct("<IBBHQQ")
WORD = struct.Struct("<I")


def cstr(buf, off):
    return bytes(buf[off:buf.index(b"\0", off)]).decode()


def in_range(start, end, rng):
    return rng[0] <= start and end <= rng[1]


class Elf:
    def __init__(self, buf):
        if buf[:4] != b"\x7fELF" or buf[4] != 2 or buf[5] != 1:
            raise ValueError("not an ELF64 little-endian file")
        (self.e_type, self.e_machine, _, self.e_entry, phoff, shoff, self.e_flags,
         _, phentsize, phnum, shentsize, shnum, shstrndx) = EHDR.unpack_from(buf, 16)
        self.phdrs = [PHDR.unpack_from(buf, phoff + i * phentsize) for i in range(phnum)]
        shdrs = [SHDR.unpack_from(buf, shoff + i * shentsize) for i in range(shnum)]
        shstr_off = shdrs[shstrndx][4] if shnum else 0
        self.sections = [(cstr(buf, shstr_off + s[0]),) + s[1:] for s in shdrs]
        self.symbols = {}
        for _, sh_type, _, _, off, size, link, _, _, entsize in self.sections:
            if sh_type != SHT_SYMTAB:
                continue
            str_off = self.sections[link][4]
            for i in range(size // entsize):
                st_name, _, _, _, value, _ = SYM.unpack_from(buf, off + i * entsize)
                if st_name:
                    self.symbols.setdefault(cstr(buf, str_off + st_name), value)

    def section(self, name):
        return next((s for s in self.sections if s[0] == name), None)


def rewrite_and_check_code(buf, elf, errors):
    rewritten = 0
    zero_words = 0
    bad = {}
    for p_type, p_flags, p_offset, p_vaddr, _, p_filesz, _, _ in elf.phdrs:
        if p_type != PT_LOAD or not p_flags & PF_X:
            continue
        if p_offset % 4 or p_vaddr % 4 or p_filesz % 4:
            errors.append(f"exec segment 0x{p_vaddr:x} not 4-byte aligned/sized")
            continue
        for i, (w,) in enumerate(WORD.iter_unpack(buf[p_offset:p_offset + p_filesz])):
            addr = p_vaddr + 4 * i
            if w == EBREAK:
                WORD.pack_into(buf, p_offset + 4 * i, HALT)
                rewritten += 1
            elif w == 0:
                zero_words += 1  # padding; decodes to CHalt
            elif w & 3 != 3:
                bad.setdefault("compressed (C)", []).append(addr)
            elif w & 0x7F in FORBIDDEN_OPCODES:
                bad.setdefault(FORBIDDEN_OPCODES[w & 0x7F], []).append(addr)
    for kind, addrs in bad.items():
        sample = ", ".join(f"0x{a:x}" for a in addrs[:4])
        errors.append(f"{len(addrs)} {kind} instruction(s) at {sample}")
    return rewritten, zero_words


def check_header(elf, errors):
    if elf.e_type != ET_EXEC or elf.e_machine != EM_RISCV:
        errors.append("not a RISC-V ET_EXEC")
    if elf.e_flags & EF_RISCV_RVC:
        errors.append("e_flags has RVC (compressed) set")
    if elf.e_flags & EF_RISCV_FLOAT_ABI:
        errors.append("e_flags float ABI is not soft-float (lp64)")


def check_segments(elf, errors):
    loaded = []
    for p_type, p_flags, _, p_vaddr, _, p_filesz, p_memsz, _ in elf.phdrs:
        if p_type == PT_TLS:
            errors.append("PT_TLS segment present")
        if p_type != PT_LOAD:
            continue
        end = p_vaddr + p_memsz
        name = f"PT_LOAD 0x{p_vaddr:x}-0x{end:x}"
        if p_flags & PF_W and p_flags & PF_X:
            errors.append(f"{name} is both W and X")
        if p_flags & PF_X:
            if not in_range(p_vaddr, end, ROM):
                errors.append(f"{name} is executable but outside ROM")
            if p_filesz != p_memsz:
                errors.append(f"{name} is executable with a zero-fill tail")
        elif p_flags & PF_W:
            if not in_range(p_vaddr, end, RAM):
                errors.append(f"{name} is writable but outside RAM")
        elif not (in_range(p_vaddr, end, ROM) or in_range(p_vaddr, end, RAM)):
            errors.append(f"{name} is outside ROM and RAM")
        for o_start, o_end in loaded:
            if p_vaddr < o_end and o_start < end:
                errors.append(f"{name} overlaps 0x{o_start:x}-0x{o_end:x}")
        loaded.append((p_vaddr, end))


def check_symbols(elf, errors):
    start = elf.symbols.get("_start")
    if start is None:
        errors.append("_start missing")
    elif start != elf.e_entry or not ROM[0] <= start < ROM[1]:
        errors.append(f"_start 0x{start:x} != e_entry 0x{elf.e_entry:x} or not in ROM")
    for name, expected in EXPECTED_SYMBOLS.items():
        value = elf.symbols.get(name)
        if value != expected:
            got = "missing" if value is None else f"0x{value:x}"
            errors.append(f"{name} = {got}, expected 0x{expected:x}")
    bottom = elf.symbols.get("_heap_bottom")
    if bottom is None or bottom >= EXPECTED_SYMBOLS["_heap_top"]:
        errors.append("_heap_bottom missing or above _heap_top")


def check_tls(elf, errors):
    for name, _, flags, *_ in elf.sections:
        if name.startswith((".tdata", ".tbss")) or flags & SHF_TLS:
            errors.append(f"TLS section {name} present")


def main():
    if len(sys.argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    path = sys.argv[1]
    with open(path, "rb") as f:
        buf = bytearray(f.read())
    original = bytes(buf)

    errors = []
    elf = Elf(buf)
    check_header(elf, errors)
    rewritten, zero_words = rewrite_and_check_code(buf, elf, errors)
    check_segments(elf, errors)
    check_symbols(elf, errors)
    check_tls(elf, errors)

    print(f"ebreak->halt: {rewritten}")
    if errors:
        for e in errors:
            print(f"zisk_postlink: error: {e}", file=sys.stderr)
        os.replace(path, path + ".rejected")
        print(f"zisk_postlink: moved ELF to {path}.rejected", file=sys.stderr)
        return 1

    if buf != original:
        with open(path, "r+b") as f:
            f.write(buf)

    heap_bottom = elf.symbols["_heap_bottom"]
    heap_top = EXPECTED_SYMBOLS["_heap_top"]
    init_array = elf.section(".init_array")
    init_entries = init_array[5] // 8 if init_array else 0
    print(f"zero padding words: {zero_words}, .init_array entries: {init_entries}")
    print(f"heap: 0x{heap_bottom:x}-0x{heap_top:x} ({(heap_top - heap_bottom) / (1 << 20):.1f} MiB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
