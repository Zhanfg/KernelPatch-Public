#!/usr/bin/env python3
"""Source/model contracts for issue #13 untrusted KPM ELF parsing.

This test intentionally has no kernel/device dependency. It verifies the loader
orders structural validation before metadata consumption and models the key
integer/index/string rejection rules with hostile fixtures. Full fuzzing under
KASAN/UBSAN remains a separate release blocker.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / "kernel/patch/module/module.c").read_text(encoding="utf-8")
SAFETY_H = (ROOT / "kernel/patch/include/kpm_safety.h").read_text(encoding="utf-8")

# The untrusted structure gate must run before setup_load_info dereferences
# e_shstrndx, sh_name, sh_link, or string tables.
load = SRC[SRC.index("long load_module"):SRC.index("long unload_module")]
assert load.index("elf_header_check(info)") < load.index("validate_elf_structure(info)")
assert load.index("validate_elf_structure(info)") < load.index("setup_load_info(info)")

# Global limits and subtraction-based file-range checks.
for token in (
    "MAX_ELF_SECTIONS 4096U",
    "MAX_SECTION_ALIGN (1UL << 20)",
    "MAX_ELF_SYMBOLS (1UL << 20)",
    "MAX_ELF_RELOCS (1UL << 20)",
):
    assert token in SRC
assert "size <= info->len - offset" in SRC
assert "info->len < shdr->sh_offset + shdr->sh_size" not in SRC
assert "e_shstrndx >= info->hdr->e_shnum" in SRC

# Every externally supplied string offset must be bounded and NUL-terminated.
assert "static bool string_in_table" in SRC
assert "offset >= table_size" in SRC
assert "if (table[i] == '\\0') return true;" in SRC
assert "string_in_table(section_names, shstr->sh_size, sec->sh_name)" in SRC
assert "string_in_table(strings, strsec->sh_size, symbols[i].st_name)" in SRC

# Symbol and relocation indexes must point at validated sections/entries.
assert "symsec->sh_link >= info->hdr->e_shnum" in SRC
assert "shndx >= info->hdr->e_shnum" in SRC
assert "relsec->sh_link >= info->hdr->e_shnum" in SRC
assert "relsec->sh_info >= info->hdr->e_shnum" in SRC
assert "ELF64_R_SYM(rel[i].r_info) >= symcount" in SRC
assert "ELF64_R_SYM(rela[i].r_info) >= symcount" in SRC
assert "rel[i].r_offset >= target->sh_size" in SRC
assert "rela[i].r_offset >= target->sh_size" in SRC

# .kpm.info has its own bounded NUL-scanner and never strcmp/strncmp's an
# unterminated final entry outside the section.
meta = SRC[SRC.index("static char *get_next_modinfo"):SRC.index("static char *get_modinfo")]
assert "while (end < section_size && base[end] != '\\0') end++;" in meta
assert "if (end == section_size) return 0;" in meta
assert "entry_len > taglen" in meta
assert "base[cursor + taglen] == '='" in meta
assert "strncmp(p, tag, taglen)" not in meta

# kpm_safety_validate is explicitly not the structural parser anymore.
assert "Basic ELF identity/header sanity only" in SAFETY_H
assert "validate_elf_structure()" in SAFETY_H

MAX_FILE = 0x08000000
MAX_SECTIONS = 4096
MAX_ALIGN = 1 << 20


def range_ok(file_len: int, offset: int, size: int) -> bool:
    return 0 <= offset <= file_len and 0 <= size <= file_len - offset


def string_ok(table: bytes, offset: int) -> bool:
    return 0 <= offset < len(table) and b"\0" in table[offset:]


def metadata_find(section: bytes, tag: bytes):
    cursor = 0
    while cursor < len(section):
        try:
            end = section.index(0, cursor)
        except ValueError:
            return None
        entry = section[cursor:end]
        prefix = tag + b"="
        if len(entry) > len(tag) and entry.startswith(prefix):
            return entry[len(prefix):]
        cursor = end + 1
        while cursor < len(section) and section[cursor] == 0:
            cursor += 1
    return None


def basic_structure(*, file_len=1024, shnum=4, shstrndx=1,
                    shstr=b"\0.text\0.shstrtab\0.symtab\0.strtab\0",
                    section_name_offset=1, align=8,
                    section_offset=64, section_size=16,
                    sym_link=3, st_name=1,
                    strtab=b"\0symbol\0", rel_link=2, rel_info=0,
                    rel_sym=0, symcount=1, rel_offset=0,
                    target_size=16):
    if not (0 < file_len <= MAX_FILE):
        return False
    if not (0 < shnum <= MAX_SECTIONS):
        return False
    if not (0 < shstrndx < shnum):
        return False
    if not string_ok(shstr, section_name_offset):
        return False
    if align <= 0 or align > MAX_ALIGN or align & (align - 1):
        return False
    if not range_ok(file_len, section_offset, section_size):
        return False
    if not (0 <= sym_link < shnum):
        return False
    if not string_ok(strtab, st_name):
        return False
    if not (0 <= rel_link < shnum and 0 <= rel_info < shnum):
        return False
    if not (0 <= rel_sym < symcount):
        return False
    if not (0 <= rel_offset < target_size):
        return False
    return True

# Positive baseline.
assert basic_structure()

# Hostile index/string/integer fixtures.
assert not basic_structure(shstrndx=4)                 # e_shstrndx >= e_shnum
assert not basic_structure(section_name_offset=999)    # sh_name out of range
assert not basic_structure(shstr=b"\0.text")          # section name lacks final NUL
assert not basic_structure(sym_link=4)                 # SYMTAB sh_link out of range
assert not basic_structure(st_name=999)                # st_name out of range
assert not basic_structure(strtab=b"\0symbol", st_name=1)  # symbol lacks NUL
assert not basic_structure(rel_link=4)                 # relocation sh_link invalid
assert not basic_structure(rel_info=4)                 # relocation sh_info invalid
assert not basic_structure(rel_sym=1, symcount=1)      # relocation symbol invalid
assert not basic_structure(rel_offset=16, target_size=16)
assert not basic_structure(align=(1 << 21))             # oversized alignment
assert not basic_structure(align=3)                     # non-power-of-two alignment
assert not basic_structure(file_len=100, section_offset=90, section_size=20)
assert not basic_structure(file_len=MAX_FILE + 1)
assert not basic_structure(shnum=MAX_SECTIONS + 1)

# Metadata parsing: valid fields work; malformed trailing entry is rejected
# without scanning outside the supplied section.
assert metadata_find(b"name=demo\0version=1\0", b"name") == b"demo"
assert metadata_find(b"name=demo", b"name") is None
assert metadata_find(b"name=demo\0description=unterminated", b"description") is None
assert metadata_find(b"x=1\0name=demo\0", b"name") == b"demo"

print("Issue #13 hostile ELF parser source/model contracts passed.")
