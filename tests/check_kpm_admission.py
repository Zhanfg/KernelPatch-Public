#!/usr/bin/env python3
"""Compare kptools and the loader on identical bytes, then run a benign KPM on the host."""
import os
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SHDR = struct.Struct("<IIQQQQIIQQ")


def build(tmp):
    # Compile module.c and relo.c in full. Only replace headers for kernel services.
    for name in """
        uapi/asm-generic/errno.h pgtable.h kpmalloc.h linux/err.h linux/string.h symbol.h
        kallsyms.h cache.h common.h linux/fs.h uapi/linux/fs.h hotpatch.h linux/list.h
        linux/kernel.h linux/spinlock.h linux/slab.h linux/vmalloc.h linux/rcupdate.h
        linux/rculist.h compact.h selinux_hide.h proc_hide.h kpm_safety.h accctl.h
        linux/printk.h linux/elf.h ktypes.h
    """.split():
        path = tmp / name
        path.parent.mkdir(exist_ok=True, parents=True)
        path.touch()
    driver = tmp / "driver"
    subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O2", "-Wall", "-Werror",
                    "-ffunction-sections", "-Wl,--gc-sections", "-I", tmp,
                    "-I", ROOT / "kernel/patch/include", "-idirafter", ROOT / "kernel/include",
                    "-idirafter", ROOT / "kernel/linux/include", ROOT / "tests/kpm_admission_test.c",
                    ROOT / "tools/kpm.c", ROOT / "tools/common.c", "-o", driver], check=True)
    return driver


def benign_kpm(with_exit):
    # ELF64 LE with only data sections. ABS64 RELAs populate the SDK callback slots
    # from named host functions. No ARM instructions or executable pages are needed.
    data = bytearray(64)
    sections = [None]
    strings = bytearray(b"\0")
    offsets = {}

    def string(value):
        offset = len(strings)
        strings.extend(value.encode() + b"\0")
        return offset

    def section(name, kind, flags, content, align=1, link=0, info=0, entsize=0):
        data.extend(bytes(-len(data) % align))
        result = len(sections)
        offsets[name] = result
        sections.append((string(name), kind, flags, 0, len(data), len(content), link, info, align, entsize))
        data.extend(content)
        return result

    callbacks = [("init", "benign_init"), ("ctl0", "benign_control")]
    if with_exit:
        callbacks.append(("exit", "benign_exit"))
    symbols = bytearray(24)  # STN_UNDEF
    for _, symbol in callbacks:
        symbols.extend(struct.pack("<IBBHQQ", string(symbol), 0x12, 0, 0, 0, 0))
    # Section 1 will be the combined section-name and symbol-name string table.
    sections.append(None)
    sym = section(".symtab", 2, 0, symbols, 8, link=1, info=1, entsize=24)
    section(".kpm.info", 1, 2, b"name=benign\0version=1\0")
    for index, (slot, _) in enumerate(callbacks, 1):
        target = section(".kpm." + slot, 1, 3, bytes(8), 8)
        rela = struct.pack("<QQq", 0, index << 32 | 257, 0)  # R_AARCH64_ABS64
        section(".rela.kpm." + slot, 4, 0, rela, 8, link=sym, info=target, entsize=24)
    for name in (".init.text", ".exit.text"):
        string(name)
    names = string(".strtab")
    sections[1] = (names, 3, 0, 0, len(data), len(strings), 0, 0, 1, 0)
    data.extend(strings)
    data.extend(bytes(-len(data) % 8))
    table = len(data)
    for sh in sections:
        data.extend(SHDR.pack(*sh) if sh else bytes(SHDR.size))
    struct.pack_into("<16sHHIQQQIHHHHHH", data, 0, b"\x7fELF\x02\x01\x01", 1, 183, 1, 0, 0,
                     table, 0, 64, 0, 0, SHDR.size, len(sections), 1)
    return data, {name: table + i * SHDR.size for name, i in offsets.items()}, strings


def main():
    with tempfile.TemporaryDirectory(prefix="kpm-admission-") as directory:
        tmp = Path(directory)
        driver = build(tmp)

        def check(mode, path):
            subprocess.run([driver, mode, path], check=True)

        samples = ROOT / "tests/kpm"
        check("reject", samples / "DevSafe_android15-6.6.ko")
        for path in sorted(samples.glob("*.kpm")):
            check("admit", path)
        path = tmp / "fixture"
        for has_exit in (False, True):
            data, sh, names = benign_kpm(has_exit)
            path.write_bytes(data)
            check("with-exit" if has_exit else "without-exit", path)

        init = sh[".kpm.init"]
        rel = sh[".rela.kpm.init"]
        entry = SHDR.unpack_from(data, rel)[4]
        # Each mutation starts from the admitted with-exit fixture. For REL, use
        # the actual implicit-addend entry size, including a non-allocated target.
        for edits in (
            [(init, "I", names.index(b".init.text\0"))],
            [(sh[".kpm.exit"], "I", names.index(b".exit.text\0"))],
            [(rel + 4, "I", 9), (rel + 32, "Q", 16), (rel + 56, "Q", 16)],
            [(rel + 4, "I", 9), (rel + 32, "Q", 16), (rel + 56, "Q", 16), (rel + 44, "I", 1)],
            [(init + 8, "Q", 0)], [(init + 8, "Q", 6)], [(init + 4, "I", 8)],
            [(sh[".kpm.ctl0"] + 32, "Q", 7)], [(sh[".kpm.info"] + 8, "Q", 0)],
            [(sh[".symtab"] + 4, "I", 1)], [(rel + 40, "I", 1)], [(rel + 56, "Q", 16)],
            [(rel + 32, "Q", 23)], [(entry, "Q", 1)], [(entry, "Q", (1 << 64) - 1)],
            [(entry + 8, "Q", 4 << 32 | 257)], [(entry + 8, "Q", 1 << 32 | 65535)],
        ):
            sample = bytearray(data)
            for offset, fmt, value in edits:
                struct.pack_into("<" + fmt, sample, offset, value)
            path.write_bytes(sample)
            check("reject", path)
    print("KPM host/loader admission and init/control/unload with and without exit passed")


if __name__ == "__main__":
    main()
