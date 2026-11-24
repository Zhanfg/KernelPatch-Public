#!/usr/bin/env python3
"""Run after 'make -C kernel hdr TARGET_COMPILE=placeholder && make -C tools' on Linux."""
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import tempfile

from check_kpm_rcu_paths import find_functions

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
CLI = TOOLS / "kptools"
KPM_LIMIT = 128 << 20
IMAGE_LIMIT = 512 << 20


def build_driver(tmp):
    functions = [
        ("kernel/patch/module/module.c", "long load_module_path(const char *path, const char *args, void *reserved)"),
        ("kernel/patch/common/supercall.c", "static long call_skey_set(char *new_key)"),
        ("tools/patch.c", "static void set_image_superkey(setup_preset_t *setup, const char *superkey, bool root_key)"),
    ]
    definitions = []
    for path, signature in functions:
        name = signature.split("(")[0].split()[-1]
        definitions.append(signature + "\n" + find_functions((ROOT / path).read_text())[name][1])
    (tmp / "parser_keys_under_test.h").write_text("\n".join(definitions))
    driver = tmp / "driver"
    objects = [obj for obj in TOOLS.glob("*.o") if obj.name != "kptools.o"]
    subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Werror", "-I", TOOLS,
                    "-I", tmp, ROOT / "tests/parser_keys_test.c", *objects, *TOOLS.glob("lib/*/*.o"),
                    "-Wl,--wrap=fread,--wrap=malloc", "-lz", "-o", driver], check=True)
    return driver


def run(tmp, args, error=None):
    result = subprocess.run(args, cwd=tmp, capture_output=True, timeout=10)
    output = result.stdout + result.stderr
    if error is None:
        assert result.returncode == 0, (args[0:2], result.returncode, output)
    else:
        assert result.returncode > 0 and error in result.stderr, (args[0:2], result.returncode, output)
    return output


def kpm_checks(tmp, driver):
    # Use a valid KPM from the repository. Change one field per rejection case.
    fixture = (ROOT / "tests/kpm/selinux_hook_1.1.0.kpm").read_bytes()
    path = tmp / "sample.kpm"
    path.write_bytes(fixture)
    assert b"version=1.1.0\n" in run(tmp, [CLI, "-l", "-M", path])
    table, = struct.unpack_from("<Q", fixture, 40)
    entsize, count, names_index = struct.unpack_from("<HHH", fixture, 58)
    sections = [struct.unpack_from("<IIQQQQIIQQ", fixture, table + i * entsize) for i in range(count)]
    names, names_size = sections[names_index][4:6]
    sym_index = next(i for i, sh in enumerate(sections) if sh[1] == 2)
    sym = sections[sym_index]
    strings = sections[sym[6]]
    info = next(sh for sh in sections if fixture.startswith(b".kpm.info\0", names + sh[0]))
    for label, offset, fmt, value in [
        ("empty section table", 60, "H", 0),
        ("section table extent", 40, "Q", len(fixture)),
        ("section name table index", 62, "H", count),
        ("section name table type", table + names_index * entsize + 4, "I", 8),
        ("section extent", table + entsize + 24, "Q", (1 << 64) - 1),
        ("section name index", table + entsize, "I", names_size),
        ("section name terminator", names + names_size - 1, "B", 65),
        ("symbol string table index", table + sym_index * entsize + 40, "I", count),
        ("symbol name index", sym[4], "I", strings[5]),
        ("symbol string terminator", strings[4] + strings[5] - 1, "B", 65),
        ("metadata terminator", info[4] + info[5] - 1, "B", 65),
    ]:
        sample = bytearray(fixture)
        struct.pack_into("<" + fmt, sample, offset, value)
        path.write_bytes(sample)
        assert b"[kpm]" not in run(tmp, [CLI, "-l", "-M", path], b"invalid KPM"), label
    with path.open("wb") as f:
        f.truncate(KPM_LIMIT + 1)
    run(tmp, [driver, "list", path], b"file too large")
    run(tmp, [CLI, "-l", "-M", path], b"file too large")


def boot_checks(tmp, driver):
    path = tmp / "boot.img"
    kernel = tmp / "kernel"
    payload = b"raw!"
    header = bytearray(4096)
    struct.pack_into("<8sI", header, 0, b"ANDROID!", len(payload))
    struct.pack_into("<I", header, 36, 4096)
    path.write_bytes(header + payload)
    run(tmp, [CLI, "unpacknolog", path])
    assert kernel.read_bytes() == payload
    kernel.unlink()
    # The merged reader loads the whole image before decoding, so a short
    # payload is a truncated file rather than a short fread at the kernel
    # offset; the property (explicit failure, no output file) is the same.
    path.write_bytes(header + payload[:-1])
    run(tmp, [driver, "unpack", path], b"truncated")
    assert not kernel.exists()
    path.write_bytes(header + payload)
    for short in [header[:8], header + payload[:-1]]:
        path.write_bytes(short)
        run(tmp, [CLI, "unpacknolog", path], b"truncated")
        assert not kernel.exists()
    # Repack measures the replacement kernel separately from the source image.
    path.write_bytes((header + payload).ljust(3 * 4096, b"\0"))
    with kernel.open("wb") as f:
        f.truncate(IMAGE_LIMIT + 1)
    run(tmp, [CLI, "repack", path], b"file too large")
    assert not (tmp / "new-boot.img").exists()
    kernel.write_bytes(payload)
    run(tmp, [CLI, "repack", path])
    kernel.unlink()
    run(tmp, [CLI, "unpacknolog", tmp / "new-boot.img"])
    assert kernel.read_bytes() == payload
    kernel.unlink()
    struct.pack_into("<I", header, 8, IMAGE_LIMIT + 1)
    path.write_bytes(header)
    run(tmp, [driver, "unpack", path], b"truncated kernel")
    with path.open("wb") as f:
        f.truncate(IMAGE_LIMIT + 1)
    run(tmp, [driver, "unpack", path], b"file too large")
    run(tmp, [CLI, "-l", "-k", path], b"file too large")
    assert not kernel.exists()


def key_checks(tmp, driver):
    old, new = "sample-initial-key", "sample-new-key"
    digest = hashlib.sha256(old.encode()).digest()
    logs = run(tmp, [driver, old, new])
    logs += run(tmp, [CLI, "-l", "-k", tmp / "reset"])
    inspected = run(tmp, [CLI, "-l", "-i", tmp / "image"])
    assert b"banner=Linux version 6.1.0" in inspected and b"patched=true" in inspected
    logs += inspected
    bad = subprocess.run([CLI, "-l", "-i", tmp / "truncated-extra"], capture_output=True, timeout=10)
    assert bad.returncode > 0 and b"[kpm]" not in bad.stdout
    for secret in [old.encode(), new.encode(), digest.hex().encode()]:
        assert secret not in logs
    for field in [b"superkey set", b"root superkey hash set", b"superkey reset", b"version=0xd00"]:
        assert field in logs
    original, reset = [(tmp / name).read_bytes() for name in ["preset", "reset"]]
    assert old.encode() in original and digest in original
    assert new.encode() in reset and old.encode() not in reset and digest in reset


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="kpp-parser-keys-") as directory:
        tmp = Path(directory)
        driver = build_driver(tmp)
        kpm_checks(tmp, driver)
        boot_checks(tmp, driver)
        key_checks(tmp, driver)
    print("KPM bounds, boot short reads, loader, setter and SuperKey output checks passed")
