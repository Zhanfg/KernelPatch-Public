#!/usr/bin/env python3
"""Host-only, offline CLI tests. Pass the path to a built kptools."""
import bz2
import gzip
import hashlib
import lzma
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

TOOL = Path(__file__).resolve().parents[1] / "tools/kptools"
PAGE = 4096
MAGIC = b"KP1158\0\0"
PI = bytes.fromhex("e60316aae7031f2a3411889a")


def align(size, block=PAGE):
    return (size + block - 1) // block * block


def image(footprint, efi=False, vendor_edits=False, page_shift=12):
    """An inert Image with a relative kallsyms table large enough for the real scanner."""
    body = bytearray(0x20000)
    struct.pack_into("<IIQQQ", body, 0, 0x5A4D if efi else 0x14000020,
                     0x14000020 if efi else 0, 0x80000, footprint, page_shift - 10)
    body[56:60] = b"ARM\x64"
    version = b"6.12.23" if vendor_edits else b"5.4.0"
    banner = b"Linux version " + version + b" (host fixture)\n\0"
    body[0x1000:0x1000 + len(banner)] = banner
    body[0x808:0x810] = body[0x8000:0x8008] = MAGIC  # Unaligned and page-aligned false positives.
    if vendor_edits:
        struct.pack_into("<II", body, 0x2000, 0xd503233f, 0xd50323bf)
        body[0x3900:0x3900 + len(PI)] = PI
    symbols = ["_text", "linux_banner", "tcp_init_sock", "pid_vnr", "paging_init",
               "kallsyms_lookup_name", "printk", "rest_init", "copy_process",
               "memblock_reserve", "memblock_free", "memblock_alloc_try_nid"]
    n = 104 * 256
    offsets = [0, 0x1000] + [0x2000 + i * 4 for i in range(n - 2)]
    body += struct.pack(f"<{n}I", *offsets) + struct.pack("<I", n)
    # Each name uses one token, including its type prefix.
    body += b"".join(bytes([1, 160 + i]) for i in range(len(symbols)))
    body += bytes([1, 159]) * (n - len(symbols))
    body += struct.pack("<104I", *range(0, 2 * n, 512))
    tokens = [b"Tx"] * 256
    for c in b"0123456789abcdefghij":
        tokens[c] = bytes([c])
    for i, name in enumerate(symbols):
        tokens[160 + i] = b"T" + name.encode()
    table = bytearray()
    index = []
    for token in tokens:
        index.append(len(table))
        table += token + b"\0"
    body += table + struct.pack("<256H", *index)
    body += bytes(0x10000)
    body += b"original trailing bytes\0\xaa\0"
    return bytes(body)


def boot(kernel, version=0, ramdisk=b"", sha256=False):
    header = bytearray(PAGE)
    header[:8] = b"ANDROID!"
    struct.pack_into("<I", header, 8, len(kernel))
    struct.pack_into("<I", header, 12 if version >= 3 else 16, len(ramdisk))
    if version < 3:
        struct.pack_into("<I", header, 36, PAGE)
        header[576:608] = (b"S" * 32 if sha256 else b"s" * 20 + bytes(12))
    struct.pack_into("<I", header, 40, version)
    header[1300:1305] = b"keep!"
    return header + kernel + bytes(align(len(kernel)) - len(kernel)) + ramdisk


def appended_dtb():
    dtb = bytearray(90)
    struct.pack_into(">III", dtb, 0, 0xd00dfeed, len(dtb), 40)
    struct.pack_into(">I", dtb, 40, 1)
    return dtb


class Integrity(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def put(self, name, data):
        (self.dir / name).write_bytes(data)

    def get(self, name):
        return (self.dir / name).read_bytes()

    def cli(self, *args, fail=False, env=None):
        p = subprocess.run([TOOL, *args], cwd=self.dir, capture_output=True, timeout=30, env=env)
        report = (p.stderr + p.stdout).decode(errors="replace")
        if fail:
            self.assertGreater(p.returncode, 0, report)
            self.assertTrue(p.stderr.strip(), report)
        else:
            self.assertEqual(p.returncode, 0, report)
        return report

    def test_patch_update_unpatch(self):
        payload = MAGIC + bytes([0, 2, 13, 0]) + bytes(8193)
        self.put("kpimg", payload)
        self.put("extra", b"raw fixture!")
        for footprint, efi, vendor, wrapped, shift in [
                (0, False, False, False, 12), (0x130077, True, True, True, 14),
                (0x100002345, False, False, False, 16)]:
            with self.subTest(footprint=footprint):
                original = image(footprint, efi, vendor, shift)
                if shift == 16:
                    original += bytes([0xa5]) * (align(len(original)) - len(original))
                prefix = b"UNCOMPRESSED_IMG" + struct.pack("<I", len(original) - 3) if wrapped else b""
                self.put("Image", prefix + original)
                args = ["-p", "-k", "kpimg", "-M", "extra", "-T", "raw",
                        "-A", "abc"]
                self.cli(*args, "-i", "Image", "-o", "patched")
                patched = self.get("patched")[len(prefix):]
                offset = align(len(original))
                self.assertEqual(patched[len(original):offset], bytes(offset - len(original)))
                self.assertEqual(patched[offset:offset + 8], MAGIC)
                fields = struct.unpack_from("<7Q", patched, offset + 64 + 8)
                saved, kp_size, orig_footprint, page_shift, setup, start, extra = fields
                self.assertEqual((saved, orig_footprint, page_shift, setup),
                                 (len(original), footprint, shift, offset))
                self.assertEqual(kp_size, align(len(payload), 16))
                self.assertEqual(patched[offset + len(payload):offset + kp_size], bytes(kp_size - len(payload)))
                items = offset + kp_size
                self.assertEqual(patched[items:items + 4], b"kpe\0")
                self.assertEqual(patched[items + 128:items + 144], b"abc" + bytes(13))
                self.assertEqual(patched[items + 144:items + 160], b"raw fixture!" + bytes(4))
                self.assertEqual(patched[items + 160:items + 288], bytes(128))
                self.assertEqual(len(patched), offset + kp_size + extra)
                self.assertEqual(start, align(max(footprint, len(patched))))
                self.assertEqual(struct.unpack_from("<Q", patched, 16)[0], align(start + kp_size + extra))
                entry = 4 if efi else 0
                self.assertNotEqual(patched[entry:entry + 4], original[entry:entry + 4])
                if wrapped:
                    self.assertEqual(struct.unpack_from("<I", self.get("patched"), 16)[0], len(patched))
                if vendor:
                    self.assertNotEqual(patched[0x2000:0x2008], original[0x2000:0x2008])
                    self.assertNotEqual(patched[0x3900:0x390c], PI)
                self.cli(*args, "-i", "patched", "-o", "updated")
                self.assertEqual(self.get("patched"), self.get("updated"))
                self.cli("-u", "-i", "updated", "-o", "original")
                self.assertEqual(self.get("original"), prefix + original)
                self.put("cut", self.get("patched")[:-1])
                self.cli("-u", "-i", "cut", "-o", "original", fail=True)
                self.assertEqual(self.get("original"), prefix + original)

    def test_complete_boot_roundtrip(self):
        self.put("kpimg", MAGIC + bytes(8192))
        ramdisk = b"fixture ramdisk" + bytes(PAGE - 15)
        raw = image(0xb0023, efi=True, vendor_edits=True)
        for version, compressed in [(0, False), (4, False), (0, True)]:
            with self.subTest(version=version, compressed=compressed):
                dtb = appended_dtb() if version == 0 else b""
                kernel = (lzma.compress(raw, check=lzma.CHECK_CRC32) if compressed else raw) + dtb
                original = boot(kernel, version=version, ramdisk=ramdisk)
                if version == 0:
                    digest = hashlib.sha1()
                    for section in [kernel, ramdisk, b""]:
                        digest.update(section + struct.pack("<I", len(section)))
                    original[576:596] = digest.digest()
                self.put("boot", original)
                self.cli("unpack", "boot")
                self.cli("-p", "-i", "kernel", "-k", "kpimg", "-o", "kernel")
                self.cli("repack", "boot")
                self.put("patched-boot", self.get("new-boot.img"))
                self.assertNotEqual(original, self.get("patched-boot"))
                self.cli("unpack", "patched-boot")
                self.cli("-u", "-i", "kernel", "-o", "kernel")
                self.assertEqual(self.get("kernel"), raw if compressed else kernel)
                self.cli("repack", "patched-boot")
                if compressed:
                    out = self.get("new-boot.img")
                    size = struct.unpack_from("<I", out, 8)[0]
                    self.assertEqual(gzip.decompress(out[PAGE:PAGE + size - len(dtb)]), raw)
                    self.assertEqual(out[PAGE + size - len(dtb):PAGE + size], dtb)
                    self.assertEqual(out[PAGE + align(size):], ramdisk)
                else:
                    self.assertEqual(self.get("new-boot.img"), original)

    def test_legacy_preset(self):
        original = image(0x96023)
        self.put("Image", original)
        self.put("kpimg", MAGIC + bytes(8192))
        self.cli("-p", "-i", "Image", "-k", "kpimg", "-o", "patched")
        patched = bytearray(self.get("patched"))
        # Old local writers zeroed the spare preset bytes and left image_size unchanged.
        preset = align(len(original))
        marker = patched.index(b"KPU1", preset)
        patched[marker:marker + 20] = bytes(20)
        for declared in (0x96023, struct.unpack_from("<Q", patched, 16)[0]):
            struct.pack_into("<Q", patched, 16, declared)
            self.put("legacy", patched)
            self.cli("-u", "-i", "legacy", "-o", "restored")
            self.assertEqual(self.get("restored"), original)
            self.cli("-p", "-i", "legacy", "-k", "kpimg", "-o", "updated")
            self.assertEqual(self.get("updated"), self.get("patched"))

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux dynamic linker fault injection")
    def test_gzip_encoder_failure(self):
        source = self.dir / "fail.c"
        source.write_text("#include <zlib.h>\nint deflate(z_streamp s, int flush) { return Z_STREAM_ERROR; }\n")
        shim = str(self.dir / "fail.so")
        subprocess.run(["cc", "-shared", "-fPIC", str(source), "-o", shim], check=True)
        env = os.environ.copy()
        env["LD_PRELOAD"] = " ".join(filter(None, (env.get("LD_PRELOAD"), shim)))
        if "ASAN_OPTIONS" in env:
            env["ASAN_OPTIONS"] += ":verify_asan_link_order=0"
        self.put("kernel", b"replacement")
        self.put("new-boot.img", b"previous output")
        for fmt in (lzma.FORMAT_XZ, lzma.FORMAT_ALONE):
            self.put("boot", boot(lzma.compress(b"old", format=fmt)))
            report = self.cli("repack", "boot", fail=True, env=env)
            self.assertIn("compression failed", report)
            self.assertEqual(self.get("new-boot.img"), b"previous output")

    def test_boot_tail_and_footer(self):
        # A v2 boot with a ramdisk, second stage, recovery DTBO, DTB and partition padding.
        sections = [b"ramdisk\0", b"second", b"r" * 12, b"d" * 15]
        original = boot(gzip.compress(b"old"), version=2)
        struct.pack_into("<I", original, 16, len(sections[0]))
        struct.pack_into("<I", original, 24, len(sections[1]))
        struct.pack_into("<IQII", original, 1632, len(sections[2]), 4 * PAGE, 1660, len(sections[3]))
        for section in sections:
            original += section + bytes(align(len(section)) - len(section))
        original_size = len(original)
        vbmeta = b"AVB0" + bytes(172)
        original += vbmeta + bytes(PAGE * 4 - len(vbmeta) - 64)
        original += struct.pack(">4sIIQQQ28x", b"AVBf", 1, 0, original_size, original_size, len(vbmeta))
        self.put("boot", original)
        self.put("kernel", random.Random(3).randbytes(PAGE * 2))
        self.cli("repack", "boot")
        out = self.get("new-boot.img")
        klen = struct.unpack_from("<I", out, 8)[0]
        delta = align(klen) - PAGE
        self.assertGreater(delta, 0)
        self.assertEqual(len(out), len(original))
        self.assertEqual(struct.unpack_from("<Q", out, 1636)[0], 4 * PAGE + delta)
        self.assertEqual(out[2 * PAGE + delta:original_size + delta], original[2 * PAGE:original_size])
        self.assertEqual(out[original_size + delta:original_size + delta + len(vbmeta)], vbmeta)
        self.assertEqual(struct.unpack_from(">QQQ", out, len(out) - 64 + 12),
                         (original_size + delta, original_size + delta, len(vbmeta)))
        digest = hashlib.sha1()
        for section in [out[PAGE:PAGE + klen], *sections]:
            digest.update(section + struct.pack("<I", len(section)))
        self.assertEqual(out[576:596], digest.digest())

    def test_boot_compressed_lengths(self):
        dtb = appended_dtb()
        ramdisk = b"ramdisk content" + bytes(100)  # trailing zero bytes participate in the hash
        cases = [(lzma.FORMAT_XZ, b"A" * 19000, False),
                 (lzma.FORMAT_ALONE, random.Random(2).randbytes(4096), True)]
        for fmt, raw, sha256 in cases:
            with self.subTest(fmt=fmt):
                original = (lzma.compress(b"old", format=fmt, check=lzma.CHECK_CRC32)
                            if fmt == lzma.FORMAT_XZ else lzma.compress(b"old", format=fmt))
                self.put("boot", boot(original + dtb, ramdisk=ramdisk, sha256=sha256))
                if fmt == lzma.FORMAT_XZ:
                    self.cli("unpack", "boot")
                    self.assertEqual(self.get("kernel"), b"old")
                else:
                    self.cli("unpacknolog", "boot", fail=True)  # bundled decoder supports XZ containers
                self.put("kernel", raw)
                self.cli("repack", "boot")
                out = self.get("new-boot.img")
                length = struct.unpack_from("<I", out, 8)[0]
                decoder = zlib.decompressobj(31)
                self.assertEqual(decoder.decompress(out[PAGE:]), raw)
                self.assertTrue(decoder.eof)
                compressed = len(out) - PAGE - len(decoder.unused_data)
                if fmt == lzma.FORMAT_XZ:
                    self.assertLess(compressed, len(raw))
                else:
                    self.assertGreater(compressed, len(raw))
                self.assertEqual(length, compressed + len(dtb))
                self.assertEqual(out[PAGE + compressed:PAGE + length], dtb)
                self.assertEqual(out[PAGE + length:PAGE + align(length)], bytes(align(length) - length))
                self.assertEqual(out[PAGE + align(length):], ramdisk)
                digest = hashlib.sha256() if sha256 else hashlib.sha1()
                for section in [out[PAGE:PAGE + length], ramdisk, b""]:
                    digest.update(section + struct.pack("<I", len(section)))
                self.assertEqual(out[576:576 + digest.digest_size], digest.digest())
                self.cli("unpack", "new-boot.img")
                self.assertEqual(self.get("kernel"), raw)

    def test_other_codecs(self):
        raw = b"fixture " * 1024
        for old in [b"raw kernel", gzip.compress(b"old"), bz2.compress(b"old"),
                    bytes.fromhex("04224d1860400000"), bytes.fromhex("02214c1800000000")]:
            with self.subTest(old=old[:4]):
                self.put("boot", boot(old, version=4))
                self.put("kernel", raw)
                self.cli("repack", "boot")
                self.assertEqual(self.get("new-boot.img")[1300:1305], b"keep!")
                self.cli("unpack", "new-boot.img")
                self.assertEqual(self.get("kernel"), raw)

    def test_errors(self):
        self.put("kernel", b"previous kernel")
        xz = lzma.compress(b"content", check=lzma.CHECK_CRC32)
        for broken in [xz[:-1], gzip.compress(b"content")[:-1], bz2.compress(b"content")[:-2],
                       bytes.fromhex("28b52ffd"), bytes.fromhex("02214c180100")]:
            self.put("boot", boot(broken))
            self.cli("unpacknolog", "boot", fail=True)
            self.assertEqual(self.get("kernel"), b"previous kernel")
        self.put("new-boot.img", b"previous output")
        # Recognized LZ4 magic with an invalid block size forces the compressor to fail.
        for bad in [boot(bytes.fromhex("04224d1860000000")), boot(b"\x28\xb5\x2f\xfd"),
                    boot(xz)[:PAGE + 5], b"ANDROID!"]:
            self.put("boot", bad)
            self.cli("repack", "boot", fail=True)
            self.assertEqual(self.get("new-boot.img"), b"previous output")
        self.put("boot", boot(xz))
        (self.dir / "kernel").unlink()
        self.cli("repack", "boot", fail=True)
        if Path("/dev/full").exists():
            (self.dir / "kernel").symlink_to("/dev/full")
            self.cli("unpacknolog", "boot", fail=True)
            (self.dir / "kernel").unlink()
            self.put("kernel", b"replacement")
            (self.dir / "new-boot.img").unlink()
            (self.dir / "new-boot.img").symlink_to("/dev/full")
            self.cli("repack", "boot", fail=True)


if __name__ == "__main__":
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        TOOL = Path(sys.argv.pop(1)).resolve()
    unittest.main()
