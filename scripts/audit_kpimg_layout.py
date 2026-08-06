#!/usr/bin/env python3
"""Audit the boot-critical kpimg ELF/raw-binary layout without changing it."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

REQUIRED_SYMBOLS = (
    "_link_base",
    "_setup_start",
    "_setup_end",
    "_map_start",
    "_map_end",
    "_kp_start",
    "_kp_text_start",
    "_kp_text_end",
    "_kp_data_start",
    "_kp_data_end",
    "_kp_end",
    "_link_end",
)

REQUIRED_SECTIONS = (
    ".setup.data",
    ".setup.text",
    ".setup.map",
    ".kp.text",
    ".kp.data",
)


def run(command: list[str]) -> str:
    result = subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout


def parse_symbols(text: str) -> dict[str, int]:
    symbols: dict[str, int] = {}
    pattern = re.compile(r"^([0-9a-fA-F]+)\s+\S\s+(\S+)$")
    for raw_line in text.splitlines():
        match = pattern.match(raw_line.strip())
        if not match:
            continue
        address, name = match.groups()
        if name in REQUIRED_SYMBOLS:
            symbols[name] = int(address, 16)
    return symbols


def parse_sections(text: str) -> dict[str, dict[str, Any]]:
    sections: dict[str, dict[str, Any]] = {}
    pattern = re.compile(
        r"^\s*\[\s*(\d+)\]\s+"
        r"(\S+)\s+"
        r"(\S+)\s+"
        r"([0-9a-fA-F]+)\s+"
        r"([0-9a-fA-F]+)\s+"
        r"([0-9a-fA-F]+)\s+"
        r"\S+\s+"
        r"(\S*)"
    )
    for line in text.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        index, name, section_type, address, offset, size, flags = match.groups()
        if name in REQUIRED_SECTIONS:
            sections[name] = {
                "index": int(index),
                "type": section_type,
                "address": int(address, 16),
                "offset": int(offset, 16),
                "size": int(size, 16),
                "flags": flags,
            }
    return sections


def parse_load_segments(text: str) -> list[dict[str, Any]]:
    loads: list[dict[str, Any]] = []
    pattern = re.compile(
        r"^\s*LOAD\s+"
        r"(0x[0-9a-fA-F]+)\s+"
        r"(0x[0-9a-fA-F]+)\s+"
        r"(0x[0-9a-fA-F]+)\s+"
        r"(0x[0-9a-fA-F]+)\s+"
        r"(0x[0-9a-fA-F]+)\s+"
        r"([RWE ]+?)\s+"
        r"(0x[0-9a-fA-F]+)\s*$"
    )
    for line in text.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        offset, vaddr, paddr, filesz, memsz, flags, align = match.groups()
        loads.append(
            {
                "offset": int(offset, 16),
                "virtual_address": int(vaddr, 16),
                "physical_address": int(paddr, 16),
                "file_size": int(filesz, 16),
                "memory_size": int(memsz, 16),
                "flags": flags.replace(" ", ""),
                "alignment": int(align, 16),
            }
        )
    return loads


def hexadecimal(value: int) -> str:
    return f"0x{value:x}"


def markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# kpimg linker-layout audit",
        "",
        f"Status: **{report['status']}**",
        "",
        "## Raw image",
        "",
        f"- Size: `{report['raw']['size']}` bytes (`{hexadecimal(report['raw']['size'])}`)",
        f"- SHA-256: `{report['raw']['sha256']}`",
        f"- ELF prefix omitted by raw conversion: `{hexadecimal(report['derived']['leading_virtual_gap'])}`",
        f"- File-backed end address: `{hexadecimal(report['derived']['file_backed_end'])}`",
        f"- Aligned link end: `{hexadecimal(report['derived']['aligned_link_end'])}`",
        f"- Trailing address-only alignment: `{hexadecimal(report['derived']['trailing_virtual_padding'])}`",
        "",
        "## Required symbols",
        "",
        "| Symbol | Address | Raw offset |",
        "|---|---:|---:|",
    ]
    link_base = report["symbols"].get("_link_base", 0)
    for name in REQUIRED_SYMBOLS:
        address = report["symbols"].get(name)
        if address is None:
            lines.append(f"| `{name}` | missing | missing |")
        else:
            lines.append(
                f"| `{name}` | `{hexadecimal(address)}` | "
                f"`{hexadecimal(address - link_base)}` |"
            )

    lines.extend(
        [
            "",
            "## Allocated output sections",
            "",
            "| Section | Address | Size | Flags | Raw range |",
            "|---|---:|---:|---|---|",
        ]
    )
    for name in REQUIRED_SECTIONS:
        section = report["sections"].get(name)
        if section is None:
            lines.append(f"| `{name}` | missing | missing | missing | missing |")
            continue
        start = section["address"] - link_base
        end = start + section["size"]
        lines.append(
            f"| `{name}` | `{hexadecimal(section['address'])}` | "
            f"`{hexadecimal(section['size'])}` | `{section['flags']}` | "
            f"`{hexadecimal(start)}..{hexadecimal(end)}` |"
        )

    lines.extend(
        [
            "",
            "## ELF LOAD segments",
            "",
            "| # | Virtual address | File size | Memory size | Flags | Alignment |",
            "|---:|---:|---:|---:|---|---:|",
        ]
    )
    for index, load in enumerate(report["load_segments"]):
        lines.append(
            f"| {index} | `{hexadecimal(load['virtual_address'])}` | "
            f"`{hexadecimal(load['file_size'])}` | "
            f"`{hexadecimal(load['memory_size'])}` | `{load['flags']}` | "
            f"`{hexadecimal(load['alignment'])}` |"
        )

    lines.extend(["", "## Checks", ""])
    for name, passed in report["checks"].items():
        lines.append(f"- {'PASS' if passed else 'FAIL'}: `{name}`")

    if report["warnings"]:
        lines.extend(["", "## Warnings", ""])
        for warning in report["warnings"]:
            lines.append(f"- {warning}")

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--elf", required=True, type=Path)
    parser.add_argument("--raw", required=True, type=Path)
    parser.add_argument("--readelf", required=True)
    parser.add_argument("--nm", required=True)
    parser.add_argument("--json", required=True, type=Path)
    parser.add_argument("--markdown", required=True, type=Path)
    args = parser.parse_args()

    for path in (args.elf, args.raw):
        if not path.is_file() or path.stat().st_size == 0:
            raise SystemExit(f"missing or empty input: {path}")

    symbols = parse_symbols(run([args.nm, "-n", str(args.elf)]))
    sections = parse_sections(run([args.readelf, "-SW", str(args.elf)]))
    loads = parse_load_segments(run([args.readelf, "-lW", str(args.elf)]))
    raw_data = args.raw.read_bytes()
    raw_size = len(raw_data)

    missing_symbols = sorted(set(REQUIRED_SYMBOLS) - symbols.keys())
    missing_sections = sorted(set(REQUIRED_SECTIONS) - sections.keys())

    link_base = symbols.get("_link_base", 0)
    aligned_link_end = symbols.get("_link_end", 0)
    file_backed_end = max(
        (section["address"] + section["size"] for section in sections.values()),
        default=0,
    )

    checks: dict[str, bool] = {
        "all_required_symbols_present": not missing_symbols,
        "all_required_sections_present": not missing_sections,
    }

    if not missing_symbols:
        link_end = symbols["_link_end"]
        checks.update(
            {
                "link_base_is_0xd000": link_base == 0xD000,
                "setup_starts_at_link_base": symbols["_setup_start"] == link_base,
                "setup_then_map_then_kernel": (
                    symbols["_setup_start"]
                    <= symbols["_setup_end"]
                    <= symbols["_map_start"]
                    <= symbols["_map_end"]
                    <= symbols["_kp_start"]
                ),
                "kernel_text_then_data": (
                    symbols["_kp_start"]
                    == symbols["_kp_text_start"]
                    <= symbols["_kp_text_end"]
                    <= symbols["_kp_data_start"]
                    <= symbols["_kp_data_end"]
                    <= symbols["_kp_end"]
                    == link_end
                ),
                "kernel_start_is_64k_aligned": symbols["_kp_start"] % 0x10000 == 0,
                "kernel_data_is_64k_aligned": symbols["_kp_data_start"] % 0x10000 == 0,
                "kernel_end_is_64k_aligned": symbols["_kp_end"] % 0x10000 == 0,
            }
        )

    if not missing_symbols and not missing_sections:
        checks.update(
            {
                "setup_data_starts_at_link_base": sections[".setup.data"]["address"] == link_base,
                "setup_data_reserves_4k": sections[".setup.data"]["size"] == 0x1000,
                "setup_map_is_currently_wax": set("WAX").issubset(
                    set(sections[".setup.map"]["flags"])
                ),
                "file_backed_end_matches_kp_data_end": file_backed_end
                == symbols["_kp_data_end"],
                "aligned_link_end_follows_file_data": aligned_link_end >= file_backed_end,
                "raw_size_matches_file_backed_span": raw_size
                == file_backed_end - link_base,
                "sections_fit_raw_image": all(
                    section["address"] >= link_base
                    and section["address"] - link_base + section["size"] <= raw_size
                    for section in sections.values()
                ),
            }
        )

    checks["single_load_segment"] = len(loads) == 1
    if len(loads) == 1 and not missing_symbols and not missing_sections:
        load = loads[0]
        checks.update(
            {
                "load_starts_at_zero": load["virtual_address"] == 0,
                "load_file_size_matches_file_backed_end": load["file_size"]
                == file_backed_end,
                "load_memory_size_matches_file_backed_end": load["memory_size"]
                == file_backed_end,
                "raw_size_matches_trimmed_load": raw_size
                == load["file_size"] - link_base,
                "load_alignment_is_64k": load["alignment"] == 0x10000,
            }
        )

    warnings: list[str] = []
    setup_map = sections.get(".setup.map")
    if setup_map and "W" in setup_map["flags"] and "X" in setup_map["flags"]:
        warnings.append(
            "The .setup.map output section is both writable and executable because it "
            "combines map data and map text. Splitting only ELF program headers would not "
            "fully remove the W+X overlap."
        )

    rwx_loads = [load for load in loads if set("RWE").issubset(set(load["flags"]))]
    if rwx_loads:
        warnings.append(
            "The intermediate ELF contains an RWE LOAD segment. This audit records the "
            "existing flat-image layout; it does not approve or modify that permission model."
        )

    status = "pass" if checks and all(checks.values()) else "fail"
    report: dict[str, Any] = {
        "status": status,
        "raw": {
            "path": str(args.raw),
            "size": raw_size,
            "sha256": hashlib.sha256(raw_data).hexdigest(),
        },
        "elf": {"path": str(args.elf)},
        "derived": {
            "leading_virtual_gap": link_base,
            "file_backed_end": file_backed_end,
            "aligned_link_end": aligned_link_end,
            "trailing_virtual_padding": max(aligned_link_end - file_backed_end, 0),
        },
        "symbols": symbols,
        "sections": sections,
        "load_segments": loads,
        "checks": checks,
        "warnings": warnings,
        "missing_symbols": missing_symbols,
        "missing_sections": missing_sections,
    }

    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.markdown.write_text(markdown_report(report), encoding="utf-8")

    print(markdown_report(report), end="")
    if status != "pass":
        print("kpimg layout audit failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
