#!/usr/bin/env python3
"""Audit the boot-critical kpimg ELF/raw image layout."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

SYMBOLS = (
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

SECTIONS = (
    ".setup.data",
    ".setup.text",
    ".setup.map.data",
    ".setup.map.text",
    ".kp.text",
    ".kp.data",
)

SPLIT_BASELINE_COMMIT = "b2270f7bd3d186b6960e44d87a5885ab11bf7c41"
SPLIT_BRANCH = "restart/setup-map-split-audit"
STRICT_FLAGS = (
    "-Werror=implicit-function-declaration "
    "-Werror=unused-variable "
    "-Werror=int-conversion"
)


def execute(
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    capture: bool = True,
) -> str:
    result = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        check=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        text=True,
    )
    return result.stdout if capture else ""


def parse_symbols(text: str) -> dict[str, int]:
    result: dict[str, int] = {}
    pattern = re.compile(r"^([0-9a-fA-F]+)\s+\S\s+(\S+)$")
    for line in text.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        address, name = match.groups()
        if name in SYMBOLS:
            result[name] = int(address, 16)
    return result


def parse_sections(text: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    pattern = re.compile(
        r"^\s*\[\s*(\d+)\]\s+(\S+)\s+(\S+)\s+"
        r"([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+"
        r"\S+\s+(\S*)"
    )
    for line in text.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        index, name, section_type, address, offset, size, flags = match.groups()
        if name not in SECTIONS:
            continue
        result[name] = {
            "index": int(index),
            "type": section_type,
            "address": int(address, 16),
            "offset": int(offset, 16),
            "size": int(size, 16),
            "flags": flags,
        }
    return result


def parse_loads(text: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    pattern = re.compile(
        r"^\s*LOAD\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+"
        r"(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+"
        r"(0x[0-9a-fA-F]+)\s+([RWE ]+?)\s+(0x[0-9a-fA-F]+)\s*$"
    )
    for line in text.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        offset, vaddr, paddr, filesz, memsz, flags, align = match.groups()
        result.append(
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
    return result


def hx(value: int) -> str:
    return f"0x{value:x}"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def split_experiment_enabled() -> bool:
    return (
        os.environ.get("GITHUB_HEAD_REF") == SPLIT_BRANCH
        or os.environ.get("GITHUB_REF_NAME") == SPLIT_BRANCH
    )


def build_kernel(root: Path, prefix: str, epoch: str) -> None:
    env = os.environ.copy()
    env.update(
        {
            "TARGET_COMPILE": prefix,
            "SOURCE_DATE_EPOCH": epoch,
            "EXTRA_CFLAGS": STRICT_FLAGS,
        }
    )
    execute(["make", "-C", "kernel", "clean"], cwd=root, env=env, capture=False)
    execute(["make", "-C", "kernel"], cwd=root, env=env, capture=False)


def compare_split_baseline(args: argparse.Namespace) -> dict[str, Any] | None:
    if not split_experiment_enabled():
        return None

    repo = Path.cwd().resolve()
    toolchain_prefix = args.readelf
    if not toolchain_prefix.endswith("readelf"):
        raise SystemExit("cannot derive cross-toolchain prefix from --readelf")
    toolchain_prefix = toolchain_prefix[: -len("readelf")]

    epoch = execute(
        ["git", "show", "-s", "--format=%ct", SPLIT_BASELINE_COMMIT],
        cwd=repo,
    ).strip()
    temp_root = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir()))
    worktree = temp_root / f"kpimg-layout-baseline-{os.getpid()}"
    if worktree.exists():
        shutil.rmtree(worktree)

    try:
        execute(
            ["git", "worktree", "add", "--detach", str(worktree), SPLIT_BASELINE_COMMIT],
            cwd=repo,
            capture=False,
        )
        build_kernel(worktree, toolchain_prefix, epoch)
        baseline_raw = worktree / "kernel" / "kpimg"
        baseline_elf = worktree / "kernel" / "kpimg.elf"
        baseline_symbols = parse_symbols(
            execute([f"{toolchain_prefix}nm", "-n", str(baseline_elf)])
        )

        # Rebuild the candidate with the exact same compiler timestamp and flags.
        build_kernel(repo, toolchain_prefix, epoch)
        candidate_raw = Path(args.raw)
        candidate_elf = Path(args.elf)
        candidate_symbols = parse_symbols(
            execute([f"{toolchain_prefix}nm", "-n", str(candidate_elf)])
        )

        baseline_bytes = baseline_raw.read_bytes()
        candidate_bytes = candidate_raw.read_bytes()
        return {
            "baseline_commit": SPLIT_BASELINE_COMMIT,
            "source_date_epoch": int(epoch),
            "baseline_sha256": hashlib.sha256(baseline_bytes).hexdigest(),
            "candidate_sha256": hashlib.sha256(candidate_bytes).hexdigest(),
            "raw_byte_identical": baseline_bytes == candidate_bytes,
            "required_symbols_identical": baseline_symbols == candidate_symbols,
            "baseline_symbols": baseline_symbols,
            "candidate_symbols": candidate_symbols,
        }
    finally:
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(worktree)],
            cwd=repo,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def render(report: dict[str, Any]) -> str:
    lines = [
        "# kpimg linker-layout audit",
        "",
        f"Status: **{report['status']}**",
        "",
        "## Raw image",
        "",
        f"- Size: `{report['raw']['size']}` bytes (`{hx(report['raw']['size'])}`)",
        f"- SHA-256: `{report['raw']['sha256']}`",
        f"- Leading virtual gap removed by objcopy: `{hx(report['derived']['leading_virtual_gap'])}`",
        f"- File-backed end: `{hx(report['derived']['file_backed_end'])}`",
        f"- Aligned link end: `{hx(report['derived']['aligned_link_end'])}`",
        f"- Address-only trailing alignment: `{hx(report['derived']['trailing_virtual_padding'])}`",
    ]

    comparison = report.get("comparison")
    if comparison:
        lines.extend(
            [
                "",
                "## Pre-split comparison",
                "",
                f"- Baseline commit: `{comparison['baseline_commit']}`",
                f"- Shared SOURCE_DATE_EPOCH: `{comparison['source_date_epoch']}`",
                f"- Baseline SHA-256: `{comparison['baseline_sha256']}`",
                f"- Candidate SHA-256: `{comparison['candidate_sha256']}`",
                f"- Raw byte-identical: `{comparison['raw_byte_identical']}`",
                f"- Required symbols identical: `{comparison['required_symbols_identical']}`",
            ]
        )

    lines.extend(
        [
            "",
            "## Symbols",
            "",
            "| Symbol | Address | Raw offset |",
            "|---|---:|---:|",
        ]
    )

    base = report["symbols"].get("_link_base", 0)
    for name in SYMBOLS:
        address = report["symbols"].get(name)
        if address is None:
            lines.append(f"| `{name}` | missing | missing |")
        else:
            lines.append(f"| `{name}` | `{hx(address)}` | `{hx(address - base)}` |")

    lines.extend(
        [
            "",
            "## Output sections",
            "",
            "| Section | Address | Size | Flags | Raw range |",
            "|---|---:|---:|---|---|",
        ]
    )
    for name in SECTIONS:
        section = report["sections"].get(name)
        if section is None:
            lines.append(f"| `{name}` | missing | missing | missing | missing |")
            continue
        start = section["address"] - base
        end = start + section["size"]
        lines.append(
            f"| `{name}` | `{hx(section['address'])}` | `{hx(section['size'])}` | "
            f"`{section['flags']}` | `{hx(start)}..{hx(end)}` |"
        )

    lines.extend(
        [
            "",
            "## LOAD segments",
            "",
            "| # | Vaddr | File size | Memory size | Flags | Alignment |",
            "|---:|---:|---:|---:|---|---:|",
        ]
    )
    for index, load in enumerate(report["load_segments"]):
        lines.append(
            f"| {index} | `{hx(load['virtual_address'])}` | `{hx(load['file_size'])}` | "
            f"`{hx(load['memory_size'])}` | `{load['flags']}` | `{hx(load['alignment'])}` |"
        )

    lines.extend(["", "## Checks", ""])
    for name, passed in report["checks"].items():
        lines.append(f"- {'PASS' if passed else 'FAIL'}: `{name}`")

    if report["warnings"]:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {warning}" for warning in report["warnings"])

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--readelf", required=True)
    parser.add_argument("--nm", required=True)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    args = parser.parse_args()

    for path in (args.elf, args.raw):
        if not path.is_file() or path.stat().st_size == 0:
            raise SystemExit(f"missing or empty input: {path}")

    comparison = compare_split_baseline(args)

    symbols = parse_symbols(execute([args.nm, "-n", str(args.elf)]))
    sections = parse_sections(execute([args.readelf, "-SW", str(args.elf)]))
    loads = parse_loads(execute([args.readelf, "-lW", str(args.elf)]))
    raw = args.raw.read_bytes()

    missing_symbols = sorted(set(SYMBOLS) - symbols.keys())
    missing_sections = sorted(set(SECTIONS) - sections.keys())
    raw_size = len(raw)
    link_base = symbols.get("_link_base", 0)
    link_end = symbols.get("_link_end", 0)
    file_backed_end = max(
        (section["address"] + section["size"] for section in sections.values()),
        default=0,
    )

    checks: dict[str, bool] = {
        "all_required_symbols_present": not missing_symbols,
        "all_required_sections_present": not missing_sections,
    }

    if comparison:
        checks["pre_split_raw_byte_identical"] = comparison["raw_byte_identical"]
        checks["pre_split_required_symbols_identical"] = comparison[
            "required_symbols_identical"
        ]

    if not missing_symbols:
        checks.update(
            {
                "link_base_is_0xd000": link_base == 0xD000,
                "setup_starts_at_link_base": symbols["_setup_start"] == link_base,
                "setup_map_kernel_order": (
                    symbols["_setup_start"]
                    <= symbols["_setup_end"]
                    <= symbols["_map_start"]
                    <= symbols["_map_end"]
                    <= symbols["_kp_start"]
                ),
                "kernel_text_data_order": (
                    symbols["_kp_start"]
                    == symbols["_kp_text_start"]
                    <= symbols["_kp_text_end"]
                    <= symbols["_kp_data_start"]
                    <= symbols["_kp_data_end"]
                    <= symbols["_kp_end"]
                    == link_end
                ),
                "kernel_start_64k_aligned": symbols["_kp_start"] % 0x10000 == 0,
                "kernel_data_64k_aligned": symbols["_kp_data_start"] % 0x10000 == 0,
                "kernel_end_64k_aligned": symbols["_kp_end"] % 0x10000 == 0,
            }
        )

    if not missing_symbols and not missing_sections:
        map_data = sections[".setup.map.data"]
        map_text = sections[".setup.map.text"]
        checks.update(
            {
                "setup_data_starts_at_link_base": sections[".setup.data"]["address"] == link_base,
                "setup_data_reserves_4k": sections[".setup.data"]["size"] == 0x1000,
                "map_data_starts_at_map_start": map_data["address"] == symbols["_map_start"],
                "map_text_ends_at_map_end": map_text["address"] + map_text["size"] == symbols["_map_end"],
                "map_sections_are_contiguous": map_data["address"] + map_data["size"] == map_text["address"],
                "map_data_is_writable_non_executable": "W" in map_data["flags"] and "X" not in map_data["flags"],
                "map_text_is_executable_non_writable": "X" in map_text["flags"] and "W" not in map_text["flags"],
                "map_region_under_0xa00": symbols["_map_end"] - symbols["_map_start"] < 0xA00,
                "file_backed_end_matches_kp_data_end": file_backed_end == symbols["_kp_data_end"],
                "link_end_not_before_file_data": link_end >= file_backed_end,
                "raw_size_matches_file_backed_span": raw_size == file_backed_end - link_base,
                "all_sections_fit_raw": all(
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
                "load_file_size_matches_file_backed_end": load["file_size"] == file_backed_end,
                "load_memory_size_matches_file_backed_end": load["memory_size"] == file_backed_end,
                "raw_size_matches_trimmed_load": raw_size == load["file_size"] - link_base,
                "load_alignment_is_64k": load["alignment"] == 0x10000,
            }
        )

    warnings: list[str] = []
    if any(set("RWE").issubset(set(load["flags"])) for load in loads):
        warnings.append(
            "The intermediate ELF still contains one RWE LOAD segment. The section split "
            "removes W+X from the individual setup-map sections but does not change PHDR permissions."
        )

    status = "pass" if checks and all(checks.values()) else "fail"
    report: dict[str, Any] = {
        "status": status,
        "raw": {
            "path": str(args.raw),
            "size": raw_size,
            "sha256": sha256(args.raw),
        },
        "elf": {"path": str(args.elf)},
        "derived": {
            "leading_virtual_gap": link_base,
            "file_backed_end": file_backed_end,
            "aligned_link_end": link_end,
            "trailing_virtual_padding": max(link_end - file_backed_end, 0),
        },
        "comparison": comparison,
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
    rendered = render(report)
    args.markdown.write_text(rendered, encoding="utf-8")
    print(rendered, end="")

    if status != "pass":
        print("kpimg layout audit failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
