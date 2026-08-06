#!/usr/bin/env python3
"""Audit the isolated kpimg PHDR-split experiment."""

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

BASELINE_COMMIT = "0bdf0094f7c90cead5dd1a221af957ea2ed01948"
EXPERIMENT_BRANCH = "restart/phdr-split-experiment"
STRICT_FLAGS = (
    "-Werror=implicit-function-declaration "
    "-Werror=unused-variable "
    "-Werror=int-conversion"
)

SYMBOL_NAMES = (
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

SECTION_ACCESS = {
    ".setup.data": "RW",
    ".setup.text": "RE",
    ".setup.map.data": "RW",
    ".setup.map.text": "RE",
    ".kp.text": "RE",
    ".kp.data": "RW",
}


def run(
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
        if name in SYMBOL_NAMES:
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
        if name not in SECTION_ACCESS:
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


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def hx(value: int) -> str:
    return f"0x{value:x}"


def tool_prefix(readelf: str) -> str:
    if not readelf.endswith("readelf"):
        raise SystemExit("cannot derive cross-toolchain prefix from --readelf")
    return readelf[: -len("readelf")]


def build_kernel(root: Path, prefix: str, epoch: str) -> None:
    env = os.environ.copy()
    env.update(
        {
            "TARGET_COMPILE": prefix,
            "SOURCE_DATE_EPOCH": epoch,
            "EXTRA_CFLAGS": STRICT_FLAGS,
        }
    )
    run(["make", "-C", "kernel", "clean"], cwd=root, env=env, capture=False)
    run(["make", "-C", "kernel"], cwd=root, env=env, capture=False)


def compare_baseline(args: argparse.Namespace) -> dict[str, Any]:
    branch = os.environ.get("GITHUB_HEAD_REF") or os.environ.get("GITHUB_REF_NAME")
    if branch != EXPERIMENT_BRANCH:
        raise SystemExit(
            f"PHDR experiment audit may run only on {EXPERIMENT_BRANCH}; got {branch!r}"
        )

    repo = Path.cwd().resolve()
    prefix = tool_prefix(args.readelf)
    epoch = run(
        ["git", "show", "-s", "--format=%ct", BASELINE_COMMIT], cwd=repo
    ).strip()

    temporary_root = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir()))
    baseline_tree = temporary_root / f"kpimg-phdr-baseline-{os.getpid()}"
    if baseline_tree.exists():
        shutil.rmtree(baseline_tree)

    try:
        run(
            ["git", "worktree", "add", "--detach", str(baseline_tree), BASELINE_COMMIT],
            cwd=repo,
            capture=False,
        )
        build_kernel(baseline_tree, prefix, epoch)
        build_kernel(repo, prefix, epoch)

        baseline_raw = baseline_tree / "kernel" / "kpimg"
        baseline_elf = baseline_tree / "kernel" / "kpimg.elf"
        candidate_raw = Path(args.raw)
        candidate_elf = Path(args.elf)

        baseline_symbols = parse_symbols(
            run([f"{prefix}nm", "-n", str(baseline_elf)])
        )
        candidate_symbols = parse_symbols(
            run([f"{prefix}nm", "-n", str(candidate_elf)])
        )

        return {
            "baseline_commit": BASELINE_COMMIT,
            "source_date_epoch": int(epoch),
            "baseline_sha256": sha256(baseline_raw),
            "candidate_sha256": sha256(candidate_raw),
            "raw_byte_identical": baseline_raw.read_bytes() == candidate_raw.read_bytes(),
            "required_symbols_identical": baseline_symbols == candidate_symbols,
            "baseline_symbols": baseline_symbols,
            "candidate_symbols": candidate_symbols,
        }
    finally:
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(baseline_tree)],
            cwd=repo,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def load_contains(load: dict[str, Any], section: dict[str, Any]) -> bool:
    start = section["address"]
    end = start + section["size"]
    load_start = load["virtual_address"]
    load_end = load_start + load["memory_size"]
    return load_start <= start and end <= load_end


def compatible(load_flags: str, required: str) -> bool:
    if required == "RW":
        return "R" in load_flags and "W" in load_flags and "E" not in load_flags
    return "R" in load_flags and "E" in load_flags and "W" not in load_flags


def render(report: dict[str, Any]) -> str:
    comparison = report["comparison"]
    lines = [
        "# kpimg PHDR split experiment",
        "",
        f"Status: **{report['status']}**",
        "",
        "## Baseline comparison",
        "",
        f"- Baseline commit: `{comparison['baseline_commit']}`",
        f"- Shared SOURCE_DATE_EPOCH: `{comparison['source_date_epoch']}`",
        f"- Baseline raw SHA-256: `{comparison['baseline_sha256']}`",
        f"- Candidate raw SHA-256: `{comparison['candidate_sha256']}`",
        f"- Raw byte-identical: `{comparison['raw_byte_identical']}`",
        f"- Required symbols identical: `{comparison['required_symbols_identical']}`",
        "",
        "## LOAD segments",
        "",
        "| # | Offset | Vaddr | File size | Memory size | Flags | Alignment |",
        "|---:|---:|---:|---:|---:|---|---:|",
    ]
    for index, load in enumerate(report["load_segments"]):
        lines.append(
            f"| {index} | `{hx(load['offset'])}` | `{hx(load['virtual_address'])}` | "
            f"`{hx(load['file_size'])}` | `{hx(load['memory_size'])}` | "
            f"`{load['flags']}` | `{hx(load['alignment'])}` |"
        )

    lines.extend(
        [
            "",
            "## Section coverage",
            "",
            "| Section | Address | Size | Section flags | Required LOAD | Matching LOAD |",
            "|---|---:|---:|---|---|---:|",
        ]
    )
    for name, section in report["sections"].items():
        coverage = report["section_coverage"].get(name)
        lines.append(
            f"| `{name}` | `{hx(section['address'])}` | `{hx(section['size'])}` | "
            f"`{section['flags']}` | `{SECTION_ACCESS[name]}` | "
            f"`{coverage if coverage is not None else 'missing'}` |"
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

    comparison = compare_baseline(args)
    symbols = parse_symbols(run([args.nm, "-n", str(args.elf)]))
    sections = parse_sections(run([args.readelf, "-SW", str(args.elf)]))
    loads = parse_loads(run([args.readelf, "-lW", str(args.elf)]))

    missing_symbols = sorted(set(SYMBOL_NAMES) - symbols.keys())
    missing_sections = sorted(set(SECTION_ACCESS) - sections.keys())
    section_coverage: dict[str, int | None] = {}
    for name, section in sections.items():
        match_index: int | None = None
        for index, load in enumerate(loads):
            if load_contains(load, section) and compatible(
                load["flags"], SECTION_ACCESS[name]
            ):
                match_index = index
                break
        section_coverage[name] = match_index

    checks = {
        "raw_byte_identical_to_main": comparison["raw_byte_identical"],
        "required_symbols_identical_to_main": comparison[
            "required_symbols_identical"
        ],
        "all_required_symbols_present": not missing_symbols,
        "all_required_sections_present": not missing_sections,
        "six_load_segments": len(loads) == 6,
        "no_writable_executable_load": not any(
            "W" in load["flags"] and "E" in load["flags"] for load in loads
        ),
        "all_loads_are_readable": all("R" in load["flags"] for load in loads),
        "all_sections_have_compatible_load": (
            not missing_sections
            and all(section_coverage.get(name) is not None for name in SECTION_ACCESS)
        ),
        "section_addresses_preserved": (
            not missing_symbols
            and sections.get(".setup.data", {}).get("address") == symbols.get("_setup_start")
            and sections.get(".setup.map.data", {}).get("address")
            == symbols.get("_map_start")
            and sections.get(".setup.map.text", {}).get("address", 0)
            + sections.get(".setup.map.text", {}).get("size", 0)
            == symbols.get("_map_end")
            and sections.get(".kp.text", {}).get("address") == symbols.get("_kp_start")
            and sections.get(".kp.data", {}).get("address")
            == symbols.get("_kp_data_start")
        ),
    }

    warnings: list[str] = []
    if all(checks.values()):
        warnings.append(
            "This proves ELF/raw equivalence and segment permissions only. It does not "
            "replace physical-device patch, boot, rollback, or KPM validation."
        )

    status = "pass" if all(checks.values()) else "fail"
    report: dict[str, Any] = {
        "status": status,
        "comparison": comparison,
        "raw": {
            "path": str(args.raw),
            "size": args.raw.stat().st_size,
            "sha256": sha256(args.raw),
        },
        "elf": {"path": str(args.elf)},
        "symbols": symbols,
        "sections": sections,
        "load_segments": loads,
        "section_coverage": section_coverage,
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
        print("kpimg PHDR experiment failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
