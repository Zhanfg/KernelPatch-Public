#!/usr/bin/env python3
"""Static checks for the KPM list copy bound and RCU read-side exits.

The missing-module bug is a return while rcu_read_lock() is held. This
scanner flags that shape, an unlock nested on only one branch, and a
copy that uses the raw user length as the source size.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "kernel/patch/module/module.c"
SUPERCALL = ROOT / "kernel/patch/common/supercall.c"

RCU_FUNCTIONS = {
    "unload_module",
    "module_control0",
    "module_control1",
    "get_module_nums",
    "list_modules",
    "get_module_info",
    "module_dispatch_event",
}

FUNC_RE = re.compile(
    r"^(?:static\s+)?(?:inline\s+)?(?:const\s+)?"
    r"(?:struct\s+\w+\s*\*+\s*|"
    r"(?:unsigned\s+)?(?:long|int|void|bool|char|short)\s*\*+\s*|"
    r"(?:unsigned\s+)?(?:long|int|void|bool|char|short)\s+)"
    r"([A-Za-z_]\w*)\s*\(",
    re.M,
)


def mask_non_code(src: str) -> str:
    out = list(src)
    i = 0
    n = len(src)
    while i < n:
        if src.startswith("//", i):
            j = src.find("\n", i)
            if j < 0:
                j = n
            for k in range(i, j):
                out[k] = " "
            i = j
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue
        if src[i] in "\"'":
            quote = src[i]
            out[i] = " "
            i += 1
            while i < n:
                if src[i] == "\\":
                    if out[i] != "\n":
                        out[i] = " "
                    i += 1
                    if i < n and out[i] != "\n":
                        out[i] = " "
                    i += 1
                    continue
                if src[i] == "\n":
                    break
                if src[i] == quote:
                    out[i] = " "
                    i += 1
                    break
                if out[i] != "\n":
                    out[i] = " "
                i += 1
            continue
        i += 1
    return "".join(out)


def line_of(src: str, index: int) -> int:
    return src.count("\n", 0, index) + 1


def find_functions(src: str) -> dict[str, tuple[int, str, str]]:
    """Map function name to (line, original body, comment-stripped body)."""
    masked = mask_non_code(src)
    found: dict[str, tuple[int, str, str]] = {}
    for match in FUNC_RE.finditer(masked):
        name = match.group(1)
        paren = 0
        i = match.end() - 1
        started = False
        while i < len(masked):
            ch = masked[i]
            if ch == "(":
                paren += 1
                started = True
            elif ch == ")":
                paren -= 1
                if started and paren == 0:
                    i += 1
                    break
            i += 1
        while i < len(masked) and masked[i] in " \t\r\n":
            i += 1
        if i >= len(masked) or masked[i] != "{":
            continue
        depth = 0
        body_start = i
        while i < len(masked):
            if masked[i] == "{":
                depth += 1
            elif masked[i] == "}":
                depth -= 1
                if depth == 0:
                    i += 1
                    break
            i += 1
        found[name] = (line_of(src, match.start()), src[body_start:i], masked[body_start:i])
    return found


def check_rcu_function(name: str, line: int, body: str) -> list[str]:
    errors: list[str] = []
    locks = [m.start() for m in re.finditer(r"\brcu_read_lock\b", body)]
    unlocks = [m.start() for m in re.finditer(r"\brcu_read_unlock\b", body)]
    if len(locks) != 1 or len(unlocks) != 1:
        errors.append(
            f"{name}:{line}: expected one rcu_read_lock/unlock pair, "
            f"found {len(locks)} lock and {len(unlocks)} unlock"
        )
        return errors

    depth = 0
    lock_depth = None
    unlock_depth = None
    held = 0
    for index, ch in enumerate(body):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        if index == locks[0]:
            lock_depth = depth
            held += 1
        elif index == unlocks[0]:
            unlock_depth = depth
            held -= 1
        elif held > 0 and re.match(r"return\b", body[index:]):
            errors.append(
                f"{name}:{line + body.count(chr(10), 0, index)}: "
                "return while rcu_read_lock() is held"
            )
    if lock_depth != unlock_depth:
        errors.append(
            f"{name}:{line}: rcu_read_unlock() is not on the same path as rcu_read_lock()"
        )
    if held != 0:
        errors.append(f"{name}:{line}: RCU read lock depth ends at {held}")
    return errors


def check_module(src: str) -> list[str]:
    functions = find_functions(src)
    errors: list[str] = []
    missing = RCU_FUNCTIONS - set(functions)
    if missing:
        errors.append("function scanner missed: " + ", ".join(sorted(missing)))
    for name in sorted(RCU_FUNCTIONS & set(functions)):
        line, _original, body = functions[name]
        if "rcu_read_lock" not in body:
            errors.append(f"{name}:{line}: expected an RCU read-side section")
            continue
        errors.extend(check_rcu_function(name, line, body))

    info = functions.get("get_module_info")
    if info:
        body = info[1]
        if re.search(r"return\s+-ENOENT\s*;", body):
            errors.append("get_module_info still returns -ENOENT directly")
        if "goto out" not in body:
            errors.append("get_module_info is missing the shared unlock exit")

    listed = functions.get("list_modules")
    if listed:
        body = listed[1]
        if "size - 1 - off" in body:
            errors.append("list_modules still accumulates snprintf lengths with size - 1 - off")
        for needle in ("kpm_list_append", "kpm_list_finish", "out_names[0] = '\\0'"):
            if needle not in body:
                errors.append(f"list_modules is missing {needle}")
    return errors


def check_supercall(src: str) -> list[str]:
    functions = find_functions(src)
    errors: list[str] = []
    found = functions.get("call_kpm_list")
    if not found:
        return ["call_kpm_list was not found"]
    _line, body, _masked = found
    if re.search(r"compat_copy_to_user\s*\(\s*names\s*,\s*buf\s*,\s*len\s*\)", body):
        errors.append("call_kpm_list still copies the raw user len")
    for needle in (
        "kpm_bounded_copy_len",
        "memset(buf, 0, sizeof(buf))",
        "compat_copy_to_user(names, buf, copy_len)",
        "if (copy_len <= 0)",
    ):
        if needle not in body:
            errors.append(f"call_kpm_list is missing {needle}")
    return errors


def self_test() -> list[str]:
    leaked = """
int get_module_info(const char *name, char *out_info, int size)
{
    if (size <= 0) return 0;
    rcu_read_lock();
    if (!mod) return -ENOENT;
    rcu_read_unlock();
    return sz;
}
"""
    nested = """
int get_module_info(const char *name)
{
    rcu_read_lock();
    if (!mod) {
        rcu_read_unlock();
        return -ENOENT;
    }
    return sz;
}
"""
    shared = """
int get_module_info(const char *name, char *out_info, int size)
{
    if (size <= 0) return 0;
    rcu_read_lock();
    if (!mod) {
        sz = -ENOENT;
        goto out;
    }
out:
    rcu_read_unlock();
    return sz;
}
"""
    errors: list[str] = []
    leaked_errors = check_rcu_function("sample", 1, find_functions(leaked)["get_module_info"][2])
    if not any("return while" in item for item in leaked_errors):
        errors.append("self-test did not flag a direct return under rcu_read_lock()")
    nested_errors = check_rcu_function("sample", 1, find_functions(nested)["get_module_info"][2])
    if not nested_errors:
        errors.append("self-test did not flag an unlock nested on one branch")
    shared_errors = check_rcu_function("sample", 1, find_functions(shared)["get_module_info"][2])
    if shared_errors:
        errors.append("self-test rejected the shared unlock exit: " + "; ".join(shared_errors))
    return errors


def main() -> int:
    errors = self_test()
    errors.extend(check_module(MODULE.read_text()))
    errors.extend(check_supercall(SUPERCALL.read_text()))
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("kpm rcu and list-copy paths ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
