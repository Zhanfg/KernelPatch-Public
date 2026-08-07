#!/usr/bin/env python3
"""Source-level contracts for the KernelPatch-Public security issue batch.

These checks do not replace kernel builds, KASAN/KCSAN, fuzzing, or device tests.
They prevent known vulnerable source patterns from silently returning while the
runtime evidence matrix is still pending.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> int:
    predata = read("kernel/base/predata.c")
    supercall = read("kernel/patch/common/supercall.c")
    module = read("kernel/patch/module/module.c")
    relo = read("kernel/patch/module/relo.c")
    safety = read("kernel/patch/common/kpm_safety.c")
    userd = read("kernel/patch/android/userd.c")

    # #7 exact bounded superkey authentication.
    require("lib_strnlen(superkey, SUPER_KEY_LEN)" in predata,
            "#7: stored superkey length is not bounded")
    require("candidate_len == stored_len" in predata,
            "#7: candidate length is not required to match")

    # #9 one user copy, then kernel copy only; temporary key material cleared.
    skey = re.search(r"static long call_skey_set\(.*?\n\}", supercall, re.S)
    require(skey is not None, "#9: call_skey_set not found")
    skey_text = skey.group(0)
    require("reset_superkey(buf);" in skey_text,
            "#9: validated kernel copy is not used")
    require("reset_superkey(new_key)" not in skey_text,
            "#9: original user pointer is reread")
    require("memzero_explicit(buf" in skey_text,
            "#9: temporary superkey buffer is not cleared")

    # #6 delegated SU cannot mutate the management/control plane.
    first_auth_gate = supercall.find("if (!is_authed) return -EPERM;")
    grant = supercall.find("case SUPERCALL_SU_GRANT_UID:")
    safemode = supercall.find("case SUPERCALL_SET_SAFEMODE:")
    blacklist = supercall.find("case SUPERCALL_SAFETY_BL_CLEAR:")
    require(first_auth_gate >= 0 and min(grant, safemode, blacklist) > first_auth_gate,
            "#6: global mutation opcode appears before full-auth gate")

    # #11 remote task mutation is fail-closed until a target-context redesign.
    su_task = re.search(r"static long call_su_task\(.*?\n\}", supercall, re.S)
    require(su_task is not None and "return -EOPNOTSUPP;" in su_task.group(0),
            "#11: unsafe remote SU_TASK path is reachable")

    # #8 list source and destination lengths are bounded and exact.
    kpm_list = re.search(r"static long call_kpm_list\(.*?\n\}", supercall, re.S)
    require(kpm_list is not None, "#8: call_kpm_list not found")
    require("len > (int)sizeof(buf)" in kpm_list.group(0),
            "#8: caller can request source overread")
    require("compat_copy_to_user(names, buf, sz)" in kpm_list.group(0),
            "#8: KPM list does not copy exact produced length")
    require("written >= remaining" in module and "size - off" in module,
            "#8: list_modules producer lacks truncation accounting")

    # #15 every info lookup exits through an RCU unlock path.
    info = re.search(r"int get_module_info\(.*?\n\}", module, re.S)
    require(info is not None, "#15: get_module_info not found")
    require("goto out;" in info.group(0) and "rcu_read_unlock();" in info.group(0),
            "#15: module-info error path can leak RCU read lock")

    # #12 explicit KPM callback ABI only; no .init.text fallback.
    setup = re.search(r"static int setup_load_info\(.*?\n\}", module, re.S)
    require(setup is not None, "#12: setup_load_info not found")
    require('find_sec(info, ".kpm.init")' in setup.group(0),
            "#12: explicit .kpm.init is not required")
    require('.init.text' not in setup.group(0) and '.exit.text' not in setup.group(0),
            "#12: ordinary .ko section-start callback fallback remains")
    require("validate_module_callbacks(mod)" in module,
            "#12: relocated callback targets are not validated")

    # #10 RCU deletion waits before executable memory reclamation.
    unload = re.search(r"long unload_module\(.*?\n\}", module, re.S)
    require(unload is not None, "#10: unload_module not found")
    require("list_del_rcu" in unload.group(0) and "synchronize_rcu();" in unload.group(0),
            "#10: module is reclaimed without RCU grace period")
    require(unload.group(0).find("synchronize_rcu();") < unload.group(0).find("kp_free_exec"),
            "#10: executable memory is freed before grace period")

    # #13 untrusted ELF indices/ranges and relocation writes are bounded.
    for token in (
        "e_shstrndx >= info->hdr->e_shnum",
        "string_offset_valid(section_names",
        "shdr->sh_link >= info->hdr->e_shnum",
        "shdr->sh_info >= info->hdr->e_shnum",
        "symbols[i].st_name",
    ):
        require(token in module, f"#13: missing ELF validation token: {token}")
    require("sym_no >= sym_count" in relo,
            "#13: relocation symbol index is not bounded")
    require("target->sh_size - rel[i].r_offset" in relo,
            "#13: relocation write range is not bounded")
    require("relocation_write_width" in relo,
            "#13: relocation memory write width is not modeled")
    rel_handler = re.search(r"int apply_relocate\(.*?\n\}", relo, re.S)
    require(rel_handler is not None and "return -ENOEXEC;" in rel_handler.group(0),
            "#13: unsupported REL sections are silently accepted")

    # #14 one persistent attempt and existing Android boot-completed event bind.
    early = re.search(r"void kpm_safety_early_count\(.*?\n\}", safety, re.S)
    require(early is not None and "BOOT_COUNT_FILE" not in early.group(0),
            "#14: early tmpfs phase still mutates persistent failure count")
    require("persistent_attempt_recorded" in safety,
            "#14: one-attempt-per-boot guard is missing")
    require("prior_count >= MAX_BOOT_COUNT" in safety,
            "#14: safe-mode threshold semantics are missing")
    require("KPM_EVENT_BOOT_COMPLETED" in supercall and
            "kpm_safety_confirm_boot_completed();" in supercall,
            "#14: boot-completed event is not connected to confirmation")
    require("sys.boot_completed=1" in userd and "event boot-completed" in userd,
            "#14: Android boot-completed trigger is absent")

    # #6 cached manager trust must fail closed when package/signature refresh fails.
    refresh = re.search(r"static int refresh_trusted_manager_state_from_packages_list\(.*?\n\}", userd, re.S)
    require(refresh is not None, "#6: trusted-manager refresh function not found")
    stale_fixed = re.search(
        r"if \(rc\) \{.*?trusted_manager_uid\s*=\s*TRUSTED_MANAGER_UID_INVALID",
        refresh.group(0),
        re.S,
    )
    require(stale_fixed is not None,
            "#6: trusted-manager refresh failure retains cached UID")

    print("KernelPatch security source contracts passed; runtime evidence is still required.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
