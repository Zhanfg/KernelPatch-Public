#!/usr/bin/env python3
"""Static regression gates for isolated EXP hotpatch backport and KPM sample.
These checks do not replace ARM64 builds or physical boot testing.
"""
from pathlib import Path
root = Path(__file__).resolve().parents[1]
hotpatch = (root / "kernel/base/hotpatch.c").read_text()
demo = (root / "kpms/demo-argv/argv_demo.c").read_text()
checks = {
    "legacy threshold": "kver < VERSION(4, 6, 0)" in hotpatch,
    "disable unsafe alias on 4.14": "kver < VERSION(4, 15, 0)" in hotpatch,
    "text symbol fallback": "kfunc(aarch64_insn_patch_text)" in hotpatch,
    "modern stop_machine preserved": "return stop_machine(hotpatch_cb, &patch, cpu_online_mask);" in hotpatch,
    "legacy direct fallback": "hotpatch_nosync(addrs[i], values[i])" in hotpatch,
    "argv decode at consumer": "pn_argv_decode(" in demo,
    "legacy compatibility": "PN_ARGV_LEGACY" in demo,
    "malformed frame rejected": "return -EINVAL" in demo,
    "optional events": "#ifdef PATCHNEST_EVENT_ABI" in demo and "KPM_EVENT(argv_event);" in demo,
    "no automatic payload logging": 'pr_info("PatchNest %s: PNARGV1 items=%d' in demo,
}
for name, valid in checks.items():
    print(f"{'PASS' if valid else 'FAIL'}: {name}")
if not all(checks.values()):
    raise SystemExit(1)
