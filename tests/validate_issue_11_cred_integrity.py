#!/usr/bin/env python3
"""Source/model contracts for issue #11 credential/seccomp integrity."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACC = (ROOT / "kernel/patch/common/accctl.c").read_text(encoding="utf-8")
SC = (ROOT / "kernel/patch/common/supercall.c").read_text(encoding="utf-8")


def section(text: str, start: str, end: str) -> str:
    a = text.index(start)
    b = text.index(end, a + len(start))
    return text[a:b]

# Arbitrary-target SU is not implemented by raw task mutation anymore.
task = section(ACC, "int task_su", "/* Safe mode flag")
assert "return -EOPNOTSUPP;" in task
assert "find_get_task_by_vpid" not in task
assert "get_task_thread_info" not in task
assert "cred_offset.cred_offset" not in task
assert "cred_offset.real_cred_offset" not in task
assert "SECCOMP_MODE_DISABLED" not in task
assert "_TIF_SECCOMP" not in task
assert "target-context handoff required" in task

# Current-context SU replaces a fresh credential object and preserves seccomp.
common = section(ACC, "int commit_common_su", "int commit_su(")
assert "new = prepare_creds();" in common
assert "su_cred(new, to_uid);" in common
assert "commit_creds(new)" in common
assert "abort_creds(new)" in common
assert "groups_alloc(0)" in common
assert "set_groups(new, group_info);" in common
assert "SECCOMP_MODE_DISABLED" not in common
assert "_TIF_SECCOMP" not in common
assert "seccomp->mode" not in common

profile = section(ACC, "int commit_su_with_profile", "int check_umount_modules")
assert "new = prepare_creds();" in profile
assert "commit_creds(new)" in profile
assert "abort_creds(new)" in profile
assert "SECCOMP_MODE_DISABLED" not in profile
assert "_TIF_SECCOMP" not in profile
assert "seccomp->mode" not in profile

# No remaining code path in accctl.c may directly disable seccomp.
assert "SECCOMP_MODE_DISABLED" not in ACC
assert "_TIF_SECCOMP" not in ACC
assert "thi->flags" not in ACC

# SU_TASK remains administrator-gated by #6 but its backend is deliberately
# unsupported, so neither delegated nor administrator calls can mutate another
# task until a target-context handoff is implemented.
assert "case SUPERCALL_SU_TASK:" in SC
assert "authz == SC_AUTHZ_DELEGATED" in SC
admin = SC[SC.index("/* Everything below is administrator-only control plane. */"):]
assert "SUPERCALL_SU_TASK" in admin
assert "call_su_task" in admin

# Minimal behavioral model.
def remote_task_su(_pid, _profile):
    return "EOPNOTSUPP"


def current_su(seccomp_state, uid):
    return {"seccomp": seccomp_state, "uid": uid, "cred_object": "new"}

assert remote_task_su(1234, {"uid": 0}) == "EOPNOTSUPP"
state = current_su("FILTER", 0)
assert state == {"seccomp": "FILTER", "uid": 0, "cred_object": "new"}

print("Issue #11 credential integrity source/model contracts passed.")
