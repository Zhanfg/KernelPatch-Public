#!/usr/bin/env python3
"""Source/model contracts for issue #6 supercall authorization."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SC = (ROOT / "kernel/patch/common/supercall.c").read_text(encoding="utf-8")
USERD = (ROOT / "kernel/patch/android/userd.c").read_text(encoding="utf-8")

assert "SC_AUTHZ_DELEGATED" in SC
assert "SC_AUTHZ_ADMIN" in SC
assert "static long call_delegated_su(uid_t caller_uid)" in SC
assert "su_allow_uid_profile(0, caller_uid, &profile)" in SC
assert "profile.uid != caller_uid" in SC
assert "commit_su(profile.to_uid, profile.scontext)" in SC

# Delegated block permits exactly profile-bound current-process SU; everything
# else reaches an explicit EPERM. It must not consume a caller-supplied profile.
delegated = SC[SC.index("if (authz == SC_AUTHZ_DELEGATED)"):SC.index("if (authz != SC_AUTHZ_ADMIN)")]
assert "cmd == SUPERCALL_SU" in delegated
assert "call_delegated_su(caller_uid)" in delegated
assert "call_su((struct su_profile" not in delegated
assert "return -EPERM;" in delegated
for forbidden in (
    "SUPERCALL_SU_TASK",
    "SUPERCALL_SU_GRANT_UID",
    "SUPERCALL_SU_REVOKE_UID",
    "SUPERCALL_SET_SAFEMODE",
    "SUPERCALL_UMOUNT_ADD",
    "SUPERCALL_SAFETY_BL_CLEAR",
    "SUPERCALL_KPM_LOAD",
    "SUPERCALL_SKEY_SET",
    "SUPERCALL_SEPOLICY_CMD",
    "SUPERCALL_PANIC",
):
    assert forbidden not in delegated

# Administrator switch owns all global mutations and arbitrary-target actions.
admin = SC[SC.index("/* Everything below is administrator-only control plane. */"):SC.index("int is_trusted_manager_uid")]
for required in (
    "SUPERCALL_SU_TASK",
    "SUPERCALL_SU_GRANT_UID",
    "SUPERCALL_SU_REVOKE_UID",
    "SUPERCALL_SU_SET_ALLOW_SCTX",
    "SUPERCALL_KSTORAGE_WRITE",
    "SUPERCALL_APP_PROFILE_SET",
    "SUPERCALL_SET_SAFEMODE",
    "SUPERCALL_UMOUNT_ADD",
    "SUPERCALL_SAFETY_BL_CLEAR",
    "SUPERCALL_KPM_LOAD",
    "SUPERCALL_SKEY_SET",
    "SUPERCALL_SEPOLICY_CMD",
    "SUPERCALL_PANIC",
):
    assert required in admin

# A bad/unreadable superkey no longer prevents an allowlisted UID from being
# classified as delegated; it simply fails to elevate the caller to ADMIN.
before = SC[SC.index("static void before"):SC.index("int supercall_install")]
assert "if (len > 0 && !auth_superkey(key)) authz = SC_AUTHZ_ADMIN;" in before
assert "if (len <= 0) return;" not in before
assert "is_trusted_manager_uid(uid)" in before
assert "authz = SC_AUTHZ_ADMIN" in before
assert "is_su_allow_uid(uid)" in before
assert "authz = SC_AUTHZ_DELEGATED" in before
assert "supercall(authz, uid, cmd" in before
assert "authz=%s" in before

# Android manager identity is not a bare cached UID registration: refresh only
# accepts a discovered APK after its configured signature digest verifies, then
# resolves that package's UID. Package-list updates and boot completion refresh
# this state elsewhere in user_event.c.
refresh = USERD[USERD.index("static int refresh_trusted_manager_uid_from_packages_list"):USERD.index("int refresh_trusted_manager_uid(void)")]
assert "apk_matches_trusted_signature" in refresh
assert "trusted_managers[i].digest" in refresh
assert "lookup_package_list_uid" in refresh
assert refresh.index("apk_matches_trusted_signature") < refresh.index("lookup_package_list_uid")

# Pure capability model.
PUBLIC = {"HELLO", "KP_VER", "KERNEL_VER", "BUILD_TIME", "SAFE_MODE_READ"}
DELEGATED = PUBLIC | {"SU_SELF_PROFILE"}
ADMIN = DELEGATED | {
    "SU_TASK", "GRANT_UID", "REVOKE_UID", "PROFILE_SET", "SET_SAFEMODE",
    "UMOUNT_MUTATE", "BLACKLIST_MUTATE", "KPM_MUTATE", "SKEY_MUTATE",
    "SEPOLICY_MUTATE", "KSTORAGE_MUTATE", "PANIC",
}

for capability in ("GRANT_UID", "REVOKE_UID", "SET_SAFEMODE", "UMOUNT_MUTATE",
                   "BLACKLIST_MUTATE", "KPM_MUTATE", "SKEY_MUTATE", "PANIC"):
    assert capability not in DELEGATED
    assert capability in ADMIN
assert "SU_SELF_PROFILE" in DELEGATED
assert "SU_TASK" not in DELEGATED

print("Issue #6 authorization matrix source/model contracts passed.")
