#!/usr/bin/env python3
"""Exercise the SuperCall hook and dispatcher with inert host handlers."""

import os
from pathlib import Path
import re
import subprocess
import tempfile

from check_kpm_rcu_paths import find_functions

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "kernel/patch/common/supercall.c"

HARNESS = r'''
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <supercall_access.h>
#include <kpm_boot_count.h>

typedef struct { long args[6], ret; int skip_origin; } hook_fargs6_t;
enum { UNKNOWN_UID, SU_UID, MANAGER_UID };
static uid_t mock_uid;
static int preset = 1, excluded, kp_safe_mode, calls;
static const int kpver = 1, kver = 2;
#define __user
#define MAX_KEY_LEN 128
#define syscall_argn(frame, index) ((frame)->args[index])
#define current_uid() mock_uid
#define get_ap_mod_exclude(id) excluded
#define has_preset_superkey() preset
#define auth_superkey(key) strcmp(key, "test-key")
#define is_trusted_manager_uid_android(id) ((id) == MANAGER_UID)
#define is_su_allow_uid(id) ((id) == SU_UID)

static long compat_strncpy_from_user(char *dest, const char *src, size_t size)
{
    if (!src || strlen(src) >= size) return -EFAULT;
    strcpy(dest, src);
    return strlen(dest) + 1;
}

static int copy_size = sizeof(struct kpm_safety_status);
static int compat_copy_to_user(void *dst, const void *src, size_t size)
{
    assert(size == sizeof(struct kpm_safety_status));
    memcpy(dst, src, copy_size);
    return copy_size;
}

static struct kpm_boot_attempt boot;
#define spin_lock(lock) ((void)0)
#define spin_unlock(lock) ((void)0)

static int handled(void) { calls++; return 0; }
#define logki(...) handled()
#define app_profile_num() handled()
#define umount_set_enabled(...) handled()
#define proc_hide_rename_current(...) handled()
#define kpm_safety_clear_blacklist() handled()
#define kpm_safety_add_to_blacklist(...) handled()
#define sepolicy_apply(...) handled()
// PRODUCTION_DISPATCH

/* An untouched result means the hook passed the call to the original syscall. */
enum { ORIGINAL = -1000 };
static long invoke(uid_t caller, const char *key, long cmd)
{
    mock_uid = caller;
    calls = 0;
    hook_fargs6_t frame = { .args = { (long)key, (0x1158L << 16) | cmd, (long)"arg" } };
    before(&frame, NULL);
    if (!frame.skip_origin || frame.ret < 0) assert(calls == 0);
    return frame.skip_origin ? frame.ret : ORIGINAL;
}

int main(void)
{
    const long admin[] = {
        SUPERCALL_KLOG, SUPERCALL_BOOTLOG, SUPERCALL_PANIC, SUPERCALL_TEST,
        SUPERCALL_SKEY_GET, SUPERCALL_SKEY_SET, SUPERCALL_SKEY_ROOT_ENABLE,
        SUPERCALL_SU_GRANT_UID, SUPERCALL_SU_REVOKE_UID, SUPERCALL_SU_RESET_PATH,
        SUPERCALL_SU_SET_ALLOW_SCTX, SUPERCALL_KSTORAGE_WRITE, SUPERCALL_KSTORAGE_REMOVE,
        SUPERCALL_APP_PROFILE_SET, SUPERCALL_SET_SAFEMODE, SUPERCALL_UMOUNT_ADD,
        SUPERCALL_UMOUNT_REMOVE, SUPERCALL_UMOUNT_ENABLE, SUPERCALL_SAFETY_BL_CLEAR,
        SUPERCALL_SAFETY_BL_ADD, SUPERCALL_KPM_LOAD, SUPERCALL_KPM_UNLOAD,
        SUPERCALL_KPM_CONTROL, SUPERCALL_KPM_NUMS, SUPERCALL_KPM_LIST,
        SUPERCALL_KPM_INFO, SUPERCALL_KPM_EVENT, SUPERCALL_SEPOLICY_CMD,
#ifdef ANDROID
        SUPERCALL_AP_LOAD_PACKAGE_CONFIG,
#endif
    };
    const long su[] = {
        SUPERCALL_HELLO, SUPERCALL_BUILD_TIME, SUPERCALL_KERNELPATCH_VER, SUPERCALL_KERNEL_VER,
        SUPERCALL_SU, SUPERCALL_PROC_RENAME, SUPERCALL_SU_NUMS, SUPERCALL_SU_LIST,
        SUPERCALL_SU_PROFILE, SUPERCALL_SU_GET_PATH, SUPERCALL_SU_GET_ALLOW_SCTX,
        SUPERCALL_KSTORAGE_READ, SUPERCALL_KSTORAGE_LIST_IDS, SUPERCALL_APP_PROFILE_GET,
        SUPERCALL_APP_PROFILE_LIST, SUPERCALL_APP_PROFILE_NUM, SUPERCALL_UMOUNT_LIST,
#ifdef ANDROID
        SUPERCALL_SU_GET_SAFEMODE,
#endif
    };
    for (size_t i = 0; i < sizeof(admin) / sizeof(admin[0]); i++) {
        assert(invoke(SU_UID, "su", admin[i]) == -EPERM);
        assert(invoke(UNKNOWN_UID, "su", admin[i]) == ORIGINAL);
        assert(invoke(UNKNOWN_UID, "test-key", admin[i]) == 0 && calls == 1);
        assert(invoke(SU_UID, "test-key", admin[i]) == 0 && calls == 1);
#ifdef ANDROID
        assert(invoke(MANAGER_UID, "su", admin[i]) == 0 && calls == 1);
#else
        assert(invoke(MANAGER_UID, "su", admin[i]) == ORIGINAL);
#endif
    }
    for (size_t i = 0; i < sizeof(su) / sizeof(su[0]); i++)
        assert(invoke(SU_UID, "su", su[i]) >= 0);
    assert(invoke(SU_UID, "su", SUPERCALL_SU_TASK) == -EOPNOTSUPP);
    assert(supercall(SUPERCALL_ROLE_NONE, SUPERCALL_SU, 0, 0, 0, 0) == -EPERM);
    kp_safe_mode = 1;
    assert(invoke(SU_UID, "su", SUPERCALL_SU) == -EACCES);
    assert(invoke(UNKNOWN_UID, "test-key", SUPERCALL_SU_TASK) == -EOPNOTSUPP);
    assert(invoke(SU_UID, "su", SUPERCALL_SAFETY_STATUS) == -EPERM);
    struct kpm_safety_status status = { 0 };
    boot.count = 2;
    boot.errors = KPM_COUNT_DATA_ERROR;
    assert(supercall(SUPERCALL_ROLE_ADMIN, SUPERCALL_SAFETY_STATUS, (long)&status, 0, 0, 0) == 0);
    assert(status.boot_count == 2 && status.safe_mode == 1 && status.storage_errors == KPM_COUNT_DATA_ERROR);
    boot.count = -1;
    boot.errors |= KPM_COUNT_EARLY_ERROR;
    kp_safe_mode = 0;
    assert(supercall(SUPERCALL_ROLE_ADMIN, SUPERCALL_SAFETY_STATUS, (long)&status, 0, 0, 0) == 0);
    assert(status.boot_count == -1 && status.safe_mode == 0 && status.storage_errors == boot.errors);
    assert(supercall(SUPERCALL_ROLE_ADMIN, SUPERCALL_SAFETY_STATUS, 0, 0, 0, 0) == -EFAULT);
    copy_size--;
    assert(supercall(SUPERCALL_ROLE_ADMIN, SUPERCALL_SAFETY_STATUS, (long)&status, 0, 0, 0) == -EFAULT);
    assert(invoke(UNKNOWN_UID, "test-key", SUPERCALL_MAX) == -ENOSYS);
    assert(invoke(UNKNOWN_UID, "test-key", SUPERCALL_MAX + 1) == ORIGINAL);
    assert(invoke(MANAGER_UID, NULL, SUPERCALL_HELLO) == ORIGINAL);
    excluded = 1;
    assert(invoke(UNKNOWN_UID, "test-key", SUPERCALL_SU_GRANT_UID) == ORIGINAL);
    excluded = 0;
    preset = 0;
    assert(invoke(UNKNOWN_UID, "test-key", SUPERCALL_HELLO) == ORIGINAL);
#ifdef ANDROID
    assert(invoke(MANAGER_UID, NULL, SUPERCALL_HELLO) == SUPERCALL_HELLO_MAGIC);
    excluded = 1;
    assert(invoke(MANAGER_UID, NULL, SUPERCALL_HELLO) == ORIGINAL);
#endif
}
'''


def main():
    functions = find_functions(SOURCE.read_text())
    dispatch = functions["supercall"][1]
    # Replace only leaf call_* handlers. Keep authorization and routing intact.
    handlers = sorted(set(re.findall(r"\b(call_\w+)\(", functions["supercall"][2])))
    safety = find_functions(SOURCE.with_name("kpm_safety.c").read_text())
    code = [f"#define {name}(...) handled()" for name in handlers if name != "call_safety_status"]
    code += [
        "void kpm_safety_get_status(struct kpm_safety_status *status)", safety["kpm_safety_get_status"][1],
        "static long call_safety_status(struct kpm_safety_status *out)", functions["call_safety_status"][1],
        "static long supercall(enum supercall_role role, long cmd, long arg1, long arg2, long arg3, long arg4)",
        dispatch,
        "int is_trusted_manager_uid(uid_t uid)", functions["is_trusted_manager_uid"][1],
        "static void before(hook_fargs6_t *args, void *udata)", functions["before"][1],
    ]
    with tempfile.TemporaryDirectory(prefix="supercall-host-") as directory:
        source = Path(directory) / "test.c"
        exe = Path(directory) / "test"
        source.write_text(HARNESS.replace("// PRODUCTION_DISPATCH", "\n".join(code)))
        for flags in ([], ["-DANDROID"]):
            subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Werror",
                            "-I", ROOT / "kernel/patch/include", "-idirafter", ROOT / "kernel/linux/include",
                            *flags, source, "-o", exe], check=True)
            subprocess.run([exe], check=True)
    print("supercall access checks passed (Linux and Android)")


if __name__ == "__main__":
    main()
