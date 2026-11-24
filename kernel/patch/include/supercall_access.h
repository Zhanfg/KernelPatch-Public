/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_SUPERCALL_ACCESS_H_
#define _KP_SUPERCALL_ACCESS_H_

#include <uapi/scdefs.h>
#include <uapi/asm-generic/errno.h>

enum supercall_role
{
    SUPERCALL_ROLE_NONE,
    SUPERCALL_ROLE_SU,
    SUPERCALL_ROLE_ADMIN, /* Trusted manager UID or authenticated superkey. */
};

/* Every implemented command needs an explicit entry before it can dispatch. */
static inline int supercall_access(enum supercall_role role, long cmd)
{
    if (role != SUPERCALL_ROLE_SU && role != SUPERCALL_ROLE_ADMIN) return -EPERM;

    switch (cmd) {
    case SUPERCALL_HELLO:
    case SUPERCALL_BUILD_TIME:
    case SUPERCALL_KERNELPATCH_VER:
    case SUPERCALL_KERNEL_VER:
    case SUPERCALL_SU:
    case SUPERCALL_PROC_RENAME: /* Only changes current->comm. */
    case SUPERCALL_SU_NUMS:
    case SUPERCALL_SU_LIST:
    case SUPERCALL_SU_PROFILE:
    case SUPERCALL_SU_GET_PATH:
    case SUPERCALL_SU_GET_ALLOW_SCTX:
#ifdef ANDROID
    case SUPERCALL_SU_GET_SAFEMODE:
#endif
    case SUPERCALL_KSTORAGE_READ:
    case SUPERCALL_KSTORAGE_LIST_IDS:
    case SUPERCALL_APP_PROFILE_GET:
    case SUPERCALL_APP_PROFILE_LIST:
    case SUPERCALL_APP_PROFILE_NUM:
    case SUPERCALL_UMOUNT_LIST:
        return 0;

    case SUPERCALL_SU_TASK:
        return -EOPNOTSUPP;

    case SUPERCALL_KLOG:
    case SUPERCALL_BOOTLOG:
    case SUPERCALL_PANIC:
    case SUPERCALL_TEST:
    case SUPERCALL_SKEY_GET:
    case SUPERCALL_SKEY_SET:
    case SUPERCALL_SKEY_ROOT_ENABLE:
#ifdef ANDROID
    case SUPERCALL_AP_LOAD_PACKAGE_CONFIG:
#endif
    case SUPERCALL_SU_GRANT_UID:
    case SUPERCALL_SU_REVOKE_UID:
    case SUPERCALL_SU_RESET_PATH:
    case SUPERCALL_SU_SET_ALLOW_SCTX:
    case SUPERCALL_KSTORAGE_WRITE:
    case SUPERCALL_KSTORAGE_REMOVE:
    case SUPERCALL_APP_PROFILE_SET:
    case SUPERCALL_SET_SAFEMODE:
    case SUPERCALL_UMOUNT_ADD:
    case SUPERCALL_UMOUNT_REMOVE:
    case SUPERCALL_UMOUNT_ENABLE:
    case SUPERCALL_SAFETY_STATUS:
    case SUPERCALL_SAFETY_BL_CLEAR:
    case SUPERCALL_SAFETY_BL_ADD:
    case SUPERCALL_KPM_LOAD:
    case SUPERCALL_KPM_UNLOAD:
    case SUPERCALL_KPM_CONTROL:
    case SUPERCALL_KPM_NUMS:
    case SUPERCALL_KPM_LIST:
    case SUPERCALL_KPM_INFO:
    case SUPERCALL_KPM_EVENT:
    case SUPERCALL_SEPOLICY_CMD:
        return role == SUPERCALL_ROLE_ADMIN ? 0 : -EPERM;
    default:
        return role == SUPERCALL_ROLE_ADMIN ? -ENOSYS : -EPERM;
    }
}

#endif
