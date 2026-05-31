/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SELinux policy manipulation — inspired by KernelSU.
 * Allows runtime policy modifications via supercall.
 */

#ifndef _KP_SEPOLICY_H_
#define _KP_SEPOLICY_H_

#include <ktypes.h>

/* Command types */
#define KSU_SEPOLICY_CMD_NORMAL_PERM     1
#define KSU_SEPOLICY_CMD_XPERM           2
#define KSU_SEPOLICY_CMD_TYPE_STATE      3
#define KSU_SEPOLICY_CMD_TYPE            4
#define KSU_SEPOLICY_CMD_TYPE_ATTR       5
#define KSU_SEPOLICY_CMD_ATTR            6
#define KSU_SEPOLICY_CMD_TYPE_TRANSITION 7
#define KSU_SEPOLICY_CMD_TYPE_CHANGE     8
#define KSU_SEPOLICY_CMD_GENFSCON        9

/* Sub-commands for NORMAL_PERM */
#define KSU_SEPOLICY_SUBCMD_NORMAL_PERM_ALLOW     1
#define KSU_SEPOLICY_SUBCMD_NORMAL_PERM_DENY      2
#define KSU_SEPOLICY_SUBCMD_NORMAL_PERM_AUDITALLOW 3
#define KSU_SEPOLICY_SUBCMD_NORMAL_PERM_DONTAUDIT 4

/* Sub-commands for XPERM */
#define KSU_SEPOLICY_SUBCMD_XPERM_ALLOW      1
#define KSU_SEPOLICY_SUBCMD_XPERM_AUDITALLOW 2
#define KSU_SEPOLICY_SUBCMD_XPERM_DONTAUDIT  3

/* Sub-commands for TYPE_STATE */
#define KSU_SEPOLICY_SUBCMD_TYPE_STATE_PERMISSIVE 1
#define KSU_SEPOLICY_SUBCMD_TYPE_STATE_ENFORCE    2

/* Sub-commands for TYPE_CHANGE */
#define KSU_SEPOLICY_SUBCMD_TYPE_CHANGE_CHANGE 1
#define KSU_SEPOLICY_SUBCMD_TYPE_CHANGE_MEMBER 2

/*
 * Process a serialized sepolicy command buffer from userspace.
 * Format: [cmd_hdr][args...] where each arg is [u32 len][bytes \0]
 *
 * Returns 0 on success, negative errno on failure.
 */
int sepolicy_apply(const void __user *data, int data_len);

#endif
