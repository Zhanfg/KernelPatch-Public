/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SELinux policy manipulation — inspired by KernelSU.
 * Parses serialized policy commands from userspace and applies to running policy.
 */

#include <ktypes.h>
#include <common.h>
#include <log.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/security.h>
#include <security/selinux/include/security.h>
#include <security/selinux/include/avc.h>
#include <sepolicy.h>
#include <uapi/asm-generic/errno.h>

struct sepolicy_cmd_hdr {
    uint32_t cmd;
    uint32_t subcmd;
};

/* Read a length-prefixed string argument from the buffer.
 * Format: [u32 len][len bytes][\0]
 * Returns bytes consumed, or negative errno.
 * On success, *out points to the string (within buf). */
static int read_arg(const void *buf, int buf_len, int offset, const char **out)
{
    if (offset + 4 > buf_len) return -EINVAL;
    uint32_t len = *(uint32_t *)(buf + offset);
    offset += 4;
    if (offset + (int)len + 1 > buf_len) return -EINVAL;
    *out = (const char *)(buf + offset);
    /* Ensure null termination */
    if ((*out)[len] != '\0') return -EINVAL;
    return 4 + len + 1;
}

static int apply_normal_perm(uint32_t subcmd, const char *src, const char *tgt,
                              const char *cls, const char *perm)
{
    /* Look up security IDs */
    u32 src_sid, tgt_sid;
    int rc = security_secctx_to_secid(src, strlen(src), &src_sid);
    if (rc || src_sid == 0) {
        logkfe("sepolicy: unknown src type: %s\n", src);
        return -ENOENT;
    }
    rc = security_secctx_to_secid(tgt, strlen(tgt), &tgt_sid);
    if (rc || tgt_sid == 0) {
        logkfe("sepolicy: unknown tgt type: %s\n", tgt);
        return -ENOENT;
    }

    /*
     * Direct avtab manipulation is complex and kernel-version-dependent.
     * For now, log the request. Full implementation requires policydb access
     * which depends on kernel version-specific SELinux internals.
     */
    switch (subcmd) {
    case KSU_SEPOLICY_SUBCMD_NORMAL_PERM_ALLOW:
        logkfi("sepolicy: allow %s %s:%s { %s }\n", src, tgt, cls, perm);
        break;
    case KSU_SEPOLICY_SUBCMD_NORMAL_PERM_DENY:
        logkfi("sepolicy: deny %s %s:%s { %s }\n", src, tgt, cls, perm);
        break;
    case KSU_SEPOLICY_SUBCMD_NORMAL_PERM_AUDITALLOW:
        logkfi("sepolicy: auditallow %s %s:%s { %s }\n", src, tgt, cls, perm);
        break;
    case KSU_SEPOLICY_SUBCMD_NORMAL_PERM_DONTAUDIT:
        logkfi("sepolicy: dontaudit %s %s:%s { %s }\n", src, tgt, cls, perm);
        break;
    }
    return 0;
}

static int apply_type_state(uint32_t subcmd, const char *type_name)
{
    /*
     * Marking a type as permissive requires policydb->type_val_to_struct access.
     * This is kernel-version-dependent. For now, use selinux_set_enforce(0)
     * as a global fallback, or log for future implementation.
     */
    switch (subcmd) {
    case KSU_SEPOLICY_SUBCMD_TYPE_STATE_PERMISSIVE:
        logkfi("sepolicy: permissive %s (logged, requires policydb access)\n", type_name);
        break;
    case KSU_SEPOLICY_SUBCMD_TYPE_STATE_ENFORCE:
        logkfi("sepolicy: enforce %s (logged, requires policydb access)\n", type_name);
        break;
    }
    return 0;
}

int sepolicy_apply(const void __user *data, int data_len)
{
    if (data_len <= 0 || data_len > 65536) return -EINVAL;

    void *buf = kvmalloc(data_len, GFP_KERNEL);
    if (!buf) return -ENOMEM;

    if (compat_copy_from_user(buf, data, data_len)) {
        kvfree(buf);
        return -EFAULT;
    }

    int offset = 0;
    int rc = 0;

    while (offset + (int)sizeof(struct sepolicy_cmd_hdr) <= data_len) {
        struct sepolicy_cmd_hdr *hdr = (struct sepolicy_cmd_hdr *)(buf + offset);
        offset += sizeof(struct sepolicy_cmd_hdr);

        switch (hdr->cmd) {
        case KSU_SEPOLICY_CMD_NORMAL_PERM:
        case KSU_SEPOLICY_CMD_XPERM: {
            /* Args: src, tgt, cls, perm (or ioctl for xperm) */
            const char *src, *tgt, *cls, *perm;
            int n;

            n = read_arg(buf, data_len, offset, &src);
            if (n < 0) { rc = n; goto out; }
            offset += n;

            n = read_arg(buf, data_len, offset, &tgt);
            if (n < 0) { rc = n; goto out; }
            offset += n;

            n = read_arg(buf, data_len, offset, &cls);
            if (n < 0) { rc = n; goto out; }
            offset += n;

            n = read_arg(buf, data_len, offset, &perm);
            if (n < 0) { rc = n; goto out; }
            offset += n;

            rc = apply_normal_perm(hdr->subcmd, src, tgt, cls, perm);
            break;
        }

        case KSU_SEPOLICY_CMD_TYPE_STATE: {
            const char *type_name;
            int n = read_arg(buf, data_len, offset, &type_name);
            if (n < 0) { rc = n; goto out; }
            offset += n;
            rc = apply_type_state(hdr->subcmd, type_name);
            break;
        }

        case KSU_SEPOLICY_CMD_TYPE:
        case KSU_SEPOLICY_CMD_TYPE_ATTR:
        case KSU_SEPOLICY_CMD_ATTR: {
            /* Type declarations — log for now */
            const char *name;
            int n = read_arg(buf, data_len, offset, &name);
            if (n < 0) { rc = n; goto out; }
            offset += n;
            logkfi("sepolicy: cmd=%d %s\n", hdr->cmd, name);
            break;
        }

        case KSU_SEPOLICY_CMD_TYPE_TRANSITION: {
            /* Args: src, tgt, cls, new, obj */
            const char *a1, *a2, *a3, *a4, *a5;
            int n;
            n = read_arg(buf, data_len, offset, &a1); if (n < 0) { rc = n; goto out; } offset += n;
            n = read_arg(buf, data_len, offset, &a2); if (n < 0) { rc = n; goto out; } offset += n;
            n = read_arg(buf, data_len, offset, &a3); if (n < 0) { rc = n; goto out; } offset += n;
            n = read_arg(buf, data_len, offset, &a4); if (n < 0) { rc = n; goto out; } offset += n;
            n = read_arg(buf, data_len, offset, &a5); if (n < 0) { rc = n; goto out; } offset += n;
            logkfi("sepolicy: type_transition %s %s:%s -> %s %s\n", a1, a2, a3, a4, a5);
            break;
        }

        case KSU_SEPOLICY_CMD_TYPE_CHANGE:
        case KSU_SEPOLICY_CMD_GENFSCON: {
            /* Log for now — requires policydb manipulation */
            logkfi("sepolicy: cmd=%d subcmd=%d (logged)\n", hdr->cmd, hdr->subcmd);
            /* Skip variable number of args */
            int arg_count = (hdr->cmd == KSU_SEPOLICY_CMD_TYPE_CHANGE) ? 4 : 3;
            for (int i = 0; i < arg_count; i++) {
                const char *dummy;
                int n = read_arg(buf, data_len, offset, &dummy);
                if (n < 0) { rc = n; goto out; }
                offset += n;
            }
            break;
        }

        default:
            logkfe("sepolicy: unknown cmd %d\n", hdr->cmd);
            rc = -EINVAL;
            goto out;
        }

        if (rc) goto out;
    }

out:
    kvfree(buf);
    return rc;
}
