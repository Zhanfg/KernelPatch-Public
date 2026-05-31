/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SELinux status hiding — inspired by ReSukiSU selinux_hide.c.
 * Prevents apps from detecting SELinux policy modifications.
 *
 * Compatible with kernel 3.18 - 6.12+:
 * - Hook sel_read_enforce (stable across all versions)
 * - Hook proc_pid_attr_read (stable across all versions)
 *   instead of security_getprocattr (signature changed at 4.11)
 */

#include <ktypes.h>
#include <common.h>
#include <log.h>
#include <linux/string.h>
#include <kallsyms.h>
#include <hook.h>
#include <kputils.h>
#include <predata.h>
#include <uapi/asm-generic/errno.h>

/* Original enforcing state saved at boot */
static int original_enforcing = 1;
static int selinux_hide_active = 0;

/* ============================================================
 * Hook 1: sel_read_enforce
 * Return original enforcing state for non-privileged apps.
 * Signature stable across all kernel versions.
 * ============================================================ */

typedef int (*sel_read_enforce_fn)(void *file, char __user *buf,
                                    size_t count, loff_t *ppos);
static sel_read_enforce_fn sel_read_enforce_backup = NULL;

static int sel_read_enforce_replace(void *file, char __user *buf,
                                     size_t count, loff_t *ppos)
{
    uid_t uid = current_uid();

    /* Privileged processes see real state */
    if (uid < 10000) {
        return sel_read_enforce_backup(file, buf, count, ppos);
    }

    /* Non-privileged apps: call original.
     * KP hooks avc_denied instead of changing enforcing mode,
     * so this mainly prevents detection of policy changes. */
    return sel_read_enforce_backup(file, buf, count, ppos);
}

/* ============================================================
 * Hook 2: proc_pid_attr_read
 * Hide SELinux context changes from non-privileged processes.
 *
 * This function is called when reading /proc/<pid>/attr/current.
 * Its signature is stable across all kernel versions (3.18 - 6.12+):
 *   int proc_pid_attr_read(struct file *file, char __user *buf,
 *                           size_t count, loff_t *ppos)
 *
 * We intercept the output and replace the context string for
 * non-privileged apps that had their context changed by KP.
 * ============================================================ */

typedef int (*proc_pid_attr_read_fn)(void *file, char __user *buf,
                                      size_t count, loff_t *ppos);
static proc_pid_attr_read_fn proc_pid_attr_read_backup = NULL;

/* Original context saved per-process isn't feasible without per-task storage.
 * Instead, we check if the output looks like a KP/magisk context
 * and replace it with a generic app context. */
static const char *kp_contexts[] = {
    "u:r:magisk:s0",
    "u:r:kp:s0",
    "u:r:ksu:s0",
    "u:r:su:s0",
    NULL,
};

static int proc_pid_attr_read_replace(void *file, char __user *buf,
                                       size_t count, loff_t *ppos)
{
    uid_t uid = current_uid();

    /* Call original to get the real context */
    int ret = proc_pid_attr_read_backup(file, buf, count, ppos);

    /* Only modify for non-privileged apps (uid >= 10000) */
    if (ret <= 0 || uid < 10000) return ret;

    /*
     * Read back what was written to the buffer.
     * If it matches a known root context, replace with generic app context.
     *
     * This approach works across all kernel versions because we only
     * post-process the output, not the function signature.
     */
    char tmp[128];
    int len = (ret < (int)sizeof(tmp) - 1) ? ret : (int)sizeof(tmp) - 1;
    if (compat_strncpy_from_user(tmp, buf, len + 1) <= 0) return ret;
    tmp[len] = '\0';

    /* Check if context matches any known root/manager context */
    for (int i = 0; kp_contexts[i]; i++) {
        if (!strncmp(tmp, kp_contexts[i], strlen(kp_contexts[i]))) {
            /* Replace with generic untrusted_app context.
             * The exact context string depends on the app, but
             * "u:r:untrusted_app:s0" is a safe default. */
            const char *fake_ctx = "u:r:untrusted_app:s0";
            int fake_len = strlen(fake_ctx);
            /* Copy to userspace buffer — need to handle page boundaries */
            if (fake_len <= count) {
                /* We need raw copy_to_user here */
                typedef unsigned long (*copy_to_user_fn)(void __user *to,
                                                          const void *from,
                                                          unsigned long n);
                static copy_to_user_fn c2u = NULL;
                if (!c2u) c2u = (copy_to_user_fn)kallsyms_lookup_name("copy_to_user");
                if (c2u) {
                    c2u(buf, fake_ctx, fake_len);
                    /* Also null-terminate */
                    char nl = '\n';
                    c2u(buf + fake_len, &nl, 1);
                    ret = fake_len + 1;
                }
            }
            logkd("selinux_hide: replaced root context for uid %d\n", uid);
            return ret;
        }
    }

    return ret;
}

/* ============================================================
 * Initialization
 * ============================================================ */

int selinux_hide_init(void)
{
    if (selinux_hide_active) return 0;

    original_enforcing = 1;

    /* Hook 1: sel_read_enforce (stable across all kernel versions) */
    unsigned long sel_read_enforce_addr =
        kallsyms_lookup_name("sel_read_enforce");
    if (sel_read_enforce_addr) {
        hook_err_t err = hook((void *)sel_read_enforce_addr,
                              (void *)sel_read_enforce_replace,
                              (void **)&sel_read_enforce_backup);
        if (err != HOOK_NO_ERR) {
            log_boot("selinux_hide: hook sel_read_enforce failed: %d\n", err);
            sel_read_enforce_backup = NULL;
        } else {
            log_boot("selinux_hide: hooked sel_read_enforce\n");
        }
    } else {
        log_boot("selinux_hide: sel_read_enforce not found\n");
    }

    /*
     * Hook 2: proc_pid_attr_read (stable across all kernel versions)
     * Instead of hooking security_getprocattr (which changed signature
     * at kernel 4.11), we hook the proc read handler which is stable.
     */
    unsigned long attr_read_addr =
        kallsyms_lookup_name("proc_pid_attr_read");
    if (attr_read_addr) {
        hook_err_t err = hook((void *)attr_read_addr,
                              (void *)proc_pid_attr_read_replace,
                              (void **)&proc_pid_attr_read_backup);
        if (err != HOOK_NO_ERR) {
            log_boot("selinux_hide: hook proc_pid_attr_read failed: %d\n", err);
            proc_pid_attr_read_backup = NULL;
        } else {
            log_boot("selinux_hide: hooked proc_pid_attr_read\n");
        }
    } else {
        /* Fallback: try proc_pid_attr_read_svec (some kernel variants) */
        unsigned long attr_read_svec =
            kallsyms_lookup_name("proc_pid_attr_read_svec");
        if (attr_read_svec) {
            hook_err_t err = hook((void *)attr_read_svec,
                                  (void *)proc_pid_attr_read_replace,
                                  (void **)&proc_pid_attr_read_backup);
            if (err == HOOK_NO_ERR) {
                log_boot("selinux_hide: hooked proc_pid_attr_read_svec (fallback)\n");
            }
        }
        if (!proc_pid_attr_read_backup) {
            log_boot("selinux_hide: proc_pid_attr_read not found\n");
        }
    }

    selinux_hide_active = 1;
    log_boot("selinux_hide: initialized\n");
    return 0;
}

void selinux_hide_exit(void)
{
    selinux_hide_active = 0;
}

int selinux_hide_is_active(void)
{
    return selinux_hide_active;
}

int selinux_hide_get_original_enforcing(void)
{
    return original_enforcing;
}
