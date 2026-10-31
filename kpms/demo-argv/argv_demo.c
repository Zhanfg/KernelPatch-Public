/* SPDX-License-Identifier: GPL-2.0-or-later */
/* PatchNest: example opt-in decoder; no new supercall or hooks. */
#include <common.h>
#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <uapi/asm-generic/errno.h>
#include <patchnest_argv_v1.h>
#ifdef PATCHNEST_EVENT_ABI
#include <uapi/kpm_event.h>
#endif

KPM_NAME("patchnest-argv-demo");
KPM_VERSION("0.1.0");
KPM_LICENSE("GPL-2.0");
KPM_AUTHOR("PatchNest contributors");
KPM_DESCRIPTION("Safe opt-in PNARGV1 argument decoding example");

/* Never log individual arguments: they may contain user-private data. */
static int inspect_args(const char *raw, const char *channel)
{
    struct pn_argv_slice slices[PN_ARGV_COUNT_MAX];
    int count = pn_argv_decode(raw ? raw : "", slices, PN_ARGV_COUNT_MAX);
    if (count == PN_ARGV_LEGACY) {
        pr_info("PatchNest %s: legacy raw-string payload\n", channel);
        return count;
    }
    if (count < 0) {
        pr_info("PatchNest %s: malformed argument frame rejected\n", channel);
        return count;
    }
    pr_info("PatchNest %s: PNARGV1 items=%d\n", channel, count);
    return count;
}

static long argv_init(const char *args, const char *event, void *__user reserved)
{
    (void)event;
    (void)reserved;
    int rc = inspect_args(args, "init");
    return (rc == PN_ARGV_INVALID || rc == PN_ARGV_NO_SPACE) ? -EINVAL : 0;
}

static long argv_control(const char *args, char *__user out_msg, int outlen)
{
    char reply[72];
    int rc = inspect_args(args, "ctl0");
    int n;
    if (rc == PN_ARGV_INVALID || rc == PN_ARGV_NO_SPACE) return -EINVAL;
    n = snprintf(reply, sizeof(reply), rc == PN_ARGV_LEGACY ?
                 "mode=legacy\n" : "mode=PNARGV1 count=%d\n", rc);
    if (n < 0 || n >= (int)sizeof(reply)) return -EINVAL;
    if (!out_msg || outlen <= n) return -ENOBUFS;
    return compat_copy_to_user(out_msg, reply, (size_t)n + 1) ? -EFAULT : 0;
}

static long argv_exit(void *__user reserved)
{
    (void)reserved;
    return 0;
}

KPM_INIT(argv_init);
KPM_CTL0(argv_control);
KPM_EXIT(argv_exit);

/* Optional: only build with PATCHNEST_EVENT_ABI on kernels verified to
 * implement the PUBLIC1158 event callback layout. NEXT2026 is not enough.
 */
#ifdef PATCHNEST_EVENT_ABI
static long argv_event(const struct kpm_event_data *data)
{
    int rc = inspect_args(data ? data->args : "", "event");
    return (rc == PN_ARGV_INVALID || rc == PN_ARGV_NO_SPACE) ? -EINVAL : 0;
}
KPM_EVENT(argv_event);
#endif
