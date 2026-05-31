/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Module umount for non-root apps.
 * Unmounts module overlay mount points to prevent root detection.
 */

#include <ktypes.h>
#include <common.h>
#include <log.h>
#include <accctl.h>
#include <linux/string.h>
#include <linux/umh.h>
#include <kputils.h>

/* Paths where modules may be overlaid */
static const char *module_mount_paths[] = {
    "/system",
    "/vendor",
    "/product",
    "/system_ext",
    "/data/adb/modules",
    NULL
};

/*
 * Get ksys_umount function pointer.
 * ksys_umount is exported in most kernels; fallback to do_umount via kallsyms.
 */
typedef int (*umount_fn_t)(char __user *name, int flags);
static umount_fn_t ksys_umount_ptr = NULL;

static int resolve_umount_fn(void)
{
    if (ksys_umount_ptr) return 0;
    ksys_umount_ptr = (umount_fn_t)kallsyms_lookup_name("ksys_umount");
    if (!ksys_umount_ptr) {
        ksys_umount_ptr = (umount_fn_t)kallsyms_lookup_name("__x64_sys_umount2");
    }
    return ksys_umount_ptr ? 0 : -ENOENT;
}

/*
 * Called after execve for apps with umount_modules flag.
 * Unmounts overlay mounts for known module paths.
 */
void umount_modules_for_current(void)
{
    if (resolve_umount_fn()) {
        logkfe("umount: ksys_umount not found\n");
        return;
    }

    uid_t uid = current_uid();
    if (!check_umount_modules(uid)) return;

    for (int i = 0; module_mount_paths[i]; i++) {
        /*
         * Use MNT_DETACH (2) for lazy unmount — detaches from namespace
         * but doesn't force busy mounts to fail.
         */
        const char *path = module_mount_paths[i];
        int rc = ksys_umount_ptr((char __user *)path, 2 /* MNT_DETACH */);
        if (rc == 0) {
            logkfi("umount: detached %s for uid %d\n", path, uid);
        }
    }
}
