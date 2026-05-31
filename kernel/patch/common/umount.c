/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Root/module detection hiding — inspired by ReSukiSU kernel_umount.c.
 * Unmounts module-related mount points for specific apps to prevent root detection.
 *
 * Trigger: setresuid syscall hook (when app process gets its real UID).
 * Config: runtime-configurable mount list via supercall.
 */

#include <ktypes.h>
#include <common.h>
#include <log.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/version.h>
#include <kallsyms.h>
#include <kputils.h>
#include <accctl.h>
#include <uapi/asm-generic/errno.h>

/* Mount entry for the umount list */
struct mount_entry {
    char path[256];
    unsigned int flags; /* MNT_DETACH=2, etc. */
    struct list_head list;
};

static LIST_HEAD(mount_list);
static DEFINE_RWLOCK(mount_list_lock);
static int umount_enabled = 1;

/* Default paths to unmount — these hide root/module traces */
static const char *default_paths[] = {
    "/data/adb/modules",
    "/data/adb/kp-next",
    "/data/adb/kp",
    "/data/adb/ap",
    "/data/adb/ksu",
    "/system",
    "/vendor",
    "/product",
    "/system_ext",
    NULL,
};

/* Resolve and call umount */
typedef int (*umount_fn_t)(const char __user *name, int flags);
static umount_fn_t resolve_umount(void)
{
    static umount_fn_t fn = NULL;
    if (fn) return fn;
    fn = (umount_fn_t)kallsyms_lookup_name("ksys_umount");
    if (!fn) fn = (umount_fn_t)kallsyms_lookup_name("do_umount");
    return fn;
}

static void try_umount_one(const char *mnt, int flags)
{
    struct path path;
    int err = kern_path(mnt, 0, &path);
    if (err) return;

    /* Only unmount if it's a root mountpoint (not already unmounted) */
    if (path.dentry != path.mnt->mnt_root) {
        path_put(&path);
        return;
    }
    path_put(&path);

    umount_fn_t umount_fn = resolve_umount();
    if (!umount_fn) return;

    /* Use MNT_DETACH (lazy) by default for safety */
    int use_flags = (flags > 0) ? flags : 2; /* MNT_DETACH */
    err = umount_fn((const char __user *)mnt, use_flags);
    if (err == 0) {
        logkfi("umount: detached %s\n", mnt);
    }
}

/*
 * Called when an app process gets its real UID (setresuid hook).
 * Checks if the app should have modules hidden, then unmounts.
 */
void umount_for_app(uid_t uid)
{
    if (!umount_enabled) return;

    /* Check app profile: only umount if configured */
    if (!check_umount_modules(uid)) return;

    read_lock(&mount_list_lock);
    struct mount_entry *entry;
    list_for_each_entry(entry, &mount_list, list) {
        try_umount_one(entry->path, entry->flags);
    }
    read_unlock(&mount_list_lock);
}

/*
 * Simplified version for execve hook (backward compat).
 * Checks current UID.
 */
void umount_modules_for_current(void)
{
    if (!umount_enabled) return;
    uid_t uid = current_uid();
    umount_for_app(uid);
}

/* --- Runtime configuration via supercall --- */

int umount_add_path(const char *path, unsigned int flags)
{
    if (!path || !path[0]) return -EINVAL;

    /* Check for duplicates */
    read_lock(&mount_list_lock);
    struct mount_entry *entry;
    list_for_each_entry(entry, &mount_list, list) {
        if (!strcmp(entry->path, path)) {
            read_unlock(&mount_list_lock);
            entry->flags = flags; /* update flags */
            return 0;
        }
    }
    read_unlock(&mount_list_lock);

    struct mount_entry *new_entry = vmalloc(sizeof(struct mount_entry));
    if (!new_entry) return -ENOMEM;
    strncpy(new_entry->path, path, sizeof(new_entry->path) - 1);
    new_entry->path[sizeof(new_entry->path) - 1] = '\0';
    new_entry->flags = flags ? flags : 2; /* default MNT_DETACH */

    write_lock(&mount_list_lock);
    list_add_tail(&new_entry->list, &mount_list);
    write_unlock(&mount_list_lock);

    logkfi("umount: added path %s flags=%u\n", path, new_entry->flags);
    return 0;
}

int umount_remove_path(const char *path)
{
    if (!path) return -EINVAL;
    write_lock(&mount_list_lock);
    struct mount_entry *entry, *tmp;
    list_for_each_entry_safe(entry, tmp, &mount_list, list) {
        if (!strcmp(entry->path, path)) {
            list_del(&entry->list);
            vfree(entry);
            write_unlock(&mount_list_lock);
            logkfi("umount: removed path %s\n", path);
            return 0;
        }
    }
    write_unlock(&mount_list_lock);
    return -ENOENT;
}

void umount_set_enabled(int enable)
{
    umount_enabled = !!enable;
    logkfi("umount: %s\n", enable ? "enabled" : "disabled");
}

int umount_list_paths(char *out, int size)
{
    int off = 0;
    read_lock(&mount_list_lock);
    struct mount_entry *entry;
    list_for_each_entry(entry, &mount_list, list) {
        off += snprintf(out + off, size - 1 - off, "%s (flags=%u)\n",
                        entry->path, entry->flags);
    }
    read_unlock(&mount_list_lock);
    if (off > 0) out[off - 1] = '\0';
    return off;
}

/* Initialize with default paths */
void umount_init(void)
{
    for (int i = 0; default_paths[i]; i++) {
        umount_add_path(default_paths[i], 2 /* MNT_DETACH */);
    }
    log_boot("umount: initialized with %d default paths\n",
             (int)(sizeof(default_paths) / sizeof(default_paths[0]) - 1));
}
