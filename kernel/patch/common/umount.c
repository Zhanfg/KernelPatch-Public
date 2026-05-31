/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Root/module detection hiding — inspired by ReSukiSU kernel_umount.c.
 * Unmounts module-related mount points for specific apps.
 */

#include <ktypes.h>
#include <common.h>
#include <log.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <kallsyms.h>
#include <kputils.h>
#include <accctl.h>
#include <uapi/asm-generic/errno.h>

struct mount_entry {
    char path[256];
    unsigned int flags;
    struct list_head list;
};

static LIST_HEAD(mount_list);
static spinlock_t mount_list_lock;
static int umount_initialized = 0;
static int umount_enabled = 1;

static const char *default_paths[] = {
    "/data/adb/modules",
    "/data/adb/kp-next",
    "/data/adb/kp",
    "/data/adb/ap",
    "/data/adb/ksu",
    NULL,
};

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
    umount_fn_t umount_fn = resolve_umount();
    if (!umount_fn) return;
    int use_flags = (flags > 0) ? flags : 2; /* MNT_DETACH */
    int err = umount_fn((const char __user *)mnt, use_flags);
    if (err == 0) {
        logkfi("umount: detached %s\n", mnt);
    }
}

void umount_for_app(uid_t uid)
{
    if (!umount_enabled || !umount_initialized) return;
    if (!check_umount_modules(uid)) return;

    spin_lock(&mount_list_lock);
    struct mount_entry *entry;
    list_for_each_entry(entry, &mount_list, list) {
        try_umount_one(entry->path, entry->flags);
    }
    spin_unlock(&mount_list_lock);
}

void umount_modules_for_current(void)
{
    if (!umount_enabled || !umount_initialized) return;
    umount_for_app(current_uid());
}

int umount_add_path(const char *path, unsigned int flags)
{
    if (!path || !path[0]) return -EINVAL;

    spin_lock(&mount_list_lock);
    /* Check duplicates */
    struct mount_entry *entry;
    list_for_each_entry(entry, &mount_list, list) {
        if (!strcmp(entry->path, path)) {
            entry->flags = flags ? flags : 2;
            spin_unlock(&mount_list_lock);
            return 0;
        }
    }

    struct mount_entry *ne = vmalloc(sizeof(struct mount_entry));
    if (!ne) {
        spin_unlock(&mount_list_lock);
        return -ENOMEM;
    }
    strncpy(ne->path, path, sizeof(ne->path) - 1);
    ne->path[sizeof(ne->path) - 1] = '\0';
    ne->flags = flags ? flags : 2;
    list_add_tail(&ne->list, &mount_list);
    spin_unlock(&mount_list_lock);

    logkfi("umount: added %s\n", path);
    return 0;
}

int umount_remove_path(const char *path)
{
    if (!path) return -EINVAL;
    spin_lock(&mount_list_lock);
    struct mount_entry *entry, *tmp;
    list_for_each_entry_safe(entry, tmp, &mount_list, list) {
        if (!strcmp(entry->path, path)) {
            list_del(&entry->list);
            vfree(entry);
            spin_unlock(&mount_list_lock);
            return 0;
        }
    }
    spin_unlock(&mount_list_lock);
    return -ENOENT;
}

void umount_set_enabled(int enable)
{
    umount_enabled = !!enable;
}

int umount_list_paths(char *out, int size)
{
    int off = 0;
    spin_lock(&mount_list_lock);
    struct mount_entry *entry;
    list_for_each_entry(entry, &mount_list, list) {
        int remaining = size - 1 - off;
        if (remaining <= 0) break;
        int n = strlen(entry->path);
        if (n > remaining) n = remaining;
        memcpy(out + off, entry->path, n);
        off += n;
        if (off < size - 1) out[off++] = '\n';
    }
    spin_unlock(&mount_list_lock);
    if (off > 0) out[off - 1] = '\0';
    else out[0] = '\0';
    return off;
}

void umount_init(void)
{
    spin_lock_init(&mount_list_lock);
    for (int i = 0; default_paths[i]; i++) {
        umount_add_path(default_paths[i], 2);
    }
    umount_initialized = 1;
    log_boot("umount: initialized with default paths\n");
}
