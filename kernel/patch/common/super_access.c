/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM struct member access — inspired by ReSukiSU.
 * Runtime struct introspection for KPM modules.
 * Avoids hard dependency on specific kernel header versions.
 */

#include <ktypes.h>
#include <common.h>
#include <log.h>
#include <linux/string.h>
#include <uapi/asm-generic/errno.h>
#include <super_access.h>

struct dynamic_member {
    const char *name;
    size_t size;
    size_t offset;
};

struct dynamic_struct {
    const char *name;
    size_t member_count;
    size_t total_size;
    struct dynamic_member *members;
};

/* --- cred struct --- */
#include <linux/cred.h>

static struct dynamic_member cred_members[] = {
    { "uid",         sizeof((struct cred *)0)->uid,         offsetof(struct cred, uid) },
    { "gid",         sizeof((struct cred *)0)->gid,         offsetof(struct cred, gid) },
    { "euid",        sizeof((struct cred *)0)->euid,        offsetof(struct cred, euid) },
    { "egid",        sizeof((struct cred *)0)->egid,        offsetof(struct cred, egid) },
    { "suid",        sizeof((struct cred *)0)->suid,        offsetof(struct cred, suid) },
    { "sgid",        sizeof((struct cred *)0)->sgid,        offsetof(struct cred, sgid) },
    { "fsuid",       sizeof((struct cred *)0)->fsuid,       offsetof(struct cred, fsuid) },
    { "fsgid",       sizeof((struct cred *)0)->fsgid,       offsetof(struct cred, fsgid) },
};

static struct dynamic_struct cred_struct = {
    .name = "cred",
    .member_count = sizeof(cred_members) / sizeof(cred_members[0]),
    .total_size = sizeof(struct cred),
    .members = cred_members,
};

/* --- task_struct (partial, using offsets from KP) --- */
#include <linux/sched.h>
#include <taskext.h>

static struct dynamic_member task_struct_members[] = {
    /* We expose only commonly-needed members.
     * Actual offsets are resolved at runtime via task_struct_offset. */
    { "pid",          sizeof(pid_t),             0 }, /* placeholder */
    { "tgid",         sizeof(pid_t),             0 }, /* placeholder */
    { "comm",         16,                        0 }, /* placeholder */
};

static struct dynamic_struct task_struct_struct = {
    .name = "task_struct",
    .member_count = sizeof(task_struct_members) / sizeof(task_struct_members[0]),
    .total_size = 0, /* unknown at compile time */
    .members = task_struct_members,
};

/* --- All known structs --- */
static struct dynamic_struct *all_structs[] = {
    &cred_struct,
    &task_struct_struct,
    NULL,
};

int super_find_struct(const char *struct_name, size_t *out_size, int *out_members)
{
    if (!struct_name) return -EINVAL;

    for (int i = 0; all_structs[i]; i++) {
        if (!strcmp(struct_name, all_structs[i]->name)) {
            if (out_size) *out_size = all_structs[i]->total_size;
            if (out_members) *out_members = (int)all_structs[i]->member_count;
            return 0;
        }
    }
    return -ENOENT;
}

int super_access(const char *struct_name, const char *member_name,
                 size_t *out_offset, size_t *out_size)
{
    if (!struct_name || !member_name) return -EINVAL;

    for (int i = 0; all_structs[i]; i++) {
        if (strcmp(struct_name, all_structs[i]->name)) continue;

        struct dynamic_struct *s = all_structs[i];
        for (size_t j = 0; j < s->member_count; j++) {
            if (!strcmp(member_name, s->members[j].name)) {
                if (out_offset) *out_offset = s->members[j].offset;
                if (out_size) *out_size = s->members[j].size;
                return 0;
            }
        }
        return -ENOENT;
    }
    return -ENOENT;
}

int super_container_of(const char *struct_name, const char *member_name,
                       void *ptr, void **out_ptr)
{
    size_t offset;
    int rc = super_access(struct_name, member_name, &offset, NULL);
    if (rc) return rc;
    if (!ptr || !out_ptr) return -EINVAL;
    *out_ptr = (void *)((uintptr_t)ptr - offset);
    return 0;
}
