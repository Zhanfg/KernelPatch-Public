/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM struct member access — inspired by ReSukiSU.
 * Runtime struct introspection for KPM modules.
 * Uses KP's predata offsets instead of direct struct references.
 */

#include <ktypes.h>
#include <common.h>
#include <log.h>
#include <linux/string.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <uapi/asm-generic/errno.h>
#include <predata.h>
#include <super_access.h>

struct dynamic_member {
    const char *name;
    size_t size;
    size_t offset;
};

struct dynamic_struct {
    const char *name;
    size_t member_count;
    struct dynamic_member *members;
};

/* Members are filled at init using KP's predata offsets */
#define MAX_MEMBERS 16

static struct dynamic_member cred_members[MAX_MEMBERS];
static int cred_member_count = 0;

static struct dynamic_struct cred_struct = {
    .name = "cred",
    .member_count = 0,
    .members = cred_members,
};

static struct dynamic_struct *all_structs[] = {
    &cred_struct,
    NULL,
};

void super_access_init(void)
{
    /* Fill cred struct members from KP's runtime-detected offsets */
    int i = 0;

    #define ADD_CRED_MEMBER(field, type) do { \
        if (i < MAX_MEMBERS && cred_offset.field##_offset) { \
            cred_members[i].name = #field; \
            cred_members[i].size = sizeof(type); \
            cred_members[i].offset = cred_offset.field##_offset; \
            i++; \
        } \
    } while (0)

    ADD_CRED_MEMBER(uid, uid_t);
    ADD_CRED_MEMBER(gid, uid_t);
    ADD_CRED_MEMBER(euid, uid_t);
    ADD_CRED_MEMBER(egid, uid_t);
    ADD_CRED_MEMBER(suid, uid_t);
    ADD_CRED_MEMBER(sgid, uid_t);
    ADD_CRED_MEMBER(fsuid, uid_t);
    ADD_CRED_MEMBER(fsgid, uid_t);
    ADD_CRED_MEMBER(cap_inheritable, kernel_cap_t);
    ADD_CRED_MEMBER(cap_permitted, kernel_cap_t);
    ADD_CRED_MEMBER(cap_effective, kernel_cap_t);
    ADD_CRED_MEMBER(cap_bset, kernel_cap_t);
    ADD_CRED_MEMBER(cap_ambient, kernel_cap_t);

    cred_member_count = i;
    cred_struct.member_count = i;

    log_boot("super_access: %d cred members registered\n", i);
}

int super_find_struct(const char *struct_name, size_t *out_size, int *out_members)
{
    if (!struct_name) return -EINVAL;

    for (int i = 0; all_structs[i]; i++) {
        if (!strcmp(struct_name, all_structs[i]->name)) {
            if (out_size) *out_size = 0; /* size unknown at compile time */
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
