/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM struct member access API — inspired by ReSukiSU super_access.c.
 * Allows KPM modules to access kernel struct members by name,
 * avoiding direct kernel header dependency.
 */

#ifndef _KP_SUPER_ACCESS_H_
#define _KP_SUPER_ACCESS_H_

#include <ktypes.h>

/*
 * Get struct info: size and member count.
 * Returns 0 on success, -ENOENT if struct not known.
 */
int super_find_struct(const char *struct_name, size_t *out_size, int *out_members);

/*
 * Get a specific member's offset and size within a struct.
 * Returns 0 on success, -ENOENT if not found.
 */
int super_access(const char *struct_name, const char *member_name,
                 size_t *out_offset, size_t *out_size);

/*
 * Given a pointer to a struct and a member name, return pointer to the member.
 * Equivalent to container_of-style access.
 * Returns 0 on success.
 */
int super_container_of(const char *struct_name, const char *member_name,
                       void *ptr, void **out_ptr);

#endif
