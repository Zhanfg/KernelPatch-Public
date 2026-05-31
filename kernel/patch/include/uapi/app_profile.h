/* SPDX-License-Identifier: GPL-2.0-later */
/*
 * App profile system inspired by KernelSU.
 * Provides per-app root/non-root profile management.
 */

#ifndef _KP_UAPI_APP_PROFILE_H_
#define _KP_UAPI_APP_PROFILE_H_

#include <stdint.h>

#define KP_APP_PROFILE_VER 1
#define KP_MAX_PACKAGE_NAME 256
#define KP_MAX_GROUPS 32
#define KP_SELINUX_DOMAIN 64

struct root_profile {
    int32_t uid;
    int32_t gid;

    uint32_t groups_count;
    int32_t groups[KP_MAX_GROUPS];

    /* kernel_cap_t is u32[2] for capabilities v3 */
    struct {
        uint64_t effective;
        uint64_t permitted;
        uint64_t inheritable;
    } capabilities;

    char selinux_domain[KP_SELINUX_DOMAIN];

    int32_t namespaces;
};

struct non_root_profile {
    int umount_modules; /* bool: unmount module overlays for this app */
};

struct app_profile {
    uint32_t version;

    /* usually the package name, but can be other value for special apps */
    char key[KP_MAX_PACKAGE_NAME];
    int32_t curr_uid;
    int allow_su; /* bool */

    union {
        struct {
            int use_default; /* bool */
            struct root_profile profile;
        } rp_config;

        struct {
            int use_default; /* bool */
            struct non_root_profile profile;
        } nrp_config;
    };
};

#endif
