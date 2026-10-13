/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * PatchNest dual-backend management ABI, version 1.
 *
 * This is a wire contract shared by an in-tree kernel implementation,
 * an image-patched kpimg implementation, and their management clients.
 * Declaring the ABI does NOT mean an implementation is already connected.
 *
 * Never pass raw user pointers, kernel addresses, or function pointers
 * through this structure. Every implementation must authenticate each
 * mutating operation, validate size/version, and copy bounded payloads.
 */
#ifndef PATCHNEST_RUNTIME_ABI_H
#define PATCHNEST_RUNTIME_ABI_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef __u32 pn_u32;
typedef __u64 pn_u64;
#else
#include <stdint.h>
typedef uint32_t pn_u32;
typedef uint64_t pn_u64;
#endif

#define PATCHNEST_ABI_MAJOR 1u
#define PATCHNEST_ABI_MINOR 0u
#define PATCHNEST_ABI_VERSION ((PATCHNEST_ABI_MAJOR << 16) | PATCHNEST_ABI_MINOR)
#define PATCHNEST_KPM_NAME_MAX 64u

/* Backends are mutually exclusive for an active kernel session. */
enum patchnest_backend {
    PATCHNEST_BACKEND_NONE = 0,
    PATCHNEST_BACKEND_BUILTIN = 1,  /* compiled into kernel, distributed in AK3 */
    PATCHNEST_BACKEND_PATCHED = 2,  /* freestanding kpimg, offline image patch */
};

/* Advertised capabilities, never infer support from backend type alone. */
#define PATCHNEST_CAP_KPM_LIST    (1u << 0)
#define PATCHNEST_CAP_KPM_LOAD    (1u << 1)
#define PATCHNEST_CAP_KPM_UNLOAD  (1u << 2)
#define PATCHNEST_CAP_KPM_EVENT   (1u << 3)
#define PATCHNEST_CAP_EMBEDDED    (1u << 4)
#define PATCHNEST_CAP_SAFE_MODE   (1u << 5)
#define PATCHNEST_CAP_AUDIT_LOG   (1u << 6)

enum patchnest_safety_state {
    PATCHNEST_SAFETY_NOT_READY = 0,
    PATCHNEST_SAFETY_READY = 1,
    PATCHNEST_SAFETY_QUARANTINED = 2,
    PATCHNEST_SAFETY_SAFE_MODE = 3
};

/*
 * First-stage readonly handshake. Client initializes struct_size to
 * sizeof(struct patchnest_status_v1). Providers must reject smaller
 * structures and zero fields they do not support. Integers are native
 * endian, little-endian on supported Android arm64 targets.
 */
struct patchnest_status_v1 {
    pn_u32 struct_size;
    pn_u32 abi_version;
    pn_u32 backend;
    pn_u32 capabilities;
    pn_u32 safety_state;
    pn_u32 loaded_kpm_count;
    pn_u64 boot_session_id;
};

enum patchnest_operation {
    PATCHNEST_OP_STATUS = 1,
    PATCHNEST_OP_LIST_KPM = 2,
    PATCHNEST_OP_LOAD_KPM = 3,
    PATCHNEST_OP_UNLOAD_KPM = 4,
    PATCHNEST_OP_DISPATCH_EVENT = 5,
    PATCHNEST_OP_READ_AUDIT = 6,
};

/*
 * All requests have this prefix. size includes the complete payload.
 * No operation may bypass caller authentication or safe-mode gating.
 * Runtime implementations set strict maximum payload lengths per op.
 */
struct patchnest_request_v1 {
    pn_u32 size;
    pn_u32 abi_version;
    pn_u32 operation;
    pn_u32 flags;             /* MUST be zero in v1 */
};

#endif /* PATCHNEST_RUNTIME_ABI_H */
