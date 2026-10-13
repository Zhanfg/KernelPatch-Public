/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Host-side layout and protocol smoke test for the dual-backend ABI. */
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include "../include/patchnest/runtime_abi.h"

_Static_assert(sizeof(struct patchnest_request_v1) == 16,
               "request header layout changed");
_Static_assert(sizeof(struct patchnest_status_v1) == 32,
               "status layout changed");
_Static_assert(offsetof(struct patchnest_status_v1, boot_session_id) == 24,
               "status field offset changed");

int main(void)
{
    struct patchnest_status_v1 status = {
        .struct_size = sizeof(struct patchnest_status_v1),
        .abi_version = PATCHNEST_ABI_VERSION,
        .backend = PATCHNEST_BACKEND_PATCHED,
        .capabilities = PATCHNEST_CAP_KPM_LIST | PATCHNEST_CAP_SAFE_MODE,
        .safety_state = PATCHNEST_SAFETY_NOT_READY,
        .loaded_kpm_count = 0,
        .boot_session_id = 0,
    };
    struct patchnest_request_v1 request = {
        .size = sizeof(struct patchnest_request_v1),
        .abi_version = PATCHNEST_ABI_VERSION,
        .operation = PATCHNEST_OP_STATUS,
        .flags = 0,
    };
    assert(status.struct_size == 32);
    assert(PATCHNEST_ABI_MAJOR == 1);
    assert(PATCHNEST_BACKEND_BUILTIN != PATCHNEST_BACKEND_PATCHED);
    assert((status.capabilities & PATCHNEST_CAP_KPM_LOAD) == 0);
    assert(request.size == 16);
    assert(request.operation == PATCHNEST_OP_STATUS);
    puts("PatchNest management ABI v1: host layout PASS");
    return 0;
}
