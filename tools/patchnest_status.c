// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PatchNest built-in backend status probe. Read-only by construction.
 * This tool MUST NOT mistake successful root access for KPM support.
 *
 * For patched kernels, an eventual patched-backend adapter will provide
 * the same ABI data; do not infer runtime capabilities from kpatch hello.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "../include/patchnest/runtime_abi.h"

int main(int argc, char **argv)
{
    struct patchnest_status_v1 status = {
        .struct_size = sizeof(struct patchnest_status_v1),
        .abi_version = PATCHNEST_ABI_VERSION,
    };
    int fd;
    int rc;

    (void)argv;
    if (argc != 1) {
        fprintf(stderr, "usage: patchnest-status\n");
        return 2;
    }

    fd = open("/dev/patchnest", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "PatchNest native control device unavailable: %s\n",
                strerror(errno));
        return errno == ENOENT ? 4 : 6;
    }

    rc = ioctl(fd, PATCHNEST_IOCTL_STATUS, &status);
    if (rc < 0) {
        int saved_errno = errno;
        fprintf(stderr, "PatchNest ABI negotiation failed: %s\n",
                strerror(saved_errno));
        close(fd);
        return saved_errno == ENOTTY || saved_errno == EPROTONOSUPPORT ? 4 : 6;
    }
    close(fd);

    if (status.struct_size != sizeof(status) ||
        (status.abi_version >> 16) != PATCHNEST_ABI_MAJOR ||
        (status.abi_version & 0xffffu) != PATCHNEST_ABI_MINOR ||
        status.backend != PATCHNEST_BACKEND_BUILTIN) {
        fprintf(stderr, "PatchNest backend returned incompatible status\n");
        return 4;
    }

    printf("abi=%u.%u\nbackend=native\ncapabilities=0x%x\nsafety=%u\n"
           "loaded=%u\n",
           status.abi_version >> 16, status.abi_version & 0xffffu,
           status.capabilities, status.safety_state, status.loaded_kpm_count);
    return 0;
}
