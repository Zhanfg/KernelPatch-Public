/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "kpm.h"

int get_kpm_info(const char *kpm, int len, kpm_info_t *out_info)
{
    struct kpm_metadata meta;
    struct kpm_sections sections;
    int rc = kpm_validate(kpm, len, &sections, &meta);
    if (rc) return rc;
    out_info->name = meta.name;
    out_info->version = meta.version;
    out_info->license = meta.license ? meta.license : "(null)";
    out_info->author = meta.author ? meta.author : "(null)";
    out_info->description = meta.description ? meta.description : "(null)";
    return 0;
}

void print_kpm_info(kpm_info_t *info)
{
    fprintf(stdout, "name=%s\n", info->name);
    fprintf(stdout, "version=%s\n", info->version);
    fprintf(stdout, "license=%s\n", info->license);
    fprintf(stdout, "author=%s\n", info->author);
    fprintf(stdout, "description=%s\n", info->description);
}

int print_kpm_info_path(const char *kpm_path)
{
    char *img;
    int len = 0;
    read_file_align(kpm_path, &img, &len, 1, KPM_MAX_FILE_SIZE);
    kpm_info_t kpm_info = { 0 };
    int rc = get_kpm_info(img, len, &kpm_info);
    if (!rc) {
        fprintf(stdout, INFO_EXTRA_KPM_SESSION "\n");
        print_kpm_info(&kpm_info);
    } else {
        fprintf(stderr, "invalid KPM: %s (expected AArch64 RELA with .kpm.info and .kpm.init)\n", kpm_path);
    }
    free(img);
    return rc;
}
