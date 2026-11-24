/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "kpm.h"

/* The caller verifies that the last record ends inside the section. */
static const char *get_modinfo(const char *base, size_t size, const char *tag)
{
    size_t taglen = strlen(tag);
    const char *end = base + size;
    for (const char *p = base; p < end; p += strlen(p) + 1) {
        if (!strncmp(p, tag, taglen) && p[taglen] == '=') return p + taglen + 1;
    }
    return NULL;
}

int get_kpm_info(const char *kpm, int len, kpm_info_t *out_info)
{
    Elf64_Ehdr hdr;
    if (!kpm || len <= (int)sizeof(hdr) || len > KPM_MAX_FILE_SIZE) return -ENOEXEC;
    memcpy(&hdr, kpm, sizeof(hdr));
    if (memcmp(hdr.e_ident, ELFMAG, SELFMAG) || hdr.e_type != ET_REL || hdr.e_machine != EM_AARCH64 ||
        hdr.e_shentsize != sizeof(Elf64_Shdr)) return -ENOEXEC;
    if (kpm_validate_sections(kpm, len, &hdr)) return -ENOEXEC;

    const char *table = kpm + hdr.e_shoff;
    const char *names = kpm + kpm_section(table, hdr.e_shstrndx).sh_offset;
    for (unsigned int i = 1; i < hdr.e_shnum; i++) {
        Elf64_Shdr sh = kpm_section(table, i);
        if (!(sh.sh_flags & SHF_ALLOC) || strcmp(names + sh.sh_name, ".kpm.info")) continue;
        if (sh.sh_type == SHT_NOBITS || !sh.sh_size) return -ENOEXEC;
        const char *base = kpm + sh.sh_offset;
        if (base[sh.sh_size - 1]) return -ENOEXEC;

        out_info->name = get_modinfo(base, sh.sh_size, "name");
        out_info->version = get_modinfo(base, sh.sh_size, "version");
        if (!out_info->name || !out_info->version) return -ENOEXEC;
        out_info->license = get_modinfo(base, sh.sh_size, "license");
        out_info->author = get_modinfo(base, sh.sh_size, "author");
        out_info->description = get_modinfo(base, sh.sh_size, "description");
        if (!out_info->license) out_info->license = "(null)";
        if (!out_info->author) out_info->author = "(null)";
        if (!out_info->description) out_info->description = "(null)";
        return 0;
    }
    return -ENOEXEC;
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
        fprintf(stderr, "invalid KPM metadata: %s\n", kpm_path);
    }
    free(img);
    return rc;
}
