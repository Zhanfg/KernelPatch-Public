/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#ifndef _KP_TOOL_KPM_H_
#define _KP_TOOL_KPM_H_

#include "elf/elf.h"
#include "common.h"

#include "../include/kpm_elf.h"

#define INFO_EXTRA_KPM_SESSION "[kpm]"

typedef struct
{
    const char *name, *version, *license, *author, *description;
} kpm_info_t;

int get_kpm_info(const char *kpm, int len, kpm_info_t *info);

void print_kpm_info(kpm_info_t *info);
int print_kpm_info_path(const char *kpm_path);

#endif