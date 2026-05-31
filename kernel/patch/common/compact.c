/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM compact symbol resolver — inspired by ReSukiSU/SukiSU-Ultra.
 * Provides a curated symbol table for KPM modules to access KP and kernel functions.
 */

#include <ktypes.h>
#include <common.h>
#include <log.h>
#include <linux/string.h>
#include <symbol.h>
#include <kallsyms.h>
#include <compact.h>
#include <accctl.h>
#include <kputils.h>
#include <linux/security.h>

/* Forward declarations for functions exposed to KPM modules */
extern int app_profile_set(const struct app_profile *profile);
extern int app_profile_get(uid_t uid, struct app_profile *out);
extern int check_umount_modules(uid_t uid);
extern int kp_safe_mode;

/* Curated symbol table — KPM modules can resolve these by name */
struct compact_symbol {
    const char *name;
    void *addr;
};

static struct compact_symbol compact_symbols[] = {
    /* Core KP functions */
    { "compact_find_symbol",        (void *)compact_find_symbol },
    { "kallsyms_lookup_name",       (void *)kallsyms_lookup_name },
    { "symbol_lookup_name",         (void *)symbol_lookup_name },

    /* Access control */
    { "is_su_allow_uid",            0 }, /* filled at init */
    { "commit_su",                  (void *)commit_su },
    { "commit_common_su",           (void *)commit_common_su },
    { "set_all_allow_sctx",         (void *)set_all_allow_sctx },

    /* App profile system */
    { "app_profile_set",            (void *)app_profile_set },
    { "app_profile_get",            (void *)app_profile_get },
    { "check_umount_modules",       (void *)check_umount_modules },

    /* Safe mode */
    { "kp_safe_mode",               (void *)&kp_safe_mode },

    /* Security */
    { "security_secctx_to_secid",   (void *)security_secctx_to_secid },
    { "set_security_override_from_ctx", (void *)set_security_override_from_ctx },

    /* Logging — these are macros in KP, provide wrappers below */
    { "compact_log_info",           0 }, /* filled at init */
    { "compact_log_error",          0 }, /* filled at init */

    /* Sentinel */
    { 0, 0 },
};

/* Log wrappers for KPM modules */
static void compact_log_info(const char *fmt, ...)
{
    /* KPM modules can use this for info logging */
    (void)fmt;
}

static void compact_log_error(const char *fmt, ...)
{
    (void)fmt;
}

unsigned long compact_find_symbol(const char *name)
{
    if (!name) return 0;

    /* Search curated table */
    for (int i = 0; compact_symbols[i].name; i++) {
        if (!strcmp(name, compact_symbols[i].name)) {
            return (unsigned long)compact_symbols[i].addr;
        }
    }

    /* Fallback to KP internal symbols */
    unsigned long addr = symbol_lookup_name(name);
    if (addr) return addr;

    /* Fallback to kernel kallsyms */
    addr = kallsyms_lookup_name(name);
    if (addr) return addr;

    return 0;
}

void compact_init(void)
{
    /* Fill dynamic addresses */
    for (int i = 0; compact_symbols[i].name; i++) {
        if (!strcmp(compact_symbols[i].name, "compact_log_info"))
            compact_symbols[i].addr = (void *)compact_log_info;
        if (!strcmp(compact_symbols[i].name, "compact_log_error"))
            compact_symbols[i].addr = (void *)compact_log_error;
    }
    log_boot("compact symbol resolver initialized\n");
}
