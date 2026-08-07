/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM Crash Protection System
 */

#ifndef _KP_KPM_SAFETY_H_
#define _KP_KPM_SAFETY_H_

/* Begin exactly one transient attempt for the current boot. */
void kpm_safety_begin_boot_attempt(void);

/*
 * Persist/check the current attempt once /data is available.
 * Returns 1 when safe mode is required, 0 for normal operation, or a negative
 * errno when persistent state is unavailable/corrupt. Callers must treat a
 * negative result as degraded/fail-closed.
 */
int kpm_safety_persist_boot_attempt(void);

/* Confirm the current persisted attempt after boot-completed. */
int kpm_safety_confirm_boot_completed(void);

/*
 * Compatibility with the existing module_init() call sites.  These wrappers
 * deliberately perform no persistent /data accounting: module_init may run
 * before /data is mounted.  The persistent transition is owned exclusively by
 * the post-fs-data event path.
 */
static inline void kpm_safety_early_count(void)
{
    kpm_safety_begin_boot_attempt();
}

static inline int kpm_safety_check_boot_count(void)
{
    return 0;
}

/* Pre-load ELF validation */
int kpm_safety_validate(const void *data, int len);

/* Blacklist check: returns 1 if KPM should be skipped */
int kpm_safety_check_blacklist(const char *kpm_name);

/* Mark a KPM as currently being loaded (for crash attribution) */
void kpm_safety_mark_loading(const char *kpm_name);

/* Explicit blacklist management */
void kpm_safety_add_to_blacklist(const char *kpm_name);
void kpm_safety_clear_blacklist(void);

/* Init */
void kpm_safety_init(void);

#endif
