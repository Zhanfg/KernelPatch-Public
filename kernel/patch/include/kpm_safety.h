/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM Crash Protection System
 */

#ifndef _KP_KPM_SAFETY_H_
#define _KP_KPM_SAFETY_H_

/* Boot counter: returns 1 if safe mode should be activated */
int kpm_safety_check_boot_count(void);

/* Confirm boot succeeded — resets counter */
void kpm_safety_confirm_boot(void);
void kpm_safety_confirm_boot_completed(void);

/* Pre-load ELF validation */
int kpm_safety_validate(const void *data, int len);

/* Blacklist check: returns 1 if KPM should be skipped */
int kpm_safety_check_blacklist(const char *kpm_name);

/* Mark a KPM as currently being loaded (for crash detection) */
void kpm_safety_mark_loading(const char *kpm_name);

/* Explicit blacklist management */
void kpm_safety_add_to_blacklist(const char *kpm_name);
void kpm_safety_clear_blacklist(void);

/* Init */
void kpm_safety_init(void);

#endif
