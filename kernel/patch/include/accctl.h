/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_ACCCTL_H_
#define _KP_ACCCTL_H_

#include <ktypes.h>
#include <linux/cred.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <uapi/scdefs.h>
#include <uapi/app_profile.h>
#include <pgtable.h>
#include <taskext.h>
#include <asm/current.h>

extern char all_allow_sctx[SUPERCALL_SCONTEXT_LEN];
extern uint32_t all_allow_sid;

int set_all_allow_sctx(const char *sctx);
int commit_kernel_su();
int commit_common_su(uid_t to_uid, const char *sctx);
int commit_su(uid_t uid, const char *sctx);
int task_su(pid_t pid, uid_t to_uid, const char *sctx);

/* App profile system */
int app_profile_set(const struct app_profile *profile);
int app_profile_get(uid_t uid, struct app_profile *out);
int app_profile_list(uid_t *uids, int max_count);
int app_profile_num(void);
int commit_su_with_profile(const struct root_profile *rp);
int check_umount_modules(uid_t uid);

/* Safe mode */
extern int kp_safe_mode;

/* Umount hiding */
void umount_for_app(uid_t uid);
void umount_modules_for_current(void);
int umount_add_path(const char *path, unsigned int flags);
int umount_remove_path(const char *path);
void umount_set_enabled(int enable);
int umount_list_paths(char *out, int size);
void umount_init(void);

/**
 * @brief Whether to make the current task bypass all selinux permission checks.
 * 
 * @param task 
 * @param val 
 */
static inline void set_priv_sel_allow(struct task_struct *task, bool val)
{
    struct task_ext *ext = get_task_ext(task);
    ext->priv_sel_allow = val;
    dsb(ish);
}

#endif