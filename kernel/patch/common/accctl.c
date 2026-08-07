/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include "accctl.h"

#include <pgtable.h>
#include <ksyms.h>
#include <taskext.h>
#include <uapi/scdefs.h>
#include <linux/spinlock.h>
#include <linux/capability.h>
#include <linux/security.h>
#include <asm/current.h>
#include <linux/pid.h>
#include <linux/sched/task.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <asm/thread_info.h>
#include <uapi/asm-generic/errno.h>
#include <hook.h>
#include <linux/string.h>
#include <security/selinux/include/avc.h>
#include <security/selinux/include/security.h>
#include <predata.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <kputils.h>

char all_allow_sctx[SUPERCALL_SCONTEXT_LEN] = { '\0' };
uint32_t all_allow_sid = SECSID_NULL;

static void su_cred(struct cred *cred, uid_t uid)
{
    *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_inheritable_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_permitted_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_effective_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_bset_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)cred + cred_offset.cap_ambient_offset) = full_cap;

    *(uid_t *)((uintptr_t)cred + cred_offset.uid_offset) = uid;
    *(uid_t *)((uintptr_t)cred + cred_offset.euid_offset) = uid;
    *(uid_t *)((uintptr_t)cred + cred_offset.fsuid_offset) = uid;
    *(uid_t *)((uintptr_t)cred + cred_offset.suid_offset) = uid;

    *(uid_t *)((uintptr_t)cred + cred_offset.gid_offset) = uid;
    *(uid_t *)((uintptr_t)cred + cred_offset.egid_offset) = uid;
    *(uid_t *)((uintptr_t)cred + cred_offset.fsgid_offset) = uid;
    *(uid_t *)((uintptr_t)cred + cred_offset.sgid_offset) = uid;
}

int set_all_allow_sctx(const char *sctx)
{
    if (!sctx || !sctx[0]) {
        all_allow_sctx[0] = 0;
        all_allow_sid = SECSID_NULL;
        dsb(ish);
        logkfd("clear all allow sconetxt\n");
        return 0;
    }

    int rc = security_secctx_to_secid(sctx, strlen(sctx), &all_allow_sid);
    if (!rc && all_allow_sid != SECSID_NULL) {
        strncpy(all_allow_sctx, sctx, sizeof(all_allow_sctx) - 1);
        all_allow_sctx[sizeof(all_allow_sctx) - 1] = '\0';
        dsb(ish);
        logkfd("set all allow sconetxt: %s, sid: %d\n", all_allow_sctx, all_allow_sid);
    }
    return rc;
}

int commit_kernel_su()
{
    struct cred *new = prepare_kernel_cred(0);
    if (!new) return -ENOMEM;
    set_security_override(new, all_allow_sid);
    return commit_creds(new);
}

int commit_common_su(uid_t to_uid, const char *sctx)
{
    int rc = 0;
    struct task_struct *task = current;
    struct task_ext *ext = get_task_ext(task);
    struct cred *new;
    struct group_info *group_info;

    if (unlikely(!task_ext_valid(ext))) {
        logkfe("dirty task_ext, pid(maybe dirty): %d\n", ext->pid);
        return -ENOMEM;
    }

    /* Preserve existing seccomp state; this transition replaces credentials only. */
    ext->sel_allow = 1;
    new = prepare_creds();
    if (!new) return -ENOMEM;
    su_cred(new, to_uid);

    group_info = groups_alloc(0);
    if (!group_info || IS_ERR(group_info)) {
        abort_creds(new);
        return group_info ? PTR_ERR(group_info) : -ENOMEM;
    }
    set_groups(new, group_info);

    if (sctx && sctx[0]) {
        ext->sel_allow = !!set_security_override_from_ctx(new, sctx);
    }
    rc = commit_creds(new);

    logkfi("pid: %d, tgid: %d, to_uid: %d, sctx: %s, via_hook: %d\n", ext->pid, ext->tgid, to_uid,
           sctx ?: "", ext->sel_allow);
    return rc;
}

int commit_su(uid_t to_uid, const char *sctx)
{
    if (all_allow_sid != SECSID_NULL && !to_uid) {
        return commit_kernel_su();
    } else {
        return commit_common_su(to_uid, sctx);
    }
}

int task_su(pid_t pid, uid_t to_uid, const char *sctx)
{
    /*
     * Remote task elevation used to mutate task->cred/real_cred and seccomp
     * fields in place. Those objects can be shared and are governed by RCU,
     * refcount and target-task synchronization rules; no lock around these raw
     * writes can make that design valid. Until a target-context task_work style
     * handoff is implemented and proved for all supported kernels, fail closed.
     */
    (void)to_uid;
    (void)sctx;
    logkfe("remote task_su is unsupported for pid=%d; target-context handoff required\n", pid);
    return -EOPNOTSUPP;
}

/* Safe mode flag — set by userspace via SUPERCALL_SET_SAFEMODE */
int kp_safe_mode = 0;

/* App profile storage */
#define MAX_APP_PROFILES 256
static struct app_profile *app_profiles[MAX_APP_PROFILES];
static int app_profile_count = 0;
static DEFINE_SPINLOCK(app_profile_lock);

int app_profile_set(const struct app_profile *profile)
{
    if (!profile || profile->version != KP_APP_PROFILE_VER) return -EINVAL;

    spin_lock(&app_profile_lock);

    for (int i = 0; i < app_profile_count; i++) {
        if (app_profiles[i] && app_profiles[i]->curr_uid == profile->curr_uid &&
            strncmp(app_profiles[i]->key, profile->key, KP_MAX_PACKAGE_NAME) == 0) {
            memcpy(app_profiles[i], profile, sizeof(struct app_profile));
            spin_unlock(&app_profile_lock);
            return 0;
        }
    }

    if (app_profile_count >= MAX_APP_PROFILES) {
        spin_unlock(&app_profile_lock);
        return -ENOMEM;
    }

    struct app_profile *new_profile = vmalloc(sizeof(struct app_profile));
    if (!new_profile) {
        spin_unlock(&app_profile_lock);
        return -ENOMEM;
    }
    memcpy(new_profile, profile, sizeof(struct app_profile));
    app_profiles[app_profile_count++] = new_profile;

    spin_unlock(&app_profile_lock);
    return 0;
}

int app_profile_get(uid_t uid, struct app_profile *out)
{
    int rc = -ENOENT;
    spin_lock(&app_profile_lock);
    for (int i = 0; i < app_profile_count; i++) {
        if (app_profiles[i] && app_profiles[i]->curr_uid == (int32_t)uid) {
            memcpy(out, app_profiles[i], sizeof(struct app_profile));
            rc = 0;
            break;
        }
    }
    spin_unlock(&app_profile_lock);
    return rc;
}

int app_profile_list(uid_t *uids, int max_count)
{
    int count = 0;
    spin_lock(&app_profile_lock);
    for (int i = 0; i < app_profile_count && count < max_count; i++) {
        if (app_profiles[i]) {
            uids[count++] = app_profiles[i]->curr_uid;
        }
    }
    spin_unlock(&app_profile_lock);
    return count;
}

int app_profile_num(void)
{
    return app_profile_count;
}

int commit_su_with_profile(const struct root_profile *rp)
{
    if (!rp) return -EINVAL;

    int rc = 0;
    struct task_struct *task = current;
    struct task_ext *ext = get_task_ext(task);
    struct cred *new;

    if (unlikely(!task_ext_valid(ext))) {
        logkfe("dirty task_ext, pid: %d\n", ext->pid);
        return -ENOMEM;
    }

    /* Preserve the current task's seccomp policy; only replace credentials. */
    ext->sel_allow = 1;
    new = prepare_creds();
    if (!new) return -ENOMEM;

    uid_t to_uid = rp->uid >= 0 ? (uid_t)rp->uid : current_uid();
    *(uid_t *)((uintptr_t)new + cred_offset.uid_offset) = to_uid;
    *(uid_t *)((uintptr_t)new + cred_offset.euid_offset) = to_uid;
    *(uid_t *)((uintptr_t)new + cred_offset.fsuid_offset) = to_uid;
    *(uid_t *)((uintptr_t)new + cred_offset.suid_offset) = to_uid;

    gid_t to_gid = rp->gid >= 0 ? (gid_t)rp->gid : to_uid;
    *(gid_t *)((uintptr_t)new + cred_offset.gid_offset) = to_gid;
    *(gid_t *)((uintptr_t)new + cred_offset.egid_offset) = to_gid;
    *(gid_t *)((uintptr_t)new + cred_offset.fsgid_offset) = to_gid;
    *(gid_t *)((uintptr_t)new + cred_offset.sgid_offset) = to_gid;

    if (rp->capabilities.effective || rp->capabilities.permitted || rp->capabilities.inheritable) {
        kernel_cap_t cap;
        cap.val = rp->capabilities.effective;
        *(kernel_cap_t *)((uintptr_t)new + cred_offset.cap_effective_offset) = cap;
        cap.val = rp->capabilities.permitted;
        *(kernel_cap_t *)((uintptr_t)new + cred_offset.cap_permitted_offset) = cap;
        cap.val = rp->capabilities.inheritable;
        *(kernel_cap_t *)((uintptr_t)new + cred_offset.cap_inheritable_offset) = cap;
    } else {
        *(kernel_cap_t *)((uintptr_t)new + cred_offset.cap_inheritable_offset) = full_cap;
        *(kernel_cap_t *)((uintptr_t)new + cred_offset.cap_permitted_offset) = full_cap;
        *(kernel_cap_t *)((uintptr_t)new + cred_offset.cap_effective_offset) = full_cap;
    }
    *(kernel_cap_t *)((uintptr_t)new + cred_offset.cap_bset_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)new + cred_offset.cap_ambient_offset) = full_cap;

    if (rp->groups_count > 0 && rp->groups_count <= KP_MAX_GROUPS) {
        struct group_info *gi = groups_alloc(rp->groups_count);
        if (!gi || IS_ERR(gi)) {
            abort_creds(new);
            return gi ? PTR_ERR(gi) : -ENOMEM;
        }
        for (uint32_t i = 0; i < rp->groups_count; i++) {
            gid_t *g = (gid_t *)((uintptr_t)gi + 16 + i * sizeof(gid_t));
            *g = rp->groups[i];
        }
        set_groups(new, gi);
    } else {
        struct group_info *group_info = groups_alloc(0);
        if (!group_info || IS_ERR(group_info)) {
            abort_creds(new);
            return group_info ? PTR_ERR(group_info) : -ENOMEM;
        }
        set_groups(new, group_info);
    }

    if (rp->selinux_domain[0]) {
        ext->sel_allow = !!set_security_override_from_ctx(new, rp->selinux_domain);
    }

    rc = commit_creds(new);
    logkfi("profile su pid: %d, uid: %d, gid: %d, sctx: %s\n", ext->pid, to_uid, to_gid, rp->selinux_domain);
    return rc;
}

int check_umount_modules(uid_t uid)
{
    struct app_profile profile;
    if (app_profile_get(uid, &profile)) return 0;
    if (!profile.allow_su) {
        return profile.nrp_config.profile.umount_modules;
    }
    return 0;
}

static int (*avc_denied_backup)(struct selinux_state *state, void *ssid, void *tsid, void *tclass, void *requested,
                                void *driver, void *xperm, void *flags, struct av_decision *avd) = 0;

static int avc_denied_replace(struct selinux_state *_state, void *_ssid, void *_tsid, void *_tclass, void *_requested,
                              void *_driver, void *_xperm, void *_flags, struct av_decision *_avd)
{
    if (all_allow_sid != SECSID_NULL) {
        u32 ssid = (u32)(u64)_ssid;
        if ((uint64_t)_state <= 0xffffffffL) {
            ssid = (u32)(u64)_state;
        }
        if (ssid == all_allow_sid) {
            goto allow;
        }
    }

    struct task_ext *ext = get_current_task_ext();
    if (unlikely(task_ext_valid(ext) && (ext->sel_allow || ext->priv_sel_allow))) {
        goto allow;
    }

    int rc = avc_denied_backup(_state, _ssid, _tsid, _tclass, _requested, _driver, _xperm, _flags, _avd);
    return rc;

allow:
    struct av_decision *avd = (struct av_decision *)_avd;
    if ((uint64_t)_state <= 0xffffffffL) {
        avd = (struct av_decision *)_flags;
    }
    avd->allowed = 0xffffffff;
    avd->auditallow = 0;
    avd->auditdeny = 0;
    return 0;
}

static int (*slow_avc_audit_backup)(struct selinux_state *_state, void *_ssid, void *_tsid, void *_tclass,
                                    void *_requested, void *_audited, void *_denied, void *_result,
                                    struct common_audit_data *_a) = 0;

static int slow_avc_audit_replace(struct selinux_state *_state, void *_ssid, void *_tsid, void *_tclass,
                                  void *_requested, void *_audited, void *_denied, void *_result,
                                  struct common_audit_data *_a)
{
    if (all_allow_sid != SECSID_NULL) {
        u32 ssid = (u64)_ssid;
        if ((uint64_t)_state <= 0xffffffffL) {
            ssid = (u64)_state;
        }
        if (ssid == all_allow_sid) {
            return 0;
        }
    }

    struct task_ext *ext = get_current_task_ext();
    if (unlikely(task_ext_valid(ext) && (ext->sel_allow || ext->priv_sel_allow))) {
        return 0;
    }

    int rc = slow_avc_audit_backup(_state, _ssid, _tsid, _tclass, _requested, _audited, _denied, _result, _a);
    return rc;
}

int bypass_selinux()
{
    unsigned long avc_denied_addr = patch_config->avc_denied;
    if (avc_denied_addr) {
        hook_err_t err = hook((void *)avc_denied_addr, (void *)avc_denied_replace, (void **)&avc_denied_backup);
        if (err != HOOK_NO_ERR) {
            log_boot("hook avc_denied_addr: %llx, error: %d\n", avc_denied_addr, err);
        }
    }

    unsigned long slow_avc_audit_addr = patch_config->slow_avc_audit;
    if (slow_avc_audit_addr) {
        hook_err_t err =
            hook((void *)slow_avc_audit_addr, (void *)slow_avc_audit_replace, (void **)&slow_avc_audit_backup);
        if (err != HOOK_NO_ERR) {
            log_boot("hook slow_avc_audit: %llx, error: %d\n", slow_avc_audit_addr, err);
        }
    }

    return 0;
}
