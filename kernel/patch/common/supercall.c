/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <ktypes.h>
#include <uapi/scdefs.h>
#include <hook.h>
#include <common.h>
#include <log.h>
#include <predata.h>
#include <pgtable.h>
#include <linux/syscall.h>
#include <uapi/asm-generic/errno.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <asm/current.h>
#include <linux/string.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <syscall.h>
#include <accctl.h>
#include <module.h>
#include <kputils.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <kputils.h>
#include <predata.h>
#include <linux/random.h>
#include <sucompat.h>
#include <accctl.h>
#include <kstorage.h>
#include <uapi/app_profile.h>
#include <sepolicy.h>
#include <uapi/kpm_event.h>
#include <proc_hide.h>
#include <kpm_safety.h>
#ifdef ANDROID
#include <userd.h>
#endif

#define MAX_KEY_LEN 128

#include <linux/umh.h>

static long call_test(long arg1, long arg2, long arg3)
{
    return 0;
}

static long call_bootlog()
{
    print_bootlog();
    return 0;
}

static long call_panic()
{
    unsigned long panic_addr = kallsyms_lookup_name("panic");
    ((void (*)(const char *fmt, ...))panic_addr)("!!!! kernel_patch panic !!!!");
    return 0;
}

static long call_klog(const char __user *arg1)
{
    char buf[1024];
    long len = compat_strncpy_from_user(buf, arg1, sizeof(buf));
    if (len <= 0) return -EINVAL;
    if (len > 0) logki("user log: %s", buf);
    return 0;
}

static long call_buildtime(char __user *out_buildtime, int u_len)
{
    const char *buildtime = get_build_time();
    int len = strlen(buildtime);
    if (len >= u_len) return -ENOMEM;
    int rc = compat_copy_to_user(out_buildtime, buildtime, len + 1);
    return rc;
}

static long call_kpm_load(const char __user *arg1, const char *__user arg2, void *__user reserved)
{
    char path[1024], args[KPM_ARGS_LEN];
    long pathlen = compat_strncpy_from_user(path, arg1, sizeof(path));
    if (pathlen <= 0) return -EINVAL;
    long arglen = compat_strncpy_from_user(args, arg2, sizeof(args));
    return load_module_path(path, arglen <= 0 ? 0 : args, reserved);
}

static long call_kpm_control(const char __user *arg1, const char *__user arg2, void *__user out_msg, int outlen)
{
    char name[KPM_NAME_LEN], args[KPM_ARGS_LEN];
    long namelen = compat_strncpy_from_user(name, arg1, sizeof(name));
    if (namelen <= 0) return -EINVAL;
    long arglen = compat_strncpy_from_user(args, arg2, sizeof(args));
    return module_control0(name, arglen <= 0 ? 0 : args, out_msg, outlen);
}

static long call_kpm_unload(const char *__user arg1, void *__user reserved)
{
    char name[KPM_NAME_LEN];
    long len = compat_strncpy_from_user(name, arg1, sizeof(name));
    if (len <= 0) return -EINVAL;
    return unload_module(name, reserved);
}

static long call_kpm_nums()
{
    return get_module_nums();
}

static long call_kpm_list(char *__user names, int len)
{
    if (len <= 0) return -EINVAL;
    char buf[4096];
    int sz = list_modules(buf, sizeof(buf));
    if (sz > len) return -ENOBUFS;
    sz = compat_copy_to_user(names, buf, len);
    return sz;
}

static long call_kpm_info(const char *__user uname, char *__user out_info, int out_len)
{
    if (out_len <= 0) return -EINVAL;
    char name[64];
    char buf[2048];
    int len = compat_strncpy_from_user(name, uname, sizeof(name));
    if (len <= 0) return -EINVAL;
    int sz = get_module_info(name, buf, sizeof(buf));
    if (sz < 0) return sz;
    if (sz > out_len) return -ENOBUFS;
    sz = compat_copy_to_user(out_info, buf, sz);
    return sz;
}

static long call_su(struct su_profile *__user uprofile)
{
    struct su_profile *profile = memdup_user(uprofile, sizeof(struct su_profile));
    if (!profile || IS_ERR(profile)) return PTR_ERR(profile);
    profile->scontext[sizeof(profile->scontext) - 1] = '\0';
    int rc = commit_su(profile->to_uid, profile->scontext);
    kvfree(profile);
    return rc;
}

static long call_su_task(pid_t pid, struct su_profile *__user uprofile)
{
    struct su_profile *profile = memdup_user(uprofile, sizeof(struct su_profile));
    if (!profile || IS_ERR(profile)) return PTR_ERR(profile);
    profile->scontext[sizeof(profile->scontext) - 1] = '\0';
    int rc = task_su(pid, profile->to_uid, profile->scontext);
    kvfree(profile);
    return rc;
}

static long call_skey_get(char *__user out_key, int out_len)
{
    const char *key = get_superkey();
    int klen = strlen(key);
    if (klen >= out_len) return -ENOMEM;
    int rc = compat_copy_to_user(out_key, key, klen + 1);
    return rc;
}

static long call_skey_set(char *__user new_key)
{
    char buf[SUPER_KEY_LEN];
    int len = compat_strncpy_from_user(buf, new_key, sizeof(buf));
    if (len >= SUPER_KEY_LEN && buf[SUPER_KEY_LEN - 1]) return -E2BIG;
    reset_superkey(new_key);
    return 0;
}

static long call_skey_root_enable(int enable)
{
    enable_auth_root_key(enable);
    return 0;
}

static long call_grant_uid(struct su_profile *__user uprofile)
{
    struct su_profile *profile = memdup_user(uprofile, sizeof(struct su_profile));
    if (!profile || IS_ERR(profile)) return PTR_ERR(profile);
    int rc = su_add_allow_uid(profile->uid, profile->to_uid, profile->scontext);
    kvfree(profile);
    return rc;
}

static long call_revoke_uid(uid_t uid)
{
    return su_remove_allow_uid(uid);
}

static long call_su_allow_uid_nums()
{
    return su_allow_uid_nums();
}

#ifdef ANDROID
extern int android_is_safe_mode;
static long call_su_get_safemode()
{
    int result = android_is_safe_mode;
    logkfd("[call_su_get_safemode] %d\n", result);
    return result;
}

extern int load_ap_package_config(void);
static long call_ap_load_package_config()
{
    int result = load_ap_package_config();
    logkfd("[call_ap_load_package_config] loaded %d entries\n", result);
    return result;
}
#endif

static long call_su_list_allow_uid(uid_t *__user uids, int num)
{
    return su_allow_uids(1, uids, num);
}

static long call_su_allow_uid_profile(uid_t uid, struct su_profile *__user uprofile)
{
    return su_allow_uid_profile(1, uid, uprofile);
}

static long call_reset_su_path(const char *__user upath)
{
    return su_reset_path(strndup_user(upath, SU_PATH_MAX_LEN));
}

static long call_su_get_path(char *__user ubuf, int buf_len)
{
    const char *path = su_get_path();
    int len = strlen(path);
    if (buf_len <= len) return -ENOBUFS;
    return compat_copy_to_user(ubuf, path, len + 1);
}

static long call_su_get_allow_sctx(char *__user usctx, int ulen)
{
    int len = strlen(all_allow_sctx);
    if (ulen <= len) return -ENOBUFS;
    return compat_copy_to_user(usctx, all_allow_sctx, len + 1);
}

static long call_su_set_allow_sctx(char *__user usctx)
{
    char buf[SUPERCALL_SCONTEXT_LEN];
    buf[0] = '\0';
    int len = compat_strncpy_from_user(buf, usctx, sizeof(buf));
    if (len >= SUPERCALL_SCONTEXT_LEN && buf[SUPERCALL_SCONTEXT_LEN - 1]) return -E2BIG;
    return set_all_allow_sctx(buf);
}

static long call_kstorage_read(int gid, long did, void *out_data, int offset, int dlen)
{
    return read_kstorage(gid, did, out_data, offset, dlen, true);
}

static long call_kstorage_write(int gid, long did, void *data, int offset, int dlen)
{
    return write_kstorage(gid, did, data, offset, dlen, true);
}

static long call_list_kstorage_ids(int gid, long *ids, int ids_len)
{
    return list_kstorage_ids(gid, ids, ids_len, false);
}

static long call_kstorage_remove(int gid, long did)
{
    return remove_kstorage(gid, did);
}

/* App profile supercall handlers */
static long call_app_profile_set(const struct app_profile __user *uprofile)
{
    struct app_profile *profile = memdup_user(uprofile, sizeof(struct app_profile));
    if (!profile || IS_ERR(profile)) return PTR_ERR(profile);
    profile->key[sizeof(profile->key) - 1] = '\0';
    int rc = app_profile_set(profile);
    kvfree(profile);
    return rc;
}

static long call_app_profile_get(uid_t uid, struct app_profile __user *uprofile)
{
    struct app_profile profile;
    int rc = app_profile_get(uid, &profile);
    if (rc) return rc;
    return compat_copy_to_user(uprofile, &profile, sizeof(struct app_profile));
}

static long call_app_profile_list(uid_t __user *uids, int max_count)
{
    uid_t *buf = vmalloc(max_count * sizeof(uid_t));
    if (!buf) return -ENOMEM;
    int count = app_profile_list(buf, max_count);
    int rc = compat_copy_to_user(uids, buf, count * sizeof(uid_t));
    kvfree(buf);
    if (rc) return -EFAULT;
    return count;
}

static long call_set_safemode(int mode)
{
    extern int kp_safe_mode;
    kp_safe_mode = !!mode;
    logkfd("safe mode set to %d\n", kp_safe_mode);
    return 0;
}

/* KPM event trigger */
static long call_kpm_event(int event, const char __user *usource, const char __user *uargs)
{
    char source[128] = { 0 };
    char args[1024] = { 0 };
    if (usource) compat_strncpy_from_user(source, usource, sizeof(source));
    if (uargs) compat_strncpy_from_user(args, uargs, sizeof(args));
    return module_dispatch_event((enum kpm_event)event,
                                 source[0] ? source : NULL,
                                 args[0] ? args : NULL);
}

/* Umount config handlers */
static long call_umount_add(const char __user *upath, unsigned int flags)
{
    char path[256];
    int len = compat_strncpy_from_user(path, upath, sizeof(path));
    if (len <= 0) return -EINVAL;
    return umount_add_path(path, flags);
}

static long call_umount_remove(const char __user *upath)
{
    char path[256];
    int len = compat_strncpy_from_user(path, upath, sizeof(path));
    if (len <= 0) return -EINVAL;
    return umount_remove_path(path);
}

static long call_umount_list(char __user *out, int size)
{
    char buf[4096];
    int sz = umount_list_paths(buf, sizeof(buf));
    if (sz > size) return -ENOBUFS;
    return compat_copy_to_user(out, buf, sz);
}

static long supercall(int is_authed, long cmd, long arg1, long arg2, long arg3, long arg4)
{
    switch (cmd) {
    case SUPERCALL_HELLO:
        logki(SUPERCALL_HELLO_ECHO "\n");
        return SUPERCALL_HELLO_MAGIC;
    case SUPERCALL_KLOG:
        return call_klog((const char *__user)arg1);
    case SUPERCALL_KERNELPATCH_VER:
        return kpver;
    case SUPERCALL_KERNEL_VER:
        return kver;
    case SUPERCALL_BUILD_TIME:
        return call_buildtime((char *__user)arg1, (int)arg2);
    #ifdef ANDROID
    case SUPERCALL_AP_LOAD_PACKAGE_CONFIG:
        return call_ap_load_package_config();
    #endif
    }

    switch (cmd) {
    case SUPERCALL_SU:
        if (kp_safe_mode) return -EACCES;
        return call_su((struct su_profile * __user) arg1);
    case SUPERCALL_SU_TASK:
        if (kp_safe_mode) return -EACCES;
        return call_su_task((pid_t)arg1, (struct su_profile * __user) arg2);

    case SUPERCALL_SU_GRANT_UID:
        return call_grant_uid((struct su_profile * __user) arg1);
    case SUPERCALL_SU_REVOKE_UID:
        return call_revoke_uid((uid_t)arg1);
    case SUPERCALL_SU_NUMS:
        return call_su_allow_uid_nums();
    case SUPERCALL_SU_LIST:
        return call_su_list_allow_uid((uid_t *)arg1, (int)arg2);
    case SUPERCALL_SU_PROFILE:
        return call_su_allow_uid_profile((uid_t)arg1, (struct su_profile * __user) arg2);
    case SUPERCALL_SU_RESET_PATH:
        return call_reset_su_path((const char *)arg1);
    case SUPERCALL_SU_GET_PATH:
        return call_su_get_path((char *__user)arg1, (int)arg2);
    case SUPERCALL_SU_GET_ALLOW_SCTX:
        return call_su_get_allow_sctx((char *__user)arg1, (int)arg2);
    case SUPERCALL_SU_SET_ALLOW_SCTX:
        return call_su_set_allow_sctx((char *__user)arg1);

    case SUPERCALL_KSTORAGE_READ:
        return call_kstorage_read((int)arg1, (long)arg2, (void *)arg3, (int)((long)arg4 >> 32), (long)arg4 << 32 >> 32);
    case SUPERCALL_KSTORAGE_WRITE:
        return call_kstorage_write((int)arg1, (long)arg2, (void *)arg3, (int)((long)arg4 >> 32),
                                   (long)arg4 << 32 >> 32);
    case SUPERCALL_KSTORAGE_LIST_IDS:
        return call_list_kstorage_ids((int)arg1, (long *)arg2, (int)arg3);
    case SUPERCALL_KSTORAGE_REMOVE:
        return call_kstorage_remove((int)arg1, (long)arg2);

#ifdef ANDROID
    case SUPERCALL_SU_GET_SAFEMODE:
        return call_su_get_safemode();
#endif

    /* App profile system */
    case SUPERCALL_APP_PROFILE_GET:
        return call_app_profile_get((uid_t)arg1, (struct app_profile __user *)arg2);
    case SUPERCALL_APP_PROFILE_SET:
        return call_app_profile_set((const struct app_profile __user *)arg1);
    case SUPERCALL_APP_PROFILE_LIST:
        return call_app_profile_list((uid_t __user *)arg1, (int)arg2);
    case SUPERCALL_APP_PROFILE_NUM:
        return app_profile_num();

    /* Safe mode */
    case SUPERCALL_SET_SAFEMODE:
        return call_set_safemode((int)arg1);

    /* Umount/hiding config */
    case SUPERCALL_UMOUNT_ADD:
        return call_umount_add((const char __user *)arg1, (unsigned int)arg2);
    case SUPERCALL_UMOUNT_REMOVE:
        return call_umount_remove((const char __user *)arg1);
    case SUPERCALL_UMOUNT_ENABLE:
        umount_set_enabled((int)arg1);
        return 0;
    case SUPERCALL_UMOUNT_LIST:
        return call_umount_list((char __user *)arg1, (int)arg2);

    /* Process hiding */
    case SUPERCALL_PROC_RENAME: {
        char name[16];
        int len = compat_strncpy_from_user(name, (const char __user *)arg1, sizeof(name));
        if (len <= 0) return -EINVAL;
        return proc_hide_rename_current(name);
    }

    /* KPM safety / crash protection */
    case SUPERCALL_SAFETY_BL_CLEAR:
        kpm_safety_clear_blacklist();
        return 0;
    case SUPERCALL_SAFETY_BL_ADD: {
        char name[64];
        int len = compat_strncpy_from_user(name, (const char __user *)arg1, sizeof(name));
        if (len <= 0) return -EINVAL;
        kpm_safety_add_to_blacklist(name);
        return 0;
    }

    default:
        break;
    }

    switch (cmd) {
    case SUPERCALL_BOOTLOG:
        return call_bootlog();
    case SUPERCALL_PANIC:
        return call_panic();
    case SUPERCALL_TEST:
        return call_test(arg1, arg2, arg3);
    default:
        break;
    }

    if (!is_authed) return -EPERM;

    switch (cmd) {
    case SUPERCALL_SKEY_GET:
        return call_skey_get((char *__user)arg1, (int)arg2);
    case SUPERCALL_SKEY_SET:
        return call_skey_set((char *__user)arg1);
    case SUPERCALL_SKEY_ROOT_ENABLE:
        return call_skey_root_enable((int)arg1);
        break;
    }

    switch (cmd) {
    case SUPERCALL_KPM_LOAD:
        return call_kpm_load((const char *__user)arg1, (const char *__user)arg2, (void *__user)arg3);
    case SUPERCALL_KPM_UNLOAD:
        return call_kpm_unload((const char *__user)arg1, (void *__user)arg2);
    case SUPERCALL_KPM_CONTROL:
        return call_kpm_control((const char *__user)arg1, (const char *__user)arg2, (char *__user)arg3, (int)arg4);
    case SUPERCALL_KPM_NUMS:
        return call_kpm_nums();
    case SUPERCALL_KPM_LIST:
        return call_kpm_list((char *__user)arg1, (int)arg2);
    case SUPERCALL_KPM_INFO:
        return call_kpm_info((const char *__user)arg1, (char *__user)arg2, (int)arg3);

    /* KPM event dispatch (authed) */
    case SUPERCALL_KPM_EVENT:
        return call_kpm_event((int)arg1, (const char __user *)arg2, (const char __user *)arg3);

    /* SELinux policy operations (authed only) */
    case SUPERCALL_SEPOLICY_CMD:
        return sepolicy_apply((const void __user *)arg1, (int)arg2);
    }

    switch (cmd) {
    default:
        break;
    }

    return -ENOSYS;
}

int is_trusted_manager_uid(uid_t uid)
{
    #ifdef ANDROID
    return is_trusted_manager_uid_android(uid);
    #endif
    return 0;
}

static void before(hook_fargs6_t *args, void *udata)
{
    int uid = current_uid();
    if (get_ap_mod_exclude(uid)) return;

    int is_trusted_caller = 0;
    int is_authed = 0;
    if (has_preset_superkey()) {
        const char *__user key_user = (const char *__user)syscall_argn(args, 0);
        
        char key[MAX_KEY_LEN];
        long len = compat_strncpy_from_user(key, key_user, MAX_KEY_LEN);
        if (len <= 0) return;
        is_authed = !auth_superkey(key);
        is_trusted_caller = is_authed;
    }
    if (is_trusted_manager_uid(uid)) {
        is_trusted_caller = 1;
        is_authed = 1;
    } else if (is_su_allow_uid(uid)) {
        is_trusted_caller = 1;
    }

    if (!is_trusted_caller) return;

    long ver_xx_cmd = (long)syscall_argn(args, 1);
    long cmd = ver_xx_cmd & 0xFFFF;
    if (cmd < SUPERCALL_HELLO || cmd > SUPERCALL_MAX) return;

    // todo: from 0.10.5
    // uint32_t ver = (ver_xx_cmd & 0xFFFFFFFF00000000ul) >> 32;
    // long xx = (ver_xx_cmd & 0xFFFF0000) >> 16;

    long a1 = (long)syscall_argn(args, 2);
    long a2 = (long)syscall_argn(args, 3);
    long a3 = (long)syscall_argn(args, 4);
    long a4 = (long)syscall_argn(args, 5);

    args->skip_origin = 1;
    args->ret = supercall(is_authed, cmd, a1, a2, a3, a4);
}

int supercall_install()
{
    int rc = 0;

    hook_err_t err = hook_syscalln(__NR_supercall, 6, before, 0, 0);
    if (err) {
        log_boot("install supercall hook error: %d\n", err);
        rc = err;
        goto out;
    }
out:
    return rc;
}
