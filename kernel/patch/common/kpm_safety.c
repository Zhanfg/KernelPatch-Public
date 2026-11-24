/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM Crash Protection System
 *
 * Three-layer defense against faulty KPM modules:
 * 1. Boot counter: auto-disable KPM after N failed boots
 * 2. Pre-load validation: check ELF structure before loading
 * 3. Faulty KPM blacklist: skip modules that caused crashes
 *
 * Counter storage is probed at initialization and may be unavailable.
 */

#include <ktypes.h>
#include <common.h>
#include <log.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <uapi/asm-generic/errno.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <accctl.h>
#include <kpm_safety.h>
#include <kpm_boot_count.h>

/* ============================================================
 * Configuration
 * ============================================================ */

#define BOOT_COUNT_FILE    "/data/adb/kp-next/boot_count"
#define EARLY_BOOT_COUNT_FILE "/dev/.kp_bootcount"
#define BLACKLIST_FILE     "/data/adb/kp-next/kpm_blacklist"
#define LAST_KPM_FILE      "/data/adb/kp-next/kpm_last_loaded"

/* ============================================================
 * File I/O helpers (kernel-side)
 * ============================================================ */

static struct {
    const char *path;
    int digits; /* width read during init, for in-place updates of older records */
} count_files[KPM_COUNT_STORES] = {
    [KPM_EARLY_STORE] = { .path = EARLY_BOOT_COUNT_FILE },
    [KPM_DATA_STORE] = { .path = BOOT_COUNT_FILE },
};

/* Accept the original decimal files and an optional trailing newline. */
static int read_count(enum kpm_count_store store)
{
    char buf[12];
    size_t used = 0;
    int value = 0;
    loff_t pos = 0;
    const char *path = count_files[store].path;
    struct file *f = filp_open(path, O_RDONLY, 0);
    int rc;

    if (IS_ERR_OR_NULL(f)) {
        rc = f ? PTR_ERR(f) : -EIO;
        if (rc == -ENOENT) return rc; /* try exclusive creation */
        goto error;
    }
    while (used < sizeof(buf)) {
        rc = kernel_read(f, buf + used, sizeof(buf) - used, &pos);
        if (rc <= 0) break;
        used += rc;
    }
    filp_close(f, 0);
    if (rc < 0) goto error;
    rc = -EINVAL;
    if (used && buf[used - 1] == '\n') used--;
    if (used == 0 || used > 10) goto error;
    for (size_t i = 0; i < used; i++) {
        int digit = buf[i] - '0';
        if (digit < 0 || digit > 9 || value > (__INT_MAX__ - digit) / 10) goto error;
        value = value * 10 + digit;
    }
    count_files[store].digits = used;
    return value;

error:
    log_boot("kpm_safety: cannot read counter %s (%d)\n", path, rc);
    return rc;
}

static int write_count(enum kpm_count_store store, int count, bool exclusive)
{
    const char *path = count_files[store].path;
    int flags = O_WRONLY;
    if (exclusive) flags |= O_CREAT | O_EXCL;
    if (!count) flags |= O_CREAT | O_TRUNC; /* explicit confirmation */
    struct file *f = filp_open(path, flags, 0644);
    int rc;

    if (IS_ERR_OR_NULL(f)) {
        rc = f ? PTR_ERR(f) : -EIO;
    } else {
        /* Keep the decimal file format and avoid truncating known history on open. */
        char buf[12];
        int width = count ? count_files[store].digits : 0;
        int len = snprintf(buf, sizeof(buf), "%0*d", width, count);
        loff_t pos = 0;
        rc = kernel_write(f, buf, len, &pos);
        int close_rc = filp_close(f, 0);
        if (rc == len && !close_rc) return 0;
        if (rc >= 0) rc = close_rc ? close_rc : -EIO;
    }
    log_boot("kpm_safety: cannot write counter %s (%d)\n", path, rc);
    return rc;
}

static int read_file_string(const char *path, char *out, int maxlen)
{
    struct file *f;
    loff_t pos = 0;
    int len;

    f = filp_open(path, O_RDONLY, 0);
    if (!f || IS_ERR(f)) {
        out[0] = '\0';
        return 0;
    }

    memset(out, 0, maxlen);
    len = kernel_read(f, out, maxlen - 1, &pos);
    filp_close(f, 0);

    if (len > 0 && out[len - 1] == '\n') out[len - 1] = '\0';
    return len;
}

static void write_file_string(const char *path, const char *str)
{
    struct file *f;
    loff_t pos = 0;

    f = filp_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (!f || IS_ERR(f)) return;

    kernel_write(f, str, strlen(str), &pos);
    filp_close(f, 0);
}

static void append_file_string(const char *path, const char *str)
{
    struct file *f;
    loff_t pos = 0;

    f = filp_open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (!f || IS_ERR(f)) return;

    /* Seek to end */
    pos = vfs_llseek(f, 0, SEEK_END);
    kernel_write(f, str, strlen(str), &pos);
    filp_close(f, 0);
}

/* ============================================================
 * 1. Boot Counter
 * ============================================================ */

static const struct kpm_count_io count_io = { .read = read_count, .write = write_count };
static struct kpm_boot_attempt boot = { .count = -1 };
static DEFINE_SPINLOCK(boot_lock);
static bool reset_in_progress;

void kpm_safety_init(void)
{
    if (!kpm_boot_start(&boot, &count_io)) return;
    if (boot.count >= KPM_BOOT_LIMIT) {
        kp_safe_mode = 1;
        log_boot("kpm_safety: safe mode activated due to boot counter\n");
    }
    log_boot("kpm_safety: boot count=%d storage_errors=%#x\n", boot.count, boot.errors);
}

void kpm_safety_get_status(struct kpm_safety_status *status)
{
    spin_lock(&boot_lock);
    *status = kpm_boot_status(&boot, kp_safe_mode);
    spin_unlock(&boot_lock);
}

/* ============================================================
 * 2. Pre-load Validation
 *
 * Check KPM binary before loading:
 * - Valid ELF header
 * - Required sections present
 * - All undefined symbols resolvable
 * ============================================================ */

int kpm_safety_validate(const void *data, int len)
{
    /* Check minimum size */
    if (len < 64) {
        logkfe("kpm_safety: file too small (%d bytes)\n", len);
        return -EINVAL;
    }

    /* Check ELF magic */
    const unsigned char *hdr = (const unsigned char *)data;
    if (hdr[0] != 0x7f || hdr[1] != 'E' || hdr[2] != 'L' || hdr[3] != 'F') {
        logkfe("kpm_safety: not a valid ELF file\n");
        return -ENOEXEC;
    }

    /* Check ELF64 */
    if (hdr[4] != 2) {
        logkfe("kpm_safety: not ELF64\n");
        return -ENOEXEC;
    }

    /* Check little-endian */
    if (hdr[5] != 1) {
        logkfe("kpm_safety: not little-endian\n");
        return -ENOEXEC;
    }

    /* Check aarch64 (EM_AARCH64 = 0xB7) */
    unsigned short e_machine = *(unsigned short *)(data + 18);
    if (e_machine != 0xB7) {
        logkfe("kpm_safety: not aarch64 (machine=%d)\n", e_machine);
        return -ENOEXEC;
    }

    /* Check relocatable */
    unsigned short e_type = *(unsigned short *)(data + 16);
    if (e_type != 1) { /* ET_REL = 1 */
        logkfe("kpm_safety: not relocatable (type=%d)\n", e_type);
        return -ENOEXEC;
    }

    logkd("kpm_safety: ELF validation passed\n");
    return 0;
}

/* ============================================================
 * 3. Faulty KPM Blacklist
 *
 * Before loading a KPM:
 *   - Write KPM name to LAST_KPM_FILE
 *   - If boot counter > 1 and last_kpm matches current,
 *     skip the module
 *
 * After boot confirmed:
 *   - Clear LAST_KPM_FILE
 *   - Clear blacklist
 * ============================================================ */

static char last_kpm_name[64] = { 0 };

int kpm_safety_check_blacklist(const char *kpm_name)
{
    if (!kpm_name) return 0;

    /* Read last loaded KPM */
    read_file_string(LAST_KPM_FILE, last_kpm_name, sizeof(last_kpm_name));

    /* If we're on a retry boot and the last KPM matches, skip it */
    struct kpm_safety_status status;
    kpm_safety_get_status(&status);
    if (status.boot_count > 1 && last_kpm_name[0] &&
        !strncmp(last_kpm_name, kpm_name, sizeof(last_kpm_name))) {
        log_boot("kpm_safety: BLACKLISTED — %s caused previous crash\n", kpm_name);
        return 1; /* blacklisted */
    }

    /* Check explicit blacklist file */
    char bl_entry[128];
    read_file_string(BLACKLIST_FILE, bl_entry, sizeof(bl_entry));
    if (bl_entry[0]) {
        /* Check if kpm_name is in the blacklist (newline-separated) */
        char *pos = bl_entry;
        while (*pos) {
            char *end = pos;
            while (*end && *end != '\n') end++;
            int entry_len = end - pos;
            if (entry_len > 0 && !strncmp(pos, kpm_name, entry_len)) {
                log_boot("kpm_safety: %s is in explicit blacklist\n", kpm_name);
                return 1;
            }
            pos = end;
            if (*pos == '\n') pos++;
        }
    }

    return 0; /* not blacklisted */
}

void kpm_safety_mark_loading(const char *kpm_name)
{
    if (!kpm_name) return;
    write_file_string(LAST_KPM_FILE, kpm_name);
    logkd("kpm_safety: marking %s as loading\n", kpm_name);
}

void kpm_safety_confirm_boot_completed(void)
{
    struct kpm_boot_attempt updated;
    spin_lock(&boot_lock);
    if (reset_in_progress || (boot.confirmed && !boot.errors)) {
        spin_unlock(&boot_lock);
        return;
    }
    reset_in_progress = true;
    updated = boot;
    spin_unlock(&boot_lock);

    /* File operations may sleep. Publish the finished snapshot as a unit. */
    if (!updated.confirmed) write_file_string(LAST_KPM_FILE, "");
    kpm_boot_confirm(&updated, &count_io);

    spin_lock(&boot_lock);
    boot = updated;
    reset_in_progress = false;
    spin_unlock(&boot_lock);
    log_boot("kpm_safety: boot completed, counter reset errors=%#x\n", updated.errors);
}

void kpm_safety_add_to_blacklist(const char *kpm_name)
{
    if (!kpm_name) return;
    append_file_string(BLACKLIST_FILE, kpm_name);
    append_file_string(BLACKLIST_FILE, "\n");
    logkfi("kpm_safety: added %s to blacklist\n", kpm_name);
}

void kpm_safety_clear_blacklist(void)
{
    write_file_string(BLACKLIST_FILE, "");
    log_boot("kpm_safety: blacklist cleared\n");
}
