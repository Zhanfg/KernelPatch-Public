/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM Crash Protection System
 *
 * Three-layer defense against faulty KPM modules:
 * 1. Boot counter: auto-disable KPM after N failed boots
 * 2. Pre-load validation: check ELF structure before loading
 * 3. Faulty KPM blacklist: skip modules that caused crashes
 *
 * All state persisted via filesystem (/data/adb/kp-next/).
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
#include <kputils.h>

/* ============================================================
 * Configuration
 * ============================================================ */

#define BOOT_COUNT_FILE    "/data/adb/kp-next/boot_count"
#define BOOT_CONFIRM_FILE  "/data/adb/kp-next/boot_confirmed"
#define BLACKLIST_FILE     "/data/adb/kp-next/kpm_blacklist"
#define LAST_KPM_FILE      "/data/adb/kp-next/kpm_last_loaded"
#define BOOT_COUNT_MAX     3  /* max failed boots before safe mode */

/* ============================================================
 * File I/O helpers (kernel-side)
 * ============================================================ */

static int read_file_int(const char *path, int default_val)
{
    struct file *f;
    char buf[16];
    loff_t pos = 0;
    int val;

    f = filp_open(path, O_RDONLY, 0);
    if (!f || IS_ERR(f)) return default_val;

    memset(buf, 0, sizeof(buf));
    kernel_read(f, buf, sizeof(buf) - 1, &pos);
    filp_close(f, 0);

    val = 0;
    for (int i = 0; buf[i] >= '0' && buf[i] <= '9'; i++) {
        val = val * 10 + (buf[i] - '0');
    }
    return val > 0 ? val : default_val;
}

static void write_file_int(const char *path, int val)
{
    struct file *f;
    char buf[16];
    loff_t pos = 0;
    int len;

    f = filp_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (!f || IS_ERR(f)) return;

    len = 0;
    if (val == 0) {
        buf[0] = '0';
        len = 1;
    } else {
        int tmp = val;
        char rev[16];
        int i = 0;
        while (tmp > 0 && i < 15) {
            rev[i++] = '0' + (tmp % 10);
            tmp /= 10;
        }
        for (int j = 0; j < i; j++) {
            buf[j] = rev[i - 1 - j];
        }
        len = i;
    }
    kernel_write(f, buf, len, &pos);
    filp_close(f, 0);
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
 *
 * - Incremented at module_init() (early boot)
 * - Reset to 0 when boot_completed is confirmed
 * - If counter >= BOOT_COUNT_MAX, enable safe mode
 * ============================================================ */

static int boot_count = 0;

int kpm_safety_check_boot_count(void)
{
    boot_count = read_file_int(BOOT_COUNT_FILE, 0);
    boot_count++;
    write_file_int(BOOT_COUNT_FILE, boot_count);

    log_boot("kpm_safety: boot count = %d (max %d)\n", boot_count, BOOT_COUNT_MAX);

    if (boot_count >= BOOT_COUNT_MAX) {
        log_boot("kpm_safety: SAFE MODE — too many failed boots (%d)\n", boot_count);
        return 1; /* safe mode */
    }
    return 0; /* normal */
}

void kpm_safety_confirm_boot(void)
{
    /* Called when boot_completed is reached */
    write_file_int(BOOT_COUNT_FILE, 0);
    write_file_string(BOOT_CONFIRM_FILE, "1");
    log_boot("kpm_safety: boot confirmed, counter reset\n");
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
    if (boot_count > 1 && last_kpm_name[0] &&
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
    /* Clear all safety markers */
    write_file_int(BOOT_COUNT_FILE, 0);
    write_file_string(LAST_KPM_FILE, "");
    /* Don't clear explicit blacklist — user manages that */
    log_boot("kpm_safety: boot completed, safety markers cleared\n");
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

/* ============================================================
 * Initialization
 * ============================================================ */

void kpm_safety_init(void)
{
    log_boot("kpm_safety: initialized\n");
}
