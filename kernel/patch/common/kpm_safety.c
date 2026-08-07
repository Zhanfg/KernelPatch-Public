/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM Crash Protection System
 *
 * Defensive state is intentionally fail-observable: early boot state is only
 * current-boot diagnostics, while consecutive failed-boot accounting is kept
 * exclusively in persistent /data state once that storage is available.
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

#define BOOT_COUNT_FILE    "/data/adb/kp-next/boot_count"
#define BOOT_CONFIRM_FILE  "/data/adb/kp-next/boot_confirmed"
#define BLACKLIST_FILE     "/data/adb/kp-next/kpm_blacklist"
#define LAST_KPM_FILE      "/data/adb/kp-next/kpm_last_loaded"
#define EARLY_BOOT_COUNT_FILE "/dev/.kp_bootcount"
#define MAX_BOOT_COUNT 3

static int boot_count = 0;
static bool early_attempt_started = false;
static bool persistent_attempt_recorded = false;
static bool safe_mode_due_failures = false;

static int read_file_int_checked(const char *path, int *out)
{
    if (!path || !out) return -EINVAL;

    struct file *f = filp_open(path, O_RDONLY, 0);
    if (!f || IS_ERR(f)) return f ? PTR_ERR(f) : -ENOENT;

    char buf[16] = { 0 };
    loff_t pos = 0;
    int len = kernel_read(f, buf, sizeof(buf) - 1, &pos);
    filp_close(f, 0);
    if (len < 0) return len;
    if (len == 0) return -EINVAL;

    int val = 0;
    for (int i = 0; i < len && buf[i] != '\0' && buf[i] != '\n'; i++) {
        if (buf[i] < '0' || buf[i] > '9') return -EINVAL;
        if (val > 1000000) return -ERANGE;
        val = val * 10 + (buf[i] - '0');
    }
    *out = val;
    return 0;
}

static int write_file_int(const char *path, int val)
{
    struct file *f;
    char buf[16];
    loff_t pos = 0;
    int len;

    f = filp_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (!f || IS_ERR(f)) return f ? PTR_ERR(f) : -EIO;

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
        if (tmp > 0) {
            filp_close(f, 0);
            return -ERANGE;
        }
        for (int j = 0; j < i; j++) buf[j] = rev[i - 1 - j];
        len = i;
    }

    int written = kernel_write(f, buf, len, &pos);
    filp_close(f, 0);
    if (written < 0) return written;
    return written == len ? 0 : -EIO;
}

static int read_file_string(const char *path, char *out, int maxlen)
{
    if (!path || !out || maxlen <= 1) return -EINVAL;

    struct file *f = filp_open(path, O_RDONLY, 0);
    if (!f || IS_ERR(f)) {
        out[0] = '\0';
        return f ? PTR_ERR(f) : -ENOENT;
    }

    memset(out, 0, maxlen);
    loff_t pos = 0;
    int len = kernel_read(f, out, maxlen - 1, &pos);
    filp_close(f, 0);
    if (len < 0) {
        out[0] = '\0';
        return len;
    }
    if (len > 0 && out[len - 1] == '\n') out[len - 1] = '\0';
    return len;
}

static int write_file_string(const char *path, const char *str)
{
    if (!path || !str) return -EINVAL;

    struct file *f = filp_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (!f || IS_ERR(f)) return f ? PTR_ERR(f) : -EIO;

    loff_t pos = 0;
    int len = strlen(str);
    int written = kernel_write(f, str, len, &pos);
    filp_close(f, 0);
    if (written < 0) return written;
    return written == len ? 0 : -EIO;
}

static int append_file_string(const char *path, const char *str)
{
    if (!path || !str) return -EINVAL;

    struct file *f = filp_open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (!f || IS_ERR(f)) return f ? PTR_ERR(f) : -EIO;

    loff_t pos = vfs_llseek(f, 0, SEEK_END);
    if (pos < 0) {
        filp_close(f, 0);
        return (int)pos;
    }
    int len = strlen(str);
    int written = kernel_write(f, str, len, &pos);
    filp_close(f, 0);
    if (written < 0) return written;
    return written == len ? 0 : -EIO;
}

/* Early boot storage is tmpfs and therefore cannot prove prior failed boots.
 * Record only that this boot entered the KPM subsystem; never increment the
 * persistent failure counter here. */
void kpm_safety_early_count(void)
{
    if (early_attempt_started) return;
    early_attempt_started = true;

    int rc = write_file_int(EARLY_BOOT_COUNT_FILE, 1);
    if (rc) log_boot("kpm_safety: early attempt marker unavailable: %d\n", rc);
    else log_boot("kpm_safety: current boot attempt marked (non-persistent)\n");
}

/* Register exactly one persistent attempt once /data state is reachable.
 * BOOT_COUNT_FILE stores the number of consecutive unconfirmed attempts,
 * including the currently active attempt. A value of MAX_BOOT_COUNT from the
 * previous boot means three attempts already failed, so safe mode begins on
 * the fourth attempt rather than on the third attempt before its outcome is
 * known. */
int kpm_safety_check_boot_count(void)
{
    if (persistent_attempt_recorded) return safe_mode_due_failures ? 1 : 0;

    int prior_count = 0;
    int confirmed = 0;
    int count_rc = read_file_int_checked(BOOT_COUNT_FILE, &prior_count);
    int confirm_rc = read_file_int_checked(BOOT_CONFIRM_FILE, &confirmed);

    if (count_rc && count_rc != -ENOENT) {
        log_boot("kpm_safety: persistent boot counter unreadable: %d\n", count_rc);
        return 0;
    }
    if (confirm_rc && confirm_rc != -ENOENT) {
        log_boot("kpm_safety: boot confirmation unreadable: %d\n", confirm_rc);
        return 0;
    }

    /* If neither state file exists, /data or its PatchNest directory may not
     * be ready. Probe by trying to create the confirmation marker; failure is
     * a degraded, retryable state rather than a fake successful persistence. */
    if (count_rc == -ENOENT && confirm_rc == -ENOENT) {
        int probe = write_file_int(BOOT_CONFIRM_FILE, 0);
        if (probe) {
            log_boot("kpm_safety: persistent state unavailable, deferring attempt registration: %d\n", probe);
            return 0;
        }
        prior_count = 0;
        confirmed = 0;
    }

    if (confirmed == 1) prior_count = 0;
    if (prior_count < 0 || prior_count > 1000000) {
        log_boot("kpm_safety: invalid persistent count %d\n", prior_count);
        return 0;
    }

    safe_mode_due_failures = prior_count >= MAX_BOOT_COUNT;
    int current_count = prior_count + 1;

    /* Mark this attempt unconfirmed before storing its sequence number. */
    int rc = write_file_int(BOOT_CONFIRM_FILE, 0);
    if (rc) {
        log_boot("kpm_safety: cannot mark attempt unconfirmed: %d\n", rc);
        return 0;
    }
    rc = write_file_int(BOOT_COUNT_FILE, current_count);
    if (rc) {
        log_boot("kpm_safety: cannot persist boot count: %d\n", rc);
        return 0;
    }

    boot_count = current_count;
    persistent_attempt_recorded = true;
    log_boot("kpm_safety: persistent attempt=%d, prior failures=%d, max=%d\n",
             current_count, prior_count, MAX_BOOT_COUNT);

    if (safe_mode_due_failures) {
        log_boot("kpm_safety: SAFE MODE — %d prior attempts were unconfirmed\n", prior_count);
        return 1;
    }
    return 0;
}

static void confirm_boot_state(void)
{
    int rc_count = write_file_int(BOOT_COUNT_FILE, 0);
    int rc_confirm = write_file_int(BOOT_CONFIRM_FILE, 1);
    int rc_early = write_file_int(EARLY_BOOT_COUNT_FILE, 0);

    if (rc_count || rc_confirm) {
        log_boot("kpm_safety: boot confirmation persistence failed: count=%d confirm=%d\n",
                 rc_count, rc_confirm);
        return;
    }

    boot_count = 0;
    safe_mode_due_failures = false;
    if (rc_early) log_boot("kpm_safety: early marker reset failed: %d\n", rc_early);
    log_boot("kpm_safety: boot confirmed, failure sequence reset\n");
}

void kpm_safety_confirm_boot(void)
{
    confirm_boot_state();
}

int kpm_safety_validate(const void *data, int len)
{
    if (len < 64) {
        logkfe("kpm_safety: file too small (%d bytes)\n", len);
        return -EINVAL;
    }

    const unsigned char *hdr = (const unsigned char *)data;
    if (hdr[0] != 0x7f || hdr[1] != 'E' || hdr[2] != 'L' || hdr[3] != 'F') {
        logkfe("kpm_safety: not a valid ELF file\n");
        return -ENOEXEC;
    }
    if (hdr[4] != 2) {
        logkfe("kpm_safety: not ELF64\n");
        return -ENOEXEC;
    }
    if (hdr[5] != 1) {
        logkfe("kpm_safety: not little-endian\n");
        return -ENOEXEC;
    }

    unsigned short e_machine = *(unsigned short *)(data + 18);
    if (e_machine != 0xB7) {
        logkfe("kpm_safety: not aarch64 (machine=%d)\n", e_machine);
        return -ENOEXEC;
    }
    unsigned short e_type = *(unsigned short *)(data + 16);
    if (e_type != 1) {
        logkfe("kpm_safety: not relocatable (type=%d)\n", e_type);
        return -ENOEXEC;
    }

    /* Detailed section/string/symbol/relocation bounds are enforced by the
     * main loader before this compatibility-layer validation runs. */
    logkd("kpm_safety: base ELF validation passed\n");
    return 0;
}

static char last_kpm_name[64] = { 0 };

int kpm_safety_check_blacklist(const char *kpm_name)
{
    if (!kpm_name) return 0;

    /* Retry persistent attempt registration lazily. module_init may run before
     * /data exists, while filesystem KPM loading normally runs after mount. */
    if (!persistent_attempt_recorded) (void)kpm_safety_check_boot_count();

    read_file_string(LAST_KPM_FILE, last_kpm_name, sizeof(last_kpm_name));
    if (boot_count > 1 && last_kpm_name[0] &&
        !strncmp(last_kpm_name, kpm_name, sizeof(last_kpm_name))) {
        log_boot("kpm_safety: BLACKLISTED — %s was last loaded on an unconfirmed attempt\n", kpm_name);
        return 1;
    }

    char bl_entry[128];
    read_file_string(BLACKLIST_FILE, bl_entry, sizeof(bl_entry));
    if (bl_entry[0]) {
        char *pos = bl_entry;
        while (*pos) {
            char *end = pos;
            while (*end && *end != '\n') end++;
            int entry_len = end - pos;
            if (entry_len > 0 && strlen(kpm_name) == (unsigned long)entry_len &&
                !strncmp(pos, kpm_name, entry_len)) {
                log_boot("kpm_safety: %s is in explicit blacklist\n", kpm_name);
                return 1;
            }
            pos = end;
            if (*pos == '\n') pos++;
        }
    }

    return 0;
}

void kpm_safety_mark_loading(const char *kpm_name)
{
    if (!kpm_name) return;
    int rc = write_file_string(LAST_KPM_FILE, kpm_name);
    if (rc) logkfe("kpm_safety: cannot persist last KPM %s: %d\n", kpm_name, rc);
    else logkd("kpm_safety: marking %s as loading\n", kpm_name);
}

void kpm_safety_confirm_boot_completed(void)
{
    confirm_boot_state();
    int rc = write_file_string(LAST_KPM_FILE, "");
    if (rc) log_boot("kpm_safety: cannot clear last-KPM marker: %d\n", rc);
}

void kpm_safety_add_to_blacklist(const char *kpm_name)
{
    if (!kpm_name || !*kpm_name) return;
    int rc = append_file_string(BLACKLIST_FILE, kpm_name);
    if (!rc) rc = append_file_string(BLACKLIST_FILE, "\n");
    if (rc) logkfe("kpm_safety: failed to add %s to blacklist: %d\n", kpm_name, rc);
    else logkfi("kpm_safety: added %s to blacklist\n", kpm_name);
}

void kpm_safety_clear_blacklist(void)
{
    int rc = write_file_string(BLACKLIST_FILE, "");
    if (rc) log_boot("kpm_safety: blacklist clear failed: %d\n", rc);
    else log_boot("kpm_safety: blacklist cleared\n");
}

void kpm_safety_init(void)
{
    boot_count = 0;
    early_attempt_started = false;
    persistent_attempt_recorded = false;
    safe_mode_due_failures = false;
    log_boot("kpm_safety: initialized\n");
}