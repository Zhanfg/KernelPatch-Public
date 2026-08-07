/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM Crash Protection System
 *
 * Three-layer defense against faulty KPM modules:
 * 1. Checksummed boot-attempt state: auto-safe-mode after repeated failures
 * 2. Pre-load validation: check ELF structure before loading
 * 3. Faulty KPM blacklist: skip modules associated with failed attempts
 */

#include <ktypes.h>
#include <common.h>
#include <log.h>
#include <predata.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <uapi/asm-generic/errno.h>
#include <kputils.h>

#define BOOT_STATE_FILE       "/data/adb/kp-next/boot_state_v2"
#define EARLY_BOOT_MARKER     "/dev/.kp_boot_attempt"
#define BLACKLIST_FILE        "/data/adb/kp-next/kpm_blacklist"
#define LEGACY_BOOT_COUNT     "/data/adb/kp-next/boot_count"
#define LEGACY_BOOT_CONFIRM   "/data/adb/kp-next/boot_confirmed"
#define LEGACY_LAST_KPM       "/data/adb/kp-next/kpm_last_loaded"

#define BOOT_STATE_MAGIC      0x4b504253u /* KPBS */
#define BOOT_STATE_SCHEMA     2u
#define BOOT_PHASE_PENDING    1u
#define BOOT_PHASE_CONFIRMED  2u
#define MAX_BOOT_COUNT        3u

struct kpm_boot_state {
    uint32_t magic;
    uint32_t version;
    uint64_t generation;
    uint64_t attempt_id;
    uint64_t boot_id;
    uint32_t failures;
    uint32_t phase;
    char last_kpm[64];
    uint32_t checksum;
};

static struct kpm_boot_state current_state;
static uint64_t boot_id;
static int boot_attempt_started;
static int boot_attempt_persisted;
static int boot_state_degraded;
static char previous_failed_kpm[64];
static char current_last_kpm[64];

static uint32_t boot_state_checksum(const struct kpm_boot_state *state)
{
    const unsigned char *p = (const unsigned char *)state;
    const unsigned char *end = (const unsigned char *)&state->checksum;
    uint32_t hash = 2166136261u;

    while (p < end) {
        hash ^= *p++;
        hash *= 16777619u;
    }
    return hash;
}

static int validate_boot_state(const struct kpm_boot_state *state)
{
    if (state->magic != BOOT_STATE_MAGIC || state->version != BOOT_STATE_SCHEMA)
        return -EINVAL;
    if (state->phase != BOOT_PHASE_PENDING && state->phase != BOOT_PHASE_CONFIRMED)
        return -EINVAL;
    if (state->failures > 1000000u)
        return -ERANGE;
    if (state->last_kpm[sizeof(state->last_kpm) - 1] != '\0')
        return -EINVAL;
    if (state->checksum != boot_state_checksum(state))
        return -EIO;
    return 0;
}

static int read_boot_state(struct kpm_boot_state *state)
{
    struct file *f;
    loff_t pos = 0;
    ssize_t len;

    if (!state) return -EINVAL;
    f = filp_open(BOOT_STATE_FILE, O_RDONLY | O_NOFOLLOW, 0);
    if (!f || IS_ERR(f)) return f ? PTR_ERR(f) : -ENOENT;

    memset(state, 0, sizeof(*state));
    len = kernel_read(f, state, sizeof(*state), &pos);
    filp_close(f, 0);
    if (len != (ssize_t)sizeof(*state))
        return len < 0 ? (int)len : -EIO;
    return validate_boot_state(state);
}

static int write_boot_state(struct kpm_boot_state *state)
{
    struct file *f;
    loff_t pos = 0;
    ssize_t written;

    if (!state) return -EINVAL;
    state->magic = BOOT_STATE_MAGIC;
    state->version = BOOT_STATE_SCHEMA;
    state->last_kpm[sizeof(state->last_kpm) - 1] = '\0';
    state->checksum = boot_state_checksum(state);

    f = filp_open(BOOT_STATE_FILE, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (!f || IS_ERR(f)) return f ? PTR_ERR(f) : -EIO;
    written = kernel_write(f, state, sizeof(*state), &pos);
    filp_close(f, 0);
    if (written != (ssize_t)sizeof(*state))
        return written < 0 ? (int)written : -EIO;
    return 0;
}

static int write_file_string_checked(const char *path, const char *str)
{
    struct file *f;
    loff_t pos = 0;
    ssize_t written;
    size_t len;

    if (!path || !str) return -EINVAL;
    len = strlen(str);
    f = filp_open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (!f || IS_ERR(f)) return f ? PTR_ERR(f) : -EIO;
    written = kernel_write(f, str, len, &pos);
    filp_close(f, 0);
    return written == (ssize_t)len ? 0 : (written < 0 ? (int)written : -EIO);
}

static void write_file_string(const char *path, const char *str)
{
    int rc = write_file_string_checked(path, str);
    if (rc) log_boot("kpm_safety: write %s failed rc=%d\n", path, rc);
}

static int read_file_string(const char *path, char *out, int maxlen)
{
    struct file *f;
    loff_t pos = 0;
    int len;

    if (!out || maxlen <= 0) return -EINVAL;
    f = filp_open(path, O_RDONLY | O_NOFOLLOW, 0);
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

static void append_file_string(const char *path, const char *str)
{
    struct file *f;
    loff_t pos;
    size_t len;
    ssize_t written;

    if (!path || !str) return;
    len = strlen(str);
    f = filp_open(path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0600);
    if (!f || IS_ERR(f)) {
        log_boot("kpm_safety: append %s open failed rc=%ld\n", path, f ? PTR_ERR(f) : -EIO);
        return;
    }
    pos = vfs_llseek(f, 0, SEEK_END);
    written = kernel_write(f, str, len, &pos);
    filp_close(f, 0);
    if (written != (ssize_t)len)
        log_boot("kpm_safety: append %s failed rc=%ld\n", path, (long)written);
}

static void clear_legacy_boot_state(void)
{
    /* Legacy values were produced by the broken double-increment model. They
     * are never imported into schema 2; best-effort clearing prevents tools
     * from mistaking them for current state. */
    write_file_string(LEGACY_BOOT_COUNT, "0");
    write_file_string(LEGACY_BOOT_CONFIRM, "1");
    write_file_string(LEGACY_LAST_KPM, "");
}

/* ============================================================
 * 1. Boot-attempt state machine
 *
 * module_init:    one transient identity, no /data access and no failure count.
 * post-fs-data:   account exactly one previous pending attempt, then persist
 *                 exactly one pending record for the current boot.
 * boot-completed: confirm that same attempt and reset consecutive failures.
 *
 * /dev is diagnostic only and is never treated as reboot-persistent storage.
 * A torn/invalid persistent state fails closed instead of guessing a count.
 * ============================================================ */

void kpm_safety_begin_boot_attempt(void)
{
    if (boot_attempt_started) return;
    boot_attempt_started = 1;
    boot_id = rand_next();
    if (!boot_id) boot_id = 1;
    write_file_string(EARLY_BOOT_MARKER, "started");
    log_boot("kpm_safety: boot id %llx started (transient stage)\n", boot_id);
}

int kpm_safety_persist_boot_attempt(void)
{
    struct kpm_boot_state previous;
    int rc;

    if (boot_attempt_persisted) {
        if (boot_state_degraded) return -EIO;
        return current_state.failures >= MAX_BOOT_COUNT ? 1 : 0;
    }
    if (!boot_attempt_started) kpm_safety_begin_boot_attempt();

    memset(&previous, 0, sizeof(previous));
    memset(previous_failed_kpm, 0, sizeof(previous_failed_kpm));
    rc = read_boot_state(&previous);

    memset(&current_state, 0, sizeof(current_state));
    current_state.boot_id = boot_id;
    current_state.phase = BOOT_PHASE_PENDING;
    strncpy(current_state.last_kpm, current_last_kpm, sizeof(current_state.last_kpm) - 1);

    if (rc == -ENOENT) {
        /* First schema-2 boot. Do not import values from the known-broken
         * legacy counter. */
        current_state.generation = 1;
        current_state.attempt_id = 1;
        current_state.failures = 0;
        log_boot("kpm_safety: starting schema-2 state; legacy counter ignored\n");
    } else if (rc) {
        log_boot("kpm_safety: persistent state corrupt/unreadable rc=%d; degraded\n", rc);
        boot_state_degraded = 1;
        boot_attempt_persisted = 1;
        return rc;
    } else {
        current_state.generation = previous.generation + 1;
        current_state.attempt_id = previous.attempt_id + 1;
        if (previous.phase == BOOT_PHASE_PENDING) {
            current_state.failures = previous.failures + 1;
            strncpy(previous_failed_kpm, previous.last_kpm, sizeof(previous_failed_kpm) - 1);
        } else {
            current_state.failures = 0;
        }
    }

    rc = write_boot_state(&current_state);
    if (rc) {
        log_boot("kpm_safety: persist attempt %llu failed rc=%d; degraded\n",
                 current_state.attempt_id, rc);
        boot_state_degraded = 1;
        boot_attempt_persisted = 1;
        return rc;
    }

    boot_attempt_persisted = 1;
    if (current_state.generation == 1) clear_legacy_boot_state();

    log_boot("kpm_safety: attempt=%llu boot=%llx persisted, previous failures=%u\n",
             current_state.attempt_id, boot_id, current_state.failures);

    if (current_state.failures >= MAX_BOOT_COUNT) {
        log_boot("kpm_safety: SAFE MODE — %u previous boots were unconfirmed\n",
                 current_state.failures);
        return 1;
    }
    return 0;
}

int kpm_safety_confirm_boot_completed(void)
{
    int rc;

    if (!boot_attempt_persisted) {
        rc = kpm_safety_persist_boot_attempt();
        if (rc < 0) return rc;
    }
    if (boot_state_degraded) return -EIO;

    current_state.generation++;
    current_state.failures = 0;
    current_state.phase = BOOT_PHASE_CONFIRMED;
    strncpy(current_state.last_kpm, current_last_kpm, sizeof(current_state.last_kpm) - 1);

    rc = write_boot_state(&current_state);
    if (rc) {
        log_boot("kpm_safety: attempt=%llu confirmation failed rc=%d\n",
                 current_state.attempt_id, rc);
        boot_state_degraded = 1;
        return rc;
    }

    write_file_string(EARLY_BOOT_MARKER, "confirmed");
    log_boot("kpm_safety: attempt=%llu confirmed; failure count reset\n",
             current_state.attempt_id);
    return 0;
}

/* ============================================================
 * 2. Pre-load Validation
 * ============================================================ */

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

    logkd("kpm_safety: ELF validation passed\n");
    return 0;
}

/* ============================================================
 * 3. Faulty KPM blacklist / attribution
 * ============================================================ */

int kpm_safety_check_blacklist(const char *kpm_name)
{
    if (!kpm_name) return 0;

    if (previous_failed_kpm[0] &&
        !strncmp(previous_failed_kpm, kpm_name, sizeof(previous_failed_kpm))) {
        log_boot("kpm_safety: BLACKLISTED — %s was last KPM in previous failed attempt\n", kpm_name);
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
            if (entry_len > 0 && (int)strlen(kpm_name) == entry_len &&
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
    int rc;

    if (!kpm_name) return;
    memset(current_last_kpm, 0, sizeof(current_last_kpm));
    strncpy(current_last_kpm, kpm_name, sizeof(current_last_kpm) - 1);

    if (boot_attempt_persisted && !boot_state_degraded) {
        current_state.generation++;
        memset(current_state.last_kpm, 0, sizeof(current_state.last_kpm));
        strncpy(current_state.last_kpm, current_last_kpm, sizeof(current_state.last_kpm) - 1);
        rc = write_boot_state(&current_state);
        if (rc) {
            boot_state_degraded = 1;
            log_boot("kpm_safety: bind KPM %s to attempt=%llu failed rc=%d\n",
                     kpm_name, current_state.attempt_id, rc);
        }
    }

    logkd("kpm_safety: attempt=%llu boot=%llx loading %s\n",
          current_state.attempt_id, boot_id, kpm_name);
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

void kpm_safety_init(void)
{
    memset(&current_state, 0, sizeof(current_state));
    memset(previous_failed_kpm, 0, sizeof(previous_failed_kpm));
    memset(current_last_kpm, 0, sizeof(current_last_kpm));
    boot_id = 0;
    boot_attempt_started = 0;
    boot_attempt_persisted = 0;
    boot_state_degraded = 0;
    log_boot("kpm_safety: initialized schema=%u\n", BOOT_STATE_SCHEMA);
}
