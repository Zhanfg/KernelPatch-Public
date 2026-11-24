/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_KPM_BOOT_COUNT_H_
#define _KP_KPM_BOOT_COUNT_H_

#include <stdbool.h>
#include <uapi/asm-generic/errno.h>
#include <uapi/scdefs.h>

#define KPM_BOOT_LIMIT 3

enum kpm_count_store {
    KPM_EARLY_STORE, KPM_DATA_STORE, KPM_COUNT_STORES
};

struct kpm_count_io {
    /* read returns a nonnegative count or -errno */
    int (*read)(enum kpm_count_store store);
    /* exclusive creates a missing counter without replacing unseen history */
    int (*write)(enum kpm_count_store store, int count, bool exclusive);
};

struct kpm_boot_attempt {
    int count;
    unsigned int errors;
    bool started;
    bool confirmed;
};

/* Called during single-threaded init, before event and query hooks are installed. */
static inline bool kpm_boot_start(struct kpm_boot_attempt *boot, const struct kpm_count_io *io)
{
    int prior[KPM_COUNT_STORES];
    int highest = -1;

    if (boot->started) return false;
    boot->started = true;
    boot->errors = 0;
    for (int i = 0; i < KPM_COUNT_STORES; i++) {
        prior[i] = io->read(i);
        if (prior[i] > highest) highest = prior[i];
    }

    int next = 1;
    boot->count = -1;
    if (highest >= 0) {
        next = highest == __INT_MAX__ ? highest : highest + 1;
        boot->count = next; /* retain known history even on a write failure */
    }
    for (int i = 0; i < KPM_COUNT_STORES; i++) {
        /* ENOENT may mean a new file or a missing mount/directory. Only a
         * successful exclusive create establishes a new counter at this path. */
        bool missing = prior[i] == -ENOENT;
        if ((prior[i] < 0 && !missing) || io->write(i, next, missing)) {
            boot->errors |= 1U << i;
        } else {
            boot->count = next;
        }
    }
    return true;
}

/* On a redelivered event, retry only the stores whose reset failed. */
static inline void kpm_boot_confirm(struct kpm_boot_attempt *boot, const struct kpm_count_io *io)
{
    for (int i = 0; i < KPM_COUNT_STORES; i++) {
        unsigned int bit = 1U << i;
        if (boot->confirmed && !(boot->errors & bit)) continue;
        if (io->write(i, 0, false))
            boot->errors |= bit;
        else
            boot->errors &= ~bit;
    }
    boot->confirmed = true;
    boot->count = 0;
}

static inline struct kpm_safety_status kpm_boot_status(const struct kpm_boot_attempt *boot, int safe_mode)
{
    return (struct kpm_safety_status) {
        .boot_count = boot->count,
        .safe_mode = safe_mode,
        .storage_errors = boot->errors,
    };
}

#endif
