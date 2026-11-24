/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <sys/types.h>
#include <kpm_boot_count.h>

struct counter {
    int value;      /* count or read error */
    int write_rc;
    int reads;
    int writes;
};
static struct counter stores[KPM_COUNT_STORES];

static int read_count(enum kpm_count_store store)
{
    stores[store].reads++;
    return stores[store].value;
}

static int write_count(enum kpm_count_store store, int count, bool exclusive)
{
    struct counter *c = &stores[store];
    c->writes++;
    if (count) assert(exclusive == (c->value == -ENOENT));
    if (c->write_rc) return c->write_rc;
    c->value = count;
    return 0;
}

static const struct kpm_count_io io = { .read = read_count, .write = write_count };

static void set_stores(int early, int data)
{
    stores[KPM_EARLY_STORE] = (struct counter){ .value = early };
    stores[KPM_DATA_STORE] = (struct counter){ .value = data };
}

static void expect_status(struct kpm_boot_attempt *boot, int safe_mode, int count, unsigned int errors)
{
    struct kpm_safety_status s = kpm_boot_status(boot, safe_mode);
    assert(s.boot_count == count && s.safe_mode == safe_mode && s.storage_errors == errors);
}

int main(void)
{
    struct kpm_boot_attempt boot = { 0 };
    set_stores(-ENOENT, -ENOENT);
    for (int attempt = 1; attempt <= KPM_BOOT_LIMIT; attempt++) {
        boot = (struct kpm_boot_attempt){ 0 };
        kpm_boot_start(&boot, &io);
        kpm_boot_start(&boot, &io);
        expect_status(&boot, 0, attempt, 0);
        for (int i = 0; i < KPM_COUNT_STORES; i++) {
            assert(stores[i].reads == attempt && stores[i].writes == attempt);
            assert(stores[i].value == attempt);
        }
    }

    stores[KPM_DATA_STORE].write_rc = -EROFS;
    kpm_boot_confirm(&boot, &io);
    expect_status(&boot, 1, 0, KPM_COUNT_DATA_ERROR);
    assert(stores[KPM_DATA_STORE].value == KPM_BOOT_LIMIT);
    stores[KPM_DATA_STORE].write_rc = 0;
    kpm_boot_confirm(&boot, &io);
    kpm_boot_confirm(&boot, &io);
    kpm_boot_start(&boot, &io);
    expect_status(&boot, 1, 0, 0);
    assert(stores[KPM_EARLY_STORE].writes == KPM_BOOT_LIMIT + 1);
    assert(stores[KPM_DATA_STORE].writes == KPM_BOOT_LIMIT + 2);
    assert(stores[KPM_EARLY_STORE].value == 0 && stores[KPM_DATA_STORE].value == 0);

    const struct {
        int early, data, early_write_rc, data_write_rc, count;
        unsigned int errors;
    } cases[] = {
        { 0, 0, 0, 0, 1, 0 },
        { 2, 0, 0, 0, 3, 0 },
        { 0, 4, 0, 0, 5, 0 },
        { INT_MAX, 0, 0, 0, INT_MAX, 0 },
        { -EACCES, 2, 0, 0, 3, KPM_COUNT_EARLY_ERROR },
        { 2, -EINVAL, 0, 0, 3, KPM_COUNT_DATA_ERROR },
        { -ENOENT, 2, -ENOENT, -EIO, 3, KPM_COUNT_EARLY_ERROR | KPM_COUNT_DATA_ERROR },
        { -ENOENT, -EACCES, -ENOENT, 0, -1, KPM_COUNT_EARLY_ERROR | KPM_COUNT_DATA_ERROR },
        { -EIO, -EINVAL, 0, 0, -1, KPM_COUNT_EARLY_ERROR | KPM_COUNT_DATA_ERROR },
    };
    for (size_t n = 0; n < sizeof(cases) / sizeof(cases[0]); n++) {
        boot = (struct kpm_boot_attempt){ 0 };
        set_stores(cases[n].early, cases[n].data);
        stores[KPM_EARLY_STORE].write_rc = cases[n].early_write_rc;
        stores[KPM_DATA_STORE].write_rc = cases[n].data_write_rc;
        kpm_boot_start(&boot, &io);
        kpm_boot_start(&boot, &io);
        expect_status(&boot, 0, cases[n].count, cases[n].errors);
        for (int i = 0; i < KPM_COUNT_STORES; i++) {
            int prior = i == KPM_EARLY_STORE ? cases[n].early : cases[n].data;
            assert(stores[i].reads == 1);
            assert(stores[i].writes == (prior == -ENOENT || prior >= 0));
            assert(stores[i].value == ((cases[n].errors & (1U << i)) ? prior : boot.count));
        }
    }
    puts("KPM boot-attempt accounting passed");
}
