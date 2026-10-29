/* Host checks for the KPM list copy bound and name formatter. */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KP_KPM_LIST_FORMAT
#include "../kernel/patch/include/kpm_query.h"

static int failures;

static void expect_int(const char *what, int got, int want)
{
    if (got == want)
        return;
    fprintf(stderr, "FAIL %s: got %d want %d\n", what, got, want);
    failures++;
}

static void expect_str(const char *what, const char *got, const char *want)
{
    if (got && want && strcmp(got, want) == 0)
        return;
    fprintf(stderr, "FAIL %s: got \"%s\" want \"%s\"\n", what, got ? got : "(null)", want ? want : "(null)");
    failures++;
}

/* Same control flow as list_modules(), without the module list or RCU. */
static int format_names(char *out, int size, const char *const *names, int count)
{
    int off = 0;
    int i;

    if (!out || size <= 0)
        return -EINVAL;
    out[0] = '\0';
    for (i = 0; i < count; i++) {
        int rc = kpm_list_append(out, size, &off, names[i]);
        if (rc)
            return rc;
    }
    kpm_list_finish(out, off);
    return off;
}

static void test_copy_bounds(void)
{
    const int src = 4096;
    const struct {
        int filled;
        int dest;
        int want;
    } cases[] = {
        { 0, 4095, 0 },
        { 0, 4096, 0 },
        { 0, 4097, -ENOBUFS },
        { 4, 4095, 4 },
        { 4, 4096, 4 },
        { 4, 4097, -ENOBUFS },
        { 4095, 4095, 4095 },
        { 4095, 4096, 4095 },
        { 4095, 4097, -ENOBUFS },
        { 4096, 4095, -ENOBUFS },
        { 4096, 4096, 4096 },
        { 4096, 4097, -ENOBUFS },
        { 10, 8192, -ENOBUFS },
        { 10, INT_MAX, -ENOBUFS },
        { 10, 0, -EINVAL },
        { 10, -1, -EINVAL },
        { 5000, 4096, -ENOBUFS },
        { 100, 50, -ENOBUFS },
        { 50, 50, 50 },
        { -ENOBUFS, 4096, -ENOBUFS },
        { -ENOBUFS, 4097, -ENOBUFS },
        { -ENOENT, 128, -ENOENT },
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char label[64];
        int got = kpm_bounded_copy_len(cases[i].filled, cases[i].dest, src);
        snprintf(label, sizeof(label), "copy filled=%d dest=%d", cases[i].filled, cases[i].dest);
        expect_int(label, got, cases[i].want);
        if (got > 0) {
            if (got > cases[i].filled || got > cases[i].dest || got > src) {
                fprintf(stderr, "FAIL %s: length %d exceeds filled/dest/src\n", label, got);
                failures++;
            }
        }
    }

    expect_int("src cap 0", kpm_bounded_copy_len(4, 4, 0), -EINVAL);
}

static void test_empty_and_exact_names(void)
{
    char buf[64];
    const char *one[] = { "alpha" };
    const char *two[] = { "alpha", "beta" };
    int sz;

    memset(buf, 0xA5, sizeof(buf));
    sz = format_names(buf, (int)sizeof(buf), NULL, 0);
    expect_int("empty size", sz, 0);
    expect_int("empty first byte", (unsigned char)buf[0], 0);
    expect_int("empty copy", kpm_bounded_copy_len(sz, 4096, 4096), 0);

    memset(buf, 0xA5, sizeof(buf));
    sz = format_names(buf, (int)sizeof(buf), one, 1);
    expect_int("one size", sz, 6);
    expect_str("one text", buf, "alpha");
    expect_int("byte after record stays poison", (unsigned char)buf[7], 0xA5);
    expect_int("copy exact filled", kpm_bounded_copy_len(sz, 4096, 4096), 6);
    expect_int("copy does not grow to user len", kpm_bounded_copy_len(sz, 4095, 4096), 6);

    sz = format_names(buf, (int)sizeof(buf), two, 1 + 1);
    expect_int("two size", sz, 11);
    expect_str("two text", buf, "alpha\nbeta");
}

static void test_truncation_stays_inside_allocation(void)
{
    const int caps[] = { 1, 2, 8, 4095, 4096, 4097 };
    char huge[4600];
    size_t i;

    memset(huge, 'A', sizeof(huge) - 1);
    huge[sizeof(huge) - 1] = '\0';

    for (i = 0; i < sizeof(caps) / sizeof(caps[0]); i++) {
        char *buf = malloc((size_t)caps[i]);
        const char *names[] = { huge };
        int rc;

        if (!buf) {
            fprintf(stderr, "FAIL malloc %d\n", caps[i]);
            failures++;
            return;
        }
        memset(buf, 0xA5, (size_t)caps[i]);
        rc = format_names(buf, caps[i], names, 1);
        expect_int("overlong name", rc, -ENOBUFS);
        free(buf);
    }
}

static void test_previous_names_kept_when_next_does_not_fit(void)
{
    char *buf = malloc(8);
    const char *names[] = { "ab", "cdefghij" };
    int rc;

    if (!buf) {
        fprintf(stderr, "FAIL malloc 8\n");
        failures++;
        return;
    }
    rc = format_names(buf, 8, names, 2);
    expect_int("second name overflows", rc, -ENOBUFS);
    expect_int("partial start wiped", (unsigned char)buf[3], 0);
    expect_int("first record kept", memcmp(buf, "ab\n", 3), 0);
    free(buf);
}

static void test_filled_prefix_is_what_would_be_copied(void)
{
    const char *names[] = { "mod" };
    char *src = malloc(4096);
    int sz;
    int n;
    char *window;

    if (!src) {
        fprintf(stderr, "FAIL malloc 4096\n");
        failures++;
        return;
    }
    memset(src, 0xA5, 4096);
    sz = format_names(src, 4096, names, 1);
    expect_int("mod filled", sz, 4);
    expect_str("mod text", src, "mod");

    n = kpm_bounded_copy_len(sz, 4096, 4096);
    expect_int("mod copy", n, 4);
    window = malloc((size_t)n);
    if (!window) {
        fprintf(stderr, "FAIL malloc window\n");
        failures++;
        free(src);
        return;
    }
    /* n is the filled prefix. A larger copy would read off this allocation. */
    memcpy(window, src, (size_t)n);
    expect_int("copied nul", window[n - 1], 0);
    free(window);

    expect_int("4097 rejected", kpm_bounded_copy_len(sz, 4097, 4096), -ENOBUFS);
    expect_int("INT_MAX rejected", kpm_bounded_copy_len(sz, INT_MAX, 4096), -ENOBUFS);
    free(src);
}

static void test_many_names_stop_at_capacity(void)
{
    const char *names[3000];
    char storage[] = "m";
    char *buf;
    int i;
    int rc;

    for (i = 0; i < 3000; i++)
        names[i] = storage;

    buf = malloc(4096);
    if (!buf) {
        fprintf(stderr, "FAIL malloc names\n");
        failures++;
        return;
    }
    memset(buf, 0xA5, 4096);
    rc = format_names(buf, 4096, names, 3000);
    expect_int("full list", rc, -ENOBUFS);
    expect_int("full list terminated", buf[4095] == '\0' || buf[0] == '\0' || memchr(buf, '\0', 4096) != NULL, 1);
    free(buf);
}

int main(void)
{
    test_copy_bounds();
    test_empty_and_exact_names();
    test_truncation_stays_inside_allocation();
    test_previous_names_kept_when_next_does_not_fit();
    test_filled_prefix_is_what_would_be_copied();
    test_many_names_stop_at_capacity();
    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("kpm query bounds ok\n");
    return 0;
}
