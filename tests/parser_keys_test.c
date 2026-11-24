/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Compiled by check_parser_keys.py with the production functions under test. */
#include <assert.h>
#include <sys/types.h>
#include "kpm.h"
#include "patch.h"
#include "bootimg.h"
#include "lib/sha/sha256.h"

static int fail_payload_read;
size_t __real_fread(void *, size_t, size_t, FILE *);
size_t __wrap_fread(void *ptr, size_t size, size_t count, FILE *fp)
{
    if (fail_payload_read && ftell(fp) == 4096 && count) count--;
    return __real_fread(ptr, size, count, fp);
}

/* Oversized-file tests must exit via their size check before a large allocation. */
void *__real_malloc(size_t);
void *__wrap_malloc(size_t size)
{
    assert(size <= 1024 * 1024);
    return __real_malloc(size);
}

#define __user
#define Elf_Ehdr Elf64_Ehdr
#define unlikely(x) (x)
#define IS_ERR(x) 0
#define PTR_ERR(x) (-EIO)
#define O_RDONLY 0
#define logkfd(...) ((void)0)
#define logkfe(...) ((void)0)
struct file { int unused; };
static struct file file;
static loff_t file_len;
static ssize_t read_result;
static int allocations, frees, closes, loads;
static char dummy;
static struct file *filp_open(const char *p, int flags, int mode) { return &file; }
static loff_t vfs_llseek(struct file *f, loff_t off, int whence) { return file_len; }
static void filp_close(struct file *f, void *owner) { closes++; }
static void *vmalloc(size_t n) { allocations++; return &dummy; }
static void kvfree(void *p) { assert(p == &dummy); frees++; }
static ssize_t kernel_read(struct file *f, void *p, size_t n, loff_t *pos)
{
    assert(*pos == 0);
    return read_result;
}
static long load_module(const void *p, int n, const char *args, const char *event, void *reserved)
{
    assert(p == &dummy && n == file_len && closes == 1);
    loads++;
    return 0;
}

static char saved_key[SUPER_KEY_LEN];
static long compat_strncpy_from_user(char *dst, char *src, long capacity)
{
    if (!src) return -EFAULT;
    size_t n = strlen(src);
    if (n >= (size_t)capacity) n = capacity - 1;
    memcpy(dst, src, n);
    dst[n] = 0;
    src[0] = '!'; /* The user can change the source as soon as the copy returns. */
    return n ? (long)n + 1 : 0;
}
static void reset_superkey(const char *src)
{
    assert(strlen(src) < sizeof(saved_key));
    strcpy(saved_key, src);
}

#include "parser_keys_under_test.h"

static void check_loader(loff_t len, ssize_t bytes, long expected, int allocs, int calls)
{
    file_len = len;
    read_result = bytes;
    allocations = frees = closes = loads = 0;
    assert(load_module_path("sample", NULL, NULL) == expected);
    assert(allocations == allocs && frees == allocs && closes == 1 && loads == calls);
}

static void check_setter(void)
{
    char buf[SUPER_KEY_LEN + 2];
    memset(buf, 'a', sizeof(buf));
    buf[SUPER_KEY_LEN - 1] = 0;
    assert(call_skey_set(buf) == 0);
    assert(strlen(saved_key) == SUPER_KEY_LEN - 1 && saved_key[0] == 'a');
    for (int n = SUPER_KEY_LEN; n <= SUPER_KEY_LEN + 1; n++) {
        memset(buf, 'b', n);
        buf[n] = 0;
        assert(call_skey_set(buf) == -E2BIG);
    }
    buf[0] = 0;
    assert(call_skey_set(buf) < 0);
    assert(call_skey_set(NULL) == -EFAULT);
    assert(saved_key[0] == 'a');
}

int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "list")) return print_kpm_info_path(argv[2]);
    if (argc == 3 && !strcmp(argv[1], "unpack")) {
        fail_payload_read = 1;
        return extract_kernel(argv[2]);
    }
    assert(argc == 3);
    check_loader(-ESPIPE, 0, -ESPIPE, 0, 0);
    check_loader(sizeof(Elf_Ehdr), 0, -ENOEXEC, 0, 0);
    check_loader(KPM_MAX_FILE_SIZE + 1, 0, -ENOEXEC, 0, 0);
    check_loader(1LL << 32, 0, -ENOEXEC, 0, 0);
    check_loader(1024, 1023, -EIO, 1, 0);
    check_loader(1024, -EFAULT, -EFAULT, 1, 0);
    check_loader(KPM_MAX_FILE_SIZE, KPM_MAX_FILE_SIZE, 0, 1, 1);
    check_setter();

    set_log_enable(true);
    preset_t preset = { .header = { .magic = KP_MAGIC, .kp_version.minor = 13 } };
    set_image_superkey(&preset.setup, argv[1], false);
    assert(!strcmp((char *)preset.setup.superkey, argv[1]));
    set_image_superkey(&preset.setup, argv[1], true);
    write_file("preset", (const char *)&preset, sizeof(preset), false);
    /* A small image with a preset at the expected page boundary. */
    char image[4096] = { 0 };
    uint32_t branch = 0x14000001;
    memcpy(image, &branch, sizeof(branch));
    memcpy(image + 56, "ARM\x64", 4);
    strcpy(image + 128, "Linux version 6.1.0\n");
    preset.setup.kimg_size = sizeof(image);
    preset.setup.kpimg_size = sizeof(preset);
    /* A real patch run stores the original header and kernel size in the
       preset; the merged info path restores from them before inspecting. */
    memcpy(preset.setup.header_backup, image, sizeof(preset.setup.header_backup));
    preset.setup.kernel_size = sizeof(image);
    write_file("image", image, sizeof(image), false);
    write_file("image", (const char *)&preset, sizeof(preset), true);
    patch_extra_item_t item = { .magic = EXTRA_HDR_MAGIC, .type = EXTRA_TYPE_KPM, .con_size = 1024 };
    preset.setup.extra_size = sizeof(item);
    write_file("truncated-extra", image, sizeof(image), false);
    write_file("truncated-extra", (const char *)&preset, sizeof(preset), true);
    write_file("truncated-extra", (const char *)&item, sizeof(item), true);
    assert(print_kp_image_info_path("preset") == 0);
    assert(reset_key("preset", "reset", argv[2]) == 0);
    assert(print_kp_image_info_path("reset") == 0);
    return 0;
}
