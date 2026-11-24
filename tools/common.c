/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#define _POSIX_C_SOURCE 200809L
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include "common.h"
#include "order.h"

bool log_enable = false;

int can_b_imm(uint64_t from, uint64_t to)
{
    // B: 128M
    uint32_t imm26 = 1 << 25 << 2;
    return (to >= from && to - from < imm26) || (from >= to && from - to <= imm26);
}

int b(uint32_t *buf, uint64_t from, uint64_t to)
{
    if (can_b_imm(from, to)) {
        buf[0] = 0x14000000u | (((to - from) & 0x0FFFFFFFu) >> 2u);
        return 4;
    }
    return 0;
}

int32_t relo_branch_func(const char *img, int32_t func_offset)
{
    uint32_t inst = *(uint32_t *)(img + func_offset);
    int32_t relo_offset = func_offset;
    if (INSN_IS_B(inst)) {
        uint64_t imm26 = bits32(inst, 25, 0);
        uint64_t imm64 = sign64_extend(imm26 << 2u, 28u);
        relo_offset = func_offset + (int32_t)imm64;
        tools_logi("relocate branch function 0x%x to 0x%x\n", func_offset, relo_offset);
    }
    return relo_offset;
}

int bounded_file_size(FILE *fp, const char *path, int limit)
{
    long len;
    if (fseek(fp, 0, SEEK_END) || (len = ftell(fp)) < 0 || fseek(fp, 0, SEEK_SET)) {
        fprintf(stderr, "cannot measure file: %s\n", path);
        return -EIO;
    }
    if (len > limit) {
        fprintf(stderr, "file too large: %s (limit %d bytes)\n", path, limit);
        return -EFBIG;
    }
    return (int)len;
}

int read_exact(FILE *fp, void *buf, size_t size, const char *path)
{
    size_t n = fread(buf, 1, size, fp);
    if (n == size) return 0;
    fprintf(stderr, "short read: %s (expected %zu bytes, got %zu)\n", path, size, n);
    return -EIO;
}

int read_file_align(const char *path, char **con, int *out_len, int align, int limit)
{
    if (!path) tools_loge_exit("missing input file path\n");
    FILE *fp = fopen(path, "rb");
    if (!fp) tools_log_errno_exit("open file %s\n", path);
    int len = bounded_file_size(fp, path, limit);
    if (len < 0) exit(EXIT_FAILURE);
    uint64_t padded = align_ceil(len, align);
    if (padded > (unsigned)limit) tools_loge_exit("aligned file too large: %s\n", path);
    char *buf = malloc(padded ? padded : 1);
    if (!buf) tools_loge_exit("cannot allocate buffer for %s\n", path);
    if (read_exact(fp, buf, len, path)) exit(EXIT_FAILURE);
    if (fgetc(fp) != EOF || ferror(fp))
        tools_loge_exit("incomplete read or size changed for %s\n", path);
    if (fclose(fp)) tools_log_errno_exit("close %s", path);
    memset(buf + len, 0, padded - len);
    *con = buf;
    *out_len = (int)padded;
    return len;
}

static int write_parts(FILE *fp, const file_part_t *parts, size_t count)
{
    static const char zeros[4096];
    for (size_t i = 0; i < count; ++i) {
        size_t len = parts[i].len;
        if (parts[i].data && len) {
            if (fwrite(parts[i].data, 1, len, fp) != len) return -1;
        } else {
            while (len) {
                size_t n = len < sizeof(zeros) ? len : sizeof(zeros);
                if (fwrite(zeros, 1, n, fp) != n) return -1;
                len -= n;
            }
        }
    }
    return 0;
}

void write_file_parts(const char *path, const file_part_t *parts, size_t count)
{
    struct stat st;
    int exists = lstat(path, &st) == 0;
    if (!exists && errno != ENOENT) tools_log_errno_exit("stat %s", path);
    FILE *fp;
    char *tmp = NULL;
    if (!exists || S_ISREG(st.st_mode)) {
        tmp = malloc(strlen(path) + sizeof(".XXXXXX"));
        if (!tmp) tools_log_errno_exit("allocate output path");
        sprintf(tmp, "%s.XXXXXX", path);
        int fd = mkstemp(tmp);
        if (fd < 0) tools_log_errno_exit("create output for %s", path);
        mode_t mask = umask(0);
        umask(mask);
        if (fchmod(fd, exists ? st.st_mode & 0777 : 0666 & ~mask) || !(fp = fdopen(fd, "wb"))) {
            close(fd);
            unlink(tmp);
            tools_loge_exit("cannot open output for %s\n", path);
        }
    } else {
        fp = fopen(path, "wb");
        if (!fp) tools_log_errno_exit("open %s", path);
    }
    int rc = write_parts(fp, parts, count) || ferror(fp);
    if (fclose(fp) || rc || (tmp && rename(tmp, path))) {
        if (tmp) unlink(tmp);
        tools_loge_exit("failed to write %s\n", path);
    }
    free(tmp);
}

void write_file(const char *path, const void *con, size_t len, bool append)
{
    file_part_t part = { con, len };
    if (!append) {
        write_file_parts(path, &part, 1);
        return;
    }
    FILE *fp = fopen(path, "ab");
    if (!fp) tools_log_errno_exit("open %s", path);
    int rc = write_parts(fp, &part, 1);
    if (fclose(fp) || rc) tools_loge_exit("failed to append %s\n", path);
}

int64_t int_unpack(void *ptr, int32_t size, bool is_be)
{
    bool swp = is_be ^ is_be();
    int64_t res64;
    int32_t res32;
    int16_t res16;
    switch (size) {
    case 8:
        res64 = *(int64_t *)ptr;
        return swp ? i64swp(res64) : res64;
    case 4:
        res32 = *(int32_t *)ptr;
        return swp ? i32swp(res32) : res32;
    case 2:
        res16 = *(int16_t *)ptr;
        return swp ? i16swp(res16) : res16;
    default:
        return *(int8_t *)ptr;
    }
}

uint64_t uint_unpack(void *ptr, int32_t size, bool is_be)
{
    bool swp = is_be ^ is_be();
    uint64_t res64;
    uint32_t res32;
    uint16_t res16;
    switch (size) {
    case 8:
        res64 = *(uint64_t *)ptr;
        return swp ? u64swp(res64) : res64;
    case 4:
        res32 = *(uint32_t *)ptr;
        return swp ? u32swp(res32) : res32;
    case 2:
        res16 = *(uint16_t *)ptr;
        return swp ? u16swp(res16) : res16;
    default:
        return *(uint8_t *)ptr;
    }
}
