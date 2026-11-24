/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include "common.h"
#include "order.h"

bool log_enable = false;

int can_b_imm(uint64_t from, uint64_t to)
{
    // B: 128M
    uint32_t imm26 = 1 << 25 << 2;
    return (to >= from && to - from <= imm26) || (from >= to && from - to <= imm26);
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
    FILE *fp = fopen(path, "rb");
    if (!fp) tools_log_errno_exit("open file %s\n", path);
    int len = bounded_file_size(fp, path, limit);
    if (len < 0) exit(EXIT_FAILURE);
    uint64_t padded = align_ceil(len, align);
    if (padded > (unsigned)limit) tools_loge_exit("aligned file too large: %s\n", path);
    char *buf = malloc(padded ? padded : 1);
    if (!buf) tools_loge_exit("cannot allocate buffer for %s\n", path);
    if (read_exact(fp, buf, len, path)) exit(EXIT_FAILURE);
    fclose(fp);
    memset(buf + len, 0, padded - len);
    *con = buf;
    *out_len = (int)padded;
    return len;
}

void write_file(const char *path, const char *con, int len, bool append)
{
    FILE *fout = fopen(path, append ? "ab" : "wb");
    if (!fout) tools_log_errno_exit("open file %s\n", path);
    int writelen = fwrite(con, 1, len, fout);
    if (writelen != len) tools_log_errno_exit("write file %s\n", path);
    fclose(fout);
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
