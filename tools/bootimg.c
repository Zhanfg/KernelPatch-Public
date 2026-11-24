/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2026 bmax121. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <zlib.h>
#include <limits.h>
#include <stddef.h>
#include "order.h"
#include "bootimg.h"
#include "common.h"
#include "lib/lz4/lz4.h"
#include "lib/lz4/lz4frame.h"
#include "lib/lz4/lz4hc.h"
#include "lib/bz2/bzlib.h"
#include "lib/xz/xz.h"
#include "lib/sha/sha256.h"
#include "lib/sha/sha1.h"
// #include "lib/zstd/zstd.h"


typedef struct {
    uint8_t *data;
    uint32_t size;
} kernel_blob_t;

void *memmem(const void *haystack, size_t haystacklen,
                       const void *needle, size_t needlelen) {
    if (needlelen == 0) return (void *)haystack;
    if (haystacklen < needlelen) return NULL;

    const char *h = (const char *)haystack;
    const char *n = (const char *)needle;
    size_t i;

    for (i = 0; i <= haystacklen - needlelen; i++) {
        if (h[i] == n[0] && memcmp(&h[i], n, needlelen) == 0) {
            return (void *)&h[i];
        }
    }
    return NULL;
}

static bool uses_sha256(const uint32_t id[8])
{
    return !(id[0] | id[1] | id[2] | id[3] | id[4] | id[5]) || id[6] || id[7];
}

static int find_dtb_offset(const uint8_t *buf, unsigned int sz) {
    if (!buf || sz < sizeof(struct fdt_header)) return -1;
    const uint8_t *curr = buf;
    const uint8_t *end = buf + sz;

    while ((size_t)(end - curr) >= sizeof(struct fdt_header)) {
        curr = memmem(curr, end - curr, DTB_MAGIC, 4);
        if (!curr || (size_t)(end - curr) < sizeof(struct fdt_header)) break;
        struct fdt_header hdr;
        memcpy(&hdr, curr, sizeof(hdr));
        uint32_t total = u32be(hdr.totalsize);
        uint32_t offset = u32be(hdr.off_dt_struct);
        if (total <= (size_t)(end - curr) && total > 0x48 && offset <= total - 4 &&
            !memcmp(curr + offset, "\0\0\0\1", 4))
            return (int)(curr - buf);
        curr += 4;
    }
    return -1;
}

static int compress_gzip(const kernel_blob_t *raw, kernel_blob_t *out)
{
    z_stream stream = {0};
    if (deflateInit2(&stream, 9, Z_DEFLATED, 16 + MAX_WBITS, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        return -1;
    uLong bound = deflateBound(&stream, raw->size);
    uint8_t *data = bound <= UINT_MAX ? malloc(bound) : NULL;
    if (!data) {
        deflateEnd(&stream);
        return -1;
    }
    stream.next_in = raw->data;
    stream.avail_in = raw->size;
    stream.next_out = data;
    stream.avail_out = (uInt)bound;
    int rc = deflate(&stream, Z_FINISH);
    uint32_t size = (uint32_t)stream.total_out;
    if (deflateEnd(&stream) != Z_OK || rc != Z_STREAM_END) {
        free(data);
        return -1;
    }
    *out = (kernel_blob_t){data, size};
    return 0;
}

static int decompress_gzip(const uint8_t *data, uint32_t size, kernel_blob_t *out)
{
    z_stream stream = {0};
    if (inflateInit2(&stream, 16 + MAX_WBITS) != Z_OK) return -1;
    stream.next_in = (Bytef *)data;
    stream.avail_in = size;
    size_t capacity = 65536;
    uint8_t *buf = NULL;
    int rc = Z_OK;
    while (rc == Z_OK) {
        uint8_t *grown = realloc(buf, capacity);
        if (!grown) break;
        buf = grown;
        stream.next_out = buf + stream.total_out;
        stream.avail_out = capacity - stream.total_out;
        rc = inflate(&stream, Z_NO_FLUSH);
        if (stream.avail_out || capacity == INT_MAX) break;
        capacity = capacity > INT_MAX / 2 ? INT_MAX : capacity * 2;
    }
    uint32_t produced = (uint32_t)stream.total_out;
    if (inflateEnd(&stream) != Z_OK || rc != Z_STREAM_END || stream.avail_in) {
        free(buf);
        return -1;
    }
    *out = (kernel_blob_t){buf, produced};
    return 0;
}

static int parse_lz4_header(const compress_head *head, LZ4F_preferences_t *prefs) {
    uint32_t magic = (head->magic[0] << 0) | (head->magic[1] << 8) | 
                     (head->magic[2] << 16) | (head->magic[3] << 24);
    if (magic != 0x184D2204) {
        return -1;
    }
    LZ4F_preferences_t tmp = LZ4F_INIT_PREFERENCES;
    *prefs = tmp;

    uint8_t flg = head->magic[4];
    prefs->frameInfo.blockMode = (flg & 0x20) ? LZ4F_blockIndependent : LZ4F_blockLinked;
    prefs->frameInfo.blockChecksumFlag = (flg & 0x10) ? 
                                         LZ4F_blockChecksumEnabled : LZ4F_noBlockChecksum;
    prefs->frameInfo.contentChecksumFlag = (flg & 0x08) ? 
                                           LZ4F_contentChecksumEnabled : LZ4F_noContentChecksum;
    

    uint8_t bd = head->magic[5];
    uint8_t block_size_id = (bd >> 4) & 0x07;
    switch (block_size_id) {
        case 4: prefs->frameInfo.blockSizeID = LZ4F_max64KB; break;
        case 5: prefs->frameInfo.blockSizeID = LZ4F_max256KB; break;
        case 6: prefs->frameInfo.blockSizeID = LZ4F_max1MB; break;
        case 7: prefs->frameInfo.blockSizeID = LZ4F_max4MB; break;
        default: return -2;
    }
    
    return 0;
}

static int compress_lz4(const kernel_blob_t *raw, kernel_blob_t *out, compress_head head)
{
    LZ4F_preferences_t prefs;
    if (parse_lz4_header(&head, &prefs)) return -1;
    size_t bound = LZ4F_compressFrameBound(raw->size, &prefs);
    if (LZ4F_isError(bound) || bound > UINT32_MAX) return -1;
    uint8_t *data = malloc(bound);
    if (!data) return -1;
    size_t size = LZ4F_compressFrame(data, bound, raw->data, raw->size, &prefs);
    if (LZ4F_isError(size)) {
        free(data);
        return -1;
    }
    *out = (kernel_blob_t){data, (uint32_t)size};
    return 0;
}

static int compress_lz4_le(const kernel_blob_t *raw, kernel_blob_t *result)
{
    size_t in_size = raw->size;
    size_t max_blocks = (in_size + LZ4_BLOCK_SIZE - 1) / LZ4_BLOCK_SIZE;
    size_t max_out =
        sizeof(uint32_t) +                         // MAGIC
        max_blocks * (sizeof(uint32_t) +           // block header
        LZ4_compressBound(LZ4_BLOCK_SIZE));

    uint8_t *out = malloc(max_out);
    if (!out) {
        tools_loge("Failed to allocate memory for LZ4 compression,size: %zu\n",max_out);
        return -2;
    }

    size_t out_off = 0;

    /* write MAGIC */
    uint32_t magic = u32le(LZ4_MAGIC);
    memcpy(out + out_off, &magic, sizeof(magic));
    out_off += sizeof(magic);

    size_t in_off = 0;

    while (in_off < in_size) {
        size_t chunk_size = in_size - in_off;
        if (chunk_size > LZ4_BLOCK_SIZE)
            chunk_size = LZ4_BLOCK_SIZE;

        int max_dst = LZ4_compressBound((int)chunk_size);

        int compressed = LZ4_compress_HC(
            (const char *)(raw->data + in_off),
            (char *)(out + out_off + sizeof(uint32_t)),
            (int)chunk_size,
            max_dst,
            LZ4HC_CLEVEL
        );

        if (compressed <= 0) {
            tools_loge("LZ4 compression failed for block at offset %zu\n", in_off);
            free(out);
            return -3;
        }

        /* write compressed block size */
        uint32_t csz = u32le((uint32_t)compressed);
        memcpy(out + out_off, &csz, sizeof(csz));
        out_off += sizeof(uint32_t);

        /* advance over compressed data */
        out_off += compressed;
        in_off += chunk_size;
    }

    *result = (kernel_blob_t){out, (uint32_t)out_off};
    return 0;
}

static int decode_kernel(int method, const uint8_t *data, uint32_t size, kernel_blob_t *out)
{
    if (method == 1) return decompress_gzip(data, size, out);
    if (method == 2) {
        LZ4F_decompressionContext_t ctx;
        if (LZ4F_isError(LZ4F_createDecompressionContext(&ctx, LZ4F_VERSION))) return -1;
        size_t consumed = size, produced = 64 * 1024 * 1024;
        uint8_t *buf = malloc(produced);
        size_t rc = buf ? LZ4F_decompress(ctx, buf, &produced, data, &consumed, NULL) : 1;
        LZ4F_freeDecompressionContext(ctx);
        if (rc || consumed != size) {
            free(buf);
            return -1;
        }
        *out = (kernel_blob_t){buf, (uint32_t)produced};
        return 0;
    }
    if (method == 3) {
        tools_logi("Probing LZ4 Legacy (block-based)...\n");

        const uint8_t *p   = (const uint8_t *)data;
        const uint8_t *end = p + size;


        if (size < 4)
            return -1;


        if (memcmp(p, "\x02\x21\x4c\x18", 4))
            return -1;

        p += 4;  

        size_t out_cap = 64 * 1024 * 1024;
        uint8_t *out_buf = malloc(out_cap);
        if (!out_buf)
            return -1;

        size_t out_off = 0;

        uint8_t *block_out = malloc(LZ4_BLOCK_SIZE);
        if (!block_out) {
            free(out_buf);
            return -1;
        }

        int decoded_any = 0;
        while (1) {
            uint32_t block_size;

            if (p == end) break;
            if (end - p < 4) goto fail;

            memcpy(&block_size, p, 4);
            block_size = u32le(block_size);
            p += 4;

            if (p == end && (block_size == 0 || block_size == out_off)) break;
            if (!block_size) goto fail;

            if (block_size > (unsigned)LZ4_compressBound(LZ4_BLOCK_SIZE))
                goto fail;

            if (block_size > (size_t)(end - p))
                goto fail;

            int decoded = LZ4_decompress_safe(
                (const char *)p,
                (char *)block_out,
                (int)block_size,
                LZ4_BLOCK_SIZE
            );

            if (decoded < 0)
                goto fail;

            decoded_any = 1;

            if (out_off + (size_t)decoded > out_cap) {
                size_t new_cap = out_cap * 2;
                if (out_off > INT_MAX - (size_t)decoded) goto fail;
                while (new_cap < out_off + (size_t)decoded)
                    new_cap *= 2;

                uint8_t *tmp = realloc(out_buf, new_cap);
                if (!tmp)
                    goto fail;

                out_buf = tmp;
                out_cap = new_cap;
            }

            memcpy(out_buf + out_off, block_out, (size_t)decoded);
            out_off += (size_t)decoded;

            p += block_size;
        }


        if (!decoded_any)
            goto fail;

        *out = (kernel_blob_t){out_buf, (uint32_t)out_off};
        free(block_out);
        return 0;
    fail:
        free(block_out);
        free(out_buf);
        return -1;
    }
    if (method == 5) {
        unsigned int capacity = 64 * 1024 * 1024;
        uint8_t *buf = malloc(capacity);
        if (!buf) return -1;
        bz_stream stream = {0};
        int rc = BZ2_bzDecompressInit(&stream, 0, 0);
        if (rc == BZ_OK) {
            stream.next_in = (char *)data;
            stream.avail_in = size;
            stream.next_out = (char *)buf;
            stream.avail_out = capacity;
            rc = BZ2_bzDecompress(&stream);
            BZ2_bzDecompressEnd(&stream);
        }
        if (rc != BZ_STREAM_END || stream.avail_in) {
            free(buf);
            return -1;
        }
        *out = (kernel_blob_t){buf, capacity - stream.avail_out};
        return 0;
    }
    if (method == 6) {
        xz_crc32_init();
        struct xz_dec *decoder = xz_dec_init(XZ_SINGLE, 0);
        if (!decoder) return -1;
        struct xz_buf buf = { .in = data, .in_size = size, .out_size = 128 * 1024 * 1024 };
        buf.out = malloc(buf.out_size);
        enum xz_ret rc = buf.out ? xz_dec_run(decoder, &buf) : XZ_MEM_ERROR;
        xz_dec_end(decoder);
        // XZ stream padding is a multiple of four zero bytes.
        if (rc != XZ_STREAM_END || (size - buf.in_pos) % 4) {
            free(buf.out);
            return -1;
        }
        for (size_t i = buf.in_pos; i < size; ++i) {
            if (data[i]) {
                free(buf.out);
                return -1;
            }
        }
        *out = (kernel_blob_t){buf.out, (uint32_t)buf.out_pos};
        return 0;
    }
    tools_loge_exit("unsupported kernel compression method %d\n", method);
}

int detect_compress_method(compress_head data) {
    // 1. GZIP / ZOPFLI (1F 8B)
    if (data.magic[0] == 0x1F && data.magic[1] == 0x8B) return 1;
    if (data.magic[0] == 0x1F && data.magic[1] == 0x9E) return 1;
    // 2. LZ4 (04 22 4D 18 is Frame )
    if (data.magic[0] == 0x04 && data.magic[1] == 0x22 && 
        data.magic[2] == 0x4D && data.magic[3] == 0x18) return 2;

    if (data.magic[0] == 0x03 && data.magic[1] == 0x21 && 
        data.magic[2] == 0x4C && data.magic[3] == 0x18) return 2;

    // LZ4 Legacy (02 21 4C 18)
    if (data.magic[0] == 0x02 && data.magic[1] == 0x21 && 
        data.magic[2] == 0x4C && data.magic[3] == 0x18) return 3;

    // 3. ZSTD  28 B5 2F FD
    if (data.magic[0] == 0x28 && data.magic[1] == 0xB5 && 
        data.magic[2] == 0x2F && data.magic[3] == 0xFD) return 4;

    // 4. BZIP2 (BZh) - 42 5A 68
    if (data.magic[0] == 0x42 && data.magic[1] == 0x5A && 
        data.magic[2] == 0x68) return 5;

    // 5. XZ - FD 37 7A 58 5A 00
    if (data.magic[0] == 0xFD && data.magic[1] == 0x37 && 
        data.magic[2] == 0x7A && data.magic[3] == 0x58) return 6;

    // 6. LZMA - 5D 00 00
    if (data.magic[0] == 0x5D && data.magic[1] == 0x00 && 
        data.magic[2] == 0x00) return 7;

    return 0; // Raw Kernel
}

// The returned blob owns exactly the bytes that will go in the kernel section.
static kernel_blob_t encode_kernel(kernel_blob_t raw, int method, compress_head head)
{
    kernel_blob_t encoded = {0};
    int rc;
    switch (method) {
    case 0: return raw;
    case 1:
    case 6: // The original XZ and LZMA paths deliberately emit gzip.
    case 7: rc = compress_gzip(&raw, &encoded); break;
    case 2: rc = compress_lz4(&raw, &encoded, head); break;
    case 3: rc = compress_lz4_le(&raw, &encoded); break;
    case 5: {
        unsigned int capacity = raw.size + raw.size / 100 + 601;
        encoded.data = malloc(capacity);
        if (!encoded.data) tools_loge_exit("out of memory compressing bzip2\n");
        rc = BZ2_bzBuffToBuffCompress((char *)encoded.data, &capacity, (char *)raw.data, raw.size, 9, 0, 30);
        encoded.size = capacity;
        break;
    }
    default: tools_loge_exit("unsupported kernel compression method %d\n", method);
    }
    free(raw.data);
    if (rc) tools_loge_exit("kernel compression failed (method %d, error %d)\n", method, rc);
    return encoded;
}

typedef struct {
    struct boot_img_hdr *hdr;
    int file_size;
    uint32_t version, page;
    uint8_t *kernel;
    compress_head head;
    int method, dtb_offset;
} boot_image_t;

_Static_assert(sizeof(struct avb_footer) == AVB_FOOTER_SIZE, "AVB footer size");
_Static_assert(offsetof(struct boot_img_hdr, dtb_addr) == 1652, "packed boot v2 header");

static boot_image_t read_boot_image(const char *path)
{
    char *data;
    boot_image_t img = {0};
    read_file(path, &data, &img.file_size);
    img.hdr = (struct boot_img_hdr *)data;
    if ((size_t)img.file_size < sizeof(*img.hdr) || memcmp(data, "ANDROID!", 8))
        tools_loge_exit("invalid or truncated boot header in %s\n", path);
    img.version = u32le(img.hdr->unused[0]);
    if (img.version > 10) img.version = 0; // older DT-size header
    img.page = img.version >= 3 ? 4096 : u32le(img.hdr->page_size);
    if (!img.page || (img.page & (img.page - 1)) || img.page < sizeof(*img.hdr) ||
        img.page > (unsigned)img.file_size || !img.hdr->kernel_size ||
        u32le(img.hdr->kernel_size) > (unsigned)img.file_size - img.page)
        tools_loge_exit("invalid boot page or truncated kernel in %s\n", path);
    img.kernel = (uint8_t *)data + img.page;
    size_t n = u32le(img.hdr->kernel_size);
    memcpy(&img.head, img.kernel, n < sizeof(img.head) ? n : sizeof(img.head));
    img.method = detect_compress_method(img.head);
    img.dtb_offset = img.version < 3 ? find_dtb_offset(img.kernel, n) : -1;
    return img;
}

int extract_kernel(const char *path)
{
    boot_image_t img = read_boot_image(path);
    uint32_t size = u32le(img.hdr->kernel_size);
    int method = img.method;
    kernel_blob_t decoded = {img.kernel, size};
    if (method) {
        if (img.dtb_offset > 0) size = img.dtb_offset;
        if (decode_kernel(method, img.kernel, size, &decoded))
            tools_loge_exit("kernel decompression failed (method %d)\n", method);
    }
    write_file("kernel", decoded.data, decoded.size, false);
    if (method) free(decoded.data);
    free(img.hdr);
    return 0;
}

// Hash each legacy section's on-disk bytes followed by its (unpadded) size.
static size_t update_boot_id(boot_image_t *img, const kernel_blob_t *kernel, const uint8_t *tail, size_t tail_size)
{
    struct boot_img_hdr *hdr = img->hdr;
    if (img->version >= 3) {
        uint64_t used = u32le(hdr->kernel_addr); // v3/v4 ramdisk_size
        if (img->version == 4) {
            uint32_t signature_size;
            memcpy(&signature_size, (const uint8_t *)hdr + 1580, sizeof(signature_size));
            if (signature_size) used = align_ceil(used, img->page) + u32le(signature_size);
        }
        if (used > tail_size) tools_loge_exit("truncated ramdisk or boot signature\n");
        return used;
    }
    uint32_t sizes[6] = {kernel->size, u32le(hdr->ramdisk_size), u32le(hdr->second_size)};
    size_t count = 3;
    if (u32le(hdr->unused[0]) > 10) sizes[count++] = u32le(hdr->unused[0]);
    if (img->version >= 1) sizes[count++] = u32le(hdr->recovery_dtbo_size);
    if (img->version == 2) sizes[count++] = u32le(hdr->dtb_size);

    SHA256_CTX sha256;
    SHA1_CTX sha1;
    uint32_t old_id[8];
    memcpy(old_id, hdr->id, sizeof(old_id));
    bool use_sha256 = uses_sha256(old_id);
    if (use_sha256) sha256_init(&sha256);
    else sha1_init(&sha1);
    uint64_t offset = 0, used = 0;
    for (size_t i = 0; i < count; ++i) {
        uint32_t size = sizes[i];
        const uint8_t *data = kernel->data;
        if (i && size) {
            if (offset + size > tail_size) tools_loge_exit("truncated boot section %zu\n", i);
            data = tail + offset;
            used = offset + size;
            offset += align_ceil(size, img->page);
        }
        uint32_t le = u32le(size);
        if (use_sha256) {
            sha256_update(&sha256, data, size);
            sha256_update(&sha256, (uint8_t *)&le, sizeof(le));
        } else {
            sha1_update(&sha1, data, size);
            sha1_update(&sha1, (uint8_t *)&le, sizeof(le));
        }
    }
    if (use_sha256) sha256_final(&sha256, (uint8_t *)hdr->id);
    else sha1_final(&sha1, (uint8_t *)hdr->id);
    return used;
}

int repack_bootimg(const char *orig_path, const char *kernel_path, const char *out_path)
{
    boot_image_t img = read_boot_image(orig_path);
    struct boot_img_hdr *hdr = img.hdr;
    uint32_t old_size = u32le(hdr->kernel_size);
    char *raw;
    int raw_size;
    read_file(kernel_path, &raw, &raw_size);
    if (!raw_size) tools_loge_exit("empty replacement kernel\n");
    kernel_blob_t kernel = encode_kernel((kernel_blob_t){(uint8_t *)raw, raw_size}, img.method, img.head);

    if (img.dtb_offset > 0) {
        const uint8_t *dtb = img.kernel + img.dtb_offset;
        uint32_t len = old_size - img.dtb_offset;
        // Raw unpack keeps the original appended DTB.
        if (img.method || find_dtb_offset(kernel.data, kernel.size) < 0) {
            if ((uint64_t)kernel.size + len > UINT32_MAX) tools_loge_exit("kernel section too large\n");
            uint8_t *buf = realloc(kernel.data, (size_t)kernel.size + len);
            if (!buf) tools_log_errno_exit("append kernel DTB");
            memcpy(buf + kernel.size, dtb, len);
            kernel = (kernel_blob_t){buf, kernel.size + len};
        }
    }

    size_t old_end = img.page + align_ceil(old_size, img.page);
    if (old_end > (unsigned)img.file_size) tools_loge_exit("truncated boot kernel padding\n");
    uint64_t new_end = img.page + align_ceil(kernel.size, img.page);
    if (new_end > INT_MAX) tools_loge_exit("repacked boot image too large\n");
    uint8_t *tail = (uint8_t *)hdr + old_end;
    size_t tail_size = img.file_size - old_end;
    struct avb_footer *footer = NULL;
    if (tail_size >= sizeof(*footer)) {
        struct avb_footer *candidate = (struct avb_footer *)(tail + tail_size - sizeof(*footer));
        if (!memcmp(&candidate->magic, "AVBf", 4)) {
            footer = candidate;
            tail_size -= sizeof(*footer);
        }
    }
    hdr->kernel_size = u32le(kernel.size);
    size_t used = update_boot_id(&img, &kernel, tail, tail_size);
    if ((img.version == 1 || img.version == 2) && hdr->recovery_dtbo_size)
        hdr->recovery_dtbo_offset = u64le(new_end + align_ceil(u32le(hdr->ramdisk_size), img.page) +
                                          align_ceil(u32le(hdr->second_size), img.page));
    size_t padding = 0;
    if (footer) {
        // Keep partition padding and its footer at the end when the new kernel fits.
        uint64_t original_size = u64be(footer->image_size_be);
        uint64_t vbmeta = u64be(footer->vbmeta_offset_be);
        uint64_t vbmeta_size = u64be(footer->vbmeta_size_be);
        size_t limit = old_end + tail_size;
        if (original_size < old_end || original_size > limit || vbmeta < original_size ||
            vbmeta > limit || vbmeta_size > limit - vbmeta)
            tools_loge_exit("invalid AVB footer extents\n");
        if (used < vbmeta + vbmeta_size - old_end) used = vbmeta + vbmeta_size - old_end;
        while (tail_size > used && !tail[tail_size - 1]) --tail_size;
        uint64_t needed = new_end + tail_size + sizeof(*footer);
        uint64_t total = (unsigned)img.file_size;
        if (needed > total) total = align_ceil(needed, img.page);
        padding = total - needed;
        footer->image_size_be = u64be(original_size - old_end + new_end);
        footer->vbmeta_offset_be = u64be(vbmeta - old_end + new_end);
    }
    size_t kpad = new_end - img.page - kernel.size;
    file_part_t parts[] = {
        {hdr, img.page}, {kernel.data, kernel.size},
        {kpad == old_end - img.page - old_size ? img.kernel + old_size : NULL, kpad},
        {tail, tail_size}, {NULL, padding}, {footer, footer ? sizeof(*footer) : 0},
    };
    write_file_parts(out_path, parts, sizeof(parts) / sizeof(parts[0]));
    free(kernel.data);
    free(hdr);
    tools_logi("Repack completed: %s\n", out_path);
    return 0;
}
int cacluate_sha1(const char *file) {
    FILE *fp = fopen(file, "rb");
    if (!fp) tools_log_errno_exit("open %s", file);
    SHA1_CTX ctx;
    sha1_init(&ctx);

    uint8_t *buffer = malloc(409600);
    if (!buffer) tools_log_errno_exit("allocate checksum buffer");
    size_t bytesRead;
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        sha1_update(&ctx, buffer, bytesRead);
    }
    if (ferror(fp) || fclose(fp)) tools_loge_exit("failed to read %s\n", file);
    uint8_t hash[SHA1_BLOCK_SIZE];
    sha1_final(&ctx, hash);
    free(buffer);
    for (int i = 0; i < 20; i++) { 
        printf("%02x", hash[i]);
    }
    return 0;
}
