/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#define _GNU_SOURCE
#define __USE_GNU

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>

#include "kallsym.h"
#include "bootimg.h"
#include "patch.h"
#include "kallsym.h"
#include "image.h"
#include "common.h"
#include "order.h"
#include "preset.h"
#include "symbol.h"
#include "kpm.h"
#include "lib/sha/sha256.h"

void read_kernel_file(const char *path, kernel_file_t *kernel_file)
{
    memset(kernel_file, 0, sizeof(*kernel_file));
    read_file(path, &kernel_file->kimg, &kernel_file->kimg_len);
    kernel_file->is_uncompressed_img = kernel_file->kimg_len >= 20 &&
                                       !memcmp("UNCOMPRESSED_IMG", kernel_file->kimg, 16);
    if (kernel_file->is_uncompressed_img) {
        memcpy(kernel_file->prefix, kernel_file->kimg, sizeof(kernel_file->prefix));
        kernel_file->kimg_len -= sizeof(kernel_file->prefix);
        memmove(kernel_file->kimg, kernel_file->kimg + sizeof(kernel_file->prefix), kernel_file->kimg_len);
    }
}

static void set_wrapped_size(kernel_file_t *file)
{
    uint32_t len = u32le(file->kimg_len);
    memcpy(file->prefix + 16, &len, sizeof(len));
}

void write_kernel_file(kernel_file_t *file, const char *path)
{
    file_part_t parts[] = {
        { file->prefix, file->is_uncompressed_img ? sizeof(file->prefix) : 0 },
        { file->kimg, file->kimg_len },
    };
    write_file_parts(path, parts, 2);
}

void free_kernel_file(kernel_file_t *file)
{
    free(file->kimg);
    file->kimg = NULL;
}

preset_t *get_preset(const char *kimg, int kimg_len)
{
    char magic[MAGIC_LEN] = KP_MAGIC;
    return (preset_t *)memmem(kimg, kimg_len, magic, sizeof(magic));
}

uint32_t get_kpimg_version(const char *kpimg_path)
{
    char *kpimg = NULL;
    int kpimg_len = 0;
    read_file(kpimg_path, &kpimg, &kpimg_len);
    preset_t *preset = get_preset(kpimg, kpimg_len);
    if (!preset) tools_loge_exit("not patched kernel image\n");
    version_t ver = preset->header.kp_version;
    uint32_t version = (ver.major << 16) + (ver.minor << 8) + ver.patch;
    return version;
}

int extra_str_type(const char *extra_str)
{
    int extra_type = EXTRA_TYPE_NONE;
    if (!strcmp(extra_str, EXTRA_TYPE_KPM_STR)) {
        extra_type = EXTRA_TYPE_KPM;
    } else if (!strcmp(extra_str, EXTRA_TYPE_EXEC_STR)) {
        extra_type = EXTRA_TYPE_EXEC;
    } else if (!strcmp(extra_str, EXTRA_TYPE_SHELL_STR)) {
        extra_type = EXTRA_TYPE_SHELL;
    } else if (!strcmp(extra_str, EXTRA_TYPE_RAW_STR)) {
        extra_type = EXTRA_TYPE_RAW;
    } else if (!strcmp(extra_str, EXTRA_TYPE_ANDROID_RC_STR)) {
        extra_type = EXTRA_TYPE_ANDROID_RC;
    } else {
    }
    return extra_type;
}

const char *extra_type_str(extra_item_type extra_type)
{
    switch (extra_type) {
    case EXTRA_TYPE_KPM:
        return EXTRA_TYPE_KPM_STR;
    case EXTRA_TYPE_EXEC:
        return EXTRA_TYPE_EXEC_STR;
    case EXTRA_TYPE_SHELL:
        return EXTRA_TYPE_SHELL_STR;
    case EXTRA_TYPE_RAW:
        return EXTRA_TYPE_RAW_STR;
    case EXTRA_TYPE_ANDROID_RC:
        return EXTRA_TYPE_ANDROID_RC_STR;
    default:
        return EXTRA_TYPE_NONE_STR;
    }
}

static char *bytes_to_hexstr(const unsigned char *data, int len)
{
    char *buf = (char *)malloc(2 * len + 1);
    buf[2 * len] = '\0';
    for (int i = 0; i < len; i++) {
        sprintf(&buf[2 * i], "%02x", data[i]);
    }
    return buf;
}

void print_preset_info(preset_t *preset)
{
    setup_header_t *header = &preset->header;
    setup_preset_t *setup = &preset->setup;
    version_t ver = header->kp_version;
    uint32_t ver_num = (ver.major << 16) + (ver.minor << 8) + ver.patch;
    bool is_android = header->config_flags & CONFIG_ANDROID;
    bool is_debug = header->config_flags & CONFIG_DEBUG;

    fprintf(stdout, INFO_KP_IMG_SESSION "\n");
    fprintf(stdout, "version=0x%x\n", ver_num);
    fprintf(stdout, "compile_time=%s\n", header->compile_time);
    fprintf(stdout, "config=%s,%s\n", is_android ? "android" : "linux", is_debug ? "debug" : "release");
    fprintf(stdout, "superkey=%s\n", setup->superkey);

    // todo: remove compat version
    if (ver_num > 0xa04) {
        char *hexstr = bytes_to_hexstr(setup->root_superkey, ROOT_SUPER_KEY_HASH_LEN);
        fprintf(stdout, "root_superkey=%s\n", hexstr);
        free(hexstr);
    }

    fprintf(stdout, INFO_ADDITIONAL_SESSION "\n");
    char *addition = setup->additional;
    // todo: remove compat version
    if (ver_num <= 0xa04) {
        addition -= (ROOT_SUPER_KEY_HASH_LEN + SETUP_PRESERVE_LEN);
    }
    char *pos = addition;
    while (pos < addition + ADDITIONAL_LEN) {
        int len = *pos;
        if (!len) break;
        pos++;
        char backup = *(pos + len);
        *(pos + len) = 0;
        fprintf(stdout, "%s\n", pos);
        *(pos + len) = backup;
        pos += len;
    }
}

int print_kp_image_info_path(const char *kpimg_path)
{
    int rc = 0;
    char *kpimg;
    int len = 0;
    read_file(kpimg_path, &kpimg, &len);
    preset_t *preset = (preset_t *)kpimg;
    if (get_preset(kpimg, len) != preset) {
        rc = -ENOENT;
    } else {
        print_preset_info(preset);
        fprintf(stdout, "\n");
        free(kpimg);
    }
    return rc;
}

// Stored in existing preset spare bytes. The optional map backup follows the empty
// extra item, so older payloads stop enumerating before the backup.
typedef struct {
    char magic[4];
    uint32_t map_bytes_le;
    uint32_t pi_offset_le;
    char pi_original[4];
    char wrapper_size[4];
} image_undo_t;

_Static_assert(sizeof(image_undo_t) <= sizeof(((setup_preset_t *)0)->__), "image undo metadata");

static preset_t *find_image_preset(kernel_file_t *file, int *original_len)
{
    int pos = 0;
    while (pos < file->kimg_len) {
        preset_t *preset = get_preset(file->kimg + pos, file->kimg_len - pos);
        if (!preset) break;
        int offset = (char *)preset - file->kimg;
        pos = offset + 1;
        if (!offset || offset % SZ_4K || (size_t)(file->kimg_len - offset) < sizeof(*preset)) continue;
        uint64_t saved = u64le(preset->setup.kimg_size);
        // Old unpatch also accepted a missing file length on page-aligned images.
        if (!saved) {
            if (u64le(preset->setup.setup_offset) != (unsigned)offset) continue;
            saved = offset;
        }
        if (saved < 64 || saved > (unsigned)offset || align_ceil(saved, SZ_4K) != (unsigned)offset) continue;
        *original_len = (int)saved;
        return preset;
    }
    return NULL;
}

static void restore_image(kernel_file_t *file, preset_t *preset, int original_len)
{
    setup_preset_t *setup = &preset->setup;
    uint64_t orig_size = u64le(setup->kernel_size);
    image_undo_t undo;
    memcpy(&undo, setup->__, sizeof(undo));
    bool has_undo = !memcmp(undo.magic, "KPU1", 4);
    uint64_t current_size;
    memcpy(&current_size, file->kimg + 16, sizeof(current_size));
    if (has_undo || (orig_size && orig_size < u64le(current_size)))
        kernel_resize(file->kimg, orig_size);
    memcpy(file->kimg, setup->header_backup, sizeof(setup->header_backup));

    if (file->is_uncompressed_img) {
        uint32_t len = u32le(original_len);
        if (has_undo) memcpy(&len, undo.wrapper_size, sizeof(len));
        memcpy(file->prefix + 16, &len, sizeof(len));
    }
    if (!has_undo) return;
    size_t offset = (char *)preset - file->kimg;
    uint64_t kp = u64le(setup->kpimg_size), extra = u64le(setup->extra_size);
    size_t remaining = file->kimg_len - offset;
    uint32_t bytes = u32le(undo.map_bytes_le), pi = u32le(undo.pi_offset_le);
    uint64_t map = u64le(setup->map_offset);
    if (kp < sizeof(*preset) || kp > remaining || extra > remaining - kp ||
        extra < sizeof(patch_extra_item_t) + (uint64_t)bytes || map > (unsigned)original_len ||
        bytes > original_len - map || (pi && pi > original_len - sizeof(undo.pi_original)))
        tools_loge_exit("invalid image recovery bounds\n");
    memcpy(file->kimg + map, file->kimg + offset + kp + extra - bytes, bytes);
    if (pi) memcpy(file->kimg + pi, undo.pi_original, sizeof(undo.pi_original));
}

static int parse_image_patch_info(kernel_file_t *file, patched_kimg_t *pimg)
{
    char *kimg = file->kimg;
    int kimg_len = file->kimg_len;
    pimg->kimg = kimg;
    pimg->kimg_len = kimg_len;
    pimg->ori_kimg_len = kimg_len;
    preset_t *old_preset = find_image_preset(file, &pimg->ori_kimg_len);
    pimg->preset = old_preset;
    if (old_preset) restore_image(file, old_preset, pimg->ori_kimg_len);

    kernel_info_t *kinfo = &pimg->kinfo;
    get_kernel_info(kinfo, kimg, pimg->ori_kimg_len);

    // find banner
    char linux_banner_prefix[] = "Linux version ";
    size_t prefix_len = strlen(linux_banner_prefix);
    const char *imgend = kimg + pimg->ori_kimg_len;
    const char *banner = (char *)pimg->kimg;
    while (banner < imgend && (banner = memmem(banner, imgend - banner, linux_banner_prefix, prefix_len))) {
        if (imgend - banner >= (int)prefix_len + 2 && isdigit((unsigned char)*(banner + prefix_len)) && *(banner + prefix_len + 1) == '.') {
            pimg->banner = banner;
            break;
        }
        ++banner;
    }
    if (!pimg->banner) tools_loge_exit("can't find linux banner\n");

    if (!old_preset) return 0;
    size_t offset = (char *)old_preset - kimg;
    size_t remaining = kimg_len - offset;
    uint64_t kp = u64le(old_preset->setup.kpimg_size);
    uint64_t extra = u64le(old_preset->setup.extra_size);
    if (kp > remaining || extra > remaining - kp) tools_loge_exit("invalid appended image sizes\n");
    const char *item_pos = kimg + offset + kp;
    while (extra >= sizeof(patch_extra_item_t)) {
        patch_extra_item_t *item = (patch_extra_item_t *)item_pos;
        if (memcmp(EXTRA_HDR_MAGIC, item->magic, sizeof(item->magic)) || item->type == EXTRA_TYPE_NONE) break;
        uint64_t len = sizeof(*item) + (uint64_t)u32le(item->args_size) + u32le(item->con_size);
        if (len > extra || pimg->embed_item_num == EXTRA_ITEM_MAX_NUM) tools_loge_exit("invalid extra length\n");
        pimg->embed_item[pimg->embed_item_num++] = item;
        item_pos += len;
        extra -= len;
    }

    return 0;
}

int parse_image_patch_info_path(const char *kimg_path, patched_kimg_t *pimg)
{
    if (!kimg_path) tools_loge_exit("empty kernel image\n");

    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);
    int rc = parse_image_patch_info(&kernel_file, pimg);
    free_kernel_file(&kernel_file);
    return rc;
}

int print_image_patch_info(patched_kimg_t *pimg)
{
    int rc = 0;

    preset_t *preset = pimg->preset;

    fprintf(stdout, INFO_KERNEL_IMG_SESSION "\n");
    fprintf(stdout, "banner=%s", pimg->banner);

    if (pimg->banner[strlen(pimg->banner) - 1] != '\n') fprintf(stdout, "\n");
    fprintf(stdout, "patched=%s\n", preset ? "true" : "false");

    if (preset) {
        print_preset_info(preset);

        fprintf(stdout, INFO_EXTRA_SESSION "\n");
        fprintf(stdout, "num=%d\n", pimg->embed_item_num);

        for (int i = 0; i < pimg->embed_item_num; i++) {
            patch_extra_item_t *item = pimg->embed_item[i];
            const char *type = extra_type_str(item->type);
            fprintf(stdout, INFO_EXTRA_SESSION_N "\n", i);
            fprintf(stdout, "index=%d\n", i);
            fprintf(stdout, "type=%s\n", type);
            fprintf(stdout, "name=%s\n", item->name);
            fprintf(stdout, "event=%s\n", item->event);
            fprintf(stdout, "priority=%d\n", item->priority);
            fprintf(stdout, "args_size=0x%x\n", item->args_size);
            fprintf(stdout, "args=%s\n", item->args_size > 0 ? (char *)item + sizeof(*item) : "");
            fprintf(stdout, "con_size=0x%x\n", item->con_size);

            if (item->type == EXTRA_TYPE_KPM) {
                kpm_info_t kpm_info = { 0 };
                void *kpm = (kpm_info_t *)((uintptr_t)item + sizeof(patch_extra_item_t) + item->args_size);
                rc = get_kpm_info(kpm, item->con_size, &kpm_info);
                if (rc) tools_loge_exit("get kpm infomation error: %d\n", rc);
                fprintf(stdout, "version=%s\n", kpm_info.version);
                fprintf(stdout, "license=%s\n", kpm_info.license);
                fprintf(stdout, "author=%s\n", kpm_info.author);
                fprintf(stdout, "description=%s\n", kpm_info.description);
            }
        }
    }
    return rc;
}

int print_image_patch_info_path(const char *kimg_path)
{
    patched_kimg_t pimg = { 0 };
    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);
    int rc = parse_image_patch_info(&kernel_file, &pimg);
    print_image_patch_info(&pimg);
    free_kernel_file(&kernel_file);
    return rc;
}

static int extra_compare(const void *a, const void *b)
{
    extra_config_t *pa = (extra_config_t *)a;
    extra_config_t *pb = (extra_config_t *)b;
    return -(pa->priority - pb->priority);
}

static void extra_append(char *kimg, const void *data, int len, int *offset)
{
    memcpy(kimg + *offset, data, len);
    *offset += len;
}

static int disable_pi_map(char *img, size_t len)
{
    static const unsigned char pattern[] = {
        0xe6, 0x03, 0x16, 0xaa, 0xe7, 0x03, 0x1f, 0x2a, 0x34, 0x11, 0x88, 0x9a
    };
    char *pos = memmem(img, len, pattern, sizeof(pattern));
    if (!pos) return 0;
    memcpy(pos + 8, "\xf4\x03\x09\xaa", 4);
    return (int)(pos - img) + 8;
}

int patch_update_img(const char *kimg_path, const char *kpimg_path, const char *out_path, const char *superkey,
                     bool root_key, const char **additional, extra_config_t *extra_configs, int extra_config_num)
{
    set_log_enable(true);

    if (!kpimg_path) tools_loge_exit("empty kpimg\n");
    if (!out_path) tools_loge_exit("empty out image path\n");
    if (!superkey && !root_key) tools_loge_exit("empty superkey\n");

    patched_kimg_t pimg = { 0 };
    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);
    if (kernel_file.is_uncompressed_img) tools_logw("kernel image with UNCOMPRESSED_IMG header\n");

    int rc = parse_image_patch_info(&kernel_file, &pimg);
    if (rc) tools_loge_exit("parse kernel image error\n");
    // print_image_patch_info(&pimg);

    kernel_info_t *kinfo = &pimg.kinfo;

    // kimg kallsym
    char *kallsym_kimg = (char *)malloc(pimg.ori_kimg_len);
    if (!kallsym_kimg) tools_log_errno_exit("allocate symbol analysis image");
    memcpy(kallsym_kimg, pimg.kimg, pimg.ori_kimg_len);
    kallsym_t kallsym = { 0 };
    int kver = 0;
    find_linux_banner(&kallsym, kallsym_kimg, pimg.ori_kimg_len, &kver);
    bool is_gki = kver >= 330240;  // 5.10
    tools_logi("is_gki: %s\n", is_gki ? "true" : "false");
    if (analyze_kallsym_info(&kallsym, kallsym_kimg, pimg.ori_kimg_len, ARM64, 1)) {
        tools_loge_exit("analyze_kallsym_info error\n");
    }

    // kpimg
    char *kpimg = NULL;
    int kpimg_len = 0;
    read_file_align(kpimg_path, &kpimg, &kpimg_len, 0x10);

    if (kpimg_len <= SZ_4K || get_preset(kpimg, kpimg_len) != (preset_t *)kpimg)
        tools_loge_exit("invalid or truncated kpimg header\n");

    // extra
    uint64_t extra_size = 0;

    for (int i = 0; i < extra_config_num; i++) {
        extra_config_t *config = extra_configs + i;
        if (config->is_path && config->extra_type == EXTRA_TYPE_NONE) {
            tools_loge_exit("extra type none\n");
        }
        if (config->set_event && strnlen(config->set_event, EXTRA_EVENT_LEN) >= EXTRA_EVENT_LEN) {
            tools_loge_exit("extra event too long: %s\n", config->set_event);
        }
        if (config->set_name && strnlen(config->set_name, EXTRA_NAME_LEN) >= EXTRA_NAME_LEN) {
            tools_loge_exit("extra name too long: %s\n", config->set_event);
        }

        patch_extra_item_t *item = NULL;
        if (config->is_path) {
            // todo: free
            item = (patch_extra_item_t *)malloc(sizeof(patch_extra_item_t));
            memset(item, 0, sizeof(patch_extra_item_t));
            const char *path = config->path;
            char *data;
            int len = 0;
            read_file_align(path, &data, &len, EXTRA_ALIGN);
            config->data = data;
            item->con_size = len;
            // if name not set
            if (!config->set_name) {
                if (config->extra_type == EXTRA_TYPE_KPM) {
                    kpm_info_t kpm_info = { 0 };
                    int rc = get_kpm_info(data, len, &kpm_info);
                    if (rc) tools_loge_exit("can get infomation of kpm, path: %s\n", path);
                    strcpy(item->name, kpm_info.name);
                } else {
                    char *rsp = strrchr(path, '/');
                    strncpy(item->name, rsp ? rsp + 1 : path, EXTRA_NAME_LEN - 1);
                }
            }
        } else {
            const char *name = config->name;
            for (int j = 0; j < pimg.embed_item_num; j++) {
                item = pimg.embed_item[j];
                if (strcmp(name, item->name)) continue;
                if (is_be() ^ kinfo->is_be) {
                    item->type = i32swp(item->type);
                    item->priority = i32swp(item->priority);
                    item->con_size = i32swp(item->con_size);
                    item->args_size = i32swp(item->args_size);
                }
                if (!config->set_args && item->args_size > 0) {
                    config->set_args = (char *)item + sizeof(*item);
                }
                config->extra_type = item->type;
                config->data = (char *)item + sizeof(*item) + item->args_size;
                break;
            }
        }
        if (!item) tools_loge_exit("empty extra item\n");
        strcpy(item->magic, EXTRA_HDR_MAGIC);
        config->item = item;
        item->type = config->extra_type;
        if (config->set_args) item->args_size = align_ceil(strlen(config->set_args) + 1, EXTRA_ALIGN);
        if (config->set_name) strcpy(item->name, config->set_name);
        if (config->set_event) strcpy(item->event, config->set_event);
        if (config->priority) item->priority = config->priority;
    }

    qsort(extra_configs, extra_config_num, sizeof(extra_config_t), extra_compare);

    extra_size += sizeof(patch_extra_item_t); // ending with empty item

    for (int i = 0; i < extra_config_num; i++) {
        extra_config_t *config = extra_configs + i;
        extra_size += sizeof(patch_extra_item_t);
        extra_size += config->item->args_size;
        extra_size += config->item->con_size;
    }

    int ori_kimg_len = pimg.ori_kimg_len;
    int map_start, map_max_size;
    select_map_area(&kallsym, kallsym_kimg, ori_kimg_len, &map_start, &map_max_size, is_gki);
    int sync_size = map_max_size * 2;
    if (sync_size > ori_kimg_len - map_start) sync_size = ori_kimg_len - map_start;
    int map_bytes = memcmp(kernel_file.kimg + map_start, kallsym_kimg + map_start, sync_size) ? sync_size : 0;
    extra_size += align_ceil(map_bytes, 8);

    uint64_t aligned = align_ceil(ori_kimg_len, SZ_4K);
    uint64_t file_len = aligned + kpimg_len + extra_size;
    if (file_len > INT_MAX - sizeof(kernel_file.prefix))
        tools_loge_exit("unsupported image or payload length\n");
    int align_kimg_len = (int)aligned, out_img_len = align_kimg_len + kpimg_len;
    if (kinfo->kernel_size > INT64_MAX - file_len - 2 * SZ_4K)
        tools_loge_exit("ARM64 footprint too large\n");
    uint64_t start_offset = align_ceil(kinfo->kernel_size > file_len ? kinfo->kernel_size : file_len, SZ_4K);
    uint64_t footprint = align_ceil(start_offset + kpimg_len + extra_size, SZ_4K);
    tools_logi("layout: file 0x%" PRIx64 ", start 0x%" PRIx64 ", reserved end 0x%" PRIx64 "\n",
               file_len, start_offset, footprint);

    kernel_file_t out_kernel_file = kernel_file;
    out_kernel_file.kimg = calloc(1, file_len);
    if (!out_kernel_file.kimg) tools_log_errno_exit("allocate patched image");
    out_kernel_file.kimg_len = (int)file_len;
    set_wrapped_size(&out_kernel_file);
    memcpy(out_kernel_file.kimg, pimg.kimg, ori_kimg_len);
    memcpy(out_kernel_file.kimg + align_kimg_len, kpimg, kpimg_len);

    // set preset
    preset_t *preset = (preset_t *)(out_kernel_file.kimg + align_kimg_len);

    setup_header_t *header = &preset->header;
    version_t ver = header->kp_version;
    uint32_t ver_num = (ver.major << 16) + (ver.minor << 8) + ver.patch;
    bool is_android = header->config_flags & CONFIG_ANDROID;
    bool is_debug = header->config_flags & CONFIG_DEBUG;
    tools_logi("kpimg version: %x\n", ver_num);
    tools_logi("kpimg compile time: %.*s\n", COMPILE_TIME_LEN, header->compile_time);
    tools_logi("kpimg config: %s, %s\n", is_android ? "android" : "linux", is_debug ? "debug" : "release");

    setup_preset_t *setup = &preset->setup;
    memset(setup, 0, sizeof(preset->setup));

    setup->kernel_version.major = kallsym.version.major;
    setup->kernel_version.minor = kallsym.version.minor;
    setup->kernel_version.patch = kallsym.version.patch;
    setup->kimg_size = ori_kimg_len;
    setup->kpimg_size = kpimg_len;

    setup->kernel_size = kinfo->kernel_size;
    setup->page_shift = kinfo->page_shift;
    setup->setup_offset = align_kimg_len;
    setup->start_offset = start_offset;
    setup->extra_size = extra_size;

    setup->map_offset = map_start;
    setup->map_max_size = map_max_size;
    int pi_offset = kver > 395008 ? disable_pi_map(out_kernel_file.kimg, ori_kimg_len) : 0;
    image_undo_t undo = { .magic = "KPU1", .map_bytes_le = u32le(map_bytes), .pi_offset_le = u32le(pi_offset) };
    if (kernel_file.is_uncompressed_img) memcpy(undo.wrapper_size, kernel_file.prefix + 16, 4);
    if (pi_offset) {
        memcpy(undo.pi_original, kernel_file.kimg + pi_offset, 4);
        tools_logi("applied PI map change at 0x%x\n", pi_offset);
    }
    memcpy(setup->__, &undo, sizeof(undo));
    memcpy(out_kernel_file.kimg + map_start, kallsym_kimg + map_start, sync_size);
    kernel_resize(out_kernel_file.kimg, footprint);

    const char *symbol_lookup_anchor_name = 0;
    setup->sprintf_offset = get_usable_symbol_offset_try(&kallsym, kallsym_kimg, ori_kimg_len, "sprintf");
    setup->symbol_lookup_anchor_offset =
        select_symbol_lookup_anchor_offset(&kallsym, kallsym_kimg, ori_kimg_len, &symbol_lookup_anchor_name);
    setup->kallsyms_lookup_name_offset =
        get_usable_symbol_offset_try(&kallsym, kallsym_kimg, ori_kimg_len, "kallsyms_lookup_name");
    if (setup->symbol_lookup_anchor_offset && setup->sprintf_offset) {
        tools_logi("prefer runtime forward scan anchor for kallsyms_lookup_name: %s, offset: 0x%08lx\n",
                   symbol_lookup_anchor_name, (unsigned long)setup->symbol_lookup_anchor_offset);
    } else if (setup->kallsyms_lookup_name_offset) {
        tools_logi("fallback to direct kallsyms_lookup_name symbol\n");
    } else {
        tools_loge_exit("no usable symbol scan anchor/sprintf chain and no kallsyms_lookup_name symbol\n");
    }

    setup->printk_offset = get_symbol_offset_zero(&kallsym, kallsym_kimg, "printk");
    if (!setup->printk_offset) setup->printk_offset = get_symbol_offset_zero(&kallsym, kallsym_kimg, "_printk");
    if (!setup->printk_offset) tools_loge_exit("no symbol printk\n");

    if ((is_be() ^ kinfo->is_be)) {
        setup->kimg_size = i64swp(setup->kimg_size);
        setup->kpimg_size = i64swp(setup->kpimg_size);
        setup->kernel_size = i64swp(setup->kernel_size);
        setup->page_shift = i64swp(setup->page_shift);
        setup->setup_offset = i64swp(setup->setup_offset);
        setup->start_offset = i64swp(setup->start_offset);
        setup->extra_size = i64swp(setup->extra_size);
        setup->map_offset = i64swp(setup->map_offset);
        setup->map_max_size = i64swp(setup->map_max_size);
        setup->kallsyms_lookup_name_offset = i64swp(setup->kallsyms_lookup_name_offset);
        setup->sprintf_offset = i64swp(setup->sprintf_offset);
        setup->symbol_lookup_anchor_offset = i64swp(setup->symbol_lookup_anchor_offset);
        setup->paging_init_offset = i64swp(setup->paging_init_offset);
        setup->printk_offset = i64swp(setup->printk_offset);
    }

    // map symbol
    fillin_map_symbol(&kallsym, kallsym_kimg, &setup->map_symbol, kinfo->is_be);

    // header backup
    memcpy(setup->header_backup, pimg.kimg, sizeof(setup->header_backup));

    // start symbol
    fillin_patch_config(&kallsym, kallsym_kimg, ori_kimg_len, &setup->patch_config, kinfo->is_be, 0);

    // superkey
    if (!root_key) {
        tools_logi("superkey: %s\n", superkey);
        strncpy((char *)setup->superkey, superkey, SUPER_KEY_LEN - 1);
    } else if (superkey && superkey[0] != '\0') {
        int len = SHA256_BLOCK_SIZE > ROOT_SUPER_KEY_HASH_LEN ? ROOT_SUPER_KEY_HASH_LEN : SHA256_BLOCK_SIZE;
        BYTE buf[SHA256_BLOCK_SIZE];
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, (const BYTE *)superkey, strnlen(superkey, SUPER_KEY_LEN));
        sha256_final(&ctx, buf);
        memcpy(setup->root_superkey, buf, len);
        char *hexstr = bytes_to_hexstr(setup->root_superkey, len);
        tools_logi("root superkey hash: %s\n", hexstr);
        free(hexstr);
    } else {
        memset(setup->root_superkey, 0, ROOT_SUPER_KEY_HASH_LEN);
        tools_logi("root_key mode with empty superkey: root_superkey zeroed\n");
    }

    // modify kernel entry
    int paging_init_offset = get_symbol_offset_exit(&kallsym, kallsym_kimg, "paging_init");
    setup->paging_init_offset = relo_branch_func(kallsym_kimg, paging_init_offset);
    uint64_t text_offset = aligned + SZ_4K;
    if (!b((uint32_t *)(out_kernel_file.kimg + kinfo->b_stext_insn_offset), kinfo->b_stext_insn_offset, text_offset))
        tools_loge_exit("patched entry outside branch range\n");

    // additional [len key=value] set
    char *addition_pos = setup->additional;
    for (int i = 0;; i++) {
        const char *kv = additional[i];
        if (!kv) break;
        if (!strchr(kv, '=')) tools_loge_exit("addition must be format of key=value\n");

        int kvlen = strlen(kv);
        if (kvlen > 127) tools_loge_exit("addition %s too long\n", kv);
        if (addition_pos + kvlen + 1 > setup->additional + ADDITIONAL_LEN) tools_loge_exit("no memory for addition\n");

        *addition_pos = (char)kvlen;
        addition_pos++;

        tools_logi("adding addition: %s\n", kv);
        strcpy(addition_pos, kv);
        addition_pos += kvlen;
    }

    // append extra
    int current_offset = out_img_len;
    for (int i = 0; i < extra_config_num; i++) {
        extra_config_t *config = extra_configs + i;
        patch_extra_item_t *item = config->item;
        const char *type = extra_type_str(item->type);
        tools_logi("embedding %s, name: %s, priority: %d, event: %s, args: %s, size: 0x%x+0x%x+0x%x\n", type,
                   item->name, item->priority, item->event, config->set_args ?: "", (int)sizeof(*item), item->args_size,
                   item->con_size);

        int args_len = item->args_size;
        int con_len = item->con_size;

        if (is_be() ^ kinfo->is_be) {
            item->type = i32swp(item->type);
            item->priority = i32swp(item->priority);
            item->con_size = i32swp(item->con_size);
            item->args_size = i32swp(item->args_size);
        }

        extra_append(out_kernel_file.kimg, (void *)item, sizeof(*item), &current_offset);
        if (args_len > 0) {
            memcpy(out_kernel_file.kimg + current_offset, config->set_args, strnlen(config->set_args, args_len));
            current_offset += args_len;
        }
        extra_append(out_kernel_file.kimg, (void *)config->data, con_len, &current_offset);
    }

    // guard extra
    patch_extra_item_t empty_item = { 0 };
    extra_append(out_kernel_file.kimg, (void *)&empty_item, sizeof(empty_item), &current_offset);

    if (map_bytes)
        memcpy(out_kernel_file.kimg + out_kernel_file.kimg_len - map_bytes, pimg.kimg + map_start, map_bytes);

    write_kernel_file(&out_kernel_file, out_path);

    // free
    free(kallsym_kimg);
    free(kpimg);
    free_kernel_file(&out_kernel_file);
    free_kernel_file(&kernel_file);

    tools_logi("patch done: %s\n", out_path);

    set_log_enable(false);
    return 0;
}

int unpatch_img(const char *kimg_path, const char *out_path)
{
    if (!kimg_path) tools_loge_exit("empty kernel image\n");
    if (!out_path) tools_loge_exit("empty out image path\n");

    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);

    int original_len;
    preset_t *preset = find_image_preset(&kernel_file, &original_len);
    if (!preset) tools_loge_exit("not a patched kernel image\n");
    restore_image(&kernel_file, preset, original_len);
    kernel_file.kimg_len = original_len;
    write_kernel_file(&kernel_file, out_path);
    free_kernel_file(&kernel_file);
    return 0;
}

int reset_key(const char *kimg_path, const char *out_path, const char *superkey)
{
    if (!kimg_path) tools_loge_exit("empty kernel image\n");
    if (!out_path) tools_loge_exit("empty out image path\n");
    if (!superkey) tools_loge_exit("empty superkey\n");

    if (strlen(superkey) <= 0) tools_loge_exit("empty superkey\n");
    if (strlen(superkey) >= SUPER_KEY_LEN) tools_loge_exit("too long superkey\n");

    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);

    preset_t *preset = get_preset(kernel_file.kimg, kernel_file.kimg_len);
    if (!preset) tools_loge_exit("not patched kernel image\n");

    char *origin_key = strdup((char *)preset->setup.superkey);
    strcpy((char *)preset->setup.superkey, superkey);
    tools_logi("reset superkey: %s -> %s\n", origin_key, preset->setup.superkey);

    write_kernel_file(&kernel_file, out_path);

    free(origin_key);
    free_kernel_file(&kernel_file);

    return 0;
}

int dump_kallsym(const char *kimg_path)
{
    if (!kimg_path) tools_loge_exit("empty kernel image\n");
    set_log_enable(true);
    // read image files
    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);

    kallsym_t kallsym;
    if (analyze_kallsym_info(&kallsym, kernel_file.kimg, kernel_file.kimg_len, ARM64, 1)) {
        fprintf(stdout, "analyze_kallsym_info error\n");
        return -1;
    }
    dump_all_symbols(&kallsym, kernel_file.kimg);
    set_log_enable(false);
    free_kernel_file(&kernel_file);
    return 0;
}
int dump_ikconfig(const char *kimg_path)
{
    if (!kimg_path) tools_loge_exit("empty kernel image\n");
    set_log_enable(true);
    // read image files
    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);

    
    dump_all_ikconfig(kernel_file.kimg,kernel_file.kimg_len);
    set_log_enable(false);
    free_kernel_file(&kernel_file);
    return 0;
}
