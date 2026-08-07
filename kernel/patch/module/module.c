/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <uapi/asm-generic/errno.h>
#include <pgtable.h>
#include <kpmalloc.h>
#include <linux/err.h>
#include <linux/string.h>
#include <symbol.h>
#include <kallsyms.h>
#include <cache.h>
#include <common.h>
#include <linux/fs.h>
#include <uapi/linux/fs.h>
#include <hotpatch.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "module.h"
#include "relo.h"
#include <compact.h>
#include <selinux_hide.h>
#include <proc_hide.h>
#include <kpm_safety.h>
#include <accctl.h>

#define SZ_128M 0x08000000

#define ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))
#define ALIGN(x, a) ALIGN_MASK(x, (typeof(x))(a)-1)
#define align(X) ALIGN(X, page_size)
#define elf_check_arch(x) ((x)->e_machine == EM_AARCH64)
#define ARCH_SHF_SMALL 0

static inline bool strstarts(const char *str, const char *prefix)
{
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

static char *next_string(char *string, unsigned long *secsize)
{
    while (string[0]) {
        string++;
        if ((*secsize)-- <= 1) return 0;
    }
    while (!string[0]) {
        string++;
        if ((*secsize)-- <= 1) return 0;
    }
    return string;
}

static long get_offset(struct module *mod, unsigned int *size, Elf_Shdr *sechdr, unsigned int section)
{
    long ret = ALIGN(*size, sechdr->sh_addralign ?: 1);
    *size = ret + sechdr->sh_size;
    return ret;
}

static char *get_next_modinfo(const struct load_info *info, const char *tag, char *prev)
{
    char *p;
    unsigned int taglen = strlen(tag);
    Elf_Shdr *infosec = &info->sechdrs[info->index.info];
    unsigned long size = infosec->sh_size;
    char *modinfo = (char *)info->hdr + infosec->sh_offset;
    if (prev) {
        size -= prev - modinfo;
        modinfo = next_string(prev, &size);
    }
    for (p = modinfo; p; p = next_string(p, &size)) {
        if (strncmp(p, tag, taglen) == 0 && p[taglen] == '=') return p + taglen + 1;
    }
    return 0;
}

static char *get_modinfo(const struct load_info *info, const char *tag)
{
    return get_next_modinfo(info, tag, 0);
}

static int find_sec(const struct load_info *info, const char *name)
{
    for (int i = 1; i < info->hdr->e_shnum; i++) {
        Elf_Shdr *shdr = &info->sechdrs[i];
        if ((shdr->sh_flags & SHF_ALLOC) && strcmp(info->secstrings + shdr->sh_name, name) == 0) return i;
    }
    return 0;
}

static void *get_sh_base(struct load_info *info, const char *secname)
{
    int idx = find_sec(info, secname);
    if (!idx) return 0;
    Elf_Shdr *infosec = &info->sechdrs[idx];
    return (void *)info->hdr + infosec->sh_offset;
}

static unsigned long get_sh_size(struct load_info *info, const char *secname)
{
    int idx = find_sec(info, secname);
    if (!idx) return 0;
    return info->sechdrs[idx].sh_entsize;
}

static void layout_sections(struct module *mod, struct load_info *info)
{
    static unsigned long const masks[][2] = {
        { SHF_EXECINSTR | SHF_ALLOC, ARCH_SHF_SMALL },
        { SHF_ALLOC, SHF_WRITE | ARCH_SHF_SMALL },
        { SHF_WRITE | SHF_ALLOC, ARCH_SHF_SMALL },
        { ARCH_SHF_SMALL | SHF_ALLOC, 0 }
    };

    for (int i = 0; i < info->hdr->e_shnum; i++) info->sechdrs[i].sh_entsize = ~0UL;

    for (int m = 0; m < sizeof(masks) / sizeof(masks[0]); ++m) {
        for (int i = 0; i < info->hdr->e_shnum; ++i) {
            Elf_Shdr *s = &info->sechdrs[i];
            if ((s->sh_flags & masks[m][0]) != masks[m][0] || (s->sh_flags & masks[m][1]) || s->sh_entsize != ~0UL)
                continue;
            s->sh_entsize = get_offset(mod, &mod->size, s, i);
        }
        switch (m) {
        case 0:
            mod->size = align(mod->size);
            mod->text_size = mod->size;
            break;
        case 1:
            mod->size = align(mod->size);
            mod->ro_size = mod->size;
            break;
        case 2:
            break;
        case 3:
            mod->size = align(mod->size);
            break;
        }
    }
}

static bool is_core_symbol(const Elf_Sym *src, const Elf_Shdr *sechdrs, unsigned int shnum)
{
    const Elf_Shdr *sec;
    if (src->st_shndx == SHN_UNDEF || src->st_shndx >= shnum || !src->st_name) return false;
    sec = sechdrs + src->st_shndx;
    if (!(sec->sh_flags & SHF_ALLOC) || !(sec->sh_flags & SHF_EXECINSTR)) return false;
    return true;
}

static int simplify_symbols(struct module *mod, const struct load_info *info)
{
    Elf_Shdr *symsec = &info->sechdrs[info->index.sym];
    Elf_Sym *sym = (void *)symsec->sh_addr;
    unsigned long secbase;
    unsigned int i;
    int ret = 0;

    for (i = 1; i < symsec->sh_size / sizeof(Elf_Sym); i++) {
        const char *name = info->strtab + sym[i].st_name;
        switch (sym[i].st_shndx) {
        case SHN_COMMON:
            if (!strncmp(name, "__gnu_lto", 9)) {
                logkd("Please compile with -fno-common\n");
                ret = -ENOEXEC;
            }
            break;
        case SHN_ABS:
            break;
        case SHN_UNDEF: {
            unsigned long addr = symbol_lookup_name(name);
            if (!addr) addr = compact_find_symbol(name);
            if (!addr) {
                logke("unknown symbol: %s\n", name);
                ret = -ENOENT;
                break;
            }
            sym[i].st_value = addr;
            break;
        }
        default:
            secbase = info->sechdrs[sym[i].st_shndx].sh_addr;
            sym[i].st_value += secbase;
            break;
        }
    }
    return ret;
}

static int apply_relocations(struct module *mod, const struct load_info *info)
{
    int rc = 0;
    for (unsigned int i = 1; i < info->hdr->e_shnum; i++) {
        unsigned int infosec = info->sechdrs[i].sh_info;
        if (infosec >= info->hdr->e_shnum) continue;
        if (!(info->sechdrs[infosec].sh_flags & SHF_ALLOC)) continue;
        if (info->sechdrs[i].sh_type == SHT_REL)
            rc = apply_relocate(info->sechdrs, info->strtab, info->index.sym, i, mod);
        else if (info->sechdrs[i].sh_type == SHT_RELA)
            rc = apply_relocate_add(info->sechdrs, info->strtab, info->index.sym, i, mod);
        if (rc < 0) break;
    }
    return rc;
}

static void layout_symtab(struct module *mod, struct load_info *info)
{
    Elf_Shdr *symsect = info->sechdrs + info->index.sym;
    Elf_Shdr *strsect = info->sechdrs + info->index.str;
    const Elf_Sym *src;
    unsigned int i, nsrc, ndst, strtab_size = 0;

    symsect->sh_flags |= SHF_ALLOC;
    symsect->sh_entsize = get_offset(mod, &mod->size, symsect, info->index.sym);
    src = (void *)info->hdr + symsect->sh_offset;
    nsrc = symsect->sh_size / sizeof(*src);
    strtab_size = 1;
    for (ndst = i = 0; i < nsrc; i++) {
        if (i == 0 || is_core_symbol(src + i, info->sechdrs, info->hdr->e_shnum)) {
            strtab_size += strlen(&info->strtab[src[i].st_name]) + 1;
            ndst++;
        }
    }
    info->symoffs = ALIGN(mod->size, symsect->sh_addralign ?: 1);
    info->stroffs = mod->size = info->symoffs + ndst * sizeof(Elf_Sym);
    mod->size += strtab_size;
    strsect->sh_flags |= SHF_ALLOC;
    strsect->sh_entsize = get_offset(mod, &mod->size, strsect, info->index.str);
}

static int rewrite_section_headers(struct load_info *info)
{
    info->sechdrs[0].sh_addr = 0;
    for (int i = 1; i < info->hdr->e_shnum; i++) {
        Elf_Shdr *shdr = &info->sechdrs[i];
        if (shdr->sh_type != SHT_NOBITS && info->len < shdr->sh_offset + shdr->sh_size) return -ENOEXEC;
        shdr->sh_addr = (size_t)info->hdr + shdr->sh_offset;
    }
    return 0;
}

static int move_module(struct module *mod, struct load_info *info)
{
    logki("alloc module size: %llx\n", mod->size);
    mod->start = kp_malloc_exec(mod->size);
    if (!mod->start) return -ENOMEM;
    memset(mod->start, 0, mod->size);

    logkd("final section addresses:\n");
    for (int i = 1; i < info->hdr->e_shnum; i++) {
        void *dest;
        Elf_Shdr *shdr = &info->sechdrs[i];
        if (!(shdr->sh_flags & SHF_ALLOC)) continue;
        dest = mod->start + shdr->sh_entsize;
        const char *sname = info->secstrings + shdr->sh_name;
        logkd("    %s %llx %llx\n", sname, dest, shdr->sh_size);
        if (shdr->sh_type != SHT_NOBITS) memcpy(dest, (void *)shdr->sh_addr, shdr->sh_size);
        shdr->sh_addr = (unsigned long)dest;

        if (!mod->init && !strcmp(".kpm.init", sname)) mod->init = (mod_initcall_t *)dest;
        if (!strcmp(".kpm.ctl0", sname)) mod->ctl0 = (mod_ctl0call_t *)dest;
        if (!strcmp(".kpm.ctl1", sname)) mod->ctl1 = (mod_ctl1call_t *)dest;
        if (!mod->exit && !strcmp(".kpm.exit", sname)) mod->exit = (mod_exitcall_t *)dest;
        if (!mod->event && !strcmp(".kpm.event", sname)) mod->event = (mod_eventcall_t *)dest;
        if (!mod->info.base && !strcmp(".kpm.info", sname)) mod->info.base = (const char *)dest;
    }

    if (info->info.base) {
        mod->info.name = info->info.name - info->info.base + mod->info.base;
        mod->info.version = info->info.version - info->info.base + mod->info.base;
        if (info->info.license) mod->info.license = info->info.license - info->info.base + mod->info.base;
        if (info->info.author) mod->info.author = info->info.author - info->info.base + mod->info.base;
        if (info->info.description) mod->info.description = info->info.description - info->info.base + mod->info.base;
    } else {
        char *buf = vmalloc(320);
        if (!buf) return -ENOMEM;
        memset(buf, 0, 320);
        strncpy(buf, info->info.name ?: "unknown", 63);
        strncpy(buf + 64, info->info.version ?: "0.0.0", 31);
        strncpy(buf + 96, info->info.license ?: "unknown", 31);
        strncpy(buf + 128, info->info.author ?: "unknown", 63);
        strncpy(buf + 192, info->info.description ?: "loaded from object", 127);
        mod->info_storage = buf;
        mod->info.name = buf;
        mod->info.version = buf + 64;
        mod->info.license = buf + 96;
        mod->info.author = buf + 128;
        mod->info.description = buf + 192;
    }
    return 0;
}

static int setup_load_info(struct load_info *info)
{
    int rc = 0;
    info->sechdrs = (void *)info->hdr + info->hdr->e_shoff;
    info->secstrings = (void *)info->hdr + info->sechdrs[info->hdr->e_shstrndx].sh_offset;

    if ((rc = rewrite_section_headers(info))) {
        logke("rewrite section error\n");
        return rc;
    }

    int has_kpm_init = find_sec(info, ".kpm.init");
    if (!has_kpm_init) {
        if (find_sec(info, ".init.text") || find_sec(info, ".exit.text"))
            logke("legacy .ko callback inference is unsupported; explicit .kpm.init is required\n");
        else
            logke("no .kpm.init section\n");
        return -ENOEXEC;
    }

    info->index.info = find_sec(info, ".kpm.info");
    if (!info->index.info) {
        info->info.name = "unknown.o";
        info->info.version = "0.0.0";
        info->info.license = "unknown";
        info->info.author = "unknown";
        info->info.description = "loaded from object";
        goto find_symtab;
    }
    info->info.base = get_sh_base(info, ".kpm.info");
    info->info.size = get_sh_size(info, ".kpm.info");

    const char *name = get_modinfo(info, "name");
    if (!name) return -ENOEXEC;
    info->info.name = name;
    const char *version = get_modinfo(info, "version");
    if (!version) return -ENOEXEC;
    info->info.version = version;
    info->info.license = get_modinfo(info, "license");
    info->info.author = get_modinfo(info, "author");
    info->info.description = get_modinfo(info, "description");

find_symtab:
    for (int i = 1; i < info->hdr->e_shnum; i++) {
        if (info->sechdrs[i].sh_type == SHT_SYMTAB) {
            info->index.sym = i;
            info->index.str = info->sechdrs[i].sh_link;
            info->strtab = (char *)info->hdr + info->sechdrs[info->index.str].sh_offset;
            break;
        }
    }
    if (info->index.sym == 0) return -ENOEXEC;
    return 0;
}

static int elf_header_check(struct load_info *info)
{
    if (info->len <= sizeof(*(info->hdr))) return -ENOEXEC;
    if (memcmp(info->hdr->e_ident, ELFMAG, SELFMAG) || info->hdr->e_type != ET_REL || !elf_check_arch(info->hdr) ||
        info->hdr->e_shentsize != sizeof(Elf_Shdr))
        return -ENOEXEC;
    if (info->hdr->e_shoff >= info->len || (info->hdr->e_shnum * sizeof(Elf_Shdr) > info->len - info->hdr->e_shoff))
        return -ENOEXEC;
    return 0;
}

static bool callback_slot_in_module(const struct module *mod, const void *slot)
{
    unsigned long start = (unsigned long)mod->start;
    unsigned long end = start + mod->size;
    unsigned long addr = (unsigned long)slot;
    if (mod->size < sizeof(void *)) return false;
    return slot && addr >= start && addr <= end - sizeof(void *);
}

static bool callback_target_in_text(const struct module *mod, unsigned long target)
{
    unsigned long start = (unsigned long)mod->start;
    unsigned long text_end = start + mod->text_size;
    return target && target >= start && target < text_end;
}

static int validate_module_callbacks(struct module *mod)
{
    if (!callback_slot_in_module(mod, mod->init) || !*mod->init ||
        !callback_target_in_text(mod, (unsigned long)*mod->init))
        return -ENOEXEC;
    if (mod->exit && (!callback_slot_in_module(mod, mod->exit) || !*mod->exit ||
                      !callback_target_in_text(mod, (unsigned long)*mod->exit)))
        return -ENOEXEC;
    return 0;
}

struct module modules = { 0 };
static spinlock_t module_lock;

static const char *module_state_name(enum module_state state)
{
    switch (state) {
    case MODULE_STATE_LOADING: return "loading";
    case MODULE_STATE_LIVE: return "live";
    case MODULE_STATE_QUIESCING: return "quiescing";
    case MODULE_STATE_UNLOADING: return "unloading";
    case MODULE_STATE_DEAD: return "dead";
    default: return "unknown";
    }
}

static struct module *find_module_any_locked(const char *name)
{
    struct module *pos;
    list_for_each_entry(pos, &modules.list, list) {
        if (!strcmp(name, pos->info.name)) return pos;
    }
    return 0;
}

static struct module *get_live_module(const char *name)
{
    struct module *mod = 0;
    if (!name) return 0;
    spin_lock(&module_lock);
    mod = find_module_any_locked(name);
    if (!mod || mod->state != MODULE_STATE_LIVE) {
        mod = 0;
    } else {
        mod->active_refs++;
    }
    spin_unlock(&module_lock);
    return mod;
}

struct module *find_module(const char *name)
{
    return get_live_module(name);
}

void put_module(struct module *mod)
{
    if (!mod) return;
    spin_lock(&module_lock);
    if (!mod->active_refs) {
        logkfe("module ref underflow: %s\n", mod->info.name ?: "unknown");
    } else {
        mod->active_refs--;
    }
    spin_unlock(&module_lock);
}

static int reserve_loading_module(struct module *mod)
{
    int rc = 0;
    spin_lock(&module_lock);
    if (find_module_any_locked(mod->info.name)) {
        rc = -EEXIST;
    } else {
        mod->state = MODULE_STATE_LOADING;
        mod->active_refs = 0;
        list_add_tail(&mod->list, &modules.list);
    }
    spin_unlock(&module_lock);
    return rc;
}

static void remove_reserved_module(struct module *mod)
{
    spin_lock(&module_lock);
    if (mod->state != MODULE_STATE_DEAD) {
        list_del(&mod->list);
        mod->state = MODULE_STATE_DEAD;
    }
    spin_unlock(&module_lock);
}

static void free_module_storage(struct module *mod)
{
    if (!mod) return;
    if (mod->args) kvfree(mod->args);
    if (mod->ctl_args) kvfree(mod->ctl_args);
    if (mod->info_storage) kvfree(mod->info_storage);
    if (mod->start) kp_free_exec(mod->start);
    kvfree(mod);
}

long load_module(const void *data, int len, const char *args, const char *event, void *__user reserved)
{
    struct load_info load_info = { .len = len, .hdr = data };
    struct load_info *info = &load_info;
    struct module *mod = 0;
    int reserved_in_list = 0;
    long rc = 0;

    if ((rc = elf_header_check(info))) goto out;
    if ((rc = setup_load_info(info))) goto out;
    if (kpm_safety_check_blacklist(info->info.name)) {
        rc = -EACCES;
        goto out;
    }
    if ((rc = kpm_safety_validate(data, len))) goto out;

    mod = (struct module *)vmalloc(sizeof(*mod));
    if (!mod) return -ENOMEM;
    memset(mod, 0, sizeof(*mod));

    if (args) {
        mod->args = vmalloc(strlen(args) + 1);
        if (!mod->args) {
            rc = -ENOMEM;
            goto free;
        }
        strcpy(mod->args, args);
    }

    layout_sections(mod, info);
    layout_symtab(mod, info);
    if ((rc = move_module(mod, info))) goto free;
    if ((rc = simplify_symbols(mod, info))) goto free;
    if ((rc = apply_relocations(mod, info))) goto free;
    if ((rc = validate_module_callbacks(mod))) goto free;
    flush_icache_all();

    /* Reserve the name before running module code. This closes the two-load
     * race without exposing a half-initialized module to readers. */
    if ((rc = reserve_loading_module(mod))) goto free;
    reserved_in_list = 1;

    kpm_safety_mark_loading(info->info.name);
    rc = (*mod->init)(mod->args, event, reserved);
    if (!rc) {
        spin_lock(&module_lock);
        if (mod->state == MODULE_STATE_LOADING) mod->state = MODULE_STATE_LIVE;
        spin_unlock(&module_lock);
        logkfi("[%s] loaded\n", mod->info.name);
        return 0;
    }

    if (mod->exit && *mod->exit) {
        long exit_rc = (*mod->exit)(reserved);
        logkfi("[%s] init-failure cleanup exit rc=%d\n", mod->info.name, exit_rc);
    }

free:
    if (reserved_in_list) remove_reserved_module(mod);
    free_module_storage(mod);
out:
    return rc;
}

long unload_module(const char *name, void *__user reserved)
{
    struct module *mod;
    long rc = 0;

    if (!name) return -EINVAL;

    spin_lock(&module_lock);
    mod = find_module_any_locked(name);
    if (!mod) {
        spin_unlock(&module_lock);
        return -ENOENT;
    }

    if (mod->state == MODULE_STATE_LOADING || mod->state == MODULE_STATE_UNLOADING || mod->state == MODULE_STATE_DEAD) {
        spin_unlock(&module_lock);
        return -EBUSY;
    }
    if (mod->state == MODULE_STATE_LIVE) mod->state = MODULE_STATE_QUIESCING;
    if (mod->active_refs) {
        unsigned int refs = mod->active_refs;
        spin_unlock(&module_lock);
        logkfi("[%s] unload deferred, active_refs=%u\n", name, refs);
        return -EBUSY;
    }
    mod->state = MODULE_STATE_UNLOADING;
    spin_unlock(&module_lock);

    if (mod->exit && *mod->exit) rc = (*mod->exit)(reserved);
    if (rc) {
        spin_lock(&module_lock);
        if (mod->state == MODULE_STATE_UNLOADING) mod->state = MODULE_STATE_LIVE;
        spin_unlock(&module_lock);
        logkfe("[%s] exit failed rc=%d; module retained\n", name, rc);
        return rc;
    }

    spin_lock(&module_lock);
    if (mod->active_refs) {
        mod->state = MODULE_STATE_QUIESCING;
        spin_unlock(&module_lock);
        return -EBUSY;
    }
    list_del(&mod->list);
    mod->state = MODULE_STATE_DEAD;
    spin_unlock(&module_lock);

    free_module_storage(mod);
    logkfi("[%s] unloaded\n", name);
    return 0;
}

long load_module_path(const char *path, const char *args, void *__user reserved)
{
    long rc = 0;
    if (!path) return -EINVAL;

    struct file *filp = filp_open(path, O_RDONLY, 0);
    if (unlikely(!filp || IS_ERR(filp))) return PTR_ERR(filp);
    loff_t len = vfs_llseek(filp, 0, SEEK_END);
    if (len <= 0 || len > SZ_128M) {
        rc = -E2BIG;
        goto close;
    }
    vfs_llseek(filp, 0, SEEK_SET);
    void *data = vmalloc(len);
    if (!data) {
        rc = -ENOMEM;
        goto close;
    }
    memset(data, 0, len);
    loff_t pos = 0;
    rc = kernel_read(filp, data, len, &pos);
    if (rc < 0 || pos != len) {
        rc = -EIO;
        goto free;
    }
    rc = load_module(data, len, args, "load-file", reserved);
free:
    kvfree(data);
close:
    filp_close(filp, 0);
    return rc;
}

long module_control0(const char *name, const char *ctl_args, char *__user out_msg, int outlen)
{
    struct module *mod;
    char *local_args;
    long rc;
    int args_len;

    if (!name || !ctl_args) return -EINVAL;
    args_len = strlen(ctl_args);
    if (args_len <= 0) return -EINVAL;

    mod = get_live_module(name);
    if (!mod) return -ENOENT;
    if (!mod->ctl0 || !*mod->ctl0) {
        put_module(mod);
        return -ENOSYS;
    }

    local_args = vmalloc(args_len + 1);
    if (!local_args) {
        put_module(mod);
        return -ENOMEM;
    }
    strcpy(local_args, ctl_args);
    rc = (*mod->ctl0)(local_args, out_msg, outlen);
    kvfree(local_args);
    put_module(mod);
    return rc;
}

long module_control1(const char *name, void *a1, void *a2, void *a3)
{
    struct module *mod = get_live_module(name);
    long rc;
    if (!mod) return -ENOENT;
    if (!mod->ctl1 || !*mod->ctl1) {
        put_module(mod);
        return -ENOSYS;
    }
    rc = (*mod->ctl1)(a1, a2, a3);
    put_module(mod);
    return rc;
}

int get_module_nums()
{
    struct module *pos;
    int n = 0;
    spin_lock(&module_lock);
    list_for_each_entry(pos, &modules.list, list) {
        if (pos->state == MODULE_STATE_LIVE) n++;
    }
    spin_unlock(&module_lock);
    return n;
}

int list_modules(char *out_names, int size)
{
    struct module *pos;
    int rc = 0;
    int off = 0;

    if (!out_names || size <= 0) return -EINVAL;
    out_names[0] = '\0';

    spin_lock(&module_lock);
    list_for_each_entry(pos, &modules.list, list) {
        int remaining;
        int written;
        if (pos->state != MODULE_STATE_LIVE) continue;
        remaining = size - off;
        if (remaining <= 1) {
            rc = -ENOBUFS;
            goto out;
        }
        written = snprintf(out_names + off, remaining, "%s\n", pos->info.name);
        if (written < 0) {
            rc = written;
            goto out;
        }
        if (written >= remaining) {
            rc = -ENOBUFS;
            goto out;
        }
        off += written;
    }
    if (off > 0) out_names[off - 1] = '\0';
    rc = off;
out:
    spin_unlock(&module_lock);
    return rc;
}

int get_module_info(const char *name, char *out_info, int size)
{
    struct module *mod;
    int rc;

    if (!name || !out_info || size <= 0) return -EINVAL;

    spin_lock(&module_lock);
    mod = find_module_any_locked(name);
    if (!mod) {
        spin_unlock(&module_lock);
        return -ENOENT;
    }

    rc = snprintf(out_info, size,
                  "name=%s\nversion=%s\nlicense=%s\nauthor=%s\ndescription=%s\nargs=%s\nstate=%s\nactive_refs=%u\n",
                  mod->info.name ?: "unknown",
                  mod->info.version ?: "0.0.0",
                  mod->info.license ?: "unknown",
                  mod->info.author ?: "unknown",
                  mod->info.description ?: "",
                  mod->args ?: "",
                  module_state_name(mod->state),
                  mod->active_refs);
    spin_unlock(&module_lock);

    if (rc < 0) return rc;
    if (rc >= size) {
        out_info[size - 1] = '\0';
        return -ENOBUFS;
    }
    if (rc > 0 && out_info[rc - 1] == '\n') out_info[rc - 1] = '\0';
    return rc;
}

void module_init()
{
    INIT_LIST_HEAD(&modules.list);
    spin_lock_init(&module_lock);

    kpm_safety_init();
    kpm_safety_early_count();
    if (kpm_safety_check_boot_count()) {
        extern int kp_safe_mode;
        kp_safe_mode = 1;
        log_boot("kpm_safety: safe mode activated due to boot counter\n");
    }

    compact_init();
    umount_init();
    selinux_hide_init();
    proc_hide_init();
}

int module_dispatch_event(enum kpm_event event, const char *source_name, const char *args)
{
    struct module **targets = 0;
    struct module *pos;
    struct kpm_event_data data = {
        .event = event,
        .source_name = source_name,
        .args = args,
        .reserved = NULL,
    };
    int capacity = 0;
    int count = 0;
    int delivered = 0;

    if (event <= KPM_EVENT_NONE || event >= KPM_EVENT_MAX) return -EINVAL;

    /* Snapshot retained LIVE modules. Loads racing after the first pass are
     * intentionally deferred to the next event; unload cannot free retained
     * targets until each reference is released. */
    spin_lock(&module_lock);
    list_for_each_entry(pos, &modules.list, list) {
        if (pos->state == MODULE_STATE_LIVE) capacity++;
    }
    spin_unlock(&module_lock);

    if (!capacity) return 0;
    targets = vmalloc(capacity * sizeof(*targets));
    if (!targets) return -ENOMEM;

    spin_lock(&module_lock);
    list_for_each_entry(pos, &modules.list, list) {
        if (count >= capacity) break;
        if (pos->state != MODULE_STATE_LIVE) continue;
        pos->active_refs++;
        targets[count++] = pos;
    }
    spin_unlock(&module_lock);

    for (int i = 0; i < count; i++) {
        struct module *mod = targets[i];
        if (mod->event && *mod->event) {
            long rc = (*mod->event)(&data);
            logkfi("event %d -> module %s: rc=%ld\n", event, mod->info.name, rc);
            delivered++;
        }
        put_module(mod);
    }

    kvfree(targets);
    return delivered;
}
