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
#include <linux/rcupdate.h>
#include <linux/rculist.h>

#include "module.h"
#include "relo.h"
#include <compact.h>
#include <selinux_hide.h>
#include <proc_hide.h>
#include <kpm_safety.h>
#include <accctl.h>

#define SZ_128M 0x08000000
#define MAX_KPM_SECTIONS 4096

#define ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))
#define ALIGN(x, a) ALIGN_MASK(x, (typeof(x))(a)-1)

#define align(X) ALIGN(X, page_size)

#define elf_check_arch(x) ((x)->e_machine == EM_AARCH64)

#define ARCH_SHF_SMALL 0

static inline bool strstarts(const char *str, const char *prefix)
{
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

static bool file_range_valid(const struct load_info *info, unsigned long offset, unsigned long size)
{
    if (!info || info->len < 0) return false;
    if (offset > (unsigned long)info->len) return false;
    return size <= (unsigned long)info->len - offset;
}

static bool string_offset_valid(const char *table, unsigned long table_size, unsigned long offset)
{
    if (!table || offset >= table_size) return false;
    return memchr(table + offset, '\0', table_size - offset) != NULL;
}

static bool valid_alignment(unsigned long alignment)
{
    if (!alignment) return true;
    if (alignment > SZ_128M) return false;
    return (alignment & (alignment - 1)) == 0;
}

static int validate_section_table(struct load_info *info)
{
    if (!info || !info->hdr || !info->sechdrs) return -ENOEXEC;
    if (!info->hdr->e_shnum || info->hdr->e_shnum > MAX_KPM_SECTIONS) return -ENOEXEC;
    if (info->hdr->e_shstrndx >= info->hdr->e_shnum) return -ENOEXEC;

    Elf_Shdr *shstr = &info->sechdrs[info->hdr->e_shstrndx];
    if (shstr->sh_type != SHT_STRTAB || !shstr->sh_size ||
        !file_range_valid(info, shstr->sh_offset, shstr->sh_size)) {
        return -ENOEXEC;
    }
    const char *section_names = (const char *)info->hdr + shstr->sh_offset;

    unsigned long alloc_budget = 0;
    for (int i = 0; i < info->hdr->e_shnum; i++) {
        Elf_Shdr *shdr = &info->sechdrs[i];
        if (shdr->sh_type != SHT_NOBITS && !file_range_valid(info, shdr->sh_offset, shdr->sh_size)) {
            return -ENOEXEC;
        }
        if (!valid_alignment(shdr->sh_addralign)) return -ENOEXEC;
        if (!string_offset_valid(section_names, shstr->sh_size, shdr->sh_name)) return -ENOEXEC;

        if (shdr->sh_flags & SHF_ALLOC) {
            unsigned long alignment = shdr->sh_addralign ?: 1;
            unsigned long padding = alignment - 1;
            if (padding > SZ_128M - alloc_budget) return -E2BIG;
            alloc_budget += padding;
            if (shdr->sh_size > SZ_128M - alloc_budget) return -E2BIG;
            alloc_budget += shdr->sh_size;
        }

        if (shdr->sh_type == SHT_SYMTAB) {
            if (shdr->sh_entsize != sizeof(Elf_Sym) || shdr->sh_size % sizeof(Elf_Sym)) return -ENOEXEC;
            if (shdr->sh_link >= info->hdr->e_shnum) return -ENOEXEC;
            Elf_Shdr *strtab = &info->sechdrs[shdr->sh_link];
            if (strtab->sh_type != SHT_STRTAB || !strtab->sh_size ||
                !file_range_valid(info, strtab->sh_offset, strtab->sh_size)) {
                return -ENOEXEC;
            }
        } else if (shdr->sh_type == SHT_REL || shdr->sh_type == SHT_RELA) {
            if (shdr->sh_link >= info->hdr->e_shnum || shdr->sh_info >= info->hdr->e_shnum) return -ENOEXEC;
            if (info->sechdrs[shdr->sh_link].sh_type != SHT_SYMTAB) return -ENOEXEC;
            unsigned long expected = shdr->sh_type == SHT_RELA ? sizeof(Elf_Rela) : sizeof(Elf_Rel);
            if (shdr->sh_entsize != expected || shdr->sh_size % expected) return -ENOEXEC;
        }
    }
    return 0;
}

static int validate_symbol_table(struct load_info *info)
{
    if (!info->index.sym || info->index.sym >= info->hdr->e_shnum ||
        !info->index.str || info->index.str >= info->hdr->e_shnum) {
        return -ENOEXEC;
    }

    Elf_Shdr *symsec = &info->sechdrs[info->index.sym];
    Elf_Shdr *strsec = &info->sechdrs[info->index.str];
    Elf_Sym *symbols = (void *)info->hdr + symsec->sh_offset;
    const char *strtab = (const char *)info->hdr + strsec->sh_offset;
    unsigned long count = symsec->sh_size / sizeof(Elf_Sym);

    for (unsigned long i = 0; i < count; i++) {
        if (!string_offset_valid(strtab, strsec->sh_size, symbols[i].st_name)) return -ENOEXEC;
        unsigned int section = symbols[i].st_shndx;
        if (section != SHN_UNDEF && section != SHN_ABS && section != SHN_COMMON &&
            section >= info->hdr->e_shnum) {
            return -ENOEXEC;
        }
    }
    return 0;
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

/* Update size with this section: return offset. */
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
    void *addr = (void *)info->hdr + infosec->sh_offset;
    return addr;
}

static unsigned long get_sh_size(struct load_info *info, const char *secname)
{
    int idx = find_sec(info, secname);
    if (!idx) return 0;
    Elf_Shdr *infosec = &info->sechdrs[idx];
    return infosec->sh_entsize;
}

static void layout_sections(struct module *mod, struct load_info *info)
{
    static unsigned long const masks[][2] = {
        { SHF_EXECINSTR | SHF_ALLOC, ARCH_SHF_SMALL },
        { SHF_ALLOC, SHF_WRITE | ARCH_SHF_SMALL },
        { SHF_WRITE | SHF_ALLOC, ARCH_SHF_SMALL },
        { ARCH_SHF_SMALL | SHF_ALLOC, 0 }
    };

    for (int i = 0; i < info->hdr->e_shnum; i++)
        info->sechdrs[i].sh_entsize = ~0UL;

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
    unsigned int i;
    for (i = 1; i < info->hdr->e_shnum; i++) {
        unsigned int infosec = info->sechdrs[i].sh_info;
        if (infosec >= info->hdr->e_shnum) continue;
        if (!(info->sechdrs[infosec].sh_flags & SHF_ALLOC)) continue;
        if (info->sechdrs[i].sh_type == SHT_REL) {
            rc = apply_relocate(info->sechdrs, info->strtab, info->index.sym, i, mod);
        } else if (info->sechdrs[i].sh_type == SHT_RELA) {
            rc = apply_relocate_add(info->sechdrs, info->strtab, info->index.sym, i, mod);
        }
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
        if (shdr->sh_type != SHT_NOBITS && !file_range_valid(info, shdr->sh_offset, shdr->sh_size)) {
            return -ENOEXEC;
        }
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
        if (buf) {
            memset(buf, 0, 320);
            strncpy(buf, info->info.name ?: "unknown", 63);
            strncpy(buf + 64, info->info.version ?: "0.0.0", 31);
            strncpy(buf + 96, info->info.license ?: "unknown", 31);
            strncpy(buf + 128, info->info.author ?: "unknown", 63);
            strncpy(buf + 192, info->info.description ?: "loaded without .kpm.info", 127);
            mod->info.name = buf;
            mod->info.version = buf + 64;
            mod->info.license = buf + 96;
            mod->info.author = buf + 128;
            mod->info.description = buf + 192;
        } else {
            mod->info.name = "unknown";
            mod->info.version = "0.0.0";
            mod->info.license = "unknown";
            mod->info.author = "unknown";
            mod->info.description = "oom";
        }
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

    int init_idx = find_sec(info, ".kpm.init");
    if (!init_idx || info->sechdrs[init_idx].sh_size < sizeof(void *)) {
        logke("KPM requires a valid .kpm.init callback slot\n");
        return -ENOEXEC;
    }
    int exit_idx = find_sec(info, ".kpm.exit");
    if (exit_idx && info->sechdrs[exit_idx].sh_size < sizeof(void *)) {
        logke("invalid .kpm.exit callback slot\n");
        return -ENOEXEC;
    }

    /* Ordinary .ko/.o .init.text section starts are not a KPM callback ABI.
     * Only explicit KPM callback sections are accepted. */
    info->index.info = find_sec(info, ".kpm.info");
    if (!info->index.info) {
        info->info.name = "unknown.o";
        info->info.version = "0.0.0";
        info->info.license = "unknown";
        info->info.author = "unknown";
        info->info.description = "loaded without .kpm.info";
        goto find_symtab;
    }
    info->info.base = get_sh_base(info, ".kpm.info");
    info->info.size = get_sh_size(info, ".kpm.info");

    const char *name = get_modinfo(info, "name");
    if (!name) {
        logke("module name not found\n");
        return -ENOEXEC;
    }
    info->info.name = name;
    logkd("loading module: \n");
    logkd("    name: %s\n", name);

    const char *version = get_modinfo(info, "version");
    if (!version) {
        logkd("module version not found\n");
        return -ENOEXEC;
    }
    info->info.version = version;
    logkd("    version: %s\n", version);

    info->info.license = get_modinfo(info, "license");
    logkd("    license: %s\n", info->info.license);
    info->info.author = get_modinfo(info, "author");
    logkd("    author: %s\n", info->info.author);
    info->info.description = get_modinfo(info, "description");
    logkd("    description: %s\n", info->info.description);

find_symtab:
    for (int i = 1; i < info->hdr->e_shnum; i++) {
        if (info->sechdrs[i].sh_type == SHT_SYMTAB) {
            info->index.sym = i;
            info->index.str = info->sechdrs[i].sh_link;
            info->strtab = (char *)info->hdr + info->sechdrs[info->index.str].sh_offset;
            break;
        }
    }

    if (info->index.sym == 0) {
        logkd("module has no symbols (stripped?)\n");
        return -ENOEXEC;
    }
    return validate_symbol_table(info);
}

static int elf_header_check(struct load_info *info)
{
    if (!info || !info->hdr || info->len <= (int)sizeof(*(info->hdr)) || info->len > SZ_128M) return -ENOEXEC;
    if (memcmp(info->hdr->e_ident, ELFMAG, SELFMAG) || info->hdr->e_type != ET_REL || !elf_check_arch(info->hdr) ||
        info->hdr->e_shentsize != sizeof(Elf_Shdr)) {
        return -ENOEXEC;
    }
    if (!info->hdr->e_shnum || info->hdr->e_shnum > MAX_KPM_SECTIONS) return -ENOEXEC;
    if (info->hdr->e_shoff >= (unsigned long)info->len ||
        info->hdr->e_shnum * sizeof(Elf_Shdr) > (unsigned long)info->len - info->hdr->e_shoff) {
        return -ENOEXEC;
    }

    info->sechdrs = (void *)info->hdr + info->hdr->e_shoff;
    return validate_section_table(info);
}

static bool module_slot_valid(const struct module *mod, const void *slot)
{
    uintptr_t start = (uintptr_t)mod->start;
    uintptr_t addr = (uintptr_t)slot;
    if (!slot || addr < start || mod->size < sizeof(void *)) return false;
    return addr - start <= mod->size - sizeof(void *);
}

static bool module_callback_valid(const struct module *mod, uintptr_t callback)
{
    uintptr_t start = (uintptr_t)mod->start;
    if (!callback || callback < start) return false;
    return callback - start < mod->text_size;
}

static int validate_module_callbacks(const struct module *mod)
{
    if (!mod->init || !module_slot_valid(mod, mod->init) || !*mod->init ||
        !module_callback_valid(mod, (uintptr_t)*mod->init)) {
        logke("invalid or missing KPM init callback\n");
        return -ENOEXEC;
    }
    if (mod->exit && (!module_slot_valid(mod, mod->exit) || !*mod->exit ||
                      !module_callback_valid(mod, (uintptr_t)*mod->exit))) {
        logke("invalid KPM exit callback\n");
        return -ENOEXEC;
    }
    if (mod->ctl0 && (!module_slot_valid(mod, mod->ctl0) || !*mod->ctl0 ||
                      !module_callback_valid(mod, (uintptr_t)*mod->ctl0))) return -ENOEXEC;
    if (mod->ctl1 && (!module_slot_valid(mod, mod->ctl1) || !*mod->ctl1 ||
                      !module_callback_valid(mod, (uintptr_t)*mod->ctl1))) return -ENOEXEC;
    if (mod->event && (!module_slot_valid(mod, mod->event) || !*mod->event ||
                       !module_callback_valid(mod, (uintptr_t)*mod->event))) return -ENOEXEC;
    return 0;
}

struct module modules = { 0 };
static spinlock_t module_lock;

struct module *find_module(const char *name)
{
    struct module *pos;
    list_for_each_entry_rcu(pos, &modules.list, list) {
        if (!strcmp(name, pos->info.name)) return pos;
    }
    return 0;
}

long load_module(const void *data, int len, const char *args, const char *event, void *__user reserved)
{
    struct load_info load_info = { .len = len, .hdr = data };
    struct load_info *info = &load_info;
    long rc = 0;

    if ((rc = elf_header_check(info))) goto out;
    if ((rc = setup_load_info(info))) goto out;

    if (kpm_safety_check_blacklist(info->info.name)) {
        logkfe("kpm_safety: skipping blacklisted module %s\n", info->info.name);
        rc = -EACCES;
        goto out;
    }
    if ((rc = kpm_safety_validate(data, len))) {
        logkfe("kpm_safety: validation failed for %s\n", info->info.name);
        goto out;
    }

    rcu_read_lock();
    if (find_module(info->info.name)) rc = -EEXIST;
    rcu_read_unlock();
    if (rc) goto out;

    struct module *mod = (struct module *)vmalloc(sizeof(struct module));
    if (!mod) return -ENOMEM;
    memset(mod, 0, sizeof(struct module));

    if (args) {
        mod->args = vmalloc(strlen(args) + 1);
        if (!mod->args) {
            rc = -ENOMEM;
            goto free1;
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
    kpm_safety_mark_loading(info->info.name);

    rc = (*mod->init)(mod->args, event, reserved);
    if (!rc) {
        unsigned long flags;
        spin_lock_irqsave(&module_lock, flags);
        if (find_module(info->info.name)) {
            spin_unlock_irqrestore(&module_lock, flags);
            rc = -EEXIST;
            if (mod->exit && *mod->exit) (*mod->exit)(reserved);
            goto free;
        }
        list_add_tail_rcu(&mod->list, &modules.list);
        spin_unlock_irqrestore(&module_lock, flags);
        logkfi("[%s] succeed with [%s] \n", mod->info.name, args);
        goto out;
    }

    logkfi("[%s] failed with [%s] error: %d, try exit ...\n", mod->info.name, args, rc);
    if (mod->exit && *mod->exit) (*mod->exit)(reserved);

free:
    if (mod->args) kvfree(mod->args);
    kp_free_exec(mod->start);
free1:
    kvfree(mod);
out:
    return rc;
}

long unload_module(const char *name, void *__user reserved)
{
    if (!name) return -EINVAL;
    logkfe("name: %s\n", name);

    unsigned long flags;
    long rc = 0;
    struct module *mod = 0;

    spin_lock_irqsave(&module_lock, flags);
    mod = find_module(name);
    if (!mod) {
        spin_unlock_irqrestore(&module_lock, flags);
        return -ENOENT;
    }
    list_del_rcu(&mod->list);
    spin_unlock_irqrestore(&module_lock, flags);

    /* Every control/event/info reader executes under rcu_read_lock(). Wait for
     * those callbacks to finish before invoking exit or reclaiming code/data. */
    synchronize_rcu();

    if (mod->exit && *mod->exit) rc = (*mod->exit)(reserved);
    if (mod->args) kvfree(mod->args);
    if (mod->ctl_args) kvfree(mod->ctl_args);
    kp_free_exec(mod->start);
    kvfree(mod);

    logkfi("name: %s, rc: %d\n", name, rc);
    return rc;
}

long load_module_path(const char *path, const char *args, void *__user reserved)
{
    long rc = 0;
    logkfd("%s\n", path);
    if (!path) return -EINVAL;

    struct file *filp = filp_open(path, O_RDONLY, 0);
    if (unlikely(!filp || IS_ERR(filp))) {
        logkfe("open module: %s error\n", path);
        rc = PTR_ERR(filp);
        goto out;
    }
    loff_t len = vfs_llseek(filp, 0, SEEK_END);
    logkfd("module size: %llx\n", len);
    if (len <= 0 || len > SZ_128M) {
        rc = -E2BIG;
        filp_close(filp, 0);
        goto out;
    }
    vfs_llseek(filp, 0, SEEK_SET);

    void *data = vmalloc(len);
    if (!data) {
        rc = -ENOMEM;
        filp_close(filp, 0);
        goto out;
    }
    memset(data, 0, len);

    loff_t pos = 0;
    kernel_read(filp, data, len, &pos);
    filp_close(filp, 0);

    if (pos != len) {
        logkfe("read module: %s error\n", path);
        rc = -EIO;
        goto free;
    }

    rc = load_module(data, len, args, "load-file", reserved);
free:
    kvfree(data);
out:
    return rc;
}

long module_control0(const char *name, const char *ctl_args, char *__user out_msg, int outlen)
{
    if (!name || !ctl_args) return -EINVAL;
    int args_len = strlen(ctl_args);
    if (args_len <= 0) return -EINVAL;

    logkfi("name %s, args: %s\n", name, ctl_args);
    char *local_args = vmalloc(args_len + 1);
    if (!local_args) return -ENOMEM;
    strcpy(local_args, ctl_args);

    long rc = 0;
    rcu_read_lock();
    struct module *mod = find_module(name);
    if (!mod) {
        rc = -ENOENT;
        goto out;
    }
    if (!mod->ctl0 || !*mod->ctl0) {
        rc = -ENOSYS;
        goto out;
    }

    rc = (*mod->ctl0)(local_args, out_msg, outlen);
    logkfi("name: %s, rc: %d\n", name, rc);
out:
    rcu_read_unlock();
    kvfree(local_args);
    return rc;
}

long module_control1(const char *name, void *a1, void *a2, void *a3)
{
    logkfi("name %s, a1: %llx, a2: %llx, a3: %llx\n", name, a1, a2, a3);
    long rc = 0;
    rcu_read_lock();

    struct module *mod = find_module(name);
    if (!mod) {
        rc = -ENOENT;
        goto out;
    }
    if (!mod->ctl1 || !*mod->ctl1) {
        rc = -ENOSYS;
        goto out;
    }

    rc = (*mod->ctl1)(a1, a2, a3);
    logkfi("name: %s, rc: %d\n", name, rc);
out:
    rcu_read_unlock();
    return rc;
}

int get_module_nums()
{
    rcu_read_lock();
    struct module *pos;
    int n = 0;
    list_for_each_entry_rcu(pos, &modules.list, list) n++;
    rcu_read_unlock();
    logkfd("%d\n", n);
    return n;
}

int list_modules(char *out_names, int size)
{
    if (!out_names || size <= 0) return -EINVAL;
    out_names[0] = '\0';

    int rc = 0;
    int off = 0;
    rcu_read_lock();
    struct module *pos;
    list_for_each_entry_rcu(pos, &modules.list, list) {
        int remaining = size - off;
        if (remaining <= 1) {
            rc = -ENOBUFS;
            goto out;
        }
        int written = snprintf(out_names + off, remaining, "%s\n", pos->info.name);
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
    rcu_read_unlock();
    return rc;
}

int get_module_info(const char *name, char *out_info, int size)
{
    if (!name || !out_info || size <= 0) return -EINVAL;

    int rc = 0;
    rcu_read_lock();
    struct module *mod = find_module(name);
    if (!mod) {
        rc = -ENOENT;
        goto out;
    }

    int sz = snprintf(out_info, size,
                      "name=%s\n"
                      "version=%s\n"
                      "license=%s\n"
                      "author=%s\n"
                      "description=%s\n"
                      "args=%s\n",
                      mod->info.name ?: "unknown",
                      mod->info.version ?: "0.0.0",
                      mod->info.license ?: "unknown",
                      mod->info.author ?: "unknown",
                      mod->info.description ?: "",
                      mod->args ?: "");
    if (sz < 0) {
        rc = sz;
        goto out;
    }
    if (sz >= size) {
        out_info[size - 1] = '\0';
        rc = -ENOBUFS;
        goto out;
    }
    logkfd("%s", out_info);
    rc = sz;
out:
    rcu_read_unlock();
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
    if (event <= KPM_EVENT_NONE || event >= KPM_EVENT_MAX) return -EINVAL;

    struct kpm_event_data data = {
        .event = event,
        .source_name = source_name,
        .args = args,
        .reserved = NULL,
    };

    int count = 0;
    rcu_read_lock();
    struct module *pos;
    list_for_each_entry_rcu(pos, &modules.list, list) {
        if (pos->event && *pos->event) {
            long rc = (*pos->event)(&data);
            logkfi("event %d -> module %s: rc=%ld\n", event, pos->info.name, rc);
            count++;
        }
    }
    rcu_read_unlock();

    logkfi("dispatched event %d to %d modules\n", event, count);
    return count;
}