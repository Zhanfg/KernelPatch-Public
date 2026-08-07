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

#define SZ_128M 0x08000000UL
#define MAX_ELF_SECTIONS 4096U
#define MAX_SECTION_ALIGN (1UL << 20)
#define MAX_ELF_SYMBOLS (1UL << 20)
#define MAX_ELF_RELOCS (1UL << 20)

#define ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))
#define ALIGN(x, a) ALIGN_MASK(x, (typeof(x))(a)-1)
#define align(X) ALIGN(X, page_size)
#define elf_check_arch(x) ((x)->e_machine == EM_AARCH64)
#define ARCH_SHF_SMALL 0

static inline bool strstarts(const char *str, const char *prefix)
{
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

static long get_offset(struct module *mod, unsigned int *size, Elf_Shdr *sechdr, unsigned int section)
{
    long ret = ALIGN(*size, sechdr->sh_addralign ?: 1);
    *size = ret + sechdr->sh_size;
    return ret;
}

static char *get_next_modinfo(const struct load_info *info, const char *tag, char *prev)
{
    Elf_Shdr *infosec;
    char *base;
    uint64_t section_size;
    uint64_t cursor = 0;
    uint64_t taglen;

    if (!info || !tag || !info->index.info) return 0;
    infosec = &info->sechdrs[info->index.info];
    section_size = infosec->sh_size;
    base = (char *)info->hdr + infosec->sh_offset;
    taglen = strlen(tag);
    if (!section_size || taglen >= section_size) return 0;

    if (prev) {
        uintptr_t base_addr = (uintptr_t)base;
        uintptr_t prev_addr = (uintptr_t)prev;
        uint64_t prev_offset;
        if (prev_addr < base_addr) return 0;
        prev_offset = prev_addr - base_addr;
        if (prev_offset >= section_size) return 0;
        cursor = prev_offset;

        while (cursor < section_size && base[cursor] != '\0') cursor++;
        if (cursor == section_size) return 0;
        while (cursor < section_size && base[cursor] == '\0') cursor++;
    }

    while (cursor < section_size) {
        uint64_t end = cursor;
        uint64_t entry_len;
        while (end < section_size && base[end] != '\0') end++;
        if (end == section_size) return 0;
        entry_len = end - cursor;

        if (entry_len > taglen &&
            !memcmp(base + cursor, tag, taglen) &&
            base[cursor + taglen] == '=')
            return base + cursor + taglen + 1;

        cursor = end + 1;
        while (cursor < section_size && base[cursor] == '\0') cursor++;
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
    return (void *)info->hdr + info->sechdrs[idx].sh_offset;
}

static unsigned long get_sh_size(struct load_info *info, const char *secname)
{
    int idx = find_sec(info, secname);
    if (!idx) return 0;
    return info->sechdrs[idx].sh_entsize;
}

static bool file_range_ok(const struct load_info *info, uint64_t offset, uint64_t size)
{
    if (offset > info->len) return false;
    return size <= info->len - offset;
}

static bool string_in_table(const char *table, uint64_t table_size, uint64_t offset)
{
    if (!table || offset >= table_size) return false;
    for (uint64_t i = offset; i < table_size; i++) {
        if (table[i] == '\0') return true;
    }
    return false;
}

static int validate_symbol_table(const struct load_info *info, unsigned int index)
{
    const Elf64_Shdr *symsec = &info->sechdrs[index];
    const Elf64_Shdr *strsec;
    const Elf64_Sym *symbols;
    const char *strings;
    uint64_t count;

    if (symsec->sh_entsize != sizeof(Elf64_Sym) || symsec->sh_size % sizeof(Elf64_Sym)) return -ENOEXEC;
    count = symsec->sh_size / sizeof(Elf64_Sym);
    if (count == 0 || count > MAX_ELF_SYMBOLS) return -E2BIG;
    if (symsec->sh_link >= info->hdr->e_shnum) return -ENOEXEC;
    strsec = &info->sechdrs[symsec->sh_link];
    if (strsec->sh_type != SHT_STRTAB || !file_range_ok(info, strsec->sh_offset, strsec->sh_size)) return -ENOEXEC;

    symbols = (const Elf64_Sym *)((const char *)info->hdr + symsec->sh_offset);
    strings = (const char *)info->hdr + strsec->sh_offset;
    for (uint64_t i = 0; i < count; i++) {
        uint16_t shndx = symbols[i].st_shndx;
        if (!string_in_table(strings, strsec->sh_size, symbols[i].st_name)) return -ENOEXEC;
        if (shndx == SHN_UNDEF || shndx == SHN_ABS || shndx == SHN_COMMON) continue;
        if (shndx >= info->hdr->e_shnum) return -ENOEXEC;
    }
    return 0;
}

static int validate_relocation_section(const struct load_info *info, unsigned int index)
{
    const Elf64_Shdr *relsec = &info->sechdrs[index];
    const Elf64_Shdr *symsec;
    const Elf64_Shdr *target;
    uint64_t count;
    uint64_t symcount;

    if (relsec->sh_link >= info->hdr->e_shnum || relsec->sh_info >= info->hdr->e_shnum) return -ENOEXEC;
    symsec = &info->sechdrs[relsec->sh_link];
    target = &info->sechdrs[relsec->sh_info];
    if (symsec->sh_type != SHT_SYMTAB || symsec->sh_entsize != sizeof(Elf64_Sym)) return -ENOEXEC;
    if (symsec->sh_size % sizeof(Elf64_Sym)) return -ENOEXEC;
    symcount = symsec->sh_size / sizeof(Elf64_Sym);

    if (relsec->sh_type == SHT_REL) {
        const Elf64_Rel *rel;
        if (relsec->sh_entsize != sizeof(Elf64_Rel) || relsec->sh_size % sizeof(Elf64_Rel)) return -ENOEXEC;
        count = relsec->sh_size / sizeof(Elf64_Rel);
        if (count > MAX_ELF_RELOCS) return -E2BIG;
        rel = (const Elf64_Rel *)((const char *)info->hdr + relsec->sh_offset);
        for (uint64_t i = 0; i < count; i++) {
            if (ELF64_R_SYM(rel[i].r_info) >= symcount) return -ENOEXEC;
            if (rel[i].r_offset >= target->sh_size) return -ENOEXEC;
        }
    } else if (relsec->sh_type == SHT_RELA) {
        const Elf64_Rela *rela;
        if (relsec->sh_entsize != sizeof(Elf64_Rela) || relsec->sh_size % sizeof(Elf64_Rela)) return -ENOEXEC;
        count = relsec->sh_size / sizeof(Elf64_Rela);
        if (count > MAX_ELF_RELOCS) return -E2BIG;
        rela = (const Elf64_Rela *)((const char *)info->hdr + relsec->sh_offset);
        for (uint64_t i = 0; i < count; i++) {
            if (ELF64_R_SYM(rela[i].r_info) >= symcount) return -ENOEXEC;
            if (rela[i].r_offset >= target->sh_size) return -ENOEXEC;
        }
    }
    return 0;
}

static int validate_elf_structure(struct load_info *info)
{
    const Elf64_Shdr *shstr;
    const char *section_names;
    uint64_t alloc_total = 0;
    unsigned int symtabs = 0;

    if (!info->hdr->e_shnum || info->hdr->e_shnum > MAX_ELF_SECTIONS) return -E2BIG;
    if (info->hdr->e_shstrndx == SHN_UNDEF || info->hdr->e_shstrndx >= info->hdr->e_shnum) return -ENOEXEC;

    info->sechdrs = (Elf_Shdr *)((char *)info->hdr + info->hdr->e_shoff);
    shstr = &info->sechdrs[info->hdr->e_shstrndx];
    if (shstr->sh_type != SHT_STRTAB || !file_range_ok(info, shstr->sh_offset, shstr->sh_size)) return -ENOEXEC;
    section_names = (const char *)info->hdr + shstr->sh_offset;

    for (unsigned int i = 0; i < info->hdr->e_shnum; i++) {
        const Elf64_Shdr *sec = &info->sechdrs[i];
        uint64_t align = sec->sh_addralign ?: 1;

        if (align > MAX_SECTION_ALIGN || (align & (align - 1))) return -ENOEXEC;
        if (sec->sh_type != SHT_NOBITS && !file_range_ok(info, sec->sh_offset, sec->sh_size)) return -ENOEXEC;
        if (!string_in_table(section_names, shstr->sh_size, sec->sh_name)) return -ENOEXEC;

        if (sec->sh_flags & SHF_ALLOC) {
            uint64_t mask = align - 1;
            if (alloc_total > SZ_128M - mask) return -E2BIG;
            alloc_total = (alloc_total + mask) & ~mask;
            if (sec->sh_size > SZ_128M - alloc_total) return -E2BIG;
            alloc_total += sec->sh_size;
        }

        if (sec->sh_type == SHT_SYMTAB) {
            symtabs++;
            if (symtabs > 1) return -ENOEXEC;
            int rc = validate_symbol_table(info, i);
            if (rc) return rc;
        } else if (sec->sh_type == SHT_REL || sec->sh_type == SHT_RELA) {
            int rc = validate_relocation_section(info, i);
            if (rc) return rc;
        }
    }

    if (symtabs != 1) return -ENOEXEC;
    return 0;
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
        case 0: mod->size = align(mod->size); mod->text_size = mod->size; break;
        case 1: mod->size = align(mod->size); mod->ro_size = mod->size; break;
        case 2: break;
        case 3: mod->size = align(mod->size); break;
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
            if (!strncmp(name, "__gnu_lto", 9)) { logkd("Please compile with -fno-common\n"); ret = -ENOEXEC; }
            break;
        case SHN_ABS: break;
        case SHN_UNDEF: {
            unsigned long addr = symbol_lookup_name(name);
            if (!addr) addr = compact_find_symbol(name);
            if (!addr) { logke("unknown symbol: %s\n", name); ret = -ENOENT; break; }
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
        if (shdr->sh_type != SHT_NOBITS && !file_range_ok(info, shdr->sh_offset, shdr->sh_size)) return -ENOEXEC;
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

    for (int i = 1; i < info->hdr->e_shnum; i++) {
        void *dest;
        Elf_Shdr *shdr = &info->sechdrs[i];
        if (!(shdr->sh_flags & SHF_ALLOC)) continue;
        dest = mod->start + shdr->sh_entsize;
        const char *sname = info->secstrings + shdr->sh_name;
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
        mod->info.name = buf; mod->info.version = buf + 64; mod->info.license = buf + 96;
        mod->info.author = buf + 128; mod->info.description = buf + 192;
    }
    return 0;
}

static int setup_load_info(struct load_info *info)
{
    int rc = 0;
    info->sechdrs = (void *)info->hdr + info->hdr->e_shoff;
    info->secstrings = (void *)info->hdr + info->sechdrs[info->hdr->e_shstrndx].sh_offset;
    if ((rc = rewrite_section_headers(info))) return rc;

    if (!find_sec(info, ".kpm.init")) {
        if (find_sec(info, ".init.text") || find_sec(info, ".exit.text"))
            logke("legacy .ko callback inference is unsupported; explicit .kpm.init is required\n");
        return -ENOEXEC;
    }

    info->index.info = find_sec(info, ".kpm.info");
    if (!info->index.info) {
        info->info.name = "unknown.o"; info->info.version = "0.0.0"; info->info.license = "unknown";
        info->info.author = "unknown"; info->info.description = "loaded from object";
        goto find_symtab;
    }
    info->info.base = get_sh_base(info, ".kpm.info");
    info->info.size = get_sh_size(info, ".kpm.info");
    info->info.name = get_modinfo(info, "name");
    info->info.version = get_modinfo(info, "version");
    if (!info->info.name || !info->info.version) return -ENOEXEC;
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
    return info->index.sym ? 0 : -ENOEXEC;
}

static int elf_header_check(struct load_info *info)
{
    if (info->len <= sizeof(*(info->hdr)) || info->len > SZ_128M) return -ENOEXEC;
    if (memcmp(info->hdr->e_ident, ELFMAG, SELFMAG) || info->hdr->e_type != ET_REL || !elf_check_arch(info->hdr) ||
        info->hdr->e_shentsize != sizeof(Elf_Shdr)) return -ENOEXEC;
    if (!info->hdr->e_shnum || info->hdr->e_shnum > MAX_ELF_SECTIONS) return -E2BIG;
    if (info->hdr->e_shoff > info->len) return -ENOEXEC;
    if (info->hdr->e_shnum > (info->len - info->hdr->e_shoff) / sizeof(Elf_Shdr)) return -ENOEXEC;
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
    return target && target >= start && target < start + mod->text_size;
}

static int validate_module_callbacks(struct module *mod)
{
    if (!callback_slot_in_module(mod, mod->init) || !*mod->init || !callback_target_in_text(mod, (unsigned long)*mod->init)) return -ENOEXEC;
    if (mod->exit && (!callback_slot_in_module(mod, mod->exit) || !*mod->exit || !callback_target_in_text(mod, (unsigned long)*mod->exit))) return -ENOEXEC;
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
    list_for_each_entry(pos, &modules.list, list) if (!strcmp(name, pos->info.name)) return pos;
    return 0;
}

static struct module *get_live_module(const char *name)
{
    struct module *mod = 0;
    if (!name) return 0;
    spin_lock(&module_lock);
    mod = find_module_any_locked(name);
    if (!mod || mod->state != MODULE_STATE_LIVE) mod = 0;
    else mod->active_refs++;
    spin_unlock(&module_lock);
    return mod;
}

struct module *find_module(const char *name) { return get_live_module(name); }

void put_module(struct module *mod)
{
    if (!mod) return;
    spin_lock(&module_lock);
    if (!mod->active_refs) logkfe("module ref underflow: %s\n", mod->info.name ?: "unknown");
    else mod->active_refs--;
    spin_unlock(&module_lock);
}

static int reserve_loading_module(struct module *mod)
{
    int rc = 0;
    spin_lock(&module_lock);
    if (find_module_any_locked(mod->info.name)) rc = -EEXIST;
    else { mod->state = MODULE_STATE_LOADING; mod->active_refs = 0; list_add_tail(&mod->list, &modules.list); }
    spin_unlock(&module_lock);
    return rc;
}

static void remove_reserved_module(struct module *mod)
{
    spin_lock(&module_lock);
    if (mod->state != MODULE_STATE_DEAD) { list_del(&mod->list); mod->state = MODULE_STATE_DEAD; }
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
    if ((rc = validate_elf_structure(info))) goto out;
    if ((rc = setup_load_info(info))) goto out;
    if (kpm_safety_check_blacklist(info->info.name)) { rc = -EACCES; goto out; }
    if ((rc = kpm_safety_validate(data, len))) goto out;

    mod = (struct module *)vmalloc(sizeof(*mod));
    if (!mod) return -ENOMEM;
    memset(mod, 0, sizeof(*mod));
    if (args) {
        mod->args = vmalloc(strlen(args) + 1);
        if (!mod->args) { rc = -ENOMEM; goto free; }
        strcpy(mod->args, args);
    }

    layout_sections(mod, info);
    layout_symtab(mod, info);
    if (mod->size > SZ_128M) { rc = -E2BIG; goto free; }
    if ((rc = move_module(mod, info))) goto free;
    if ((rc = simplify_symbols(mod, info))) goto free;
    if ((rc = apply_relocations(mod, info))) goto free;
    if ((rc = validate_module_callbacks(mod))) goto free;
    flush_icache_all();

    if ((rc = reserve_loading_module(mod))) goto free;
    reserved_in_list = 1;
    kpm_safety_mark_loading(info->info.name);
    rc = (*mod->init)(mod->args, event, reserved);
    if (!rc) {
        spin_lock(&module_lock);
        if (mod->state == MODULE_STATE_LOADING) mod->state = MODULE_STATE_LIVE;
        spin_unlock(&module_lock);
        return 0;
    }
    if (mod->exit && *mod->exit) (*mod->exit)(reserved);

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
    if (!mod) { spin_unlock(&module_lock); return -ENOENT; }
    if (mod->state == MODULE_STATE_LOADING || mod->state == MODULE_STATE_UNLOADING || mod->state == MODULE_STATE_DEAD) {
        spin_unlock(&module_lock); return -EBUSY;
    }
    if (mod->state == MODULE_STATE_LIVE) mod->state = MODULE_STATE_QUIESCING;
    if (mod->active_refs) { spin_unlock(&module_lock); return -EBUSY; }
    mod->state = MODULE_STATE_UNLOADING;
    spin_unlock(&module_lock);

    if (mod->exit && *mod->exit) rc = (*mod->exit)(reserved);
    if (rc) {
        spin_lock(&module_lock);
        if (mod->state == MODULE_STATE_UNLOADING) mod->state = MODULE_STATE_LIVE;
        spin_unlock(&module_lock);
        return rc;
    }
    spin_lock(&module_lock);
    if (mod->active_refs) { mod->state = MODULE_STATE_QUIESCING; spin_unlock(&module_lock); return -EBUSY; }
    list_del(&mod->list); mod->state = MODULE_STATE_DEAD;
    spin_unlock(&module_lock);
    free_module_storage(mod);
    return 0;
}

long load_module_path(const char *path, const char *args, void *__user reserved)
{
    long rc = 0;
    if (!path) return -EINVAL;
    struct file *filp = filp_open(path, O_RDONLY | O_NOFOLLOW, 0);
    if (unlikely(!filp || IS_ERR(filp))) return filp ? PTR_ERR(filp) : -ENOENT;
    loff_t len = vfs_llseek(filp, 0, SEEK_END);
    if (len <= 0 || len > SZ_128M) { rc = -E2BIG; goto close; }
    vfs_llseek(filp, 0, SEEK_SET);
    void *data = vmalloc(len);
    if (!data) { rc = -ENOMEM; goto close; }
    memset(data, 0, len);
    loff_t pos = 0;
    ssize_t got = kernel_read(filp, data, len, &pos);
    if (got != len || pos != len) { rc = got < 0 ? got : -EIO; goto free; }
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
    if (!mod->ctl0 || !*mod->ctl0) { put_module(mod); return -ENOSYS; }
    local_args = vmalloc(args_len + 1);
    if (!local_args) { put_module(mod); return -ENOMEM; }
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
    if (!mod->ctl1 || !*mod->ctl1) { put_module(mod); return -ENOSYS; }
    rc = (*mod->ctl1)(a1, a2, a3);
    put_module(mod);
    return rc;
}

int get_module_nums()
{
    struct module *pos;
    int n = 0;
    spin_lock(&module_lock);
    list_for_each_entry(pos, &modules.list, list) if (pos->state == MODULE_STATE_LIVE) n++;
    spin_unlock(&module_lock);
    return n;
}

int list_modules(char *out_names, int size)
{
    struct module *pos;
    int rc = 0, off = 0;
    if (!out_names || size <= 0) return -EINVAL;
    out_names[0] = '\0';
    spin_lock(&module_lock);
    list_for_each_entry(pos, &modules.list, list) {
        if (pos->state != MODULE_STATE_LIVE) continue;
        int remaining = size - off;
        if (remaining <= 1) { rc = -ENOBUFS; goto out; }
        int written = snprintf(out_names + off, remaining, "%s\n", pos->info.name);
        if (written < 0) { rc = written; goto out; }
        if (written >= remaining) { rc = -ENOBUFS; goto out; }
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
    if (!mod) { spin_unlock(&module_lock); return -ENOENT; }
    rc = snprintf(out_info, size,
                  "name=%s\nversion=%s\nlicense=%s\nauthor=%s\ndescription=%s\nargs=%s\nstate=%s\nactive_refs=%u\n",
                  mod->info.name ?: "unknown", mod->info.version ?: "0.0.0", mod->info.license ?: "unknown",
                  mod->info.author ?: "unknown", mod->info.description ?: "", mod->args ?: "",
                  module_state_name(mod->state), mod->active_refs);
    spin_unlock(&module_lock);
    if (rc < 0) return rc;
    if (rc >= size) { out_info[size - 1] = '\0'; return -ENOBUFS; }
    if (rc > 0 && out_info[rc - 1] == '\n') out_info[rc - 1] = '\0';
    return rc;
}

void module_init()
{
    INIT_LIST_HEAD(&modules.list);
    spin_lock_init(&module_lock);
    kpm_safety_init();
    kpm_safety_early_count();
    if (kpm_safety_check_boot_count()) { extern int kp_safe_mode; kp_safe_mode = 1; }
    compact_init();
    umount_init();
    selinux_hide_init();
    proc_hide_init();
}

int module_dispatch_event(enum kpm_event event, const char *source_name, const char *args)
{
    struct module **targets = 0;
    struct module *pos;
    struct kpm_event_data data = { .event = event, .source_name = source_name, .args = args, .reserved = NULL };
    int capacity = 0, count = 0, delivered = 0;
    if (event <= KPM_EVENT_NONE || event >= KPM_EVENT_MAX) return -EINVAL;

    spin_lock(&module_lock);
    list_for_each_entry(pos, &modules.list, list) if (pos->state == MODULE_STATE_LIVE) capacity++;
    spin_unlock(&module_lock);
    if (!capacity) return 0;
    if (capacity > 4096) return -E2BIG;
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
        if (mod->event && *mod->event) { (*mod->event)(&data); delivered++; }
        put_module(mod);
    }
    kvfree(targets);
    return delivered;
}
