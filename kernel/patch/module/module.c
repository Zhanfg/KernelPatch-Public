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
/* The KPM list uses a short spinlock, not RCU callback lifetime. */

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

/* ELF section layout has already been checked by elf_header_check(). */
static long get_offset(struct module *mod, unsigned int *size, Elf_Shdr *sechdr, unsigned int section)
{
    long ret = ALIGN(*size, sechdr->sh_addralign ?: 1);
    *size = ret + sechdr->sh_size;
    return ret;
}

/* Never use strlen() on an untrusted ELF .modinfo/.kpm.info record. */
static char *get_modinfo(const struct load_info *info, const char *tag)
{
    const Elf_Shdr *sec;
    const char *cursor, *end;
    size_t left, tag_len;

    if (!info || !tag || !info->index.info ||
        info->index.info >= info->hdr->e_shnum)
        return NULL;
    sec = &info->sechdrs[info->index.info];
    cursor = (const char *)info->hdr + sec->sh_offset;
    left = sec->sh_size;
    tag_len = strlen(tag);

    while (left) {
        size_t item_len;
        end = memchr(cursor, '\0', left);
        if (!end) return NULL; /* Unterminated metadata is malformed. */
        item_len = (size_t)(end - cursor);
        if (item_len > tag_len && cursor[tag_len] == '=' &&
            !memcmp(cursor, tag, tag_len))
            return (char *)cursor + tag_len + 1;
        cursor = end + 1;
        left -= item_len + 1;
    }
    return NULL;
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
    return infosec->sh_size;
}

static void layout_sections(struct module *mod, struct load_info *info)
{
    static unsigned long const masks[][2] = {
        /* NOTE: all executable code must be the first section in this array; otherwise modify the text_size finder in the two loops below */
        { SHF_EXECINSTR | SHF_ALLOC, ARCH_SHF_SMALL },
        { SHF_ALLOC, SHF_WRITE | ARCH_SHF_SMALL },
        { SHF_WRITE | SHF_ALLOC, ARCH_SHF_SMALL },
        { ARCH_SHF_SMALL | SHF_ALLOC, 0 }
    };

    for (int i = 0; i < info->hdr->e_shnum; i++)
        info->sechdrs[i].sh_entsize = ~0UL;

    // todo: tslf alloc all rwx and not page aligned
    for (int m = 0; m < sizeof(masks) / sizeof(masks[0]); ++m) {
        for (int i = 0; i < info->hdr->e_shnum; ++i) {
            Elf_Shdr *s = &info->sechdrs[i];
            if ((s->sh_flags & masks[m][0]) != masks[m][0] || (s->sh_flags & masks[m][1]) || s->sh_entsize != ~0UL)
                continue;
            s->sh_entsize = get_offset(mod, &mod->size, s, i);
            // const char *sname = info->secstrings + s->sh_name;
        }
        switch (m) {
        case 0: /* executable */
            mod->size = align(mod->size);
            mod->text_size = mod->size;
            break;
        case 1: /* RO: text and ro-data */
            mod->size = align(mod->size);
            mod->ro_size = mod->size;
            break;
        case 2:
            break;
        case 3: /* whole */
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

/* Change all symbols so that st_value encodes the pointer directly. */
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
        case SHN_UNDEF:
            unsigned long addr = symbol_lookup_name(name);
            /* Fallback: try compact resolver (exposes kernel + KP symbols to KPM) */
            if (!addr) addr = compact_find_symbol(name);
            if (!addr) {
                logke("unknown symbol: %s\n", name);
                ret = -ENOENT;
                break;
            }
            sym[i].st_value = addr;
            break;
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

// todo: free .strtab and .symtab after relocation
static void layout_symtab(struct module *mod, struct load_info *info)
{
    Elf_Shdr *symsect = info->sechdrs + info->index.sym;
    Elf_Shdr *strsect = info->sechdrs + info->index.str;
    const Elf_Sym *src;
    unsigned int i, nsrc, ndst, strtab_size = 0;

    /* Put symbol section at end of module. */
    symsect->sh_flags |= SHF_ALLOC;
    symsect->sh_entsize = get_offset(mod, &mod->size, symsect, info->index.sym);

    src = (void *)info->hdr + symsect->sh_offset;
    nsrc = symsect->sh_size / sizeof(*src);

    /* strtab always starts with a nul, so offset 0 is the empty string. */
    strtab_size = 1;
    /* Compute total space required for the core symbols' strtab. */
    for (ndst = i = 0; i < nsrc; i++) {
        if (i == 0 || is_core_symbol(src + i, info->sechdrs, info->hdr->e_shnum)) {
            strtab_size += strlen(&info->strtab[src[i].st_name]) + 1;
            ndst++;
        }
    }

    /* Append room for core symbols at end. */
    info->symoffs = ALIGN(mod->size, symsect->sh_addralign ?: 1);
    info->stroffs = mod->size = info->symoffs + ndst * sizeof(Elf_Sym);
    mod->size += strtab_size;

    /* Put string table section at end of module. */
    strsect->sh_flags |= SHF_ALLOC;
    strsect->sh_entsize = get_offset(mod, &mod->size, strsect, info->index.str);
}

static int rewrite_section_headers(struct load_info *info)
{
    info->sechdrs[0].sh_addr = 0;
    for (int i = 1; i < info->hdr->e_shnum; i++) {
        Elf_Shdr *shdr = &info->sechdrs[i];
        if (shdr->sh_type != SHT_NOBITS && info->len < shdr->sh_offset + shdr->sh_size) {
            return -ENOEXEC;
        }
        /* Mark all sections sh_addr with their address in the temporary image. */
        shdr->sh_addr = (size_t)info->hdr + shdr->sh_offset;
    }
    return 0;
}

static int move_module(struct module *mod, struct load_info *info)
{
    // todo:
    logki("alloc module size: %llx\n", mod->size);
    mod->start = kp_malloc_exec(mod->size);
    if (!mod->start) {
        return -ENOMEM;
    }
    memset(mod->start, 0, mod->size);

    /* Transfer each section which specifies SHF_ALLOC */
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
        /* .ko format: accept standard .init.text/.exit.text */
        if (!mod->init && !strcmp(".init.text", sname)) mod->init = (mod_initcall_t *)dest;

        if (!strcmp(".kpm.ctl0", sname)) mod->ctl0 = (mod_ctl0call_t *)dest;
        if (!strcmp(".kpm.ctl1", sname)) mod->ctl1 = (mod_ctl1call_t *)dest;

        if (!mod->exit && !strcmp(".kpm.exit", sname)) mod->exit = (mod_exitcall_t *)dest;
        /* .ko format: accept standard .exit.text */
        if (!mod->exit && !strcmp(".exit.text", sname)) mod->exit = (mod_exitcall_t *)dest;

        if (!mod->event && !strcmp(".kpm.event", sname)) mod->event = (mod_eventcall_t *)dest;

        if (!mod->info.base && !strcmp(".kpm.info", sname)) mod->info.base = (const char *)dest;
    }

    /* For .ko/.o without .kpm.info, metadata is static (from setup_load_info).
     * Use the strings directly — they point to the original ELF data (still valid). */
    if (info->info.base) {
        /* KPM format: compute relocated offsets */
        mod->info.name = info->info.name - info->info.base + mod->info.base;
        mod->info.version = info->info.version - info->info.base + mod->info.base;
        if (info->info.license) mod->info.license = info->info.license - info->info.base + mod->info.base;
        if (info->info.author) mod->info.author = info->info.author - info->info.base + mod->info.base;
        if (info->info.description) mod->info.description = info->info.description - info->info.base + mod->info.base;
    } else {
        /* .ko/.o format: metadata strings point into original ELF data.
         * Copy into per-module allocated buffers since original data is freed after load. */
        char *buf = vmalloc(320); /* 64+32+32+64+128 = 320 */
        if (buf) {
            memset(buf, 0, 320);
            strncpy(buf, info->info.name ?: "unknown", 63);
            strncpy(buf + 64, info->info.version ?: "0.0.0", 31);
            strncpy(buf + 96, info->info.license ?: "unknown", 31);
            strncpy(buf + 128, info->info.author ?: "unknown", 63);
            strncpy(buf + 192, info->info.description ?: "loaded from .ko", 127);
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

    int has_kpm_init = find_sec(info, ".kpm.init") || find_sec(info, ".kpm.exit");
    int has_ko_init = find_sec(info, ".init.text") || find_sec(info, ".exit.text");

    if (!has_kpm_init && !has_ko_init) {
        logke("no .kpm.init/.kpm.exit or .init.text/.exit.text section\n");
        return -ENOEXEC;
    }

    /* .ko format: parse .modinfo for metadata */
    if (!has_kpm_init && has_ko_init) {
        int modinfo_idx = find_sec(info, ".modinfo");
        if (modinfo_idx) {
            /* Temporarily set index.info to .modinfo for get_modinfo() */
            info->index.info = modinfo_idx;
            info->info.base = get_sh_base(info, ".modinfo");
            info->info.size = get_sh_size(info, ".modinfo");

            info->info.name = get_modinfo(info, "name");
            if (!info->info.name) info->info.name = "unknown.ko";
            info->info.version = get_modinfo(info, "version");
            if (!info->info.version) info->info.version = "0.0.0";
            info->info.license = get_modinfo(info, "license");
            if (!info->info.license) info->info.license = "unknown";
            info->info.author = get_modinfo(info, "author");
            if (!info->info.author) info->info.author = "unknown";
            info->info.description = get_modinfo(info, "description");
            if (!info->info.description) info->info.description = "loaded from .ko";
        } else {
            info->index.info = 0;
            info->info.name = "unknown.ko";
            info->info.version = "0.0.0";
            info->info.license = "unknown";
            info->info.author = "unknown";
            info->info.description = "loaded from .ko";
        }
        logkd("loading .ko: name=%s version=%s license=%s\n",
              info->info.name, info->info.version, info->info.license);
        goto find_symtab;
    }

    info->index.info = find_sec(info, ".kpm.info");
    if (!info->index.info) {
        /* .o file without .kpm.info — auto-generate metadata */
        info->info.name = "unknown.o";
        info->info.version = "0.0.0";
        info->info.license = "unknown";
        info->info.author = "unknown";
        info->info.description = "loaded from .o";
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

    const char *license = get_modinfo(info, "license");
    info->info.license = license;
    logkd("    license: %s\n", license);

    const char *author = get_modinfo(info, "author");
    info->info.author = author;
    logkd("    author: %s\n", author);
    const char *description = get_modinfo(info, "description");
    info->info.description = description;
    logkd("    description: %s\n", description);

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
    return 0;
}

static int elf_header_check(struct load_info *info)
{
    if (!info || !info->hdr || info->len < (int)sizeof(Elf_Ehdr)) return -ENOEXEC;

    const Elf_Ehdr *hdr = info->hdr;
    unsigned long len = (unsigned long)info->len;
    if (memcmp(hdr->e_ident, ELFMAG, SELFMAG) ||
        hdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        hdr->e_ident[EI_DATA] != ELFDATA2LSB ||
        hdr->e_type != ET_REL || !elf_check_arch(hdr) ||
        hdr->e_shentsize != sizeof(Elf_Shdr) || !hdr->e_shnum ||
        hdr->e_shstrndx == SHN_UNDEF || hdr->e_shstrndx >= hdr->e_shnum)
        return -ENOEXEC;

    /*
     * Keep an upper bound on ELF metadata and all executable/data mappings.
     * Even SHT_NOBITS consumes memory at relocation time.
     */
    if (len > (16u * 1024u * 1024u) || hdr->e_shnum > 1024)
        return -EFBIG;

    /* Check bounds before setup_load_info dereferences the section table. */
    if (hdr->e_shoff > len ||
        hdr->e_shnum > (len - hdr->e_shoff) / sizeof(Elf_Shdr))
        return -ENOEXEC;

    const Elf_Shdr *sections = (const void *)((const char *)hdr + hdr->e_shoff);
    const Elf_Shdr *names = &sections[hdr->e_shstrndx];
    if (names->sh_type != SHT_STRTAB || !names->sh_size ||
        names->sh_offset > len || names->sh_size > len - names->sh_offset)
        return -ENOEXEC;

    const char *shstrtab = (const char *)hdr + names->sh_offset;
    unsigned long long mapped_budget = 0;
    for (unsigned int i = 0; i < hdr->e_shnum; ++i) {
        const Elf_Shdr *sec = &sections[i];

        /* Alignment is always power of two, not user-controlled padding. */
        if (sec->sh_addralign &&
            ((sec->sh_addralign & (sec->sh_addralign - 1)) != 0 ||
             sec->sh_addralign > 65536))
            return -ENOEXEC;
        if (sec->sh_flags & SHF_ALLOC) {
            /* Includes NOBITS, which has no ELF file payload. */
            if (sec->sh_size > (32u * 1024u * 1024u))
                return -EFBIG;
            mapped_budget += sec->sh_size + (sec->sh_addralign ?: 1);
            if (mapped_budget > (64u * 1024u * 1024u))
                return -EFBIG;
        }
        if (sec->sh_type != SHT_NOBITS &&
            (sec->sh_offset > len || sec->sh_size > len - sec->sh_offset))
            return -ENOEXEC;
        if (sec->sh_name >= names->sh_size ||
            !memchr(shstrtab + sec->sh_name, '\0', names->sh_size - sec->sh_name))
            return -ENOEXEC;
        if (sec->sh_type == SHT_SYMTAB &&
            (sec->sh_link >= hdr->e_shnum ||
             sections[sec->sh_link].sh_type != SHT_STRTAB ||
             sec->sh_entsize != sizeof(Elf_Sym) ||
             (sec->sh_size % sizeof(Elf_Sym)) != 0))
            return -ENOEXEC;
        if (sec->sh_type == SHT_SYMTAB) {
            const Elf_Shdr *strings = &sections[sec->sh_link];
            /* The linked string table may appear later in the section list. */
            if (strings->sh_offset > len ||
                strings->sh_size > len - strings->sh_offset)
                return -ENOEXEC;
            const char *strtab = (const char *)hdr + strings->sh_offset;
            const Elf_Sym *syms = (const void *)((const char *)hdr + sec->sh_offset);
            unsigned long count = sec->sh_size / sizeof(*syms);

            if (!strings->sh_size) return -ENOEXEC;
            for (unsigned long j = 0; j < count; j++) {
                const Elf_Sym *sym = &syms[j];
                if (sym->st_name >= strings->sh_size ||
                    !memchr(strtab + sym->st_name, '\0',
                            strings->sh_size - sym->st_name))
                    return -ENOEXEC;
                if (sym->st_shndx >= hdr->e_shnum &&
                    sym->st_shndx != SHN_UNDEF &&
                    sym->st_shndx != SHN_ABS &&
                    sym->st_shndx != SHN_COMMON)
                    return -ENOEXEC;
            }
        }
        /* AArch64 KPM uses RELA. REL is not implemented; fail closed. */
        if (sec->sh_type == SHT_REL)
            return -ENOEXEC;
        if (sec->sh_type == SHT_RELA) {
            if (sec->sh_info >= hdr->e_shnum ||
                sec->sh_link >= hdr->e_shnum ||
                sections[sec->sh_link].sh_type != SHT_SYMTAB ||
                sec->sh_entsize != sizeof(Elf64_Rela) ||
                (sec->sh_size % sizeof(Elf64_Rela)) != 0)
                return -ENOEXEC;
            const Elf_Shdr *target = &sections[sec->sh_info];
            const Elf_Shdr *symtab = &sections[sec->sh_link];
            const Elf64_Rela *relas =
                (const void *)((const char *)hdr + sec->sh_offset);
            unsigned long nrelas = sec->sh_size / sizeof(*relas);
            unsigned long nsym = symtab->sh_size / sizeof(Elf_Sym);
            for (unsigned long j = 0; j < nrelas; j++) {
                if (ELF64_R_SYM(relas[j].r_info) >= nsym ||
                    target->sh_size < 4 ||
                    relas[j].r_offset > target->sh_size - 4)
                    return -ENOEXEC;
            }
        }
    }
    return 0;
}

struct module modules = { 0 };
static spinlock_t module_lock;

/*
 * KPM lifetime rules: module_lock protects list membership, callback_users
 * and module_load_inflight. Module callbacks MUST run with the lock released.
 * An unload during an active callback returns -EBUSY (never frees live code).
 * This avoids blocking or sleeping in an RCU read-side critical section.
 */
#define PATCHNEST_MAX_KPM_MODULES 64
#define PATCHNEST_KPM_NAME_MAX 64
#define PATCHNEST_KPM_FILE_MAX (16 * 1024 * 1024)
static unsigned int module_count;
static bool module_load_inflight;

static struct module *module_acquire(const char *name)
{
    struct module *mod;

    if (!name) return NULL;
    spin_lock(&module_lock);
    mod = find_module(name); /* Must be called with module_lock held. */
    if (mod && !pn_kpm_lifetime_get(&mod->lifetime)) mod = NULL;
    spin_unlock(&module_lock);
    return mod;
}

static void module_release(struct module *mod)
{
    spin_lock(&module_lock);
    if (!pn_kpm_lifetime_put(&mod->lifetime)) logkfe("KPM callback reference underflow\n");
    spin_unlock(&module_lock);
}

long load_module(const void *data, int len, const char *args, const char *event, void *__user reserved)
{
    struct load_info load_info = { .len = len, .hdr = data };
    struct load_info *info = &load_info;
    long rc = 0;

    if ((rc = elf_header_check(info))) goto out;
    if ((rc = kpm_safety_validate(data, len))) goto out;
    if ((rc = setup_load_info(info))) goto out;
    if (!info->info.name ||
        strnlen(info->info.name, PATCHNEST_KPM_NAME_MAX) >= PATCHNEST_KPM_NAME_MAX) {
        rc = -EINVAL;
        goto out;
    }
    if (args && strnlen(args, 4097) > 4096) {
        rc = -E2BIG;
        goto out;
    }

    /* Safety: check blacklist */
    if (kpm_safety_check_blacklist(info->info.name)) {
        logkfe("kpm_safety: skipping blacklisted module %s\n", info->info.name);
        rc = -EACCES;
        goto out;
    }

    /* Reserve the single loader slot. Never hold a spinlock across init. */
    spin_lock(&module_lock);
    if (module_load_inflight) {
        rc = -EBUSY;
    } else if (find_module(info->info.name)) {
        rc = -EEXIST;
    } else if (module_count >= PATCHNEST_MAX_KPM_MODULES) {
        rc = -ENOSPC;
    } else {
        module_load_inflight = true;
    }
    spin_unlock(&module_lock);
    if (rc) goto out;

    struct module *mod = (struct module *)vmalloc(sizeof(struct module));
    if (!mod) {
        rc = -ENOMEM;
        goto clear_loader;
    }
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

    flush_icache_all();

    /* Validate before recording an in-progress load transaction. */
    if (!mod->init || !*mod->init) {
        rc = -ENOEXEC;
        logkfe("KPM has no callable init entry point\n");
        goto free;
    }

    /* Mark this KPM as loading (for crash detection) */
    kpm_safety_mark_loading(info->info.name);
    rc = (*mod->init)(mod->args, event, reserved);

    if (!rc) {
        logkfi("[%s] succeed with [%s] \n", mod->info.name, args);
        spin_lock(&module_lock);
        list_add_tail(&mod->list, &modules.list);
        module_count++;
        spin_unlock(&module_lock);
        goto clear_loader;
    } else {
        logkfi("[%s] failed with [%s] error: %d, try exit ...\n", mod->info.name, args, rc);
        if (mod->exit && *mod->exit)
            (*mod->exit)(reserved);
    }

free:
    if (mod->args) kvfree(mod->args);
    kp_free_exec(mod->start);
free1:
    kvfree(mod);
clear_loader:
    spin_lock(&module_lock);
    module_load_inflight = false;
    spin_unlock(&module_lock);
out:
    return rc;
}

// todo: lock
long unload_module(const char *name, void *__user reserved)
{
    struct module *mod;
    long rc = 0;

    if (!name) return -EINVAL;
    spin_lock(&module_lock);
    mod = find_module(name);
    if (!mod) {
        rc = -ENOENT;
    } else if (!pn_kpm_lifetime_may_unload(&mod->lifetime)) {
        /* Do not free executable memory while control/event is running. */
        rc = -EBUSY;
    } else {
        list_del(&mod->list);
        module_count--;
    }
    spin_unlock(&module_lock);
    if (rc) return rc;

    /* Detached: nobody can obtain new callback references. */
    if (mod->exit && *mod->exit)
        rc = (*mod->exit)(reserved);

    if (mod->args) kvfree(mod->args);
    if (mod->ctl_args) kvfree(mod->ctl_args);
    kp_free_exec(mod->start);
    kvfree(mod);
    return rc;
}

long load_module_path(const char *path, const char *args, void *__user reserved)
{
    long rc = 0;
    struct file *filp;
    void *data;
    loff_t len;
    loff_t pos = 0;

    if (!path) return -EINVAL;
    logkfd("%s\n", path);
    filp = filp_open(path, O_RDONLY, 0);
    if (unlikely(!filp || IS_ERR(filp))) {
        logkfe("open module: %s error\n", path);
        rc = PTR_ERR(filp);
        goto out;
    }
    len = vfs_llseek(filp, 0, SEEK_END);
    if (len < (loff_t)sizeof(Elf_Ehdr) || len > PATCHNEST_KPM_FILE_MAX) {
        rc = len < 0 ? (long)len : -EFBIG;
        goto close_file;
    }
    if (vfs_llseek(filp, 0, SEEK_SET) < 0) {
        rc = -EIO;
        goto close_file;
    }

    data = vmalloc((size_t)len);
    if (!data) {
        rc = -ENOMEM;
        goto close_file;
    }

    rc = kernel_read(filp, data, (size_t)len, &pos);
    if (rc != len) {
        rc = rc < 0 ? rc : -EIO;
        goto free_data;
    }

    /* Parsed and copied before closing the file; no stale file pointer. */
    rc = load_module(data, (int)len, args, "load-file", reserved);
free_data:
    kvfree(data);
close_file:
    filp_close(filp, 0);
out:
    return rc;
}

/*
 * A callback gets a pin under module_lock; it may sleep once the lock
 * is dropped. Dynamic unload fails with -EBUSY rather than freeing code
 * underneath an in-flight callback. ctl0 arguments are call-scoped.
 */
long module_control0(const char *name, const char *ctl_args,
                     char *__user out_msg, int outlen)
{
    struct module *mod;
    char *local_args;
    long rc;
    size_t args_len;

    if (!name || !ctl_args || outlen < 0) return -EINVAL;
    args_len = strlen(ctl_args);
    if (!args_len || args_len > 4096) return -E2BIG;

    mod = module_acquire(name);
    if (!mod) return -ENOENT;

    if (!mod->ctl0 || !*mod->ctl0) {
        rc = -ENOSYS;
        goto out;
    }

    local_args = vmalloc(args_len + 1);
    if (!local_args) {
        rc = -ENOMEM;
        goto out;
    }
    memcpy(local_args, ctl_args, args_len + 1);
    rc = (*mod->ctl0)(local_args, out_msg, outlen);
    kvfree(local_args);

out:
    module_release(mod);
    return rc;
}

long module_control1(const char *name, void *a1, void *a2, void *a3)
{
    struct module *mod;
    long rc;

    if (!name) return -EINVAL;
    mod = module_acquire(name);
    if (!mod) return -ENOENT;
    if (!mod->ctl1 || !*mod->ctl1) {
        rc = -ENOSYS;
    } else {
        rc = (*mod->ctl1)(a1, a2, a3);
    }
    module_release(mod);
    return rc;
}

struct module *find_module(const char *name)
{
    struct module *pos;
    list_for_each_entry(pos, &modules.list, list)
    {
        if (!strcmp(name, pos->info.name)) {
            return pos;
        }
    }
    return 0;
}

int get_module_nums()
{
    int n;
    spin_lock(&module_lock);
    n = (int)module_count;
    spin_unlock(&module_lock);
    return n;
}

int list_modules(char *out_names, int size)
{
    struct module *pos;
    int off = 0;

    if (!out_names || size <= 0) return -EINVAL;
    out_names[0] = '\0';
    spin_lock(&module_lock);
    list_for_each_entry(pos, &modules.list, list) {
        int remaining = size - off;
        int n;
        if (remaining <= 1) break;
        n = snprintf(out_names + off, remaining, "%s\n", pos->info.name);
        if (n < 0) {
            off = n;
            break;
        }
        if (n >= remaining) {
            off = size - 1;
            break;
        }
        off += n;
    }
    if (off > 0 && out_names[off - 1] == '\n') out_names[off - 1] = '\0';
    spin_unlock(&module_lock);
    return off;
}

int get_module_info(const char *name, char *out_info, int size)
{
    struct module *mod;
    int sz;

    if (!name || !out_info || size <= 0) return -EINVAL;
    spin_lock(&module_lock);
    mod = find_module(name);
    if (!mod) {
        spin_unlock(&module_lock);
        return -ENOENT;
    }
    sz = snprintf(out_info, size,
                  "name=%s\nversion=%s\nlicense=%s\nauthor=%s\ndescription=%s\nargs=%s\n",
                  mod->info.name ?: "unknown",
                  mod->info.version ?: "0.0.0",
                  mod->info.license ?: "unknown",
                  mod->info.author ?: "unknown",
                  mod->info.description ?: "",
                  mod->args ?: "");
    if (sz >= size) sz = size - 1;
    if (sz > 0 && out_info[sz - 1] == '\n') out_info[sz - 1] = '\0';
    spin_unlock(&module_lock);
    return sz;
}

void module_init()
{
    INIT_LIST_HEAD(&modules.list);
    spin_lock_init(&module_lock);

    kpm_safety_init();

    /* Early boot counter (before /data mount) — protects embedded KPMs */
    kpm_safety_early_count();

    /* Full boot counter check (after /data mount available) */
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

int module_dispatch_event(enum kpm_event event, const char *source_name,
                          const char *args)
{
    struct module *snapshot[PATCHNEST_MAX_KPM_MODULES];
    struct kpm_event_data data = {
        .event = event,
        .source_name = source_name,
        .args = args,
        .reserved = NULL,
    };
    struct module *pos;
    unsigned int size = 0;
    int dispatched = 0;

    if (event <= KPM_EVENT_NONE || event >= KPM_EVENT_MAX)
        return -EINVAL;

    /*
     * Take a bounded snapshot under module_lock. Pin each callback before
     * releasing the lock; unload sees -EBUSY until all pins are dropped.
     * Callbacks may sleep; never run them under RCU or a spinlock.
     */
    spin_lock(&module_lock);
    list_for_each_entry(pos, &modules.list, list) {
        if (size >= PATCHNEST_MAX_KPM_MODULES) break;
        if (pn_kpm_lifetime_get(&pos->lifetime))
            snapshot[size++] = pos;
    }
    spin_unlock(&module_lock);

    for (unsigned int i = 0; i < size; i++) {
        pos = snapshot[i];
        if (pos->event && *pos->event) {
            long rc = (*pos->event)(&data);
            logkfi("event %d -> module %s: rc=%ld\n",
                   event, pos->info.name, rc);
            dispatched++;
        }
        module_release(pos);
    }
    return dispatched;
}
