/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef KP_KPM_ELF_H
#define KP_KPM_ELF_H

#include "../kernel/linux/arch/arm64/include/asm/elf-reloc.h"

/* Host and kernel supply their own ELF64 types, string functions and errno definitions. */
#define KPM_MAX_FILE_SIZE (128 * 1024 * 1024)

static inline int elf_bytes_fit(uint64_t len, uint64_t offset, uint64_t size)
{
    return offset <= len && size <= len - offset;
}

/* An embedded host image need not start at a naturally aligned address. */
static inline Elf64_Shdr kpm_section(const char *table, unsigned int index)
{
    Elf64_Shdr section;
    memcpy(&section, table + index * sizeof(section), sizeof(section));
    return section;
}

static inline int kpm_string_table_valid(const char *data, uint64_t len, const Elf64_Shdr *sh)
{
    if (sh->sh_type != SHT_STRTAB || !elf_bytes_fit(len, sh->sh_offset, sh->sh_size)) return 0;
    return !sh->sh_size || (!data[sh->sh_offset] && !data[sh->sh_offset + sh->sh_size - 1]);
}

/* Bytes written at the relocation target. -1 rejects an unsupported type before any store. */
static inline int kpm_reloc_write_width(unsigned int type)
{
    switch (type) {
    case R_ARM_NONE:
    case R_AARCH64_NONE:
        return 0;
    case R_AARCH64_ABS16:
    case R_AARCH64_PREL16:
        return 2;
    case R_AARCH64_ABS32:
    case R_AARCH64_PREL32:
        return 4;
    case R_AARCH64_ABS64:
    case R_AARCH64_PREL64:
        return 8;
    case R_AARCH64_MOVW_UABS_G0_NC:
    case R_AARCH64_MOVW_UABS_G0:
    case R_AARCH64_MOVW_UABS_G1_NC:
    case R_AARCH64_MOVW_UABS_G1:
    case R_AARCH64_MOVW_UABS_G2_NC:
    case R_AARCH64_MOVW_UABS_G2:
    case R_AARCH64_MOVW_UABS_G3:
    case R_AARCH64_MOVW_SABS_G0:
    case R_AARCH64_MOVW_SABS_G1:
    case R_AARCH64_MOVW_SABS_G2:
    case R_AARCH64_MOVW_PREL_G0_NC:
    case R_AARCH64_MOVW_PREL_G0:
    case R_AARCH64_MOVW_PREL_G1_NC:
    case R_AARCH64_MOVW_PREL_G1:
    case R_AARCH64_MOVW_PREL_G2_NC:
    case R_AARCH64_MOVW_PREL_G2:
    case R_AARCH64_MOVW_PREL_G3:
    case R_AARCH64_LD_PREL_LO19:
    case R_AARCH64_ADR_PREL_LO21:
    case R_AARCH64_ADR_PREL_PG_HI21_NC:
    case R_AARCH64_ADR_PREL_PG_HI21:
    case R_AARCH64_ADD_ABS_LO12_NC:
    case R_AARCH64_LDST8_ABS_LO12_NC:
    case R_AARCH64_LDST16_ABS_LO12_NC:
    case R_AARCH64_LDST32_ABS_LO12_NC:
    case R_AARCH64_LDST64_ABS_LO12_NC:
    case R_AARCH64_LDST128_ABS_LO12_NC:
    case R_AARCH64_TSTBR14:
    case R_AARCH64_CONDBR19:
    case R_AARCH64_JUMP26:
    case R_AARCH64_CALL26:
        return 4;
    default:
        return -1;
    }
}

static inline int kpm_rela_fits(const Elf64_Rela *rel, uint64_t symtab_size, uint64_t target_size)
{
    int width = kpm_reloc_write_width(ELF64_R_TYPE(rel->r_info));
    return width >= 0 && ELF64_R_SYM(rel->r_info) < symtab_size / sizeof(Elf64_Sym) &&
           (!width || elf_bytes_fit(target_size, rel->r_offset, width));
}

struct kpm_sections {
    unsigned int init, ctl0, ctl1, exit, event, info, sym, str;
};

struct kpm_metadata {
    const char *base, *name, *version, *license, *author, *description;
};

static inline unsigned int *kpm_callback_section(struct kpm_sections *sections, const char *name)
{
    if (!strcmp(name, ".kpm.init")) return &sections->init;
    if (!strcmp(name, ".kpm.ctl0")) return &sections->ctl0;
    if (!strcmp(name, ".kpm.ctl1")) return &sections->ctl1;
    if (!strcmp(name, ".kpm.exit")) return &sections->exit;
    if (!strcmp(name, ".kpm.event")) return &sections->event;
    return 0;
}

static inline int kpm_validate_sections(const char *data, uint64_t len, const Elf64_Ehdr *hdr,
                                        struct kpm_sections *sections)
{
    unsigned int count = hdr->e_shnum;
    if (!count || !elf_bytes_fit(len, hdr->e_shoff, count * sizeof(Elf64_Shdr))) return -ENOEXEC;
    if (!hdr->e_shstrndx || hdr->e_shstrndx >= count) return -ENOEXEC;
    const char *table = data + hdr->e_shoff;
    Elf64_Shdr names = kpm_section(table, hdr->e_shstrndx);
    if (!kpm_string_table_valid(data, len, &names)) return -ENOEXEC;

    *sections = (struct kpm_sections){ 0 };
    uint64_t alloc_budget = 0;
    for (unsigned int i = 0; i < count; i++) {
        Elf64_Shdr sh = kpm_section(table, i);
        if (!i && (sh.sh_type != SHT_NULL || sh.sh_flags)) return -ENOEXEC;
        if (sh.sh_type != SHT_NOBITS && !elf_bytes_fit(len, sh.sh_offset, sh.sh_size)) return -ENOEXEC;
        /* The final NUL in a validated string table terminates every in-range name. */
        if (sh.sh_name >= names.sh_size) return -ENOEXEC;
        if (sh.sh_type == SHT_REL) return -ENOEXEC;
        if (sh.sh_type == SHT_RELA) {
            if (sh.sh_link >= count || sh.sh_info >= count || sh.sh_size % sizeof(Elf64_Rela) ||
                (sh.sh_entsize && sh.sh_entsize != sizeof(Elf64_Rela))) return -ENOEXEC;
        }
        if (sh.sh_flags & SHF_ALLOC) {
            uint64_t align = sh.sh_addralign ? sh.sh_addralign : 1;
            if (align > KPM_MAX_FILE_SIZE || (align & (align - 1))) return -ENOEXEC;
            if (align - 1 > KPM_MAX_FILE_SIZE - alloc_budget) return -ENOEXEC;
            alloc_budget += align - 1;
            if (sh.sh_size > KPM_MAX_FILE_SIZE - alloc_budget) return -ENOEXEC;
            alloc_budget += sh.sh_size;

            const char *name = data + names.sh_offset + sh.sh_name;
            /* Linux module entry sections contain instructions, not KPM callback pointers. */
            if (!strcmp(name, ".init.text") || !strcmp(name, ".exit.text")) return -ENOEXEC;
            unsigned int *slot = kpm_callback_section(sections, name);
            if (slot) {
                if (*slot || sh.sh_type != SHT_PROGBITS || (sh.sh_flags & SHF_EXECINSTR) ||
                    sh.sh_size < sizeof(Elf64_Addr)) return -ENOEXEC;
                *slot = i;
            }
            if (!strcmp(name, ".kpm.info")) {
                if (sections->info || sh.sh_type != SHT_PROGBITS || !sh.sh_size) return -ENOEXEC;
                sections->info = i;
            }
        }
        if (sh.sh_type == SHT_SYMTAB && !sections->sym) {
            sections->sym = i;
            sections->str = sh.sh_link;
        }
        if (sh.sh_type != SHT_SYMTAB && sh.sh_type != SHT_DYNSYM) continue;
        if (sh.sh_link >= count || sh.sh_size % sizeof(Elf64_Sym) ||
            (sh.sh_entsize && sh.sh_entsize != sizeof(Elf64_Sym))) return -ENOEXEC;
        Elf64_Shdr strings = kpm_section(table, sh.sh_link);
        if (!kpm_string_table_valid(data, len, &strings)) return -ENOEXEC;
        for (uint64_t off = 0; off < sh.sh_size; off += sizeof(Elf64_Sym)) {
            Elf64_Sym sym;
            memcpy(&sym, data + sh.sh_offset + off, sizeof(sym));
            if (sym.st_name >= strings.sh_size) return -ENOEXEC;
            if (sym.st_shndx >= count && sym.st_shndx != SHN_ABS && sym.st_shndx != SHN_COMMON)
                return -ENOEXEC;
        }
    }
    return 0;
}

/* The final NUL was checked before any record is scanned. */
static inline const char *kpm_modinfo(const char *base, uint64_t size, const char *tag)
{
    size_t taglen = strlen(tag);
    for (const char *p = base; p < base + size; p += strlen(p) + 1) {
        if (!strncmp(p, tag, taglen) && p[taglen] == '=') return p + taglen + 1;
    }
    return 0;
}

/* Both the loader and kptools admit the original file before rewriting any section. */
static inline int kpm_validate(const char *data, uint64_t len, struct kpm_sections *sections,
                               struct kpm_metadata *meta)
{
    Elf64_Ehdr hdr;
    if (!data || len <= sizeof(hdr) || len > KPM_MAX_FILE_SIZE) return -ENOEXEC;
    memcpy(&hdr, data, sizeof(hdr));
    if (memcmp(hdr.e_ident, ELFMAG, SELFMAG) || hdr.e_ident[EI_CLASS] != ELFCLASS64 ||
        hdr.e_ident[EI_DATA] != ELFDATA2LSB || hdr.e_machine != EM_AARCH64 || hdr.e_type != ET_REL ||
        hdr.e_shentsize != sizeof(Elf64_Shdr)) return -ENOEXEC;

    if (kpm_validate_sections(data, len, &hdr, sections)) return -ENOEXEC;
    if (!sections->init || !sections->info || !sections->sym) return -ENOEXEC;
    const char *table = data + hdr.e_shoff;
    Elf64_Shdr sym = kpm_section(table, sections->sym);
    for (unsigned int i = 1; i < hdr.e_shnum; i++) {
        Elf64_Shdr sh = kpm_section(table, i);
        if (sh.sh_type != SHT_RELA) continue;
        Elf64_Shdr target = kpm_section(table, sh.sh_info);
        /* layout_symtab also allocates the selected symbol and string tables. */
        if (!(target.sh_flags & SHF_ALLOC) && sh.sh_info != sections->sym && sh.sh_info != sym.sh_link) continue;
        if (sh.sh_link != sections->sym) return -ENOEXEC;
        for (uint64_t off = 0; off < sh.sh_size; off += sizeof(Elf64_Rela)) {
            Elf64_Rela rel;
            memcpy(&rel, data + sh.sh_offset + off, sizeof(rel));
            if (!kpm_rela_fits(&rel, sym.sh_size, target.sh_size)) return -ENOEXEC;
        }
    }

    Elf64_Shdr info = kpm_section(table, sections->info);
    const char *base = data + info.sh_offset;
    if (base[info.sh_size - 1]) return -ENOEXEC;
    meta->base = base;
    meta->name = kpm_modinfo(base, info.sh_size, "name");
    meta->version = kpm_modinfo(base, info.sh_size, "version");
    if (!meta->name || !meta->version) return -ENOEXEC;
    meta->license = kpm_modinfo(base, info.sh_size, "license");
    meta->author = kpm_modinfo(base, info.sh_size, "author");
    meta->description = kpm_modinfo(base, info.sh_size, "description");
    return 0;
}
#endif
