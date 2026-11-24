/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef KP_KPM_ELF_H
#define KP_KPM_ELF_H

/* Host and kernel supply their own ELF64 types, memcpy and errno definitions. */
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

static inline int kpm_validate_sections(const char *data, uint64_t len, const Elf64_Ehdr *hdr)
{
    unsigned int count = hdr->e_shnum;
    if (!count || !elf_bytes_fit(len, hdr->e_shoff, count * sizeof(Elf64_Shdr))) return -ENOEXEC;
    if (!hdr->e_shstrndx || hdr->e_shstrndx >= count) return -ENOEXEC;
    const char *table = data + hdr->e_shoff;
    Elf64_Shdr names = kpm_section(table, hdr->e_shstrndx);
    if (!kpm_string_table_valid(data, len, &names)) return -ENOEXEC;

    for (unsigned int i = 0; i < count; i++) {
        Elf64_Shdr sh = kpm_section(table, i);
        if (sh.sh_type != SHT_NOBITS && !elf_bytes_fit(len, sh.sh_offset, sh.sh_size)) return -ENOEXEC;
        /* The final NUL in a validated string table terminates every in-range name. */
        if (sh.sh_name >= names.sh_size) return -ENOEXEC;
        if (sh.sh_type == SHT_REL || sh.sh_type == SHT_RELA) {
            if (sh.sh_link >= count || sh.sh_info >= count) return -ENOEXEC;
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
#endif
