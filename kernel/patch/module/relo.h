#ifndef _KP_RELO_H_
#define _KP_RELO_H_

#include <uapi/linux/elf.h>

/* Kernel architecture headers commonly expose Elf_Rel/Elf_Rela as aliases to
 * the native ELF class. KPatch-Public is AArch64-only here, so provide an
 * explicit fallback when a target header does not define those alias macros. */
#ifndef Elf_Rel
typedef Elf64_Rel Elf_Rel;
#endif
#ifndef Elf_Rela
typedef Elf64_Rela Elf_Rela;
#endif

int apply_relocate_add(Elf64_Shdr *sechdrs, const char *strtab, unsigned int symindex, unsigned int relsec,
                       struct module *me);
int apply_relocate(Elf64_Shdr *sechdrs, const char *strtab, unsigned int symindex, unsigned int relsec,
                   struct module *me);

#endif
