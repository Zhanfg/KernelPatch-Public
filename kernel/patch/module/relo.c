#include <linux/printk.h>
#include <linux/elf.h>
#include <uapi/linux/elf.h>
#include <asm/elf.h>
#include <kpmalloc.h>
#include <linux/err.h>

#include "insn.h"

#define AARCH64_INSN_IMM_MOVNZ AARCH64_INSN_IMM_MAX
#define AARCH64_INSN_IMM_MOVK AARCH64_INSN_IMM_16

#define le32_to_cpu(x) (x)
#define cpu_to_le32(x) (x)

enum aarch64_reloc_op
{
    RELOC_OP_NONE,
    RELOC_OP_ABS,
    RELOC_OP_PREL,
    RELOC_OP_PAGE,
};

static u64 do_reloc(enum aarch64_reloc_op reloc_op, void *place, u64 val)
{
    switch (reloc_op) {
    case RELOC_OP_ABS:
        return val;
    case RELOC_OP_PREL:
        return val - (u64)place;
    case RELOC_OP_PAGE:
        return (val & ~0xfff) - ((u64)place & ~0xfff);
    case RELOC_OP_NONE:
        return 0;
    }

    pr_err("do_reloc: unknown relocation operation %d\n", reloc_op);
    return 0;
}

static int reloc_data(enum aarch64_reloc_op op, void *place, u64 val, int len)
{
    u64 imm_mask = (1ULL << len) - 1;
    s64 sval = do_reloc(op, place, val);

    switch (len) {
    case 16:
        *(s16 *)place = sval;
        break;
    case 32:
        *(s32 *)place = sval;
        break;
    case 64:
        *(s64 *)place = sval;
        break;
    default:
        pr_err("Invalid length (%d) for data relocation\n", len);
        return -EINVAL;
    }

    sval = (s64)(sval & ~(imm_mask >> 1)) >> (len - 1);
    if ((u64)(sval + 1) > 2) return -ERANGE;
    return 0;
}

static int reloc_insn_movw(enum aarch64_reloc_op op, void *place, u64 val, int lsb,
                           enum aarch64_insn_imm_type imm_type)
{
    u64 imm, limit = 0;
    s64 sval;
    u32 insn = le32_to_cpu(*(u32 *)place);

    sval = do_reloc(op, place, val);
    sval >>= lsb;
    imm = sval & 0xffff;

    if (imm_type == AARCH64_INSN_IMM_MOVNZ) {
        insn &= ~(3 << 29);
        if ((s64)imm >= 0) {
            insn |= 2 << 29;
        } else {
            imm = ~imm;
        }
        imm_type = AARCH64_INSN_IMM_MOVK;
    }

    insn = aarch64_insn_encode_immediate(imm_type, insn, imm);
    *(u32 *)place = cpu_to_le32(insn);
    sval >>= 16;

    if (imm_type != AARCH64_INSN_IMM_16) {
        sval++;
        limit++;
    }
    if ((u64)sval > limit) return -ERANGE;
    return 0;
}

static int reloc_insn_imm(enum aarch64_reloc_op op, void *place, u64 val, int lsb, int len,
                          enum aarch64_insn_imm_type imm_type)
{
    u64 imm, imm_mask;
    s64 sval;
    u32 insn = le32_to_cpu(*(u32 *)place);

    sval = do_reloc(op, place, val);
    sval >>= lsb;
    imm_mask = (BIT(lsb + len) - 1) >> lsb;
    imm = sval & imm_mask;
    insn = aarch64_insn_encode_immediate(imm_type, insn, imm);
    *(u32 *)place = cpu_to_le32(insn);
    sval = (s64)(sval & ~(imm_mask >> 1)) >> (len - 1);
    if ((u64)(sval + 1) >= 2) return -ERANGE;
    return 0;
}

/* Return the number of bytes a relocation may write at r_offset. Unknown
 * relocations return -1 and are rejected before any pointer arithmetic. */
static int relocation_write_width(unsigned int type)
{
    switch (type) {
    case R_ARM_NONE:
    case R_AARCH64_NONE:
        return 0;
    case R_AARCH64_ABS16:
    case R_AARCH64_PREL16:
        return 2;
    case R_AARCH64_ABS64:
    case R_AARCH64_PREL64:
        return 8;
    case R_AARCH64_ABS32:
    case R_AARCH64_PREL32:
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

int apply_relocate(Elf64_Shdr *sechdrs, const char *strtab, unsigned int symindex,
                   unsigned int relsec, struct module *me)
{
    /* REL relocations are not implemented for this AArch64 KPM loader. Do not
     * silently accept an unprocessed relocation section. */
    (void)sechdrs;
    (void)strtab;
    (void)symindex;
    (void)relsec;
    (void)me;
    return -ENOEXEC;
}

int apply_relocate_add(Elf64_Shdr *sechdrs, const char *strtab, unsigned int symindex,
                       unsigned int relsec, struct module *me)
{
    unsigned int i;
    int ovf;
    bool overflow_check;
    Elf64_Sym *sym;
    void *loc;
    u64 val;
    Elf64_Shdr *relhdr = &sechdrs[relsec];
    Elf64_Shdr *symhdr = &sechdrs[symindex];
    Elf64_Shdr *target = &sechdrs[relhdr->sh_info];
    Elf64_Rela *rel = (void *)relhdr->sh_addr;
    unsigned long sym_count;

    (void)strtab;
    (void)me;

    if (relhdr->sh_type != SHT_RELA || relhdr->sh_entsize != sizeof(Elf64_Rela) ||
        relhdr->sh_size % sizeof(Elf64_Rela)) {
        pr_err("invalid RELA section metadata\n");
        return -ENOEXEC;
    }
    if (symhdr->sh_type != SHT_SYMTAB || symhdr->sh_entsize != sizeof(Elf64_Sym) ||
        symhdr->sh_size % sizeof(Elf64_Sym)) {
        pr_err("invalid symbol table metadata\n");
        return -ENOEXEC;
    }
    if (!target->sh_addr && target->sh_size) {
        pr_err("relocation target section is not mapped\n");
        return -ENOEXEC;
    }

    sym_count = symhdr->sh_size / sizeof(Elf64_Sym);
    if (!sym_count) return -ENOEXEC;

    for (i = 0; i < relhdr->sh_size / sizeof(*rel); i++) {
        unsigned int type = ELF64_R_TYPE(rel[i].r_info);
        unsigned long sym_no = ELF64_R_SYM(rel[i].r_info);
        int width = relocation_write_width(type);

        if (width < 0) {
            pr_err("unsupported RELA relocation: %u\n", type);
            return -ENOEXEC;
        }
        if (sym_no >= sym_count) {
            pr_err("relocation symbol index out of range: %lu >= %lu\n", sym_no, sym_count);
            return -ENOEXEC;
        }
        if (rel[i].r_offset > target->sh_size ||
            (unsigned long)width > target->sh_size - rel[i].r_offset) {
            pr_err("relocation target offset out of range: off=%llx width=%d size=%llx\n",
                   rel[i].r_offset, width, target->sh_size);
            return -ENOEXEC;
        }

        /* Null relocations are validated but perform no memory access. */
        if (width == 0) continue;

        loc = (void *)target->sh_addr + rel[i].r_offset;
        sym = (Elf64_Sym *)symhdr->sh_addr + sym_no;
        val = sym->st_value + rel[i].r_addend;
        overflow_check = true;

        switch (type) {
        case R_AARCH64_ABS64:
            overflow_check = false;
            ovf = reloc_data(RELOC_OP_ABS, loc, val, 64);
            break;
        case R_AARCH64_ABS32:
            ovf = reloc_data(RELOC_OP_ABS, loc, val, 32);
            break;
        case R_AARCH64_ABS16:
            ovf = reloc_data(RELOC_OP_ABS, loc, val, 16);
            break;
        case R_AARCH64_PREL64:
            overflow_check = false;
            ovf = reloc_data(RELOC_OP_PREL, loc, val, 64);
            break;
        case R_AARCH64_PREL32:
            ovf = reloc_data(RELOC_OP_PREL, loc, val, 32);
            break;
        case R_AARCH64_PREL16:
            ovf = reloc_data(RELOC_OP_PREL, loc, val, 16);
            break;
        case R_AARCH64_MOVW_UABS_G0_NC:
            overflow_check = false;
            /* fall through */
        case R_AARCH64_MOVW_UABS_G0:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 0, AARCH64_INSN_IMM_16);
            break;
        case R_AARCH64_MOVW_UABS_G1_NC:
            overflow_check = false;
            /* fall through */
        case R_AARCH64_MOVW_UABS_G1:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 16, AARCH64_INSN_IMM_16);
            break;
        case R_AARCH64_MOVW_UABS_G2_NC:
            overflow_check = false;
            /* fall through */
        case R_AARCH64_MOVW_UABS_G2:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 32, AARCH64_INSN_IMM_16);
            break;
        case R_AARCH64_MOVW_UABS_G3:
            overflow_check = false;
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 48, AARCH64_INSN_IMM_16);
            break;
        case R_AARCH64_MOVW_SABS_G0:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 0, AARCH64_INSN_IMM_MOVNZ);
            break;
        case R_AARCH64_MOVW_SABS_G1:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 16, AARCH64_INSN_IMM_MOVNZ);
            break;
        case R_AARCH64_MOVW_SABS_G2:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 32, AARCH64_INSN_IMM_MOVNZ);
            break;
        case R_AARCH64_MOVW_PREL_G0_NC:
            overflow_check = false;
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 0, AARCH64_INSN_IMM_MOVK);
            break;
        case R_AARCH64_MOVW_PREL_G0:
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 0, AARCH64_INSN_IMM_MOVNZ);
            break;
        case R_AARCH64_MOVW_PREL_G1_NC:
            overflow_check = false;
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 16, AARCH64_INSN_IMM_MOVK);
            break;
        case R_AARCH64_MOVW_PREL_G1:
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 16, AARCH64_INSN_IMM_MOVNZ);
            break;
        case R_AARCH64_MOVW_PREL_G2_NC:
            overflow_check = false;
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 32, AARCH64_INSN_IMM_MOVK);
            break;
        case R_AARCH64_MOVW_PREL_G2:
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 32, AARCH64_INSN_IMM_MOVNZ);
            break;
        case R_AARCH64_MOVW_PREL_G3:
            overflow_check = false;
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 48, AARCH64_INSN_IMM_MOVNZ);
            break;
        case R_AARCH64_LD_PREL_LO19:
            ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 19, AARCH64_INSN_IMM_19);
            break;
        case R_AARCH64_ADR_PREL_LO21:
            ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 0, 21, AARCH64_INSN_IMM_ADR);
            break;
        case R_AARCH64_ADR_PREL_PG_HI21_NC:
            overflow_check = false;
            /* fall through */
        case R_AARCH64_ADR_PREL_PG_HI21:
            ovf = reloc_insn_imm(RELOC_OP_PAGE, loc, val, 12, 21, AARCH64_INSN_IMM_ADR);
            break;
        case R_AARCH64_ADD_ABS_LO12_NC:
        case R_AARCH64_LDST8_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 0, 12, AARCH64_INSN_IMM_12);
            break;
        case R_AARCH64_LDST16_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 1, 11, AARCH64_INSN_IMM_12);
            break;
        case R_AARCH64_LDST32_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 2, 10, AARCH64_INSN_IMM_12);
            break;
        case R_AARCH64_LDST64_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 3, 9, AARCH64_INSN_IMM_12);
            break;
        case R_AARCH64_LDST128_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 4, 8, AARCH64_INSN_IMM_12);
            break;
        case R_AARCH64_TSTBR14:
            ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 14, AARCH64_INSN_IMM_14);
            break;
        case R_AARCH64_CONDBR19:
            ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 19, AARCH64_INSN_IMM_19);
            break;
        case R_AARCH64_JUMP26:
        case R_AARCH64_CALL26:
            ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 26, AARCH64_INSN_IMM_26);
            break;
        default:
            return -ENOEXEC;
        }

        if (overflow_check && ovf == -ERANGE) goto overflow;
        if (ovf < 0 && ovf != -ERANGE) return ovf;
    }
    return 0;

overflow:
    pr_err("overflow in relocation type %d val %llx\n", (int)ELF64_R_TYPE(rel[i].r_info), val);
    return -ENOEXEC;
}