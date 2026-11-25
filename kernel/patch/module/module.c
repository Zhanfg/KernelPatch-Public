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
#define KP_KPM_LIST_FORMAT
#include <kpm_query.h>
#include "relo.h"
#include <compact.h>
#include <selinux_hide.h>
#include <proc_hide.h>
#include <kpm_safety.h>
#include <accctl.h>

#include "../../../include/kpm_elf.h"

struct load_info
{
    struct kpm_metadata info;
    const Elf_Ehdr *hdr;
    unsigned long len;
    Elf_Shdr *sechdrs;
    char *secstrings, *strtab;
    unsigned long symoffs, stroffs;
    struct kpm_sections index;
};

#define ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))
#define ALIGN(x, a) ALIGN_MASK(x, (typeof(x))(a)-1)

#define align(X) ALIGN(X, page_size)

#define ARCH_SHF_SMALL 0

static inline bool strstarts(const char *str, const char *prefix)
{
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

/* Update size with this section: return offset. */
static long get_offset(struct module *mod, unsigned int *size, Elf_Shdr *sechdr, unsigned int section)
{
    long ret = ALIGN(*size, sechdr->sh_addralign ?: 1);
    *size = ret + sechdr->sh_size;
    return ret;
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
            if (sym[i].st_shndx >= info->hdr->e_shnum) {
                ret = -ENOEXEC;
                break;
            }
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
        if (info->sechdrs[i].sh_type == SHT_REL) return -ENOEXEC;
        if (info->sechdrs[i].sh_type != SHT_RELA) continue;
        if (infosec >= info->hdr->e_shnum || info->sechdrs[i].sh_link >= info->hdr->e_shnum) return -ENOEXEC;
        if (!(info->sechdrs[infosec].sh_flags & SHF_ALLOC)) continue;
        rc = apply_relocate_add(info->sechdrs, info->strtab, info->index.sym, i, mod);
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
        if (shdr->sh_type != SHT_NOBITS && !elf_bytes_fit(info->len, shdr->sh_offset, shdr->sh_size)) {
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
    }

    /* Absent optional slots use section zero, whose address is cleared during setup. */
    mod->init = (mod_initcall_t *)info->sechdrs[info->index.init].sh_addr;
    mod->ctl0 = (mod_ctl0call_t *)info->sechdrs[info->index.ctl0].sh_addr;
    mod->ctl1 = (mod_ctl1call_t *)info->sechdrs[info->index.ctl1].sh_addr;
    mod->exit = (mod_exitcall_t *)info->sechdrs[info->index.exit].sh_addr;
    mod->event = (mod_eventcall_t *)info->sechdrs[info->index.event].sh_addr;
    mod->info.base = (const char *)info->sechdrs[info->index.info].sh_addr;
    mod->info.name = info->info.name - info->info.base + mod->info.base;
    mod->info.version = info->info.version - info->info.base + mod->info.base;
    if (info->info.license) mod->info.license = info->info.license - info->info.base + mod->info.base;
    if (info->info.author) mod->info.author = info->info.author - info->info.base + mod->info.base;
    if (info->info.description) mod->info.description = info->info.description - info->info.base + mod->info.base;

    return 0;
}

static int setup_load_info(struct load_info *info)
{
    int rc = kpm_validate((const char *)info->hdr, info->len, &info->index, &info->info);
    if (rc) {
        logke("invalid KPM: expected AArch64 RELA, .kpm.info and .kpm.init (Linux .ko and SHT_REL unsupported)\n");
        return rc;
    }
    info->sechdrs = (void *)info->hdr + info->hdr->e_shoff;
    info->secstrings = (void *)info->hdr + info->sechdrs[info->hdr->e_shstrndx].sh_offset;
    info->strtab = (void *)info->hdr + info->sechdrs[info->index.str].sh_offset;
    return rewrite_section_headers(info);
}

struct module modules = { 0 };
static spinlock_t module_lock;

/* Event dispatch pins at most this many modules before dropping RCU. */
#define MODULE_EVENT_SNAP 64

static struct module *find_module_locked(const char *name)
{
    struct module *pos;

    list_for_each_entry(pos, &modules.list, list) {
        if (pos->info.name && !strcmp(name, pos->info.name)) return pos;
    }
    return 0;
}

/* Caller holds no RCU read lock. kf_synchronize_rcu is the resolved symbol;
 * the inline synchronize_rcu() wrapper used to call a different, unresolved function. */
static void module_quiesce(void)
{
    if (kfunc(synchronize_rcu)) kfunc(synchronize_rcu)();
    else logke("synchronize_rcu unavailable\n");
}

long load_module(const void *data, int len, const char *args, const char *event, void *__user reserved)
{
    struct load_info load_info = { .len = len, .hdr = data };
    struct load_info *info = &load_info;
    long rc = 0;

    if ((rc = setup_load_info(info))) goto out;

    /* Safety: check blacklist */
    if (kpm_safety_check_blacklist(info->info.name)) {
        logkfe("kpm_safety: skipping blacklisted module %s\n", info->info.name);
        rc = -EACCES;
        goto out;
    }

    /* Safety: validate ELF structure */
    if ((rc = kpm_safety_validate(data, len))) {
        logkfe("kpm_safety: validation failed for %s\n", info->info.name);
        goto out;
    }

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

    flush_icache_all();

    if (!mod->init || !*mod->init) {
        logke("module %s has no init callback\n", mod->info.name ? mod->info.name : "?");
        rc = -ENOEXEC;
        goto free;
    }
    if (!kfunc(synchronize_rcu)) {
        logke("synchronize_rcu unavailable\n");
        rc = -ENOSYS;
        goto free;
    }

    /* Reserve the name before init so a second load cannot insert a duplicate. */
    spin_lock(&module_lock);
    if (find_module_locked(mod->info.name)) {
        spin_unlock(&module_lock);
        logkfd("%s exist\n", mod->info.name);
        rc = -EEXIST;
        goto free;
    }
    list_add_tail_rcu(&mod->list, &modules.list);
    spin_unlock(&module_lock);

    /* Mark this KPM as loading (for crash detection) */
    kpm_safety_mark_loading(info->info.name);

    rc = (*mod->init)(mod->args, event, reserved);

    if (!rc) {
        spin_lock(&module_lock);
        smp_store_release(&mod->live, 1);
        spin_unlock(&module_lock);
        logkfi("[%s] succeed with [%s] \n", mod->info.name, args);
        goto out;
    }

    logkfi("[%s] failed with [%s] error: %d, try exit ...\n", mod->info.name, args, rc);
    spin_lock(&module_lock);
    list_del_rcu(&mod->list);
    spin_unlock(&module_lock);
    module_quiesce();
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
    struct module *mod;
    long rc = 0;

    if (!name) return -EINVAL;
    logkfe("name: %s\n", name);
    if (!kfunc(synchronize_rcu)) return -ENOSYS;

    spin_lock(&module_lock);
    mod = find_module_locked(name);
    if (!mod) {
        spin_unlock(&module_lock);
        return -ENOENT;
    }
    /* Init still running, or a control/event callback still holds the module. */
    if (!mod->live || mod->active_refs) {
        spin_unlock(&module_lock);
        return -EBUSY;
    }
    smp_store_release(&mod->live, 0);
    list_del_rcu(&mod->list);
    spin_unlock(&module_lock);

    /* In-flight readers leave their read-side section before this returns. */
    module_quiesce();

    spin_lock(&module_lock);
    if (mod->active_refs) {
        list_add_tail_rcu(&mod->list, &modules.list);
        smp_store_release(&mod->live, 1);
        spin_unlock(&module_lock);
        return -EBUSY;
    }
    spin_unlock(&module_lock);

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
        return filp ? PTR_ERR(filp) : -ENOENT;
    }
    void *data = NULL;
    loff_t len = vfs_llseek(filp, 0, SEEK_END);
    logkfd("module size: %llx\n", len);
    if (len < 0) {
        rc = len;
        goto close;
    }
    if (len <= (loff_t)sizeof(Elf_Ehdr) || len > KPM_MAX_FILE_SIZE) {
        rc = -ENOEXEC;
        goto close;
    }

    data = vmalloc(len);
    if (!data) {
        rc = -ENOMEM;
        goto close;
    }
    loff_t pos = 0;
    ssize_t n = kernel_read(filp, data, len, &pos);
    if (n != len) {
        logkfe("read module: %s error\n", path);
        rc = n < 0 ? n : -EIO;
    }
close:
    filp_close(filp, 0);
    if (!rc) rc = load_module(data, (int)len, args, "load-file", reserved);
    if (data) kvfree(data);
    return rc;
}

long module_control0(const char *name, const char *ctl_args, char *__user out_msg, int outlen)
{
    char *args_buf;
    struct module *mod;
    mod_ctl0call_t ctl = 0;
    long rc = 0;
    int args_len;

    if (!name || !ctl_args) return -EINVAL;
    args_len = strlen(ctl_args);
    if (args_len <= 0) return -EINVAL;

    logkfi("name %s, args: %s\n", name, ctl_args);

    /* Per-call copy. The old shared mod->ctl_args was freed by the next caller. */
    args_buf = vmalloc(args_len + 1);
    if (!args_buf) return -ENOMEM;
    strcpy(args_buf, ctl_args);

    rcu_read_lock();
    mod = find_module(name);
    if (!mod) {
        rc = -ENOENT;
        goto out;
    }
    if (!mod->ctl0 || !*mod->ctl0) {
        logkfe("no ctl0\n");
        rc = -ENOSYS;
        goto out;
    }
    spin_lock(&module_lock);
    if (!mod->live) {
        spin_unlock(&module_lock);
        rc = -ENOENT;
        goto out;
    }
    mod->active_refs++;
    ctl = *mod->ctl0;
    spin_unlock(&module_lock);
out:
    rcu_read_unlock();
    if (!ctl) {
        kvfree(args_buf);
        return rc;
    }

    rc = ctl(args_buf, out_msg, outlen);
    logkfi("name: %s, rc: %d\n", name, rc);
    kvfree(args_buf);

    spin_lock(&module_lock);
    mod->active_refs--;
    spin_unlock(&module_lock);
    return rc;
}

long module_control1(const char *name, void *a1, void *a2, void *a3)
{
    struct module *mod;
    mod_ctl1call_t ctl = 0;
    long rc = 0;

    logkfi("name %s, a1: %llx, a2: %llx, a3: %llx\n", name, a1, a2, a3);
    rcu_read_lock();

    mod = find_module(name);
    if (!mod) {
        rc = -ENOENT;
        goto out;
    }
    if (!mod->ctl1 || !*mod->ctl1) {
        logkfe("no ctl1\n");
        rc = -ENOSYS;
        goto out;
    }
    spin_lock(&module_lock);
    if (!mod->live) {
        spin_unlock(&module_lock);
        rc = -ENOENT;
        goto out;
    }
    mod->active_refs++;
    ctl = *mod->ctl1;
    spin_unlock(&module_lock);
out:
    rcu_read_unlock();
    if (!ctl) return rc;

    rc = ctl(a1, a2, a3);
    logkfi("name: %s, rc: %d\n", name, rc);

    spin_lock(&module_lock);
    mod->active_refs--;
    spin_unlock(&module_lock);
    return rc;
}

struct module *find_module(const char *name)
{
    struct module *pos;

    if (!name) return 0;
    list_for_each_entry_rcu(pos, &modules.list, list) {
        if (!smp_load_acquire(&pos->live)) continue;
        if (pos->info.name && !strcmp(name, pos->info.name)) return pos;
    }
    return 0;
}

int get_module_nums()
{
    rcu_read_lock();

    struct module *pos;
    int n = 0;
    list_for_each_entry_rcu(pos, &modules.list, list) {
        if (!smp_load_acquire(&pos->live)) continue;
        n++;
    }
    rcu_read_unlock();

    logkfd("%d\n", n);
    return n;
}

int list_modules(char *out_names, int size)
{
    struct module *pos;
    int off = 0;
    int rc = 0;

    if (!out_names || size <= 0)
        return -EINVAL;

    out_names[0] = '\0';
    rcu_read_lock();

    list_for_each_entry_rcu(pos, &modules.list, list) {
        if (!smp_load_acquire(&pos->live) || !pos->info.name) continue;
        rc = kpm_list_append(out_names, size, &off, pos->info.name);
        if (rc)
            goto out;
    }
    kpm_list_finish(out_names, off);
    rc = off;

out:
    rcu_read_unlock();
    return rc;
}

int get_module_info(const char *name, char *out_info, int size)
{
    int sz = 0;
    struct module *mod;

    if (size <= 0) return 0;
    rcu_read_lock();

    mod = find_module(name);
    if (!mod) {
        sz = -ENOENT;
        goto out;
    }

    sz = snprintf(out_info, size,
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

    /* Never expose snprintf's would-be length as initialized output bytes. */
    if (sz >= size) {
        sz = -ENOBUFS;
        goto out;
    }
    if (sz > 0)
        out_info[sz - 1] = '\0';
    if (sz >= 0)
        logkfd("%s", out_info);

out:
    rcu_read_unlock();
    return sz;
}

void module_init()
{
    INIT_LIST_HEAD(&modules.list);
    spin_lock_init(&module_lock);

    kpm_safety_init();

    compact_init();
    umount_init();
    selinux_hide_init();
    proc_hide_init();
}

int module_dispatch_event(enum kpm_event event, const char *source_name, const char *args)
{
    struct module *snap[MODULE_EVENT_SNAP];
    struct module *pos;
    struct kpm_event_data data;
    int n = 0;
    int i;
    int count = 0;
    int overflow = 0;

    if (event <= KPM_EVENT_NONE || event >= KPM_EVENT_MAX) return -EINVAL;

    data.event = event;
    data.source_name = source_name;
    data.args = args;
    data.reserved = NULL;

    rcu_read_lock();
    spin_lock(&module_lock);
    list_for_each_entry(pos, &modules.list, list) {
        if (!pos->live || !pos->event || !*pos->event) continue;
        if (n >= MODULE_EVENT_SNAP) {
            overflow = 1;
            break;
        }
        pos->active_refs++;
        snap[n++] = pos;
    }
    spin_unlock(&module_lock);
    rcu_read_unlock();

    for (i = 0; i < n; i++) {
        long rc = (*snap[i]->event)(&data);
        logkfi("event %d -> module %s: rc=%ld\n", event, snap[i]->info.name, rc);
        count++;
        spin_lock(&module_lock);
        snap[i]->active_refs--;
        spin_unlock(&module_lock);
    }
    if (overflow) logke("event dispatch stopped at %d modules\n", MODULE_EVENT_SNAP);

    logkfi("dispatched event %d to %d modules\n", event, count);
    return count;
}
