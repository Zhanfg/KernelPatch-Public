/* Host harness for the production loader. Only the data-only lifecycle fixture is run. */
#include <assert.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/types.h>
#include "../tools/kpm.h"

#define __user
typedef uint64_t u64;
typedef int64_t s64;
typedef uint32_t u32;
typedef int32_t s32;
typedef int16_t s16;
#define BIT(n) (1UL << (n))

struct list_head { struct list_head *next, *prev; };
#include "../kernel/patch/include/module.h"
#define INIT_LIST_HEAD(head) ((head)->next = (head)->prev = (head))
#define list_for_each_entry(pos, head, member)                                              \
    for (struct list_head *entry = (head)->next;                                            \
         entry != (head) && ((pos) = (void *)((char *)entry - offsetof(struct module, member)), 1); \
         entry = entry->next)
#define list_for_each_entry_rcu list_for_each_entry

static void list_add_tail_rcu(struct list_head *node, struct list_head *head)
{
    node->next = head;
    node->prev = head->prev;
    head->prev->next = node;
    head->prev = node;
}

static void list_del_rcu(struct list_head *node)
{
    node->prev->next = node->next;
    node->next->prev = node->prev;
}

typedef int spinlock_t;
#define spin_lock_init(lock) (*(lock) = 0)
#define spin_lock(lock) assert(!(*(lock))++)
#define spin_unlock(lock) assert((*(lock))-- == 1)
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define smp_store_release(ptr, val) (*(ptr) = (val))
#define smp_load_acquire(ptr) (*(ptr))
static void quiesce(void) {}
static void (*kf_synchronize_rcu)(void) = quiesce;
#define kfunc(name) kf_##name
#define vmalloc malloc
#define kvfree free
#define kp_malloc_exec malloc
#define kp_free_exec free
#define page_size 4096
#define flush_icache_all() ((void)0)
#define compact_find_symbol(name) 0
#define kpm_safety_validate(data, len) 0
#define kpm_safety_mark_loading(name) ((void)0)
static int past_admission;

/* Unused kernel services in other entry points of module.c. */
struct file;
struct file *filp_open(const char *, int, int);
int filp_close(struct file *, void *);
loff_t vfs_llseek(struct file *, loff_t, int);
ssize_t kernel_read(struct file *, void *, size_t, loff_t *);
#define unlikely(x) (x)
#define IS_ERR(x) ((x) == NULL)
#define PTR_ERR(x) (-ENOENT)
void compact_init(void), proc_hide_init(void), umount_init(void), selinux_hide_init(void), kpm_safety_init(void);
static void log_ignore(const char *fmt, ...) { (void)fmt; }
#define logkd log_ignore
#define logki log_ignore
#define logke log_ignore
#define logkfd log_ignore
#define logkfi log_ignore
#define logkfe log_ignore
#define pr_err log_ignore

static int init_calls, ctl_calls, exit_calls;
static long benign_init(const char *args, const char *event, void *reserved)
{
    assert(!strcmp(args, "start") && !strcmp(event, "load-test") && reserved == &init_calls);
    init_calls++;
    return 0;
}

static long benign_control(const char *args, char *out, int len)
{
    assert(init_calls == 1 && !strcmp(args, "ping") && len >= 5);
    strcpy(out, "pong");
    ctl_calls++;
    return 17;
}

static long benign_exit(void *reserved)
{
    assert(ctl_calls == 1 && reserved == &exit_calls);
    exit_calls++;
    return 23;
}

static unsigned long symbol_lookup_name(const char *name)
{
    if (!strcmp(name, "benign_init")) return (uintptr_t)benign_init;
    if (!strcmp(name, "benign_control")) return (uintptr_t)benign_control;
    if (!strcmp(name, "benign_exit")) return (uintptr_t)benign_exit;
    return 0;
}

/* A format regression must stop here before any rejected fixture could run. */
static int lifecycle;
static int kpm_safety_check_blacklist(const char *name)
{
    past_admission++;
    return !lifecycle;
}

#include "../kernel/patch/module/module.c"
#include "../kernel/patch/module/relo.c"

/* The benign fixture contains only ABS64 data relocations. */
u32 aarch64_insn_encode_immediate(enum aarch64_insn_imm_type type, u32 insn, u64 imm)
{
    abort();
}

int main(int argc, char **argv)
{
    assert(argc == 3);
    const char *mode = argv[1];
    int len;
    char *data;
    read_file_align(argv[2], &data, &len, 1, KPM_MAX_FILE_SIZE);
    /* Exercise the unaligned embedded-image case on the tools side. */
    char *copy = malloc((size_t)len + 1);
    assert(copy);
    memcpy(copy + 1, data, len);
    kpm_info_t meta;
    int host_rc = get_kpm_info(copy + 1, len, &meta);
    int expected = !strcmp(mode, "reject") ? -ENOEXEC : 0;
    assert(host_rc == expected);

    INIT_LIST_HEAD(&modules.list);
    lifecycle = !strcmp(mode, "with-exit") || !strcmp(mode, "without-exit");
    long rc = load_module(data, len, "start", "load-test", &init_calls);
    if (expected) {
        assert(rc == -ENOEXEC && !past_admission && !init_calls);
        assert(!memcmp(data, copy + 1, len)); /* rejected before rewriting sections */
    } else if (!lifecycle) {
        assert(rc == -EACCES && past_admission == 1); /* fixture reached the blacklist */
    } else {
        assert(rc == 0 && init_calls == 1 && !strcmp(meta.name, "benign"));
        free(data); /* metadata and callback slots must survive release of the input */
        data = NULL;
        char out[8];
        assert(module_control0("benign", "ping", out, sizeof(out)) == 17);
        assert(ctl_calls == 1 && !strcmp(out, "pong"));
        int has_exit = !strcmp(mode, "with-exit");
        assert(unload_module("benign", &exit_calls) == (has_exit ? 23 : 0));
        assert(exit_calls == has_exit && module_control0("benign", "ping", out, sizeof(out)) == -ENOENT);
    }
    free(copy);
    free(data);
    return 0;
}
