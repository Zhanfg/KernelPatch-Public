/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Process hiding — renames kpatch/kptools processes to avoid detection.
 *
 * Approach: provide a supercall that renames the current task's comm field.
 * Userspace (service.sh) uses a wrapper that calls kpatch then renames itself.
 * Also: hook the task creation to auto-rename kpatch/kptools processes.
 *
 * Since kpatch/kptools are short-lived commands (ms-level), the risk is minimal.
 * This provides defense-in-depth.
 */

#include <ktypes.h>
#include <common.h>
#include <log.h>
#include <linux/string.h>
#include <asm/current.h>
#include <taskext.h>
#include <kputils.h>
#include <uapi/asm-generic/errno.h>

/* Names to match for auto-rename */
static const char *hide_names[] = { "kpatch", "kptools", "kp", NULL };

/* Innocuous replacement names */
static const char *fake_names[] = { "kworker/u16:2", "kworker/u16:3", "kworker/u16:4" };

/* Rename current process comm field */
int proc_hide_rename_current(const char *new_name)
{
    if (!new_name || !new_name[0]) return -EINVAL;

    struct task_struct *task = current;
    if (task_struct_offset.comm_offset <= 0) return -ENOSYS;

    char *comm = (char *)((uintptr_t)task + task_struct_offset.comm_offset);
    strncpy(comm, new_name, 15);
    comm[15] = '\0';

    logkfi("proc_hide: renamed to '%s'\n", new_name);
    return 0;
}

/* Check if current process should be hidden and auto-rename if so */
void proc_hide_check_and_rename(void)
{
    if (task_struct_offset.comm_offset <= 0) return;

    struct task_struct *task = current;
    const char *comm = (const char *)((uintptr_t)task + task_struct_offset.comm_offset);

    for (int i = 0; hide_names[i]; i++) {
        if (!strncmp(comm, hide_names[i], 16)) {
            proc_hide_rename_current(fake_names[i]);
            return;
        }
    }
}

int proc_hide_init(void)
{
    log_boot("proc_hide: initialized (auto-rename via supercall or check_and_rename)\n");
    return 0;
}

void proc_hide_exit(void)
{
    /* Nothing to clean up */
}
