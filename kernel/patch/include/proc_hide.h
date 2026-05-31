/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Process hiding — provides process rename capability.
 */

#ifndef _KP_PROC_HIDE_H_
#define _KP_PROC_HIDE_H_

int proc_hide_rename_current(const char *new_name);
void proc_hide_check_and_rename(void);
int proc_hide_init(void);
void proc_hide_exit(void);

#endif
