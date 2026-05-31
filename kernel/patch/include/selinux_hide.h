/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SELinux status hiding — prevents apps from detecting policy modifications.
 */

#ifndef _KP_SELINUX_HIDE_H_
#define _KP_SELINUX_HIDE_H_

int selinux_hide_init(void);
void selinux_hide_exit(void);
int selinux_hide_is_active(void);
int selinux_hide_get_original_enforcing(void);

#endif
