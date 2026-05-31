/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM event system — inspired by ReSukiSU/SukiSU-Ultra.
 * Defines structured events that KPM modules can subscribe to.
 */

#ifndef _KP_UAPI_KPM_EVENT_H_
#define _KP_UAPI_KPM_EVENT_H_

enum kpm_event {
    KPM_EVENT_NONE = 0,
    KPM_EVENT_PRE_KERNEL_INIT,    /* before kernel init stage */
    KPM_EVENT_POST_KERNEL_INIT,   /* after kernel init stage */
    KPM_EVENT_POST_FS_DATA,       /* /data mounted, sepolicy loaded */
    KPM_EVENT_BOOT_COMPLETED,     /* system fully booted */
    KPM_EVENT_MODULE_LOADED,      /* another KPM was loaded */
    KPM_EVENT_MODULE_UNLOADED,    /* another KPM was unloaded */
    KPM_EVENT_MAX,
};

struct kpm_event_data {
    enum kpm_event event;
    const char *source_name;    /* name of module that triggered MODULE_LOADED/UNLOADED */
    const char *args;           /* event-specific string args */
    void *reserved;
};

#endif
