/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include <user_event.h>
#include <userd.h>
#include <baselib.h>
#include <log.h>
#include <module.h>
#include <uapi/kpm_event.h>
#include <kpm_safety.h>

int report_user_event(const char *event, const char *args)
{
    const char *safe_event = event ? event : "";
    const char *safe_args = args ? args : "";

    #ifdef ANDROID
    if (lib_strcmp(safe_event, "post-fs-data") == 0) {
        log_boot("post-fs-data: loading ap package config ...\n");
        load_ap_package_config();
        /* Dispatch KPM event */
        module_dispatch_event(KPM_EVENT_POST_FS_DATA, NULL, safe_args);
    }
    if (lib_strcmp(safe_event, "boot-completed") == 0) {
        module_dispatch_event(KPM_EVENT_BOOT_COMPLETED, NULL, safe_args);
        /* Confirm boot succeeded — reset crash protection counter */
        kpm_safety_confirm_boot_completed();
    }
    if (lib_strcmp(safe_event, "uid_listener") == 0 && lib_strcmp(safe_args, "package-list-updated") == 0) {
        int trust_rc = refresh_trusted_manager_state();
        log_boot("boot-completed: trusted manager refresh rc=%d\n", trust_rc);
    }
    #else
    /* Non-Android: still dispatch events */
    if (lib_strcmp(safe_event, "post-fs-data") == 0) {
        module_dispatch_event(KPM_EVENT_POST_FS_DATA, NULL, safe_args);
    }
    if (lib_strcmp(safe_event, "boot-completed") == 0) {
        module_dispatch_event(KPM_EVENT_BOOT_COMPLETED, NULL, safe_args);
        /* Confirm boot succeeded — reset crash protection counter */
        kpm_safety_confirm_boot_completed();
    }
    #endif
    logki("user report event: %s, args: %s\n", safe_event, safe_args);
    return 0;
}
