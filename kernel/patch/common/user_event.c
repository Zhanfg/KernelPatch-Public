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

extern int kp_safe_mode;

int report_user_event(const char *event, const char *args)
{
    const char *safe_event = event ? event : "";
    const char *safe_args = args ? args : "";

    if (lib_strcmp(safe_event, "post-fs-data") == 0) {
        int safety_rc = kpm_safety_persist_boot_attempt();
        if (safety_rc != 0) {
            kp_safe_mode = 1;
            if (safety_rc < 0)
                log_boot("kpm_safety: persistent state degraded rc=%d; fail-closed safe mode\n", safety_rc);
            else
                log_boot("kpm_safety: previous failed-boot threshold reached; safe mode\n");
        }

        #ifdef ANDROID
        log_boot("post-fs-data: loading ap package config ...\n");
        load_ap_package_config();
        #endif

        /* Do not execute KPM post-fs-data callbacks after a safety failure. */
        if (safety_rc == 0)
            module_dispatch_event(KPM_EVENT_POST_FS_DATA, NULL, safe_args);
    }

    if (lib_strcmp(safe_event, "boot-completed") == 0) {
        int confirm_rc;

        /* Safe-mode boots still need a successful-boot confirmation so the
         * next boot can recover instead of remaining permanently latched. */
        if (!kp_safe_mode)
            module_dispatch_event(KPM_EVENT_BOOT_COMPLETED, NULL, safe_args);

        #ifdef ANDROID
        {
            int trust_rc = refresh_trusted_manager_state();
            log_boot("boot-completed: trusted manager refresh rc=%d\n", trust_rc);
        }
        #endif

        confirm_rc = kpm_safety_confirm_boot_completed();
        if (confirm_rc)
            log_boot("kpm_safety: boot-completed confirmation failed rc=%d; state remains unconfirmed\n", confirm_rc);
    }

    #ifdef ANDROID
    if (lib_strcmp(safe_event, "uid_listener") == 0 && lib_strcmp(safe_args, "package-list-updated") == 0) {
        int trust_rc = refresh_trusted_manager_state();
        log_boot("uid-listener: trusted manager refresh rc=%d\n", trust_rc);
    }
    #endif

    logki("user report event: %s, args: %s\n", safe_event, safe_args);
    return 0;
}
