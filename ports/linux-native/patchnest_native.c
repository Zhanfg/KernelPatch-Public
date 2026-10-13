// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PatchNest in-tree Linux adapter, bring-up stage.
 *
 * This device currently reports native-backend presence and zero runtime
 * capabilities. It must not claim that KPM loading is operational.
 *
 * Integration: copy ports/linux-native into drivers/patchnest, copy
 * include/patchnest into include/patchnest, source its Kconfig and
 * add the directory to drivers/Makefile.
 */
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include "../../include/patchnest/runtime_abi.h"

static long patchnest_native_ioctl(struct file *file,
                                   unsigned int cmd, unsigned long arg)
{
    struct patchnest_status_v1 status;
    void __user *user = (void __user *)arg;

    (void)file;
    if (cmd != PATCHNEST_IOCTL_STATUS)
        return -ENOTTY;
    if (!user || copy_from_user(&status, user, sizeof(status)))
        return -EFAULT;

    if (status.struct_size != sizeof(status) ||
        (status.abi_version >> 16) != PATCHNEST_ABI_MAJOR)
        return -EPROTONOSUPPORT;
    if (status.abi_version & 0xffffu)
        return -EPROTONOSUPPORT;

    /* Fail closed: advertise no KPM capability until shared runtime works. */
    memset(&status, 0, sizeof(status));
    status.struct_size = sizeof(status);
    status.abi_version = PATCHNEST_ABI_VERSION;
    status.backend = PATCHNEST_BACKEND_BUILTIN;
    status.capabilities = 0;
    status.safety_state = PATCHNEST_SAFETY_NOT_READY;

    if (copy_to_user(user, &status, sizeof(status)))
        return -EFAULT;
    return 0;
}

static const struct file_operations patchnest_native_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = patchnest_native_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = patchnest_native_ioctl,
#endif
    .llseek = no_llseek,
};

static struct miscdevice patchnest_native_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "patchnest",
    .fops = &patchnest_native_fops,
    .mode = 0600,
};

static int __init patchnest_native_init(void)
{
    return misc_register(&patchnest_native_device);
}
device_initcall(patchnest_native_init);
