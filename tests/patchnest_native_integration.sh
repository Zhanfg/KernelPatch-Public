#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Host-only Kbuild staging regression. Does not compile a Linux kernel.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir -p "$tmp/linux/drivers" "$tmp/linux/include/linux"
printf 'menu "Device Drivers"\nendmenu\n' > "$tmp/linux/drivers/Kconfig"
printf 'obj-y += base/\n' > "$tmp/linux/drivers/Makefile"
printf 'original\n' > "$tmp/linux/drivers/original.txt"
export PATCHNEST_KERNEL_SOURCE="$tmp/linux"
sh "$root/ports/linux-native/integrate.sh" > "$tmp/dryrun"
[ ! -e "$tmp/linux/drivers/patchnest" ]
PATCHNEST_APPLY=1 sh "$root/ports/linux-native/integrate.sh"
PATCHNEST_APPLY=1 sh "$root/ports/linux-native/integrate.sh"
[ "$(grep -Fc 'source "drivers/patchnest/Kconfig"' "$tmp/linux/drivers/Kconfig")" = 1 ]
[ "$(grep -Fc 'obj-$(CONFIG_PATCHNEST_CORE) += patchnest/' "$tmp/linux/drivers/Makefile")" = 1 ]
grep -Fq '#include <linux/patchnest_runtime_abi.h>' "$tmp/linux/drivers/patchnest/patchnest_native.c"
cmp "$tmp/linux/drivers/original.txt" /dev/null >/dev/null && exit 1 || :
grep -Fq 'original' "$tmp/linux/drivers/original.txt"
# Conflicting preexisting driver must never be overwritten.
printf 'different implementation\n' > "$tmp/linux/drivers/patchnest/patchnest_native.c"
if PATCHNEST_APPLY=1 sh "$root/ports/linux-native/integrate.sh" >/dev/null 2>&1; then
    echo "ERROR: conflicting implementation overwritten" >&2
    exit 1
fi
echo "PASS: opt-in, idempotent integration and conflict rejection"
