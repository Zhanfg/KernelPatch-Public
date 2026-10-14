#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Safely stage the PatchNest built-in status adapter into a kernel tree.
# No arguments. Set PATCHNEST_KERNEL_SOURCE and PATCHNEST_APPLY=1 to apply.
# This does not configure KPM or generate an AK3 archive.
set -eu
SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SELF_DIR/../.." && pwd)
KERNEL=${PATCHNEST_KERNEL_SOURCE:-}
if [ -z "$KERNEL" ]; then
    if [ -t 0 ]; then
        printf 'Kernel source directory: '
        IFS= read -r KERNEL
    else
        echo "ERROR: PATCHNEST_KERNEL_SOURCE is required in CI" >&2
        exit 2
    fi
fi

[ -d "$KERNEL" ] || { echo "ERROR: no kernel source at $KERNEL" >&2; exit 2; }
KERNEL=$(CDPATH= cd -- "$KERNEL" && pwd)
case "$KERNEL" in
    /|"$PROJECT_DIR"|"$PROJECT_DIR"/*)
        echo "ERROR: refuse to alter root or PatchNest source" >&2; exit 2 ;;
esac
for required in drivers/Makefile drivers/Kconfig include/linux; do
    [ -e "$KERNEL/$required" ] || {
        echo "ERROR: incomplete Linux kernel tree ($required missing)" >&2
        exit 2
    }
done
grep -qE '(^|[[:space:]])ARM64|^#' "$KERNEL/drivers/Kconfig" || true
if [ "${PATCHNEST_APPLY:-0}" != "1" ]; then
    echo "DRY RUN: validated kernel tree $KERNEL"
    echo "Would install drivers/patchnest + include/linux/patchnest_runtime_abi.h"
    echo "Would update drivers/{Makefile,Kconfig} idempotently."
    echo "Set PATCHNEST_APPLY=1 to explicitly apply."
    exit 0
fi

# Preflight ALL destination files before creating anything.
# Reject symlinked adapter trees and conflicting prior implementations.
dst="$KERNEL/drivers/patchnest"
abi_dst="$KERNEL/include/linux/patchnest_runtime_abi.h"
if [ -L "$dst" ] || [ -L "$abi_dst" ]; then
    echo "ERROR: symlinked destination is not trusted" >&2
    exit 1
fi
if [ -e "$abi_dst" ] && ! cmp -s "$PROJECT_DIR/include/patchnest/runtime_abi.h" "$abi_dst"; then
    echo "ERROR: ABI header differs, refusing overwrite" >&2
    exit 1
fi
for file in Kconfig Makefile; do
    if [ -e "$dst/$file" ] && ! cmp -s "$SELF_DIR/$file" "$dst/$file"; then
        echo "ERROR: existing $file differs, refusing overwrite" >&2
        exit 1
    fi
done
if [ -f "$dst/patchnest_native.c" ] &&
   ! cmp -s "$SELF_DIR/patchnest_native.c" "$dst/patchnest_native.c"; then
    # The installed file has an adjusted include, compare a normalized copy.
    tmp=$(mktemp) || exit 1
    sed 's|#include "../../include/patchnest/runtime_abi.h"|#include <linux/patchnest_runtime_abi.h>|' \
        "$SELF_DIR/patchnest_native.c" > "$tmp"
    if ! cmp -s "$tmp" "$dst/patchnest_native.c"; then
        rm -f "$tmp"
        echo "ERROR: unknown existing native adapter; review conflicts manually" >&2
        exit 1
    fi
    rm -f "$tmp"
fi

mkdir -p "$dst"
cp "$SELF_DIR/Kconfig" "$dst/Kconfig"
cp "$SELF_DIR/Makefile" "$dst/Makefile"
tmp=$(mktemp) || exit 1
trap 'rm -f "$tmp"' EXIT HUP INT TERM
sed 's|#include "../../include/patchnest/runtime_abi.h"|#include <linux/patchnest_runtime_abi.h>|' \
    "$SELF_DIR/patchnest_native.c" > "$tmp"
cp "$tmp" "$dst/patchnest_native.c"
cp "$PROJECT_DIR/include/patchnest/runtime_abi.h" \
    "$KERNEL/include/linux/patchnest_runtime_abi.h"

if ! grep -Fq 'source "drivers/patchnest/Kconfig"' "$KERNEL/drivers/Kconfig"; then
    printf '\nsource "drivers/patchnest/Kconfig"\n' >> "$KERNEL/drivers/Kconfig"
fi
if ! grep -Fq 'obj-$(CONFIG_PATCHNEST_CORE) += patchnest/' "$KERNEL/drivers/Makefile"; then
    printf '\nobj-$(CONFIG_PATCHNEST_CORE) += patchnest/\n' >> "$KERNEL/drivers/Makefile"
fi

echo "Integrated status-only driver at: $KERNEL/drivers/patchnest"
echo "CONFIG_PATCHNEST_CORE is default n. This does NOT enable KPM loading."
