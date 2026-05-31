/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM compact symbol resolver — inspired by ReSukiSU compact.c.
 * Exposes curated kernel/KP functions to KPM modules via find_symbol().
 */

#ifndef _KP_COMPACT_H_
#define _KP_COMPACT_H_

#include <ktypes.h>

/*
 * Resolve a symbol by name. KPM modules call this to get function pointers.
 * Search order:
 *   1. Curated compact symbol table (KP functions)
 *   2. symbol_lookup_name() (KP internal symbols)
 *   3. kallsyms_lookup_name() (kernel symbols, if available)
 *
 * Returns address or 0 if not found.
 */
unsigned long compact_find_symbol(const char *name);

#endif
