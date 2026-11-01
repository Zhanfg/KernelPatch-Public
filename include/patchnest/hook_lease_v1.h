/* SPDX-License-Identifier: GPL-2.0-or-later */
/* PatchNest hook lease v1: bounded, allocation-free resource ledger.
 *
 * NOT a kernel hook interceptor. Every modifying function MUST be called
 * under the same external mutex/spinlock. Never sleep with a spinlock held.
 * A state change never installs/removes or drains an actual hook.
 *
 * The kernel broker must validate callers and control *all* competing hook
 * APIs before this can become a security or exclusivity boundary.
 */
#ifndef PATCHNEST_HOOK_LEASE_V1_H
#define PATCHNEST_HOOK_LEASE_V1_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef u32 pn_lease_u32;
typedef u64 pn_lease_u64;
#else
#include <stdint.h>
typedef uint32_t pn_lease_u32;
typedef uint64_t pn_lease_u64;
#endif

#define PN_LEASE_V1_CAPACITY 64u

enum pn_lease_domain {
    PN_LEASE_DOMAIN_SYSCALL = 1,
    PN_LEASE_DOMAIN_VFS = 2,
    PN_LEASE_DOMAIN_LSM = 3,
    PN_LEASE_DOMAIN_KPM_RUNTIME = 4,
    PN_LEASE_DOMAIN_ROOT_CORE = 5
};
enum pn_lease_state {
    PN_LEASE_EMPTY = 0,
    PN_LEASE_RESERVED = 1,
    PN_LEASE_ACTIVE = 2,
    PN_LEASE_DRAINING = 3
};
enum pn_lease_result {
    PN_LEASE_OK = 0,
    PN_LEASE_ERR_INVALID = -1,
    PN_LEASE_ERR_CONFLICT = -2,
    PN_LEASE_ERR_FULL = -3,
    PN_LEASE_ERR_STALE = -4,
    PN_LEASE_ERR_STATE = -5,
    PN_LEASE_ERR_EXHAUSTED = -6
};

struct pn_lease_entry {
    pn_lease_u64 target;
    pn_lease_u64 token;
    pn_lease_u32 owner_id;
    pn_lease_u32 domain;
    pn_lease_u32 state;
};
struct pn_lease_table {
    pn_lease_u64 last_token;
    struct pn_lease_entry entries[PN_LEASE_V1_CAPACITY];
};

static inline void pn_lease_init(struct pn_lease_table *table)
{
    pn_lease_u32 i;
    if (!table) return;
    table->last_token = 0;
    for (i = 0; i < PN_LEASE_V1_CAPACITY; ++i) {
        table->entries[i].target = 0;
        table->entries[i].token = 0;
        table->entries[i].owner_id = 0;
        table->entries[i].domain = 0;
        table->entries[i].state = PN_LEASE_EMPTY;
    }
}

static inline int pn_lease_valid_domain(pn_lease_u32 domain)
{
    return domain >= PN_LEASE_DOMAIN_SYSCALL &&
           domain <= PN_LEASE_DOMAIN_ROOT_CORE;
}

/* Results are snapshots, not direct pointers to the mutable table. */
static inline int pn_lease_lookup(const struct pn_lease_table *table,
                                  pn_lease_u32 domain, pn_lease_u64 target,
                                  struct pn_lease_entry *out)
{
    pn_lease_u32 i;
    if (!table || !out || !pn_lease_valid_domain(domain))
        return PN_LEASE_ERR_INVALID;
    for (i = 0; i < PN_LEASE_V1_CAPACITY; ++i) {
        const struct pn_lease_entry *e = &table->entries[i];
        if (e->state != PN_LEASE_EMPTY && e->domain == domain &&
            e->target == target) {
            *out = *e;
            return PN_LEASE_OK;
        }
    }
    return PN_LEASE_ERR_STALE;
}

/* All consumers of a given hook domain + target must use this one broker
 * for exclusivity to hold. Even same-owner duplicate claims are rejected,
 * preventing repeated KPM initialization from overwriting the same hook.
 */
static inline int pn_lease_claim(struct pn_lease_table *table,
                                 pn_lease_u32 owner_id, pn_lease_u32 domain,
                                 pn_lease_u64 target, pn_lease_u64 *out_token)
{
    pn_lease_u32 i;
    struct pn_lease_entry *empty = 0;
    if (!table || !out_token || !owner_id || !pn_lease_valid_domain(domain))
        return PN_LEASE_ERR_INVALID;
    *out_token = 0;
    for (i = 0; i < PN_LEASE_V1_CAPACITY; ++i) {
        struct pn_lease_entry *e = &table->entries[i];
        if (e->state != PN_LEASE_EMPTY) {
            if (e->domain == domain && e->target == target)
                return PN_LEASE_ERR_CONFLICT;
        } else if (!empty) {
            empty = e;
        }
    }
    if (!empty) return PN_LEASE_ERR_FULL;
    if (table->last_token == ~(pn_lease_u64)0)
        return PN_LEASE_ERR_EXHAUSTED;
    ++table->last_token;
    empty->target = target;
    empty->token = table->last_token;
    empty->owner_id = owner_id;
    empty->domain = domain;
    empty->state = PN_LEASE_RESERVED;
    *out_token = empty->token;
    return PN_LEASE_OK;
}

/* Modifying operations are token AND owner gated. A stale token cannot
 * release a later claim for the same target even after slot reuse.
 */
static inline int pn_lease_transition(struct pn_lease_table *table,
                                      pn_lease_u32 owner_id,
                                      pn_lease_u64 token,
                                      pn_lease_u32 next_state,
                                      int drained)
{
    pn_lease_u32 i;
    if (!table || !owner_id || !token) return PN_LEASE_ERR_INVALID;
    for (i = 0; i < PN_LEASE_V1_CAPACITY; ++i) {
        struct pn_lease_entry *e = &table->entries[i];
        if (e->state == PN_LEASE_EMPTY || e->token != token) continue;
        if (e->owner_id != owner_id) return PN_LEASE_ERR_STALE;
        if (next_state == PN_LEASE_ACTIVE &&
            e->state == PN_LEASE_RESERVED) {
            e->state = PN_LEASE_ACTIVE;
            return PN_LEASE_OK;
        }
        if (next_state == PN_LEASE_DRAINING &&
            (e->state == PN_LEASE_ACTIVE ||
             e->state == PN_LEASE_RESERVED)) {
            e->state = PN_LEASE_DRAINING;
            return PN_LEASE_OK;
        }
        if (next_state == PN_LEASE_EMPTY &&
            e->state == PN_LEASE_DRAINING && drained == 1) {
            /* 'drained' is an external attestation, not an RCU operation. */
            e->target = 0;
            e->token = 0;
            e->owner_id = 0;
            e->domain = 0;
            e->state = PN_LEASE_EMPTY;
            return PN_LEASE_OK;
        }
        return PN_LEASE_ERR_STATE;
    }
    return PN_LEASE_ERR_STALE;
}
#endif /* PATCHNEST_HOOK_LEASE_V1_H */
