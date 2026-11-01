/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "../include/patchnest/hook_lease_v1.h"

int main(void)
{
    struct pn_lease_table table;
    struct pn_lease_entry snapshot;
    pn_lease_u64 first = 0, second = 0, t = 0;
    pn_lease_u32 i;

    pn_lease_init(&table);
    assert(pn_lease_claim(&table, 0, PN_LEASE_DOMAIN_SYSCALL, 45, &t) == PN_LEASE_ERR_INVALID);
    assert(pn_lease_claim(&table, 1, 0, 45, &t) == PN_LEASE_ERR_INVALID);
    assert(pn_lease_claim(&table, 1, PN_LEASE_DOMAIN_SYSCALL, 45, 0) == PN_LEASE_ERR_INVALID);

    assert(pn_lease_claim(&table, 1, PN_LEASE_DOMAIN_SYSCALL, 45, &first) == PN_LEASE_OK);
    assert(first != 0);
    assert(pn_lease_claim(&table, 1, PN_LEASE_DOMAIN_SYSCALL, 45, &t) == PN_LEASE_ERR_CONFLICT);
    assert(pn_lease_claim(&table, 2, PN_LEASE_DOMAIN_SYSCALL, 45, &t) == PN_LEASE_ERR_CONFLICT);
    assert(pn_lease_lookup(&table, PN_LEASE_DOMAIN_SYSCALL, 45, &snapshot) == PN_LEASE_OK);
    assert(snapshot.state == PN_LEASE_RESERVED && snapshot.owner_id == 1);
    assert(snapshot.token == first);
    assert(pn_lease_transition(&table, 2, first, PN_LEASE_ACTIVE, 0) == PN_LEASE_ERR_STALE);
    assert(pn_lease_transition(&table, 1, first, PN_LEASE_EMPTY, 1) == PN_LEASE_ERR_STATE);
    assert(pn_lease_transition(&table, 1, first, PN_LEASE_ACTIVE, 0) == PN_LEASE_OK);
    assert(pn_lease_transition(&table, 1, first, PN_LEASE_ACTIVE, 0) == PN_LEASE_ERR_STATE);
    assert(pn_lease_transition(&table, 1, first, PN_LEASE_DRAINING, 0) == PN_LEASE_OK);
    assert(pn_lease_claim(&table, 2, PN_LEASE_DOMAIN_SYSCALL, 45, &t) == PN_LEASE_ERR_CONFLICT);
    assert(pn_lease_transition(&table, 1, first, PN_LEASE_EMPTY, 0) == PN_LEASE_ERR_STATE);
    assert(pn_lease_transition(&table, 1, first, PN_LEASE_EMPTY, 1) == PN_LEASE_OK);
    assert(pn_lease_claim(&table, 2, PN_LEASE_DOMAIN_SYSCALL, 45, &second) == PN_LEASE_OK);
    assert(second > first);
    assert(pn_lease_transition(&table, 1, first, PN_LEASE_DRAINING, 0) == PN_LEASE_ERR_STALE);
    assert(pn_lease_transition(&table, 2, first, PN_LEASE_DRAINING, 0) == PN_LEASE_ERR_STALE);
    assert(pn_lease_claim(&table, 3, PN_LEASE_DOMAIN_VFS, 45, &t) == PN_LEASE_OK);

    pn_lease_init(&table);
    for (i = 0; i < PN_LEASE_V1_CAPACITY; ++i)
        assert(pn_lease_claim(&table, 1, PN_LEASE_DOMAIN_SYSCALL, i, &t) == PN_LEASE_OK);
    assert(pn_lease_claim(&table, 1, PN_LEASE_DOMAIN_LSM, 500, &t) == PN_LEASE_ERR_FULL);

    pn_lease_init(&table);
    table.last_token = UINT64_MAX;
    assert(pn_lease_claim(&table, 1, PN_LEASE_DOMAIN_VFS, 0, &t) == PN_LEASE_ERR_EXHAUSTED);
    assert(pn_lease_lookup(&table, PN_LEASE_DOMAIN_SYSCALL, 45, &snapshot) == PN_LEASE_ERR_STALE);

    puts("PatchNest hook lease v1 host tests: PASS");
    return 0;
}
