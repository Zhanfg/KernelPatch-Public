# PatchNest Hook Lease Ledger v1 (2026-11-01)

Scope: a bounded C reference implementation for **voluntary** hook ownership
coordination. Not wired to the KernelPatch hooking engine, Root Core, SUSFS,
a KPM loader, or any existing syscall.

## Invariants

- Single (domain, target) claim at a time, including same-owner duplicates.
- 64 fixed slots, no allocation, no kernel private headers, no syscall IDs,
  no Root Core mutation, no text patches.
- Claim generates an increasing token, starts RESERVED.
- Activate: RESERVED -> ACTIVE.
- Unload: RESERVED/ACTIVE -> DRAINING -> EMPTY only with an explicit
  \`drained=1\` acknowledgment after external synchronization.
- Old token and wrong owner never release a subsequent claim.
- No automatic refcount or same-owner re-entrant hooks; errors are explicit.

## Critical limitations

This is not yet an enforced kernel lease. It is safe to compile and unit-test,
but a full owner of KPM/LKM hooks must ALSO:

1. Intercept every relevant hook registration API or explicitly require all
   clients to cooperate. Other modules can still bypass this ledger.
2. Authenticate/assign owner IDs; calling code can currently provide arbitrary
   integers. Do not accept them from userspace unvalidated.
3. Hold a single real lock around every lookup, claim and transition.
4. Guarantee RCU grace periods, callback draining, function-pointer restoration
   and executable-memory lifetime *before* calling final release.
5. Verify the target's original instruction/pointer, PAC/BTI/KCFI behavior,
   SELinux and KMI before actually installing a hook.
6. Use distinct verified providers for Root Core, SUSFS-LKM and KPM; never
   assume that seeing \`/proc/modules\` proves exclusive ownership.

A host test passing says **nothing** about whether a kernel is safe to boot.
The only purpose of the ledger now is a versioned interface and deterministic
conflict/lifetime contract to integrate into future native and patched
backends without changing today's Root Core behavior.
