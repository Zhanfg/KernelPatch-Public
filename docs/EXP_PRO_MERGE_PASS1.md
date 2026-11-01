# EXP / Pro convergence — pass 1 (2026-10-31)

Scope: isolated, reviewable source integration. **Not a boot-tested release.**

Baseline: Zhanfg/KernelPatch-Public main (3d07345e1a92).
Reference: 741afb7/KPatch-Next-EXP @ 0bf6e6321253d83d9eff4cdbfd4fe6b9b81c731f
(and yyyy1314/KPatch-Next-Pro 0.13.9).

## Ported

1. EXP `kernel/base/hotpatch.c` legacy ARM64 text patch selection.
   For pre-4.6 kernels use the legacy symbol/fallback strategy; on pre-4.15
   skip the vmalloc alias fast path. Linux 6.6 uses the pre-existing
   stop_machine/alias strategy. No changes to supercall IDs or Root Core.
2. A concrete KPM `PNARGV1` consumer and opt-in PUBLIC1158 event callback.
   Legacy callbacks still receive their existing raw string.
3. Host-only contract/static CI checks.

## Not ported / not implicitly enabled

- EXP LKM (`kernelpatch.ko`): hook engine expects
  `KP_HOOK_EXTERNAL_CHAIN_PREPARE` absent from this baseline. Also conflicts
  with possible root-manager ownership of syscall 45. Requires KMI-specific
  build, symbol and unload-life-cycle validation.
- EXP BTF offsets, MTE/KASAN scans and boot Image/BTI entry changes:
  assembly/layout/cred-scanning impact, require target KMI and boot evidence.
- EXP RCU fix is superseded by the PatchNest own module lifetime fixes
  on main (PRs #17/#18); do not double-apply.
- Pro 0.13.9 is a reference, not a justified downgrade from main.

## Required gates before main/flash

1. Successful host unit/static jobs, GCC/Clang.
2. ARM64 KPM and kpimg builds with known target toolchains.
3. ABI compatibility: PUBLIC1158 / NEXT2026, legacy raw strings and PNARGV1.
4. Real boot/load/control/event/unload tests with rollback capability.
5. Never auto-flash or load new KPM/LKM as part of CI.
