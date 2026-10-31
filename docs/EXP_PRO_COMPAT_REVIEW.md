# KPatch-Next EXP / Pro compatibility review (2026-10-31)

Reviewed upstreams:
- EXP core: https://github.com/741afb7/KPatch-Next-EXP at `0bf6e6321253d83d9eff4cdbfd4fe6b9b81c731f`
- EXP Module: https://github.com/741afb7/KPatch-Next-Module-EXP
- Pro core: https://github.com/yyyy1314/KPatch-Next-Pro (0.13.9)
- Pro Module: https://github.com/yyyy1314/KPatch-Next-Module-Pro

Main PatchNest user-space: https://github.com/Zhanfg/PatchNest/pull/14
Active dual-backend core WIP: https://github.com/Zhanfg/KernelPatch-Public/pull/16

## Integrations in this review branch

- Optional, freestanding `kernel/include/patchnest_argv_v1.h` used by KPM
  authors to decode the **existing** single-string kernel callback field
  as opt-in versioned, length-delimited argv slices.
- No change to existing callback ABI, kernel hook paths, boot patch format,
  supercall ID mapping, KPM lifetime or Root Core.
- `tests/patchnest_argv_v1_test.c` exercises malformed/truncated inputs,
  empty arguments, arbitrary UTF-8, length limits and legacy fallback.
- User-space encoder resides in the companion PatchNest PR #14.
- Does NOT change KPM code automatically; a KPM must opt in to decoding.

## Upstream changes reviewed but **not blindly copied**

| EXP area | Decision | Reason |
| --- | --- | --- |
| LKM backend (2026-10-23) | BLOCKED pending port | `lkm/hook/hook_engine.c` requires `KP_HOOK_EXTERNAL_CHAIN_PREPARE`, absent from our `kernel/base/hook.c`; LKM root-only syscall-45 handler also conflicts with potential SukiSU ownership |
| 6.6+ LKM module/fixmap (2026-10-23) | BLOCKED with LKM | Requires matching DDK/KMI, KCFI/BTI, module signing, runtime symbol resolution |
| BTF offsets (2026-10-14) | REVIEW ONLY | Cross-cutting preset, assembly offsets, tools and runtime interfaces; cannot add selectively without ABI/boot tests |
| MTE/KASAN cred scans (2026-10-28) | REVIEW ONLY | Requires hardware tagging and field bounds verification on actual target |
| ARM64 image_size / BTI entry (2026-10-28) | REVIEW ONLY | Bootloader/entry-memory critical; cannot claim boot safety from host CI |
| KPM RCU lifetime (2026-10-10) | RECONCILE | Our main already includes 2026-10-29 module lifetime and RCU fixes; line-by-line reconcile before cherry-pick |
| Pro 0.13.9 | REFERENCE | Older baseline than EXP 0.13.14; do not downgrade existing core based on label |

**Release gate:** never auto-enable new KPM or LKM hooks, overwrite boot,
or publish a flashable artifact based only on host/CI success. Need target
KMI build, hardening, recoverability, and physical-device validation.
