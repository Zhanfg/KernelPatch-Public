# KernelPatch-Public release provenance

Baseline date: 2026-08-06

## Legacy release finding

The only public release is tagged `0.13.3` and points to commit:

```text
e26a2e14e3b8d60a19dd3c7f354a777faa574f4f
```

However, the `version` header at that exact tagged commit declares:

```c
#define MAJOR 0
#define MINOR 13
#define PATCH 2
```

Therefore the historical `0.13.3` release is mis-versioned. It is retained because PatchNest-Module currently consumes two of its assets, but it must not be used as the template for future publishing.

## Reproducibility result

Both consumed assets have now been reproduced byte-for-byte from the repository source.

| Input | Verified value |
|---|---|
| Source/tag commit | `e26a2e14e3b8d60a19dd3c7f354a777faa574f4f` |
| Arm toolchain | GNU Arm `12.2.rel1` |
| Arm archive SHA-256 | `62d66e0ad7bd7f2a183d236ee301a5c73c737c886c7944aa4f39415aab528daf` |
| Android NDK | `r26b` |
| Embedded compile time | `10:33:25 May 31 2026` |
| `SOURCE_DATE_EPOCH` | `1780223605` |

The original `kpimg` source embeds `__TIME__` and `__DATE__` in `kernel/base/setup.c`. A normal rebuild therefore produces a different digest. Restoring the compile timestamp through `SOURCE_DATE_EPOCH` reproduces the historical asset exactly.

## Trusted legacy assets

| Asset | SHA-256 | Reproduction |
|---|---|---|
| `kpimg-linux` | `7b8cf7e97169d2d73bba2e11653ad5bdbc6fc6251c5507b8d108f4a2e0bcd76f` | Byte-identical |
| `kptools-android` | `ebf9b8eb17b4b3a6b1d4959402033bb1c6c4044d0e2532d480c34d1f412d5225` | Byte-identical |

This proves source and build provenance for the consumed files. It does not correct the release version mismatch or establish device compatibility.

## Build warnings found

The reproducibility build also exposed warnings that require a separate correctness PR:

- implicit declaration of `is_trusted_manager_uid` in `sucompat.c`;
- implicit declaration of `is_trusted_manager_uid` in `supercmd.c`;
- unused `rc` in `supercall.c`;
- implicit declaration of `umount_init` in `module.c`;
- `kpimg.elf` has an RWX load segment;
- two `uint64_t` format mismatches in `tools/kallsym.c`;
- outdated CMake minimum-version declarations.

These warnings are not being silently fixed in the provenance PR because doing so would change the historical binary. They must be corrected and tested as a new source version.

## Restart policy

1. Existing `0.13.3` assets remain immutable.
2. Automatic or manual release replacement is disabled.
3. Pull requests build with read-only repository permissions.
4. The Arm cross toolchain, Android NDK and legacy assets are pinned and verified.
5. A future corrected release derives its tag from the source version, not from a free-form workflow input.
6. The corrected release uses a new tag and never overwrites `0.13.3`.
7. PatchNest-Module updates this dependency only after build verification and real-device Boot/KPM regression tests.

## Next corrected release

The final tag is intentionally not selected in this baseline. It must reflect the actual corrected source version and compatibility decision after the warning and runtime audit. A tag such as `0.13.3-r1` would still be misleading while the source declares `0.13.2`.
