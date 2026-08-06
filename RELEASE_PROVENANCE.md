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

Therefore the historical `0.13.3` release is not a correctly versioned release. It is retained because PatchNest-Module currently consumes two of its assets, but it must not be used as the template for future publishing.

## Trusted legacy assets

PatchNest-Module currently pins the following Runner-calculated SHA-256 values:

| Asset | SHA-256 |
|---|---|
| `kpimg-linux` | `7b8cf7e97169d2d73b2e11653ad5bdbc6fc6251c5507b8d108f4a2e0bcd76f` |
| `kptools-android` | `ebf9b8eb17b4b3a6b1d4959402033bb1c6c4044d0e2532d480c34d1f412d5225` |

These hashes identify the legacy files; they do not correct the version mismatch or prove device compatibility.

## Restart policy

1. Existing `0.13.3` assets remain immutable.
2. Automatic or manual release replacement is disabled.
3. Pull requests must build with read-only repository permissions.
4. The Arm cross toolchain and Android NDK must be pinned and verified.
5. A future corrected release must derive its tag from the source version, not from a free-form workflow input.
6. The corrected release must use a new tag and must not overwrite `0.13.3`.
7. PatchNest-Module may update its dependency only after build verification and real-device Boot/KPM regression tests.

## Next corrected release

The final tag is intentionally not chosen in this baseline. It must reflect the actual source version and compatibility decision after the code audit. Candidates such as `0.13.3-r1` are invalid if the source still reports `0.13.2`.
