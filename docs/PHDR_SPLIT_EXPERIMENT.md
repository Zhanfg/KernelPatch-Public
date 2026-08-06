# kpimg PHDR split experiment

Experiment date: 2026-08-06

## Status

**Build and binary-layout checks pass. Merge is blocked on physical-device validation.**

The experiment replaces the single intermediate `RWE` LOAD segment with six permission-specific LOAD segments while keeping every raw `kpimg` byte and required linker symbol unchanged.

## Controlled comparison

The baseline and experiment were built on the same GitHub Runner with the same pinned GNU Arm toolchain, strict compiler flags, and `SOURCE_DATE_EPOCH=1786030938`.

| Property | Baseline | Experiment |
|---|---|---|
| Baseline commit | `0bdf0094f7c90cead5dd1a221af957ea2ed01948` | — |
| Raw SHA-256 | `579d38d8297497a5a8842446b94bbc90ec865490973bc45745fbc99098c01735` | `579d38d8297497a5a8842446b94bbc90ec865490973bc45745fbc99098c01735` |
| Raw size | `183744` bytes | `183744` bytes |
| Raw comparison | — | Byte-identical |
| Required symbols | — | Identical |

## Measured LOAD segments

| # | Offset / Vaddr | Size | Flags | Covered output section |
|---:|---:|---:|---|---|
| 0 | `0xd000` | `0x1000` | `RW` | `.setup.data` |
| 1 | `0xe000` | `0x378` | `RE` | `.setup.text` |
| 2 | `0xe380` | `0xa0` | `RW` | `.setup.map.data` |
| 3 | `0xe420` | `0x580` | `RE` | `.setup.map.text` |
| 4 | `0x10000` | `0x1b470` | `RE` | `.kp.text` |
| 5 | `0x30000` | `0x9dc0` | `RW` | `.kp.data` |

All six LOAD segments are readable. No LOAD segment is both writable and executable.

## Automated checks

- legacy `0.13.3` assets reproduce byte-for-byte;
- current strict-warning kernel build passes;
- current Android tools format checks pass;
- candidate raw image equals the merged main baseline byte-for-byte;
- all required linker symbols are identical;
- all six required output sections are present;
- each section is covered by a compatible `RW` or `RE` LOAD;
- no `W+E` LOAD exists;
- section addresses remain unchanged.

## Why this is not merged yet

ELF and raw-image equivalence do not prove that every supported boot chain ignores or correctly handles the new program-header table. Before merge, the exact candidate must pass physical validation for:

1. `kptools` patch and unpatch round trips;
2. boot on supported A/B and non-A/B devices;
3. rollback to the verified backup;
4. KPM load, control, unload, and reboot persistence;
5. safe-mode and failed-boot recovery;
6. Android/kernel combinations in the project test matrix.

The experiment branch must remain isolated until those results are recorded against the exact candidate commit.
