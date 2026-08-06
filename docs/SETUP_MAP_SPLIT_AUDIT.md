# Setup map section split audit

Audit date: 2026-08-06

## Scope

The linker previously merged writable map state and executable map code into one `.setup.map` output section, making that individual ELF section `WAX`.

This branch preserves the existing byte order but separates the output sections:

```text
.setup.map.data
    base/map.o(.map.data)

.setup.map.text
    base/map.o(.map.text)
    base/map.o(.text)
    base/map1.o(.text)
```

`_map_start` remains at the beginning of `map_data`, and `_map_end` remains after the setup-map code. The input sections, function order, `MAP_ALIGN`, 64 KiB boundaries, C source, raw conversion and program headers are not changed.

## Required result

- `.setup.map.data` is `WA`, not executable.
- `.setup.map.text` is `AX`, not writable.
- the two sections are contiguous;
- all linker symbols retain their previous addresses;
- the raw `kpimg` is byte-for-byte identical to the pre-split baseline when built with the same source timestamp and toolchain;
- the setup-map region remains below `MAP_MAX_SIZE` (`0xa00`).

## Limitation

The intermediate ELF still contains one `RWE` LOAD segment. Separating output-section flags removes the direct `.setup.map=WAX` condition but does not change PHDR permissions. A LOAD-segment split remains a separate boot-critical experiment.

## Merge gate

1. Legacy `0.13.3` assets still reproduce byte-for-byte.
2. Current strict-warning builds pass.
3. The permanent layout auditor passes.
4. A dedicated baseline/candidate experiment proves raw-image byte identity.
5. Required symbol addresses and raw offsets are identical.
6. No Release is created.
