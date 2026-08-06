# Setup map section split audit

Audit date: 2026-08-06

## Scope

The linker previously merged writable map state and executable map code into one `.setup.map` output section, making that individual ELF section `WAX`.

The new layout preserves the original byte order but separates the output sections:

```text
.setup.map.data
    base/map.o(.map.data)

.setup.map.text
    base/map.o(.map.text)
    base/map.o(.text)
    base/map1.o(.text)
```

`_map_start` remains at the beginning of `map_data`, and `_map_end` remains after the setup-map code. The input sections, function order, `MAP_ALIGN`, 64 KiB boundaries, C source, raw conversion and program headers are unchanged.

## Controlled comparison

The pre-split baseline and split candidate were built on the same GitHub Runner with:

- baseline commit: `b2270f7bd3d186b6960e44d87a5885ab11bf7c41`;
- GNU Arm toolchain `12.2.rel1` with pinned archive SHA-256;
- identical strict compiler flags;
- shared `SOURCE_DATE_EPOCH=1786025302`.

Result:

| Check | Result |
|---|---|
| Baseline raw SHA-256 | `afd39b9c077afdd15454e2eebb2db7b454c079cd5b8b71c5663511a73e371d24` |
| Candidate raw SHA-256 | `afd39b9c077afdd15454e2eebb2db7b454c079cd5b8b71c5663511a73e371d24` |
| Complete raw-image comparison | Byte-identical |
| Required symbol addresses | Identical |
| Raw image size | `0x2cdc0` |
| `_map_start` | `0xe380` |
| `_map_end` | `0xe9a0` |

## Measured split sections

| Section | Address | Size | Flags | Raw range |
|---|---:|---:|---|---|
| `.setup.map.data` | `0xe380` | `0xa0` | `WA` | `0x1380..0x1420` |
| `.setup.map.text` | `0xe420` | `0x580` | `AX` | `0x1420..0x19a0` |

The sections are contiguous and the complete setup-map region is `0x620` bytes, below `MAP_MAX_SIZE` (`0xa00`).

## Verified gates

1. Legacy `0.13.3` `kpimg-linux` and `kptools-android` still reproduce byte-for-byte.
2. Current strict-warning kernel and Android tools builds pass.
3. All permanent linker-layout checks pass.
4. Candidate raw `kpimg` is byte-for-byte identical to the pre-split baseline.
5. All required linker symbol addresses and raw offsets are unchanged.
6. No Release is created.

## Remaining limitation

The intermediate ELF still contains one `RWE` LOAD segment starting at virtual address `0x0`. Separating output-section flags removes the direct `.setup.map=WAX` condition but does not change PHDR permissions.

A LOAD-segment split remains a separate boot-critical experiment. It must not be combined with this byte-preserving section split because PHDR changes can alter ELF offsets, alignment and raw conversion behavior.
