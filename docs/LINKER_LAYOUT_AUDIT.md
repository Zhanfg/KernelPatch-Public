# kpimg linker-layout audit

Audit scope: current `KernelPatch-Public` source after the compiler-warning cleanup.

## Why this is separate

The linker reports that the intermediate `kpimg.elf` has a LOAD segment with read, write, and execute permissions. That warning cannot be treated like an ordinary compiler warning:

- `kpimg.elf` is converted to a flat raw image with `objcopy -O binary`;
- setup code begins below the first 64 KiB boundary;
- the main KernelPatch text and data regions use fixed 64 KiB alignment;
- the patching tools and boot-time loader depend on symbol addresses and raw offsets, not only ELF section names;
- adding `PHDRS` or splitting LOAD segments can alter offsets, padding, file size, or the raw output even when the C source is unchanged.

A blind linker-script cleanup could therefore produce an apparently safer ELF that no longer boots or can no longer be located by the patcher.

## Verified current layout

The current build has the following structure:

- `_link_base` and `_setup_start` are `0xd000`;
- the ELF LOAD segment begins at virtual address `0x0`, not `_link_base`;
- `objcopy -O binary` omits the leading `0xd000` virtual gap;
- file-backed content ends at `_kp_data_end = 0x39dc0`;
- `_kp_end` and `_link_end` are aligned forward to `0x40000`, but the trailing `0x6240` alignment is not emitted into the raw image;
- the raw image therefore spans `_link_base` through `_kp_data_end` and is `0x2cdc0` bytes;
- `.setup.map` is itself `WAX` because map data and map code share one output section;
- the intermediate ELF has one `RWE` LOAD segment aligned to `0x10000`.

## Current audit gate

`scripts/audit_kpimg_layout.py` inspects the current build and fails CI when any established boot-critical invariant changes unexpectedly:

1. all required linker symbols and output sections exist;
2. `_link_base` remains `0xd000`;
3. setup, map, kernel text, and kernel data preserve their ordering;
4. the main kernel text, data, and end boundaries retain 64 KiB alignment;
5. `.setup.data` starts at `_link_base` and reserves 4 KiB;
6. file-backed content ends at `_kp_data_end`;
7. the raw `kpimg` size equals `_kp_data_end - _link_base`;
8. all required allocated sections fit inside the raw image;
9. the current ELF retains one LOAD segment beginning at virtual address `0x0`;
10. the LOAD file and memory sizes equal the file-backed end address;
11. removing the leading `_link_base` gap from the LOAD size yields the raw-image size;
12. the LOAD alignment remains 64 KiB.

The audit writes JSON, Markdown, program-header, section-header, and sorted-symbol reports into the CI artifact. The `RWE` LOAD segment and `.setup.map=WAX` section are emitted as explicit warnings rather than silently ignored or described as resolved.

## What this audit does not claim

- It does not claim that an RWE segment is desirable.
- It does not claim that `.setup.map=WAX` is safe.
- It does not claim that ELF program-header permissions are enforced after the image is injected into a target kernel.
- It does not alter `kpimg.lds`, section placement, program headers, or the generated raw binary.
- It does not replace real-device boot, patch, rollback, and KPM testing.

## Gate for a future linker change

A linker-layout change must be isolated in its own PR and provide all of the following evidence:

1. before/after `readelf -lW`, `readelf -SW`, and sorted symbol maps;
2. a complete raw-offset comparison for every required symbol and output section;
3. an explanation for every changed byte in the raw image;
4. successful patch/unpatch round trips with `kptools`;
5. boot and rollback validation on supported Android kernel ranges;
6. KPM load/control/unload validation after boot;
7. confirmation that safe-mode and recovery paths remain reachable.

A future attempt must account for `.setup.map` combining writable data and executable code. Splitting only the ELF program headers is insufficient to remove the write-plus-execute overlap.

Until those gates are available, the repository records and monitors the current condition but does not risk an unvalidated layout rewrite.
