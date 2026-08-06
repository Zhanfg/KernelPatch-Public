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

## Current audit gate

`scripts/audit_kpimg_layout.py` inspects the current build and fails CI when any boot-critical invariant changes unexpectedly:

1. all required linker symbols exist;
2. `_link_base` remains `0xd000`;
3. setup, map, kernel text, and kernel data preserve their ordering;
4. the main kernel text/data/end boundaries retain 64 KiB alignment;
5. the raw `kpimg` size exactly matches `_link_end - _link_base`;
6. required allocated sections fit inside the raw image;
7. the current single LOAD segment starts at `_link_base` and spans the raw image.

The audit writes both JSON and Markdown reports into the CI artifact. The RWE LOAD segment is reported as an explicit warning rather than silently ignored.

## What this audit does not claim

- It does not claim that an RWE segment is desirable.
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

Until those gates are available, the repository records and monitors the RWE condition but does not risk an unvalidated layout rewrite.
