# PatchNest KPM argv v1 consumer example

This sample opts in to decoding `PNARGV1` without changing the KPM
callback ABI, the supercall IDs or the legacy raw-string path.

- `kpatch kpm loadv ./argv_demo.kpm mode=safe "two words" ""`
- `kpatch kpm ctlv patchnest-argv-demo action=check retries=2`
- `kpatch kpm ctl0 patchnest-argv-demo "legacy raw data"`

Build using the existing project ARM64 toolchain:
`make KP_DIR=../.. TARGET_COMPILE=<toolchain-prefix>`

`KPM_INIT` and `KPM_CTL0` accept either legacy raw strings or the
opt-in length-delimited frame. A malformed `PNARGV1` frame is rejected.
The example intentionally **never logs argument contents**. Event handling
is compiled only with `-DPATCHNEST_EVENT_ABI` after PUBLIC1158 event
capability has been validated; do not enable this for NEXT2026 by guesswork.

This sample does not grant root, load hooks, modify boot, or demonstrate
that a particular phone/kernel combination is safe to flash. It is source
for testing and review, not an automatically installed KPM.
