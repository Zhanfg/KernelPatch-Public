#!/usr/bin/env python3
"""Source/model contracts for issue #14 boot-attempt accounting."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAFETY = (ROOT / "kernel/patch/common/kpm_safety.c").read_text(encoding="utf-8")
HEADER = (ROOT / "kernel/patch/include/kpm_safety.h").read_text(encoding="utf-8")
EVENT = (ROOT / "kernel/patch/common/user_event.c").read_text(encoding="utf-8")
MODULE = (ROOT / "kernel/patch/module/module.c").read_text(encoding="utf-8")
MAX = 3

# Persistent state is one checksummed record, not two independently incremented
# counters. /dev is explicitly current-boot diagnostics only.
assert 'BOOT_STATE_FILE       "/data/adb/kp-next/boot_state_v2"' in SAFETY
assert "boot_state_checksum" in SAFETY
assert "state->checksum != boot_state_checksum(state)" in SAFETY
assert 'EARLY_BOOT_MARKER     "/dev/.kp_boot_attempt"' in SAFETY
assert "/dev is diagnostic only" in SAFETY
assert "legacy counter ignored" in SAFETY

# Existing module_init call sites remain source-compatible, but both old APIs
# are side-effect-free wrappers: no /data accounting can happen from module_init.
assert "static inline void kpm_safety_early_count" in HEADER
assert "kpm_safety_begin_boot_attempt();" in HEADER
legacy = HEADER[HEADER.index("static inline int kpm_safety_check_boot_count"):]
legacy = legacy[:legacy.index("/* Pre-load ELF validation")]
assert "return 0;" in legacy
assert "kpm_safety_early_count();" in MODULE
assert "kpm_safety_check_boot_count()" in MODULE

# post-fs-data is the only persistent transition in the boot event path and any
# invalid/write-failed state becomes fail-closed safe mode.
post = EVENT[EVENT.index('if (lib_strcmp(safe_event, "post-fs-data")'):]
post = post[:post.index('if (lib_strcmp(safe_event, "boot-completed")')]
assert "kpm_safety_persist_boot_attempt()" in post
assert "kp_safe_mode = 1;" in post
assert "if (safety_rc == 0)" in post

# boot-completed confirms the same attempt; failed confirmation is observable.
completed = EVENT[EVENT.index('if (lib_strcmp(safe_event, "boot-completed")'):]
assert "kpm_safety_confirm_boot_completed()" in completed
assert "confirmation failed" in completed

# Last-KPM attribution is stored inside the attempt record rather than a loose
# global marker. Corrupt persistent state must not be guessed through.
assert "char last_kpm[64];" in SAFETY
assert "previous_failed_kpm" in SAFETY
assert "persistent state corrupt/unreadable" in SAFETY
assert "boot_state_degraded = 1;" in SAFETY

# Pure state model: current boot never increments itself. A pending *previous*
# attempt contributes exactly one failure. Three prior unconfirmed attempts
# cause safe mode on the fourth boot. A confirmed attempt resets the chain.
def begin(previous):
    if previous is None:
        return {"attempt": 1, "generation": 1, "failures": 0, "phase": "pending"}
    failures = previous["failures"] + 1 if previous["phase"] == "pending" else 0
    return {
        "attempt": previous["attempt"] + 1,
        "generation": previous["generation"] + 1,
        "failures": failures,
        "phase": "pending",
    }


def confirm(current):
    current = dict(current)
    current["generation"] += 1
    current["failures"] = 0
    current["phase"] = "confirmed"
    return current

state = None
observed = []
for boot in range(1, 5):
    state = begin(state)
    observed.append((boot, state["failures"], state["failures"] >= MAX))
assert observed == [(1, 0, False), (2, 1, False), (3, 2, False), (4, 3, True)]

state = begin(None)
state = confirm(state)
state = begin(state)
assert state["attempt"] == 2
assert state["failures"] == 0
assert state["phase"] == "pending"

print("Issue #14 boot-attempt source/model contracts passed.")
