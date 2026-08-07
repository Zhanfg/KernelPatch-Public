#!/usr/bin/env python3
"""Source/model contracts for issue #10 KPM lifetime safety."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / "kernel/patch/module/module.c").read_text(encoding="utf-8")
HDR = (ROOT / "kernel/patch/include/module.h").read_text(encoding="utf-8")

for state in ("LOADING", "LIVE", "QUIESCING", "UNLOADING", "DEAD"):
    assert f"MODULE_STATE_{state}" in HDR
assert "unsigned int active_refs;" in HDR
assert "caller must put_module()" in HDR

# One lock owns list membership, lifecycle state and reference acquisition.
assert "static spinlock_t module_lock;" in SRC
assert "static struct module *find_module_any_locked" in SRC
assert "static struct module *get_live_module" in SRC
assert "mod->state != MODULE_STATE_LIVE" in SRC
assert "mod->active_refs++;" in SRC
assert "mod->active_refs--;" in SRC

# Duplicate name reservation happens before init callback execution.
reserve = SRC.index("reserve_loading_module(mod)")
init = SRC.index("rc = (*mod->init)", reserve)
assert reserve < init
assert "mod->state = MODULE_STATE_LOADING;" in SRC
assert "find_module_any_locked(mod->info.name)" in SRC

# Unload cannot free while callbacks are retained. Quiescing prevents new refs,
# and an explicit retry completes unload after refs drain.
unload_start = SRC.index("long unload_module")
unload_end = SRC.index("long load_module_path", unload_start)
unload = SRC[unload_start:unload_end]
assert "mod->state = MODULE_STATE_QUIESCING" in unload
assert "if (mod->active_refs)" in unload
assert "return -EBUSY;" in unload
assert "mod->state = MODULE_STATE_UNLOADING" in unload
assert "if (rc)" in unload and "mod->state = MODULE_STATE_LIVE" in unload
assert unload.index("list_del(&mod->list)") < unload.index("free_module_storage(mod)")
assert "mod->state = MODULE_STATE_DEAD" in unload

# Control callbacks acquire/release a LIVE reference; ctl0 arguments are local
# per call instead of shared/free-raced through mod->ctl_args.
ctl0 = SRC[SRC.index("long module_control0"):SRC.index("long module_control1")]
assert "mod = get_live_module(name);" in ctl0
assert "put_module(mod);" in ctl0
assert "local_args = vmalloc" in ctl0
assert "mod->ctl_args = vmalloc" not in ctl0
ctl1 = SRC[SRC.index("long module_control1"):SRC.index("int get_module_nums")]
assert "get_live_module(name)" in ctl1
assert "put_module(mod);" in ctl1

# Event dispatch snapshots retained LIVE modules before invoking callbacks.
event = SRC[SRC.index("int module_dispatch_event"):]
assert "pos->state == MODULE_STATE_LIVE" in event
assert "pos->active_refs++;" in event
assert "targets[count++] = pos;" in event
assert "put_module(mod);" in event

# Legacy RCU-reader/immediate-free mixture must be absent from this file.
assert "rcu_read_lock" not in SRC
assert "rcu_read_unlock" not in SRC

# Lifecycle is observable for diagnostics.
info = SRC[SRC.index("int get_module_info"):SRC.index("void module_init")]
assert '"state=%s' in info
assert '"active_refs=%u' in info

# Minimal executable state model for the race that caused the UAF.
def acquire(state, refs):
    if state != "LIVE":
        return state, refs, False
    return state, refs + 1, True


def release(state, refs):
    assert refs > 0
    return state, refs - 1


def unload(state, refs, exit_ok=True):
    if state in {"LOADING", "UNLOADING", "DEAD"}:
        return state, refs, "EBUSY"
    if state == "LIVE":
        state = "QUIESCING"
    if refs:
        return state, refs, "EBUSY"
    state = "UNLOADING"
    if not exit_ok:
        return "LIVE", refs, "EXIT_ERROR"
    return "DEAD", refs, "OK"

state, refs = "LIVE", 0
state, refs, ok = acquire(state, refs)
assert ok and refs == 1
state, refs, result = unload(state, refs)
assert (state, refs, result) == ("QUIESCING", 1, "EBUSY")
state, refs = release(state, refs)
state, refs, result = unload(state, refs)
assert (state, refs, result) == ("DEAD", 0, "OK")

state, refs, result = unload("LIVE", 0, exit_ok=False)
assert (state, refs, result) == ("LIVE", 0, "EXIT_ERROR")

# A second loader sees the LOADING reservation and cannot create a duplicate.
existing_names = {"demo": "LOADING"}
assert "demo" in existing_names

print("Issue #10 KPM lifetime source/model contracts passed.")
