#!/usr/bin/env python3
"""Static contracts for KernelPatch issues #7, #8, #9, #12 and #15.

These checks are intentionally source-only so they can run without a kernel,
device, network, or GitHub Actions.  They do not replace runtime/KASAN testing.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRE = (ROOT / "kernel/base/predata.c").read_text(encoding="utf-8")
SC = (ROOT / "kernel/patch/common/supercall.c").read_text(encoding="utf-8")
MOD = (ROOT / "kernel/patch/module/module.c").read_text(encoding="utf-8")


def section(text: str, start: str, end: str) -> str:
    a = text.index(start)
    b = text.index(end, a + len(start))
    return text[a:b]


# #7: exact bounded superkey semantics.
assert "stored_len = lib_strnlen(superkey, SUPER_KEY_LEN)" in PRE
assert "key_len = lib_strnlen(key, SUPER_KEY_LEN)" in PRE
assert "stored_len != key_len" in PRE
assert "i < SUPER_KEY_LEN" in PRE
assert "stored_len == 0 || stored_len >= SUPER_KEY_LEN" in PRE
assert "key_len == 0 || key_len >= SUPER_KEY_LEN" in PRE
assert "for (int i = 0; superkey[i]; i++)" not in PRE

# #8: user capacity must never become the kernel source-read length.
kpm_list = section(SC, "static long call_kpm_list", "static long call_kpm_info")
assert "char buf[4096] = { 0 };" in kpm_list
assert "if (len > 4096) return -E2BIG;" in kpm_list
assert "if (sz < 0) return sz;" in kpm_list
assert "compat_copy_to_user(names, buf, sz)" in kpm_list
assert "compat_copy_to_user(names, buf, len)" not in kpm_list

list_modules = section(MOD, "int list_modules", "int get_module_info")
assert "int remaining = size - off;" in list_modules
assert "written >= remaining" in list_modules
assert "off += snprintf" not in list_modules
assert "rc = -ENOBUFS" in list_modules

# #9: validate one kernel copy and never re-read the original user pointer.
skey_set = section(SC, "static long call_skey_set", "static long call_skey_root_enable")
assert "const char __user *new_key" in skey_set
assert "char buf[SUPER_KEY_LEN] = { 0 };" in skey_set
assert "reset_superkey(buf);" in skey_set
assert "reset_superkey(new_key)" not in skey_set
assert "wipe_sensitive(buf, sizeof(buf))" in skey_set

# #12: explicit KPM callback ABI, no guessed .ko code-section callback slots.
setup = section(MOD, "static int setup_load_info", "static int elf_header_check")
assert 'int has_kpm_init = find_sec(info, ".kpm.init");' in setup
assert 'find_sec(info, ".kpm.init") || find_sec(info, ".kpm.exit")' not in setup
assert "explicit .kpm.init is required" in setup
move = section(MOD, "static int move_module", "static int setup_load_info")
assert 'if (!mod->init && !strcmp(".kpm.init", sname))' in move
assert 'if (!mod->init && !strcmp(".init.text", sname))' not in move
assert 'if (!mod->exit && !strcmp(".exit.text", sname))' not in move
assert "validate_module_callbacks(mod)" in MOD
assert "callback_target_in_text" in MOD
load = section(MOD, "long load_module", "long unload_module")
assert "if (mod->exit && *mod->exit)" in load

# #15: missing info lookup must use the common RCU unlock exit.
info = section(MOD, "int get_module_info", "void module_init")
assert "rc = -ENOENT;" in info
assert "goto out;" in info
assert "if (!mod) return -ENOENT;" not in info
assert info.count("rcu_read_lock();") == 1
assert info.count("rcu_read_unlock();") == 1

print("Issue batch #7/#8/#9/#12/#15 source contracts passed.")
