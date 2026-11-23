#!/usr/bin/env python3
"""Exercise kstorage queries using the actual function bodies and host mocks."""

import os
from pathlib import Path
import subprocess
import tempfile

from check_kpm_rcu_paths import find_functions

ROOT = Path(__file__).resolve().parents[1]

HOST_STUBS = r'''
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
struct kstorage { long did; int dlen; char data[8]; };
struct list_head { struct kstorage *first; int count; };
#define KSTRORAGE_MAX_GROUP_NUM 4
static struct kstorage entries[] = {{11, 4, "abcd"}, {22, 3, "xyz"}};
static struct list_head kstorage_groups[4] = {{entries, 2}};
static int lock_depth, copy_calls;
static int copy_limit = INT_MAX;
#define rcu_read_lock() (++lock_depth)
#define rcu_read_unlock() (--lock_depth)
#define IS_ERR(p) ((p) == NULL)
#define PTR_ERR(p) (-ENOENT)
#define logkfe(...) ((void)0)
#define list_for_each_entry(pos, head, member) \
    for (pos = (head)->first; pos < (head)->first + (head)->count; pos++)

static const struct kstorage *get_kstorage(int gid, long did)
{
    return gid == 0 && did == 11 ? &entries[0] : NULL;
}

static int compat_copy_to_user(void *dst, const void *src, int size)
{
    int count = size < copy_limit ? size : copy_limit;
    copy_calls++;
    if (count > 0) memcpy(dst, src, count);
    return count;
}
'''
CHECKS = r'''
int main(void)
{
    char out[8] = {0};
    long ids[2] = {0};
    assert(call_kstorage_read(0, 11, out, -1, 1) == -EINVAL);
    assert(call_kstorage_read(0, 11, out, 5, 1) == -EINVAL);
    assert(call_kstorage_read(0, 11, out, 0, -1) == -EINVAL);
    assert(call_kstorage_read(0, 11, out, INT_MAX, INT_MAX) == -EINVAL);
    assert(call_kstorage_read(0, 99, out, 0, 1) == -ENOENT);
    assert(copy_calls == 0);
    assert(call_kstorage_read(0, 11, out, 4, 4) == 0 && out[0] == 0);
    assert(call_kstorage_read(0, 11, out, 2, 8) == 0 && !strcmp(out, "cd"));

    copy_calls = 0;
    assert(call_list_kstorage_ids(0, ids, 2) == 2 && ids[0] == 11 && ids[1] == 22 && copy_calls == 2);
    const int failures[] = {0, 1, -EFAULT};
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); i++) {
        copy_limit = failures[i];
        copy_calls = 0;
        assert(call_list_kstorage_ids(0, ids, 2) == -EFAULT && copy_calls == 1);
    }
    copy_calls = 0;
    assert(list_kstorage_ids(0, ids, 2, false) == 2 && copy_calls == 0);
    assert(lock_depth == 0);
    puts("kstorage read bounds and list copy mock: PASS");
}
'''


def main():
    storage = find_functions((ROOT / "kernel/patch/common/kstorage.c").read_text())
    supercall = find_functions((ROOT / "kernel/patch/common/supercall.c").read_text())
    functions = [
        (storage, "read_kstorage", "int read_kstorage(int gid, long did, void *data, int offset, int len, bool data_is_user)"),
        (storage, "list_kstorage_ids", "int list_kstorage_ids(int gid, long *ids, int idslen, bool data_is_user)"),
        (supercall, "call_kstorage_read", "static long call_kstorage_read(int gid, long did, void *out_data, int offset, int dlen)"),
        (supercall, "call_list_kstorage_ids", "static long call_list_kstorage_ids(int gid, long *ids, int ids_len)"),
    ]
    definitions = [signature + "\n" + bodies[name][1] for bodies, name, signature in functions]
    source = "\n".join([HOST_STUBS, *definitions, CHECKS])
    with tempfile.TemporaryDirectory(prefix="kstorage-host-") as directory:
        source_path = Path(directory) / "test.c"
        executable = Path(directory) / "test"
        source_path.write_text(source)
        subprocess.run([os.environ.get("CC", "gcc"), "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        str(source_path), "-o", str(executable)], check=True)
        subprocess.run([str(executable)], check=True)


if __name__ == "__main__":
    main()
