#!/usr/bin/env python3
"""Exercise the production SU entry points with host substitutes for kernel APIs."""

import os
from pathlib import Path
import subprocess
import tempfile

from check_kpm_rcu_paths import find_functions


ROOT = Path(__file__).resolve().parents[1]
ACCCTL = ROOT / "kernel/patch/common/accctl.c"

HARNESS = r'''
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <sys/types.h>

#define SECSID_NULL 0

static unsigned int all_allow_sid;
static int kernel_calls;
static int common_calls;
static uid_t observed_uid;
static const char *observed_sctx;

static int commit_kernel_su(void)
{
    kernel_calls++;
    return -41;
}

static int commit_common_su(uid_t uid, const char *sctx)
{
    common_calls++;
    observed_uid = uid;
    observed_sctx = sctx;
    return -42;
}

/* No target-task APIs are provided to the extracted task_su body. */
__FUNCTIONS__

int main(void)
{
    const pid_t tids[] = { -1, 0, 1, 12345, INT_MAX };
    const char context[] = "u:r:test:s0";
    unsigned int i;

    for (i = 0; i < sizeof(tids) / sizeof(tids[0]); i++) {
        if (task_su(tids[i], 0, context) != -EOPNOTSUPP ||
            task_su(tids[i], 1234, NULL) != -EOPNOTSUPP) {
            fprintf(stderr, "task_su did not reject tid %d\n", tids[i]);
            return 1;
        }
    }

    all_allow_sid = 7;
    if (commit_su(0, context) != -41 || kernel_calls != 1 || common_calls != 0) {
        fprintf(stderr, "kernel credential path did not return its result\n");
        return 1;
    }
    if (commit_su(1234, context) != -42 || kernel_calls != 1 || common_calls != 1 ||
        observed_uid != 1234 || observed_sctx != context) {
        fprintf(stderr, "common credential path did not forward its arguments and result\n");
        return 1;
    }
    all_allow_sid = SECSID_NULL;
    if (commit_su(0, NULL) != -42 || kernel_calls != 1 || common_calls != 2 ||
        observed_uid != 0 || observed_sctx != NULL) {
        fprintf(stderr, "common credential path did not handle a null SID and context\n");
        return 1;
    }
    puts("accctl SU paths ok");
    return 0;
}
'''


def main():
    functions = find_functions(ACCCTL.read_text())
    definitions = "\n".join(
        signature + "\n" + functions[name][1]
        for name, signature in (
            ("commit_su", "int commit_su(uid_t to_uid, const char *sctx)"),
            ("task_su", "int task_su(pid_t pid, uid_t to_uid, const char *sctx)"),
        )
    )
    with tempfile.TemporaryDirectory(prefix="accctl-host-") as directory:
        source = Path(directory) / "test.c"
        executable = Path(directory) / "test"
        source.write_text(HARNESS.replace("__FUNCTIONS__", definitions))
        subprocess.run(
            [os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra", "-Werror",
             "-Wno-unused-parameter", str(source), "-o", str(executable)],
            check=True,
        )
        subprocess.run([str(executable)], check=True)


if __name__ == "__main__":
    main()
