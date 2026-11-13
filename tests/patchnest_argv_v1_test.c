/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../kernel/include/patchnest_argv_v1.h"
int main(void)
{
    char wire[PN_ARGV_WIRE_MAX];
    struct pn_argv_slice args[PN_ARGV_COUNT_MAX] = {{0}};
    const char *values[] = { "mode=fast", "two words", "", "colon:inside", "雪" };
    assert(pn_argv_encode(5, values, wire, sizeof(wire)) == PN_ARGV_OK);
    assert(pn_argv_decode(wire, args, 5) == 5);
    for (size_t i = 0; i < 5; ++i) {
        assert(args[i].length == strlen(values[i]));
        assert(memcmp(args[i].data, values[i], args[i].length) == 0);
    }
    assert(pn_argv_decode("old=legacy args", args, 5) == PN_ARGV_LEGACY);
    assert(pn_argv_decode("PNARGV1:2:10:abc", args, 5) == PN_ARGV_INVALID);
    assert(pn_argv_decode("PNARGV1:99:", args, 5) == PN_ARGV_INVALID);
    assert(pn_argv_decode(wire, args, 1) == PN_ARGV_NO_SPACE);
    assert(pn_argv_encode(5, values, wire, 10) == PN_ARGV_NO_SPACE);
    char huge[1024];
    memset(huge, 'x', sizeof(huge) - 1);
    huge[sizeof(huge) - 1] = 0;
    const char *one[] = { huge };
    assert(pn_argv_encode(1, one, wire, sizeof(wire)) == PN_ARGV_NO_SPACE);
    assert(pn_argv_decode("PNARGV1:0:", NULL, 0) == 0);
    assert(pn_argv_decode("PNARGV1:1:0:", args, 1) == 1);
    assert(args[0].length == 0);
    assert(pn_argv_decode("PNARGV1:0:extra", args, 5) == PN_ARGV_INVALID);
    assert(pn_argv_decode("PNARGV1:18446744073709551616:", args, 5) == PN_ARGV_INVALID);
    assert(pn_argv_decode("PNARGV1:1:18446744073709551616:x", args, 5) == PN_ARGV_INVALID);
    memset(wire, 'x', sizeof(wire));
    assert(pn_argv_decode(wire, args, 5) == PN_ARGV_INVALID);
    /* 8-byte prefix + count + colon + 5-byte length field + payload + NUL. */
    memset(huge, 'x', 1008);
    huge[1008] = 0;
    assert(pn_argv_encode(1, one, wire, sizeof(wire)) == PN_ARGV_OK);
    assert(strlen(wire) == sizeof(wire) - 1);
    assert(pn_argv_decode(wire, args, 1) == 1);
    assert(args[0].length == 1008);
    assert(memcmp(args[0].data, huge, 1008) == 0);
    huge[1008] = 'x';
    huge[1009] = 0;
    assert(pn_argv_encode(1, one, wire, sizeof(wire)) == PN_ARGV_NO_SPACE);
    puts("PatchNest argv v1 tests: PASS");
    return 0;
}
