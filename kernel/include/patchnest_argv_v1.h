/* SPDX-License-Identifier: GPL-2.0-or-later */
/* PatchNest opt-in argv framing, independent of KernelPatch supercall ABI.
 * A legacy KPM still receives a single NUL-terminated args string.
 * Consumers must opt in to PNARGV1 decoding; no kernel ABI change.
 */
#ifndef PATCHNEST_ARGV_V1_H
#define PATCHNEST_ARGV_V1_H
#include <stddef.h>

#define PN_ARGV_WIRE_MAX 1024u
#define PN_ARGV_COUNT_MAX 32u
#define PN_ARGV_PREFIX "PNARGV1:"
#define PN_ARGV_OK 0
#define PN_ARGV_INVALID (-1)
#define PN_ARGV_NO_SPACE (-2)
#define PN_ARGV_LEGACY (-3)

struct pn_argv_slice {
    const char *data;
    size_t length;
};

static inline size_t pn_argv_strlen_limit(const char *s, size_t max)
{
    size_t i = 0;
    if (!s) return max;
    while (i < max && s[i]) ++i;
    return i;
}

static inline int pn_argv_decimal(char *buf, size_t capacity, size_t *pos, size_t value)
{
    char digits[3 * sizeof(size_t) + 1];
    size_t count = 0;
    do {
        digits[count++] = (char)('0' + (value % 10u));
        value /= 10u;
    } while (value);
    if (*pos >= capacity || count >= capacity - *pos) return PN_ARGV_NO_SPACE;
    while (count) buf[(*pos)++] = digits[--count];
    return PN_ARGV_OK;
}

static inline int pn_argv_encode(size_t argc, const char *const *argv,
                                  char *out, size_t capacity)
{
    const char prefix[] = PN_ARGV_PREFIX;
    size_t pos = 0, i, j;
    if (!out || argc > PN_ARGV_COUNT_MAX || (argc && !argv) ||
        capacity == 0 || capacity > PN_ARGV_WIRE_MAX)
        return PN_ARGV_INVALID;
    for (j = 0; prefix[j]; ++j) {
        if (pos + 1 >= capacity) return PN_ARGV_NO_SPACE;
        out[pos++] = prefix[j];
    }
    if (pn_argv_decimal(out, capacity, &pos, argc) != PN_ARGV_OK) return PN_ARGV_NO_SPACE;
    if (pos + 1 >= capacity) return PN_ARGV_NO_SPACE;
    out[pos++] = ':';
    for (i = 0; i < argc; ++i) {
        size_t length = pn_argv_strlen_limit(argv[i], capacity);
        if (length == capacity) return PN_ARGV_NO_SPACE;
        if (pn_argv_decimal(out, capacity, &pos, length) != PN_ARGV_OK)
            return PN_ARGV_NO_SPACE;
        if (pos + 1 >= capacity) return PN_ARGV_NO_SPACE;
        out[pos++] = ':';
        if (length >= capacity - pos) return PN_ARGV_NO_SPACE;
        for (j = 0; j < length; ++j) out[pos++] = argv[i][j];
    }
    out[pos] = '\0';
    return PN_ARGV_OK;
}

/* Return 0 on success, -1 on malformed, -2 on capacity exceeded.
 * Slice data is NOT NUL-terminated: use length, never strlen(data).
 */
static inline int pn_argv_read_decimal(const char *wire, size_t length,
                                        size_t *pos, size_t maximum, size_t *result)
{
    size_t value = 0, start = *pos;
    while (*pos < length && wire[*pos] >= '0' && wire[*pos] <= '9') {
        size_t digit = (size_t)(wire[*pos] - '0');
        if (digit > maximum || value > (maximum - digit) / 10u)
            return PN_ARGV_INVALID;
        value = value * 10u + digit;
        ++*pos;
    }
    if (*pos == start || *pos == length || wire[*pos] != ':')
        return PN_ARGV_INVALID;
    ++*pos;
    *result = value;
    return PN_ARGV_OK;
}

static inline int pn_argv_decode(const char *wire, struct pn_argv_slice *out,
                                  size_t capacity)
{
    const char prefix[] = PN_ARGV_PREFIX;
    size_t length, pos = 0, count = 0, item, item_len;
    if (!wire) return PN_ARGV_INVALID;
    length = pn_argv_strlen_limit(wire, PN_ARGV_WIRE_MAX);
    if (length >= PN_ARGV_WIRE_MAX) return PN_ARGV_INVALID;
    while (prefix[pos]) {
        if (pos >= length || wire[pos] != prefix[pos]) return PN_ARGV_LEGACY;
        ++pos;
    }
    if (pn_argv_read_decimal(wire, length, &pos, PN_ARGV_COUNT_MAX, &count))
        return PN_ARGV_INVALID;
    if (count > capacity || (count && !out)) return PN_ARGV_NO_SPACE;
    for (item = 0; item < count; ++item) {
        if (pn_argv_read_decimal(wire, length, &pos, PN_ARGV_WIRE_MAX, &item_len))
            return PN_ARGV_INVALID;
        if (item_len > length - pos) return PN_ARGV_INVALID;
        out[item].data = wire + pos;
        out[item].length = item_len;
        pos += item_len;
    }
    return pos == length ? (int)count : PN_ARGV_INVALID;
}
#endif /* PATCHNEST_ARGV_V1_H */
