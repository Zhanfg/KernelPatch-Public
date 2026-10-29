/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_KPM_QUERY_H_
#define _KP_KPM_QUERY_H_

/*
 * Bytes that are safe to copy out of a fixed kernel buffer.
 *
 * dest_len is the caller capacity. src_cap is the kernel buffer size.
 * filled is the initialized prefix, or a negative errno from the producer.
 * The returned length is never above filled, dest_len, or src_cap.
 * Requires EINVAL and ENOBUFS from the includer.
 */
static inline int kpm_bounded_copy_len(int filled, int dest_len, int src_cap)
{
    if (dest_len <= 0 || src_cap <= 0)
        return -EINVAL;
    if (dest_len > src_cap)
        return -ENOBUFS;
    if (filled < 0)
        return filled;
    if (filled > src_cap || filled > dest_len)
        return -ENOBUFS;
    return filled;
}

#ifdef KP_KPM_LIST_FORMAT
/*
 * Append "name\n" only when the whole record fits. On truncation the
 * buffer stays terminated at *off and *off does not advance.
 * Requires snprintf from the includer. Define KP_KPM_LIST_FORMAT before
 * including this header to compile these helpers.
 */
static inline int kpm_list_append(char *out, int size, int *off, const char *name)
{
    int remaining;
    int written;

    if (!out || !off || size <= 0 || *off < 0 || *off >= size)
        return -EINVAL;

    remaining = size - *off;
    if (remaining <= 1) {
        out[*off] = '\0';
        return -ENOBUFS;
    }

    written = snprintf(out + *off, (size_t)remaining, "%s\n", name);
    if (written < 0)
        return written;
    if (written >= remaining) {
        out[*off] = '\0';
        return -ENOBUFS;
    }

    *off += written;
    return 0;
}

/* Replace the trailing newline from the last successful append. */
static inline void kpm_list_finish(char *out, int off)
{
    if (out && off > 0)
        out[off - 1] = '\0';
}
#endif

#endif
