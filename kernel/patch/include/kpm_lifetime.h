/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef PATCHNEST_KPM_LIFETIME_H
#define PATCHNEST_KPM_LIFETIME_H

/*
 * The caller MUST hold the registry lock for every operation below.
 * Callbacks themselves execute without the registry lock.
 *
 * The unload operation is nonblocking: it returns -EBUSY if the module
 * has active callback holders. No callback is allowed to execute after the
 * module is detached from the registry.
 */
struct pn_kpm_lifetime {
    unsigned int callback_users;
};

static inline int pn_kpm_lifetime_get(struct pn_kpm_lifetime *state)
{
    if (!state || state->callback_users == ~0u)
        return 0;
    ++state->callback_users;
    return 1;
}

static inline int pn_kpm_lifetime_put(struct pn_kpm_lifetime *state)
{
    if (!state || !state->callback_users)
        return 0;
    --state->callback_users;
    return 1;
}

static inline int pn_kpm_lifetime_may_unload(const struct pn_kpm_lifetime *state)
{
    return state && state->callback_users == 0;
}

#endif /* PATCHNEST_KPM_LIFETIME_H */
