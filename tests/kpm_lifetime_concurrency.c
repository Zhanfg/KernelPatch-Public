// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Host-side deterministic concurrent KPM lifetime test.
 *
 * Tests the SAME pn_kpm_lifetime primitive used by module.c, with a
 * pthread mutex standing in for the kernel spinlock. It is not a kernel
 * scheduler or real-device stress test.
 */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <limits.h>

#include "../kernel/patch/include/kpm_lifetime.h"

enum { THREADS = 8 };
static struct pn_kpm_lifetime lifetime = { 0 };
static pthread_mutex_t registry_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t inside_callback;
static pthread_barrier_t allow_return;

static void *callback(void *arg)
{
    (void)arg;
    pthread_mutex_lock(&registry_lock);
    assert(pn_kpm_lifetime_get(&lifetime) == 1);
    pthread_mutex_unlock(&registry_lock);

    /* Every callback must be active when the main thread tries unload. */
    pthread_barrier_wait(&inside_callback);
    pthread_barrier_wait(&allow_return);

    pthread_mutex_lock(&registry_lock);
    assert(pn_kpm_lifetime_put(&lifetime) == 1);
    pthread_mutex_unlock(&registry_lock);
    return NULL;
}

int main(void)
{
    pthread_t workers[THREADS];
    assert(pthread_barrier_init(&inside_callback, NULL, THREADS + 1) == 0);
    assert(pthread_barrier_init(&allow_return, NULL, THREADS + 1) == 0);

    assert(pn_kpm_lifetime_put(&lifetime) == 0); /* underflow refused */

    for (unsigned int i = 0; i < THREADS; ++i)
        assert(pthread_create(&workers[i], NULL, callback, NULL) == 0);

    pthread_barrier_wait(&inside_callback);
    pthread_mutex_lock(&registry_lock);
    assert(lifetime.callback_users == THREADS);
    assert(pn_kpm_lifetime_may_unload(&lifetime) == 0);
    pthread_mutex_unlock(&registry_lock);

    pthread_barrier_wait(&allow_return);
    for (unsigned int i = 0; i < THREADS; ++i)
        assert(pthread_join(workers[i], NULL) == 0);

    pthread_mutex_lock(&registry_lock);
    assert(lifetime.callback_users == 0);
    assert(pn_kpm_lifetime_may_unload(&lifetime) == 1);
    pthread_mutex_unlock(&registry_lock);

    lifetime.callback_users = UINT_MAX;
    assert(pn_kpm_lifetime_get(&lifetime) == 0); /* overflow refused */
    lifetime.callback_users = 0;

    pthread_barrier_destroy(&inside_callback);
    pthread_barrier_destroy(&allow_return);
    puts("PatchNest KPM lifetime concurrency: PASS");
    return 0;
}
