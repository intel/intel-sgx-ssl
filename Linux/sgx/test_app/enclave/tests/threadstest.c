/*
 * Copyright 2016-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>

#include <openssl/crypto.h>

#include "testutil.h"

#include <sgx.h>

sgx_status_t ucreate_thread(int *retval);

static void (*func)(void) = NULL;
static volatile int busy_wait = 0;

typedef unsigned int thread_t;

static int run_thread(thread_t *t, void (*f)(void))
{
    int res = 0;
    sgx_status_t status;

    (void)t;
    func = f;
    busy_wait = 1;

    status = ucreate_thread(&res);
    if (status != SGX_SUCCESS || res != 0)
        return 0;
    return 1;
}

static int wait_for_thread(thread_t thread)
{
    (void)thread;
    while (busy_wait == 1)
        ;
    return 1;
}

void new_thread_func(void)
{
    if (func == NULL) {
        busy_wait = 0;
        return;
    }
    func();
    busy_wait = 0;
}

static int test_lock(void)
{
    CRYPTO_RWLOCK *lock = CRYPTO_THREAD_lock_new();
    int res;

    if (!TEST_ptr(lock))
        return 0;

    res = TEST_true(CRYPTO_THREAD_read_lock(lock))
        && TEST_true(CRYPTO_THREAD_unlock(lock))
        && TEST_true(CRYPTO_THREAD_write_lock(lock))
        && TEST_true(CRYPTO_THREAD_unlock(lock));

    CRYPTO_THREAD_lock_free(lock);

    return res;
}

static CRYPTO_ONCE once_run = CRYPTO_ONCE_STATIC_INIT;
static unsigned once_run_count = 0;

static void once_do_run(void)
{
    once_run_count++;
}

static void once_run_thread_cb(void)
{
    CRYPTO_THREAD_run_once(&once_run, once_do_run);
}

static int test_once(void)
{
    thread_t thread;

    if (!TEST_true(run_thread(&thread, once_run_thread_cb))
        || !TEST_true(wait_for_thread(thread))
        || !TEST_true(CRYPTO_THREAD_run_once(&once_run, once_do_run))
        || !TEST_int_eq(once_run_count, 1))
        return 0;
    return 1;
}

static CRYPTO_THREAD_LOCAL thread_local_key;
static unsigned destructor_run_count = 0;
static int thread_local_thread_cb_ok = 0;

static void thread_local_destructor(void *arg)
{
    unsigned *count;

    if (arg == NULL)
        return;

    count = arg;

    (*count)++;
}

static void thread_local_thread_cb(void)
{
    void *ptr;

    ptr = CRYPTO_THREAD_get_local(&thread_local_key);
    if (!TEST_ptr_null(ptr)
        || !TEST_true(CRYPTO_THREAD_set_local(&thread_local_key,
            &destructor_run_count)))
        return;

    ptr = CRYPTO_THREAD_get_local(&thread_local_key);
    if (!TEST_ptr_eq(ptr, &destructor_run_count))
        return;

    thread_local_thread_cb_ok = 1;
}

static int test_thread_local(void)
{
    thread_t thread;
    void *ptr = NULL;

    if (!TEST_true(CRYPTO_THREAD_init_local(&thread_local_key,
            thread_local_destructor)))
        return 0;

    ptr = CRYPTO_THREAD_get_local(&thread_local_key);
    if (!TEST_ptr_null(ptr)
        || !TEST_true(run_thread(&thread, thread_local_thread_cb))
        || !TEST_true(wait_for_thread(thread))
        || !TEST_int_eq(thread_local_thread_cb_ok, 1))
        return 0;

#if defined(OPENSSL_THREADS) && !defined(CRYPTO_TDEBUG)
    ptr = CRYPTO_THREAD_get_local(&thread_local_key);
    if (!TEST_ptr_null(ptr))
        return 0;

    /* no atexit-like callback support for this in enclave */
    (void)destructor_run_count;
#endif

    if (!TEST_true(CRYPTO_THREAD_cleanup_local(&thread_local_key)))
        return 0;
    return 1;
}

static int test_thread_local_multi_key(void)
{
    int dummy;
    int i;

    for (i = 0; i < 1000; i++) {
        if (!TEST_true(CRYPTO_THREAD_init_local(&thread_local_key,
                thread_local_destructor)))
            return 0;

        if (!TEST_true(CRYPTO_THREAD_set_local(&thread_local_key, &dummy)))
            return 0;

        if (!TEST_true(CRYPTO_THREAD_cleanup_local(&thread_local_key)))
            return 0;
    }
    return 1;
}

static int test_atomic(void)
{
    int val = 0, ret = 0, testresult = 0;
    uint64_t val64 = 1, ret64 = 0;
    CRYPTO_RWLOCK *lock = CRYPTO_THREAD_lock_new();

    if (!TEST_ptr(lock))
        return 0;

    if (CRYPTO_atomic_add(&val, 1, &ret, NULL)) {
        if (!TEST_int_eq(val, 1) || !TEST_int_eq(val, ret))
            goto err;
    } else {
        if (!TEST_int_eq(val, 0) || !TEST_int_eq(val, ret))
            goto err;
    }
    val = 0;
    ret = 0;

    if (!TEST_true(CRYPTO_atomic_add(&val, 1, &ret, lock)))
        goto err;
    if (!TEST_int_eq(val, 1) || !TEST_int_eq(val, ret))
        goto err;

    if (CRYPTO_atomic_or(&val64, 2, &ret64, NULL)) {
        if (!TEST_uint_eq((unsigned int)val64, 3)
            || !TEST_uint_eq((unsigned int)val64, (unsigned int)ret64))
            goto err;
    } else {
        if (!TEST_uint_eq((unsigned int)val64, 1)
            || !TEST_int_eq((unsigned int)ret64, 0))
            goto err;
    }
    val64 = 1;
    ret64 = 0;

    if (!TEST_true(CRYPTO_atomic_or(&val64, 2, &ret64, lock)))
        goto err;

    if (!TEST_uint_eq((unsigned int)val64, 3)
        || !TEST_uint_eq((unsigned int)val64, (unsigned int)ret64))
        goto err;

    ret64 = 0;
    if (CRYPTO_atomic_load(&val64, &ret64, NULL)) {
        if (!TEST_uint_eq((unsigned int)val64, 3)
            || !TEST_uint_eq((unsigned int)val64, (unsigned int)ret64))
            goto err;
    } else {
        if (!TEST_uint_eq((unsigned int)val64, 3)
            || !TEST_int_eq((unsigned int)ret64, 0))
            goto err;
    }

    ret64 = 0;
    if (!TEST_true(CRYPTO_atomic_load(&val64, &ret64, lock)))
        goto err;

    if (!TEST_uint_eq((unsigned int)val64, 3)
        || !TEST_uint_eq((unsigned int)val64, (unsigned int)ret64))
        goto err;

    ret64 = 0;

    if (CRYPTO_atomic_and(&val64, 5, &ret64, NULL)) {
        if (!TEST_uint_eq((unsigned int)val64, 1)
            || !TEST_uint_eq((unsigned int)val64, (unsigned int)ret64))
            goto err;
    } else {
        if (!TEST_uint_eq((unsigned int)val64, 3)
            || !TEST_int_eq((unsigned int)ret64, 0))
            goto err;
    }
    val64 = 3;
    ret64 = 0;

    if (!TEST_true(CRYPTO_atomic_and(&val64, 5, &ret64, lock)))
        goto err;

    if (!TEST_uint_eq((unsigned int)val64, 1)
        || !TEST_uint_eq((unsigned int)val64, (unsigned int)ret64))
        goto err;

    ret64 = 0;

    if (CRYPTO_atomic_add64(&val64, 2, &ret64, NULL)) {
        if (!TEST_uint_eq((unsigned int)val64, 3)
            || !TEST_uint_eq((unsigned int)val64, (unsigned int)ret64))
            goto err;
    } else {
        if (!TEST_uint_eq((unsigned int)val64, 1)
            || !TEST_int_eq((unsigned int)ret64, 0))
            goto err;
    }
    val64 = 1;
    ret64 = 0;

    if (!TEST_true(CRYPTO_atomic_add64(&val64, 2, &ret64, lock)))
        goto err;

    if (!TEST_uint_eq((unsigned int)val64, 3)
        || !TEST_uint_eq((unsigned int)val64, (unsigned int)ret64))
        goto err;

    testresult = 1;
err:
    CRYPTO_THREAD_lock_free(lock);
    return testresult;
}

int threads_test(void)
{
    ADD_TEST(test_lock);
    ADD_TEST(test_once);
    ADD_TEST(test_thread_local);
    ADD_TEST(test_thread_local_multi_key);
    ADD_TEST(test_atomic);
    printf("%s: passed all tests\n", __func__);
    return 0;
}
