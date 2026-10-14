/*
 * Copyright 1995-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

 /*
  * SGX-SSL variant: entropy is obtained from the SGX trusted runtime
  * (sgx_read_rand -> RDRAND inside the enclave) instead of BCrypt/CryptoAPI,
  * which are not available inside an enclave.
  */

#include "internal/cryptlib.h"
#include <openssl/rand.h>
#include "crypto/rand_pool.h"
#include "crypto/rand.h"
#include "prov/seeding.h"

#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_WIN32)

#ifndef OPENSSL_RAND_SEED_OS
  // Normally this is an error, but we are avoiding the use of all OS calls in SGX SSL.
  //#error "Unsupported seeding method configured; must be os"
#endif

// Returns 0 on success.
int sgxssl_read_rand(unsigned char* rand_buf, int length_in_bytes);

size_t ossl_pool_acquire_entropy(RAND_POOL* pool)
{
    unsigned char* buffer;
    size_t bytes_needed;
    size_t entropy_available = 0;


#ifdef OPENSSL_RAND_SEED_RDTSC
#error "Unsupported entropy source"
    entropy_available = ossl_prov_acquire_entropy_from_tsc(pool);
    if (entropy_available > 0)
        return entropy_available;
#endif

#ifdef OPENSSL_RAND_SEED_RDCPU
    entropy_available = ossl_prov_acquire_entropy_from_cpu(pool);
    if (entropy_available > 0)
        return entropy_available;
#endif

    bytes_needed = ossl_rand_pool_bytes_needed(pool, 1 /*entropy_factor*/);
    buffer = ossl_rand_pool_add_begin(pool, bytes_needed);
    if (buffer != NULL) {
        size_t bytes = 0;

        /* SGX trusted RNG (RDRAND-backed) */
        if (sgxssl_read_rand(buffer, bytes_needed))
            bytes = bytes_needed;
        else
            OPENSSL_cleanse(buffer, bytes_needed);

        ossl_rand_pool_add_end(pool, bytes, 8 * bytes);
        entropy_available = ossl_rand_pool_entropy_available(pool);
    }
    if (entropy_available > 0)
        return entropy_available;

    return ossl_rand_pool_entropy_available(pool);
}

int ossl_pool_add_nonce_data(RAND_POOL* pool)
{
    // Normally this function fills in data with PID, TID, and time.
    
    //struct {
    //    DWORD pid;
    //    DWORD tid;
    //    FILETIME time;
    //} data;

    //memset(&data, 0, sizeof(data));

    //data.pid = GetCurrentProcessId();
    //data.tid = GetCurrentThreadId();
    //GetSystemTimeAsFileTime(&data.time);
    
    // We'll just fill the data with random bytes.
    unsigned char data[16];
    int ret = 0;

    if (!sgxssl_read_rand(data, sizeof(data)))
        ret = ossl_rand_pool_add(pool, data, sizeof(data), 0);
    OPENSSL_cleanse(data, sizeof(data));
    return ret;
}

int ossl_rand_pool_init(void)
{
    return 1;
}

void ossl_rand_pool_cleanup(void)
{
}

void ossl_rand_pool_keep_random_devices_open(int keep)
{
}

#endif