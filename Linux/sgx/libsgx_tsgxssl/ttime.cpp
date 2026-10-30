/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "sgx_tsgxssl_t.h"
#include "tcommon.h"
#include <assert.h>

extern sgx_status_t SGX_CDECL u_sgxssl_clock_gettime(int clk_id, void* tp, uint32_t tp_len) __attribute__((weak));

extern "C" {

#ifdef SGXSSL_FIPS
time_t time (time_t *timer)
{
    FSTART;

    struct timespec tp;

    assert(NULL != u_sgxssl_clock_gettime && "u_sgxssl_clock_gettime is NULL...");

    sgx_status_t sgx_ret = u_sgxssl_clock_gettime(CLOCK_REALTIME, &tp, sizeof(struct timespec));
    if (sgx_ret != SGX_SUCCESS)
    {
        errno = EFAULT;
        tp.tv_sec = (time_t)-1;
    }

    if (timer != NULL) {
        *timer = tp.tv_sec;
    }

    FEND;
    return tp.tv_sec;
}
#endif

time_t sgxssl_time (time_t *timer)
{
    FSTART;

    struct timespec tp;

    assert(NULL != u_sgxssl_clock_gettime && "u_sgxssl_clock_gettime is NULL...");

    sgx_status_t sgx_ret = u_sgxssl_clock_gettime(CLOCK_REALTIME, &tp, sizeof(struct timespec));
    if (sgx_ret != SGX_SUCCESS)
    {
        errno = EFAULT;
        tp.tv_sec = (time_t)-1;
    }

    if (timer != NULL) {
        *timer = tp.tv_sec;
    }

    FEND;
    return tp.tv_sec;
}

int sgxssl_gettimeofday(struct timeval *tv, struct timezone *tz)
{
    FSTART;

    if (tz != NULL) {
        // It is unreachable based on the current OpenSSL usage.
        SGX_UNREACHABLE_CODE(SET_ERRNO);
        FEND;
        return -1;
    }

    struct timespec tmp_tp;

    assert(NULL != u_sgxssl_clock_gettime && "u_sgxssl_clock_gettime is NULL...");

    sgx_status_t sgx_ret = u_sgxssl_clock_gettime(CLOCK_REALTIME, &tmp_tp, sizeof(struct timespec));
    if (sgx_ret != SGX_SUCCESS)
    {
        errno = EFAULT;
        FEND;
        return -1;
    }

    if (tv != NULL) {
        tv->tv_sec = tmp_tp.tv_sec;
        tv->tv_usec = tmp_tp.tv_nsec / 1000;
    }

    FEND;
    return 0;
}

int sgxssl_clock_gettime(int clk_id, struct timespec *tp)
{
    FSTART;

    assert(NULL != u_sgxssl_clock_gettime && "u_sgxssl_clock_gettime is NULL...");

    sgx_status_t sgx_ret = u_sgxssl_clock_gettime(clk_id, tp, sizeof(struct timespec));
    if (sgx_ret != SGX_SUCCESS) {
        errno = EFAULT;
        return -1;
    }

    FEND;
    return 0;
}

/* Intentionally left as a no-op for the time being */
void sgxssl_sleep(int seconds)
{
    (void)(seconds);
    return;
}

}
