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

#include "ucommon.h"

#include <time.h>
#include <stdint.h>
#include <windows.h>

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 0
#endif

struct sgxssl_timespec {
	int64_t tv_sec;
	long tv_nsec;
};

void u_sgxssl_clock_gettime(int clk_id, void * tpptr, uint32_t tp_len)
{
	SGX_ASSERT_STRUCT_SIZE(struct sgxssl_timespec, tp_len)
	sgxssl_timespec* tp = (sgxssl_timespec*)tpptr;
	struct timespec ts;

	if (clk_id != CLOCK_REALTIME || timespec_get(&ts, TIME_UTC) != TIME_UTC) {
		tp->tv_sec = -1;
		tp->tv_nsec = 0;
	}
	else {
		tp->tv_sec = (int64_t)ts.tv_sec;
		tp->tv_nsec = ts.tv_nsec;
	}
}

void u_sgxssl_sleep(int seconds)
{
	Sleep(seconds);
}
