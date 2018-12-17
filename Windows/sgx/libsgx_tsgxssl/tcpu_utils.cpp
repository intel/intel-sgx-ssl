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

#include <sgx_cpuid.h>

// This file is located at: <SDK_trunk>\common\inc\internal\se_cpu_feature_defs.h
// It contains masks for g_cpu_feature_indicator bits
#include "se_cpu_feature_defs.h"

#include "libsgx_tsgxssl_t.h"
#include "tCommon.h"

extern "C" {

// Recommended length is 4 bytes, as this is the basic chunk size used by sgx_read_rand implementation. 
// Giving larger buffer size will result in concatenation of chunks each one of 4 bytes length 
// and may cause entropy reduction.
int sgxssl_read_rand(unsigned char *rand_buf, int length_in_bytes)
{
	FSTART;

	sgx_status_t ret;

	if (rand_buf == NULL ||
		length_in_bytes <= 0) {
		SGX_UNREACHABLE_CODE(SET_NO_ERRNO);
		FEND;
		return 1;
	}

	ret = sgx_read_rand(rand_buf, length_in_bytes);
	if (ret == SGX_SUCCESS) {
		FEND;
		return 0;
	}

	SGX_UNREACHABLE_CODE(SET_NO_ERRNO);
	FEND;
	return 1;
}

int sgx_rand_status(void)
{
    return 1;
}

int get_sgx_rand_bytes(unsigned char *buf, int num)
{
    if (sgxssl_read_rand(buf, num) == 0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

extern uint64_t g_cpu_feature_indicator;

#define CPU_FEATURE_UNAVAILABLE         0xFFFFFFFFULL // Denoting that CPU features information is unavailable

#define FEATURES_BITS_NUM	32

unsigned long long leaf1_edx_features_mask[FEATURES_BITS_NUM] = {
	CPU_FEATURE_FPU,			// bit ix 0
	CPU_FEATURE_UNAVAILABLE,	// bit ix 1
	CPU_FEATURE_UNAVAILABLE,	// bit ix 2
	CPU_FEATURE_UNAVAILABLE,	// bit ix 3
	CPU_FEATURE_UNAVAILABLE,	// bit ix 4
	CPU_FEATURE_UNAVAILABLE,	// bit ix 5
	CPU_FEATURE_UNAVAILABLE,	// bit ix 6
	CPU_FEATURE_UNAVAILABLE,	// bit ix 7
	CPU_FEATURE_UNAVAILABLE,	// bit ix 8
	CPU_FEATURE_UNAVAILABLE,	// bit ix 9
	CPU_FEATURE_UNAVAILABLE,	// bit ix 10
	CPU_FEATURE_UNAVAILABLE,	// bit ix 11
	CPU_FEATURE_UNAVAILABLE,	// bit ix 12
	CPU_FEATURE_UNAVAILABLE,	// bit ix 13
	CPU_FEATURE_UNAVAILABLE,	// bit ix 14
	CPU_FEATURE_CMOV,			// bit ix 15
	CPU_FEATURE_UNAVAILABLE,	// bit ix 16
	CPU_FEATURE_UNAVAILABLE,	// bit ix 17
	CPU_FEATURE_UNAVAILABLE,	// bit ix 18
	CPU_FEATURE_UNAVAILABLE,	// bit ix 19
	CPU_FEATURE_UNAVAILABLE,	// bit ix 20
	CPU_FEATURE_UNAVAILABLE,	// bit ix 21
	CPU_FEATURE_UNAVAILABLE,	// bit ix 22
	CPU_FEATURE_MMX,			// bit ix 23
	CPU_FEATURE_FXSAVE,			// bit ix 24
	CPU_FEATURE_SSE,			// bit ix 25
	CPU_FEATURE_SSE2, 			// bit ix 26
	CPU_FEATURE_UNAVAILABLE,	// bit ix 27
	CPU_FEATURE_UNAVAILABLE,	// bit ix 28
	CPU_FEATURE_UNAVAILABLE,	// bit ix 29
	CPU_FEATURE_UNAVAILABLE,	// bit ix 30
	CPU_FEATURE_UNAVAILABLE		// bit ix 31
};

unsigned long long leaf1_ecx_features_mask[FEATURES_BITS_NUM] = {
	CPU_FEATURE_SSE3,			// bit ix 0
	CPU_FEATURE_PCLMULQDQ,		// bit ix 1
	CPU_FEATURE_UNAVAILABLE,	// bit ix 2
	CPU_FEATURE_UNAVAILABLE,	// bit ix 3
	CPU_FEATURE_UNAVAILABLE,	// bit ix 4
	CPU_FEATURE_UNAVAILABLE,	// bit ix 5
	CPU_FEATURE_UNAVAILABLE,	// bit ix 6
	CPU_FEATURE_UNAVAILABLE,	// bit ix 7
	CPU_FEATURE_UNAVAILABLE,	// bit ix 8
	CPU_FEATURE_SSSE3,			// bit ix 9
	CPU_FEATURE_UNAVAILABLE,	// bit ix 10
	CPU_FEATURE_UNAVAILABLE,	// bit ix 11
	CPU_FEATURE_FMA,			// bit ix 12
	CPU_FEATURE_UNAVAILABLE,	// bit ix 13
	CPU_FEATURE_UNAVAILABLE,	// bit ix 14
	CPU_FEATURE_UNAVAILABLE,	// bit ix 15
	CPU_FEATURE_UNAVAILABLE,	// bit ix 16
	CPU_FEATURE_UNAVAILABLE,	// bit ix 17
	CPU_FEATURE_UNAVAILABLE,	// bit ix 18
	CPU_FEATURE_SSE4_1,			// bit ix 19
	CPU_FEATURE_SSE4_2,			// bit ix 20
	CPU_FEATURE_UNAVAILABLE,	// bit ix 21
	CPU_FEATURE_MOVBE,			// bit ix 22
	CPU_FEATURE_POPCNT,			// bit ix 23
	CPU_FEATURE_UNAVAILABLE,	// bit ix 24
	CPU_FEATURE_UNAVAILABLE,	// bit ix 25
	CPU_FEATURE_UNAVAILABLE, 	// bit ix 26
	CPU_FEATURE_UNAVAILABLE,	// bit ix 27
	CPU_FEATURE_AVX,			// bit ix 28
	CPU_FEATURE_F16C,			// bit ix 29
	CPU_FEATURE_RDRND,			// bit ix 30
	CPU_FEATURE_UNAVAILABLE		// bit ix 31
};


unsigned long long leaf7_ebx_features_mask[FEATURES_BITS_NUM] = {
	CPU_FEATURE_UNAVAILABLE,	// bit ix 0
	CPU_FEATURE_UNAVAILABLE,	// bit ix 1
	CPU_FEATURE_UNAVAILABLE,	// bit ix 2
	CPU_FEATURE_BMI,	// bit ix 3
	CPU_FEATURE_HLE,	// bit ix 4
	CPU_FEATURE_AVX2,	// bit ix 5
	CPU_FEATURE_UNAVAILABLE,	// bit ix 6
	CPU_FEATURE_UNAVAILABLE,	// bit ix 7
	CPU_FEATURE_UNAVAILABLE,	// bit ix 8
	CPU_FEATURE_UNAVAILABLE,	// bit ix 9
	CPU_FEATURE_UNAVAILABLE,	// bit ix 10
	CPU_FEATURE_RTM,	// bit ix 11
	CPU_FEATURE_UNAVAILABLE,	// bit ix 12
	CPU_FEATURE_UNAVAILABLE,	// bit ix 13
	CPU_FEATURE_UNAVAILABLE,	// bit ix 14
	CPU_FEATURE_UNAVAILABLE,	// bit ix 15
	CPU_FEATURE_UNAVAILABLE,	// bit ix 16
	CPU_FEATURE_UNAVAILABLE,	// bit ix 17
	CPU_FEATURE_UNAVAILABLE,	// bit ix 18
	CPU_FEATURE_UNAVAILABLE,	// bit ix 19
	CPU_FEATURE_UNAVAILABLE,	// bit ix 20
	CPU_FEATURE_UNAVAILABLE,	// bit ix 21
	CPU_FEATURE_UNAVAILABLE,	// bit ix 22
	CPU_FEATURE_UNAVAILABLE,	// bit ix 23
	CPU_FEATURE_UNAVAILABLE,	// bit ix 24
	CPU_FEATURE_UNAVAILABLE,	// bit ix 25
	CPU_FEATURE_UNAVAILABLE, 	// bit ix 26
	CPU_FEATURE_UNAVAILABLE,	// bit ix 27
	CPU_FEATURE_UNAVAILABLE,	// bit ix 28
	CPU_FEATURE_UNAVAILABLE,	// bit ix 29
	CPU_FEATURE_UNAVAILABLE,	// bit ix 30
	CPU_FEATURE_UNAVAILABLE		// bit ix 31
};

static void update_feature_mask(unsigned long long* exx_feature_mask, unsigned int * p_exx_value)
{
	// Suppress information, whenever possible, from g_cpu_feature_indicator SDK variable
	for (int bit_ix = 0; bit_ix < FEATURES_BITS_NUM; bit_ix++) {
		if (exx_feature_mask[bit_ix] != CPU_FEATURE_UNAVAILABLE) {
			if (g_cpu_feature_indicator & exx_feature_mask[bit_ix] == 0) {
				*p_exx_value = *p_exx_value & (~(1 << bit_ix));
			}
			else {
				*p_exx_value = *p_exx_value | (1 << bit_ix);
			}
		}
	}
}

void sgxssl_cpuid_leaf_info(int leaf, unsigned int * p_eax_value, unsigned int * p_ebx_value, unsigned int * p_ecx_value, unsigned int * p_edx_value)
{
	FSTART;
	
	int cpuinfo[4] = { 0 };
	sgx_status_t ret;

	ret = sgx_cpuid(cpuinfo, leaf);
	if (ret != SGX_SUCCESS) {
		SGX_UNREACHABLE_CODE(SET_NO_ERRNO);
		FEND;
		return;
	}

	*p_eax_value = (unsigned int)cpuinfo[0];	// EAX
	*p_ebx_value = (unsigned int)cpuinfo[1];	// EBX
	*p_ecx_value = (unsigned int)cpuinfo[2];	// ECX
	*p_edx_value = (unsigned int)cpuinfo[3];	// EDX

	if (leaf == 1)
	{
		update_feature_mask(leaf1_ecx_features_mask, p_ecx_value);
		update_feature_mask(leaf1_edx_features_mask, p_edx_value);

		*p_edx_value &= (~(1 << 4));	// Clear EDX TSC bit #4 as RDTSC is not available inside an enclave
	}
	else if (leaf == 7)
	{
		update_feature_mask(leaf7_ebx_features_mask, p_ebx_value);
	}

	FEND;
	return;
}

} // extern "C"
