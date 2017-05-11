/**
*   Copyright(C) 2016 Intel Corporation All Rights Reserved.
*
*   The source code, information  and  material ("Material") contained herein is
*   owned  by Intel Corporation or its suppliers or licensors, and title to such
*   Material remains  with Intel Corporation  or its suppliers or licensors. The
*   Material  contains proprietary information  of  Intel or  its  suppliers and
*   licensors. The  Material is protected by worldwide copyright laws and treaty
*   provisions. No  part  of  the  Material  may  be  used,  copied, reproduced,
*   modified, published, uploaded, posted, transmitted, distributed or disclosed
*   in any way  without Intel's  prior  express written  permission. No  license
*   under  any patent, copyright  or  other intellectual property rights  in the
*   Material  is  granted  to  or  conferred  upon  you,  either  expressly,  by
*   implication, inducement,  estoppel or  otherwise.  Any  license  under  such
*   intellectual  property  rights must  be express  and  approved  by  Intel in
*   writing.
*
*   Third Party trademarks are the property of their respective owners.
*
*   Unless otherwise  agreed  by Intel  in writing, you may not remove  or alter
*   this  notice or  any other notice embedded  in Materials by Intel or Intel's
*   suppliers or licensors in any way.
*/

#include <sgx_cpuid.h>

// This file was originaly located at: <SDK_trunk>\common\inc\internal\se_cpu_feature_defs.h
// It contains masks for g_cpu_feature_indicator bits
#include "se_cpu_feature_defs.h"

#include "tcommon.h"

extern "C" {

// Recommended length is 4 bytes, as this is the basic chunk size used by sgx_read_rand implementation. 
// Giving larger buffer size will result in concatenation of chunks each one of 4 bytes length 
// and may cause entropy reduction.
int sgxopenssl_read_rand(unsigned char *rand_buf, int length_in_bytes)
{
	FSTART;

	sgx_status_t ret;
	int retval = 0;

	if (rand_buf == NULL || length_in_bytes <= 0) {
		SGX_UNREACHABLE_CODE(SET_NO_ERRNO);
		FEND;
		return 1;
	}

	ret = sgx_read_rand(rand_buf, length_in_bytes);
	if (ret != SGX_SUCCESS)
		retval = 1;
	
	FEND;
	return retval;
}


extern uint64_t g_cpu_feature_indicator; // defined in trts.lib

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
	// take information, whenever possible, from g_cpu_feature_indicator SDK variable
	for (int bit_ix = 0; bit_ix < FEATURES_BITS_NUM; bit_ix++) {
		if (exx_feature_mask[bit_ix] != CPU_FEATURE_UNAVAILABLE) {
			if ((g_cpu_feature_indicator & exx_feature_mask[bit_ix]) == 0) {
				*p_exx_value = *p_exx_value & (~(1 << bit_ix));
			}
			else {
				*p_exx_value = *p_exx_value | (1 << bit_ix);
			}
		}
	}
}

void sgxssl_cpuid_leaf_info(int leaf, uint32_t* p_eax_value, uint32_t* p_ebx_value, uint32_t* p_ecx_value, uint32_t* p_edx_value)
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

	*p_eax_value = (uint32_t)cpuinfo[0];	// EAX
	*p_ebx_value = (uint32_t)cpuinfo[1];	// EBX
	*p_ecx_value = (uint32_t)cpuinfo[2];	// ECX
	*p_edx_value = (uint32_t)cpuinfo[3];	// EDX

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
