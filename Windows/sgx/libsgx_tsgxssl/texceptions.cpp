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

#include <sgx_trts.h>
#include <sgx_trts_exception.h>
#include <sgx_cpuid.h>
#include <stdlib.h>

#include "tcommon.h"


// It is enouph to keep cpuid values for leaves 0x0, 0x1, and 0x4 (ecx = 0x0)
uint32_t cpuinfo[8][4] = { { 0x0, 0x0, 0x0, 0x0 } };
uint32_t intel_cpuid_leaf_0_ebx = 0x756e6547;	//ebx = "Genu"
uint32_t intel_cpuid_leaf_0_ecx = 0x6c65746e;	// ecx = "ntel"
uint32_t intel_cpuid_leaf_0_edx = 0x49656e69;	// edx = "ineI"


extern "C" void init_exception_handler(void);
// this global parameter will be initialized when the DLL is first loaded, before any code is executed
// this must be done this way, since openssl DLLMain function includes a call to CPUID


typedef void (*ExcHandlerInit)(void);

// Following code will be initialized as part of the global objects initializations at the first ECALL function.
// FIPS code executes cpuid as part of the global initialization (.CRT$XCUI section)
// The linker puts .CRT$XIY section before .CRT$XCU. Following code will cause linker 
// to put exceptuion handler registration inside .CRT$XIU section and hence 
// cause exception handler to be registered before cpuid is being executed.
#ifdef _WIN64
#pragma section(".CRT$XIY", long, read)
#endif
#pragma data_seg(".CRT$XIY")
ExcHandlerInit eh_init = init_exception_handler;
#pragma data_seg()

#define CPUID_OPCODE 0xA20F
#define RDTSC_OPCODE 0x310F

extern "C" void sgxssl_cpuid_leaf_info(
	int leaf,
	unsigned int * p_eax_value,
	unsigned int * p_ebx_value,
	unsigned int * p_ecx_value,
	unsigned int * p_edx_value);

// rdtsc support here is temporary, only for SKL, later CPU's will support this inside enclave
uint64_t fake_rdtsc_value = 0;
uint16_t fake_rdtsc_inc_value = 1000;

int sgxssl_exception_handler(sgx_exception_info_t* info)
{

	if (info->exception_vector == SGX_EXCEPTION_VECTOR_UD &&
		info->exception_type == SGX_EXCEPTION_HARDWARE)
	{
		uint16_t ip_opcode;
		uint32_t leaf;
		uint32_t sub_leaf;

#ifndef _WIN64
		ip_opcode = *(uint16_t*)info->cpu_context.eip;
		leaf = info->cpu_context.eax;
		sub_leaf = info->cpu_context.ecx;
#else
		ip_opcode = *(uint16_t*)info->cpu_context.rip;
		leaf = (uint32_t)info->cpu_context.rax;
		sub_leaf = (uint32_t)info->cpu_context.rcx;
#endif

		if (ip_opcode == CPUID_OPCODE)
		{
			if (leaf != 0x0
				&& leaf != 0x1
				&& (leaf != 0x4 || sub_leaf != 0x0)
				&& (leaf != 0x7 || sub_leaf != 0x0)) {
				return EXCEPTION_CONTINUE_SEARCH;
			}

#ifndef _WIN64
			info->cpu_context.eax = cpuinfo[leaf][0];
			info->cpu_context.ebx = cpuinfo[leaf][1];
			info->cpu_context.ecx = cpuinfo[leaf][2];
			info->cpu_context.edx = cpuinfo[leaf][3];
			info->cpu_context.eip += 2;
#else
			info->cpu_context.rax = cpuinfo[leaf][0];
			info->cpu_context.rbx = cpuinfo[leaf][1];
			info->cpu_context.rcx = cpuinfo[leaf][2];
			info->cpu_context.rdx = cpuinfo[leaf][3];
			info->cpu_context.rip += 2;
#endif		
			return EXCEPTION_CONTINUE_EXECUTION;
		}

		if (ip_opcode == RDTSC_OPCODE)
		{
			fake_rdtsc_value += fake_rdtsc_inc_value;
#ifndef _WIN64
			info->cpu_context.eax = (uint32_t)(fake_rdtsc_value & 0xFFFFFFFF);
			info->cpu_context.edx = (uint32_t)(fake_rdtsc_value >> 32);
			info->cpu_context.eip += 2;
#else
			info->cpu_context.rax = (uint32_t)(fake_rdtsc_value & 0xFFFFFFFF);
			info->cpu_context.rdx = (uint32_t)(fake_rdtsc_value >> 32);
			info->cpu_context.rip += 2;
#endif	
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

int is_intel_cpu(uint32_t *cpuid_leaf_0)
{
	if (cpuid_leaf_0[1] == intel_cpuid_leaf_0_ebx
		|| cpuid_leaf_0[2] == intel_cpuid_leaf_0_ecx
		|| cpuid_leaf_0[3] == intel_cpuid_leaf_0_edx)
	{
		return 1;	// It is Intel cpu
	}

	return 0;	// Not Intel cpu
}

// Initialize cpuid leaves for FIPS capable OpenSSL
//-------------------------------------------------
void init_cpuinfo(void)
{
	sgx_status_t status;

	// Leaf 0
	status = sgx_cpuid((int*)cpuinfo[0], 0);
	if (status != SGX_SUCCESS
		|| !is_intel_cpu(cpuinfo[0]))	{
		SGX_UNREACHABLE_CODE(SET_NO_ERRNO);
	}

	// Leaf 1
	sgxssl_cpuid_leaf_info(1,
		&(unsigned int)cpuinfo[1][0],
		&(unsigned int)cpuinfo[1][1],
		&(unsigned int)cpuinfo[1][2],
		&(unsigned int)cpuinfo[1][3]);

	// Leaf 4
	status = sgx_cpuid((int*)cpuinfo[4], 4);
	if (status != SGX_SUCCESS) {
		SGX_UNREACHABLE_CODE(SET_NO_ERRNO);
	}

	// Leaf 7
	sgxssl_cpuid_leaf_info(7,
		&(unsigned int)cpuinfo[7][0],
		&(unsigned int)cpuinfo[7][1],
		&(unsigned int)cpuinfo[7][2],
		&(unsigned int)cpuinfo[7][3]);

	return;
}

void init_exception_handler(void)
{
	if (!eh_init) {
		SGX_UNREACHABLE_CODE(SET_NO_ERRNO);
	}

	// Prepend the exception handler to the current exception handler's chain.
	sgx_register_exception_handler(1, sgxssl_exception_handler);

	init_cpuinfo();

	return;
}




