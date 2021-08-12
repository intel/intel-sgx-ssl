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

#define CPUID_OPCODE 0xA20F
#define RDTSC_OPCODE 0x310F

//OpenSSL initialization API
void OPENSSL_cpuid_setup(void);

void sgxssl_cpuid_leaf_info(
	int leaf,
	uint32_t * p_eax_value,
	uint32_t * p_ebx_value,
	uint32_t * p_ecx_value,
	uint32_t * p_edx_value);

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

		ip_opcode = *(uint16_t*)info->cpu_context.rip;
		leaf = (uint32_t)info->cpu_context.rax;
		sub_leaf = (uint32_t)info->cpu_context.rcx;

		if (ip_opcode == CPUID_OPCODE)
		{
			if (leaf != 0x0
				&& leaf != 0x1
				&& (leaf != 0x4 || sub_leaf != 0x0)
				&& (leaf != 0x7 || sub_leaf != 0x0)) {
				return EXCEPTION_CONTINUE_SEARCH;
			}

			info->cpu_context.rax = cpuinfo[leaf][0];
			info->cpu_context.rbx = cpuinfo[leaf][1];
			info->cpu_context.rcx = cpuinfo[leaf][2];
			info->cpu_context.rdx = cpuinfo[leaf][3];
			info->cpu_context.rip += 2;

			return EXCEPTION_CONTINUE_EXECUTION;
		}

		if (ip_opcode == RDTSC_OPCODE)
		{
			fake_rdtsc_value += fake_rdtsc_inc_value;

			info->cpu_context.rax = (uint32_t)(fake_rdtsc_value & 0xFFFFFFFF);
			info->cpu_context.rdx = (uint32_t)(fake_rdtsc_value >> 32);
			info->cpu_context.rip += 2;

			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

static int is_intel_cpu(uint32_t *cpuid_leaf_0)
{
	if (cpuid_leaf_0[1] == intel_cpuid_leaf_0_ebx
		|| cpuid_leaf_0[2] == intel_cpuid_leaf_0_ecx
		|| cpuid_leaf_0[3] == intel_cpuid_leaf_0_edx)
	{
		return 1;	// It is Intel cpu
	}

	return 0;	// Not Intel cpu
}

// Setup cpuid leaves for FIPS capable OpenSSL
//-------------------------------------------------
static void setup_cpuinfo(uint32_t *cpuinfo_table)
{
	sgx_status_t status;
    
    if (cpuinfo_table) {
        // cpuid have been passed from urts
        memcpy(cpuinfo, cpuinfo_table, sizeof(uint32_t)*8*4);
    } else {
        // Leaf 0
        status = sgx_cpuid((int*)cpuinfo[0], 0);
        if (status != SGX_SUCCESS) {
            SGX_UNREACHABLE_CODE(SET_NO_ERRNO);
        }
        
        // Leaf 1
        status = sgx_cpuid((int*)cpuinfo[1], 1);
        if (status != SGX_SUCCESS) {
            SGX_UNREACHABLE_CODE(SET_NO_ERRNO);
            return;
        }
        
        // Leaf 4
        status = sgx_cpuid((int*)cpuinfo[4], 4);
        if (status != SGX_SUCCESS) {
            SGX_UNREACHABLE_CODE(SET_NO_ERRNO);
        }
        
        // Leaf 7
        status = sgx_cpuid((int*)cpuinfo[7], 7);
        if (status != SGX_SUCCESS) {
            SGX_UNREACHABLE_CODE(SET_NO_ERRNO);
        }
    }

	// Leaf 0
	if (!is_intel_cpu(cpuinfo[0]))	{
		SGX_UNREACHABLE_CODE(SET_NO_ERRNO);
	}

	// Leaf 1
	sgxssl_cpuid_leaf_info(1,
		&cpuinfo[1][0],
		&cpuinfo[1][1],
		&cpuinfo[1][2],
		&cpuinfo[1][3]);

	// Leaf 7
	sgxssl_cpuid_leaf_info(7,
		&cpuinfo[7][0],
		&cpuinfo[7][1],
		&cpuinfo[7][2],
		&cpuinfo[7][3]);

	return;
}


static int exception_handler_initialized = 0;
static int cpuid_initialized = 0;

extern void init_exception_handler(uint32_t *cpuinfo_table)
{
    if (cpuid_initialized == 1)
        return;
    cpuid_initialized = 1;

    //initialize CPUID values
    setup_cpuinfo(cpuinfo_table);

    return;
}

__attribute__((constructor)) void const_init_exception_handler(void)
{
    if (exception_handler_initialized == 1)
        return;
    exception_handler_initialized = 1;

    //Prepend the exception handler to the current exception handler's chain.
    sgx_register_exception_handler(1, sgxssl_exception_handler);

    init_exception_handler(NULL);

    //Setup OpenSSL CPUID, this call replaces the original call in .init section
    OPENSSL_cpuid_setup();

    return;
}

