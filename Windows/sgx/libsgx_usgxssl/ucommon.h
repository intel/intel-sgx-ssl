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

#ifndef __UCOMMON_H__
#define __UCOMMON_H__


#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "uopensslsgx.h"

#pragma warning( disable: 4100 )

#define PRINT(...) 	{printf(__VA_ARGS__);}

#define DO_SGX_WARN
//#define DO_SGX_LOG

#define SGX_ERROR(...) PRINT("UERROR: " __VA_ARGS__)
#ifdef DO_SGX_WARN
#define SGX_WARNING(...) PRINT("UWARNING: "  __VA_ARGS__)
#else
#define SGX_WARNING(...)
#endif
#ifdef DO_SGX_LOG
#define SGX_LOG(...) PRINT("ULOG: "  __VA_ARGS__)
#else
#define SGX_LOG(...)
#endif

#define SGX_EXIT(err) exit(err)

#define SGX_ASSERT(expr, ...) \
{ \
	if (!(expr)) \
	{ \
		SGX_ERROR("File: %s, Line: %d\n", __FILE__, __LINE__); \
		SGX_ERROR(__VA_ARGS__); \
		SGX_EXIT(-1); \
	} \
}

#define SGX_ASSERT_STRUCT_SIZE(struct_type, struct_size) \
	SGX_ASSERT(sizeof(struct_type) == struct_size, \
	__FUNCTION__ ": Error!!! "#struct_size" (%u) != sizeof("#struct_type") (%u)\n", \
	(uint32_t)struct_size, (uint32_t)sizeof(struct_type))

#define SGX_ASSERT_SIZES_EQUAL(size1, size2) \
	SGX_ASSERT(size1 == size2, \
	__FUNCTION__ ": Error!!! "#size1" (%d) != "#size2" (%d)\n",size1, size2)

#endif // __UCOMMON_H__
