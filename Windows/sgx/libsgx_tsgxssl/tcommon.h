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

#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdlib.h>
#include <sgx_trts.h>
#include "libsgx_tsgxssl_t.h"
#include "errno.h"

#include "defines.h"
#include "tSgxSSL_api.h"

#pragma warning( disable: 4100 )

//#define DO_SGX_LOG
#define DO_SGX_WARN
#define DO_SGX_ASSERT

#define SGX_ERROR(...) sgx_print("TERROR: " __VA_ARGS__);

#ifdef DO_SGX_WARN
#define SGX_WARNING(...) sgx_print("TWARNING: " __VA_ARGS__);
#else
#define SGX_WARNING(...)
#endif

#ifdef DO_SGX_LOG
#define SGX_LOG(...) sgx_print("TLOG: " __VA_ARGS__);
#else
#define SGX_LOG(...)
#endif

#define SGX_EXIT(err) \
{ \
	abort(); \
}

#define SGX_CHECK(status)  \
{ \
	if ( status != SGX_SUCCESS ) \
	{ \
		SGX_ERROR("Check failed %s(%d), status = %d\n", __FILE__, __LINE__, status); \
		SGX_EXIT(-1); \
	} \
}

#ifdef DO_SGX_ASSERT
#define SGX_ASSERT(expr, ...) \
{ \
	if ( !(expr) ) \
	{ \
		SGX_ERROR("File: %s, Line: %d\n", __FILE__, __LINE__); \
		SGX_ERROR(__VA_ARGS__); \
		SGX_EXIT(-1); \
	} \
}

#define SGX_ASSERT_OUTSIDE_ENCLAVE(varp)		\
	SGX_ASSERT(									\
		varp == NULL || sgx_is_within_enclave(varp, 1) == 0, \
		__FUNCTION__ " Error!!! "#varp" = %p is within enclave\n", varp)

#else // DO_SGX_ASSERT

#define SGX_ASSERT_OUTSIDE_ENCLAVE(varp)
#define SGX_ASSERT(expr, ...)

#endif 

#define SGX_ALLOC_CHECK(ptr) \
{ \
	if ( (void*)(ptr) == NULL) \
	{ \
		SGX_ERROR("Alloc has failed - %s(%d)\n", __FILE__, __LINE__); \
		SGX_EXIT(-1); \
	} \
}


#ifdef DO_SGX_LOG
#define FSTART SGX_LOG("Enter %s\n", __FUNCTION__)
#define FEND SGX_LOG("Exit from %s\n", __FUNCTION__)
#else
#define FSTART
#define FEND
#endif

#define SET_NO_ERRNO	0
#define SET_ERRNO		1
#define SET_LAST_ERROR	2

#define ERROR_NOT_SUPPORTED		50L

#define SGX_REPORT_ERR(set_err) \
{ \
	if (set_err == SET_ERRNO) { \
		SGX_WARNING("%s(%d) - %s, this function is not supported! Setting errno to EINVAL...\n", __FILE__, __LINE__, __FUNCTION__); \
		errno = EINVAL; \
	} \
	else if (set_err == SET_LAST_ERROR) { \
		SGX_WARNING("%s(%d) - %s, this function is not supported! Setting LastError to ERROR_NOT_SUPPORTED...\n", __FILE__, __LINE__, __FUNCTION__); \
		sgxssl_SetLastError(ERROR_NOT_SUPPORTED); \
	} \
	else { \
		SGX_WARNING("%s(%d) - %s, this function is not supported! LastError/errno is not set ...\n", __FILE__, __LINE__, __FUNCTION__); \
	} \
}

#define SGX_UNSUPPORTED_FUNCTION	SGX_REPORT_ERR


extern UnreachableCodePolicy_t s_unreach_code_policy;

#define SGX_UNREACHABLE_CODE(set_err) \
{ \
	if (s_unreach_code_policy == UNREACH_CODE_ABORT_ENCLAVE) { \
		SGX_ERROR("%s(%d) - %s, reached a code that should be unreachable! aborting...\n", __FILE__, __LINE__, __FUNCTION__); \
		SGX_EXIT(-1); \
	}\
	else { \
		SGX_REPORT_ERR(set_err); \
	} \
}

#define SGX_BUFSIZ 512

void wstr2astr(const wchar_t* src, char* dst, size_t dstSize);
void str2Lower(char * src, char* dst, size_t dstSize);

#ifdef  __cplusplus
extern "C" {
#endif
int sgx_print(const char *fmt, ...);
void WINAPI sgxssl_SetLastError(DWORD dwErrCode);
#ifdef  __cplusplus
}
#endif


#endif // __COMMON_H__
