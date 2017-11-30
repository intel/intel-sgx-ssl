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

#include <stdio.h>
#include <string>
#include <sgx_trts.h>
#include "tcommon.h"
#include "libsgx_tsgxssl_t.h"

extern "C" {

int _OPENSSL_isservice(void)
{// returnig 0 here skips several function calls in the code
	return 0;
}

#define FAKE_HMODULE ((HMODULE)0x12345)

HMODULE WINAPI sgxssl_GetModuleHandleA(
	_In_opt_  const char* lpModuleName
	)
{
	FSTART;

	if (lpModuleName == NULL) {
		FEND;
		return FAKE_HMODULE; // not NULL
	}

	// request to retrieve module handle other then local (NULL) is not supported
	SGX_UNREACHABLE_CODE(SET_LAST_ERROR);
	
	FEND;

	// If the function fails, the return value is NULL. To get extended error information, call GetLastError.
	return NULL;
}

HMODULE WINAPI sgxssl_GetModuleHandleW(
	_In_opt_  const wchar_t* lpModuleName
	)
{
	FSTART;

	if (lpModuleName == NULL) {
		FEND;
		return FAKE_HMODULE; // not NULL
	}

	// request to retrieve module handle other then local (NULL) is not supported
	SGX_UNREACHABLE_CODE(SET_LAST_ERROR);

	FEND;

	// If the function fails, the return value is NULL. To get extended error information, call GetLastError.
	return NULL;
}


FARPROC WINAPI sgxssl_GetProcAddress(
	_In_  HMODULE hModule,
	_In_  LPCSTR lpProcName
	)
{
	FSTART;
	
	int ret = strncmp("_OPENSSL_isservice", lpProcName, strlen("_OPENSSL_isservice"));

	if (hModule == FAKE_HMODULE && ret == 0)
	{
		FEND;
		return _OPENSSL_isservice;
	}

	// only supporting request for _OPENSSL_isservice from local module
	SGX_UNREACHABLE_CODE(SET_LAST_ERROR);

	FEND;

	// If the function fails, the return value is NULL. To get extended error information, call GetLastError.
	return NULL;
}


/* 
Used in cryptlib.c:
	if ((h=GetStdHandle(STD_ERROR_HANDLE)) != NULL && GetFileType(h) != FILE_TYPE_UNKNOWN)
and in ui_openssl.c (in unreachable place - read from console)
	HANDLE inh;
	inh = GetStdHandle(STD_INPUT_HANDLE);
	FlushConsoleInputBuffer(inh);
*/

#define STD_INPUT_HANDLE    ((DWORD)-10)
#define STD_OUTPUT_HANDLE   ((DWORD)-11)
#define STD_ERROR_HANDLE    ((DWORD)-12)

 HANDLE WINAPI sgxssl_GetStdHandle(_In_  DWORD nStdHandle)
{
	FSTART;

	if (nStdHandle == STD_INPUT_HANDLE	||
		nStdHandle == STD_OUTPUT_HANDLE	||
		nStdHandle == STD_ERROR_HANDLE) {

		FEND;
		return FAKE_STD_HANDLE;
	}

	// If the function fails, the return value is INVALID_HANDLE_VALUE. To get extended error information, call GetLastError.
	SGX_UNREACHABLE_CODE(SET_LAST_ERROR);

	FEND;
	return INVALID_HANDLE_VALUE;
}

}
