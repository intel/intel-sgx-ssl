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

#include "tcommon.h"

extern "C" {

// following 3 functions are only used in OPENSSL_isservice, they should be unreacable since we implement _OPENSSL_isservice

HWND WINAPI sgxssl_GetDesktopWindow(void)
{
	FSTART;
	SGX_UNREACHABLE_CODE(SET_NO_ERRNO);

	FEND;
	// msdn function description doesn't describe return value on failure...
	return NULL;
}

BOOL WINAPI sgxssl_GetUserObjectInformationW(
	_In_       HANDLE hObj,
	_In_       int nIndex,
	_Out_opt_  PVOID pvInfo,
	_In_       DWORD nLength,
	_Out_opt_  LPDWORD lpnLengthNeeded
	)
{
	FSTART;
	SGX_UNREACHABLE_CODE(SET_LAST_ERROR);

	FEND;
	// If the function fails, the return value is zero. To get extended error information, call GetLastError.
	return FALSE;
}


HWINSTA WINAPI sgxssl_GetProcessWindowStation(void)
{
	FSTART;
	SGX_UNREACHABLE_CODE(SET_LAST_ERROR);

	FEND;
	// If the function fails, the return value is NULL. To get extended error information, call GetLastError.
	return NULL;
}


} // extern "C"
