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

#include "sgx_trts.h"
#include "string.h"

extern "C" {


HANDLE WINAPI sgxssl_RegisterEventSourceA(
  _In_  LPCSTR lpUNCServerName,
  _In_  LPCSTR lpSourceName
)
{
	FSTART;

	// If the function fails, the return value is NULL. To get extended error information, call GetLastError.
	SGX_UNREACHABLE_CODE(SET_LAST_ERROR);

	FEND;
	return NULL;
}

BOOL WINAPI sgxssl_DeregisterEventSource(
  _Inout_  HANDLE hEventLog
)
{
	FSTART;

	// If the function fails, the return value is zero. To get extended error information, call GetLastError.
	SGX_UNREACHABLE_CODE(SET_LAST_ERROR);

	FEND;
	return FALSE;
}

BOOL WINAPI sgxssl_ReportEventA(
  _In_  HANDLE hEventLog,
  _In_  WORD wType,
  _In_  WORD wCategory,
  _In_  DWORD dwEventID,
  _In_  PSID lpUserSid,
  _In_  WORD wNumStrings,
  _In_  DWORD dwDataSize,
  _In_  LPCSTR *lpStrings,
  _In_  LPVOID lpRawData
)
{
	FSTART;

	// If the function fails, the return value is zero. To get extended error information, call GetLastError
	SGX_UNREACHABLE_CODE(SET_LAST_ERROR);

	FEND;
	return FALSE;
}

BOOL WINAPI sgxssl_ReportEventW(
  _In_  HANDLE hEventLog,
  _In_  WORD wType,
  _In_  WORD wCategory,
  _In_  DWORD dwEventID,
  _In_  PSID lpUserSid,
  _In_  WORD wNumStrings,
  _In_  DWORD dwDataSize,
  _In_  LPCWSTR *lpStrings,
  _In_  LPVOID lpRawData
)
{
	FSTART;

	// If the function fails, the return value is zero. To get extended error information, call GetLastError
	SGX_UNREACHABLE_CODE(SET_LAST_ERROR);

	FEND;
	return FALSE;
}

HANDLE WINAPI sgxssl_RegisterEventSourceW(
  _In_  LPCWSTR lpUNCServerName,
  _In_  LPCWSTR lpSourceName
)
{
	FSTART;

	// If the function fails, the return value is NULL. To get extended error information, call GetLastError.
	SGX_UNREACHABLE_CODE(SET_LAST_ERROR);

	FEND;
	return NULL;
}


int WINAPI sgxssl_MessageBoxA(
  _In_opt_  HWND hWnd,
  _In_opt_  LPCSTR lpText,
  _In_opt_  LPCSTR lpCaption,
  _In_      UINT uType
)
{
	FSTART;

	// If the function fails, the return value is zero. To get extended error information, call GetLastError.
	SGX_UNREACHABLE_CODE(SET_LAST_ERROR);

	FEND;
	return 0;
}

int WINAPI sgxssl_MessageBoxW(
  _In_opt_  HWND hWnd,
  _In_opt_  LPCWSTR lpText,
  _In_opt_  LPCWSTR lpCaption,
  _In_      UINT uType
)
{
	FSTART;
	
	// If the function fails, the return value is zero. To get extended error information, call GetLastError.
	SGX_UNREACHABLE_CODE(SET_LAST_ERROR);

	FEND;
	return 0;
}

}