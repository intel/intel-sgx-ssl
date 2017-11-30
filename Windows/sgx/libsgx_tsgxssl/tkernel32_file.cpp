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

#define printf	sgxssl_printf

#include <sgx_trts.h>
#include "tcommon.h"
#include "libsgx_tsgxssl_t.h"

extern "C" {

/* 
Only used in cryptlib.c:
	if ((h=GetStdHandle(STD_ERROR_HANDLE)) != NULL && GetFileType(h) != FILE_TYPE_UNKNOWN)

	#define FILE_TYPE_UNKNOWN   0x0000
	#define FILE_TYPE_DISK      0x0001
	#define FILE_TYPE_CHAR      0x0002
	#define FILE_TYPE_PIPE      0x0003
	#define FILE_TYPE_REMOTE    0x8000
*/
#define FILE_TYPE_UNKNOWN   0x0000
#define FILE_TYPE_DISK      0x0001
DWORD WINAPI sgxssl_GetFileType ( _In_ HANDLE hFile )
{
	FSTART;

	if (hFile == FAKE_STD_HANDLE) {
		return FILE_TYPE_DISK;
	}

	// On error the function sets error code and returns FILE_TYPE_UNKNOWN.
	SGX_UNREACHABLE_CODE(SET_LAST_ERROR);
	
	FEND;

	return FILE_TYPE_UNKNOWN ;
}

#ifndef SUPPORT_FILES_APIS

BOOL WINAPI sgxssl_FindClose ( _Inout_ HANDLE hFindFile )
{
	FSTART;

	// If the function fails, the return value is zero.
	// On Failure LastError will be set. No impact on errno. 
	SGX_UNSUPPORTED_FUNCTION(SET_LAST_ERROR);

	FEND;
	return FALSE;
}


int printf(const char* fmt, ...);
BOOL WINAPI sgxssl_WriteFile(
	_In_         HANDLE hFile,
	_In_         LPCVOID lpBuffer,
	_In_         DWORD nNumberOfBytesToWrite,
	_Out_opt_    LPDWORD lpNumberOfBytesWritten,
	_Inout_opt_  LPOVERLAPPED lpOverlapped
	)
{
	FSTART;

	if (lpOverlapped != NULL) {
		SGX_UNREACHABLE_CODE(SET_LAST_ERROR);
	}

	if (hFile == FAKE_STD_HANDLE)
	{// used in FIPS OPENSSL_showfatal
		int count = printf("%.*s", nNumberOfBytesToWrite, (const char*)lpBuffer);
		if (lpNumberOfBytesWritten != NULL)
			*lpNumberOfBytesWritten = count;

		FEND;
		return TRUE;
	}

	//If the function fails, or is completing asynchronously, the return value is zero (FALSE). 
	// On Failure LastError will be set. No impact on errno. 
	SGX_UNSUPPORTED_FUNCTION(SET_LAST_ERROR);

	FEND;
	return FALSE;
}


HANDLE WINAPI sgxssl_FindFirstFileA(
  _In_   LPCSTR lpFileName,
  _Out_  LPWIN32_FIND_DATAA lpFindFileData
)
{
	FSTART;

	// If the function fails or fails to locate files from the search string in the lpFileName parameter, 
	// the return value is INVALID_HANDLE_VALUE and the contents of lpFindFileData are indeterminate.
	// On Failure LastError will be set. No impact on errno. 
	SGX_UNSUPPORTED_FUNCTION(SET_LAST_ERROR);

	FEND;
	return INVALID_HANDLE_VALUE;
}

BOOL WINAPI sgxssl_FindNextFileA(
  _In_   HANDLE hFindFile,
  _Out_  LPWIN32_FIND_DATAA lpFindFileData
)
{
	FSTART;

	// If the function fails, the return value is zero and the contents of lpFindFileData are indeterminate.
	// On Failure LastError will be set. No impact on errno. 
	SGX_UNSUPPORTED_FUNCTION(SET_LAST_ERROR);

	FEND;
	return FALSE;
}

HANDLE WINAPI sgxssl_FindFirstFileW(
  _In_   LPCWSTR lpFileName,
  _Out_  LPWIN32_FIND_DATAW lpFindFileData
)
{
	FSTART;

	// If the function fails or fails to locate files from the search string in the lpFileName parameter, 
	// the return value is INVALID_HANDLE_VALUE and the contents of lpFindFileData are indeterminate. 
	// On Failure LastError will be set. No impact on errno. 
	SGX_UNSUPPORTED_FUNCTION(SET_LAST_ERROR);

	FEND;
	return INVALID_HANDLE_VALUE;
}

BOOL WINAPI sgxssl_FindNextFileW(
  _In_   HANDLE hFindFile,
  _Out_  LPWIN32_FIND_DATAW lpFindFileData
)
{
	FSTART;

	// If the function fails, the return value is zero and the contents of lpFindFileData are indeterminate.
	// On Failure LastError will be set. No impact on errno. 
	SGX_UNSUPPORTED_FUNCTION(SET_LAST_ERROR);

	FEND;
	return FALSE;
}

#endif	// SUPPORT_FILES_APIS is not defined

}
