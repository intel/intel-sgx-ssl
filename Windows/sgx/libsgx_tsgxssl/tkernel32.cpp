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

#include <string.h>
#include <stdlib.h>
#include <map>

#include <sgx_trts.h>
#include <sgx_spinlock.h>

#include "tcommon.h"
#include "libsgx_tsgxssl_t.h"

extern "C" {

//#define CP_UTF8 65001 
//#define MB_ERR_INVALID_CHARS 0x00000008

int WINAPI sgxssl_MultiByteToWideChar(
	_In_       UINT CodePage,
	_In_       DWORD dwFlags,
	_In_       char* lpMultiByteStr,
	_In_       int cbMultiByte,
	_Out_opt_  wchar_t* lpWideCharStr,
	_In_       int cchWideChar
	)
{
	FSTART;

#ifdef SUPPORT_FILES_APIS
	size_t ret = mbstowcs(lpWideCharStr, lpMultiByteStr, cchWideChar) + 1;
	FEND;
	return (int) ret;
#else
	SGX_UNREACHABLE_CODE(SET_LAST_ERROR);
	FEND;

	// If the function fails, the return value is zero. Extended error information can be found in last error. 
	return 0;
#endif
}

int WINAPI sgxssl_WideCharToMultiByte(
	_In_       UINT CodePage,
	_In_       DWORD dwFlags,
	_In_       wchar_t* lpWideCharStr,
	_In_       int cchWideChar,
	_Out_opt_  char* lpMultiByteStr,
	_In_       int cbMultiByte,
	_In_opt_   LPCSTR lpDefaultChar,
	_Out_opt_  LPBOOL lpUsedDefaultChar
)
{
	FSTART;

	// wcstombs is dumbed down version of WideCharToMultiByte. 
	// It uses the default system code page (ANSI code page) and user has less control 
	// over different conversion options (dwFlags parameter in WideCharToMultiByte).
	// Therefore, for minimal usage of WideCharToMultiByte with CP_ACP code page 
	// we can use SGXSDK wcstombs function.
	// More enhanced usages of WideCharToMultiByte are currently not seen in OpenSSL 
	// and will be managed later when needed.

	if (CodePage != CP_ACP
		|| dwFlags != 0
		|| (cchWideChar > 0 && lpWideCharStr[cchWideChar-1] != L'0')
		|| lpDefaultChar != NULL
		|| lpUsedDefaultChar != NULL)
	{
		SGX_UNREACHABLE_CODE(SET_LAST_ERROR);
		FEND;
		// If the function fails, the return value is zero. Extended error information can be found in last error. 
		return 0;
	}

	size_t ret = wcstombs (lpMultiByteStr, lpWideCharStr, cbMultiByte);

	FEND;
	return (int)ret;
}


// this is only used in FIPS_get_timevec called from fips_rand
void WINAPI sgxssl_GetSystemTimeAsFileTime(
	_Out_  void* lpSystemTimeAsFileTime
	)
{
	FSTART;
	sgx_status_t ret;

	ret = sgx_read_rand((unsigned char*)lpSystemTimeAsFileTime, FILETIME_SIZE);
	if (ret == SGX_SUCCESS) {
		FEND;
		return;
	}

	// We get here only if we failed to produce random number. 
	// In this case, unreachable code behaviour will apply.
	SGX_UNREACHABLE_CODE(SET_NO_ERRNO);
	FEND;
}

/*
Only used ui_openssl.c (in unreachable place - read from console)
	HANDLE inh;
	inh = GetStdHandle(STD_INPUT_HANDLE);
	FlushConsoleInputBuffer(inh);
*/
BOOL WINAPI sgxssl_FlushConsoleInputBuffer(_In_  HANDLE hConsoleInput)
{	
	FSTART;

	SGX_UNREACHABLE_CODE(SET_LAST_ERROR);

	FEND;

	// If the function fails, the return value is zero. Extended error information can be found in last error. 
	return 0; // failure
}

DWORD WINAPI sgxssl_GetVersion(void)
{
	FSTART;

	SGX_UNREACHABLE_CODE(SET_NO_ERRNO);

	FEND;
	// msdn function description doesn't describe return value on failure...
	return 0;
}


typedef void (__cdecl * SIGNAL_FUNC)(int);
std::map<int, SIGNAL_FUNC> s_sigNumToFunc;
sgx_spinlock_t s_sigMapSpinLock = SGX_SPINLOCK_INITIALIZER;
#define SIG_DFL (void (__cdecl *)(int))0

int sgxssl_raise(int sigNum)
{
	FSTART;

	SIGNAL_FUNC func = NULL;

	sgx_spin_lock(&s_sigMapSpinLock);
	std::map<int, SIGNAL_FUNC>::iterator it = s_sigNumToFunc.find(sigNum);
	if (it != s_sigNumToFunc.end()) {
		func = it->second;
	}
	sgx_spin_unlock(&s_sigMapSpinLock);

	// Call signal handling function if it has been installed
	if (func != NULL) {
		func(sigNum);
		FEND;
		return 0;
	}

	// On error, the function sets errno to EINVAL and returns a nonzero value. 
	SGX_UNREACHABLE_CODE(SET_ERRNO);

	FEND;

	return -1;

}

//void (__cdecl * __cdecl signal(_In_ int sigNum, _In_opt_ SIGNAL_FUNC func))(int)
SIGNAL_FUNC sgxssl_signal(_In_ int sigNum, _In_opt_ SIGNAL_FUNC func)
{
	FSTART;

	SIGNAL_FUNC prev_func = SIG_DFL;

	// Install signal handling
	sgx_spin_lock(&s_sigMapSpinLock);
	std::map<int, SIGNAL_FUNC>::iterator it = s_sigNumToFunc.find(sigNum);
	if (it != s_sigNumToFunc.end()) {
		prev_func = it->second;
	}
	s_sigNumToFunc[sigNum] = func;
	sgx_spin_unlock(&s_sigMapSpinLock);

	FEND;

	return prev_func;
}

BOOL WINAPI sgxssl_QueryPerformanceCounter(
    _Out_ LARGE_INTEGER *lpPerformanceCount
)
{
    if (lpPerformanceCount == NULL) {
        errno = EINVAL;
        return 0;
    }
    SGX_UNSUPPORTED_FUNCTION(SET_LAST_ERROR);
    return 0;
}

DWORD WINAPI sgxssl_GetCurrentProcessId(void)
{
    SGX_UNSUPPORTED_FUNCTION(SET_LAST_ERROR);
    return 8157;
}

void WINAPI sgxssl_OutputDebugStringW(
  _In_opt_ const char* lpOutputString
)
{
    (void)(lpOutputString);
    SGX_UNREACHABLE_CODE(SET_LAST_ERROR);

    return;
}


int WINAPI sgxssl_BCryptGenRandom(
    _Inout_ void* hAlgorithm,
    _Inout_ void*            pbBuffer,
    _In_    ULONG             cbBuffer,
    _In_    ULONG             dwFlags
)
{
    FSTART;

    SGX_UNSUPPORTED_FUNCTION(SET_LAST_ERROR);

    FEND;
    return 0;
}

DWORD WINAPI sgxssl_GetEnvironmentVariableW(
    _In_ const char* lpName,
    _Out_ char*  lpBuffer,
    _In_ DWORD   nSize
) {
    FSTART;

    if (lpName == NULL) {
        FEND;
        return 0;
    }

    if (!strcmp(lpName, (const char*)L"OPENSSL_ia32cap")) {
        FEND;
        return 0;
    }

    SGX_UNREACHABLE_CODE(SET_ERRNO);

    FEND;
    return 0;




}
}   // extern "C"
