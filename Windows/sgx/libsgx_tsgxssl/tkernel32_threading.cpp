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

#pragma warning(disable:4197)
#include <map>
#include <vector>
#include <sgx_trts.h>
#include <sgx_thread.h>
#include <sgx_spinlock.h>

#include "tcommon.h"

#include "libsgx_tsgxssl_t.h"

#define NTAPI __stdcall

//////////////////// LAST ERROR ////////////////////

#ifndef SUPPORT_FILES_APIS
extern __declspec(thread)	int s_error;
#endif

extern "C" {

//////////////////// THREAD ID\HANDLE ////////////////////

DWORD WINAPI sgxssl_GetCurrentThreadId(void)
{
	FSTART;

	DWORD threadId;

	// The value is used for printouts. Implementation returns sgx_thread_self(). 
	sgx_thread_t threadSelf = sgx_thread_self();

#ifndef _WIN64
	threadId = threadSelf;
#else 
	threadId = (threadSelf & 0xFFFFFFFF);
#endif

//	SGX_LOG("GetCurrentThreadId: %d\n", threadID);
	FEND;
	return threadId;
}


//////////////////// LAST ERROR ////////////////////
#ifndef SUPPORT_FILES_APIS

DWORD WINAPI sgxssl_GetLastError(void)
{
	FSTART;

	SGX_LOG("GetLastError() = %d (internal)\n", s_error);

	FEND;
	return s_error;
}

void WINAPI sgxssl_SetLastError(DWORD dwErrCode)
{
	FSTART;

	s_error = dwErrCode;

	FEND;
}

#endif

}
