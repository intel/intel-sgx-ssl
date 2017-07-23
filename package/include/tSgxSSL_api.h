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

#ifndef __TSGXSSL_API__
#define __TSGXSSL_API__

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	STREAM_STDOUT = 1,
	STREAM_STDERR
} Stream_t;

typedef int (*PRINT_TO_STDOUT_STDERR_CB)(Stream_t stream, const char* fmt, va_list);

//---------------------------------------------------------------------
// API function to register a callback function that will intercept all printouts 
// to stdout or stderr and will be implemented by user to manage them as per user specific needs.
// When there is no registered callback, the printouts will be ignored.
//---------------------------------------------------------------------
void SGXSSLSetPrintToStdoutStderrCB(PRINT_TO_STDOUT_STDERR_CB cb);

typedef enum {
	UNREACH_CODE_ABORT_ENCLAVE = 0,
	UNREACH_CODE_REPORT_ERR_AND_CONTNUE = 1,
} UnreachableCodePolicy_t;

//---------------------------------------------------------------------
// API function to define behaviour when unreachable code is being reached and executed.
// Default policy to abort an enclave as this shouldn't happen.
// For customers, who in any case prefer to continue execution, additional mode, 
// reporting an error through return value and/or setting last error/errno, is available.
//---------------------------------------------------------------------
void SGXSSLSetUnreachableCodePolicy(UnreachableCodePolicy_t policy);

//---------------------------------------------------------------------
// API function to get SgxSSL Library version.
//---------------------------------------------------------------------
const char * SGXSSLGetSgxSSLVersion();

#ifdef __cplusplus
}
#endif

#endif //__TSGXSSL_API__
