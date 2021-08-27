/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
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

#ifndef _TESTENCLAVE_H_
#define _TESTENCLAVE_H_

#include <stdlib.h>
#include <assert.h>

#define TEST_CHECK(status)	\
{	\
	if (status != SGX_SUCCESS) {	\
		printf("OCALL status check failed %s(%d), status = %d\n", __FUNCTION__, __LINE__, status);	\
		abort();	\
	}	\
}

#if defined(__cplusplus)
extern "C" {
#endif

void printf(const char *fmt, ...);

int puts(const char* str);
char* getenv(char* name);
int fflush(void* stream);
void exit(int status);

int rsa_test();
int ec_test();
int ecdh_test();
int ecdsa_test();
int bn_test();
int dh_test();
int sha256_test();
int sha1_test();
int threads_test();
int ecall_sm2();
int ecall_sm3();
int ecall_sm4_cbc();
int ecall_sm4_ctr();

#if defined(__cplusplus)
}
#endif

#endif /* !_TESTENCLAVE_H_ */
