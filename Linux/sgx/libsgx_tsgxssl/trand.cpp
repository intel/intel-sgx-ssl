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

#include "sgx_tsgxssl_t.h"
#include "tcommon.h"

extern "C" {

// Recommended length is 4 bytes, as this is the basic chunk size used by sgx_read_rand implementation. 
// Giving larger buffer size will result in concatenation of chunks each one of 4 bytes length 
// and may cause entropy reduction.
int sgxssl_read_rand(unsigned char *rand_buf, int length_in_bytes)
{
	FSTART;

	sgx_status_t ret;

	if (rand_buf == NULL ||	length_in_bytes <= 0) {
		FEND;
		return 1;
	}

	ret = sgx_read_rand(rand_buf, length_in_bytes);
	if (ret != SGX_SUCCESS) {
		FEND;
		return 1;
	}

	FEND;
	return 0;
}

int sgx_rand_status(void) 
{ 
	return 1; 
}

int get_sgx_rand_bytes(unsigned char *buf, int num) 
{
	if (sgxssl_read_rand(buf, num) == 0) 
	{
		return 1;
	} 
	else 
	{
		return 0;
	}
}

} // extern "C"
