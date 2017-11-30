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

#include <stdlib.h>
#include <string.h>
#include "tcommon.h"
#include "errno.h"
#include "libsgx_tsgxssl_t.h"
#include "tSgxSSL_api.h"


#define ENV_OPENSSL_FIPS		"OPENSSL_FIPS"
#define ENV_X509_CERT_DIR_EVP	"X509_CERT_DIR_EVP"
#define ENV_OPENSSL_ALLOW_PROXY_CERTS	"OPENSSL_ALLOW_PROXY_CERTS"
#define ENV_OPENSSL_ENGINES		"OPENSSL_ENGINES"
#define DUMMY_PATH	"C:\\dev\\null"
#define STR_OPENSSL_FIPS			"1"
#define STR_PROXY_CERTS_ALLOWED		"1"

extern ProxyCertsPolicy_t s_proxy_certs_policy;


extern "C" {

char* sgxssl_getenv(const char* name)
{
	FSTART;

	if (! strcmp(name, ENV_X509_CERT_DIR_EVP) ||
		! strcmp(name, ENV_OPENSSL_ENGINES)) {
	    FEND;
		return DUMMY_PATH;
	}

	if (! strcmp(name, ENV_OPENSSL_ALLOW_PROXY_CERTS)) {
		if (s_proxy_certs_policy == PROXY_CERTS_ALLOWED) {
		    FEND;
			return STR_PROXY_CERTS_ALLOWED;
		}
		else {
			// OpenSSL expects NULL to be returned when proxy certificates are not allowed 
		    FEND;
			return NULL;
		}
	}

	if (! strcmp(name, "OPENSSL_ia32cap"))
	{
		FEND;
		return NULL;
	}

#ifndef SUPPORT_FILES_APIS
	SGX_UNREACHABLE_CODE(SET_ERRNO);
#endif
	
	FEND;

	// If varname is NULL. If execution is allowed to continue, this function sets errno to EINVAL and returns NULL.
	return NULL;
}


int* sgxssl__errno()
{
	return __errno();
}

void sgxssl__exit(
	int status
	)
{
	FSTART;

	SGX_WARNING("%s - The process is being terminated\n", __FUNCTION__);

	// Aborting an enclave makes it unusable. The aborting thread generates an exception and exits the enclave.
	// Other enclave threads will continue running normally until they exit an enclave.
	// After the thread calls abort, the enclave is locked and cannot be recovered. 
	abort(); 

#pragma warning(push)
#pragma warning (disable:4127)
	SGX_ASSERT(0, "The process has been terminated. This code should never be reached.\n");
#pragma warning(pop)

	FEND;
}

#ifdef _WIN64
void __imp_RtlVirtualUnwind()
{
	sgxssl__exit(1);
}
#endif



} // extern "C" 
