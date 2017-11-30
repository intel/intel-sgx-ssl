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

#include "sgx_tsgxssl_t.h"
#include "tcommon.h"


extern "C" {


int sgxssl_getsockname(int sockfd, void *addr, socklen_t *addrlen)
{
	FSTART;

	// It is unreachable under the assumption that TLS support is not required.
	// Otherwise should be implemented as OCALL.
	SGX_UNREACHABLE_CODE(SET_ERRNO);
	FEND;

	return -1;

}

int sgxssl_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
	FSTART;

	// It is unreachable under the assumption that TLS support is not required.
	// Otherwise should be implemented as OCALL.
	SGX_UNREACHABLE_CODE(SET_ERRNO);
	FEND;

	return -1;

}

int sgxssl_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
{
	FSTART;

	// It is unreachable under the assumption that TLS support is not required.
	// Otherwise should be implemented as OCALL.
	SGX_UNREACHABLE_CODE(SET_ERRNO);
	FEND;

	return -1;

}

int sgxssl_socket (int domain, int type, int protocol)
{
	FSTART;

	// It is unreachable under the assumption that TLS support is not required.
	// Otherwise should be implemented as OCALL.
	SGX_UNREACHABLE_CODE(SET_ERRNO);
	FEND;

	return -1;

}

int sgxssl_bind(int sockfd, const void* addr, socklen_t addrlen)
{
	FSTART;

	// It is unreachable under the assumption that TLS support is not required.
	// Otherwise should be implemented as OCALL.
	SGX_UNREACHABLE_CODE(SET_ERRNO);
	FEND;

	return -1;
}

int sgxssl_listen(int sockfd, int backlog)
{
	FSTART;

	// It is unreachable under the assumption that TLS support is not required.
	// Otherwise should be implemented as OCALL.
	SGX_UNREACHABLE_CODE(SET_ERRNO);
	FEND;

	return -1;

}

int sgxssl_connect(int sockfd, const void* addr, socklen_t addrlen)
{
	FSTART;

	// It is unreachable under the assumption that TLS support is not required.
	// Otherwise should be implemented as OCALL.
	SGX_UNREACHABLE_CODE(SET_ERRNO);
	FEND;

	return -1;

}

int sgxssl_accept(int fd, void* addr, socklen_t* addr_len)
{
	FSTART;

	// It is unreachable under the assumption that TLS support is not required.
	// Otherwise should be implemented as OCALL.
	SGX_UNREACHABLE_CODE(SET_ERRNO);
	FEND;

	return -1;

}

void sgxssl_freeaddrinfo(void* res)
{
	FSTART;

	// It is unreachable under the assumption that TLS support is not required.
	// Otherwise should be implemented as OCALL.
	SGX_UNREACHABLE_CODE(SET_ERRNO);
	FEND;

	return;

}

void* sgxssl_gethostbyname(const char *name)
{
	FSTART;

	// It is unreachable under the assumption that TLS support is not required.
	// Otherwise should be implemented as OCALL.
	SGX_UNREACHABLE_CODE(SET_ERRNO);
	FEND;

	return NULL;

}

int sgxssl_getnameinfo(const void* sa, socklen_t salen,
                       char *host, size_t hostlen,
                       char *serv, size_t servlen, int flags)
{
	FSTART;

	// It is unreachable under the assumption that TLS support is not required.
	// Otherwise should be implemented as OCALL.
	SGX_UNREACHABLE_CODE(SET_ERRNO);
	FEND;

	return -1;

}

int sgxssl_getaddrinfo(const char *node, const char *service,
                       const void* hints,
                       void** res)
{
	FSTART;

	// It is unreachable under the assumption that TLS support is not required.
	// Otherwise should be implemented as OCALL.
	SGX_UNREACHABLE_CODE(SET_ERRNO);
	FEND;

	return -1;

}

int sgxssl_ioctl (int fd, unsigned long int request, ...)
{
	FSTART;

	// It is unreachable under the assumption that TLS support is not required.
	// Otherwise should be implemented as OCALL.
	SGX_UNREACHABLE_CODE(SET_ERRNO);
	FEND;

	return NULL;
}

char * sgxssl_gai_strerror(int err)
{
	FSTART;

	// If unreachable code policy was changed the function below will return an error string for EINVAL.
	// Otherwise, it will be reporting "Unknown error - <errno>" until support for EAI_<errors> will be implemented.
	char * str = strerror(err);

	FEND;

	return str;
}

}
