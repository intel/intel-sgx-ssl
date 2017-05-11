/**
*   Copyright(C) 2016 Intel Corporation All Rights Reserved.
*
*   The source code, information  and  material ("Material") contained herein is
*   owned  by Intel Corporation or its suppliers or licensors, and title to such
*   Material remains  with Intel Corporation  or its suppliers or licensors. The
*   Material  contains proprietary information  of  Intel or  its  suppliers and
*   licensors. The  Material is protected by worldwide copyright laws and treaty
*   provisions. No  part  of  the  Material  may  be  used,  copied, reproduced,
*   modified, published, uploaded, posted, transmitted, distributed or disclosed
*   in any way  without Intel's  prior  express written  permission. No  license
*   under  any patent, copyright  or  other intellectual property rights  in the
*   Material  is  granted  to  or  conferred  upon  you,  either  expressly,  by
*   implication, inducement,  estoppel or  otherwise.  Any  license  under  such
*   intellectual  property  rights must  be express  and  approved  by  Intel in
*   writing.
*
*   Third Party trademarks are the property of their respective owners.
*
*   Unless otherwise  agreed  by Intel  in writing, you may not remove  or alter
*   this  notice or  any other notice embedded  in Materials by Intel or Intel's
*   suppliers or licensors in any way.
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
