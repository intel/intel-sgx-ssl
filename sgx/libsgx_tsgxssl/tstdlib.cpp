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
#include "tSgxSSL_api.h"


#ifndef SE_SIM

// following definition is copied from common/inc/internal/se_cdefs.h

#define SGX_ACCESS_VERSION(libname, num)                    \
    extern "C" const char *sgx_##libname##_version;          \
    const char * __attribute__((destructor)) libname##_access_version_dummy##num()      \
    {                                                       \
        return sgx_##libname##_version;                     \
    } 


// add a version to libsgx_tsgxssl
SGX_ACCESS_VERSION(tssl, 1);

#endif

#define PATH_DEV_NULL				"/dev/null"

extern "C" {

char *sgxssl_getenv(const char *name)
{
	FSTART;

	if (name == NULL ) {
		FEND;
		return NULL;
	}

	if (!strcmp(name, "OPENSSL_CONF" )) {
		FEND;
		return NULL;
	}

	if (!strcmp(name, "OPENSSL_ENGINES" )) {
		FEND;
		return (char *) PATH_DEV_NULL;
	}

	if (!strcmp(name, "OPENSSL_ALLOW_PROXY_CERTS" )) {
		FEND;
		return NULL;
	}
	
	if (!strcmp(name, "OPENSSL_ia32cap" )) {
		FEND;
		return NULL;
	}

	SGX_UNREACHABLE_CODE(SET_ERRNO);

	FEND;
	return NULL;
}

int sgxssl_atexit(void (*function)(void))
{
	// Do nothing, assuming that registered function does allocations cleanup.
	// This should be fine, as sgx_destroy_enclave cleans everything inside of enclave.
	return 0;
}

}
