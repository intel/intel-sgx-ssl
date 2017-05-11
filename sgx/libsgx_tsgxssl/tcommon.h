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

#ifndef __TCOMMON_H__
#define __TCOMMON_H__

#include <stdlib.h>
#include <sgx_trts.h>
#include "sgx_tsgxssl_t.h"
#include "errno.h"

#include "tdefines.h"
#include "tSgxSSL_api.h"


//#define DO_SGX_LOG
#define DO_SGX_WARN

#define SGX_ERROR(...) sgx_print("TERROR: " __VA_ARGS__);

#ifdef DO_SGX_WARN
#define SGX_WARNING(...) sgx_print("TWARNING: " __VA_ARGS__);
#else
#define SGX_WARNING(...)
#endif

#ifdef DO_SGX_LOG
#define SGX_LOG(...) sgx_print("TLOG: " __VA_ARGS__);
#else
#define SGX_LOG(...)
#endif

#define SGX_EXIT(err) \
{ \
	abort(); \
}


#ifdef DO_SGX_LOG
#define FSTART SGX_LOG("Enter %s\n", __FUNCTION__)
#define FEND SGX_LOG("Exit from %s\n", __FUNCTION__)
#else
#define FSTART
#define FEND
#endif

#define SET_NO_ERRNO	0
#define SET_ERRNO		1

#define ERROR_NOT_SUPPORTED		50L

#define SGX_REPORT_ERR(set_err) \
{ \
	if (set_err == SET_ERRNO) { \
		SGX_WARNING("%s(%d) - %s, this function is not supported! Setting errno to EINVAL...\n", __FILE__, __LINE__, __FUNCTION__); \
		errno = EINVAL; \
	} \
	else { \
		SGX_WARNING("%s(%d) - %s, this function is not supported! errno is not set ...\n", __FILE__, __LINE__, __FUNCTION__); \
	} \
}

#define SGX_UNSUPPORTED_FUNCTION	SGX_REPORT_ERR

#ifdef  __cplusplus
extern "C" {
#endif

extern UnreachableCodePolicy_t s_unreach_code_policy;

int sgx_print(const char *fmt, ...);

#ifdef  __cplusplus
}
#endif

#define SGX_UNREACHABLE_CODE(set_err) \
{ \
	if (s_unreach_code_policy == UNREACH_CODE_ABORT_ENCLAVE) { \
		SGX_ERROR("%s(%d) - %s, internal error! aborting...\n", __FILE__, __LINE__, __FUNCTION__); \
		SGX_EXIT(-1); \
	}\
	else { \
		SGX_REPORT_ERR(set_err); \
	} \
}

#endif // __TCOMMON_H__
