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

#include "sgx_tsgxssl_t.h"
#include "tcommon.h"


extern "C" {


time_t sgxssl_time (time_t *timer)
{
	FSTART;

	struct timeb timeptr;

	sgx_status_t sgx_ret = u_sgxssl_ftime(&timeptr, sizeof(struct timeb));
	if (sgx_ret != SGX_SUCCESS)
	{
		errno = EFAULT;
		timeptr.time = (time_t)-1;
	}

	if (timer != NULL) {
		*timer = timeptr.time;
	}

	FEND;
	return timeptr.time;

}

int sgxssl_gettimeofday(struct timeval *tv, struct timezone *tz)
{
	FSTART;

	if (tz != NULL) {
		// It is unreachable based on the current OpenSSL usage.
		SGX_UNREACHABLE_CODE(SET_ERRNO);
		FEND;
		return -1;
	}

	struct timeb timeptr;

	sgx_status_t sgx_ret = u_sgxssl_ftime(&timeptr, sizeof(struct timeb));
	if (sgx_ret != SGX_SUCCESS)
	{
		errno = EFAULT;
		FEND;
		return -1;
	}

	if (tv != NULL) {
		tv->tv_sec = timeptr.time;
		tv->tv_usec = timeptr.millitm;
	}

	FEND;

	return 0;
}

}
