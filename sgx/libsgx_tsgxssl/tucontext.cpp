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

int sgxssl_getcontext(void *ucp)
{
	FSTART;

	// Note, current implementation of getcontext() as unsupported function makes makecontext() unreachable
	SGX_UNSUPPORTED_FUNCTION(SET_ERRNO);

	FEND;

	// On error, return -1 and set errno appropriately
	return -1;

}

int sgxssl_setcontext(const void *ucp)
{
	FSTART;

	SGX_UNSUPPORTED_FUNCTION(SET_ERRNO);

	FEND;

	// On error, return -1 and set errno appropriately
	return -1;

}

void sgxssl_makecontext(void *ucp, void (*func)(), int argc, ...)
{
	FSTART;

	// Note, makecontext() is unreachable when getcontext() is implemented as unsupported function
	SGX_UNREACHABLE_CODE(SET_ERRNO);

	FEND;
}

}
