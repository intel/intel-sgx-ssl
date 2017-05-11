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

} // extern "C"
