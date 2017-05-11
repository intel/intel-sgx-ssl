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

#include "tcommon.h"
#include "tSgxSSL_api.h"

PRINT_TO_STDOUT_STDERR_CB s_print_cb = NULL;

extern "C" 
{

void setPrintToStdoutStderrCB(PRINT_TO_STDOUT_STDERR_CB cb)
{
	FSTART;

	s_print_cb = cb;

	FEND;
}


// By default reaching unreachable code will cause an enclave to be aborted.
UnreachableCodePolicy_t s_unreach_code_policy = UNREACH_CODE_ABORT_ENCLAVE;	

void setUnreachableCodePolicy(UnreachableCodePolicy_t policy)
{
	FSTART;

	s_unreach_code_policy = policy;

	FEND;
}

extern const char* sgx_tssl_version;
const char * getSgxSSLVersion()
{
	return sgx_tssl_version;
}

}
