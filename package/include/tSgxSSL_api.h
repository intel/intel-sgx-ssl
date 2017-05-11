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

#ifndef __TSGXSSL_API__
#define __TSGXSSL_API__

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	STREAM_STDOUT = 1,
	STREAM_STDERR
} Stream_t;

typedef int (*PRINT_TO_STDOUT_STDERR_CB)(Stream_t stream, const char* fmt, va_list);

//---------------------------------------------------------------------
// API function to register a callback function that will intercept all printouts 
// to stdout or stderr and will be implemented by user to manage them as per user specific needs.
// When there is no registered callback, the printouts will be ignored.
//---------------------------------------------------------------------
void setPrintToStdoutStderrCB(PRINT_TO_STDOUT_STDERR_CB cb);

typedef enum {
	UNREACH_CODE_ABORT_ENCLAVE = 0,
	UNREACH_CODE_REPORT_ERR_AND_CONTNUE = 1,
} UnreachableCodePolicy_t;

//---------------------------------------------------------------------
// API function to define behaviour when unreachable code is being reached and executed.
// Default policy to abort an enclave as this shouldn't happen.
// For customers, who in any case prefer to continue execution, additional mode, 
// reporting an error through return value and/or setting last error/errno, is available.
//---------------------------------------------------------------------
void setUnreachableCodePolicy(UnreachableCodePolicy_t policy);

//---------------------------------------------------------------------
// API function to get SgxSSL Library version.
//---------------------------------------------------------------------
const char * getSgxSSLVersion();

#ifdef __cplusplus
}
#endif

#endif //__TSGXSSL_API__
