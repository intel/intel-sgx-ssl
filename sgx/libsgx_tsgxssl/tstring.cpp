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
	
// from /usr/include/x86_x64-linux-gnu/sys/cdefs.h
// /* Fortify support.  */
// #define __bos(ptr) __builtin_object_size (ptr, __USE_FORTIFY_LEVEL > 1)

// From the man page:
// If the size of the object is not known or it has side effects the __builtin_object_size() function returns (size_t)-1 for type 0 and 1.

/* from /usr/include/x86_x64-linux-gnu/bits/string3.h:
__fortify_function char *
__NTH (stpcpy (char *__restrict __dest, const char *__restrict __src))
{
  return __builtin___stpcpy_chk (__dest, __src, __bos (__dest));
}
*/
char * sgxssl___builtin___strcpy_chk(char *dest, const char *src, unsigned int dest_size)
{
	FSTART;
	
	unsigned int src_len = strlen(src);
	if (src_len + 1 > dest_size)
	{
		FEND;
		return NULL;
	}
	
	char * ret = strncpy(dest, src, src_len + 1);

	FEND;

	return ret;

}

/* from /usr/include/x86_x64-linux-gnu/bits/string3.h:
__fortify_function char *
__NTH (strcat (char *__restrict __dest, const char *__restrict __src))
{
  return __builtin___strcat_chk (__dest, __src, __bos (__dest));
}
*/

char * sgxssl___builtin___strcat_chk(char *dest, const char *src, unsigned int dest_size)
{
	FSTART;
	
	unsigned int src_len = strlen(src);
	int dest_len = strlen(dest);
	if (dest_len + src_len + 1 > dest_size)
	{
		FEND;
		return NULL;
	}
	
	char * ret = strncat(dest, src, dest_len + src_len + 1);

	FEND;

	return ret;
}

}
