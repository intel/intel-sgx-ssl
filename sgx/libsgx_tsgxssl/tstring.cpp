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
