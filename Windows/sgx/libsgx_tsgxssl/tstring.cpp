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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "tcommon.h"
#include "wchar.h"

extern "C" {

char * sgxssl__strdup(
	const char *strSource
	)
{
	FSTART;
	char* ret = strndup(strSource, (strlen(strSource) + 1));
	FEND;
	return ret;
}


char* sgxssl_strcpy(char* dest, const char* src)
{
	FSTART;
	char* ret = strncpy(dest, src, (strlen(src) + 1));
	FEND;
	return ret;
}

int sgxssl__strnicmp(
	const char *string1,
	const char *string2,
	size_t count
	)
{
	FSTART;
	
	if (string1 == NULL || string2 == NULL) {
		if (string2 != NULL) {
			return 1;
		}
		if (string1 != NULL) {
			return -1;
		}
		FEND;
		return 0;
	}


	int i = 0;
	for (; count > 0 && string1[i] != 0 && string2[i] != 0 && tolower(string2[i]) == tolower(string1[i]);
		i++, count--) {
	}

	if (count == 0) {
		FEND;
		return 0;
	}

	if (string1[i] == 0 || string2[i] == 0) {
		if (string2[i] != 0) {
			FEND;
			return 1;
		}
		if (string1[i] != 0) {
			FEND;
			return -1;
		}
		FEND;
		return 0;
	}

	int res = tolower(string2[i]) - tolower(string1[i]);

	if (res == 0) {
		FEND;
		return 0;
	}
	else if (res > 0) {
		FEND;
		return 1;
	}
	else {
		FEND;
		return -1;
	}
}

int sgxssl__stricmp(
	const char *string1,
	const char *string2
	)
{
	FSTART;

	int res = sgxssl__strnicmp(string1, string2, strlen(string1) + 1);

	FEND;
	return res;
}

int sgxssl_strerror_s(char *buf, size_t bufsz, errno_t errnum)
{
	char* error;

	FSTART;
	if (NULL == buf || bufsz < 2) {
		return EINVAL;
	}

	error = strerror(errnum);
	if (NULL == error) {
		return EINVAL;
	}

	strncpy(buf, error, bufsz - 1);
	buf[bufsz - 1] = '\0';
	FEND;

	return 0;
}

wchar_t *sgxssl_wcscpy(
	wchar_t *strDestination,
	const wchar_t *strSource
	)
{
	FSTART;

	size_t size = wcslen(strSource) + 1;
	wchar_t *str =  wcsncpy(strDestination, strSource, size);

	FEND;
	return str;
}

char* sgxssl_strcat(char* dest, const char* src)
{
	FSTART;

	SGX_ASSERT(dest != NULL && src != NULL);
	SGX_LOG("sgxssl_strcat(%p[%s], %p[%s])\n", dest, dest, src, src);

	char* res = strncat(dest, src, strlen(dest) + strlen(src) + 1);
	FEND;
	return res;
}

}

void wstr2astr(const wchar_t* src, char* dst, size_t dstSize)
{
	mbstate_t state;
	mbrlen(NULL, 0, &state);
	const wchar_t* tmpSrc = src;
	wcsrtombs(dst, &tmpSrc, dstSize, &state);
}


