/*
 * Copyright (C) 2011-2024 Intel Corporation. All rights reserved.
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

#include "ucommon.h"


extern "C" {

uint64_t* u_sgxssl_fopen(const char *filename, const char *mode)
{
	return (uint64_t*)fopen(filename, mode);
}

char* u_sgxssl_fgets(char* Buffer, int MaxCount, void* Stream)
{
	return fgets(Buffer, MaxCount, (FILE*)Stream);
}

void u_sgxssl_fclose(uint64_t* Stream)
{
        fclose((FILE*)Stream);
}

uint32_t u_sgxssl_fread(void* ptr, uint32_t size, uint32_t nmemb, uint64_t* stream)
{
	uint32_t tmp = fread(ptr, size, nmemb, (FILE*)stream);
	return tmp;
//	return fread(ptr, size, nmemb, (FILE*)stream);
}

int u_sgxssl_ferror(uint64_t* Stream)
{
        return ferror((FILE*)Stream);
}

}
