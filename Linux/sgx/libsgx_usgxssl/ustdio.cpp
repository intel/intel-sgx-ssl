/*
 * Copyright (C) 2021 Intel Corporation. All rights reserved.
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
#include <stdint.h>
#include <string.h>
extern "C" {

uint64_t ocall_cc_fopen(const char *filename, size_t filename_len, const char *mode, size_t mode_len)
{
    FILE *file_host = fopen(filename, mode);
    return (uint64_t)file_host;
}

int ocall_cc_fclose(uint64_t fp)
{
    return fclose((FILE *)fp);
}

int ocall_cc_ferror(uint64_t fp)
{
    return ferror((FILE *)fp);
}

int ocall_cc_feof(uint64_t fp)
{
    return feof((FILE *)fp);
}

int ocall_cc_fflush(uint64_t fp)
{
    return fflush((FILE *)fp);
}

int ocall_cc_ftell(uint64_t fp)
{
    return ftell((FILE *)fp);
}

int ocall_cc_fseek(uint64_t fp, long offset, int origin)
{
    return fseek((FILE *)fp, offset, origin);
}

size_t ocall_cc_fread(void *buf, size_t total_size, size_t element_size, size_t cnt, uint64_t fp)
{
    return fread(buf, element_size, cnt, (FILE *)fp);
}

size_t ocall_cc_fwrite(const void *buf, size_t total_size, size_t element_size, size_t cnt, uint64_t fp)
{
    return fwrite(buf, element_size, cnt, (FILE *)fp);
}

int ocall_cc_fgets(char *str, int max_cnt, uint64_t fp)
{
    if (fgets(str, max_cnt, (FILE *)fp) != NULL) {
        return 0;
    } else {
        return -1;
    }
}

int ocall_cc_fputs(const char *str, size_t total_size, uint64_t fp)
{
    return fputs(str, (FILE *)fp);
}
}
