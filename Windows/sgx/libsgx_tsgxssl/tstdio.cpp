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
#include <stdarg.h>
#include <wchar.h>
#include <string.h>
#include "tcommon.h"
#include "libsgx_tsgxssl_t.h"
#include "tSgxSSL_api.h"

extern PRINT_TO_STDOUT_STDERR_CB s_print_cb;

// stdin/stdout/stderr file descriptors
#define FD_UNKNOWN	-1
#define FD_STDIN	0
#define FD_STDOUT	1
#define FD_STDERR	2


struct _iobuf {
        char *_ptr;
        int   _cnt;
        char *_base;
        int   _flag;
        int   _file;
        int   _charbuf;
        int   _bufsiz;
        char *_tmpfname;
        };

char *s_stdin_ptr = "0";
char *s_stdout_ptr = "1";
char *s_stderr_ptr = "2";

struct _iobuf s_iob_fake_arr[3] = {
		{s_stdin_ptr, 0, NULL, 0, 0, 0, 0, NULL},
		{s_stdout_ptr, 0, NULL, 0, 0, 0, 0, NULL},
		{s_stderr_ptr, 0, NULL, 0, 0, 0, 0, NULL}
		};

int print_with_cb(void* fp, const char* fmt, __va_list vl)
{
	int res = -1;

	SGX_ASSERT(fp != NULL && sgx_is_within_enclave(fp, 1) && s_print_cb != NULL);

	int stream = -1;
	if (((struct _iobuf *)fp)->_ptr == s_stdout_ptr) {
		stream = STREAM_STDOUT;
	}
	else if	(((struct _iobuf *)fp)->_ptr == s_stderr_ptr) {
		stream = STREAM_STDERR;
	}
	else {
		// This function is called only when fp is one of the internally implemented stdout/stderr.
		SGX_ASSERT(FALSE);
		return res;
	}
		
	res = s_print_cb((Stream_t)stream, fmt, vl);
	return res;
}

int get_std_fd(void * fp)
{
	int fd = FD_UNKNOWN;

	SGX_ASSERT(fp != NULL && sgx_is_within_enclave(fp, 1));

	if (((struct _iobuf *)fp)->_ptr == s_stdin_ptr) {
		fd = FD_STDIN;
	}
	else if (((struct _iobuf *)fp)->_ptr == s_stdout_ptr) {
		fd = FD_STDOUT;
	}
	else if (((struct _iobuf *)fp)->_ptr == s_stderr_ptr) {
		fd = FD_STDERR;
	}
	else{ 
		// Unreachable code
		SGX_ASSERT(FALSE);
	}

	return fd;
}

BOOL is_fake_stdout_stderr(void* fp)
{
	if (fp != NULL && 
		sgx_is_within_enclave(fp, 1) &&
		(	((struct _iobuf *)fp)->_ptr == s_stdout_ptr 
			|| ((struct _iobuf *)fp)->_ptr == s_stderr_ptr) ) {
		return TRUE;
	}

	return FALSE;
}

extern "C" {

void sgxssl__wassert() {
    SGX_ASSERT(0);
    return;
}

void* sgxssl___iob_func()
{
	return s_iob_fake_arr;
}


#ifndef SUPPORT_FILES_APIS

/////////////////////
// void* functions //
/////////////////////

void* sgxssl_fopen(const char* filename, const char* mode)
{
	FSTART;

	// A null pointer return value indicates an error.
	// On Failure errno will be set. No impact on LastError. 
	SGX_UNSUPPORTED_FUNCTION(SET_ERRNO);

	FEND;

	return NULL;
}

void *sgxssl__wfopen(
	const wchar_t *filename,
	const wchar_t *mode
	)
{
	FSTART;

	// A null pointer return value indicates an error.
	// On Failure errno will be set. No impact on LastError. 
	SGX_UNSUPPORTED_FUNCTION(SET_ERRNO);

	FEND;

	return NULL;
}

int sgxssl_fclose(void* fp)
{
	FSTART;

	//  Return EOF (-1) to indicate an error
	// On Failure errno will be set. No impact on LastError. 
	SGX_UNSUPPORTED_FUNCTION(SET_ERRNO);

	FEND;

	return EOF;
}


int sgxssl_ferror(void* fp)
{
	FSTART;

	int ret = 0;

	if (is_fake_stdout_stderr(fp) && 
		s_print_cb != NULL) {

		FEND;

		// If no error has occurred on stream, ferror returns 0. 
		return ret;
	}

	// On error returns a nonzero value
	// On Failure errno will be set. No impact on LastError. 
	SGX_UNSUPPORTED_FUNCTION(SET_ERRNO);

	FEND;

	return -1;
}

int sgxssl_feof(void* fp)
{
	FSTART;

	// The feof function returns a nonzero value if a read operation has attempted to read past the end of the file;
	// it returns 0 otherwise. ( On error returns 0 as well)
	// On Failure errno will be set. No impact on LastError. 
	SGX_UNSUPPORTED_FUNCTION(SET_ERRNO);

	FEND;
	return 0;
}


int sgxssl_fflush(void* fp)
{
	FSTART;

	if (is_fake_stdout_stderr(fp) &&		
		s_print_cb != NULL) {
		
		FEND;
		// fflush returns 0 if the buffer was successfully flushed. 
		return 0;
	}

	// A return value of EOF (-1) indicates an error.
	SGX_UNSUPPORTED_FUNCTION(SET_NO_ERRNO);

	FEND;
	return -1;
}

void sgxssl_rewind(void* fp)
{
	FSTART;

	// On Failure errno will be set. No impact on LastError. 
	SGX_UNSUPPORTED_FUNCTION(SET_ERRNO);

	FEND;
}


long sgxssl_ftell(void* fp)
{
	FSTART;

	long ret = -1;

	//  If execution is allowed to continue, these functions return –1L
	// On Failure errno will be set. No impact on LastError. 
	SGX_UNSUPPORTED_FUNCTION(SET_ERRNO);

	FEND;
	return ret;
}


int sgxssl_fseek(void* fp, long offset, int origin)
{
	FSTART;

	int ret = -1;

	// On error, returns a nonzero value
	// On Failure errno will be set. No impact on LastError. 
	SGX_UNSUPPORTED_FUNCTION(SET_ERRNO);

	FEND;
	return ret;
}

int sgxssl_fprintf(void* fp, const char* fmt, ...)
{
	FSTART;

	if (is_fake_stdout_stderr(fp) && 
		s_print_cb != NULL) {
		va_list vl;
		va_start(vl, fmt);
		int res = print_with_cb(fp, fmt, vl);
		va_end(vl);

		FEND;
		return res;
	}

	int ret = -1;

	// Returns a negative value when an output error occurs.
	// On Failure errno will be set. No impact on LastError. 
	SGX_UNSUPPORTED_FUNCTION(SET_ERRNO);

	FEND;
	return ret;
}


int sgxssl_vfprintf(void* fp, const char* fmt, va_list vl)
{
	FSTART;

	if (is_fake_stdout_stderr(fp) && 
		s_print_cb != NULL) {
		int res = print_with_cb(fp, fmt, vl);
		
		FEND;
		return res;
	}

	int ret = -1;
	//  Returns a negative value if an output error occurs and no characters were written
	// On Failure errno will be set. No impact on LastError. 
	SGX_UNSUPPORTED_FUNCTION(SET_ERRNO);

	FEND;
	return ret;
}

size_t sgxssl_fread(void* dest, size_t element_size, size_t cnt, void* fp)
{
	FSTART;

	// returns 0 on error
	// On Failure errno will be set. No impact on LastError. 
	SGX_UNSUPPORTED_FUNCTION(SET_ERRNO);

	FEND;
	return 0;
}


size_t sgxssl_fwrite(const void* src, size_t element_size, size_t cnt, void* fp)
{
	FSTART;

	if (is_fake_stdout_stderr(fp) && 
		s_print_cb != NULL) {
		int res = sgxssl_fprintf(fp, "%.*s", element_size*cnt, src);

		FEND;
		return res;
	}

	// Returns 0 on error
	// On Failure errno will be set. No impact on LastError. 
	SGX_UNSUPPORTED_FUNCTION(SET_ERRNO);

	FEND;
	return 0;
}


char* sgxssl_fgets(char* dest, int max_cnt, void* fp)
{
	FSTART;

	// NULL is returned to indicate an error 
	// On Failure errno will be set. No impact on LastError. 
	SGX_UNSUPPORTED_FUNCTION(SET_ERRNO);

	FEND;
	return NULL;
}


int sgxssl_fputs(const char* src, void* fp)
{
	FSTART;

	if (is_fake_stdout_stderr(fp) && 
		s_print_cb != NULL) {
		int res = sgxssl_fprintf(fp, "%s", src);
		FEND;
		return res;
	}

	// On error, returns EOF (-1)
	// On Failure errno will be set. No impact on LastError. 
	SGX_UNSUPPORTED_FUNCTION(SET_ERRNO);

	FEND;
	return EOF;
}

int sgxssl__fileno(void *stream)
{
	FSTART;

	if (stream != NULL &&
		sgx_is_within_enclave(stream, 1)) {
		int fd = get_std_fd(stream);
		FEND;
		return fd;
	}

	// returns -1 on error
	// On Failure errno will be set. No impact on LastError. 
	SGX_UNSUPPORTED_FUNCTION(SET_ERRNO);

	FEND;
	return -1;
}


int sgxssl__getch( void )
{
	int ret = 0;

	FSTART;	

	// Returns the character read. There is no error return.
	SGX_UNSUPPORTED_FUNCTION(SET_NO_ERRNO);

	FEND;
	return ret;
}

int sgxssl__stat64i32(const char * name, struct _stat64i32 * stat)
{
	FSTART;

	// A return value of –1 indicates an error
	// On Failure errno will be set. No impact on LastError. 
	SGX_UNSUPPORTED_FUNCTION(SET_ERRNO);

	FEND;
	return -1;
}

int sgxssl__setmode (int fd, int mode)
{
	FSTART;

	// Returns -1 on error
	// On Failure errno will be set. No impact on LastError. 
	SGX_UNSUPPORTED_FUNCTION(SET_ERRNO);

	FEND;
	return -1;
}

int sgxssl_printf(const char *format, ...)
{
	FSTART;

	if (s_print_cb != NULL) {
		va_list vl;
		va_start(vl, format);
		int res = s_print_cb(STREAM_STDOUT, format, vl);
		va_end(vl);
		FEND;
		return res;
	}

	int ret = -1;

	// Returns a negative value when an output error occurs.
	// On Failure errno will be set. No impact on LastError. 
	SGX_UNSUPPORTED_FUNCTION(SET_ERRNO);

	FEND;
	return ret;
}

#endif // SUPPORT_FILES_APIS is not defined

/////////////////////
// other functions //
/////////////////////

int sgxssl__vsnprintf(
	char *buffer,
	size_t count,
	const char *format,
	va_list argptr
	)
{
	FSTART;
	int ret = vsnprintf(buffer, count, format, argptr);
	SGX_LOG("_vsnprintf() = %s\n", buffer);
	FEND;
	return ret;
}

int sgxssl__snprintf( char *buffer, size_t count, const char *format, ...)
{
	FSTART;

    va_list args;
	va_start(args, format);
	int ret = vsnprintf(buffer, count, format, args);
	va_end(args);
    SGX_LOG("%s(%d, %s) = %d\n", __FUNCTION__, count, (buffer != NULL) ? buffer : "nil", ret);

    FEND;
	return ret;
}

int sgx_print(const char *format, ...)
{
	FSTART;

	if (s_print_cb != NULL) {
		va_list vl;
		va_start(vl, format);
		int res = s_print_cb(STREAM_STDOUT, format, vl);
		va_end(vl);

		FEND;
		return res;
	}
	
	FEND;
	return 0;
}


}