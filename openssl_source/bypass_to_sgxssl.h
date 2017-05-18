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


#ifndef _BYPASS_TO_SGXSSL_
#define _BYPASS_TO_SGXSSL_

#define mmap sgxssl_mmap
#define munmap sgxssl_munmap
#define mprotect sgxssl_mprotect
#define mlock sgxssl_mlock
#define madvise sgxssl_madvise

/*
#define fopen64 sgxssl_fopen64
#define fopen sgxssl_fopen
#define wfopen sgxssl_wfopen
#define fclose sgxssl_fclose
#define ferror sgxssl_ferror
#define feof sgxssl_feof
#define fflush sgxssl_fflush
#define ftell sgxssl_ftell
#define fseek sgxssl_fseek
#define fread sgxssl_fread
#define fwrite sgxssl_fwrite
#define fgets sgxssl_fgets
#define fputs sgxssl_fputs
#define fileno sgxssl_fileno
#define __fprintf_chk sgxssl_fprintf
*/

#define pipe sgxssl_pipe
#define __read_alias sgxssl_read
#define write sgxssl_write
#define close sgxssl_close


#define sysconf sgxssl_sysconf

#define getsockname sgxssl_getsockname
#define getsockopt sgxssl_getsockopt
#define setsockopt sgxssl_setsockopt
#define socket sgxssl_socket
#define bind sgxssl_bind
#define listen sgxssl_listen
#define connect sgxssl_connect
#define accept sgxssl_accept
#define getaddrinfo sgxssl_getaddrinfo
#define freeaddrinfo sgxssl_freeaddrinfo
#define gethostbyname sgxssl_gethostbyname
#define getnameinfo sgxssl_getnameinfo
#define ioctl sgxssl_ioctl

char * sgxssl___builtin___strcat_chk(char *dest, const char *src, unsigned int dest_size);
char * sgxssl___builtin___strcpy_chk(char *dest, const char *src, unsigned int dest_size);


#define __builtin___strcpy_chk sgxssl___builtin___strcpy_chk
#define __builtin___strcat_chk sgxssl___builtin___strcat_chk

#define time sgxssl_time
#define gmtime_r sgxssl_gmtime_r
#define gettimeofday sgxssl_gettimeofday

#define pthread_rwlock_init sgxssl_pthread_rwlock_init
#define pthread_rwlock_rdlock sgxssl_pthread_rwlock_rdlock
#define pthread_rwlock_wrlock sgxssl_pthread_rwlock_wrlock
#define pthread_rwlock_unlock sgxssl_pthread_rwlock_unlock
#define pthread_rwlock_destroy sgxssl_pthread_rwlock_destroy
#define pthread_once sgxssl_pthread_once
#define pthread_key_create sgxssl_pthread_key_create
#define pthread_setspecific sgxssl_pthread_setspecific
#define pthread_getspecific sgxssl_pthread_getspecific
#define pthread_key_delete sgxssl_pthread_key_delete
#define pthread_self sgxssl_pthread_self
#define pthread_equal sgxssl_pthread_equal

#define __ctype_b_loc sgxssl___ctype_b_loc
#define __ctype_tolower_loc sgxssl___ctype_tolower_loc

#define gai_strerror sgxssl_gai_strerror

#define getcontext sgxssl_getcontext
#define setcontext sgxssl_setcontext
#define makecontext sgxssl_makecontext
#define getenv	sgxssl_getenv
#define atexit sgxssl_atexit
#define sscanf sgxssl_sscanf

#include <sys/cdefs.h>

#undef __REDIRECT
#define __REDIRECT(name, proto, alias) name proto 
#undef __REDIRECT_NTH
#define __REDIRECT_NTH(name, proto, alias) name proto 
#undef __REDIRECT_NTHNL
#define __REDIRECT_NTHNL(name, proto, alias) name proto 

#endif
