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

#ifdef _WIN32
#define __declspec(dllimport) 

#ifndef _USE_32BIT_TIME_T
    #define _stat64i32	sgxssl__stat64i32
#endif /* _USE_32BIT_TIME_T */

/*fileapi.h*/
#define FindClose sgxssl_FindClose
#define FindFirstFileA      sgxssl_FindFirstFileA
#define FindFirstFileW      sgxssl_FindFirstFileW
#define FindNextFileA       sgxssl_FindNextFileA
#define FindNextFileW       sgxssl_FindNextFileW
#define GetFileType sgxssl_GetFileType
#define WriteFile sgxssl_WriteFile


/*stddef.h*/
#define _errno       sgxssl__errno
/*stdio.h*/
#define _vsnprintf    sgxssl__vsnprintf
#define _snprintf     sgxssl__snprintf
#define _vsnwprintf   sgxssl__vsnwprintf
#define fclose        sgxssl_fclose
#define feof    sgxssl_feof
#define ferror sgxssl_ferror
#define fflush        sgxssl_fflush
#define fgets sgxssl_fgets
#define _fileno sgxssl__fileno
#define fopen sgxssl_fopen
#define fputs sgxssl_fputs
#define fread   sgxssl_fread
#define fseek sgxssl_fseek
#define ftell sgxssl_ftell
#define fwrite  sgxssl_fwrite
#define vfprintf      sgxssl_vfprintf
#define fprintf sgxssl_fprintf
#define printf sgxssl_printf
#define sscanf        sgxssl_sscanf

/*stdlib.h*/
#define _exit        sgxssl__exit
#define getenv       sgxssl_getenv

/*string.h*/
#define strerror_s   sgxssl_strerror_s
#define _strdup      sgxssl__strdup
#define _stricmp        sgxssl__stricmp
#define _strnicmp       sgxssl__strnicmp
#define strcat          sgxssl_strcat
#define strcpy          sgxssl_strcpy
#define _wassert        sgxssl__wassert 
#define wcscpy		sgxssl_wcscpy

/*conio.h*/
#define _getch  sgxssl__getch

/*processthreadsapi.h*/
#define GetCurrentThreadId        sgxssl_GetCurrentThreadId
#define TlsAlloc sgxssl_TlsAlloc
#define TlsGetValue sgxssl_TlsGetValue
#define TlsSetValue sgxssl_TlsSetValue
#define TlsFree sgxssl_TlsFree

/*synchapi.h*/
#define EnterCriticalSection sgxssl_EnterCriticalSection
#define LeaveCriticalSection sgxssl_LeaveCriticalSection
#define InitializeCriticalSectionAndSpinCount sgxssl_InitializeCriticalSectionAndSpinCount
#define DeleteCriticalSection sgxssl_DeleteCriticalSection


/*WinSock2.h*/
#define WSAGetLastError    sgxssl_WSAGetLastError
#define closesocket        sgxssl_closesocket
#define recv       sgxssl_recv
#define send       sgxssl_send
#define WSASetLastError sgxssl_WSASetLastError

/*WinUser.h*/
#define GetProcessWindowStation     sgxssl_GetProcessWindowStation
#define GetUserObjectInformationW   sgxssl_GetUserObjectInformationW
#define MessageBoxA sgxssl_MessageBoxA
#define MessageBoxW sgxssl_MessageBoxW
#define GetDesktopWindow    sgxssl_GetDesktopWindow

/*WinBase.h*/
#define DeregisterEventSource sgxssl_DeregisterEventSource
#define RegisterEventSourceA sgxssl_RegisterEventSourceA
#define RegisterEventSourceW sgxssl_RegisterEventSourceW
#define ReportEventA sgxssl_ReportEventA
#define ReportEventW sgxssl_ReportEventW
#define QueryPerformanceCounter sgxssl_QueryPerformanceCounter
#define GetCurrentProcessId sgxssl_GetCurrentProcessId
#define BCryptGenRandom sgxssl_BCryptGenRandom
#define OutputDebugStringW sgxssl_OutputDebugStringW
#define GetEnvironmentVariableW sgxssl_GetEnvironmentVariableW

/*errhandlingapi.h*/
#define GetLastError sgxssl_GetLastError
#define SetLastError sgxssl_SetLastError


/*errno.h*/
#define _errno   sgxssl__errno

/*io.h*/
#define _setmode sgxssl__setmode

/*libloaderapi.h*/
#define GetModuleHandleA       sgxssl_GetModuleHandleA
#define GetModuleHandleW       sgxssl_GetModuleHandleW
#define GetProcAddress sgxssl_GetProcAddress

/*processenv.h*/
#define GetStdHandle     sgxssl_GetStdHandle

/*signal.h*/
#define signal sgxssl_signal
#define raise sgxssl_raise

/*stringapiset.h*/
#define MultiByteToWideChar sgxssl_MultiByteToWideChar
#define WideCharToMultiByte sgxssl_WideCharToMultiByte
/*sys/timeb.h**/
#define _ftime64        sgxssl__ftime64

/*sysinfoapi.h*/
#define GetVersion sgxssl_GetVersion
#define GetSystemTimeAsFileTime sgxssl_GetSystemTimeAsFileTime

/*time.h*/
#define _time64        sgxssl__time64
#define _gmtime64      sgxssl__gmtime64
#define _gmtime64_s    sgxssl__gmtime64_s
#define _localtime64   sgxssl__localtime64
#define _getsystime    sgxssl_getsystime

/*wincon.h*/
#define FlushConsoleInputBuffer sgxssl_FlushConsoleInputBuffer

#else //_WIN32

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

#if defined(SGXSDK_INT_VERSION) && (SGXSDK_INT_VERSION > 18)
	#define _longjmp longjmp
	#define _setjmp setjmp
#endif

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

//openssl 1.1.1 new APIs
//
#define getpid sgxssl_getpid
#define stat sgxssl_stat
#define syscall sgxssl_syscall
#define pthread_atfork sgxssl_pthread_atfork
#define opendir sgxssl_opendir
#define readdir sgxssl_readdir
#define closedir sgxssl_closedir
#define OPENSSL_issetugid sgxssl_OPENSSL_issetugid
#define clock_gettime sgxssl_clock_gettime


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
#define secure_getenv	sgxssl_getenv
#define atexit sgxssl_atexit
#define sscanf sgxssl_sscanf

#include <sys/cdefs.h>

#undef __REDIRECT
#define __REDIRECT(name, proto, alias) name proto 
#undef __REDIRECT_NTH
#define __REDIRECT_NTH(name, proto, alias) name proto 
#undef __REDIRECT_NTHNL
#define __REDIRECT_NTHNL(name, proto, alias) name proto 

#endif //_WIN32

#endif // _BYPASS_TO_SGXSSL_

