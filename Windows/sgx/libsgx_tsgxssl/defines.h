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

/*
* Some content of this file contains definitions copied from Windows Kit 8.0 header files
*
*       Copyright (c) Microsoft Corporation. All rights reserved.
*/

#ifndef __DEFINES_H__
#define __DEFINES_H__

#include <stdint.h>

#define MAX_PATH        260

#define VOID	void
#define BYTE	uint8_t
#define USHORT	uint16_t
#define WORD	uint16_t
#define WCHAR	wchar_t
#define INT		int32_t
#define UINT	uint32_t
#define BOOL	int32_t
#define BOOLEAN BYTE
#define LONG	long
#define DWORD	unsigned long
#define ULONG	unsigned LONG
#define SIZE_T	size_t

#ifdef _WIN64
#define UINT_PTR uint64_t
#define __int3264 int64_t
#else
#define UINT_PTR uint32_t
#define __int3264 int32_t
#endif
#define LONG_PTR __int3264 
#define LRESULT LONG_PTR
#define LPARAM LONG_PTR
#define WPARAM UINT_PTR
#define LARGE_INTEGER int64_t
#define ULARGE_INTEGER uint64_t
#define ULONGLONG unsigned long long
#define SHORT short
#define HRESULT	LONG
#define DWORDLONG uint64_t
#define LANGID	WORD

#define PVOID	VOID*
#define PLONG	LONG*
#define PULONG	ULONG*
#define PDWORD	DWORD*
#define PBOOL	BOOL*

#define LPVOID	VOID*
#define LPCVOID const LPVOID
#define LPBYTE	uint8_t* 
#define PBYTE	uint8_t* 
#define LPBOOL	BOOL*
#define LPWORD  WORD*
#define LPDWORD DWORD*
#define LPCSTR	const char*
#define LPCWTR	const wchar_t*
#define LPWSTR	wchar_t*
#define LPCWSTR const LPWSTR
#define PSID PVOID 

#define HMODULE LPVOID
#define FARPROC LPVOID
#define HWND	LPVOID

#define LPOVERLAPPED LPVOID

#define SOCKET	UINT_PTR

#define HANDLE void*
#define HWINSTA HANDLE


typedef struct _FILETIME {
	DWORD dwLowDateTime;
	DWORD dwHighDateTime;
} FILETIME, *PFILETIME;

typedef struct _WIN32_FIND_DATAA {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    char   cFileName[ MAX_PATH ];
    char   cAlternateFileName[ 14 ];
} WIN32_FIND_DATAA, *LPWIN32_FIND_DATAA;

typedef struct _WIN32_FIND_DATAW {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    WCHAR  cFileName[ MAX_PATH ];
    WCHAR  cAlternateFileName[ 14 ];
} WIN32_FIND_DATAW, *LPWIN32_FIND_DATAW;

struct _stat64i32 {
    unsigned int	st_dev;
    unsigned short     st_ino;
    unsigned short st_mode;
    short      st_nlink;
    short      st_uid;
    short      st_gid;
    unsigned int	st_rdev;
    long     st_size;
    __int64 st_atime;
    __int64 st_mtime;
    __int64 st_ctime;
};

#define TRUE	1
#define FALSE	0

#define CP_ACP	0	// Default ANSI code page

#define _In_opt_
#define _Out_opt_
#define _Inout_opt_
#define _In_
#define _Out_
#define _Inout_
#define _Reserved_
#define WINAPI	__stdcall
#define WSAAPI	__stdcall
#define WINBASEAPI	__stdcall

#define FILETIME_SIZE						(2*sizeof(DWORD))
#define OVERLAPPED_SIZE						(sizeof(HANDLE) + (2*sizeof(LPVOID)) + (2*sizeof(DWORD)))

#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)

#define FAKE_STD_HANDLE ((HANDLE)0x23456)

//#define SUPPORT_FILES_APIS 1

#endif //__DEFINES_H__
