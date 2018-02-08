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

#include "tCommon.h"
#include "time.h"
#include <sgx_trts.h>
#include "libsgx_tsgxssl_t.h"
#include "string.h"


//Weak symbol u_sgxssl_ftime64
// 64-bit msvc will not prepend an underscore for symbols.
#ifdef _M_X64
#pragma comment(linker, "/alternatename:u_sgxssl_ftime64=default_u_sgxssl_ftime64")
#else
#pragma comment(linker, "/alternatename:_u_sgxssl_ftime64=_default_u_sgxssl_ftime64")
#endif //_M_X64

extern "C" {

typedef uint64_t __time64_t;
struct __timeb64 {
    __time64_t time;
    unsigned short millitm;
    short timezone;
    short dstflag;
    };


typedef struct _SYSTEMTIME {
	WORD wYear;
	WORD wMonth;
	WORD wDayOfWeek;
	WORD wDay;
	WORD wHour;
	WORD wMinute;
	WORD wSecond;
	WORD wMilliseconds;
}SYSTEMTIME;

void default_u_sgxssl_ftime64(void * timeptr, uint32_t timeb64Len)
{
    (void)(timeptr);
    (void)(timeb64Len);
}

void sgxssl__ftime64( 
   struct __timeb64 *timeptr 
)
{
	FSTART;

	if (timeptr == NULL) {
		FEND;
		return;
	}

	sgx_status_t sgx_ret = u_sgxssl_ftime64(timeptr, sizeof(struct __timeb64));
	SGX_CHECK(sgx_ret);

	FEND;
}

__time64_t sgxssl__time64(__time64_t *timer)
{
	FSTART;

	struct __timeb64 timeptr;
	sgxssl__ftime64(&timeptr);
	if (timer != NULL)
		*timer = timeptr.time;

	FEND;

	return timeptr.time;
}

struct tm* sgxssl__gmtime64(const uint64_t* timer);
time_t sgxssl_mktime(struct tm *tmp);

struct tm *sgxssl__localtime64(const __time64_t *timer)
{
	FSTART;

	// This value is used by OpenSSL for printouts. Therefore, we can return calculated internally
	// _gmtime value (without taking into consideration time zone value).
	// During update process to newer OpenSSL veriosn, we will need to verify that there is no additional usage
	// that requires to consider timer zone.
	struct tm *timep = sgxssl__gmtime64(timer);
	
	FEND;

	return timep;
}


void WINBASEAPI sgxssl_GetSystemTime(_SYSTEMTIME * lpSystemTime)
{
	SGX_ASSERT(lpSystemTime != NULL);

	__timeb64 timeb = {0};
	sgxssl__ftime64(&timeb);
	SGX_ASSERT(timeb.time != 0);
	
	// timeb.time = Time in seconds since midnight(00:00:00), January 1, 1970, coordinated universal time(UTC).
	__time64_t timer = timeb.time;
	// which is exactly the input for gmtime function
	struct tm* tm_m = sgxssl__gmtime64(&timer);

	// conversion from struct tm to SystemTime:
	lpSystemTime->wYear = tm_m->tm_year + 1900; // in struct tm, tm_year is "current year - 1900", in systemtime wYear is the current year
	lpSystemTime->wMonth = tm_m->tm_mon + 1; // in struct tm, tm_mon starts from 0, in systemtime wMonth starts from 1
	lpSystemTime->wDayOfWeek = tm_m->tm_wday;
	lpSystemTime->wDay = tm_m->tm_mday;
	lpSystemTime->wHour = tm_m->tm_hour;
	lpSystemTime->wMinute = tm_m->tm_min;
	lpSystemTime->wSecond = tm_m->tm_sec;
	lpSystemTime->wMilliseconds = timeb.millitm;
}

//
//daylight saving time + tz are ignored!
//
BOOL WINBASEAPI sgxssl_SystemTimeToFileTime(const _SYSTEMTIME *lpSystemTime, FILETIME* lpFileTime)
{
	time_t time_t_return;
	struct tm info_tm_st;

	// conversion from struct SystemTime to tm:
	info_tm_st.tm_year = lpSystemTime->wYear - 1900; // in struct tm, tm_year is "current year - 1900", in systemtime wYear is the current year
	info_tm_st.tm_mon = lpSystemTime->wMonth - 1; // in struct tm, tm_mon starts from 0, in systemtime wMonth starts from 1
	info_tm_st.tm_mday = lpSystemTime->wDay;
	info_tm_st.tm_hour = lpSystemTime->wHour;
	info_tm_st.tm_min = lpSystemTime->wMinute;
	info_tm_st.tm_sec = lpSystemTime->wSecond;
	info_tm_st.tm_isdst = 0; //zero or less that 0 means to ignore daylight saving time.
	time_t_return = sgxssl_mktime(&info_tm_st);

	//in case of failure return zero
	if (time_t_return == -1)
	{
		return 0;
	}

	time_t_return = time_t_return * 10000000; // in units of 100 nano-seconds
	time_t_return += lpSystemTime->wMilliseconds * 10000;
	time_t_return += 116444736000000000UI64;  // convert from: time from 1/1/1970, to: time from 1/1/1601 - number is taken from openssl code

	lpFileTime->dwHighDateTime = time_t_return >> 32; //high bits
	lpFileTime->dwLowDateTime = time_t_return & 0xFFFFFFFF; //low bits
	return 1;
}


}