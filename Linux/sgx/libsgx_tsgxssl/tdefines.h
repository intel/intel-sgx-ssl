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
 
#ifndef __TDEFINES_H__
#define __TDEFINES_H__

#define TRUE	1
#define FALSE	0

typedef unsigned int socklen_t;

typedef long int time_t;

struct tm
{
  int tm_sec;
  int tm_min;
  int tm_hour;
  int tm_mday;
  int tm_mon;
  int tm_year;
  int tm_wday;
  int tm_yday;
  int tm_isdst;

  long int tm_gmtoff;
  const char *tm_zone;
};

typedef long int suseconds_t;

struct timeval
{
    time_t tv_sec;			// seconds
    suseconds_t tv_usec;	// microseconds
};

struct timespec {
    time_t   tv_sec;        /* seconds */
    long     tv_nsec;       /* nanoseconds */
};

struct timeb
{
   time_t         time;
   unsigned short millitm;
   short          timezone;
   short          dstflag;
};

struct timezone
{
  int tz_minuteswest;     /* minutes west of Greenwich */
  int tz_dsttime;         /* type of DST correction */
};

typedef void pthread_rwlock_t;

typedef void pthread_rwlockattr_t;
#define CLOCK_REALTIME 0

// Values for the argument to `sysconf'. Only _SC_PAGESIZE is actually used.
#define _UNISTD_H
#define Ubuntu 1
#define CentOS 2

#ifndef OS_ID
	#error No OS ID defined.	
#endif
#if OS_ID == Ubuntu
	#include "/usr/include/x86_64-linux-gnu/bits/confname.h"
#elif OS_ID == CentOS
	#include "/usr/include/bits/confname.h"
#else
	#error Invalid OS ID
#endif
#undef _UNISTD_H


typedef int pthread_once_t;
typedef unsigned int pthread_key_t;
typedef unsigned long int pthread_t;


#define ONCE_CONTROL_INIT	 	0
#define ONCE_CONTROL_COMPLETE	1
#define ONCE_CONTROL_BUSY	 	2

//#define SUPPORT_FILES_APIS

#endif //__DEFINES_H__
