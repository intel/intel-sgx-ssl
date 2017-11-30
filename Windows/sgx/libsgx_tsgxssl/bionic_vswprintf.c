/*	$OpenBSD: vswprintf.c,v 1.4 2012/12/05 23:20:01 deraadt Exp $	*/
/*	$NetBSD: vswprintf.c,v 1.1 2005/05/14 23:51:02 christos Exp $	*/

/*
 * Copyright (c) 1997 Todd C. Miller <Todd.Miller@courtesan.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <stddef.h>
#include <limits.h>

#include "bionic_glue.h"

#define NO_PRINTF_PERCENT_N

// Start of lines that were added to connect Bionic Open Source code to our glue code
//===================================================================================
#define MBSR_BUF		512

#define FILE	BUF_FILE

#define ssize_t	int
#define u_long	unsigned long

#pragma warning(disable: 4018)
#pragma warning(disable: 4146)
#ifdef _WIN64
#pragma warning(disable: 4244)
#pragma warning(disable: 4267)
#endif

// End of lines that were added to connect Bionic Open Source code to our glue code
//=================================================================================

union arg {
	int			intarg;
	unsigned int		uintarg;
	long			longarg;
	unsigned long		ulongarg;
	long long		longlongarg;
	unsigned long long	ulonglongarg;
	ptrdiff_t		ptrdiffarg;
	size_t			sizearg;
	ssize_t			ssizearg;
	intmax_t		intmaxarg;
	uintmax_t		uintmaxarg;
	void			*pvoidarg;
	char			*pchararg;
	signed char		*pschararg;
	short			*pshortarg;
	int			*pintarg;
	long			*plongarg;
	long long		*plonglongarg;
	ptrdiff_t		*pptrdiffarg;
	ssize_t			*pssizearg;
	intmax_t		*pintmaxarg;
#ifdef FLOATING_POINT
	double			doublearg;
	long double		longdoublearg;
#endif
	wint_t			wintarg;
	wchar_t			*pwchararg;
};

#define	__SERR	0x0040		/* found error */

/*
 * The size of the buffer we use as scratch space for integer
 * conversions, among other things.  Technically, we would need the
 * most space for base 10 conversions with thousands' grouping
 * characters between each pair of digits.  100 bytes is a
 * conservative overestimate even for a 128-bit uintmax_t.
 */
#define BUF	100

#define STATIC_ARG_TBL_SIZE 8	/* Size of static argument table. */

#define T_UNUSED	0

/*
 * Macros for converting digits to letters and vice versa
 */
#define	to_digit(c)	((c) - '0')
#define is_digit(c)	((unsigned)to_digit(c) <= 9)
#define	to_char(n)	((wchar_t)((n) + '0'))

#define bzero(b, len) (void)(memset((b), '\0', (len)))
#define __sferror(p)   (((p)->_flags & __SERR) != 0)
#define PAGE_SIZE	4096

// Portable code should use sysconf(_SC_PAGE_SIZE) directly instead.
int getpagesize() {
  // We dont use sysconf(3) here because that drags in stdio, which makes static binaries fat.
  return PAGE_SIZE;
}

void bcopy(const void* src, void* dst, size_t n) {
  memcpy(dst, src, n);
}

// Used instead of MB_LEN_MAX, which is defined as 1 by Intel® Software Guard Extensions SDK, while by windows it is defined as 5
#define WIN_MB_LEN_MAX		5

/*
 * Flags used during conversion.
 */
#define	ALT		0x0001		/* alternate form */
#define	LADJUST		0x0004		/* left adjustment */
#define	LONGDBL		0x0008		/* long double */
#define	LONGINT		0x0010		/* long integer */
#define	LLONGINT	0x0020		/* long long integer */
#define	SHORTINT	0x0040		/* short integer */
#define	ZEROPAD		0x0080		/* zero (as opposed to blank) pad */
#define FPT		0x0100		/* Floating point number */
#define PTRINT		0x0200		/* (unsigned) ptrdiff_t */
#define SIZEINT		0x0400		/* (signed) size_t */
#define CHARINT		0x0800		/* 8 bit integer */
#define MAXINT		0x1000		/* largest integer size (intmax_t) */

/*
 * Type ids for argument type table.
 */
#define T_UNUSED	0
#define T_SHORT		1
#define T_U_SHORT	2
#define TP_SHORT	3
#define T_INT		4
#define T_U_INT		5
#define TP_INT		6
#define T_LONG		7
#define T_U_LONG	8
#define TP_LONG		9
#define T_LLONG		10
#define T_U_LLONG	11
#define TP_LLONG	12
#define T_DOUBLE	13
#define T_LONG_DOUBLE	14
#define TP_CHAR		15
#define TP_VOID		16
#define T_PTRINT	17
#define TP_PTRINT	18
#define T_SIZEINT	19
#define T_SSIZEINT	20
#define TP_SSIZEINT	21
#define T_MAXINT	22
#define T_MAXUINT	23
#define TP_MAXINT	24
#define T_CHAR		25
#define T_U_CHAR	26
#define T_WINT		27
#define TP_WCHAR	28

int
sgxssl__vsnwprintf
	(wchar_t * s, 
	size_t n, 
	const wchar_t * fmt,
    __va_list ap)
{
	mbstate_t mbs;
	FILE f;
	char *mbp;
	int ret, sverrno;
	size_t nwc;
	unsigned char *base_str = NULL;

	if (n == 0) {
		errno = EINVAL;
		return (-1);
	}

	base_str = (unsigned char *) malloc(MBSR_BUF);
	if (base_str == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	f._flags = 0;	//__SWR | __SSTR | __SALC;
	f.ptr = base_str;
	f.base_len = MBSR_BUF-1;	/* Leave room for the NUL */
	f.len = 0;

	ret = __vfwprintf(&f, fmt, ap);
	if (ret < 0) {
		sverrno = errno;
		free(base_str);
		errno = sverrno;
		return (-1);
	}
	if (ret == 0) {
		s[0] = L'\0';
		free(base_str);
		return (0);
	}
	*f.ptr = '\0';
	mbp = (char *)base_str;
	/*
	 * XXX Undo the conversion from wide characters to multibyte that
	 * fputwc() did in __vfwprintf().
	 */
	bzero(&mbs, sizeof(mbs));
	nwc = mbsrtowcs(s, (const char **)&mbp, n, &mbs);
	free(base_str);
	if (nwc == (size_t)-1) {
		errno = EILSEQ;
		return (-1);
	}
	if (nwc == n) {
		s[n - 1] = L'\0';
		errno = EOVERFLOW;
		return (-1);
	}

	return (ret);
}

