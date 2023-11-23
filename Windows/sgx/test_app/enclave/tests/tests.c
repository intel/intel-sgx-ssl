/*
 * Copyright 2017-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "testutil.h"

#include <errno.h>
#include <string.h>
#include <ctype.h>
#include "internal/nelem.h"
#include <openssl/asn1.h>

/*
 * A common routine to output test failure messages.  Generally this should not
 * be called directly, rather it should be called by the following functions.
 *
 * |desc| is a printf formatted description with arguments |args| that is
 * supplied by the user and |desc| can be NULL.  |type| is the data type
 * that was tested (int, char, ptr, ...).  |fmt| is a system provided
 * printf format with following arguments that spell out the failure
 * details i.e. the actual values compared and the operator used.
 *
 * The typical use for this is from an utility test function:
 *
 * int test6(const char *file, int line, int n) {
 *     if (n != 6) {
 *         test_fail_message(1, file, line, "int", "value %d is not %d", n, 6);
 *         return 0;
 *     }
 *     return 1;
 * }
 *
 * calling test6(3, "oops") will return 0 and produce out along the lines of:
 *      FAIL oops: (int) value 3 is not 6\n
 */
static void test_fail_message(const char *prefix, const char *file, int line,
                              const char *type, const char *left,
                              const char *right, const char *op,
                              const char *fmt, ...)
            PRINTF_FORMAT(8, 9);

void test_error(const char *file, int line, const char *desc, ...)
{
}
void test_info(const char *file, int line, const char *desc, ...)
{
}
#include <stdio.h>
void test_perror(const char *s)
{
    /*
     * Using openssl_strerror_r causes linking issues since it isn't
     * exported from libcrypto.so
     */
    TEST_error("%s: %s", s, strerror(errno));
}
void test_note(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    uprint(buf);
    printf("\n");
}

int test_skip(const char *file, int line, const char *desc, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;

    va_start(ap, desc);
    printf("SKIP: ");
    vsnprintf(buf, BUFSIZ, desc, ap);
    va_end(ap);
    uprint(buf);
    printf("\n");
    return 1;//TEST_SKIP_CODE;
}

/*
 * Define some comparisons between pairs of various types.
 * These functions return 1 if the test is true.
 * Otherwise, they return 0 and pretty-print diagnostics.
 *
 * In each case the functions produced are:
 *  int test_name_eq(const type t1, const type t2, const char *desc, ...);
 *  int test_name_ne(const type t1, const type t2, const char *desc, ...);
 *  int test_name_lt(const type t1, const type t2, const char *desc, ...);
 *  int test_name_le(const type t1, const type t2, const char *desc, ...);
 *  int test_name_gt(const type t1, const type t2, const char *desc, ...);
 *  int test_name_ge(const type t1, const type t2, const char *desc, ...);
 *
 * The t1 and t2 arguments are to be compared for equality, inequality,
 * less than, less than or equal to, greater than and greater than or
 * equal to respectively.  If the specified condition holds, the functions
 * return 1.  If the condition does not hold, the functions print a diagnostic
 * message and return 0.
 *
 * The desc argument is a printf format string followed by its arguments and
 * this is included in the output if the condition being tested for is false.
 */
#define DEFINE_COMPARISON(type, name, opname, op, fmt)                  \
    int test_ ## name ## _ ## opname(const char *file, int line,        \
                                     const char *s1, const char *s2,    \
                                     const type t1, const type t2)      \
    {                                                                   \
        if (t1 op t2)                                                   \
            return 1;                                                   \
        return 0;                                                       \
    }

#define DEFINE_COMPARISONS(type, name, fmt)                             \
    DEFINE_COMPARISON(type, name, eq, ==, fmt)                          \
    DEFINE_COMPARISON(type, name, ne, !=, fmt)                          \
    DEFINE_COMPARISON(type, name, lt, <, fmt)                           \
    DEFINE_COMPARISON(type, name, le, <=, fmt)                          \
    DEFINE_COMPARISON(type, name, gt, >, fmt)                           \
    DEFINE_COMPARISON(type, name, ge, >=, fmt)

DEFINE_COMPARISONS(int, int, "%d")
DEFINE_COMPARISONS(unsigned int, uint, "%u")
DEFINE_COMPARISONS(char, char, "%c")
DEFINE_COMPARISONS(unsigned char, uchar, "%u")
DEFINE_COMPARISONS(long, long, "%ld")
DEFINE_COMPARISONS(unsigned long, ulong, "%lu")
DEFINE_COMPARISONS(size_t, size_t, "%zu")
DEFINE_COMPARISONS(double, double, "%g")

DEFINE_COMPARISON(void *, ptr, eq, ==, "%p")
DEFINE_COMPARISON(void *, ptr, ne, !=, "%p")

int test_ptr_null(const char *file, int line, const char *s, const void *p)
{
    if (p == NULL)
        return 1;
    return 0;
}

int test_ptr(const char *file, int line, const char *s, const void *p)
{
    if (p != NULL)
        return 1;
    return 0;
}

int test_true(const char *file, int line, const char *s, int b)
{
    if (b)
        return 1;
    return 0;
}

int test_false(const char *file, int line, const char *s, int b)
{
    if (!b)
        return 1;
    return 0;
}

int test_str_eq(const char *file, int line, const char *st1, const char *st2,
                const char *s1, const char *s2)
{
    if (s1 == NULL && s2 == NULL)
      return 1;
    if (s1 == NULL || s2 == NULL || strcmp(s1, s2) != 0) {
        return 0;
    }
    return 1;
}

int test_str_ne(const char *file, int line, const char *st1, const char *st2,
                const char *s1, const char *s2)
{
    if ((s1 == NULL) ^ (s2 == NULL))
      return 1;
    if (s1 == NULL || strcmp(s1, s2) == 0) {
        return 0;
    }
    return 1;
}

int test_strn_eq(const char *file, int line, const char *st1, const char *st2,
                 const char *s1, size_t n1, const char *s2, size_t n2)
{
    if (s1 == NULL && s2 == NULL)
      return 1;
    if (n1 != n2 || s1 == NULL || s2 == NULL || strncmp(s1, s2, n1) != 0) {
        return 0;
    }
    return 1;
}

int test_strn_ne(const char *file, int line, const char *st1, const char *st2,
                 const char *s1, size_t n1, const char *s2, size_t n2)
{
    if ((s1 == NULL) ^ (s2 == NULL))
      return 1;
    if (n1 != n2 || s1 == NULL || strncmp(s1, s2, n1) == 0) {
        return 0;
    }
    return 1;
}

int test_mem_eq(const char *file, int line, const char *st1, const char *st2,
                const void *s1, size_t n1, const void *s2, size_t n2)
{
    if (s1 == NULL && s2 == NULL)
        return 1;
    if (n1 != n2 || s1 == NULL || s2 == NULL || memcmp(s1, s2, n1) != 0) {
        return 0;
    }
    return 1;
}

int test_mem_ne(const char *file, int line, const char *st1, const char *st2,
                const void *s1, size_t n1, const void *s2, size_t n2)
{
    if ((s1 == NULL) ^ (s2 == NULL))
        return 1;
    if (n1 != n2)
        return 1;
    if (s1 == NULL || memcmp(s1, s2, n1) == 0) {
        return 0;
    }
    return 1;
}

#define DEFINE_BN_COMPARISONS(opname, op, zero_cond)                    \
    int test_BN_ ## opname(const char *file, int line,                  \
                           const char *s1, const char *s2,              \
                           const BIGNUM *t1, const BIGNUM *t2)          \
    {                                                                   \
        if (BN_cmp(t1, t2) op 0)                                        \
            return 1;                                                   \
        return 0;                                                       \
    }                                                                   \
    int test_BN_ ## opname ## _zero(const char *file, int line,         \
                                    const char *s, const BIGNUM *a)     \
    {                                                                   \
        if (a != NULL &&(zero_cond))                                    \
            return 1;                                                   \
        return 0;                                                       \
    }

DEFINE_BN_COMPARISONS(eq, ==, BN_is_zero(a))

int test_BN_odd(const char *file, int line, const char *s, const BIGNUM *a)
{
    if (a != NULL && BN_is_odd(a))
        return 1;
    return 0;
}

int test_BN_even(const char *file, int line, const char *s, const BIGNUM *a)
{
    if (a != NULL && !BN_is_odd(a))
        return 1;
    return 0;
}
