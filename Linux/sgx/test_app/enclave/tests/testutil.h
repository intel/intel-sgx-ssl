/*
 * Copyright 2014-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_TESTUTIL_H
# define OSSL_TESTUTIL_H

# include <stdarg.h>

# include <openssl/provider.h>
# include <openssl/err.h>
# include <openssl/e_os2.h>
# include <openssl/bn.h>
# include <openssl/x509.h>
/*
 *  Test assumption verification helpers.
 */

# define PRINTF_FORMAT(a, b)
# if defined(__GNUC__) && defined(__STDC_VERSION__)
  /*
   * Because we support the 'z' modifier, which made its appearance in C99,
   * we can't use __attribute__ with pre C99 dialects.
   */
#  if __STDC_VERSION__ >= 199901L
#   undef PRINTF_FORMAT
#   define PRINTF_FORMAT(a, b)   __attribute__ ((format(printf, a, b)))
#  endif
# endif

# define DECLARE_COMPARISON(type, name, opname)                         \
    int test_ ## name ## _ ## opname(const char *, int,                 \
                                     const char *, const char *,        \
                                     const type, const type);

# define DECLARE_COMPARISONS(type, name)                                \
    DECLARE_COMPARISON(type, name, eq)                                  \
    DECLARE_COMPARISON(type, name, ne)                                  \
    DECLARE_COMPARISON(type, name, lt)                                  \
    DECLARE_COMPARISON(type, name, le)                                  \
    DECLARE_COMPARISON(type, name, gt)                                  \
    DECLARE_COMPARISON(type, name, ge)

DECLARE_COMPARISONS(int, int)
DECLARE_COMPARISONS(unsigned int, uint)
DECLARE_COMPARISONS(char, char)
DECLARE_COMPARISONS(unsigned char, uchar)
DECLARE_COMPARISONS(long, long)
DECLARE_COMPARISONS(unsigned long, ulong)
DECLARE_COMPARISONS(double, double)
DECLARE_COMPARISONS(time_t, time_t)

/*
 * Because this comparison uses a printf format specifier that's not
 * universally known (yet), we provide an option to not have it declared.
 */
# ifndef TESTUTIL_NO_size_t_COMPARISON
DECLARE_COMPARISONS(size_t, size_t)
# endif

/*
 * Pointer comparisons against other pointers and null.
 * These functions return 1 if the test is true.
 * Otherwise, they return 0 and pretty-print diagnostics.
 * These should not be called directly, use the TEST_xxx macros below instead.
 */
DECLARE_COMPARISON(void *, ptr, eq)
DECLARE_COMPARISON(void *, ptr, ne)
int test_ptr(const char *file, int line, const char *s, const void *p);
int test_ptr_null(const char *file, int line, const char *s, const void *p);

/*
 * Equality tests for strings where NULL is a legitimate value.
 * These calls return 1 if the two passed strings compare true.
 * Otherwise, they return 0 and pretty-print diagnostics.
 * These should not be called directly, use the TEST_xxx macros below instead.
 */
DECLARE_COMPARISON(char *, str, eq)
DECLARE_COMPARISON(char *, str, ne)

/*
 * Same as above, but for strncmp.
 */
int test_strn_eq(const char *file, int line, const char *, const char *,
                 const char *a, size_t an, const char *b, size_t bn);
int test_strn_ne(const char *file, int line, const char *, const char *,
                 const char *a, size_t an, const char *b, size_t bn);

/*
 * Equality test for memory blocks where NULL is a legitimate value.
 * These calls return 1 if the two memory blocks compare true.
 * Otherwise, they return 0 and pretty-print diagnostics.
 * These should not be called directly, use the TEST_xxx macros below instead.
 */
int test_mem_eq(const char *, int, const char *, const char *,
                const void *, size_t, const void *, size_t);
int test_mem_ne(const char *, int, const char *, const char *,
                const void *, size_t, const void *, size_t);

/*
 * Check a boolean result for being true or false.
 * They return 1 if the condition is true (i.e. the value is non-zero).
 * Otherwise, they return 0 and pretty-prints diagnostics using |s|.
 * These should not be called directly, use the TEST_xxx macros below instead.
 */
int test_true(const char *file, int line, const char *s, int b);
int test_false(const char *file, int line, const char *s, int b);
/*
 * Pretty print a failure message.
 * These should not be called directly, use the TEST_xxx macros below instead.
 */
void test_error(const char *file, int line, const char *desc, ...)
    PRINTF_FORMAT(3, 4);
void test_error_c90(const char *desc, ...) PRINTF_FORMAT(1, 2);
void test_info(const char *file, int line, const char *desc, ...)
    PRINTF_FORMAT(3, 4);
void test_info_c90(const char *desc, ...) PRINTF_FORMAT(1, 2);
void test_note(const char *desc, ...) PRINTF_FORMAT(1, 2);
int test_skip(const char *file, int line, const char *desc, ...)
    PRINTF_FORMAT(3, 4);
int test_skip_c90(const char *desc, ...) PRINTF_FORMAT(1, 2);
void test_openssl_errors(void);
void test_perror(const char *s);

/*
 * The following macros provide wrapper calls to the test functions with
 * a default description that indicates the file and line number of the error.
 *
 * The following macros guarantee to evaluate each argument exactly once.
 * This allows constructs such as: if (!TEST_ptr(ptr = OPENSSL_malloc(..)))
 * to produce better contextual output than:
 *      ptr = OPENSSL_malloc(..);
 *      if (!TEST_ptr(ptr))
 */
# define TEST_int_eq(a, b)    test_int_eq(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_int_ne(a, b)    test_int_ne(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_int_lt(a, b)    test_int_lt(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_int_le(a, b)    test_int_le(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_int_gt(a, b)    test_int_gt(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_int_ge(a, b)    test_int_ge(__FILE__, __LINE__, #a, #b, a, b)

# define TEST_uint_eq(a, b)   test_uint_eq(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_uint_ne(a, b)   test_uint_ne(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_uint_lt(a, b)   test_uint_lt(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_uint_le(a, b)   test_uint_le(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_uint_gt(a, b)   test_uint_gt(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_uint_ge(a, b)   test_uint_ge(__FILE__, __LINE__, #a, #b, a, b)

# define TEST_char_eq(a, b)   test_char_eq(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_char_ne(a, b)   test_char_ne(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_char_lt(a, b)   test_char_lt(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_char_le(a, b)   test_char_le(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_char_gt(a, b)   test_char_gt(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_char_ge(a, b)   test_char_ge(__FILE__, __LINE__, #a, #b, a, b)

# define TEST_uchar_eq(a, b)  test_uchar_eq(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_uchar_ne(a, b)  test_uchar_ne(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_uchar_lt(a, b)  test_uchar_lt(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_uchar_le(a, b)  test_uchar_le(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_uchar_gt(a, b)  test_uchar_gt(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_uchar_ge(a, b)  test_uchar_ge(__FILE__, __LINE__, #a, #b, a, b)

# define TEST_long_eq(a, b)   test_long_eq(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_long_ne(a, b)   test_long_ne(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_long_lt(a, b)   test_long_lt(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_long_le(a, b)   test_long_le(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_long_gt(a, b)   test_long_gt(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_long_ge(a, b)   test_long_ge(__FILE__, __LINE__, #a, #b, a, b)

# define TEST_ulong_eq(a, b)  test_ulong_eq(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_ulong_ne(a, b)  test_ulong_ne(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_ulong_lt(a, b)  test_ulong_lt(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_ulong_le(a, b)  test_ulong_le(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_ulong_gt(a, b)  test_ulong_gt(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_ulong_ge(a, b)  test_ulong_ge(__FILE__, __LINE__, #a, #b, a, b)

# define TEST_size_t_eq(a, b) test_size_t_eq(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_size_t_ne(a, b) test_size_t_ne(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_size_t_lt(a, b) test_size_t_lt(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_size_t_le(a, b) test_size_t_le(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_size_t_gt(a, b) test_size_t_gt(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_size_t_ge(a, b) test_size_t_ge(__FILE__, __LINE__, #a, #b, a, b)

# define TEST_double_eq(a, b) test_double_eq(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_double_ne(a, b) test_double_ne(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_double_lt(a, b) test_double_lt(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_double_le(a, b) test_double_le(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_double_gt(a, b) test_double_gt(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_double_ge(a, b) test_double_ge(__FILE__, __LINE__, #a, #b, a, b)

# define TEST_time_t_eq(a, b) test_time_t_eq(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_time_t_ne(a, b) test_time_t_ne(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_time_t_lt(a, b) test_time_t_lt(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_time_t_le(a, b) test_time_t_le(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_time_t_gt(a, b) test_time_t_gt(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_time_t_ge(a, b) test_time_t_ge(__FILE__, __LINE__, #a, #b, a, b)

# define TEST_ptr_eq(a, b)    test_ptr_eq(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_ptr_ne(a, b)    test_ptr_ne(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_ptr(a)          test_ptr(__FILE__, __LINE__, #a, a)
# define TEST_ptr_null(a)     test_ptr_null(__FILE__, __LINE__, #a, a)

# define TEST_str_eq(a, b)    test_str_eq(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_str_ne(a, b)    test_str_ne(__FILE__, __LINE__, #a, #b, a, b)
# define TEST_strn_eq(a, b, n) test_strn_eq(__FILE__, __LINE__, #a, #b, a, n, b, n)
# define TEST_strn_ne(a, b, n) test_strn_ne(__FILE__, __LINE__, #a, #b, a, n, b, n)
# define TEST_strn2_eq(a, m, b, n) test_strn_eq(__FILE__, __LINE__, #a, #b, a, m, b, n)
# define TEST_strn2_ne(a, m, b, n) test_strn_ne(__FILE__, __LINE__, #a, #b, a, m, b, n)

# define TEST_mem_eq(a, m, b, n) test_mem_eq(__FILE__, __LINE__, #a, #b, a, m, b, n)
# define TEST_mem_ne(a, m, b, n) test_mem_ne(__FILE__, __LINE__, #a, #b, a, m, b, n)

# define TEST_true(a)         test_true(__FILE__, __LINE__, #a, (a) != 0)
# define TEST_false(a)        test_false(__FILE__, __LINE__, #a, (a) != 0)

# define TEST_BN_eq(a, b)     test_BN_eq(__FILE__, __LINE__, #a, #b, a, b)

/*
 * TEST_error(desc, ...) prints an informative error message in the standard
 * format.  |desc| is a printf format string.
 */
# if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L
#  define TEST_error         test_error_c90
#  define TEST_info          test_info_c90
#  define TEST_skip          test_skip_c90
# else
#  define TEST_error(...)    test_error(__FILE__, __LINE__, __VA_ARGS__)
#  define TEST_info(...)     test_info(__FILE__, __LINE__, __VA_ARGS__)
#  define TEST_skip(...)     test_skip(__FILE__, __LINE__, __VA_ARGS__)
# endif
/* Fake non-secure random number generator */
typedef int fake_random_generate_cb(unsigned char *out, size_t outlen,
                                    const char *name, EVP_RAND_CTX *ctx);
#define ADD_TEST(fn) \
        if ( 1 != fn()) return 1;

#define ADD_ALL_TESTS(fn, index) \
        for ( int i = 0 ; i < index; i++)       \
        {                                       \
                if ( 1 != fn(i))                \
                        return 1;               \
        }

#endif                          /* OSSL_TESTUTIL_H */
