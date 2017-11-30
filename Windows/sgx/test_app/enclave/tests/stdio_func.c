#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/err.h>

extern void printf(const char *fmt, ...);
static int print_fp(const char *str, size_t len, void *fp)
{
    printf("%s", str);
    return 1;
}

void ERR_print_errors_fp(void *fp)
{
    ERR_print_errors_cb(print_fp, fp);
}

int BN_print_fp(void *fp, const BIGNUM *a)
{
    char* str = BN_bn2hex(a);
    if (str == NULL)
		return 0;
	printf("%s", str);
	OPENSSL_free(str);
    return 1;
}

