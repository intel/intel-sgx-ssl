#ifndef _TESTENCLAVE_H_
#define _TESTENCLAVE_H_

#include <stdlib.h>
#include <assert.h>

#define TEST_CHECK(status)	\
{	\
	if (status != SGX_SUCCESS) {	\
		printf("OCALL status check failed %s(%d), status = %d\n", __FUNCTION__, __LINE__, status);	\
		abort();	\
	}	\
}

#if defined(__cplusplus)
extern "C" {
#endif

void printf(const char *fmt, ...);

int puts(const char* str);
char* getenv(char* name);
int fflush(void* stream);
void exit(int status);

int rsa_test();
int ec_test();
int ecdh_test();
int ecdsa_test();
int bn_test();
int dh_test();
int sha256_test();
int sha1_test();
int threads_test();

#if defined(__cplusplus)
}
#endif

#endif /* !_TESTENCLAVE_H_ */
