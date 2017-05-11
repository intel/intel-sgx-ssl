
#include <stdio.h>
#include <openssl/rand.h>

int sgxssl_read_rand(unsigned char *rand_buf, int length_in_bytes);

static int sgx_rand_status(void);
static int get_sgx_rand_bytes(unsigned char *buf, int num);

static RAND_METHOD rand_meth = {
    NULL,                       /* seed */
    get_sgx_rand_bytes,
    NULL,                       /* cleanup */
    NULL,                       /* add */
    get_sgx_rand_bytes,
    sgx_rand_status,
};

RAND_METHOD *RAND_OpenSSL(void)
{
    return (&rand_meth);
}

static int sgx_rand_status(void) 
{ 
	return 1; 
}

static int get_sgx_rand_bytes(unsigned char *buf, int num) 
{
    if (sgxssl_read_rand(buf, num) == 0) 
    {
        return 1;
    } 
    else 
    {
        return 0;
    }
}

