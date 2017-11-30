#include <stdio.h>      /* vsnprintf */
#include <stdarg.h>

#include "TestEnclave.h"
#include "TestEnclave_t.h"  /* print_string */


void exit(int status)
{
	u_sgxssl_exit(status);
	// Calling to abort function to eliminate warning: ‘noreturn’ function does return [enabled by default]
	abort();
}

int fflush(void* stream)
{
	return 0;
}

extern char* sgxssl_getenv(char* name);

char* getenv(char* name)
{
	return sgxssl_getenv(name);
}


extern void printf(const char *fmt, ...);
int puts(const char* str)
{
	printf(str);
	return 0;
}
