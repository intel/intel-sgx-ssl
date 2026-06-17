#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <emmintrin.h>
#ifndef UINT32_MAX
#define UINT32_MAX 0xFFFFFFFFU
#endif


namespace std {
        class bad_alloc
        {
        public:
		bad_alloc(const bad_alloc&) throw();
	};
	bad_alloc::bad_alloc(const bad_alloc&) throw() {}

}

typedef volatile unsigned long sgx_spinlock_t;

#if defined(__cplusplus)
extern "C" {
#endif

int sgx_read_rand(unsigned int *buf,  unsigned long size)
{
    if(buf == NULL || size == 0 || size> UINT32_MAX )
    {
        return -1;
    }
    unsigned long i;
    for(i=0;i<(unsigned long)size;++i)
    {
            buf[i]=(unsigned int)rand();
    }
    return 0;
}

static inline int _InterlockedExchange(int volatile * dst, int val)
{
    int res;

    __asm __volatile(
        "lock xchg %2, %1;"
        "mov %2, %0"
        : "=m" (res)
        : "m" (*dst),
        "r" (val) 
        : "memory"
    );

    return (res);
   
}

#define MIN_BACKOFF 2
#define MAX_BACKOFF 1024
unsigned long sgx_spin_lock(sgx_spinlock_t *lock)
{
    while(_InterlockedExchange((volatile int *)lock, 1) != 0) {
        int b = MIN_BACKOFF;
        do
        {    /* tell cpu we are spinning */
            for (int i=0; i < b; i++) {
                _mm_pause();
            }
            b <<= 1;
            if (b > MAX_BACKOFF) {
                b = MAX_BACKOFF;
            }
        } while (*lock);
    }
    return (0);
}

unsigned long sgx_spin_unlock(sgx_spinlock_t *lock)
{
	*lock = 0;
	return 0;
}

#if defined(__cplusplus)
}
#endif
