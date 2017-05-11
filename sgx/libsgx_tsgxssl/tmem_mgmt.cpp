/**
*   Copyright(C) 2016 Intel Corporation All Rights Reserved.
*
*   The source code, information  and  material ("Material") contained herein is
*   owned  by Intel Corporation or its suppliers or licensors, and title to such
*   Material remains  with Intel Corporation  or its suppliers or licensors. The
*   Material  contains proprietary information  of  Intel or  its  suppliers and
*   licensors. The  Material is protected by worldwide copyright laws and treaty
*   provisions. No  part  of  the  Material  may  be  used,  copied, reproduced,
*   modified, published, uploaded, posted, transmitted, distributed or disclosed
*   in any way  without Intel's  prior  express written  permission. No  license
*   under  any patent, copyright  or  other intellectual property rights  in the
*   Material  is  granted  to  or  conferred  upon  you,  either  expressly,  by
*   implication, inducement,  estoppel or  otherwise.  Any  license  under  such
*   intellectual  property  rights must  be express  and  approved  by  Intel in
*   writing.
*
*   Third Party trademarks are the property of their respective owners.
*
*   Unless otherwise  agreed  by Intel  in writing, you may not remove  or alter
*   this  notice or  any other notice embedded  in Materials by Intel or Intel's
*   suppliers or licensors in any way.
*/

#include <map>
#include <sgx_spinlock.h>
#include "tcommon.h"
#include "sgx_tsgxssl_t.h"


#define FAKE_DEV_ZERO_FD	99
#define PAGE_SIZE 			((uint64_t)0x1000) 	// 4096 Bytes
#define PROT_NONE			0x0
#define PROT_READ			0x1
#define PROT_WRITE			0x2
#define MAP_ANON			0x20
#define MAP_PRIVATE 		0x02

#define MADV_DONTDUMP		16
#define MAP_FAILED			(void *) -1

extern "C" {

struct MmapInfo
{
	MmapInfo(void* malockAddr, size_t length) : m_malloc_addr(malockAddr), m_length(length) {}

	void* m_malloc_addr;
	size_t m_length;
};

static sgx_spinlock_t addr_info_map_lock = SGX_SPINLOCK_INITIALIZER;

static std::map<void*, MmapInfo*> addr_info_map;


static void mmap_free(std::map<void*, MmapInfo*>::iterator& it)
{
	// NOTE: Caller function acquired the addr_info_map_lock before calling to the mmap_free() function.

	MmapInfo * addr_info = it->second;

	// free the memory allocation
	free(addr_info->m_malloc_addr);

	// Delete the aaddr_info
	delete addr_info;

	// delete the mmap entry
	addr_info_map.erase(it);
}

static void * mmap_alloc (size_t length)
{
	MmapInfo * info = NULL;
	// Allocate memory range greater than required by a page size.
	// This is needed to make the return address aligned to the page size.
	void* malloc_addr = malloc(length + PAGE_SIZE);
	if ( malloc_addr == NULL ) {
		return NULL;
	}

	// The return address must be a multiple of the page size
	uint64_t addr = (uint64_t) malloc_addr;
	addr += PAGE_SIZE;
	addr &= ~(PAGE_SIZE - 1);
	void* ret_addr = (void *)addr;

	try {
		info = new MmapInfo(malloc_addr, length);
	}
	catch (std::bad_alloc e) {
		(void)e; // remove warning
		free(malloc_addr);
		return NULL;
	}
	// Add the address info into the map
	sgx_spin_lock(&addr_info_map_lock);
	addr_info_map[ret_addr] = info;
	sgx_spin_unlock(&addr_info_map_lock);

	return ret_addr;
}

void * sgxssl_mmap (void *addr, size_t len, int prot, int flags, int fd, __off_t offset)
{
	FSTART;

	if (addr != NULL ||
		prot != (PROT_READ | PROT_WRITE) ||
		(flags != (MAP_ANON | MAP_PRIVATE)  &&  fd != -1) ||
		(flags != MAP_PRIVATE  &&  fd != FAKE_DEV_ZERO_FD) ||
		offset != 0 )
	{
		SGX_UNREACHABLE_CODE(SET_ERRNO);

		FEND;
		// On error, the value MAP_FAILED (that is, (void *) -1) is returned
		return MAP_FAILED;
	}

	void * mem_addr = mmap_alloc(len);
	if (mem_addr == NULL) {
		errno = ENOMEM;
		FEND;
		// On error, the value MAP_FAILED (that is, (void *) -1) is returned
		return MAP_FAILED;
	}

	// Memory allocated with MAP_ANON flag should be initialized to 0
	memset(mem_addr, 0, len);

	FEND;

	return mem_addr;

}

int sgxssl_munmap (void *addr, size_t len)
{
	FSTART;

	// Find and remove the address info from the map
	sgx_spin_lock(&addr_info_map_lock);

	std::map<void*, MmapInfo*>::iterator it = addr_info_map.find(addr);
	if ( it == addr_info_map.end() || it->second == NULL) {
		sgx_spin_unlock(&addr_info_map_lock);
		// On error -1 is returned and errno is set to EINVAL
		SGX_REPORT_ERR(SET_ERRNO);
		FEND;
		return -1;
	}

	// Implemented mmap support is limited for the existing OpenSSL usage.
	// Verify that the usage haven't changed.
	MmapInfo* addr_info = it->second;
	if (addr_info->m_length != len) {
		sgx_spin_unlock(&addr_info_map_lock);
		
		SGX_UNREACHABLE_CODE(SET_ERRNO); // we cannot free only part of the memory, so we will have a memory leak
		
		FEND;
		return -1;
	}

	mmap_free(it);
	sgx_spin_unlock(&addr_info_map_lock);

	FEND;
	return 0;
}




int sgxssl_mprotect (void *addr, size_t len, int prot)
{
	FSTART;

	if (prot != PROT_NONE) {
		// On error, -1 is returned, and errno is set appropriately.
		SGX_UNREACHABLE_CODE(SET_ERRNO);
		FEND;
		return -1;
	}

	// Cannot apply the required memory protection
	errno = EACCES;

	FEND;
	return -1;
}

int sgxssl_madvise (void *addr, size_t len, int advice)
{
	FSTART;

	if (advice != MADV_DONTDUMP) {
		// On error, -1 is returned, and errno is set appropriately.
		SGX_UNREACHABLE_CODE(SET_ERRNO);
		FEND;
		return -1;
	}

	// Doesn't impact the application semantic.
	FEND;
	return 0;
}




int sgxssl_mlock (const void *__addr, size_t __len)
{
	// Silently ignore - doesn't impact the application semantic.
	return 0;
}

}
