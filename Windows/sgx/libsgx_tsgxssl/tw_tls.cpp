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

#include <stdio.h>
#include <string.h>

#include "libsgx_tsgxssl_t.h"

#include "tCommon.h"
#include <sgx_thread.h>
#include <sgx_spinlock.h>
#include <map>

#ifndef TLS_OUT_OF_INDEXES
# define TLS_OUT_OF_INDEXES 0xFFFFFFFF
#endif

static sgx_spinlock_t thread_key_lock = SGX_SPINLOCK_INITIALIZER;
static int thread_next_key = 1;

static std::map<int, std::map<sgx_thread_t, const void*> *> thread_specific_data_map;




extern "C" {

void* WINAPI sgxssl_TlsGetValue(_In_ DWORD key)
{
	sgx_spin_lock(&thread_key_lock);

	std::map<int, std::map<sgx_thread_t, const void*> *>::iterator it = thread_specific_data_map.find(key);

	if (it == thread_specific_data_map.end() || it->second == NULL) {
		sgx_spin_unlock(&thread_key_lock);
		FEND;
		return NULL;
	}

	std::map<sgx_thread_t, const void*> * p_data_map = it->second;
	std::map<sgx_thread_t, const void*>::iterator iter = p_data_map->find(sgx_thread_self());

	if (iter == p_data_map->end()) {
		sgx_spin_unlock(&thread_key_lock);
		FEND;
		return NULL;
	}

	void *data = (void *)iter->second;
	sgx_spin_unlock(&thread_key_lock);
	FEND;

	return data;
}


int	WINAPI sgxssl_TlsSetValue(_In_ DWORD key, _In_opt_ LPVOID data)
{
	sgx_spin_lock(&thread_key_lock);

	std::map<sgx_thread_t, const void*> * p_data_map = NULL;
	std::map<int, std::map<sgx_thread_t, const void*> *>::iterator it = thread_specific_data_map.find(key);

	if (it == thread_specific_data_map.end() || it->second == NULL) {
		try {
			p_data_map = new std::map<sgx_thread_t, const void*>;
			thread_specific_data_map[key] = p_data_map;
		}
		catch (std::bad_alloc e)
		{
			sgx_spin_unlock(&thread_key_lock);
			(void)e; // remove warning
			if (p_data_map != NULL) // second memory allocation failed
				delete p_data_map;
			errno = ENOMEM;
			FEND;
			return 0;
		}
	}
	else {
		p_data_map = it->second;
	}

	try {
		(*p_data_map)[sgx_thread_self()] = data;
	}
	catch (std::bad_alloc e)
	{
		sgx_spin_unlock(&thread_key_lock);
		(void)e; // remove warning
		errno = ENOMEM;
		FEND;
		return 0;
	}

	sgx_spin_unlock(&thread_key_lock);

	FEND;
	return 1;
}

int	WINAPI sgxssl_TlsFree(_In_ DWORD key)
{
	FSTART;

	sgx_spin_lock(&thread_key_lock);

	std::map<int, std::map<sgx_thread_t, const void*> * >::iterator it = thread_specific_data_map.find(key);
	if (it != thread_specific_data_map.end()) {
		std::map<sgx_thread_t, const void*> * p_data_map = it->second;

		if (p_data_map != NULL) {
			// Clear all the entries from the internal thread to data map
			p_data_map->clear();

			// Delete the data map itself
			delete p_data_map;
		}
		else {
			errno = EFAULT;
			FEND;
			return 0;
		}

		// Erase the thread_specific_data_map entry with the given key
		thread_specific_data_map.erase(it);
	}

	// NOTE: Regarding the application data, it is the responsibility of the application to free/cleanup
	// any data related to the deleted key or associated thread-specific data on any thread.

	// If there are no keys in use, reset the next key number
	if (thread_specific_data_map.empty()) {
		thread_next_key = 1;
	}

	sgx_spin_unlock(&thread_key_lock);

	FEND;
	return 1;

}

int	WINAPI sgxssl_TlsAlloc() 
{
	FSTART;


	int key = 0;

	if (thread_next_key == 0) {
		// Keys count overflow
		errno = EFAULT;
		FEND;
		return TLS_OUT_OF_INDEXES;
	}

	sgx_spin_lock(&thread_key_lock);
	key = thread_next_key;

	thread_next_key++;
	sgx_spin_unlock(&thread_key_lock);
	
	FEND;
	return key;
}
}