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

#include <map>
#include <sgx_spinlock.h>
#include <sgx_thread.h>

#include "tcommon.h"
#include "sgx_tsgxssl_t.h"

struct RwlockInfo
{
	RwlockInfo() : readers_num(0), writers_num(0), busy(0), writer_thread(SGX_THREAD_T_NULL), 
	cond(SGX_THREAD_COND_INITIALIZER), mutex(SGX_THREAD_MUTEX_INITIALIZER) {}

	unsigned int 	readers_num; // protected by the mutex
	unsigned int 	writers_num; // protected by the mutex
	unsigned int    busy;	// protected by the general spinlock, makes sure the object is not deleted before the actual read/write counter is increased
	sgx_thread_t	writer_thread;	// thread holding the writer_lock
	sgx_thread_cond_t cond;
	sgx_thread_mutex_t mutex;
};

static sgx_spinlock_t rwlock_info_map_lock = SGX_SPINLOCK_INITIALIZER;

static std::map<void*, RwlockInfo*> rwlock_info_map;

static sgx_spinlock_t pthread_once_lock = SGX_SPINLOCK_INITIALIZER;

typedef void (*destr_function) (void *);

static sgx_spinlock_t pthread_key_lock = SGX_SPINLOCK_INITIALIZER;
static std::map<pthread_key_t, destr_function> pthread_key_destr_func_map;
static pthread_key_t	pthread_next_key = 1;

static std::map<pthread_key_t, std::map<sgx_thread_t, const void*> *> thread_specific_data_map;

extern "C" {

int sgxssl_pthread_rwlock_init (pthread_rwlock_t *rwlock, const pthread_rwlockattr_t * attr)
{
	FSTART;
	
	RwlockInfo *info = NULL;

	if (rwlock == NULL) {
		errno = EINVAL;
		FEND;
		return EINVAL;
	}

	try {
		info = new RwlockInfo();
	} 
	catch (std::bad_alloc e) {
		// On error errno is set and returned
		(void)e; // remove warning
		errno = ENOMEM;
		FEND;
		return ENOMEM;
	}

	sgx_spin_lock(&rwlock_info_map_lock);
	rwlock_info_map[rwlock] = info;
	sgx_spin_unlock(&rwlock_info_map_lock);

	FEND;
	return 0;
}

int sgxssl_pthread_rwlock_destroy (pthread_rwlock_t *rwlock)
{
	FSTART;

	if (rwlock == NULL) {
		errno = EINVAL;
		FEND;
		return EINVAL;
	}

	// Find and remove the rwlock_info from the map
	sgx_spin_lock(&rwlock_info_map_lock);

	std::map<void*, RwlockInfo*>::iterator it = rwlock_info_map.find(rwlock);
	if ( it == rwlock_info_map.end() ||	it->second == NULL ) {
	
		sgx_spin_unlock(&rwlock_info_map_lock);

		// On error errno is set and returned
		errno = EINVAL;
		FEND;
		return EINVAL;
	}
	
	// Delete the rwlock_info
	RwlockInfo * rwlock_info = it->second;
	
	if (rwlock_info->writers_num > 0 || rwlock_info->readers_num > 0 || rwlock_info->busy > 0)
	{
		sgx_spin_unlock(&rwlock_info_map_lock);
		
		errno = EBUSY;
		FEND;
		return EBUSY;
	}
		
	sgx_thread_cond_destroy(&rwlock_info->cond);
	sgx_thread_mutex_destroy(&rwlock_info->mutex);
		
	delete rwlock_info;

	// delete the rwlock_info_map entry
	rwlock_info_map.erase(it);

	sgx_spin_unlock(&rwlock_info_map_lock);

	FEND;
	return 0;
}

int sgxssl_pthread_rwlock_rdlock (pthread_rwlock_t *rwlock)
{
	FSTART;

	if (rwlock == NULL) {
		errno = EINVAL;
		FEND;
		return EINVAL;
	}

	sgx_spin_lock(&rwlock_info_map_lock);

	std::map<void*, RwlockInfo*>::iterator it = rwlock_info_map.find(rwlock);
	if ( it == rwlock_info_map.end() ||	it->second == NULL ) {

		sgx_spin_unlock(&rwlock_info_map_lock);

		// On error errno is set to EINVAL and errno is returned
		errno = EINVAL;
		FEND;
		return EINVAL;
	}

	RwlockInfo * rwlock_info = it->second;

	// Verify the current thread is not holding the writers lock
	if (rwlock_info->writer_thread == sgx_thread_self()) {

		sgx_spin_unlock(&rwlock_info_map_lock);

		// On error errno is set and returned.
		// EDEADLK is returned when the current thread is holding the write lock
		errno = EDEADLK;
		FEND;
		return EDEADLK;
	}
	
	rwlock_info->busy++;
	sgx_spin_unlock(&rwlock_info_map_lock);
	
	sgx_thread_mutex_lock(&rwlock_info->mutex);
	
	// Allow reader to continue only if there is no writer holding the lock or blocked on the lock
	while (rwlock_info->writers_num > 0) {
		sgx_thread_cond_wait(&rwlock_info->cond, &rwlock_info->mutex);
	}

	// We update the readers number only after we verified there is no pending writers to prevent writers starvation
	rwlock_info->readers_num++;

	sgx_thread_mutex_unlock(&rwlock_info->mutex);
	
	sgx_spin_lock(&rwlock_info_map_lock);
	rwlock_info->busy--;
	sgx_spin_unlock(&rwlock_info_map_lock);

	FEND;
	return 0;
}


int sgxssl_pthread_rwlock_wrlock (pthread_rwlock_t *rwlock)
{
	FSTART;

	if (rwlock == NULL) {
		errno = EINVAL;
		FEND;
		return EINVAL;
	}

	sgx_spin_lock(&rwlock_info_map_lock);

	std::map<void*, RwlockInfo*>::iterator it = rwlock_info_map.find(rwlock);
	if ( it == rwlock_info_map.end() ||	it->second == NULL ) {

		sgx_spin_unlock(&rwlock_info_map_lock);

		// On error errno is set to EINVAL and errno is returned
		errno = EINVAL;
		FEND;
		return EINVAL;
	}

	RwlockInfo * rwlock_info = it->second;

	// Verify the current thread is not holding the writers lock
	if (rwlock_info->writer_thread == sgx_thread_self()) {

		sgx_spin_unlock(&rwlock_info_map_lock);

		// On error errno is set and returned.
		// EDEADLK is returned when the current thread is holding the write lock
		errno = EDEADLK;
		FEND;
		return EDEADLK;
	}
	
	rwlock_info->busy++;
	sgx_spin_unlock(&rwlock_info_map_lock);
	
	sgx_thread_mutex_lock(&rwlock_info->mutex);
	
	// First of all update the writers number to prevent writers starvation
	rwlock_info->writers_num++;

	// Before acquiring writers lock, verify there is no other thread (reader or writer) holding or pending to the rwlock
	while (rwlock_info->readers_num > 0) {
		sgx_thread_cond_wait(&rwlock_info->cond, &rwlock_info->mutex);
	}

	// Before acquiring writers lock, verify there is no other writer that holding or pending to the rwlock
	while (rwlock_info->writer_thread != SGX_THREAD_T_NULL) {
		sgx_thread_cond_wait(&rwlock_info->cond, &rwlock_info->mutex);
	}

	// Acquire writers lock
	rwlock_info->writer_thread = sgx_thread_self();

	sgx_thread_mutex_unlock(&rwlock_info->mutex);
	
	sgx_spin_lock(&rwlock_info_map_lock);
	rwlock_info->busy--;
	sgx_spin_unlock(&rwlock_info_map_lock);


	FEND;
	return 0;
}

int sgxssl_pthread_rwlock_unlock (pthread_rwlock_t *rwlock)
{
	FSTART;

	if (rwlock == NULL) {
		errno = EINVAL;
		FEND;
		return EINVAL;
	}

	sgx_spin_lock(&rwlock_info_map_lock);

	std::map<void*, RwlockInfo*>::iterator it = rwlock_info_map.find(rwlock);
	if ( it == rwlock_info_map.end() ||	it->second == NULL ) {

		sgx_spin_unlock(&rwlock_info_map_lock);

		// On error errno is set to EINVAL and errno is returned
		errno = EINVAL;
		FEND;
		return EINVAL;
	}

	RwlockInfo * rwlock_info = it->second;
	
	sgx_spin_unlock(&rwlock_info_map_lock);
	
	sgx_thread_mutex_lock(&rwlock_info->mutex);

	if (rwlock_info->readers_num > 0)  {
		rwlock_info->readers_num--;
		
		if (rwlock_info->readers_num == 0 && rwlock_info->writers_num > 0)
			sgx_thread_cond_broadcast(&rwlock_info->cond); // readers no longer hold the lock adn we have writers waiting
		// else - other readers are still holding the lock -or- no one is waiting
	}
	else {
		// Verify current thread is holding writers lock
		if (rwlock_info->writer_thread != sgx_thread_self()) {
			sgx_thread_mutex_unlock(&rwlock_info->mutex);
			// On error errno is set and returned.
			// EPERM is returned when current thread doesn't hold the lock
			errno = EPERM;
			FEND;
			return EPERM;
		}

		// Release the writers lock
		rwlock_info->writers_num--;
		rwlock_info->writer_thread = SGX_THREAD_T_NULL;
		
		if (rwlock_info->busy > 0) // there might be someone waiting
			sgx_thread_cond_broadcast(&rwlock_info->cond);
	}
	
	sgx_thread_mutex_unlock(&rwlock_info->mutex);

	FEND;
	return 0;

}

int sgxssl_pthread_once (pthread_once_t *once_control, void (*init_routine) (void))
{
	FSTART;

	if (once_control == NULL) {
		errno = EINVAL;
		FEND;
		return EINVAL;
	}

	volatile pthread_once_t * once_control_p = once_control;

	sgx_spin_lock(&pthread_once_lock);

	if (*once_control != ONCE_CONTROL_INIT &&
		*once_control != ONCE_CONTROL_COMPLETE &&
		*once_control != ONCE_CONTROL_BUSY) {

		sgx_spin_unlock(&pthread_once_lock);

		SGX_UNREACHABLE_CODE(SET_ERRNO);
		FEND;
		return EINVAL;

	}

	while (*once_control == ONCE_CONTROL_BUSY) {
		sgx_spin_unlock(&pthread_once_lock);

		sgx_spin_lock(&pthread_once_lock);
	}

	// First call by any thread in a process with a given once_control causes init_routne to be executed and completed.
	// Subsequent calls with the given once_control shall not call the inti_routin.
	if (*once_control == ONCE_CONTROL_INIT) {

		*once_control_p = ONCE_CONTROL_BUSY;
		sgx_spin_unlock(&pthread_once_lock);

		// init function is called outside the lock to support recursive sgxssl_pthread_once
		// where init_routine() itself calls sgxssl_pthread_once()
		if (init_routine != NULL)
			init_routine();

		sgx_spin_lock(&pthread_once_lock);
		*once_control_p = ONCE_CONTROL_COMPLETE;
	}
	sgx_spin_unlock(&pthread_once_lock);


	FEND;
	return 0;
}

int sgxssl_pthread_key_create (pthread_key_t *key, void (*destr_function) (void *))
{
	FSTART;

	if (key == NULL) {
		errno = EINVAL;
		FEND;
		return EINVAL;
	}

	if (pthread_next_key == 0) {
		// Keys number overflow
		errno = EFAULT;
		FEND;
		return EFAULT;
	}

	sgx_spin_lock(&pthread_key_lock);
	*key = pthread_next_key;
	try {
		pthread_key_destr_func_map[pthread_next_key] = destr_function;
	} catch (std::bad_alloc e) {
		(void)e;
		sgx_spin_unlock(&pthread_key_lock);
		errno = ENOMEM;
		FEND;
		return ENOMEM;
	}
	pthread_next_key++;
	sgx_spin_unlock(&pthread_key_lock);

	// NOTE: Destructor functions are registered to be called at thread exit
	// We keep them, even we don't have a chance to run them as OpenSSL doesn't run pthread_exit

	FEND;
	return 0;
}

int sgxssl_pthread_key_delete (pthread_key_t key)
{
	FSTART;

	sgx_spin_lock(&pthread_key_lock);

	std::map<pthread_key_t, destr_function>::iterator map_it = pthread_key_destr_func_map.find(key);
	if ( map_it == pthread_key_destr_func_map.end()) {

		sgx_spin_unlock(&pthread_key_lock);
		// the key value is invalid
		errno = EINVAL;
		FEND;
		return EINVAL;
	}

	std::map<pthread_key_t, std::map<sgx_thread_t, const void*> * >::iterator it = thread_specific_data_map.find(key);
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
			return EFAULT;
		}

		// Erase the thread_specific_data_map entry with the given key
		thread_specific_data_map.erase(it);
	}

    // Erase the pthread_key_destr_func_map entry with the given key.
	pthread_key_destr_func_map.erase(map_it);

	// NOTE: Regarding the application data, it is the responsibility of the application to free/cleanup
	// any data related to the deleted key or associated thread-specific data on any thread.

	// If there are no keys in use, reset the next key number
	if (pthread_key_destr_func_map.empty()) {
		pthread_next_key = 1;
	}

	sgx_spin_unlock(&pthread_key_lock);

	FEND;
	return 0;
}

void * sgxssl_pthread_getspecific (pthread_key_t key)
{
	sgx_spin_lock(&pthread_key_lock);

	std::map<pthread_key_t, std::map<sgx_thread_t, const void*> *>::iterator it = thread_specific_data_map.find(key);

	if (it == thread_specific_data_map.end() ||	it->second == NULL) {
		sgx_spin_unlock(&pthread_key_lock);
		FEND;
		return NULL;
	}

	std::map<sgx_thread_t, const void*> * p_data_map = it->second;
	std::map<sgx_thread_t, const void*>::iterator iter = p_data_map->find(sgx_thread_self());

	if (iter == p_data_map->end()) {
		sgx_spin_unlock(&pthread_key_lock);
		FEND;
		return NULL;
	}

	void *data = (void *)iter->second;
	sgx_spin_unlock(&pthread_key_lock);
	FEND;

	return data;
}

int sgxssl_pthread_setspecific (pthread_key_t key, const void *data)
{
	sgx_spin_lock(&pthread_key_lock);

	std::map<pthread_key_t, destr_function>::iterator iter = pthread_key_destr_func_map.find(key);
	if ( iter == pthread_key_destr_func_map.end()) {

		sgx_spin_unlock(&pthread_key_lock);
		// the key value is invalid
		errno = EINVAL;
		FEND;
		return EINVAL;
	}

	std::map<sgx_thread_t, const void*> * p_data_map = NULL;
	std::map<pthread_key_t, std::map<sgx_thread_t, const void*> *>::iterator it = thread_specific_data_map.find(key);

	if (it == thread_specific_data_map.end() ||	it->second == NULL) {
		try {
			p_data_map = new std::map<sgx_thread_t, const void*>;
			thread_specific_data_map[key] = p_data_map;
		}
		catch (std::bad_alloc e)
		{
			sgx_spin_unlock(&pthread_key_lock);
			(void)e; // remove warning
			if (p_data_map != NULL) // second memory allocation failed
				delete p_data_map;
			errno = ENOMEM;
			FEND;
			return ENOMEM;
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
		sgx_spin_unlock(&pthread_key_lock);
		(void)e; // remove warning
		errno = ENOMEM;
		FEND;
		return ENOMEM;
	}
		
	sgx_spin_unlock(&pthread_key_lock);

	FEND;
	return 0;
}

pthread_t sgxssl_pthread_self (void)
{
	FSTART;

	sgx_thread_t thread_self = sgx_thread_self();

	FEND;

	return thread_self;
}

//Thread forking isn't supported inside enclave.
int sgxssl_pthread_atfork(void (*prepare)(void), void (*parent)(void), void (*child)(void))
{
    FSTART;
    SGX_UNREACHABLE_CODE(SET_ERRNO);

    FEND;
    //Operation not permitted
    return EPERM;
}

// Return 0 if the threads are not equal
int sgxssl_pthread_equal (pthread_t thread1, pthread_t thread2)
{
	FSTART;
	
	int retval = FALSE;

	if (thread1 == thread2)
		retval = TRUE;

	FEND;

	return retval;
}

}

