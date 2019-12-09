#ifndef __ALIWEB_OS__
#define __ALIWEB_OS__

#include "lwip/sockets.h"
 #include "freertos/FreeRTOS.h"
 #include "freertos/task.h"
#include "coap_wrapper.h"


void *utc_mutex_create(void);
void utc_mutex_destroy(void *mutex);
void utc_mutex_lock(void *mutex);
void utc_mutex_unlock( void *mutex);
void *utc_semaphore_create(void);
void utc_semaphore_destroy( void *sem);
void utc_semaphore_post( void *sem);
int    utc_semaphore_wait(void *sem,uint32_t timeout_ms);
void utc_free( void *ptr);
void *utc_malloc( uint32_t size);
void utc_sleepms( uint32_t ms);
int utc_thread_create(void **handle,void *(*work_routine)(void *),void* pArg);
void utc_thread_delete(void *thread_handle);
uint32_t utc_random(uint32_t region);
#endif