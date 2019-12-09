#include "aliweb_os.h"


void *utc_mutex_create(void){
    return HAL_MutexCreate();
}
void utc_mutex_destroy(void *mutex){
    return HAL_MutexDestroy(mutex);
}
void utc_mutex_lock(void *mutex){
    return HAL_MutexLock(mutex);
}
void utc_mutex_unlock( void *mutex){
    return HAL_MutexUnlock(mutex);
}
void *utc_semaphore_create(void){
    return HAL_SemaphoreCreate();
}
void utc_semaphore_destroy( void *sem){
    return HAL_SemaphoreDestroy(sem);
}
void utc_semaphore_post( void *sem){
    return HAL_SemaphorePost(sem);
}
int utc_semaphore_wait(void *sem,uint32_t timeout_ms){
    return HAL_SemaphoreWait(sem,timeout_ms);
}
void  utc_free( void *ptr){
    return HAL_Free(ptr);
}
void *utc_malloc( uint32_t size){
    return HAL_Malloc(size);
}
void utc_sleepms( uint32_t ms){
    return HAL_SleepMs(ms);
}
uint32_t utc_random(uint32_t region){
    return HAL_Random(region);
}
int utc_thread_create(void **handle,void *(*work_routine)(void *),void* pArg){
      return  (int)xTaskCreate((void (*)(void *))work_routine, "websocket", 6144, pArg, 5, NULL);
}

void utc_thread_delete(void *thread_handle){
     vTaskDelete(thread_handle);
}