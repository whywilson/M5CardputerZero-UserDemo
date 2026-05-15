/* Stub thpool.h for non-Linux / emulator builds */
#pragma once
#ifndef THPOOL_H
#define THPOOL_H
#include <stddef.h>

typedef void* threadpool;

static inline threadpool thpool_init(int num_threads) { (void)num_threads; return (void*)1; }
static inline int thpool_add_work(threadpool pool, void (*function)(void*), void* arg)
    { (void)pool; if (function) function(arg); return 0; }
static inline void thpool_wait(threadpool pool) { (void)pool; }
static inline void thpool_destroy(threadpool pool) { (void)pool; }
static inline int thpool_num_threads_working(threadpool pool) { (void)pool; return 0; }

#endif /* THPOOL_H */
