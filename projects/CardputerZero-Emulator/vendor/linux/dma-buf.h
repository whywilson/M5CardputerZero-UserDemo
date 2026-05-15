/* Stub linux/dma-buf.h for non-Linux / emulator builds */
#pragma once
#ifndef _LINUX_DMA_BUF_H
#define _LINUX_DMA_BUF_H
#include <stdint.h>

#define DMA_BUF_SYNC_READ   (1UL << 0)
#define DMA_BUF_SYNC_WRITE  (2UL << 0)
#define DMA_BUF_SYNC_RW     (DMA_BUF_SYNC_READ | DMA_BUF_SYNC_WRITE)
#define DMA_BUF_SYNC_START  (0UL << 2)
#define DMA_BUF_SYNC_END    (1UL << 2)

struct dma_buf_sync {
    uint64_t flags;
};

#endif /* _LINUX_DMA_BUF_H */
