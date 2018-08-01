/**
 * Heap Guard
 *
 * Segfaults on either overflow or underflow to the heap (but not both
 * simultaneously)
 *
 * jtavares 2018-01-19
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdint.h>
#include <errno.h>

#include "heapguard.h"
#include "crc32.h"

#define MIN_SIZE(a,b)       ((a) < (b) ? (a) : (b))

#define BLOCK_HDR_CRC32(a)  calculate_crc32c(0, (const unsigned char *)(a), offsetof(block_hdr_t, chk_crc32));

// MAP_32BIT not defined in sys/mman.h for older platforms
#ifndef MAP_32BIT
#define MAP_32BIT 0
#endif

// 32-byte random signature used in underflow detection
// to detect "short" allocations whereby the block header
// is located at the end of the page.
#if HEAPGUARD_MODE == HEAPGUARD_MODE_UNDERFLOW
static const unsigned char HEAPGUARD_SIGNATURE[] = {
    0x7c,0xf5,0x54,0xe9,0x04,0x3a,0x0c,0x95,
    0xe6,0xda,0x1d,0x2f,0x8c,0xe9,0xb9,0x27,
    0x23,0x36,0xd3,0x3b,0x64,0xca,0x56,0x46,
    0x89,0xd5,0xc3,0x23,0xbb,0xd1,0x09,0x8e
};
#endif

typedef struct block_hdr {
    uint32_t block_size;  // size of block, including guard page at end
    uint32_t size;        // user's requested size
    uint32_t alignment;   // user alignment
    uint32_t chk_crc32;   // corruption detection
#if HEAPGUARD_MODE == HEAPGUARD_MODE_UNDERFLOW
    // maintainer warning: code assumes signature is at the *end* of this struct
    unsigned char signature[sizeof(HEAPGUARD_SIGNATURE)];
#endif
} block_hdr_t;


/* Internal Prototypes */

#if HEAPGUARD_MODE == HEAPGUARD_MODE_UNDERFLOW

static void* realloc_under(void* ptr, size_t size);
static void* memalign_under(size_t alignment, size_t size);
static void  free_under(void* ptr);

#endif


#if HEAPGUARD_MODE == HEAPGUARD_MODE_OVERFLOW

static void* realloc_over(void* ptr, size_t size);
static void* memalign_over(size_t alignment, size_t size);
static void  free_over(void* ptr);

#endif

/* Internal State */

// none

/* Helpers functions */

// none

/* Underflow detection */

#if HEAPGUARD_MODE == HEAPGUARD_MODE_UNDERFLOW

static void* realloc_under(void* old_ptr, size_t new_size)
{
    // When old_ptr==NULL, realloc() is a malloc()
    if (old_ptr == NULL) {
        return malloc(new_size); // will call memalign_under()...
    }

    // When new_size == 0 and old_ptr != NULL, realloc() is a free()
    if (new_size == 0) {
        free_under(old_ptr);
        return NULL;
    }

    // check for bogus pointer
    if ((intptr_t)old_ptr & (HEAPGUARD_PAGE_SIZE-1)) {
        // bad pointer -- in underflow mode, all pointers are at a page boundary
        fprintf(stderr, "realloc_under(%p): bad pointer: not on page boundary\n",
                old_ptr);
        HEAPGUARD_ERROR;
    }

    // underflow: block begins at beginning of previous page
    char* const old_block_ptr = (char*)old_ptr - HEAPGUARD_PAGE_SIZE;

    // auto-detect header location by signature
    block_hdr_t* old_block_hdr_ptr =
        (0 != memcmp((char*)old_ptr + HEAPGUARD_PAGE_SIZE - sizeof(HEAPGUARD_SIGNATURE),
                     HEAPGUARD_SIGNATURE,
                     sizeof(HEAPGUARD_SIGNATURE)))
        ? (block_hdr_t*)(old_block_ptr)                                                 // start of guard page (1st page)
        : (block_hdr_t*)((char*)old_ptr + HEAPGUARD_PAGE_SIZE - sizeof(block_hdr_t));   // end of user page (2nd page)

    // unprotect the 1st page so *we* can read/write header
    int mprotect_res = mprotect(old_block_ptr, HEAPGUARD_PAGE_SIZE, PROT_READ|PROT_WRITE);
    if (mprotect_res == -1) {
        // fatal error
        fprintf(stderr, "realloc_under(%p): mprotect(%p) 1 failed (errno: %d)\n",
                old_ptr, old_block_ptr, errno);
        HEAPGUARD_ERROR;
    }

    // obtain (truncated) copy of old block header
    block_hdr_t old_block_hdr;
    memcpy(&old_block_hdr, old_block_hdr_ptr, offsetof(block_hdr_t, signature));

    const uint32_t old_chk_crc32 = BLOCK_HDR_CRC32(&old_block_hdr);

    // check crc32
    if (old_block_hdr.chk_crc32 != old_chk_crc32) {
        fprintf(stderr, "realloc_under(%p, %u): bad crc32 (0x%08x) for old_block_ptr=%p, old_block_size=%u, old_size=%u\n",
                old_ptr, new_size, old_block_hdr.chk_crc32, old_block_ptr,
                old_block_hdr.block_size, old_block_hdr.size);
        HEAPGUARD_ERROR;
    }

    // destroy old block header & signature
    // TODO: optimization potential: don't waste time destroying the old 
    //       header if it won't end up moving it
    memset(old_block_hdr_ptr, 0x00, sizeof(block_hdr_t));

    // new_size_rounded rounds up to the next page size
    const size_t new_size_rounded = (new_size + HEAPGUARD_PAGE_SIZE - 1) & ~(HEAPGUARD_PAGE_SIZE - 1);

    // new_block_size adds one page for the guard area
    const size_t new_block_size = new_size_rounded + HEAPGUARD_PAGE_SIZE;

    // remap the existing block
    char* const new_block_ptr = (char*)mremap(old_block_ptr, old_block_hdr.block_size,
                                              new_block_size, MREMAP_MAYMOVE);

    if (new_block_ptr == MAP_FAILED) {
        // TODO: what happens to the old mapping? I think we need to unmap it
        //       or we may have a memory leak here!
#if HEAPGUARD_DEBUG
        fprintf(stderr, "realloc_under(%p, %u): mmap failed (errno %d), old_block_ptr: %p\n",
                old_ptr, new_size, errno, old_block_ptr);

#endif
        errno = ENOMEM;
        return NULL;
    }

    char* const new_ptr = new_block_ptr + HEAPGUARD_PAGE_SIZE;

    // write new header
    // if the header fits in the user's page, put it there, otherwise
    // put it at the start of the guard page.
    block_hdr_t* new_block_hdr_ptr =
        (new_size + sizeof(block_hdr_t) > HEAPGUARD_PAGE_SIZE)
        ? (block_hdr_t*)(new_block_ptr)                                         // start of guard page (1st page)
        : (block_hdr_t*)(new_ptr + HEAPGUARD_PAGE_SIZE - sizeof(block_hdr_t));  // end of user page (2nd page)
        
    new_block_hdr_ptr->block_size = new_block_size;
    new_block_hdr_ptr->size = new_size;
    new_block_hdr_ptr->alignment = old_block_hdr.alignment;
    new_block_hdr_ptr->chk_crc32 = BLOCK_HDR_CRC32(new_block_hdr_ptr);
    memcpy(new_block_hdr_ptr->signature, HEAPGUARD_SIGNATURE, sizeof(HEAPGUARD_SIGNATURE));

    // protect the 1st page to act as guard page
    mprotect_res = mprotect(new_block_ptr, HEAPGUARD_PAGE_SIZE, PROT_NONE);
    if (mprotect_res == -1) {
        // fatal error
        fprintf(stderr, "realloc_under(%p): mprotect(%p) 2 failed (errno: %d)\n",
                old_ptr, new_block_ptr, errno);
        HEAPGUARD_ERROR;
    }

#if HEAPGUARD_DEBUG
    printf("realloc_under(%p, %u): old_blk_ptr: %p, old_blk_hdr_ptr: %p, old_blk_size: %u, old_size: %u, new_ptr: %p, new_blk_ptr: %p, new_blk_hdr_ptr: %p, new_blk_size: %d\n",
           old_ptr, new_size, old_block_ptr, old_block_hdr_ptr,
           old_block_hdr.block_size, old_block_hdr.size,
           new_ptr, new_block_ptr, new_block_hdr_ptr, new_block_size);
#endif

    return new_ptr;
}

static void* memalign_under(size_t alignment, size_t size)
{
    // TODO memalign_*() needs to check that alignment is a power of two.

    // check alignment
    if (alignment > HEAPGUARD_PAGE_SIZE) {
        fprintf(stderr, "memalign_under(%u, %u): sorry, alignment > HEAPGUARD_PAGE_SIZE (%d) not supported\n",
                alignment, size, HEAPGUARD_PAGE_SIZE);
        HEAPGUARD_ERROR;
    }

    // can't allocate an empty block
    if (size == 0) {
        return NULL;
    }

    // NOTE: we ignore the requested alignment in underflow mode as
    // user data always starts at a page boundary

    // size_rounded rounds up to the next page size
    const size_t size_rounded = (size + HEAPGUARD_PAGE_SIZE - 1) & ~(HEAPGUARD_PAGE_SIZE - 1);

    // block_size adds one page for the guard area
    const size_t block_size = size_rounded + HEAPGUARD_PAGE_SIZE;

    // allocate a block
    char* const block_ptr = (char*)mmap(NULL, block_size, PROT_READ|PROT_WRITE,
                                        MAP_PRIVATE|MAP_ANONYMOUS|MAP_32BIT, -1, 0);

    // check for out of memory
    if (block_ptr == MAP_FAILED) {
#if HEAPGUARD_DEBUG
        fprintf(stderr, "memalign_under(%u, %u): mmap failed (errno: %d)\n",
                alignment, size, block_ptr, errno);
#endif        
        errno = ENOMEM;
        return NULL;
    }

    char* const ptr = block_ptr + HEAPGUARD_PAGE_SIZE;

    // write header
    // if the header fits in the user's page, put it there, otherwise
    // put it at the start of the guard page.
    block_hdr_t* const block_hdr = (size + sizeof(block_hdr_t) > HEAPGUARD_PAGE_SIZE)
        ? (block_hdr_t*)(block_ptr)                                        // start of guard page (1st page)
        : (block_hdr_t*)(ptr + HEAPGUARD_PAGE_SIZE - sizeof(block_hdr_t)); // end of user page (2nd page)

    block_hdr->block_size = block_size;
    block_hdr->size = size;
    block_hdr->alignment = alignment;
    block_hdr->chk_crc32 = BLOCK_HDR_CRC32(block_hdr);
    memcpy(block_hdr->signature, HEAPGUARD_SIGNATURE, sizeof(HEAPGUARD_SIGNATURE));

    // overflow: protect first page
    int mprotect_res = mprotect(block_ptr, HEAPGUARD_PAGE_SIZE, PROT_NONE);
    if (mprotect_res == -1) {
        // fatal error -- kernel is likely out of vm page table structures
        fprintf(stderr, "memalign_under(%u, %u): mprotect(%p): failed (errno: %d), block_ptr: %p, block_size: %u\n",
                        alignment, size, block_ptr, errno,
                        block_ptr, block_size);
        HEAPGUARD_ERROR;
    }

    // debug
#if HEAPGUARD_DEBUG
    printf("memalign_under(%u, %u): size_rounded=%u, block_size=%u, block_ptr=%p, block_hdr=%p, ptr=%p\n",
           alignment, size, size_rounded, block_size, block_ptr, block_hdr, ptr);
#endif

    return ptr;
}

static void free_under(void* ptr)
{
    if (ptr == NULL)
        return; // nothing to do

    if ((intptr_t)ptr & (HEAPGUARD_PAGE_SIZE-1)) {
        // bad pointer -- in underflow mode, all pointers are at a page boundary
        fprintf(stderr, "free_under(%p): bad pointer: not on page boundary\n",
                ptr);
        HEAPGUARD_ERROR;
    }

    // underflow: block begins at beginning of previous page
    char* const block_ptr = (char*)ptr - HEAPGUARD_PAGE_SIZE;

    // auto-detect header location by signature
    block_hdr_t* const block_hdr_ptr =
        (0 != memcmp((char*)ptr + HEAPGUARD_PAGE_SIZE - sizeof(HEAPGUARD_SIGNATURE),
                     HEAPGUARD_SIGNATURE,
                     sizeof(HEAPGUARD_SIGNATURE)))
        ? (block_hdr_t*)(block_ptr)                                         // start of guard page (1st page)
        : (block_hdr_t*)((char*)ptr + HEAPGUARD_PAGE_SIZE - sizeof(block_hdr_t));  // end of user page (2nd page)

    // unprotect the 1st page so *we* can read header
    // (only necessary if header is located in guard page)
    if ((void*)block_hdr_ptr == (void*)block_ptr) {
        int mprotect_res = mprotect(block_ptr, HEAPGUARD_PAGE_SIZE, PROT_READ);
        if (mprotect_res == -1) {
            // fatal error
            fprintf(stderr, "free_under(%p): mprotect(%p) failed (errno: %d)\n",
                    ptr, block_ptr, errno);
            HEAPGUARD_ERROR;
        }
    }

    // obtain a (truncated) copy of the block header, before we munmap() it
    block_hdr_t block_hdr;
    memcpy(&block_hdr, block_hdr_ptr, offsetof(block_hdr_t, signature));

    const uint32_t chk_crc32 = BLOCK_HDR_CRC32(&block_hdr);

    if (block_hdr.chk_crc32 != chk_crc32) {
        fprintf(stderr, "free_under(%p): bad crc32 (0x%08x) for block_ptr=%p, block_size=%u, size=%u\n",
                ptr, block_hdr.chk_crc32, block_ptr, block_hdr.block_size, block_hdr.size);
        HEAPGUARD_ERROR;
    }

    int munmap_result = munmap(block_ptr, block_hdr.block_size);
    if (munmap_result == -1) {
        fprintf(stderr, "free_under(%p): munmap failed (%d) for block_ptr=%p, block_size=%u, size=%u\n",
                ptr, munmap_result, block_ptr, block_hdr.block_size, block_hdr.size);
        HEAPGUARD_ERROR;
    }

#if HEAPGUARD_DEBUG
    printf("free_under(%p) block_ptr=%p, block_hdr_ptr=%p, block_size=%u, size=%u\n",
           ptr, block_ptr, block_hdr_ptr, block_hdr.block_size, block_hdr.size);
#endif    
}

#endif /* HEAPGUARD_MODE == HEAPGUARD_MODE_UNDERFLOW */

/* Overflow Detection */

#if HEAPGUARD_MODE == HEAPGUARD_MODE_OVERFLOW

static void* realloc_over(void* old_ptr, size_t new_size)
{
    // When old_ptr==NULL, realloc() is a malloc()
    if (old_ptr == NULL) {
        return malloc(new_size); // will call memalign_over()...
    }

    // When new_size == 0 and old_ptr != NULL, realloc() is a free()
    if (new_size == 0) {
        free_over(old_ptr);
        return NULL;
    }

    // check for bogus pointer
    if ((intptr_t)old_ptr & (HEAPGUARD_MIN_ALIGNMENT-1)) {
        // bad pointer -- in overflow mode, all pointers are at a page boundary
        fprintf(stderr, "realloc_over(%p): bad pointer: not aligned to HEAPGUARD_MIN_ALIGNMENT (%d)\n",
                old_ptr, HEAPGUARD_MIN_ALIGNMENT);
        HEAPGUARD_ERROR;
    }

    // Translate the user pointer to the start of the mmap'd block
    char* const old_block_ptr = (char*)((intptr_t)((char*)old_ptr - sizeof(block_hdr_t)) & ~ (HEAPGUARD_PAGE_SIZE-1));

    // Make a copy of the old block header before we mremap()
    block_hdr_t old_block_hdr;
    memcpy(&old_block_hdr, old_block_ptr, sizeof(block_hdr_t));

    const uint32_t old_chk_crc32 = BLOCK_HDR_CRC32(&old_block_hdr);

    if (old_block_hdr.chk_crc32 != old_chk_crc32) {
        fprintf(stderr, "realloc_over(%p, %u): bad crc32 (0x%08x) for old_block_ptr=%p, old_block_size=%u, old_size=%u\n",
                old_ptr, new_size, old_block_hdr.chk_crc32, old_block_ptr,
                old_block_hdr.block_size, old_block_hdr.size);
        HEAPGUARD_ERROR;
    }

    // Optimization: If there is no size change requested, then we can just return existing pointer
    if (old_block_hdr.size == new_size) {
        return old_ptr;
    }

    // Unprotect the old last page in case we need to expand into it
    char* const old_last_page = old_block_ptr + old_block_hdr.block_size - HEAPGUARD_PAGE_SIZE;
    int mprotect_res = mprotect(old_last_page, HEAPGUARD_PAGE_SIZE, PROT_READ|PROT_WRITE);
    if (mprotect_res == -1) {
        // fatal error
        fprintf(stderr, "realloc_over(%p, %u): mprotect(%p) old last page failed (errno: %d), old_block_ptr: %p\n",
                old_ptr, new_size, old_last_page, errno, old_block_ptr);
        HEAPGUARD_ERROR;
    }

    // align the user's request
    const size_t new_size_aligned = (new_size + old_block_hdr.alignment - 1) & ~(old_block_hdr.alignment - 1);

    // size_rounded adds room for accounting, rounded up to the next page size
    const size_t new_size_rounded = (new_size_aligned + sizeof(block_hdr_t) + HEAPGUARD_PAGE_SIZE - 1) & ~(HEAPGUARD_PAGE_SIZE - 1);

    // block_size adds one page for the guard area
    const size_t new_block_size = new_size_rounded + HEAPGUARD_PAGE_SIZE;

    // remap the existing block
    char* const new_block_ptr = (char*)mremap(old_block_ptr, old_block_hdr.block_size,
                                              new_block_size, MREMAP_MAYMOVE);

    if (new_block_ptr == MAP_FAILED) {
        // TODO: what happens to the old mapping? I think we need to unmap it
        //       or we may have a memory leak here!
#if HEAPGUARD_DEBUG
        fprintf(stderr, "realloc_over(%p, %u): mremap failed (errno %d), old_block_ptr: %p\n",
                old_ptr, new_size, errno, old_block_ptr);

#endif
        errno = ENOMEM;
        return NULL;
    }

    char* const new_ptr = new_block_ptr + new_size_rounded - new_size_aligned;

    // copy of the data to the new block
    size_t new_delta = (char*)new_ptr - new_block_ptr;
    size_t old_delta = (char*)old_ptr - old_block_ptr;

    if (new_delta != old_delta) {
        // starting offset has changed. move user data to new starting offset
        memmove(new_ptr, new_block_ptr+old_delta, MIN_SIZE(old_block_hdr.size, new_size));
    }

    // write size information to start of first page
    block_hdr_t* const new_block_hdr = (block_hdr_t*)new_block_ptr;
    new_block_hdr->block_size = new_block_size;
    new_block_hdr->size = new_size;
    new_block_hdr->alignment = old_block_hdr.alignment;
    new_block_hdr->chk_crc32 = BLOCK_HDR_CRC32(new_block_hdr);

    // overflow: protect last page
    char* const new_last_page = new_block_ptr + new_size_rounded;
    mprotect_res = mprotect(new_last_page, HEAPGUARD_PAGE_SIZE, PROT_NONE);
    if (mprotect_res == -1) {
        // fatal error
        fprintf(stderr, "realloc_over(%p, %u): mprotect(%p) new last page failed (errno: %d), old_block_ptr: %p\n",
                old_ptr, new_size, new_last_page, errno, old_block_ptr);
        HEAPGUARD_ERROR;
    }

#if HEAPGUARD_DEBUG
    printf("realloc_over(%p, %u): old_blk_ptr: %p, old_blk_size: %u, old_size: %u, new_ptr: %p, new_blk_ptr: %p, new_blk_size: %d\n",
           old_ptr, new_size, old_block_ptr, old_block_hdr.block_size, old_block_hdr.size,
           new_ptr, new_block_ptr, new_block_size);
#endif

    return new_ptr;
}

static void* memalign_over(size_t alignment, size_t size)
{
    // TODO memalign_*() needs to check that alignment is a power of two.

    if (alignment > HEAPGUARD_PAGE_SIZE) {
        fprintf(stderr, "memalign_over(%u, %u): sorry, alignment > HEAPGUARD_PAGE_SIZE (%d) not supported\n",
                alignment, size, HEAPGUARD_PAGE_SIZE);
        HEAPGUARD_ERROR;
    }

    if (alignment < HEAPGUARD_MIN_ALIGNMENT) {
        fprintf(stderr, "memalign_over(%u, %u): sorry, alignment < HEAPGUARD_MIN_ALIGNMENT (%d) not supported\n",
                alignment, size, HEAPGUARD_MIN_ALIGNMENT);
        HEAPGUARD_ERROR;
    }

    // can't allocate empty block
    if (size == 0) {
        return NULL;
    }

    // align the user's request
    const size_t size_aligned = (size + alignment - 1) & ~(alignment - 1);

    // size_rounded adds overhead for accounting, rounded up to the next page size
    const size_t size_rounded = (size_aligned + sizeof(block_hdr_t) + HEAPGUARD_PAGE_SIZE - 1) & ~(HEAPGUARD_PAGE_SIZE - 1);

    // block_size adds one page for the guard area
    const size_t block_size = size_rounded + HEAPGUARD_PAGE_SIZE;

    // allocate a block
    char* const block_ptr = (char*)mmap(NULL, block_size, PROT_READ|PROT_WRITE,
                                        MAP_PRIVATE|MAP_ANONYMOUS|MAP_32BIT, -1, 0);

    // check for out of memory
    if (block_ptr == MAP_FAILED) {
#if HEAPGUARD_DEBUG
        fprintf(stderr, "memalign_over(%u, %u): mmap failed (errno: %d)\n",
                alignment, size, block_ptr, errno);
#endif      
        errno = ENOMEM;  
        return NULL;
    }

    char* const ptr = block_ptr + size_rounded - size_aligned;

    // write size information to start of first page
    block_hdr_t* const block_hdr = (block_hdr_t*)block_ptr;
    block_hdr->block_size = block_size;
    block_hdr->size = size;
    block_hdr->alignment = alignment;
    block_hdr->chk_crc32 = BLOCK_HDR_CRC32(block_hdr);

    // overflow: protect last page
    void* const last_page = block_ptr + size_rounded;
    int mprotect_res = mprotect(last_page, HEAPGUARD_PAGE_SIZE, PROT_NONE);
    if (mprotect_res == -1) {
        // fatal error -- kernel is likely out of vm page table structures
        fprintf(stderr, "memalign_over(%u, %u): mprotect(%p): failed (errno: %d), block_ptr: %p, block_size: %u\n",
                        alignment, size, last_page, errno,
                        block_ptr, block_size);
        HEAPGUARD_ERROR;
    }

    // debug
#if HEAPGUARD_DEBUG
    printf("memalign_over(%u, %u): size_aligned=%u, size_rounded=%u, block_size=%u, block_ptr=%p, ptr=%p\n",
           alignment, size, size_aligned, size_rounded, block_size, block_ptr, ptr);
#endif

    return ptr;
}

static void free_over(void* ptr)
{
    if (ptr == NULL)
        return;

    // check for bogus pointer
    if ((intptr_t)ptr & (HEAPGUARD_MIN_ALIGNMENT-1)) {
        // bad pointer -- in underflow mode, all pointers are at a page boundary
        fprintf(stderr, "free_over(%p): bad pointer: not aligned to HEAPGUARD_MIN_ALIGNMENT (%d)\n",
                ptr, HEAPGUARD_MIN_ALIGNMENT);
        HEAPGUARD_ERROR;
    }

    // overflow: block begins at beginning of page
    // this might be the previous page, depending on allocation size
    void* const block_ptr = (void*)((intptr_t)((char*)ptr - sizeof(block_hdr_t)) & ~ (HEAPGUARD_PAGE_SIZE-1));

    // obtain a copy of the block header, before we munmap()
    block_hdr_t block_hdr;
    memcpy(&block_hdr, block_ptr, sizeof(block_hdr_t));

    const uint32_t chk_crc32 = BLOCK_HDR_CRC32(&block_hdr);

    if (block_hdr.chk_crc32 != chk_crc32) {
        fprintf(stderr, "free_over(%p): bad crc32 (0x%08x) for block_ptr=%p, block_size=%u, size=%u\n",
                ptr, block_hdr.chk_crc32, block_ptr, block_hdr.block_size, block_hdr.size);
        HEAPGUARD_ERROR;
    }

    int munmap_result = munmap(block_ptr, block_hdr.block_size);
    if (munmap_result == -1) {
        fprintf(stderr, "free_over(%p): munmap failed (%d) for block_ptr=%p, block_size=%u, size=%u\n",
                ptr, munmap_result, block_ptr, block_hdr.block_size, block_hdr.size);
        HEAPGUARD_ERROR;
    }

#if HEAPGUARD_DEBUG
    printf("free_over(%p) block_ptr=%p, block_size=%u, size=%u\n",
           ptr, block_ptr, block_hdr.block_size, block_hdr.size);
#endif    
}

#endif /* HEAPGUARD_MODE == HEAPGUARD_MODE_OVERFLOW */

/* Public API Calls */

// None right now


/* Override glibc memory allocation routines */

void free(void *ptr)
{
#if HEAPGUARD_MODE == HEAPGUARD_MODE_OVERFLOW
    return free_over(ptr);
#else
    return free_under(ptr);
#endif
}

void* realloc(void *ptr, size_t size)
{
#if HEAPGUARD_MODE == HEAPGUARD_MODE_OVERFLOW
    return realloc_over(ptr, size);
#else
    return realloc_under(ptr, size);
#endif
}

void* memalign(size_t alignment, size_t size)
{
#if HEAPGUARD_MODE == HEAPGUARD_MODE_OVERFLOW
    return memalign_over(alignment, size);
#else
    return memalign_under(alignment, size);
#endif
}

void* malloc(size_t size)
{
    return memalign(HEAPGUARD_MIN_ALIGNMENT, size);
} 

void* calloc(size_t nmemb, size_t size)
{
    // NOTE: we are relying on mmap's behavior of zeroing pages
    return malloc(nmemb*size);
}

///////////////////////////////////////////////////////////////
////// WARNING: the following overrides are untested!!! ///////
///////////////////////////////////////////////////////////////

int posix_memalign(void** memptr, size_t alignment, size_t size)
{
    // TODO: posix_memalign() has added restriction that alignment
    //       must be a multiple of sizeof(void*). If not, return EINVAL.

    *memptr = memalign(alignment, size);
    if (*memptr == NULL) {
        // TODO we need to make sure memalign() sets errno to
        //      to either EINVAL or ENOMEM on every NULL return.
        //      if it does, then we can "return errno" here.
        //      until then, be safe and return ENOMEM
        return ENOMEM;
    }

    return 0;
}

void *aligned_alloc(size_t alignment, size_t size)
{
    // TODO: aligned_alloc has added restriction that size 
    //       should be a multiple of alignment. if not,
    //       we should return NULL (and set errno to EINVAL?)
    return memalign(alignment, size);
}

void *valloc(size_t size)
{
    // valloc() requests are aligned to the system page size
    return memalign(HEAPGUARD_PAGE_SIZE, size);
}

void *pvalloc(size_t size)
{
    // pvalloc() requests get rounded up to next multiple of system page size
    const size_t size_rounded = (size + HEAPGUARD_PAGE_SIZE - 1) & ~(HEAPGUARD_PAGE_SIZE - 1);
    return memalign(HEAPGUARD_PAGE_SIZE, size_rounded);
}

