/**
 * Heap Guard
 *
 * jtavares 2018-01-19
 */

#ifndef _HEAPGUARD_H
#define _HEAPGUARD_H

// Enumerations - do not modify
#define HEAPGUARD_MODE_OVERFLOW     1
#define HEAPGUARD_MODE_UNDERFLOW    2   // not yet implemented

///////////////////
// CONFIGURATION //
///////////////////

// Errors detected by heapguard will result in a message printed to
// stderr, regardless of HEAPGUARD_DEBUG flag. HEAPGUARD_ERROR 
// determines what other action, if any, is taken.
//
// Some reasonable choices might include:
//     __builtin_trap()         Should trigger debugger?
//     exit(1)                  Terminates program
//     {}                       Ignore error
//     (void*)0 = 1             Cause segfault
//     while(1) { getchar(); }  Loop forever
#define HEAPGUARD_ERROR __builtin_trap()

// Set this flag == 1 to print debug information on malloc/free/memalign/realloc
//#define HEAPGUARD_DEBUG 1

// Operating mode. heapguard can detect either underflows, or overflows,
// but not both.
#ifndef HEAPGUARD_MODE
#define HEAPGUARD_MODE HEAPGUARD_MODE_UNDERFLOW
#endif

// page size could be queried at runtime using sysconf(), but it has been
// defined as compile-time constant for maximum optimization potential.
// nearly all systems are 4096, anyhow
// NOTE: This *must* match mmap() page size for your system!!
#ifndef HEAPGUARD_PAGE_SIZE
#define HEAPGUARD_PAGE_SIZE 4096U
#endif

// Provides 8 byte alignment on 32-bit CPUs, 16 byte alignment on 64-bit CPUs
#ifndef HEAPGUARD_MIN_ALIGNMENT
#define HEAPGUARD_MIN_ALIGNMENT (sizeof(void*)*2)
#endif

#ifdef __cplusplus
extern "C" {
#endif

// this space intentionally left blank.
// public API calls may be added here in the future.

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _HEADGUARD_H */