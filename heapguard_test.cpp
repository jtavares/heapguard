/**
 * Heap Guard Test Cases
 *
 * jtavares 2018-01-19
 */

#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sigsegv.h>
#include <assert.h>
#include <malloc.h>
#include <errno.h>
#include <stdint.h>

#include "heapguard.h"

typedef void (*testfunc_t)();

// The following are for communication to/from the signal handler
// segfault_addr is marked as containing a (volatile void *)
// for convenience as the test harness needs to mark its pointers
// volatile to avoid compiler optimizations.
volatile int segfault_counter = 0;
volatile void * volatile segfault_addr = NULL;
volatile size_t segfault_line = 0;

// Use this to wrap an expected segfault in a test case
// NOTE: EXPECT_SEGV() can only be used once per allocation, as
//       it removed the guard page protection upon seg fault
//       in order to allow execution to continue.
// TODO: This behavior could be improved if we were to re-mprotect()
//       the guard page after the 'offending_code;' line below!
//       Perhaps an API call to heapguard should be created for 
//       this purpose.
#define EXPECT_SEGV(addr, offending_code) do {                  \
    segfault_line = __LINE__;                                   \
    segfault_counter = 0;                                       \
    segfault_addr = addr;                                       \
    offending_code;                                             \
    if (segfault_counter != 1 || segfault_addr != NULL) {       \
        printf("error: missing expected segfault at %p (line %u)\n",     \
               addr, __LINE__);                                 \
        exit(1);                                                \
    }                                                           \
    segfault_addr = NULL;                                       \
    segfault_line = 0;                                          \
} while(0);

// SEGV signal handler
void segfault(int sig, siginfo_t *si, void* unused)
{
    if (si->si_addr == segfault_addr && segfault_addr != NULL) {
        // unprotect the page in question so that execution may continue
        void* const page = (void*)((intptr_t)si->si_addr & ~ (HEAPGUARD_PAGE_SIZE-1));
        int mprotect_result = mprotect(page, HEAPGUARD_PAGE_SIZE, PROT_READ|PROT_WRITE);
        
        if (mprotect_result) {
            printf("error: mprotect_result returned %d (errno %d) (line %u)\n",
                   mprotect_result, errno, segfault_line);
            perror("mprotect");
            exit(1);
        }

        printf("got expected segfault at address %p (line %u)\n", si->si_addr, segfault_line);

        // signal to userland that we found the expected segfault
        segfault_addr = NULL;
    } else {
        printf("error: unexpected segfault at address %p (line %u)\n", si->si_addr, segfault_line);
        exit(1);
    }

    if (++segfault_counter > 5) {
        // safety hatch
        puts("ut-oh! segfault loop detected. exiting...\n");
        exit(1);
    }
}

// Perform a test
void test(const char* testname, testfunc_t testfunc)
{
    printf(">>> %s: test started\n", testname);

    testfunc();
  
    printf(">>> %s: test passed\n", testname);
}

void test_over()
{
    // note: these tests assume alignment=16 (i.e., 64-bit x86)

    test("malloc 3", [](){
        char volatile* p = (char*)malloc(3);

        p[0] = 1;
        p[1] = 2;
        p[2] = 3;
        p[3] = 4; // Out of bounds, but no segfault because of minimum alignment requirements
        //...
        p[15] = 16; // ditto
        printf("p+16: %p\n", p+16);
        EXPECT_SEGV(&p[16], p[16] = 123);
        free((void*)p);
    });

    test("malloc 4081", [](){
        char volatile* p = (char*)malloc(4081);

        p[0] = 1;
        p[1] = 2;
        p[2] = 3;
        p[4080] = 4;
        p[4081] = 123; // Out of bounds, but no segfault because of minimum alignment requirements
        //...
        p[4095] = 23; // ditto
        printf("p+4096: %p\n", p+4096);
        EXPECT_SEGV(&p[4096], p[4096] = 4);
        free((void*)p);
    });

    test("malloc 4096", [](){
        char volatile* p = (char*)malloc(4096);

        p[0] = 1;
        p[1] = 2;
        p[2] = 3;
        printf("p+4096: %p\n", p+4096);
        EXPECT_SEGV(&p[4096], p[4096] = 4);
        free((void*)p);
    });

    test("malloc 4099", [](){
        char volatile* p = (char*)malloc(4099);

        p[0] = 1;
        p[1] = 2;
        p[2] = 3;
        //...
        p[4099] = 4; // Out of bounds, but no segfault because of minimum alignment requirements
        //...
        p[4111] = 5; // ditto
        printf("p+4112: %p\n", p+4112);
        EXPECT_SEGV(&p[4112], p[4112] = 123);
        free((void*)p);
    });

    test("realloc 3 -> 4", [](){
        char* p = (char*)malloc(3);

        p[0] = 'a';
        p[1] = 'b';
        p[2] = 'c';
        // p[3] would be an overflow, if we didn't realloc() first
        char volatile* new_p = (char*)realloc((void*)p, 4);
        // make sure realloc copied the bytes
        assert(new_p[0] == 'a');
        assert(new_p[1] == 'b');
        assert(new_p[2] == 'c');
        new_p[3] = 'd';
        printf("new_p+16: %p\n", new_p+16);
        EXPECT_SEGV(&new_p[16], new_p[16] = 4);
        free((void*)new_p);
    });

    test("realloc 15 -> 17", [](){
        char volatile* p = (char*)malloc(15);

        p[0] = 'a';
        p[1] = 'b';
        p[2] = 'c';
        printf("p+16: %p\n", p+16);
        EXPECT_SEGV(&p[16], p[16] = 'd');
        char volatile* new_p = (char*)realloc((void*)p, 17);

        // in our implementation, p != new_p when offset changes
        // due to alignment requirements
        assert(new_p != p);

        // make sure realloc copied the bytes
        assert(new_p[0] == 'a');
        assert(new_p[1] == 'b');
        assert(new_p[2] == 'c');
        new_p[16] = 'd'; // should work, now!
        //...
        new_p[31] = 'e';
        printf("new_p+32: %p\n", new_p+32);
        EXPECT_SEGV(&new_p[32], new_p[32] = 4);
        free((void*)new_p);
    });

    test("realloc 8192 -> 60", [](){
        char volatile* p = (char*)malloc(8192);

        p[0] = 'a';
        p[1] = 'b';
        p[2] = 'c';
        //...
        p[8191] = 'd';
        printf("p+8192: %p\n", p+8192);
        EXPECT_SEGV(&p[8192], p[8192] = 'd');
        char volatile* new_p = (char*)realloc((void*)p, 60);

        // in our implementation, p != new_p when offset changes
        // due to alignment requirements
        assert(new_p != p);

        // make sure realloc copied the bytes to new area
        assert(new_p[0] == 'a');
        assert(new_p[1] == 'b');
        assert(new_p[2] == 'c');
        //...
        new_p[59] = 'e';
        new_p[60] = 'f'; // Does not overflow due to alignment
        new_p[63] = 'g';
        printf("new_p+64: %p\n", new_p+64);
        EXPECT_SEGV(&new_p[64], new_p[64] = 4);
        free((void*)new_p);
    });

    test("memalign 4096, 12345", [](){
        char volatile* p = (char*)memalign(4096, 12345);

        p[0] = 1;
        p[1] = 2;
        p[2] = 3;
        printf("p+4096: %p\n", p+4096);
        //EXPECT_SEGV(&p[4096], p[4096] = 4);
        free((void*)p);
    });
}

void test_under()
{
    test("malloc 3", [](){
        char volatile* p = (char*)malloc(3);

        p[0] = 1;
        p[1] = 2;
        p[2] = 3;
        printf("p-1: %p\n", p-1);
        EXPECT_SEGV(&p[-1], p[-1] = 123);
        free((void*)p);
    });

    test("malloc 4099", [](){
        char volatile* p = (char*)malloc(4099);

        p[0] = 1;
        p[1] = 2;
        p[2] = 3;
        printf("p-1: %p\n", p-1);
        EXPECT_SEGV(&p[-1], p[-1] = 123);
        free((void*)p);
    });

    test("realloc 8192 -> 60", [](){
        char volatile* p = (char*)malloc(8192);

        p[0] = 'a';
        p[1] = 'b';
        p[2] = 'c';
        //...
        p[8191] = 'd';
        printf("p-1: %p\n", p-1);
        EXPECT_SEGV(&p[-1], p[-1] = 4);

        char volatile* new_p = (char*)realloc((void*)p, 60);

        // make sure realloc copied the bytes to new area
        assert(new_p[0] == 'a');
        assert(new_p[1] == 'b');
        assert(new_p[2] == 'c');
        //...
        new_p[59] = 'e';
        printf("new_p-1: %p\n", new_p-1);
        EXPECT_SEGV(&new_p[-1], new_p[-1] = 4);
        free((void*)new_p);
    });

}

int main(int argc, char ** argv)
{
    // Install SEGV signal handler
    struct sigaction sa;

    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = segfault;
    sigaction(SIGSEGV, &sa, NULL);

    // Test
#if HEAPGUARD_MODE == HEAPGUARD_MODE_OVERFLOW
    test_over();
#else
    test_under();
#endif

    printf("heapguard_test: all tests passed\n");
}
