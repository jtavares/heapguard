# heapguard Overview
`heapguard` is a simple overflow and underflow detector which can be used to
detect and locate suspected out-of-bounds memory accesses to the heap.

`heapguard` hooks the memory manager by overriding library symbols `malloc()`
and friends to allocate memory in such a way to make it possible to detect
overflows and underflows *at the time of offense*. Your application will 
segfault or break at the precise moment an out-of-bounds read or write occurs,
rather than at some arbitrary point in the future when the corrupted memory
is used.

`heapguard` can be configured at compile time to detect either underflows or
overflows, but not both at the same time.

`heapguard` relies heavily on Linux's memory mapping and protection
facilities, which in turn rely on a hardware MPU, to accomplish its task.

`heapguard` is very resource intensive and is intended to be linked only
during debugging.

## Underflow Detection
Underflow detection works by allocating an extra page at the beginning
of the allocation and marking it as PROT_NONE so that seg fault occurs
on first read or write to the -1 position of an array. All requests
are aligned on page boundaries, and begin at the second page.

### Memory Usage
A minimum of 2 virtual pages are allocated for every request. The first
page acts as a guard page, and will not actually be backed by physical
RAM if the accounting data can be fit into the last page of the allocation.

If the accounting data cannot be placed at the end of last page, it will be
placed at the beginning of the guard page, causing it to be backed by a
physical RAM page.

## Overflow Detection
Overflow detection works by allocating an extra page at the end of the
allocation and marking it as PROT_NONE so that seg fault occurs on first
read or write. The user's allocation request is aligned according to
HEAPGUARD_MIN_ALIGNMENT (in the case of malloc()) or as requested via
memalign(), and located at close to the guard page as permitted by said
alignment. This implies that not all overflows can be detected; the overflow
must grow so large so as to exceed the slack in the requested alignment and
cross into the guard page.

### Memory Usage
A minimum of 2 pages are allocated for every request. Accounting data and
user data are stored starting at the first page, if alignment permits. In
the worst case, an alignment of 4096 bytes requires 3 pages (one for the
accounting data, one for the user's allocation, and one for the guard page).
The guard page is never touched, and therefore does not occupy a physical
memory page due to demand paging.

## Alignment
In all cases, the maximum supported user-requested alignment is one page
(`HEAPGUARD_PAGE_SIZE`) and the minimum supported user-requested alignment
is `HEAPGUARD_MIN_ALIGNMENT` (defined in `heapguard.h`).

# Usage

## Linking
`heapguard.c` and `heapguard.h` are meant to be included in (linked against)
your application. Once linked against your application, `heapguard` will
override symbols `malloc()`, `free()`, and friends, to allocate memory in
the ways described above.

## Configuration
See `heapguard.h` for configuration parameters.

## Caveats

### Memory Map Usage
Note that `heapguard` makes aggressive use of the kernel's memory mapping
facilities. You may need to increase your kernel's maximum VM mapping count
from its default. For example:

```console
sudo sysctl -w vm.max_map_count=999999
```

### Physical Memory Usage
`heapguard` thwarts the memory manager's best efforts to allocate memory
efficiently. The overhead on large allocations is negligible, but small
allocations can have enormous amplification factors. As such, you may find
yourself running out of RAM very quickly in constrained environments. In these
cases, consider using a smaller data set, or a subset of your application,
during test.

### Alternatives
Better alternatives to `heapguard` exist, including compiler-controlled
instrumentations such as clang's `AddressSanitizer`, or the `valgrind` run-
time library. You should probably use those tools before `heapguard`, as they
are harder/better/faster/stronger.

`heapguard` was developed to diagnose an out-of-bounds memory condition in a
small embedded software program running on a platform where access to these
tools was not practical due to memory limitations, as well asthe age of the OS
and toolchain. If you find yourself in this situation, maybe `heapguard` will
be useful to you, too.

# Unit Tests
To unit test `heapguard` on your hardware:

1. choose overflow detection in heapguard.h
2. run `make && ./heapguard_test` and confirm success
3. repeat steps 1 and 2 for underflow detection

(This process obviously needs to be improved)
