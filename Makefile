CFLAGS=-g -O3
CXXFLAGS=-g -std=c++11 -O3

LDFLAGS=

heapguard_test: heapguard.o heapguard_test.o crc32.o
	$(CXX) $^ $(LDFLAGS) -o $@ 

crc32.o: crc32.c

heapguard.o: heapguard.c heapguard.h

heapguard_test.o: heapguard_test.cpp heapguard.h

clean:
	rm -f *.o heapguard_test

