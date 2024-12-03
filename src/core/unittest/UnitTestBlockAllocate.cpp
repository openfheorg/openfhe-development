//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
  This code exercises the block allocator utility of the OpenFHE lattice encryption library.
 */
#if 0
// #define PROFILE    //define this is we want profiling output and statistics
    #include <assert.h>
    #include <stdio.h>

    #include <iostream>
    #include <new>

    #include "gtest/gtest.h"

    #include "math/math-hal.h"
    #include "utils/blockAllocator/blockAllocator.h"
    #include "utils/debug.h"
    #include "utils/inttypes.h"
    #include "utils/utilities.h"

using namespace lbcrypto;

class UnitTestBinInt : public ::testing::Test {
protected:
    virtual void SetUp() {}

    virtual void TearDown() {
        // Code here will be called immediately after each test
        // (right before the destructor).
    }
};

/************************************************/
/*  TESTING METHODS OF Allocator CLASS    */
/************************************************/

    #define BLOCKSIZE 8192

typedef char Block[BLOCKSIZE];  // define Block as char array of size BLOCKSIZE

class MyClass {
    DECLARE_ALLOCATOR
    // remaining class definition
};
IMPLEMENT_ALLOCATOR(MyClass, 0, 0)

// Heap blocks mode unlimited with BLOCKSIZE byte blocks
Allocator allocatorHeapBlocks(BLOCKSIZE);

// Heap pool mode with 20, BLOCKSIZE byte blocks
Allocator allocatorHeapPool(BLOCKSIZE, 20);

// Static pool mode with 20, BLOCKSIZE byte blocks
char staticMemoryPool[BLOCKSIZE * 20];
Allocator allocatorStaticPool(BLOCKSIZE, 20, staticMemoryPool);

// Static pool mode with 20 MyClass sized blocks using template
AllocatorPool<MyClass, 20> allocatorStaticPool2;

// Benchmark allocators
    #ifdef __ANDROID__
static const int MAX_BLOCKS = 512;  // reduce size of pool for limited memory
    #else
static const int MAX_BLOCKS = 4096;
    #endif
static const int MAX_BLOCK_SIZE = 8196;
char* memoryPtrs[MAX_BLOCKS];
char* memoryPtrs2[MAX_BLOCKS];
AllocatorPool<char[MAX_BLOCK_SIZE], MAX_BLOCKS * 2> allocatorStaticPoolBenchmark;
Allocator allocatorHeapBlocksBenchmark(MAX_BLOCK_SIZE);

static void out_of_memory() {
    // new-handler function called by Allocator when pool is out of memory

    std::cerr << "out_of_memory in block allocator";
    #if 0
  std::bad_alloc exception;
  throw(exception);
    #else
    assert(0);
    #endif
}

typedef char* (*AllocFunc)(int size);
typedef void (*DeallocFunc)(char* ptr);
void Benchmark(const char* name, AllocFunc allocFunc, DeallocFunc deallocFunc);
char* AllocHeap(int size);
void DeallocHeap(char* ptr);
char* AllocStaticPool(int size);
void DeallocStaticPool(char* ptr);
char* AllocHeapBlocks(int size);
void DeallocHeapBlocks(char* ptr);

//------------------------------------------------------------------------------
// AllocHeap
//------------------------------------------------------------------------------
char* AllocHeap(int size) {
    return new char[size];
}

//------------------------------------------------------------------------------
// DeallocHeap
//------------------------------------------------------------------------------
void DeallocHeap(char* ptr) {
    delete[] ptr;
}

//------------------------------------------------------------------------------
// AllocStaticPool
//------------------------------------------------------------------------------
char* AllocStaticPool(int size) {
    return reinterpret_cast<char*>(allocatorStaticPoolBenchmark.Allocate(size));
}

//------------------------------------------------------------------------------
// DeallocStaticPool
//------------------------------------------------------------------------------
void DeallocStaticPool(char* ptr) {
    allocatorStaticPoolBenchmark.Deallocate(ptr);
}

//------------------------------------------------------------------------------
// AllocHeapBlocks
//------------------------------------------------------------------------------
char* AllocHeapBlocks(int size) {
    return reinterpret_cast<char*>(allocatorHeapBlocksBenchmark.Allocate(size));
}

//------------------------------------------------------------------------------
// DeallocHeapBlocks
//------------------------------------------------------------------------------
void DeallocHeapBlocks(char* ptr) {
    allocatorHeapBlocksBenchmark.Deallocate(ptr);
}

//------------------------------------------------------------------------------
// Benchmark
//------------------------------------------------------------------------------
void Benchmark(const char* name, AllocFunc allocFunc, DeallocFunc deallocFunc) {
    TimeVar t1, t_total;

    float ElapsedMicroseconds, TotalElapsedMicroseconds = {0};
    // Allocate MAX_BLOCKS blocks MAX_BLOCK_SIZE / 2 sized blocks

    TIC(t_total);
    TIC(t1);
    for (int i = 0; i < MAX_BLOCKS; i++)
        memoryPtrs[i] = allocFunc(MAX_BLOCK_SIZE / 2);
    ElapsedMicroseconds = TOC_US(t1);

    PROFILELOG(name << " 1 allocate time: " << ElapsedMicroseconds);
    TotalElapsedMicroseconds += ElapsedMicroseconds;

    // Deallocate MAX_BLOCKS blocks (every other one)
    TIC(t1);
    for (int i = 0; i < MAX_BLOCKS; i += 2)
        deallocFunc(memoryPtrs[i]);
    ElapsedMicroseconds = TOC_US(t1);
    PROFILELOG(name << " 1 deallocate time: " << ElapsedMicroseconds);
    TotalElapsedMicroseconds += ElapsedMicroseconds;

    // Allocate MAX_BLOCKS blocks MAX_BLOCK_SIZE sized blocks
    TIC(t1);
    for (int i = 0; i < MAX_BLOCKS; i++)
        memoryPtrs2[i] = allocFunc(MAX_BLOCK_SIZE);
    ElapsedMicroseconds = TOC_US(t1);
    PROFILELOG(name << " 2 allocate time: " << ElapsedMicroseconds);
    TotalElapsedMicroseconds += ElapsedMicroseconds;

    // Deallocate MAX_BLOCKS blocks (every other one)
    TIC(t1);
    for (int i = 1; i < MAX_BLOCKS; i += 2)
        deallocFunc(memoryPtrs[i]);
    ElapsedMicroseconds = TOC_US(t1);
    PROFILELOG(name << " 2 deallocate time: " << ElapsedMicroseconds);
    TotalElapsedMicroseconds += ElapsedMicroseconds;

    // Deallocate MAX_BLOCKS blocks
    TIC(t1);
    for (int i = MAX_BLOCKS - 1; i >= 0; i--)
        deallocFunc(memoryPtrs2[i]);
    ElapsedMicroseconds = TOC_US(t1);
    PROFILELOG(name << " 2 deallocate time: " << ElapsedMicroseconds);
    TotalElapsedMicroseconds += ElapsedMicroseconds;

    PROFILELOG(name << "           TOTAL TIME: " << TotalElapsedMicroseconds);
    (void)TotalElapsedMicroseconds;  // Avoid unused variable warning
}

TEST(UTBlockAllocate, block_allocator_test) {
    std::set_new_handler(out_of_memory);

    // Allocate MyClass using fixed block allocator
    MyClass* myClass = new MyClass();
    delete myClass;

    // Allocate BLOCKSIZE bytes in fixed block allocator, then deallocate
    char* memory1 = reinterpret_cast<char*>(allocatorHeapBlocks.Allocate(BLOCKSIZE));
    allocatorHeapBlocks.Deallocate(memory1);

    char* memory2 = reinterpret_cast<char*>(allocatorHeapBlocks.Allocate(BLOCKSIZE));
    allocatorHeapBlocks.Deallocate(memory2);

    char* memory3 = reinterpret_cast<char*>(allocatorHeapPool.Allocate(BLOCKSIZE));
    allocatorHeapPool.Deallocate(memory3);

    char* memory4 = reinterpret_cast<char*>(allocatorStaticPool.Allocate(BLOCKSIZE));
    allocatorStaticPool.Deallocate(memory4);

    char* memory5 = reinterpret_cast<char*>(allocatorStaticPool2.Allocate(sizeof(MyClass)));
    allocatorStaticPool2.Deallocate(memory5);

    Benchmark("Heap (Run 1)", AllocHeap, DeallocHeap);
    Benchmark("Heap (Run 2)", AllocHeap, DeallocHeap);
    Benchmark("Heap (Run 3)", AllocHeap, DeallocHeap);
    Benchmark("Static Pool (Run 1)", AllocStaticPool, DeallocStaticPool);
    Benchmark("Static Pool (Run 2)", AllocStaticPool, DeallocStaticPool);
    Benchmark("Static Pool (Run 3)", AllocStaticPool, DeallocStaticPool);
    Benchmark("Heap Blocks (Run 1)", AllocHeapBlocks, DeallocHeapBlocks);
    Benchmark("Heap Blocks (Run 2)", AllocHeapBlocks, DeallocHeapBlocks);
    Benchmark("Heap Blocks (Run 3)", AllocHeapBlocks, DeallocHeapBlocks);
}
#endif
