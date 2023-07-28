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

// #define PROFILE  // define if we want elapsed time output and pool statistics
#include <assert.h>
#include <stdio.h>

#include <iostream>
#include <new>

#include "gtest/gtest.h"

#include "math/math-hal.h"
#include "utils/blockAllocator/xallocator.h"
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

class MyClass {
    XALLOCATOR
    // remaining class definition
};

class MyClassStatic {
public:
    MyClassStatic() {
        memory = xmalloc(100);
    }
    ~MyClassStatic() {
        xfree(memory);
    }

private:
    void* memory;
};
static MyClassStatic myClassStatic;

static void out_of_memory() {
    // new-handler function called by Allocator when pool is out of memory
    xalloc_stats();
#if 0
  std::bad_alloc exception;
  throw(exception);
#else
    assert(0);
#endif
}

static const int MAX_BLOCK_SIZE = 4000;
// static const int MAX_ALLOCATIONS = 10000;
#ifdef __ANDROID__
static const int MAX_ALLOCATIONS = 512;  // reduce size of pool for limited memory
#else
static const int MAX_ALLOCATIONS = 2048;
#endif
static void* memoryPtrs[MAX_ALLOCATIONS];
static void* memoryPtrs2[MAX_ALLOCATIONS];

typedef void* (*AllocFunc)(size_t size);
typedef void (*DeallocFunc)(void* ptr);
void Benchmark(const char* name, AllocFunc allocFunc, DeallocFunc deallocFunc);

//------------------------------------------------------------------------------
// Benchmark
//------------------------------------------------------------------------------
void Benchmark(const char* name, AllocFunc allocFunc, DeallocFunc deallocFunc) {
    TimeVar t1, t_total;

    float ElapsedMicroseconds = 0;
#if defined(__clang__)
    [[maybe_unused]] float TotalElapsedMicroseconds = 0;
#else
    float TotalElapsedMicroseconds = 0;
#endif
    // Allocate MAX_ALLOCATIONS blocks MAX_BLOCK_SIZE / 2 sized blocks
    TIC(t_total);
    TIC(t1);
    for (int i = 0; i < MAX_ALLOCATIONS; i++)
        memoryPtrs[i] = allocFunc(MAX_BLOCK_SIZE / 2);
    ElapsedMicroseconds = TOC_US(t1);

    PROFILELOG(name << " 1 allocate time: " << ElapsedMicroseconds);
    TotalElapsedMicroseconds += ElapsedMicroseconds;

    // Deallocate MAX_ALLOCATIONS blocks (every other one)
    TIC(t1);
    for (int i = 0; i < MAX_ALLOCATIONS; i += 2)
        deallocFunc(memoryPtrs[i]);
    ElapsedMicroseconds = TOC_US(t1);
    PROFILELOG(name << " 1 deallocate time: " << ElapsedMicroseconds);
    TotalElapsedMicroseconds += ElapsedMicroseconds;

    // Allocate MAX_ALLOCATIONS blocks MAX_BLOCK_SIZE sized blocks
    TIC(t1);
    for (int i = 0; i < MAX_ALLOCATIONS; i++)
        memoryPtrs2[i] = allocFunc(MAX_BLOCK_SIZE);
    ElapsedMicroseconds = TOC_US(t1);
    PROFILELOG(name << " 2 allocate time: " << ElapsedMicroseconds);
    TotalElapsedMicroseconds += ElapsedMicroseconds;

    // Deallocate MAX_ALLOCATIONS blocks (every other one)
    TIC(t1);
    for (int i = 1; i < MAX_ALLOCATIONS; i += 2)
        deallocFunc(memoryPtrs[i]);
    ElapsedMicroseconds = TOC_US(t1);
    PROFILELOG(name << " 2 deallocate time: " << ElapsedMicroseconds);
    TotalElapsedMicroseconds += ElapsedMicroseconds;

    // Deallocate MAX_ALLOCATIONS blocks
    TIC(t1);
    for (int i = MAX_ALLOCATIONS - 1; i >= 0; i--)
        deallocFunc(memoryPtrs2[i]);
    ElapsedMicroseconds = TOC_US(t1);
    PROFILELOG(name << " 2 deallocate time: " << ElapsedMicroseconds);
    TotalElapsedMicroseconds += ElapsedMicroseconds;

    PROFILELOG(name << "           TOTAL TIME: " << TotalElapsedMicroseconds);
}

TEST(UTBlockAllocate, xalloc_test) {
    srand(1);
    std::set_new_handler(out_of_memory);
    // If AUTOMATIC_XALLOCATOR_INIT_DESTROY defined then XallocInitDestroy() will
    // call xalloc_init() automatically before main().
    // xalloc_init();

    // Allocate MyClass using fixed block allocator
    MyClass* myClass = new MyClass();
    delete myClass;

    void* memory1 = xmalloc(100);
    xfree(memory1);

    char* memory2 = reinterpret_cast<char*>(xmalloc(24));
    strcpy(memory2, "TEST STRING");  // NOLINT
    memory2 = reinterpret_cast<char*>(xrealloc(memory2, 124));
    xfree(memory2);

    // Benchmark will cause out_of_memory to be called if STATIC_POOLS defined
    Benchmark("malloc/free (Run 1)", malloc, free);
    Benchmark("malloc/free (Run 2)", malloc, free);
    Benchmark("malloc/free (Run 3)", malloc, free);
    Benchmark("xmalloc/xfree (Run 1)", xmalloc, xfree);
    Benchmark("xmalloc/xfree (Run 2)", xmalloc, xfree);
    Benchmark("xmalloc/xfree (Run 3)", xmalloc, xfree);

#ifdef PROFILE
    xalloc_stats();
#endif

    // If AUTOMATIC_XALLOCATOR_INIT_DESTROY is defined, ~XallocDestroy() will call
    // xalloc_destroy() automatically. Never call xalloc_destroy() manually except
    // if using xallocator in a C-only application.
    // xalloc_destroy();
}
