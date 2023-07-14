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
  This code exercises the block allocator utility of the OpenFHE lattice encryption library
 */

// #define PROFILE  //uncomment to print out elapsed time

#include <assert.h>
#include <stdio.h>

#include <iostream>
#include <new>

#include "gtest/gtest.h"

#include "math/math-hal.h"
#include "utils/debug.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"

#include "utils/blockAllocator/xlist.h"
#include "utils/blockAllocator/xmap.h"
#include "utils/blockAllocator/xqueue.h"
#include "utils/blockAllocator/xset.h"
#include "utils/blockAllocator/xsstream.h"
#include "utils/blockAllocator/xstring.h"
#include "utils/blockAllocator/xvector.h"

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

// On VisualStudio, to disable the debug heap for faster performance when using
// the debugger use this option:
// Debugging > Environment _NO_DEBUG_HEAP=1

// static int MAX_BENCHMARK = 10000;
static int MAX_BENCHMARK = 1024;

typedef void (*TestFunc)();
void ListGlobalHeapTest();
void MapGlobalHeapTest();
void StringGlobalHeapTest();
void ListFixedBlockTest();
void MapFixedBlockTest();
void StringFixedBlockTest();
void Benchmark(const char* name, TestFunc testFunc);

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

//------------------------------------------------------------------------------
// MapGlobalHeapTest
//------------------------------------------------------------------------------
void MapGlobalHeapTest() {
    std::map<int, char> myMap;
    for (int i = 0; i < MAX_BENCHMARK; i++)
        myMap[i] = 'a';
    myMap.clear();
}

//------------------------------------------------------------------------------
// MapFixedBlockTest
//------------------------------------------------------------------------------
void MapFixedBlockTest() {
    xmap<int, char> myMap;
    for (int i = 0; i < MAX_BENCHMARK; i++)
        myMap[i] = 'a';
    myMap.clear();
}

//------------------------------------------------------------------------------
// ListGlobalHeapTest
//------------------------------------------------------------------------------
void ListGlobalHeapTest() {
    std::list<int> myList;
    for (int i = 0; i < MAX_BENCHMARK; i++)
        myList.push_back(123);
    myList.clear();
}

//------------------------------------------------------------------------------
// ListFixedBlockTest
//------------------------------------------------------------------------------
void ListFixedBlockTest() {
    xlist<int> myList;
    for (int i = 0; i < MAX_BENCHMARK; i++)
        myList.push_back(123);
    myList.clear();
}

//------------------------------------------------------------------------------
// VectorGlobalHeapTest
//------------------------------------------------------------------------------
void VectorGlobalHeapTest() {
    std::vector<int> myVector;
    for (int i = 0; i < MAX_BENCHMARK; i++)
        myVector.push_back(123);
    myVector.clear();
}

//------------------------------------------------------------------------------
// VectorFixedBlockTest
//------------------------------------------------------------------------------
void VectorFixedBlockTest() {
    xvector<int> myVector;
    for (int i = 0; i < MAX_BENCHMARK; i++)
        myVector.push_back(123);
    myVector.clear();
}

//------------------------------------------------------------------------------
// StringGlobalHeapTest
//------------------------------------------------------------------------------
void StringGlobalHeapTest() {
    std::list<std::string> myList;
    for (int i = 0; i < MAX_BENCHMARK; i++) {
        std::string myString("benchmark");
        myString +=
            "benchmark test benchmark test benchmark test benchmark test benchmark "
            "test benchmark test benchmark test "
            "benchmark test benchmark test benchmark test benchmark test benchmark "
            "test benchmark test benchmark test";
        myList.push_back(myString);
    }
    myList.clear();
}

//------------------------------------------------------------------------------
// StringFixedBlockTest
//------------------------------------------------------------------------------
void StringFixedBlockTest() {
    xlist<xstring> myList;
    for (int i = 0; i < MAX_BENCHMARK; i++) {
        xstring myString("benchmark");
        myString +=
            "benchmark test benchmark test benchmark test benchmark test benchmark "
            "test benchmark test benchmark test "
            "benchmark test benchmark test benchmark test benchmark test benchmark "
            "test benchmark test benchmark test";
        myList.push_back(myString);
    }
    myList.clear();
}

//------------------------------------------------------------------------------
// Benchmark
//------------------------------------------------------------------------------
void Benchmark(const char* name, TestFunc testFunc) {
    TimeVar t1;

    // float ElapsedMicroseconds = {0};
    // Allocate MAX_BLOCKS blocks MAX_BLOCK_SIZE / 2 sized blocks

    TIC(t1);
    // Call test function
    testFunc();
    // ElapsedMicroseconds = TOC_US(t1);

    // PROFILELOG( name << " Elapsed time: " << ElapsedMicroseconds);
    PROFILELOG(name << " Elapsed time: " << TOC_US(t1));
}

TEST(UTBlockAllocate, stl_test) {
    std::set_new_handler(out_of_memory);

    xlist<int> myList;
    myList.push_back(123);

    xmap<char, int> myMap;
    myMap['a'] = 10;

    xqueue<int> myQueue;
    myQueue.push(123);

    xset<xstring> mySet;
    mySet.insert("hello");
    mySet.insert("world");

    xstringstream myStringStream;
    myStringStream << "hello world " << 2016 << std::ends;

    xwstringstream myWStringStream;
    myWStringStream << L"hello world " << 2016 << std::ends;

    xstring myString("hello world");

    Benchmark("std::list Global Heap (Run 1)", ListGlobalHeapTest);
    Benchmark("std::list Global Heap (Run 2)", ListGlobalHeapTest);
    Benchmark("std::list Global Heap (Run 3)", ListGlobalHeapTest);

    Benchmark("xlist Fixed Block (Run 1)", ListFixedBlockTest);
    Benchmark("xlist Fixed Block (Run 2)", ListFixedBlockTest);
    Benchmark("xlist Fixed Block (Run 3)", ListFixedBlockTest);

    Benchmark("std::map Global Heap (Run 1)", MapGlobalHeapTest);
    Benchmark("std::map Global Heap (Run 2)", MapGlobalHeapTest);
    Benchmark("std::map Global Heap (Run 3)", MapGlobalHeapTest);

    Benchmark("xmap Fixed Block (Run 1)", MapFixedBlockTest);
    Benchmark("xmap Fixed Block (Run 2)", MapFixedBlockTest);
    Benchmark("xmap Fixed Block (Run 3)", MapFixedBlockTest);

    Benchmark("std::vector Global Heap (Run 1)", VectorGlobalHeapTest);
    Benchmark("std::vector Global Heap (Run 2)", VectorGlobalHeapTest);
    Benchmark("std::vector Global Heap (Run 3)", VectorGlobalHeapTest);

    Benchmark("xvector Fixed Block (Run 1)", VectorFixedBlockTest);
    Benchmark("xvector Fixed Block (Run 2)", VectorFixedBlockTest);
    Benchmark("xvector Fixed Block (Run 3)", VectorFixedBlockTest);

    Benchmark("std::string Global Heap (Run 1)", StringGlobalHeapTest);
    Benchmark("std::string Global Heap (Run 2)", StringGlobalHeapTest);
    Benchmark("std::string Global Heap (Run 3)", StringGlobalHeapTest);

    Benchmark("xstring Fixed Block (Run 1)", StringFixedBlockTest);
    Benchmark("xstring Fixed Block (Run 2)", StringFixedBlockTest);
    Benchmark("xstring Fixed Block (Run 3)", StringFixedBlockTest);

#ifdef PROFILE
    xalloc_stats();
#endif
    return;
}
