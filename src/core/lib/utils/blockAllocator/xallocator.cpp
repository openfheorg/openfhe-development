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
  See http://www.codeproject.com/Articles/1089905/A-Custom-STL-std-allocator-Replacement-Improves-Performance-
 */

#include <cassert>
#include <cstring>  // for memcpy consider changing to copy
#include <iostream>
#include <map>
#include <mutex>
#include <thread>

#include "utils/blockAllocator/blockAllocator.h"
#include "utils/blockAllocator/xallocator.h"
#include "utils/exception.h"

static std::mutex xalloc_mutex;
static bool _xallocInitialized = false;
static std::map<size_t, Allocator*> _allocators;

// #define STATIC_POOLS
#ifdef STATIC_POOLS

// Update this section, xalloc_init() and xalloc_destroy() as needed if you want to use static memory pools.
// Add add_compile_options(-mcmodel=medium) to CMakeLists.txt to avoid relocation truncated to fit: R_X86_64_PC32 against `.bss' error

#define DEFAULT_BLOCK_COUNT 1024
using _pool8 = AllocatorPool<char[sizeof(Allocator*) + (1 << 3)], DEFAULT_BLOCK_COUNT>;
using _pool16 = AllocatorPool<char[sizeof(Allocator*) + (1 << 4)], DEFAULT_BLOCK_COUNT>;
using _pool32 = AllocatorPool<char[sizeof(Allocator*) + (1 << 5)], DEFAULT_BLOCK_COUNT>;
using _pool64 = AllocatorPool<char[sizeof(Allocator*) + (1 << 6)], DEFAULT_BLOCK_COUNT>;
using _pool128 = AllocatorPool<char[sizeof(Allocator*) + (1 << 7)], DEFAULT_BLOCK_COUNT>;
using _pool256 = AllocatorPool<char[sizeof(Allocator*) + (1 << 8)], DEFAULT_BLOCK_COUNT>;
using _pool512 = AllocatorPool<char[sizeof(Allocator*) + (1 << 9)], DEFAULT_BLOCK_COUNT>;
using _pool1k = AllocatorPool<char[sizeof(Allocator*) + (1 << 10)], DEFAULT_BLOCK_COUNT>;
using _pool2k = AllocatorPool<char[sizeof(Allocator*) + (1 << 11)], DEFAULT_BLOCK_COUNT>;
using _pool4k = AllocatorPool<char[sizeof(Allocator*) + (1 << 12)], DEFAULT_BLOCK_COUNT>;
using _pool8k = AllocatorPool<char[sizeof(Allocator*) + (1 << 13)], DEFAULT_BLOCK_COUNT>;
using _pool16k = AllocatorPool<char[sizeof(Allocator*) + (1 << 14)], DEFAULT_BLOCK_COUNT>;
using _pool32k = AllocatorPool<char[sizeof(Allocator*) + (1 << 15)], 16000>;
using _pool64k = AllocatorPool<char[sizeof(Allocator*) + (1 << 16)], 65536>;
using _pool128k = AllocatorPool<char[sizeof(Allocator*) + (1 << 17)], 65536>;
using _pool256k = AllocatorPool<char[sizeof(Allocator*) + (1 << 18)], DEFAULT_BLOCK_COUNT>;
using _pool512k = AllocatorPool<char[sizeof(Allocator*) + (1 << 19)], DEFAULT_BLOCK_COUNT>;
using _pool1M = AllocatorPool<char[sizeof(Allocator*) + (1 << 20)], DEFAULT_BLOCK_COUNT>;
using _pool2M = AllocatorPool<char[sizeof(Allocator*) + (1 << 21)], DEFAULT_BLOCK_COUNT>;

// Create static storage for each static allocator instance
static char* _allocator8[sizeof(_pool8)];
static char* _allocator16[sizeof(_pool16)];
static char* _allocator32[sizeof(_pool32)];
static char* _allocator64[sizeof(_pool64)];
static char* _allocator128[sizeof(_pool128)];
static char* _allocator256[sizeof(_pool256)];
static char* _allocator512[sizeof(_pool512)];
static char* _allocator1k[sizeof(_pool1k)];
static char* _allocator2k[sizeof(_pool2k)];
static char* _allocator4k[sizeof(_pool4k)];
static char* _allocator8k[sizeof(_pool8k)];
static char* _allocator16k[sizeof(_pool16k)];
static char* _allocator32k[sizeof(_pool32k)];
static char* _allocator64k[sizeof(_pool64k)];
static char* _allocator128k[sizeof(_pool128k)];
static char* _allocator256k[sizeof(_pool256k)];
static char* _allocator512k[sizeof(_pool512k)];
static char* _allocator1M[sizeof(_pool1M)];
// static char* _allocator2M[sizeof(_pool2M)];

#endif  // STATIC_POOLS

static XallocInitDestroy xallocInitDestroy;

// For C++ applications, must define AUTOMATIC_XALLOCATOR_INIT_DESTROY to
// correctly ensure allocators are initialized before any static user C++
// construtor/destructor executes which might call into the xallocator API.
// This feature costs 1-byte of RAM per C++ translation unit. This feature
// can be disabled only under the following circumstances:
//
// 1) The xallocator is only used within C files.
// 2) STATIC_POOLS is undefined and the application never exits main (e.g.
// an embedded system).
//
// In either of the two cases above, call xalloc_init() in main at startup,
// and xalloc_destroy() before main exits. In all other situations
// XallocInitDestroy must be used to call xalloc_init() and xalloc_destroy().
#ifdef AUTOMATIC_XALLOCATOR_INIT_DESTROY
uint32_t XallocInitDestroy::refCount = 0;
XallocInitDestroy::XallocInitDestroy() {
    // Track how many static instances of XallocInitDestroy are created
    if (refCount++ == 0)
        xalloc_init();
}

XallocInitDestroy::~XallocInitDestroy() {
    // Last static instance to have destructor called?
    if (--refCount == 0)
        xalloc_destroy();
}
#endif  // AUTOMATIC_XALLOCATOR_INIT_DESTROY

/// Create the xallocator lock. Call only one time at startup.
/// note for C++11 we do not need to control the lock with the lock_* functions.
/// instead we control the next exection function in the code.
static void lock_init() {
    _xallocInitialized = true;
}

/// Destroy the xallocator lock.
static void lock_destroy() {
#if 0
    // DeleteCriticalSection(&_criticalSection);
    irc = pthread_mutex_destroy(&xalloc_mutex);
#endif
    _xallocInitialized = false;
}

/// Lock the shared resource.
static inline void lock_get() {
    if (_xallocInitialized == false)
        return;
#if 0
    // Acquire the mutex to access the shared resource
    pthread_mutex_lock(&xalloc_mutex);
    // EnterCriticalSection(&_criticalSection);
#endif
}

/// Unlock the shared resource.
static inline void lock_release() {
    if (_xallocInitialized == false)
        return;
#if 0
    // Release the mutex  and release the access to shared resource
    pthread_mutex_unlock(&xalloc_mutex);
    // LeaveCriticalSection(&_criticalSection);
#endif
}

/// Stored a pointer to the allocator instance within the block region.
///  @param[in] block - a pointer to the raw memory block.
///  @param[in] size - the client requested size of the memory block.
///  @return  A pointer to the client's address within the raw memory block.
static inline void* set_block_allocator(void* block, Allocator* allocator) {
    // Cast the raw block memory to a Allocator pointer
    // Write the size into the memory block
    // Advance the pointer past the Allocator* block size and return a pointer to
    // the client's memory region
    Allocator** pAllocatorInBlock = static_cast<Allocator**>(block);
    *pAllocatorInBlock = allocator;
    return ++pAllocatorInBlock;
}

/// Gets the size of the memory block stored within the block.
///  @param[in] block - a pointer to the client's memory block.
///  @return  The original allocator instance stored in the memory block.
static inline Allocator* get_block_allocator(void* block) {
    // Cast the client memory to a Allocator pointer
    // Back up one Allocator* position to get the stored allocator instance
    // Return the allocator instance stored within the memory block
    Allocator** pAllocatorInBlock = static_cast<Allocator**>(block);
    --pAllocatorInBlock;
    return *pAllocatorInBlock;
}

/// Returns the raw memory block pointer given a client memory pointer.
///  @param[in] block - a pointer to the client memory block.
///  @return  A pointer to the original raw memory block address.
static inline void* get_block_ptr(void* block) {
    // Cast the client memory to a Allocator* pointer
    // Back up one Allocator* position and return the original raw memory block
    // pointer
    Allocator** pAllocatorInBlock = static_cast<Allocator**>(block);
    return --pAllocatorInBlock;
}

/// This function must be called exactly one time *before* any other xallocator
/// API is called. XallocInitDestroy constructor calls this function automatically.
void xalloc_init() {
    lock_init();

#ifdef STATIC_POOLS
    // For STATIC_POOLS mode, the allocators must be initialized before any other
    // static user class constructor is run. Therefore, use placement new to
    // initialize each allocator into the previously reserved static memory locations.

    new (&_allocator8) _pool8;
    new (&_allocator16) _pool16;
    new (&_allocator32) _pool32;
    new (&_allocator64) _pool64;
    new (&_allocator128) _pool128;
    new (&_allocator256) _pool256;
    new (&_allocator512) _pool512;
    new (&_allocator1k) _pool1k;
    new (&_allocator2k) _pool2k;
    new (&_allocator4k) _pool4k;
    new (&_allocator8k) _pool8k;
    new (&_allocator16k) _pool16k;
    new (&_allocator32k) _pool32k;
    new (&_allocator64k) _pool64k;
    new (&_allocator128k) _pool128k;
    new (&_allocator256k) _pool256k;
    new (&_allocator512k) _pool512k;
    new (&_allocator1M) _pool1M;
//    new (&_allocator2M) _pool2M;

    _allocators = { {sizeof(Allocator*) + (1 << 3), reinterpret_cast<Allocator*>(&_allocator8)},
                    {sizeof(Allocator*) + (1 << 4), reinterpret_cast<Allocator*>(&_allocator16)},
                    {sizeof(Allocator*) + (1 << 5), reinterpret_cast<Allocator*>(&_allocator32)},
                    {sizeof(Allocator*) + (1 << 6), reinterpret_cast<Allocator*>(&_allocator64)},
                    {sizeof(Allocator*) + (1 << 7), reinterpret_cast<Allocator*>(&_allocator128)},
                    {sizeof(Allocator*) + (1 << 8), reinterpret_cast<Allocator*>(&_allocator256)},
                    {sizeof(Allocator*) + (1 << 9), reinterpret_cast<Allocator*>(&_allocator512)},
                    {sizeof(Allocator*) + (1 << 10), reinterpret_cast<Allocator*>(&_allocator1k)},
                    {sizeof(Allocator*) + (1 << 11), reinterpret_cast<Allocator*>(&_allocator2k)},
                    {sizeof(Allocator*) + (1 << 12), reinterpret_cast<Allocator*>(&_allocator4k)},
                    {sizeof(Allocator*) + (1 << 13), reinterpret_cast<Allocator*>(&_allocator8k)},
                    {sizeof(Allocator*) + (1 << 14), reinterpret_cast<Allocator*>(&_allocator16k)},
                    {sizeof(Allocator*) + (1 << 15), reinterpret_cast<Allocator*>(&_allocator32k)},
                    {sizeof(Allocator*) + (1 << 16), reinterpret_cast<Allocator*>(&_allocator64k)},
                    {sizeof(Allocator*) + (1 << 17), reinterpret_cast<Allocator*>(&_allocator128k)},
                    {sizeof(Allocator*) + (1 << 18), reinterpret_cast<Allocator*>(&_allocator256k)},
                    {sizeof(Allocator*) + (1 << 19), reinterpret_cast<Allocator*>(&_allocator512k)},
                    {sizeof(Allocator*) + (1 << 20), reinterpret_cast<Allocator*>(&_allocator1M)}
//                    {sizeof(Allocator*) + (1 << 21), reinterpret_cast<Allocator*>(&_allocator2M)}
    };
#else
    for (size_t b = 3; b < 21; ++b) {
        size_t blockSize = sizeof(Allocator*) + (1 << b);
        _allocators[blockSize] = new Allocator(blockSize);
    }
#endif
}

/// Called one time when the application exits to cleanup any allocated memory.
/// ~XallocInitDestroy destructor calls this function automatically.
void xalloc_destroy() {
    lock_get();
    std::unique_lock<std::mutex> lock(xalloc_mutex);
    {
        for (auto& [k, a] : _allocators) {
#ifdef STATIC_POOLS
            a->~Allocator();
#else
            delete a;
#endif
            a = nullptr;
        }
        _allocators.clear();
    }
    lock_release();
    lock_destroy();
}

/// Get an Allocator instance based upon the client's requested block size.
/// If a Allocator instance is not currently available to handle the size,
///  then a new Allocator instance is create.
///  @param[in] size - the client's requested block size.
///  @return An Allocator instance that handles blocks of the requested size.
Allocator* xallocator_get_allocator(size_t size) {
    size_t blockSize = size + sizeof(Allocator*);
    auto it = _allocators.lower_bound(blockSize);
    if (it != _allocators.end())
        return it->second;
    OPENFHE_THROW("Exceeded max block size");
}

/// Allocates a memory block of the requested size. The blocks are created from
/// the fixed block allocators.
///  @param[in] size - the client requested size of the block.
///  @return  A pointer to the client's memory block.
void* xmalloc(size_t size) {
    Allocator* allocator;
    void* blockMemoryPtr;
    lock_get();
    std::unique_lock<std::mutex> lock(xalloc_mutex);
    {
        // Allocate a raw memory block
        allocator      = xallocator_get_allocator(size);
        blockMemoryPtr = allocator->Allocate(sizeof(Allocator*) + size);
    }
    lock_release();

    // Set the block Allocator* within the raw memory block region
    return set_block_allocator(blockMemoryPtr, allocator);
}

/// Frees a memory block previously allocated with xalloc. The blocks are
/// returned to the fixed block allocator that originally created it.
///  @param[in] ptr - a pointer to a block created with xalloc.
void xfree(void* ptr) {
    if (!ptr)
        return;

    // Extract the original allocator instance from the caller's block pointer
    Allocator* allocator = get_block_allocator(ptr);

    // Convert the client pointer into the original raw block pointer
    void* blockPtr = get_block_ptr(ptr);

    lock_get();
    std::unique_lock<std::mutex> lock(xalloc_mutex);
    {
        // Deallocate the block
        allocator->Deallocate(blockPtr);
    }
    lock_release();
}

/// Reallocates a memory block previously allocated with xalloc.
///  @param[in] ptr - a pointer to a block created with xalloc.
///  @param[in] size - the client requested block size to create.
void* xrealloc(void* oldMem, size_t size) {
    if (!oldMem)
        return xmalloc(size);

    if (size == 0) {
        xfree(oldMem);
        return nullptr;
    }

    // Create a new memory block
    void* newMem = xmalloc(size);
    if (newMem) {
        // Get the original allocator instance from the old memory block
        Allocator* oldAllocator = get_block_allocator(oldMem);
        size_t oldSize          = oldAllocator->GetBlockSize() - sizeof(Allocator*);

        // Copy the bytes from the old memory block into the new (as much as will fit)
        std::memcpy(newMem, oldMem, (oldSize < size) ? oldSize : size);

        // Free the old memory block
        xfree(oldMem);

        // Return the client pointer to the new memory block
        return newMem;
    }
    return nullptr;
}

/// Output xallocator usage statistics
void xalloc_stats() {
    lock_get();
    std::unique_lock<std::mutex> lock(xalloc_mutex);
    {
        std::cout << "\n***********************";
        if (!_allocators.empty()) {
            auto mode = _allocators.begin()->second->GetMode();
            if (mode == Allocator::HEAP_BLOCKS)
                std::cout << " HEAP_BLOCKS\n";
            if (mode == Allocator::HEAP_POOL)
                std::cout << " HEAP_POOL\n";
            if (mode == Allocator::STATIC_POOL)
                std::cout << " STATIC_POOL\n";
        }

        for (auto& [k, a] : _allocators) {
            if (a->GetBlockCount() == 0)
                continue;
            if (a->GetName())
                std::cout << a->GetName();
            std::cout << " Block Size: " << a->GetBlockSize();
            std::cout << " Block Count: " << a->GetBlockCount();
            std::cout << " Block Allocs: " << a->GetAllocations();
            std::cout << " Block Deallocs: " << a->GetDeallocations();
            std::cout << " Blocks In Use: " << a->GetBlocksInUse();
            std::cout << std::endl;
        }
        std::cout << "***********************\n";
    }
    lock_release();
}
