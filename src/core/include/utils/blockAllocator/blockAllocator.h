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

// See
// http://www.codeproject.com/Articles/1089905/A-Custom-STL-std-allocator-Replacement-Improves-Performance-

#ifndef __ALLOCATOR_H
#define __ALLOCATOR_H

#include <cstdlib>

/// See
/// http://www.codeproject.com/Articles/1083210/An-efficient-Cplusplus-fixed-block-memory-allocato
class Allocator {
public:
    enum AllocatorMode { HEAP_BLOCKS, HEAP_POOL, STATIC_POOL };

    /// Constructor
    /// @param[in]  size - size of the fixed blocks
    /// @param[in]  objects - maximum number of object. If 0, new blocks are
    ///    created off the heap as necessary.
    /// @param[in]  memory - pointer to a block of static memory for allocator or nullptr
    ///    to obtain memory from global heap. If not nullptr, the objects argument
    ///    defines the size of the memory block (size x objects = memory size in bytes).
    /// @param[in]  name - optional allocator name string.
    Allocator(size_t size, size_t objects = 0, char* memory = nullptr, const char* name = nullptr);

    /// Destructor
    ~Allocator();

    /// Get a pointer to a memory block.
    /// @param[in]  size - size of the block to allocate
    /// @return     Returns pointer to the block. Otherwise nullptr if unsuccessful.
    void* Allocate(size_t size);

    /// Return a pointer to the memory pool.
    /// @param[in]  pBlock - block of memory deallocate (i.e push onto free-list)
    void Deallocate(void* pBlock);

    /// Get the allocator name string.
    /// @return  A pointer to the allocator name or nullptr if none was assigned.
    const char* GetName() const {
        return m_name;
    }

    /// Gets the fixed block memory size, in bytes, handled by the allocator.
    /// @return  The fixed block size in bytes.
    size_t GetBlockSize() const {
        return m_blockSize;
    }

    /// Gets the maximum number of blocks created by the allocator.
    /// @return  The number of fixed memory blocks created.
    size_t GetBlockCount() const {
        return m_blockCnt;
    }

    /// Gets the number of blocks in use.
    /// @return  The number of blocks in use by the application.
    size_t GetBlocksInUse() const {
        return m_blocksInUse;
    }

    /// Gets the total number of allocations for this allocator instance.
    /// @return  The total number of allocations.
    size_t GetAllocations() const {
        return m_allocations;
    }

    /// Gets the total number of deallocations for this allocator instance.
    /// @return  The total number of deallocations.
    size_t GetDeallocations() const {
        return m_deallocations;
    }

    AllocatorMode GetMode() const {
        return m_allocatorMode;
    }

private:
    /// Push a memory block onto head of free-list.
    /// @param[in]  pMemory - block of memory to push onto free-list
    void Push(void* pMemory);

    /// Pop a memory block from head of free-list.
    /// @return  Returns pointer to the block. Otherwise nullptr if unsuccessful.
    void* Pop();

    struct Block {
        Block* pNext;
    };

    size_t m_blockSize;
    size_t m_maxObjects;
    Block* m_pHead{nullptr};
    char* m_pPool{nullptr};
    size_t m_blockCnt{0};
    size_t m_blocksInUse{0};
    size_t m_allocations{0};
    size_t m_deallocations{0};
    AllocatorMode m_allocatorMode{HEAP_BLOCKS};
    const char* m_name;
};

// Template class to create external memory pool
template <class T, size_t Objects>
class AllocatorPool : public Allocator {
public:
    AllocatorPool() : Allocator(sizeof(T), Objects, m_memory) {}

private:
    char m_memory[sizeof(T) * Objects];
};

// macro to provide header file interface
#define DECLARE_ALLOCATOR                                   \
public:                                                     \
    void* operator new(size_t size) {                       \
        return _allocator.Allocate(size);                   \
    }                                                       \
    void operator delete(void* pObject) {                   \
        _allocator.Deallocate(pObject);                     \
    }                                                       \
                                                            \
private:                                                    \
    static Allocator _allocator;

// macro to provide source file interface
#define IMPLEMENT_ALLOCATOR(class, objects, memory) \
    Allocator class ::_allocator(sizeof(class), objects, memory, #class);

#define IMPLEMENT_BALLOCATOR(class, blocksize, objects, memory) \
    Allocator class ::_allocator(blocksize, objects, memory, #class);

#endif
