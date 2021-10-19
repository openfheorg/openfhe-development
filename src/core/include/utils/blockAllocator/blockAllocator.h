// @file TODO
//
// @copyright Copyright (c) TODO

// See
// http://www.codeproject.com/Articles/1089905/A-Custom-STL-std-allocator-Replacement-Improves-Performance-

#ifndef __ALLOCATOR_H
#define __ALLOCATOR_H

#include <stddef.h>
#include <cstdlib>

#include "utils/inttypes.h"

/// See
/// http://www.codeproject.com/Articles/1083210/An-efficient-Cplusplus-fixed-block-memory-allocato
class Allocator {
 public:
  /// Constructor
  /// @param[in]  size - size of the fixed blocks
  /// @param[in]  objects - maximum number of object. If 0, new blocks are
  ///    created off the heap as necessary.
  /// @param[in]  memory - pointer to a block of static memory for
  /// allocator or nullptr
  ///    to obtain memory from global heap. If not nullptr, the objects
  /// argument     defines the size of the memory block (size x objects =
  /// memory size in bytes).
  ///  @param[in]  name - optional allocator name string.
  Allocator(size_t size, usint objects = 0, char* memory = nullptr,
            const char* name = nullptr);

  /// Destructor
  ~Allocator();

  /// Get a pointer to a memory block.
  /// @param[in]  size - size of the block to allocate
  /// @return     Returns pointer to the block. Otherwise nullptr if
  /// unsuccessful.
  void* Allocate(size_t size);

  /// Return a pointer to the memory pool.
  /// @param[in]  pBlock - block of memory deallocate (i.e push onto free-list)
  void Deallocate(void* pBlock);

  /// Get the allocator name string.
  /// @return    A pointer to the allocator name or nullptr if none was
  /// assigned.
  const char* GetName() { return m_name; }

  /// Gets the fixed block memory size, in bytes, handled by the allocator.
  /// @return    The fixed block size in bytes.
  size_t GetBlockSize() { return m_blockSize; }

  /// Gets the maximum number of blocks created by the allocator.
  /// @return    The number of fixed memory blocks created.
  usint GetBlockCount() { return m_blockCnt; }

  /// Gets the number of blocks in use.
  /// @return    The number of blocks in use by the application.
  usint GetBlocksInUse() { return m_blocksInUse; }

  /// Gets the total number of allocations for this allocator instance.
  /// @return    The total number of allocations.
  usint GetAllocations() { return m_allocations; }

  /// Gets the total number of deallocations for this allocator instance.
  /// @return    The total number of deallocations.
  usint GetDeallocations() { return m_deallocations; }

 private:
  /// Push a memory block onto head of free-list.
  /// @param[in]  pMemory - block of memory to push onto free-list
  void Push(void* pMemory);

  /// Pop a memory block from head of free-list.
  /// @return     Returns pointer to the block. Otherwise nullptr if
  /// unsuccessful.
  void* Pop();

  struct Block {
    Block* pNext;
  };

  enum AllocatorMode { HEAP_BLOCKS, HEAP_POOL, STATIC_POOL };

  const size_t m_blockSize;
  const size_t m_objectSize;
  const usint m_maxObjects;
  AllocatorMode m_allocatorMode;
  Block* m_pHead;
  char* m_pPool;
  usint m_poolIndex;
  usint m_blockCnt;
  usint m_blocksInUse;
  usint m_allocations;
  usint m_deallocations;
  const char* m_name;
};

// Template class to create external memory pool
template <class T, usint Objects>
class AllocatorPool : public Allocator {
 public:
  AllocatorPool() : Allocator(sizeof(T), Objects, m_memory) {}

 private:
  char m_memory[sizeof(T) * Objects];
};

// macro to provide header file interface
#define DECLARE_ALLOCATOR                       \
 public:                                        \
  void* operator new(size_t size) {             \
    DEBUG_FLAG(false);                          \
    DEBUG("allocating   " << size << " bytes"); \
    return _allocator.Allocate(size);           \
  }                                             \
  void operator delete(void* pObject) {         \
    DEBUG_FLAG(false);                          \
    DEBUG("deallocating  ");                    \
    _allocator.Deallocate(pObject);             \
  }                                             \
                                                \
 private:                                       \
  static Allocator _allocator;

// macro to provide source file interface
#define IMPLEMENT_ALLOCATOR(class, objects, memory) \
  Allocator class ::_allocator(sizeof(class), objects, memory, #class);

#define IMPLEMENT_BALLOCATOR(class, blocksize, objects, memory) \
  Allocator class ::_allocator(blocksize, objects, memory, #class);

#endif
