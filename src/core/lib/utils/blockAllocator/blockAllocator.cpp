// @file TODO
//
// @copyright Copyright (c) TODO

// See
// http://www.codeproject.com/Articles/1089905/A-Custom-STL-std-allocator-Replacement-Improves-Performance-

#include <assert.h>
#include <new>
#include "utils/blockAllocator/blockAllocator.h"

//------------------------------------------------------------------------------
// Constructor
//------------------------------------------------------------------------------
Allocator::Allocator(size_t size, usint objects, char* memory, const char* name)
    : m_blockSize(size < sizeof(long*) ? sizeof(long*) : size),
      m_objectSize(size),
      m_maxObjects(objects),
      m_pHead(nullptr),
      m_poolIndex(0),
      m_blockCnt(0),
      m_blocksInUse(0),
      m_allocations(0),
      m_deallocations(0),
      m_name(name) {
  // If using a fixed memory pool
  if (m_maxObjects) {
    // If caller provided an external memory pool
    if (memory) {
      m_pPool = memory;
      m_allocatorMode = STATIC_POOL;
    } else {
      m_pPool = new char[m_blockSize * m_maxObjects];
      m_allocatorMode = HEAP_POOL;
    }
  } else {
    m_allocatorMode = HEAP_BLOCKS;
  }
}

//------------------------------------------------------------------------------
// Destructor
//------------------------------------------------------------------------------
Allocator::~Allocator() {
  // If using pool then destroy it, otherwise traverse free-list and
  // destroy each individual block
  if (m_allocatorMode == HEAP_POOL) {
    delete[] m_pPool;
  } else if (m_allocatorMode == HEAP_BLOCKS) {
    while (m_pHead) delete[] reinterpret_cast<char*>(Pop());
  }
}

//------------------------------------------------------------------------------
// Allocate
//------------------------------------------------------------------------------
void* Allocator::Allocate(size_t size) {
  assert(size <= m_objectSize);

  // If can't obtain existing block then get a new one
  void* pBlock = Pop();
  if (!pBlock) {
    // If using a pool method then get block from pool,
    // otherwise using dynamic so get block from heap
    if (m_maxObjects) {
      // If we have not exceeded the pool maximum
      if (m_poolIndex < m_maxObjects) {
        pBlock =
            reinterpret_cast<void*>(m_pPool + (m_poolIndex++ * m_blockSize));
      } else {
        // Get the pointer to the new handler
        std::new_handler handler = std::set_new_handler(0);
        std::set_new_handler(handler);

        // If a new handler is defined, call it
        if (handler)
          (*handler)();
        else
          assert(0);
      }
    } else {
      m_blockCnt++;
      pBlock = reinterpret_cast<void*>(new char[m_blockSize]);
    }
  }

  m_blocksInUse++;
  m_allocations++;

  return pBlock;
}

//------------------------------------------------------------------------------
// Deallocate
//------------------------------------------------------------------------------
void Allocator::Deallocate(void* pBlock) {
  Push(pBlock);
  m_blocksInUse--;
  m_deallocations++;
}

//------------------------------------------------------------------------------
// Push
//------------------------------------------------------------------------------
void Allocator::Push(void* pMemory) {
  Block* pBlock = reinterpret_cast<Block*>(pMemory);
  pBlock->pNext = m_pHead;
  m_pHead = pBlock;
}

//------------------------------------------------------------------------------
// Pop
//------------------------------------------------------------------------------
void* Allocator::Pop() {
  Block* pBlock = nullptr;

  if (m_pHead) {
    pBlock = m_pHead;
    m_pHead = m_pHead->pNext;
  }

  return reinterpret_cast<void*>(pBlock);
}
