// @file TODO
//
// @copyright Copyright (c) TODO

// See
// http://www.codeproject.com/Articles/1089905/A-Custom-STL-std-allocator-Replacement-Improves-Performance-

#include <cassert>
#include <cstring>  // for memcpy consider changing to copy
#include <iostream>
#include <mutex>
#include <thread>

#include "utils/blockAllocator/blockAllocator.h"
#include "utils/blockAllocator/xallocator.h"
#include "utils/debug.h"

using namespace std;

#ifndef CHAR_BIT
#define CHAR_BIT 8
#endif

// static CRITICAL_SECTION _criticalSection;

static std::mutex xalloc_mutex;

static bool _xallocInitialized = false;

// Define STATIC_POOLS to switch from heap blocks mode to static pools mode
// #define STATIC_POOLS
#ifdef STATIC_POOLS
// Update this section as necessary if you want to use static memory pools.
// See also xalloc_init() and xalloc_destroy() for additional updates required.
#define MAX_ALLOCATORS 14
// #define MAX_BLOCKS          2048
#define MAX_BLOCKS 18948

// Create static storage for each static allocator instance
char* _allocator8[sizeof(AllocatorPool<char[8], MAX_BLOCKS>)];
char* _allocator16[sizeof(AllocatorPool<char[16], MAX_BLOCKS>)];
char* _allocator32[sizeof(AllocatorPool<char[32], MAX_BLOCKS>)];
char* _allocator64[sizeof(AllocatorPool<char[64], MAX_BLOCKS>)];
char* _allocator128[sizeof(AllocatorPool<char[128], MAX_BLOCKS>)];
char* _allocator256[sizeof(AllocatorPool<char[256], MAX_BLOCKS>)];
char* _allocator396[sizeof(AllocatorPool<char[396], MAX_BLOCKS>)];
char* _allocator512[sizeof(AllocatorPool<char[512], MAX_BLOCKS>)];
char* _allocator768[sizeof(AllocatorPool<char[768], MAX_BLOCKS>)];
char* _allocator1024[sizeof(AllocatorPool<char[1024], MAX_BLOCKS>)];
char* _allocator2048[sizeof(AllocatorPool<char[2048], MAX_BLOCKS>)];
char* _allocator4096[sizeof(AllocatorPool<char[4096], MAX_BLOCKS>)];
char* _allocator8192[sizeof(AllocatorPool<char[8192], MAX_BLOCKS>)];
char* _allocator16384[sizeof(AllocatorPool<char[16384], MAX_BLOCKS>)];

// Array of pointers to all allocator instances
static Allocator* _allocators[MAX_ALLOCATORS];

#else
#define MAX_ALLOCATORS 15
static Allocator* _allocators[MAX_ALLOCATORS];
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
usint XallocInitDestroy::refCount = 0;
XallocInitDestroy::XallocInitDestroy() {
  // Track how many static instances of XallocInitDestroy are created
  if (refCount++ == 0) xalloc_init();
}

XallocInitDestroy::~XallocInitDestroy() {
  // Last static instance to have destructor called?
  if (--refCount == 0) xalloc_destroy();
}
#endif  // AUTOMATIC_XALLOCATOR_INIT_DESTROY

/// Returns the next higher powers of two. For instance, pass in 12 and
/// the value returned would be 16.
/// @param[in] k - numeric value to compute the next higher power of two.
/// @return  The next higher power of two based on the input k.
template <class T>
T nexthigher(T k) {
  k--;
  for (size_t i = 1; i < sizeof(T) * CHAR_BIT; i <<= 1) k |= (k >> i);
  return k + 1;
}

/// Create the xallocator lock. Call only one time at startup.
/// note for C++11 we do not need to control the lock with the lock_* functions.
/// instead we control the next exection function in the code.
static void lock_init() { _xallocInitialized = true; }

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
  if (_xallocInitialized == false) return;
#if 0
  // Acquire the mutex to access the shared resource
  pthread_mutex_lock(&xalloc_mutex);
  // EnterCriticalSection(&_criticalSection);
#endif
}

/// Unlock the shared resource.
static inline void lock_release() {
  if (_xallocInitialized == false) return;

#if 0
  // Release the mutex  and release the access to shared resource
  pthread_mutex_unlock(&xalloc_mutex);
  // LeaveCriticalSection(&_criticalSection);
#endif
}

/// Stored a pointer to the allocator instance within the block region.
///  a pointer to the client's area within the block.
/// @param[in] block - a pointer to the raw memory block.
///  @param[in] size - the client requested size of the memory block.
/// @return  A pointer to the client's address within the raw memory block.
static inline void* set_block_allocator(void* block, Allocator* allocator) {
  // Cast the raw block memory to a Allocator pointer
  Allocator** pAllocatorInBlock = static_cast<Allocator**>(block);

  // Write the size into the memory block
  *pAllocatorInBlock = allocator;

  // Advance the pointer past the Allocator* block size and return a pointer to
  // the client's memory region
  return ++pAllocatorInBlock;
}

/// Gets the size of the memory block stored within the block.
/// @param[in] block - a pointer to the client's memory block.
/// @return  The original allocator instance stored in the memory block.
static inline Allocator* get_block_allocator(void* block) {
  // Cast the client memory to a Allocator pointer
  Allocator** pAllocatorInBlock = static_cast<Allocator**>(block);

  // Back up one Allocator* position to get the stored allocator instance
  pAllocatorInBlock--;

  // Return the allocator instance stored within the memory block
  return *pAllocatorInBlock;
}

/// Returns the raw memory block pointer given a client memory pointer.
/// @param[in] block - a pointer to the client memory block.
/// @return  A pointer to the original raw memory block address.
static inline void* get_block_ptr(void* block) {
  // Cast the client memory to a Allocator* pointer
  Allocator** pAllocatorInBlock = static_cast<Allocator**>(block);

  // Back up one Allocator* position and return the original raw memory block
  // pointer
  return --pAllocatorInBlock;
}

/// Returns an allocator instance matching the size provided
/// @param[in] size - allocator block size
/// @return Allocator instance handling requested block size or nullptr
/// if no allocator exists.
static inline Allocator* find_allocator(size_t size) {
  DEBUG_FLAG(false);
  for (usint i = 0; i < MAX_ALLOCATORS; i++) {
    DEBUG("allocator " << i << " " << _allocators[i]);

    if (_allocators[i] == 0) break;

    if (_allocators[i]->GetBlockSize() == size) return _allocators[i];
  }

  return nullptr;
}

/// Insert an allocator instance into the array
/// @param[in] allocator - An allocator instance
static inline void insert_allocator(Allocator* allocator) {
  for (usint i = 0; i < MAX_ALLOCATORS; i++) {
    if (_allocators[i] == 0) {
      _allocators[i] = allocator;
      return;
    }
  }

  assert(0);
}

/// This function must be called exactly one time *before* any other xallocator
/// API is called. XallocInitDestroy constructor calls this function
/// automatically.
extern "C" void xalloc_init() {
  lock_init();

#ifdef STATIC_POOLS
  // For STATIC_POOLS mode, the allocators must be initialized before any other
  // static user class constructor is run. Therefore, use placement new to
  // initialize each allocator into the previously reserved static memory
  // locations.
  new (&_allocator8) AllocatorPool<char[8], MAX_BLOCKS>();
  new (&_allocator16) AllocatorPool<char[16], MAX_BLOCKS>();
  new (&_allocator32) AllocatorPool<char[32], MAX_BLOCKS>();
  new (&_allocator64) AllocatorPool<char[64], MAX_BLOCKS>();
  new (&_allocator128) AllocatorPool<char[128], MAX_BLOCKS>();
  new (&_allocator256) AllocatorPool<char[256], MAX_BLOCKS>();
  new (&_allocator396) AllocatorPool<char[396], MAX_BLOCKS>();
  new (&_allocator512) AllocatorPool<char[512], MAX_BLOCKS>();
  new (&_allocator768) AllocatorPool<char[768], MAX_BLOCKS>();
  new (&_allocator1024) AllocatorPool<char[1024], MAX_BLOCKS>();
  new (&_allocator2048) AllocatorPool<char[2048], MAX_BLOCKS>();
  new (&_allocator4096) AllocatorPool<char[4096], MAX_BLOCKS>();
  new (&_allocator8192) AllocatorPool<char[8192], MAX_BLOCKS>();
  new (&_allocator16384) AllocatorPool<char[16384], MAX_BLOCKS>();

  // Populate allocator array with all instances
  _allocators[0] = reinterpret_cast<Allocator*>(&_allocator8);
  _allocators[1] = reinterpret_cast<Allocator*>(&_allocator16);
  _allocators[2] = reinterpret_cast<Allocator*>(&_allocator32);
  _allocators[3] = reinterpret_cast<Allocator*>(&_allocator64);
  _allocators[4] = reinterpret_cast<Allocator*>(&_allocator128);
  _allocators[5] = reinterpret_cast<Allocator*>(&_allocator256);
  _allocators[6] = reinterpret_cast<Allocator*>(&_allocator396);
  _allocators[7] = reinterpret_cast<Allocator*>(&_allocator512);
  _allocators[8] = reinterpret_cast<Allocator*>(&_allocator768);
  _allocators[9] = reinterpret_cast<Allocator*>(&_allocator1024);
  _allocators[10] = reinterpret_cast<Allocator*>(&_allocator2048);
  _allocators[11] = reinterpret_cast<Allocator*>(&_allocator4096);
  _allocators[12] = reinterpret_cast<Allocator*>(&_allocator8192);
  _allocators[13] = reinterpret_cast<Allocator*>(&_allocator16384);

#endif
}

/// Called one time when the application exits to cleanup any allocated memory.
/// ~XallocInitDestroy destructor calls this function automatically.
extern "C" void xalloc_destroy() {
  lock_get();
  std::unique_lock<std::mutex> lock(xalloc_mutex);
  {
#ifdef STATIC_POOLS
    for (usint i = 0; i < MAX_ALLOCATORS; i++) {
      _allocators[i]->~Allocator();
      _allocators[i] = 0;
    }
#else
    for (usint i = 0; i < MAX_ALLOCATORS; i++) {
      if (_allocators[i] == 0) break;
      delete _allocators[i];
      _allocators[i] = 0;
    }
#endif
  }
  lock_release();

  lock_destroy();
}

/// Get an Allocator instance based upon the client's requested block size.
/// If a Allocator instance is not currently available to handle the size,
///  then a new Allocator instance is create.
///  @param[in] size - the client's requested block size.
///  @return An Allocator instance that handles blocks of the requested
///  size.
extern "C" Allocator* xallocator_get_allocator(size_t size) {
  // Based on the size, find the next higher powers of two value.
  // Add sizeof(Allocator*) to the requested block size to hold the size
  // within the block memory region. Most blocks are powers of two,
  // however some common allocator block sizes can be explicitly defined
  // to minimize wasted storage. This offers application specific tuning.
  DEBUG_FLAG(false);
  size_t blockSize = size + sizeof(Allocator*);
  if (blockSize > 256 && blockSize <= 396)
    blockSize = 396;
  else if (blockSize > 512 && blockSize <= 768)
    blockSize = 768;
  else
    blockSize = nexthigher<size_t>(blockSize);
  DEBUG("finding allocator for blockSize " << blockSize);
  Allocator* allocator = find_allocator(blockSize);

#ifdef STATIC_POOLS

  if (allocator == nullptr) {
    std::cerr << "static pool allocator for blockSize " << blockSize
              << " not found! " << std::endl;
  }
  assert(allocator != nullptr);
#else
  // If there is not an allocator already created to handle this block size
  if (allocator == nullptr) {
    // Create a new allocator to handle blocks of the size required
    allocator = new Allocator(blockSize, 0, 0, "xallocator");

    // Insert allocator into array
    insert_allocator(allocator);
  }
#endif

  return allocator;
}

/// Allocates a memory block of the requested size. The blocks are created from
///  the fixed block allocators.
///  @param[in] size - the client requested size of the block.
/// @return  A pointer to the client's memory block.
extern "C" void* xmalloc(size_t size) {
  DEBUG_FLAG(false);

  Allocator* allocator;
  void* blockMemoryPtr;
  lock_get();
  std::unique_lock<std::mutex> lock(xalloc_mutex);
  {
    // Allocate a raw memory block
    allocator = xallocator_get_allocator(size);
    blockMemoryPtr = allocator->Allocate(sizeof(Allocator*) + size);
    DEBUG("xmalloc " << size);
  }
  lock_release();

  // Set the block Allocator* within the raw memory block region
  void* clientsMemoryPtr = set_block_allocator(blockMemoryPtr, allocator);
  return clientsMemoryPtr;
}

/// Frees a memory block previously allocated with xalloc. The blocks are
/// returned
///  to the fixed block allocator that originally created it.
///  @param[in] ptr - a pointer to a block created with xalloc.
extern "C" void xfree(void* ptr) {
  DEBUG_FLAG(false);
  DEBUG("xfree ");
  if (ptr == 0) return;

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
extern "C" void* xrealloc(void* oldMem, size_t size) {
  if (oldMem == 0) return xmalloc(size);

  if (size == 0) {
    xfree(oldMem);
    return 0;
  } else {
    // Create a new memory block
    void* newMem = xmalloc(size);
    if (newMem != 0) {
      // Get the original allocator instance from the old memory block
      Allocator* oldAllocator = get_block_allocator(oldMem);
      size_t oldSize = oldAllocator->GetBlockSize() - sizeof(Allocator*);

      // Copy the bytes from the old memory block into the new (as much as will
      // fit)
      std::memcpy(newMem, oldMem, (oldSize < size) ? oldSize : size);

      // Free the old memory block
      xfree(oldMem);

      // Return the client pointer to the new memory block
      return newMem;
    }
    return 0;
  }
}

/// Output xallocator usage statistics
extern "C" void xalloc_stats() {
  lock_get();
  std::unique_lock<std::mutex> lock(xalloc_mutex);
  {
#ifdef STATIC_POOLS
    cout << " Static Pools " << endl;
#endif

    for (usint i = 0; i < MAX_ALLOCATORS; i++) {
      if (_allocators[i] == 0) break;

      if (_allocators[i]->GetName() != nullptr)
        cout << _allocators[i]->GetName();

      cout << " Block Size: " << _allocators[i]->GetBlockSize();
      cout << " Block Count: " << _allocators[i]->GetBlockCount();
      cout << " Blocks In Use: " << _allocators[i]->GetBlocksInUse();
      cout << endl;
    }
  }
  lock_release();
}
