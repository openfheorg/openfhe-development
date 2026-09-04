//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2024, NJIT, Duality Technologies Inc. and other contributors
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

#include "config_core.h"
#include "utils/memory.h"

#if defined(__APPLE__)
    #include <malloc/malloc.h>
#elif defined(__GLIBC__)
    #include <malloc.h>
#elif defined(_MSC_VER)
    #include <malloc.h>
#endif

#if defined(WITH_NUMA_INTERLEAVE) && defined(__linux__) && defined(PARALLEL)
    #include <cstdlib>
    #include <cstring>
    #include <omp.h>
    #include <sys/syscall.h>
    #include <unistd.h>
#endif

namespace lbcrypto {

#if defined(WITH_MALLOC_TUNING)
// Tune the process allocator to retain freed memory for reuse. OpenFHE operations allocate and
// free many large (~0.5-30 MB) buffers; on allocators that return freed buffers to the OS right
// away, re-faulting the pages on the next operation can dominate single-threaded runtime. Any
// tuning below runs once, process-wide, at library load. NOTE: retained memory shows up as a
// higher resident set size for workloads with large transient allocation peaks. Use AllocTrim()
// after large allocations are freed if this becomes an issue, or build with
// -DWITH_MALLOC_TUNING=OFF to disable this tuning entirely.
namespace {
    #if defined(__APPLE__)
    // Nothing to tune: macOS libmalloc already retains freed memory in-process. Freed pages of
    // small/medium allocations stay mapped and are marked reusable (the kernel reclaims them only
    // under memory pressure), and freed large allocations are held in the default zone's cache.
    // There is no public API to tune this behavior further; AllocTrim() releases these caches.
    #elif defined(__GLIBC__)
// By default glibc returns freed large buffers to the OS (brk heap-trim / munmap) and re-faults
// the pages on the next operation. Keeping large allocations on the heap (M_MMAP_MAX=0) and
// never trimming it back to the OS (M_TRIM_THRESHOLD=-1) lets the buffers be reused,
// eliminating the churn.
[[maybe_unused]] const bool ofheGlibcMallocTuned = []() noexcept {
    mallopt(M_MMAP_MAX, 0);
    mallopt(M_TRIM_THRESHOLD, -1);
    return true;
}();
    #elif defined(_MSC_VER)
    // Nothing to tune: the CRT heap is the Windows process heap, which serves allocations above
    // roughly 0.5-1 MB directly via VirtualAlloc and returns them to the OS on free, with no
    // supported process-wide switch to retain them. If this churn matters, link a caching
    // allocator (e.g. mimalloc or tcmalloc) instead.
    #endif
}  // namespace
#endif

#if defined(WITH_NUMA_INTERLEAVE) && defined(__linux__) && defined(PARALLEL)
// Interleave this process's pages across the NUMA nodes it is allowed to use. The polynomial
// buffers are written by whichever thread first touches them and then read by every thread in
// the next parallel region, so under the default first-touch policy a buffer allocated on one
// socket is read remotely by half the team. Interleaving spreads the pages instead, which
// trades a little locality for a lot less cross-socket traffic on the wide loops.
//
// Deliberately conservative: it does nothing unless this build is threaded and the process
// can actually use more than one thread and more than one node, and it never overrides a
// policy the operator already set (so `numactl --membind=...` and container/cpuset policies win).
//
// NOTE: set_mempolicy() is process-wide, so this also applies to allocations made by the host
// application, not just to OpenFHE's.
namespace {
using MemPolicyWord = unsigned long;  // NOLINT(runtime/int) -- kernel nodemask word

constexpr int OPENFHE_MPOL_DEFAULT        = 0;
constexpr int OPENFHE_MPOL_INTERLEAVE     = 3;
constexpr int OPENFHE_MPOL_F_MEMS_ALLOWED = 4;
constexpr MemPolicyWord OPENFHE_MAXNODE   = 1024;

[[maybe_unused]] const bool ofheNumaInterleaved = []() noexcept {
    const char* opt = std::getenv("OPENFHE_NUMA_INTERLEAVE");
    if (opt != nullptr && std::strcmp(opt, "0") == 0)
        return false;

    // single-threaded runs are strictly better off with first-touch locality
    if (omp_get_max_threads() < 2)
        return false;

    // respect an explicitly configured policy
    int mode = 0;
    if (syscall(SYS_get_mempolicy, &mode, nullptr, 0UL, nullptr, 0) != 0)
        return false;  // no NUMA support in this kernel
    if (mode != OPENFHE_MPOL_DEFAULT)
        return false;

    MemPolicyWord mask[OPENFHE_MAXNODE / (8 * sizeof(MemPolicyWord))] = {0};
    if (syscall(SYS_get_mempolicy, nullptr, mask, OPENFHE_MAXNODE, nullptr, OPENFHE_MPOL_F_MEMS_ALLOWED) != 0)
        return false;

    uint32_t nodes = 0;
    for (MemPolicyWord word : mask)
        for (; word != 0; word &= word - 1)
            ++nodes;
    if (nodes < 2)
        return false;  // single node: interleaving is a no-op at best

    return syscall(SYS_set_mempolicy, OPENFHE_MPOL_INTERLEAVE, mask, OPENFHE_MAXNODE) == 0;
}();
}  // namespace
#endif

// AllocTrim() asks the allocator to return free (unused) heap memory to the OS. It is the
// companion to the retain-by-default malloc tuning above: call it at a quiescent point after a
// large transient-footprint operation (e.g. EvalBootstrap) to reclaim peak scratch memory.
//
// WARNING: this is a performance / RSS tool, NOT a security primitive. It does not erase data --
// it only releases already-free chunks (the bytes are not scrubbed; the kernel zero-fills pages
// only when they are next handed out). To wipe sensitive data (keys, plaintext, noise) use
// secure_memset() before freeing.
//
// Not async-signal-safe and acquires allocator locks; call only from normal execution context,
// never from a signal handler. Returns true if a trim was attempted, false on unsupported builds.
bool AllocTrim() {
#if defined(__APPLE__)
    malloc_zone_pressure_relief(nullptr, 0);
    return true;
#elif defined(__GLIBC__)
    malloc_trim(0);
    return true;
#elif defined(_MSC_VER)
    _heapmin();
    return true;
#else
    return false;
#endif
}

// secure_memset() overwrites memory with c and, unlike a plain std::memset() of an object about
// to be freed or go out of scope, is guaranteed not to be removed by dead-store elimination.
void secure_memset(volatile void* mem, uint8_t c, size_t len) {
    volatile uint8_t* ptr = static_cast<volatile uint8_t*>(mem);
    for (size_t i = 0; i < len; ++i)
        *(ptr + i) = c;
}

}  // namespace lbcrypto
