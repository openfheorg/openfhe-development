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
#include "utils/memory.h"

#if defined(__GLIBC__)
    #include <malloc.h>
#endif

namespace lbcrypto {

#if defined(__GLIBC__)
// Tune glibc malloc for FHE allocation patterns. Each homomorphic operation allocates and
// frees many large (~0.5-30 MB) polynomial coefficient buffers. By default glibc returns
// these freed buffers to the OS (brk heap-trim / munmap) and re-faults the pages on the next
// operation; under a single thread this page-fault / kernel-time overhead can dominate
// runtime. Keeping large allocations on the heap (M_MMAP_MAX=0) and never trimming it back to
// the OS (M_TRIM_THRESHOLD=-1) lets the buffers be reused, eliminating the churn. Runs once,
// process-wide, at library load. NOTE: this retains freed memory in-process, so workloads
// with large transient allocation peaks will show a higher resident set size. Use AllocTrim()
// after large allocations are freed if this becomes an issue.
namespace {
[[maybe_unused]] const bool ofheGlibcMallocTuned = []() noexcept {
    mallopt(M_MMAP_MAX, 0);
    mallopt(M_TRIM_THRESHOLD, -1);
    return true;
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
#if defined(__GLIBC__)
    malloc_trim(0);
    return true;
#else
    return false;
#endif
}

void secure_memset(volatile void* mem, uint8_t c, size_t len) {
    volatile uint8_t* ptr = (volatile uint8_t*)mem;
    for (size_t i = 0; i < len; ++i)
        *(ptr + i) = c;
}

}  // namespace lbcrypto
