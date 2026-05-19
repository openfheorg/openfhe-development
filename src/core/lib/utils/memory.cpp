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

#if defined(__APPLE__)
    #include <mach/mach.h>
    #include <malloc/malloc.h>
#elif defined(__GLIBC__)
    #include <malloc.h>
#elif defined(_MSC_VER)
    #include <malloc.h>
#endif

namespace lbcrypto {

void secure_memset(volatile void* mem, uint8_t c, size_t len) {
    volatile uint8_t* ptr = (volatile uint8_t*)mem;
    for (size_t i = 0; i < len; ++i)
        *(ptr + i) = c;
}

bool TrimAllocator() {
#if defined(__GLIBC__)
    // Returns non-zero if any memory was released; absence of trim is not an error.
    malloc_trim(0);
    return true;
#elif defined(__APPLE__)
    // Walk every registered zone and pressure-relieve it. goal=0 asks libmalloc
    // to return as much as it can without capping.
    vm_address_t* zones = nullptr;
    unsigned count      = 0;
    if (malloc_get_all_zones(mach_task_self(), nullptr, &zones, &count) == KERN_SUCCESS && zones) {
        for (unsigned i = 0; i < count; ++i) {
            auto* z = reinterpret_cast<malloc_zone_t*>(zones[i]);
            if (z)
                malloc_zone_pressure_relief(z, 0);
        }
    }
    return true;
#elif defined(_MSC_VER)
    _heapmin();
    return true;
#else
    return false;
#endif
}

}  // namespace lbcrypto
