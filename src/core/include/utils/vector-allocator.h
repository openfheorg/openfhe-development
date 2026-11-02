//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
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
  Allocator for the storage of native-integer vectors
 */

#ifndef SRC_CORE_INCLUDE_UTILS_VECTOR_ALLOCATOR_H_
#define SRC_CORE_INCLUDE_UTILS_VECTOR_ALLOCATOR_H_

#include <cstddef>
#include <cstdint>
#include <new>

namespace lbcrypto {

// Smallest buffer (bytes) that NativeVectorAllocator spreads over page offsets; 0 disables spreading.
#ifndef OPENFHE_VECTOR_SPREAD_MIN_BYTES
    #define OPENFHE_VECTOR_SPREAD_MIN_BYTES 32768
#endif

/**
 * @brief Allocator for the native vector's storage.
 *
 * Buffers of kSpreadBytes and more start at page offsets that rotate in steps of kSpreadStep, so
 * the element-wise kernels, which read one vector while writing another at the same index, do
 * not wait on stores to unrelated addresses with the same low 12 bits (4K aliasing). The data
 * sits at the chosen offset inside an ordinary heap block one page larger than the buffer, with
 * the block start stored just before the data. Smaller buffers come from operator new.
 */
template <typename T>
struct NativeVectorAllocator {
    using value_type = T;
    static constexpr size_t kPage{4096};
    static constexpr size_t kSpreadBytes{OPENFHE_VECTOR_SPREAD_MIN_BYTES};
    static constexpr size_t kSpreadStep{256};

    constexpr NativeVectorAllocator() noexcept = default;
    template <typename U>
    constexpr NativeVectorAllocator(const NativeVectorAllocator<U>&) noexcept {}

    T* allocate(size_t n) {
        const size_t bytes{n * sizeof(T)};
        if (kSpreadBytes == 0 || bytes < kSpreadBytes)
            return static_cast<T*>(::operator new(bytes));
        static thread_local uint32_t slot{0};
        const size_t target{kSpreadStep * (slot++ % (kPage / kSpreadStep))};
        auto* raw{static_cast<char*>(::operator new(bytes + kPage + sizeof(void*)))};
        size_t shift{(target + kPage - (reinterpret_cast<uintptr_t>(raw) & (kPage - 1))) & (kPage - 1)};
        if (shift < sizeof(void*))
            shift += kPage;
        char* data{raw + shift};
        reinterpret_cast<void**>(data)[-1] = raw;
        return reinterpret_cast<T*>(data);
    }

    void deallocate(T* p, size_t n) noexcept {
        if (kSpreadBytes == 0 || n * sizeof(T) < kSpreadBytes) {
            ::operator delete(p);
            return;
        }
        ::operator delete(reinterpret_cast<void**>(p)[-1]);
    }

    friend bool operator==(const NativeVectorAllocator&, const NativeVectorAllocator&) noexcept {
        return true;
    }
    friend bool operator!=(const NativeVectorAllocator&, const NativeVectorAllocator&) noexcept {
        return false;
    }
};

}  // namespace lbcrypto

#endif  // SRC_CORE_INCLUDE_UTILS_VECTOR_ALLOCATOR_H_
