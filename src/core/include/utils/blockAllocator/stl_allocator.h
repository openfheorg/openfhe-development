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

#ifndef _STL_ALLOCATOR_H
#define _STL_ALLOCATOR_H

// See
// http://www.codeproject.com/Articles/1089905/A-Custom-STL-std-allocator-Replacement-Improves-Performance-

#include <cstddef>
#include <limits>
#include <new>
#include <utility>

#include "xallocator.h"

/// @brief stl_allocator is STL-compatible allocator used to provide fixed
/// block allocations.
/// @details The default allocator for the STL is the global heap. The
/// stl_allocator is custom allocator where xmalloc/xfree is used to obtain
/// and release memory.
template <typename T>
class stl_allocator {
public:
    using value_type      = T;
    using size_type       = size_t;
    using difference_type = ptrdiff_t;
    using pointer         = T*;
    using const_pointer   = const T*;
    using reference       = T&;
    using const_reference = const T&;

    /// Constructor
    stl_allocator() noexcept = default;

    /// Destructor
    ~stl_allocator() = default;

    /// Copy constructor
    template <class U>
    stl_allocator(const stl_allocator<U>&) noexcept {}

    template <class U>
    struct rebind {
        using other = stl_allocator<U>;
    };

    /// Return reference address.
    /// @return  Pointer to T memory.
    pointer address(reference x) const noexcept {
        return &x;
    }

    /// Return reference address.
    /// @return  Const pointer to T memory.
    const_pointer address(const_reference x) const noexcept {
        return &x;
    }

    /// Get the maximum size of memory.
    /// @return  Max memory size in bytes.
    size_type max_size() const noexcept {
        return std::numeric_limits<size_type>::max() / sizeof(value_type);
    }

    /// Allocates a fixed block of memory
    /// @param[in] n - size of memory to allocate in bytes
    /// @return  Pointer to the allocated memory.
    pointer allocate(size_type n) {
        return static_cast<pointer>(xmalloc(n * sizeof(T)));
    }

    /// Allocates a fixed block of memory.
    /// @param[in] n - size of memory to allocate in bytes
    /// @param[in] hint - placement hint ignored by this allocator
    /// @return  Pointer to the allocated memory.
    pointer allocate(size_type n, const void* hint) {
        (void)hint;
        return allocate(n);
    }

    /// Deallocate a previously allocated fixed memory block.
    /// @param[in] p - pointer to the memory block
    /// @param[in] n - size of memory in bytes
    void deallocate(pointer p, size_type n) noexcept {
        (void)n;
        xfree(p);
    }

    /// Constructs a new instance.
    /// @param[in] p - pointer to the memory where the instance is constructed
    ///    using placement new.
    template <class U, class... Args>
    void construct(U* p, Args&&... args) {
        new (static_cast<void*>(p)) U(std::forward<Args>(args)...);
    }

    /// Destroys an instance. Objects created with placement new must
    ///  explicitly call the destructor.
    /// @param[in] p - pointer to object instance.
    template <class U>
    void destroy(U* p) noexcept {
        p->~U();
    }
};

template <typename T, typename U>
inline bool operator==(const stl_allocator<T>&, const stl_allocator<U>&) {
    return true;
}

template <typename T, typename U>
inline bool operator!=(const stl_allocator<T>&, const stl_allocator<U>&) {
    return false;
}

#endif
