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

#ifndef _XALLOCATOR_H
#define _XALLOCATOR_H

#include <stddef.h>

// See
// http://www.codeproject.com/Articles/1084801/Replace-malloc-free-with-a-Fast-Fixed-Block-Memory

#define AUTOMATIC_XALLOCATOR_INIT_DESTROY
#ifdef AUTOMATIC_XALLOCATOR_INIT_DESTROY
/// If a C++ translation unit, create a static instance of
/// XallocInitDestroy, any C++ file including xallocator.h will have
/// the xallocDestroy instance declared first within the translation
/// unit and thus will be constructed first. Destruction will occur in
/// the reverse order so xallocInitDestroy is called last. This way,
/// any static user objects relying on xallocator will be destroyed
/// first before xalloc_destroy() is called.
class XallocInitDestroy {
public:
    XallocInitDestroy();
    ~XallocInitDestroy();

private:
    static uint32_t refCount;
};
#endif  // AUTOMATIC_XALLOCATOR_INIT_DESTROY

/// This function must be called exactly one time before the operating
/// system threading starts. If using xallocator exclusively in C
/// files within your application code, you must call this function
/// before the OS starts. If using C++, client code does not call
/// xalloc_init. Let XallocInitDestroy() call xalloc_init
/// automatically.  Embedded systems that never exit can call
/// xalloc_init() manually at startup and eliminate XallocInitDestroy
/// usage. When the system is still single threaded at startup, the
/// xallocator API does not need mutex protection.
void xalloc_init();

/// This function must be called once when the application exits.
/// Never call xalloc_destroy() manually except if using xallocator in
/// a C-only application. If using xallocator exclusively in C files
/// within your application code, you must call this function before
/// the program exits. If using C++, ~XallocInitDestroy() must call
/// xalloc_destroy automatically.  Embedded systems that never exit
/// need not call this function at all.
void xalloc_destroy();

/// Allocate a block of memory
/// @param[in] size - the size of the block to allocate.
void* xmalloc(size_t size);

/// Frees a previously xalloc allocated block
/// @param[in] ptr - a pointer to a previously allocated memory using xalloc.
void xfree(void* ptr);

/// Reallocates an existing xalloc block to a new size
/// @param[in] ptr - a pointer to a previously allocated memory using xalloc.
/// @param[in] size - the size of the new block
void* xrealloc(void* ptr, size_t size);

/// Output allocator statistics to the standard output
void xalloc_stats();

// Macro to overload new/delete with xalloc/xfree
#define XALLOCATOR                        \
public:                                   \
    void* operator new(size_t size) {     \
        return xmalloc(size);             \
    }                                     \
    void operator delete(void* pObject) { \
        xfree(pObject);                   \
    }

#endif
