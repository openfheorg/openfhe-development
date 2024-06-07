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
#include "utils/demangle.h"
#include <memory>

#if defined(__clang__) || defined(__GNUC__)
    #include <cxxabi.h>

std::string demangle(const char* const name) noexcept {
    // output_buffer must be malloc'ed
    size_t output_buffer_size = 512;
    auto output_buffer        = reinterpret_cast<char*>(std::malloc(output_buffer_size));
    int status                = -1;

    char* ptr = abi::__cxa_demangle(name, output_buffer, &output_buffer_size, &status);
    std::string result;
    if (status == 0 && ptr != nullptr) {
        result = ptr;
        // If ptr is different from output_buffer, free ptr as it points to the newly allocated (realloc) buffer
        if (ptr != output_buffer)
            std::free(ptr);
        else
            std::free(output_buffer);
    }
    else {
        result = "Cannot demangle symbol: " + std::string(name);
        std::free(output_buffer);
    }

    return result;
}
#else
std::string demangle(const char* const name) noexcept {
    return name;
}
#endif
