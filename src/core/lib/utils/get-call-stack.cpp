//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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
#include "utils/get-call-stack.h"

#if defined(__linux__) && defined(__GNUC__)
// clang-format off
#include "utils/demangle.h"

#include <execinfo.h>
#include <cxxabi.h>
#include <memory>
// clang-format on

namespace {
enum { MAX_BACKTRACE_ADDRESSES = 512 };
}

static bool stringEmpty(const std::string& str) {
    if (!str.length())
        return true;

    // str is not empty if it has any printable character
    for (const char c : str) {
        if (c >= 33 && c <= 126)
            return false;
    }

    return true;
}

std::vector<std::string> get_call_stack() {
    void* bt_buffer[MAX_BACKTRACE_ADDRESSES] = {NULL};
    const int n                              = backtrace(bt_buffer, MAX_BACKTRACE_ADDRESSES);
    if (n < 1) {
        return std::vector<std::string>();
    }
    const std::unique_ptr<char*> symbols(backtrace_symbols(bt_buffer, n));

    const size_t numSymbols = static_cast<size_t>(n);
    std::vector<std::string> ret(numSymbols);
    for (size_t i = 0; i < numSymbols; ++i) {
        std::string symbol(symbols.get()[i]);
        // we need to get rid of anything that doesn't belong to the name
        // Mangled symbol examples:
        // ./lib/libOPENFHEcore.so.1(_Z14get_call_stackB5cxx11v+0x35) [0x7f1b5cdb91d5]
        // ./unittest/pke_tests(_ZN8lbcrypto10FirstPrimeIN6intnat14NativeIntegerTImEEEET_mm+0x111) [0x5626d875c1d1]
        //  /lib/libOPENFHEpke.so.1(_ZNK8lbcrypto25ParameterGenerationBGVRNS15ParamsGenBGVRNSESt10shared_ptrINS_20CryptoParametersBaseINS_12DCRTPolyImplIN9bigintdyn9mubintvecINS4_5ubintImEEEEEEEEEjjjjjjjj+0x44a) [0x7f1b5cf6a09a]
        // 1. we may have "+", so we search to find the last one to trim "symbol" from the right
        size_t pos = symbol.find_last_of("+");
        symbol     = symbol.substr(0, pos);
        // 2. find the last "(" which indicates the beginning of the actual mangled symbol enclosed in to "()"
        pos           = symbol.find_last_of("(");
        size_t newLen = symbol.length() - pos;
        std::string mangledName(symbol.substr(pos + 1, newLen));

        ret[i] = (stringEmpty(mangledName)) ? symbols.get()[i] : demangle(mangledName.c_str());
    }

    return ret;
}
#else
std::vector<std::string> get_call_stack() {
    return std::vector<std::string>();
}
#endif
