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

/*
  Memory utlities
 */

#ifndef LBCRYPTO_UTILS_MEMORY_H
#define LBCRYPTO_UTILS_MEMORY_H

#include <algorithm>
#include <iterator>
#include <memory>
#include <utility>
#include <vector>

namespace lbcrypto {

//  make_unique was left out of c++11, these are the accepted implementation
#if _MSC_VER == 1700

    //  MSVC11 does not support variadic templates
    #define _MAKE_UNIQUE(TEMPLATE_LIST, PADDING_LIST, LIST, COMMA, X1, X2, X3, X4) \
                                                                                   \
        template <class T COMMA LIST(_CLASS_TYPE)>                                 \
        inline std::unique_ptr<T> make_unique(LIST(_TYPE_REFREF_ARG)) {            \
            return std::unique_ptr<T>(new T(LIST(_FORWARD_ARG)));                  \
        }
_VARIADIC_EXPAND_0X(_MAKE_UNIQUE, , , , )
    #undef _MAKE_UNIQUE

#else

//  *nix implementation
template <typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args) {
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

#endif

template <class X>
void MoveAppend(std::vector<X>& dst, std::vector<X>& src) {
    if (dst.empty()) {
        dst = std::move(src);
    }
    else {
        dst.reserve(dst.size() + src.size());
        std::move(std::begin(src), std::end(src), std::back_inserter(dst));
        src.clear();
    }
}

}  // namespace lbcrypto

#endif  // LBCRYPTO_UTILS_MEMORY_H
