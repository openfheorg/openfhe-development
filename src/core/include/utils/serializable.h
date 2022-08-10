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
#ifndef LBCRYPTO_SERIALIZABLE_H
#define LBCRYPTO_SERIALIZABLE_H

#ifndef CEREAL_RAPIDJSON_HAS_STDSTRING
    #define CEREAL_RAPIDJSON_HAS_STDSTRING 1
#endif
#ifndef CEREAL_RAPIDJSON_HAS_CXX11_RVALUE_REFS
    #define CEREAL_RAPIDJSON_HAS_CXX11_RVALUE_REFS 1
#endif
#define CEREAL_RAPIDJSON_HAS_CXX11_NOEXCEPT 0

// In order to correctly identify GCC and clang we must either:
// 1. use "#if defined(__GNUC__) && !defined(__clang__)" (preferred option)
// 2. or check the condition "#if defined __clang__" first
// The reason is: clang always defines __GNUC__ and __GNUC_MINOR__ and __GNUC_PATCHLEVEL__ according to the version of gcc that it claims full compatibility with.
#if defined(__GNUC__) && !defined(__clang__)
    #if __GNUC__ >= 8
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wclass-memaccess"
    #endif
#elif defined __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wunused-private-field"
    #pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#include "cereal/cereal.hpp"
#include "cereal/types/polymorphic.hpp"

#if defined(__GNUC__) && !defined(__clang__)
    #if __GNUC__ >= 8
        #pragma GCC diagnostic pop
    #endif
#elif defined __clang__
    #pragma clang diagnostic pop
#endif

#include <iostream>
#include <string>
#include <vector>

namespace lbcrypto {

/**
 * \class Serializable
 *
 * \brief Base class for OpenFHE serialization
 *
 * This class is inherited by every class that needs to be serialized.
 * The class contains some deprecated methods from the older mechanisms
 * for serialization
 */
class Serializable {
public:
    virtual ~Serializable() {}

    virtual std::string SerializedObjectName() const = 0;
};

// helper template to stream vector contents provided T has an stream operator<<
template <typename T>
std::ostream& operator<<(std::ostream& os, const std::vector<T>& v) {
    os << "[";
    for (auto i = v.begin(); i != v.end(); ++i) {
        os << " " << *i;
    }
    os << " ]";
    return os;
}

}  // namespace lbcrypto

#endif
