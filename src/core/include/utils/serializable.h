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
  Legacy Serialization utilities
 */

#ifndef LBCRYPTO_SERIALIZABLE_H
#define LBCRYPTO_SERIALIZABLE_H

// TODO (dsuponit): purge the headers below and combine #pragma for GNU and clang
#include "utils/type_name.h"
// #include "utils/exception.h"
// #include "utils/caller_info.h"
#include <iostream>
#include <string>
#include <vector>

#ifndef CEREAL_RAPIDJSON_HAS_STDSTRING
    #define CEREAL_RAPIDJSON_HAS_STDSTRING 1
#endif
#ifndef CEREAL_RAPIDJSON_HAS_CXX11_RVALUE_REFS
    #define CEREAL_RAPIDJSON_HAS_CXX11_RVALUE_REFS 1
#endif
#define CEREAL_RAPIDJSON_HAS_CXX11_NOEXCEPT 0

#ifdef __GNUC__
    #if __GNUC__ >= 8
        #pragma GCC diagnostic ignored "-Wclass-memaccess"
    #endif
#endif

#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wunused-private-field"
#endif

#include "cereal/cereal.hpp"
#include "cereal/types/polymorphic.hpp"

#ifdef __GNUC__
    #if __GNUC__ >= 8
        #pragma GCC diagnostic pop
    #endif
#endif

#ifdef __clang__
    #pragma clang diagnostic pop
#endif

namespace lbcrypto {

using Serialized = void*;

/**
 * \class Serializable
 *
 * \brief Base class for OpenFHE serialization
 *
 * This class is inherited by every class that needs to be serialized as it has 2 important interfaces:
 * SerializedObjectName() and SerializedVersion()
 * class Serializable should never be instantiated.
 *
 */
class Serializable {
protected:
    Serializable() = default;
    // virtual ~Serializable() {}

public:
    // TODO (dsuponit): should we make the interfaces non-virtual to improve performance of the derived classes ???
    // std::string SerializedObjectName() const {
    // return objectTypeName(this);
    // }

    static constexpr uint32_t SerializedVersion() {
        return 1;
    }

    // void checkVersion(uint32_t version, CALLER_INFO_ARGS_HDR) const {
    //    if (version > this->SerializedVersion()) {
    //        OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
    //            " is from a later version of the library." + CALLER_INFO);
    //    }
    // }
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
