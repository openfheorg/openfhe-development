//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2025, NJIT, Duality Technologies Inc. and other contributors
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
  Serialization utilities
 */

#ifndef __SERIAL_H__
#define __SERIAL_H__

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
        #if __GNUC__ >= 13
            #pragma GCC diagnostic ignored "-Wdangling-reference"
        #endif
    #endif
#elif defined __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wunused-private-field"
    #pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#include "cereal/archives/portable_binary.hpp"
#include "cereal/archives/json.hpp"
#include "cereal/cereal.hpp"
#include "cereal/types/map.hpp"
#include "cereal/types/memory.hpp"
#include "cereal/types/polymorphic.hpp"
#include "cereal/types/string.hpp"
#include "cereal/types/vector.hpp"

#if defined(__GNUC__) && !defined(__clang__)
    #if __GNUC__ >= 8
        #pragma GCC diagnostic pop
    #endif
#elif defined __clang__
    #pragma clang diagnostic pop
#endif

#include "utils/sertype.h"

#include <type_traits>
#include <istream>
#include <fstream>
#include <sstream>
#include <string>
#include <memory>

namespace lbcrypto {

// ATTN: the code below (including "namespace internal_cc_traits") was added to make sure that some functions
// from this file are NOT called if the object type they get as a parameter is CryptoContextImpl/CryptoContext.
// An error is generated, if those functions are called instead of the ones defined in cryptocontext-ser.h
template <typename Element>
class CryptoContextImpl;
template <typename Element>
using CryptoContext = std::shared_ptr<CryptoContextImpl<Element>>;

namespace internal_cc_traits {
template <typename T>
struct cc_ser_enabled : std::false_type {};

template <typename T>
struct is_crypto_context_like : std::false_type {};

template <typename Element>
struct is_crypto_context_like<CryptoContextImpl<Element>> : std::true_type {};
template <typename Element>
struct is_crypto_context_like<std::shared_ptr<CryptoContextImpl<Element>>> : std::true_type {};

// public trait: strips const/volatile and references
template <typename T>
struct is_crypto_context_impl : is_crypto_context_like<std::decay_t<T>> {};
}  // namespace internal_cc_traits

// Helper macro: ensure that CryptoContext serialization is only used
// when cryptocontext-ser.h has been included and the type has been enabled.
#define CHECK_CC_SERIALIZATION_ENABLED(T)                                                             \
    do {                                                                                              \
        if constexpr (::lbcrypto::internal_cc_traits::is_crypto_context_impl<T>::value) {             \
            using DecayedT = std::decay_t<T>;                                                         \
            static_assert(::lbcrypto::internal_cc_traits::cc_ser_enabled<DecayedT>::value,            \
                          "CryptoContext serialization is disabled. Include <cryptocontext-ser.h>."); \
        }                                                                                             \
    } while (0)

namespace Serial {
//========================== BINARY serialization ==========================
/**
 * Serialize an object
 * @param obj - object to serialize
 * @param stream - Stream to serialize to
 * @param sertype - type of serialization; default is BINARY
 */
template <typename T>
void Serialize(const T& obj, std::ostream& stream, const SerType::SERBINARY& st) {
    cereal::PortableBinaryOutputArchive archive(stream);
    archive(obj);
}

/**
 * Deserialize an object
 * @param obj - object to deserialize into
 * @param stream - Stream to deserialize from
 * @param sertype - type of de-serialization; default is BINARY
 */
template <typename T>
void Deserialize(T& obj, std::istream& stream, const SerType::SERBINARY& st) {
    CHECK_CC_SERIALIZATION_ENABLED(T);

    cereal::PortableBinaryInputArchive archive(stream);
    archive(obj);
}

template <typename T>
bool SerializeToFile(const std::string& filename, const T& obj, const SerType::SERBINARY& sertype) {
    CHECK_CC_SERIALIZATION_ENABLED(T);

    std::ofstream file(filename, std::ios::out | std::ios::binary);
    if (file.is_open()) {
        Serial::Serialize(obj, file, sertype);
        file.close();
        return true;
    }
    return false;
}

template <typename T>
bool DeserializeFromFile(const std::string& filename, T& obj, const SerType::SERBINARY& sertype) {
    CHECK_CC_SERIALIZATION_ENABLED(T);

    std::ifstream file(filename, std::ios::in | std::ios::binary);
    if (file.is_open()) {
        Serial::Deserialize(obj, file, sertype);
        file.close();
        return true;
    }
    return false;
}

//========================== JSON serialization ==========================
/**
 * Serialize an object
 * @param obj - object to serialize
 * @param stream - Stream to serialize to
 * @param sertype - type of serialization; default is BINARY
 */
template <typename T>
void Serialize(const T& obj, std::ostream& stream, const SerType::SERJSON& ser) {
    cereal::JSONOutputArchive archive(stream);
    archive(obj);
}

/**
 * Deserialize an object
 * @param obj - object to deserialize into
 * @param stream - Stream to deserialize from
 * @param sertype - type of serialization; default is BINARY
 */
template <typename T>
void Deserialize(T& obj, std::istream& stream, const SerType::SERJSON& ser) {
    CHECK_CC_SERIALIZATION_ENABLED(T);

    cereal::JSONInputArchive archive(stream);
    archive(obj);
}

template <typename T>
bool SerializeToFile(const std::string& filename, const T& obj, const SerType::SERJSON& sertype) {
    CHECK_CC_SERIALIZATION_ENABLED(T);

    std::ofstream file(filename, std::ios::out | std::ios::binary);
    if (file.is_open()) {
        Serial::Serialize(obj, file, sertype);
        file.close();
        return true;
    }
    return false;
}

template <typename T>
bool DeserializeFromFile(const std::string& filename, T& obj, const SerType::SERJSON& sertype) {
    CHECK_CC_SERIALIZATION_ENABLED(T);

    std::ifstream file(filename, std::ios::in | std::ios::binary);
    if (file.is_open()) {
        Serial::Deserialize(obj, file, sertype);
        file.close();
        return true;
    }
    return false;
}

/**
 * SerializeToString - serialize the object to a JSON string and return the
 * string
 * @param t - any serializable object
 * @return JSON string
 */
template <typename T>
std::string SerializeToString(const T& t) {
    CHECK_CC_SERIALIZATION_ENABLED(T);

    std::stringstream s;
    Serialize(t, s, SerType::JSON);
    return s.str();
}

/**
 * DeserializeFromString - deserialize the object from a JSON string
 * @param obj - any object to deserialize into
 * @param json - JSON string
 */
template <typename T>
void DeserializeFromString(T& obj, const std::string& json) {
    CHECK_CC_SERIALIZATION_ENABLED(T);

    std::stringstream s;
    s << json;
    Serial::Deserialize(obj, s, SerType::JSON);
}

}  // namespace Serial

}  // namespace lbcrypto

#endif  // __SERIAL_H__
