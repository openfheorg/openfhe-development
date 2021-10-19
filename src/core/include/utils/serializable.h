// @file serializable.h Legacy Serialization utilities.
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef LBCRYPTO_SERIALIZABLE_H
#define LBCRYPTO_SERIALIZABLE_H

// TODO (dsuponit): purge the headers below and combine #pragma for GNU and clang
#include <iostream>
#include <string>

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
 * \brief Base class for PALISADE serialization
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
