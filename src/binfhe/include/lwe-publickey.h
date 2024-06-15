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

#ifndef _LWE_PUBLICKEY_H_
#define _LWE_PUBLICKEY_H_

#include "lwe-publickey-fwd.h"
#include "math/math-hal.h"
#include "utils/serializable.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace lbcrypto {
/**
 * @brief Class that stores the LWE scheme public key; contains a vector
 */
class LWEPublicKeyImpl : public Serializable {
public:
    LWEPublicKeyImpl() = default;

    explicit LWEPublicKeyImpl(const std::vector<NativeVector>& A, const NativeVector& v) : m_A(A), m_v(v) {}

    LWEPublicKeyImpl(LWEPublicKeyImpl&& rhs) noexcept : m_A(std::move(rhs.m_A)), m_v(std::move(rhs.m_v)) {}

    LWEPublicKeyImpl(const LWEPublicKeyImpl& rhs) : m_A(rhs.m_A), m_v(rhs.m_v) {}

    LWEPublicKeyImpl& operator=(const LWEPublicKeyImpl& rhs) {
        this->m_A = rhs.m_A;
        this->m_v = rhs.m_v;
        return *this;
    }

    LWEPublicKeyImpl& operator=(LWEPublicKeyImpl&& rhs) noexcept {
        this->m_A = std::move(rhs.m_A);
        this->m_v = std::move(rhs.m_v);
        return *this;
    }

    const std::vector<NativeVector>& GetA() const {
        return m_A;
    }

    const NativeVector& Getv() const {
        return m_v;
    }

    void SetA(const std::vector<NativeVector>& A) {
        m_A = A;
    }

    void Setv(const NativeVector& v) {
        m_v = v;
    }

    uint32_t GetLength() const {
        return m_v.GetLength();
    }

    const NativeInteger& GetModulus() const {
        return m_v.GetModulus();
    }

    bool operator==(const LWEPublicKeyImpl& other) const {
        return (m_A == other.m_A) && (m_v == other.m_v);
    }

    bool operator!=(const LWEPublicKeyImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("A", m_A));
        ar(::cereal::make_nvp("v", m_v));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }

        ar(::cereal::make_nvp("A", m_A));
        ar(::cereal::make_nvp("v", m_v));
    }

    std::string SerializedObjectName() const override {
        return "LWEPublicKey";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

private:
    std::vector<NativeVector> m_A;
    NativeVector m_v;
};

}  // namespace lbcrypto

#endif  // _LWE_PUBLICKEY_H_
